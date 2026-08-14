//! Wire types shared between the Phase 1 agent and console. Kept separate
//! from `models` (the intel-graph vocabulary) since these describe the
//! agent<->console protocol, not indicator data.
//!
//! Two distinct credentials are in play here and must not be conflated:
//!
//! - The **bootstrap enrollment secret**: a console-operator-configured
//!   value (`NSIC_ENROLLMENT_SECRET`) that authorizes a new machine to
//!   enroll at all. It is never stored per-host and never appears in any
//!   of these structs; it's presented as a bearer token on
//!   `POST /api/v1/agents/enroll` only, the same way on every enrollment.
//! - The **per-agent credential**: minted uniquely by the console for
//!   each host at successful enrollment, returned exactly once in
//!   [`EnrollResponse::credential`]. The agent stores it locally and
//!   presents it as a bearer token on every subsequent authenticated
//!   request (heartbeat, sighting submission). The console stores only
//!   its hash, never the raw value.
//!
//! There is still no TLS in Phase 1 (see docs/phase1-design.md), so both
//! credentials cross the wire in plaintext today. That is a tracked gap,
//! not an oversight.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Hard cap on a single sample's size, shared by both sides of the wire
/// so they agree on it rather than each hardcoding their own copy that
/// can drift: the console enforces it as an upper bound on what it will
/// accept (`axum::extract::DefaultBodyLimit` on the upload route, plus a
/// redundant in-handler check), and the agent enforces it as an upper
/// bound on what it will even attempt to read off disk before making the
/// request -- reading an unbounded file into memory first and only then
/// discovering the console will reject it defeats the point of a cap.
/// 100 MiB is an arbitrary but documented ceiling for storing raw sample
/// bytes directly in Postgres -- see docs/phase1-design.md for why that
/// storage choice itself is not the final answer.
pub const MAX_SAMPLE_SIZE_BYTES: usize = 100 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollRequest {
    pub hostname: String,
    pub os: String,
    pub agent_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollResponse {
    pub host_id: Uuid,
    /// The per-agent credential, in the clear, exactly once. The console
    /// cannot show it again; losing it means re-enrolling.
    pub credential: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatRequest {
    pub agent_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatResponse {
    pub received_at: DateTime<Utc>,
}

/// Reports that this host observed a YARA rule match against a file.
/// Deliberately narrow to what `nsic-agent scan` actually produces today
/// (a sha256 plus the rule that matched), not a generic multi-indicator-
/// kind sighting -- see docs/phase1-design.md for why generalizing this
/// is deferred until something other than local YARA scanning produces a
/// sighting. `source` and `confidence` are not client-supplied: the
/// console assigns both based on the fact that this endpoint is
/// exclusively YARA-sourced, the same way it would be inconsistent to let
/// an agent claim its own trust level.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SightingRequest {
    pub sha256: String,
    pub detection_name: String,
    /// `YaraEngine::ruleset_fingerprint` at scan time: which version of the
    /// rules produced this match. Rule content can change after a match is
    /// recorded; without this, a durable sighting citing only a rule name
    /// becomes unreconstructable once that rule is edited.
    pub ruleset_fingerprint: String,
    /// Where on the host the file was found, if known. Metadata, not file
    /// contents -- see the repo README's locked architecture decisions.
    pub path: Option<String>,
    pub observed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SightingResponse {
    pub indicator_id: Uuid,
    pub recorded_at: DateTime<Utc>,
}

/// One row of the intel graph's `host_sighted_indicator` edge, denormalized
/// for read consumers so an operator querying by host or by indicator gets
/// a sha256 and a rule name directly, rather than having to separately
/// resolve `indicator_id`/`detection_id`. The read-side counterpart to
/// [`SightingRequest`] -- see `list_host_sightings`/`list_indicator_
/// sightings` in `crates/console/src/sighting.rs`, gated by a distinct
/// console-operator credential, not the per-agent credential that governs
/// writing sightings (an agent can report what it saw; it cannot read what
/// the rest of the fleet reported).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SightingView {
    pub host_id: Uuid,
    pub hostname: String,
    pub indicator_id: Uuid,
    pub sha256: String,
    pub detection_id: Uuid,
    pub detection_name: String,
    pub source: String,
    pub confidence: i16,
    pub path: Option<String>,
    pub ruleset_fingerprint: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub received_at: DateTime<Utc>,
}

/// Response for both `GET /api/v1/hosts/{host_id}/sightings` and
/// `GET /api/v1/indicators/{sha256}/sightings`. Wrapped in a struct rather
/// than returning a bare JSON array so a future page cursor can be added
/// without breaking existing clients -- see docs/phase1-design.md for why
/// this PR ships a fixed row cap instead of real pagination.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SightingListResponse {
    pub sightings: Vec<SightingView>,
    /// `true` if there were more matching rows than the server's row cap
    /// and `sightings` was cut short -- without this, a caller has no way
    /// to distinguish "this host/hash has exactly N sightings" from "this
    /// host/hash has at least N, possibly many more." Not a page cursor:
    /// there is still no way to fetch the rows past the cap, only a signal
    /// that they exist. See docs/phase1-design.md for why real pagination
    /// is deferred.
    pub truncated: bool,
}

/// An operator's request to pull a specific file off a specific host.
/// `POST /api/v1/hosts/{host_id}/sample-requests`, operator-credential
/// only -- this is the write half of sample retrieval (PR #8); reading
/// the retrieved content itself back out is deferred to a follow-up PR
/// the same way sighting reads (PR #7) followed sighting writes (PR #6).
/// See the repo README's locked architecture decision #3: file contents
/// leave a host only on explicit, logged, attributed analyst request --
/// this struct, once inserted as a `sample_request` row, *is* that log
/// entry (host, path, and eventual outcome all live on one row).
/// "Attributed" is currently only to the operator credential as a whole,
/// not to an individual analyst -- there is no per-user operator identity
/// yet (see the deferred RBAC note in docs/phase1-design.md), and this
/// doc comment used to imply otherwise by listing a "requester" as
/// something the row records, which it doesn't.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SampleRequestCreate {
    pub path: String,
    /// Set when the requester already knows the hash (e.g. pivoting from
    /// a sighting) and wants the console to flag it if the agent uploads
    /// something else -- see [`SampleRequestStatus::Mismatched`]. Left
    /// `None` for a cold request where the hash isn't known yet.
    pub expected_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SampleRequestCreated {
    pub request_id: Uuid,
}

/// Outcome of a sample request. `Mismatched` is deliberately distinct
/// from `Fulfilled`: if the requester asserted an `expected_sha256` and
/// the agent uploaded content hashing to something else, that is a real
/// discrepancy (wrong file, file changed since the hash was recorded, or
/// something worse) that must stay visible, not get silently accepted as
/// a normal fulfillment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SampleRequestStatus {
    Pending,
    Fulfilled,
    Mismatched,
    Failed,
}

/// One row of `sample_request`, denormalized the same way `SightingView`
/// is -- metadata and status only, never the sample's actual bytes. There
/// is no endpoint that returns sample content yet (see above).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SampleRequestView {
    pub id: Uuid,
    pub host_id: Uuid,
    pub path: String,
    pub expected_sha256: Option<String>,
    pub status: SampleRequestStatus,
    pub failure_reason: Option<String>,
    pub sha256: Option<String>,
    pub size_bytes: Option<i64>,
    pub requested_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
}

/// Response for `GET /api/v1/hosts/{host_id}/sample-requests` (operator,
/// every request for a host) and `GET /api/v1/agents/{host_id}/
/// sample-requests` (agent, its own pending requests only). Same
/// fixed-cap-plus-`truncated`-flag shape as `SightingListResponse`, for
/// the same reason.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SampleRequestListResponse {
    pub requests: Vec<SampleRequestView>,
    pub truncated: bool,
}

/// Body of `POST /api/v1/agents/{host_id}/sample-requests/{request_id}/
/// failure`: the agent tried and could not fulfill a request (path not
/// found, permission denied, etc.) and says so explicitly, rather than
/// leaving the request stuck at `pending` forever with no way for an
/// operator to tell "still in flight" from "never going to happen."
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SampleRequestFailure {
    pub reason: String,
}

/// Response to a successful `POST .../content` upload: what the server
/// actually computed and decided, which may differ from what the
/// requester expected (see [`SampleRequestStatus::Mismatched`]).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SampleRequestFulfilled {
    pub status: SampleRequestStatus,
    pub sha256: String,
    pub size_bytes: i64,
}
