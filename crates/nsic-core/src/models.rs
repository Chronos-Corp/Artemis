use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Kind of indicator stored in the intel graph. Mirrors the Postgres
/// `indicator_kind` enum in `src-tauri/migrations/0001_init.sql`. The
/// `sqlx::Type` derive only applies when the `db` feature is on, so the
/// agent can use this enum in its wire protocol without linking sqlx.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "db", derive(sqlx::Type))]
#[cfg_attr(
    feature = "db",
    sqlx(type_name = "indicator_kind", rename_all = "lowercase")
)]
pub enum IndicatorKind {
    Sha256,
    Md5,
    Sha1,
    Imphash,
    Tlsh,
    Ssdeep,
    Path,
    Regkey,
    Mutex,
    Domain,
    Ip,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "db", derive(sqlx::Type))]
#[cfg_attr(
    feature = "db",
    sqlx(type_name = "detection_kind", rename_all = "lowercase")
)]
pub enum DetectionKind {
    Yara,
    Sigma,
}

/// Verdict tiers, ordered strongest to weakest. Never collapse a verdict to
/// a boolean; always carry the tier and the provenance that produced it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerdictTier {
    ExactHash,
    FuzzyHash,
    YaraHit,
    PathPattern,
    Contextual,
}

/// A single piece of evidence backing a verdict. One file can accumulate
/// several of these across tiers and sources; the UI shows all of them
/// rather than collapsing to one number.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceEntry {
    pub tier: VerdictTier,
    pub source: String,
    pub confidence: i16,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub report_id: Option<Uuid>,
    pub report_title: Option<String>,
    pub report_url: Option<String>,
    pub detection_name: Option<String>,
    pub matched_value: String,
    pub cve_ids: Vec<String>,
}

/// How current the local copy of one intel feed is, as of the moment a
/// verdict was resolved. `None` means this source has never completed a
/// sync -- `feed_sync_state` only gains a row for a source once
/// `ingest::run_all`'s per-feed sync function returns `Ok`, so a source
/// that has only ever failed (bad API key, network error, upstream schema
/// change) has no row at all, not a stale one. `last_successful_sync_at`
/// is deliberately named around "successful": a feed that has been
/// silently failing (an expired abuse.ch auth key returning 401 on every
/// attempt, say) must not read as freshly synced just because an attempt
/// was made -- see `ingest::mod::run_all`'s doc comment on why a failed
/// sync is reported as an error rather than swallowed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntelSourceFreshness {
    pub source: String,
    pub last_successful_sync_at: Option<DateTime<Utc>>,
}

/// The full verdict for a file: every piece of evidence found, sorted
/// strongest tier first. No boolean "bad"/"clean" collapse happens here.
///
/// `entries` being empty means no configured intel source or local rule
/// currently flags this file -- it does not mean the file is clean. Prior
/// to `intel_freshness`, that distinction only existed as hedging prose in
/// the UI; an empty `entries` produced against an intel corpus that hasn't
/// synced in 11 days looked byte-for-byte identical to one produced
/// against a corpus that synced 18 minutes ago. `intel_freshness` carries
/// one entry per known feed (see `IntelSourceFreshness`) so the UI can
/// show, not just say, what the absence of a match is actually backed by
/// -- the same problem `nsic_core`'s Phase 1 sensor-health work solved for
/// "no sightings from this host" vs. "this host never scanned."
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verdict {
    pub path: String,
    pub sha256: String,
    pub md5: String,
    pub entries: Vec<ProvenanceEntry>,
    pub intel_freshness: Vec<IntelSourceFreshness>,
}
