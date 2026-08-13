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
//!   request (heartbeat today; sighting submission later). The console
//!   stores only its hash, never the raw value.
//!
//! There is still no TLS in Phase 1 (see docs/phase1-design.md), so both
//! credentials cross the wire in plaintext today. That is a tracked gap,
//! not an oversight.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

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
