//! Wire types shared between the Phase 1 agent and console. Kept separate
//! from `models` (the intel-graph vocabulary) since these describe the
//! agent<->console enrollment/heartbeat protocol, not indicator data.
//!
//! There is deliberately no authentication field on any of these yet
//! (`EnrollRequest` carries no pre-shared secret, `EnrollResponse` returns
//! a bare host id instead of an issued credential). That is a tracked gap,
//! not an oversight — see docs/phase1-design.md — and must close before
//! this protocol talks to a real fleet.

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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatRequest {
    pub agent_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatResponse {
    pub received_at: DateTime<Utc>,
}
