//! Shared between the Phase 0 desktop app (`src-tauri`) and the Phase 1
//! agent/console (`crates/agent`, `crates/console`): pure file hashing, the
//! intel-graph vocabulary (indicator kinds, verdict tiers, provenance), and
//! the agent<->console wire protocol. Nothing in the default feature set
//! touches Postgres, so the agent binary can depend on this crate without
//! linking sqlx/tokio-postgres at all; enable the `db` feature for that.

pub mod hashing;
pub mod models;
pub mod proto;

#[cfg(feature = "db")]
pub mod db;
