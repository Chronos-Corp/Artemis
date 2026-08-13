//! Shared between the Phase 0 desktop app (`src-tauri`) and the Phase 1
//! agent/console (`crates/agent`, `crates/console`): pure file hashing, the
//! intel-graph vocabulary (indicator kinds, verdict tiers, provenance), and
//! the agent<->console wire protocol. Nothing in the default feature set
//! touches Postgres or links libyara, so the console binary (which needs
//! neither) doesn't pull either in; enable `db` or `yara-scan` per consumer.

pub mod hashing;
pub mod models;
pub mod proto;

#[cfg(feature = "db")]
pub mod db;

#[cfg(feature = "yara-scan")]
pub mod yara_scan;
