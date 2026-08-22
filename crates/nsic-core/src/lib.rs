//! Shared between the Phase 0 desktop app (`src-tauri`) and the Phase 1
//! agent/console (`crates/agent`, `crates/console`): pure file hashing, the
//! intel-graph vocabulary (indicator kinds, verdict tiers, provenance), and
//! the agent<->console wire protocol. Nothing in the default feature set
//! touches Postgres or links libyara, so the console binary (which needs
//! neither) doesn't pull either in; enable `db` or `yara-scan` per consumer.

pub mod hashing;
pub mod hunt;
pub mod models;
pub mod orion;
pub mod proto;
pub mod sanitize;

#[cfg(feature = "db")]
pub mod db;

#[cfg(feature = "yara-scan")]
pub mod yara_scan;

// `yara::Rules` itself does not expose a useful Debug implementation, but
// callers and tests can still benefit from seeing the safe, public identity
// of an engine when a Result assertion fails. Keep the compiled rule object
// opaque while exposing the fields that actually identify the loaded set.
#[cfg(feature = "yara-scan")]
impl std::fmt::Debug for yara_scan::YaraEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("YaraEngine")
            .field("rules_dir", &self.rules_dir)
            .field("rule_count", &self.rule_count)
            .field("ruleset_fingerprint", &self.ruleset_fingerprint)
            .finish_non_exhaustive()
    }
}
