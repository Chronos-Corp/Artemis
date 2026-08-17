/// YARA rule loading and scanning now live in `nsic-core` (behind its
/// `yara-scan` feature) so the Phase 1 agent can run local scans without
/// depending on Tauri. Re-export the engine plus the verdict hit ceiling so
/// desktop call sites and regressions use the same authoritative bound as
/// the shared scanner rather than duplicating a magic number locally.
pub use nsic_core::yara_scan::{YaraEngine, MAX_YARA_MATCHES_PER_VERDICT};
