/// YARA rule loading and scanning now live in `nsic-core` (behind its
/// `yara-scan` feature) so the Phase 1 agent can run local scans without
/// depending on Tauri. Re-exported here so existing `crate::yara_scan::X`
/// call sites in this crate are unaffected.
pub use nsic_core::yara_scan::{YaraEngine, YaraMatch};
