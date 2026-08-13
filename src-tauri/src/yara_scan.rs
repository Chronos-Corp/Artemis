/// YARA rule loading and scanning now live in `nsic-core` (behind its
/// `yara-scan` feature) so the Phase 1 agent can run local scans without
/// depending on Tauri. Re-exported here so existing `crate::yara_scan::X`
/// call sites in this crate are unaffected. Only `YaraEngine` is
/// re-exported: `YaraMatch` results are only ever consumed by field
/// access (`hit.rule_name`) in this crate, never named directly, and
/// `mod yara_scan` is private, so re-exporting it too would trip
/// `unused_imports` under `-D warnings`.
pub use nsic_core::yara_scan::YaraEngine;
