/// YARA rule loading and scanning now live in `nsic-core` (behind its
/// `yara-scan` feature) so the Phase 1 agent can run local scans without
/// depending on Tauri. Re-exported here so existing desktop call sites keep
/// their local `crate::yara_scan::YaraEngine` path.
pub use nsic_core::yara_scan::YaraEngine;

/// The verdict hit ceiling is only named directly by this crate's
/// regressions; production code consumes it through `scan_bytes_bounded`.
/// Keep the re-export test-scoped so a normal `-D warnings` library build
/// does not see an otherwise-unused import in this private wrapper module.
#[cfg(test)]
pub use nsic_core::yara_scan::MAX_YARA_MATCHES_PER_VERDICT;
