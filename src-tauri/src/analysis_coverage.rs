use serde::Serialize;
use std::path::Path;
use std::sync::Arc;

use crate::yara_scan::YaraEngine;

const MAX_PUBLIC_FAILURE_REASON_CHARS: usize = 512;

/// Machine-readable YARA availability for an analyst-facing verdict.
///
/// `Empty` is a successful load of a rules directory with zero active rules.
/// `Failed` means the configured ruleset was rejected or could not be loaded,
/// so absence of YARA detections is *unknown*, not a successful zero-match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum YaraCoverageState {
    Loaded,
    Empty,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct YaraCoverage {
    pub status: YaraCoverageState,
    pub rule_count: usize,
    pub failure_reason: Option<String>,
}

pub fn load_yara_with_coverage(rules_dir: &Path) -> (Arc<YaraEngine>, YaraCoverage) {
    match YaraEngine::load(rules_dir) {
        Ok(engine) => {
            let status = if engine.rule_count == 0 {
                YaraCoverageState::Empty
            } else {
                YaraCoverageState::Loaded
            };
            tracing::info!(
                "YARA engine loaded {} rule file(s) from {}",
                engine.rule_count,
                rules_dir.display()
            );
            let rule_count = engine.rule_count;
            (
                Arc::new(engine),
                YaraCoverage {
                    status,
                    rule_count,
                    failure_reason: None,
                },
            )
        }
        Err(error) => {
            let failure_reason = sanitize_failure_reason(&error.to_string());
            tracing::warn!(
                "YARA engine failed to load from {}: {}",
                rules_dir.display(),
                failure_reason
            );
            (
                Arc::new(YaraEngine::empty(rules_dir)),
                YaraCoverage {
                    status: YaraCoverageState::Failed,
                    rule_count: 0,
                    failure_reason: Some(failure_reason),
                },
            )
        }
    }
}

fn sanitize_failure_reason(raw: &str) -> String {
    raw.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(MAX_PUBLIC_FAILURE_REASON_CHARS)
        .collect::<String>()
        .trim()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn successful_empty_ruleset_is_distinct_from_load_failure() {
        let dir = tempfile::tempdir().expect("create empty rules dir");
        let (_engine, coverage) = load_yara_with_coverage(dir.path());

        assert_eq!(coverage.status, YaraCoverageState::Empty);
        assert_eq!(coverage.rule_count, 0);
        assert_eq!(coverage.failure_reason, None);
    }

    #[test]
    fn rejected_ruleset_remains_machine_readable_as_failed_coverage() {
        let dir = tempfile::tempdir().expect("create rules dir");
        std::fs::write(
            dir.path().join("invalid.yar"),
            "include \"/outside/analysis-boundary.yar\"\nrule Local { condition: true }\n",
        )
        .expect("write invalid ruleset");

        let (engine, coverage) = load_yara_with_coverage(dir.path());

        // Degradation keeps the app usable for hash/path/intel work, but the
        // fallback engine must never make that degradation look like a
        // successful zero-rule scan to a caller.
        assert_eq!(engine.rule_count, 0);
        assert_eq!(coverage.status, YaraCoverageState::Failed);
        assert_eq!(coverage.rule_count, 0);
        assert!(coverage
            .failure_reason
            .as_deref()
            .is_some_and(|reason| reason.contains("include directives are not supported")));
    }

    #[test]
    fn public_failure_reason_is_bounded_and_single_line_safe() {
        let raw = format!("bad\nreason\t{}", "x".repeat(700));
        let sanitized = sanitize_failure_reason(&raw);

        assert!(!sanitized.contains('\n'));
        assert!(!sanitized.contains('\t'));
        assert!(sanitized.chars().count() <= MAX_PUBLIC_FAILURE_REASON_CHARS);
    }
}
