//! Local execution adapter for Orion's first relationship pivot.
//!
//! The frontend supplies only an opaque path selector, an expected seed hash,
//! and an explicit subtree root. This module reconstructs the authoritative
//! RELATE/TRACE state under one intel snapshot, validates the selector, walks
//! a bounded non-symlink scope, and classifies only evidence-backed matches.

use anyhow::{bail, Context, Result};
use chrono::Utc;
use nsic_core::hunt::{
    finding_role, same_hunt_concept, select_hypothesis, HuntBounds, HuntEvidenceRole,
    HuntFinding, HuntRequest, HuntResult, HuntScanError, HuntScope, HuntScopeKind, HuntSummary,
    DEFAULT_MAX_HUNT_ERRORS, DEFAULT_MAX_HUNT_FILES, DEFAULT_MAX_HUNT_FINDINGS,
    DEFAULT_MAX_HUNT_WALK_ENTRIES,
};
use nsic_core::orion::TracePath;
use sqlx::PgPool;
use std::cmp::Ordering;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use walkdir::WalkDir;

use crate::analysis_coverage::{YaraCoverage, YaraCoverageState};
use crate::bloom::{BloomState, IntelGate};
use crate::relationship_contract::{self, RecentYaraHits};
use crate::yara_scan::YaraEngine;

struct ScopeWalk {
    files: Vec<PathBuf>,
    errors: Vec<HuntScanError>,
    files_discovered: usize,
    files_inconclusive: usize,
    scope_truncated: bool,
    omitted_errors: usize,
}

#[allow(clippy::too_many_arguments)]
pub async fn run(
    pool: &PgPool,
    bloom: &BloomState,
    intel_gate: &IntelGate,
    yara: &Arc<YaraEngine>,
    yara_coverage: &YaraCoverage,
    request: HuntRequest,
) -> Result<HuntResult> {
    let started_at = Utc::now();
    validate_request(&request)?;

    let requested_seed = PathBuf::from(&request.seed_path);
    let canonical_seed = tokio::fs::canonicalize(&requested_seed)
        .await
        .with_context(|| format!("canonicalize seed {}", requested_seed.display()))?;
    let canonical_root = tokio::fs::canonicalize(&request.scope.root)
        .await
        .with_context(|| format!("canonicalize hunt scope {}", request.scope.root))?;
    let root_metadata = tokio::fs::metadata(&canonical_root)
        .await
        .with_context(|| format!("stat hunt scope {}", canonical_root.display()))?;
    if !root_metadata.is_dir() {
        bail!("hunt scope {} is not a directory", canonical_root.display());
    }
    if !canonical_seed.starts_with(&canonical_root) {
        bail!(
            "seed {} is outside hunt scope {}",
            canonical_seed.display(),
            canonical_root.display()
        );
    }

    let root_for_walk = canonical_root.clone();
    let seed_for_walk = canonical_seed.clone();
    let mut walked = tokio::task::spawn_blocking(move || {
        collect_scope_files_bounded(
            &root_for_walk,
            &seed_for_walk,
            DEFAULT_MAX_HUNT_FILES,
            DEFAULT_MAX_HUNT_WALK_ENTRIES,
            DEFAULT_MAX_HUNT_ERRORS,
        )
    })
    .await
    .context("hunt scope walk task panicked")??;

    // One read guard spans seed reconstruction and every candidate. A feed
    // sync cannot make half the hunt use one corpus and half use another.
    // The specialized resolver below deliberately does not reacquire this
    // fair RwLock, avoiding self-deadlock behind a queued writer.
    let _intel_snapshot = intel_gate.read().await;
    let revalidated_seed = tokio::fs::canonicalize(&requested_seed)
        .await
        .with_context(|| format!("revalidate hunt seed {}", requested_seed.display()))?;
    if revalidated_seed != canonical_seed || !revalidated_seed.starts_with(&canonical_root) {
        bail!("hunt seed changed after scope discovery; select the file again");
    }
    let observation_scope = RecentYaraHits::new();
    let seed = relationship_contract::resolve_in_intel_snapshot_with_expected_sha256(
        pool,
        bloom,
        yara,
        yara_coverage,
        &observation_scope,
        &requested_seed,
        &request.expected_seed_sha256,
    )
    .await
    .with_context(|| format!("re-resolve hunt seed {}", requested_seed.display()))?;
    let hypothesis = select_hypothesis(&seed.orion_trace, &request.trace_path_id)?;

    let mut findings = Vec::new();
    let mut files_analyzed = 0usize;
    for candidate in &walked.files {
        let revalidated = match tokio::fs::canonicalize(candidate).await {
            Ok(path) if path == *candidate && path.starts_with(&canonical_root) => path,
            Ok(_) => {
                walked.files_inconclusive += 1;
                push_error(
                    &mut walked.errors,
                    &mut walked.omitted_errors,
                    DEFAULT_MAX_HUNT_ERRORS,
                    HuntScanError {
                        path: candidate.to_string_lossy().to_string(),
                        error: "candidate changed after scope discovery".to_string(),
                    },
                );
                continue;
            }
            Err(error) => {
                walked.files_inconclusive += 1;
                push_error(
                    &mut walked.errors,
                    &mut walked.omitted_errors,
                    DEFAULT_MAX_HUNT_ERRORS,
                    HuntScanError {
                        path: candidate.to_string_lossy().to_string(),
                        error: format!("revalidate candidate: {error}"),
                    },
                );
                continue;
            }
        };
        match relationship_contract::resolve_in_intel_snapshot(
            pool,
            bloom,
            yara,
            yara_coverage,
            &observation_scope,
            &revalidated,
        )
        .await
        {
            Ok(resolved) => {
                files_analyzed += 1;
                let matching: Vec<&TracePath> = resolved
                    .orion_trace
                    .paths
                    .iter()
                    .filter(|path| {
                        same_hunt_concept(
                            path,
                            hypothesis.selected_path.target_kind,
                            &hypothesis.selected_path.target,
                        )
                    })
                    .collect();
                if let Some(best) = matching.first() {
                    findings.push(HuntFinding {
                        artifact_path: resolved.verdict.path,
                        sha256: resolved.verdict.sha256,
                        md5: resolved.verdict.md5,
                        role: finding_role(best),
                        strength: best.rank.relationship_strength,
                        supporting_path: (*best).clone(),
                        additional_matching_paths: matching.len().saturating_sub(1),
                    });
                } else if candidate_evaluation_is_partial(
                    &resolved,
                    hypothesis.selected_path.target_kind,
                    &hypothesis.selected_path.target,
                ) {
                    walked.files_inconclusive += 1;
                    push_error(
                        &mut walked.errors,
                        &mut walked.omitted_errors,
                        DEFAULT_MAX_HUNT_ERRORS,
                        HuntScanError {
                            path: resolved.verdict.path,
                            error: "relationship evaluation was partial; no negative conclusion is available"
                                .to_string(),
                        },
                    );
                }
            }
            Err(error) => {
                walked.files_inconclusive += 1;
                push_error(
                    &mut walked.errors,
                    &mut walked.omitted_errors,
                    DEFAULT_MAX_HUNT_ERRORS,
                    HuntScanError {
                        path: revalidated.to_string_lossy().to_string(),
                        error: error.to_string(),
                    },
                );
            }
        }
    }

    findings.sort_by(compare_findings);
    let confirming_findings = findings
        .iter()
        .filter(|finding| finding.role == HuntEvidenceRole::Confirming)
        .count();
    let contradicting_findings = findings
        .iter()
        .filter(|finding| finding.role == HuntEvidenceRole::Contradicting)
        .count();
    let contextual_findings = findings
        .iter()
        .filter(|finding| finding.role == HuntEvidenceRole::Contextual)
        .count();
    let omitted_findings = findings.len().saturating_sub(DEFAULT_MAX_HUNT_FINDINGS);
    findings.truncate(DEFAULT_MAX_HUNT_FINDINGS);

    let mut limitations = vec![
        "Absence of a matching artifact is not contradicting evidence; this pivot emits contradiction only when a future detector has a typed falsification primitive."
            .to_string(),
        "The initial execution scope is a bounded local subtree. Symbolic links are not followed, and candidates are revalidated before analysis."
            .to_string(),
        "The filesystem is live rather than an immutable snapshot. A candidate that changes during discovery or analysis is inconclusive; no clean-scope claim is made."
            .to_string(),
    ];
    match yara_coverage.status {
        YaraCoverageState::Failed => limitations.push(
            "YARA coverage failed to load; YARA-dependent evidence is unavailable and no negative YARA claim is made."
                .to_string(),
        ),
        YaraCoverageState::Empty => limitations.push(
            "No YARA rules are configured; this hunt contains no YARA detection coverage."
                .to_string(),
        ),
        YaraCoverageState::Loaded => {}
    }
    if walked.scope_truncated {
        limitations.push(
            "The filesystem scope exceeded an execution bound; returned results are partial."
                .to_string(),
        );
    }

    Ok(HuntResult {
        hypothesis,
        scope: HuntScope {
            kind: HuntScopeKind::Subtree,
            root: canonical_root.to_string_lossy().to_string(),
        },
        findings,
        scan_errors: walked.errors,
        summary: HuntSummary {
            files_discovered: walked.files_discovered,
            files_analyzed,
            files_inconclusive: walked.files_inconclusive,
            confirming_findings,
            contradicting_findings,
            contextual_findings,
        },
        bounds: HuntBounds {
            max_files: DEFAULT_MAX_HUNT_FILES,
            max_findings: DEFAULT_MAX_HUNT_FINDINGS,
            max_errors: DEFAULT_MAX_HUNT_ERRORS,
            max_walk_entries: DEFAULT_MAX_HUNT_WALK_ENTRIES,
            scope_truncated: walked.scope_truncated,
            findings_truncated: omitted_findings > 0,
            omitted_findings,
            errors_truncated: walked.omitted_errors > 0,
            omitted_errors: walked.omitted_errors,
        },
        limitations,
        started_at,
        completed_at: Utc::now(),
    })
}

fn validate_request(request: &HuntRequest) -> Result<()> {
    if request.seed_path.trim().is_empty() {
        bail!("hunt seed path is required");
    }
    if request.scope.root.trim().is_empty() {
        bail!("hunt scope root is required");
    }
    if request.trace_path_id.trim().is_empty() {
        bail!("Orion trace path identity is required");
    }
    if request.expected_seed_sha256.len() != 64
        || !request
            .expected_seed_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        bail!("expected seed SHA-256 must be 64 lowercase hexadecimal characters");
    }
    Ok(())
}

fn collect_scope_files_bounded(
    root: &Path,
    canonical_seed: &Path,
    max_files: usize,
    max_walk_entries: usize,
    max_errors: usize,
) -> Result<ScopeWalk> {
    let mut files = Vec::new();
    let mut errors = Vec::new();
    let mut files_discovered = 0usize;
    let mut files_inconclusive = 0usize;
    let mut scope_truncated = false;
    let mut omitted_errors = 0usize;

    for (walk_index, entry) in WalkDir::new(root)
        .follow_links(false)
        .sort_by_file_name()
        .into_iter()
        .enumerate()
    {
        if walk_index >= max_walk_entries {
            scope_truncated = true;
            break;
        }
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                files_inconclusive += 1;
                push_error(
                    &mut errors,
                    &mut omitted_errors,
                    max_errors,
                    HuntScanError {
                        path: error
                            .path()
                            .map(|path| path.to_string_lossy().to_string())
                            .unwrap_or_else(|| root.to_string_lossy().to_string()),
                        error: error.to_string(),
                    },
                );
                continue;
            }
        };
        if !entry.file_type().is_file() {
            continue;
        }
        let canonical = match std::fs::canonicalize(entry.path()) {
            Ok(path) => path,
            Err(error) => {
                files_inconclusive += 1;
                push_error(
                    &mut errors,
                    &mut omitted_errors,
                    max_errors,
                    HuntScanError {
                        path: entry.path().to_string_lossy().to_string(),
                        error: error.to_string(),
                    },
                );
                continue;
            }
        };
        if !canonical.starts_with(root) {
            files_inconclusive += 1;
            push_error(
                &mut errors,
                &mut omitted_errors,
                max_errors,
                HuntScanError {
                    path: entry.path().to_string_lossy().to_string(),
                    error: "resolved path escaped the declared hunt scope".to_string(),
                },
            );
            continue;
        }
        if canonical == canonical_seed {
            continue;
        }
        files_discovered += 1;
        if files.len() == max_files {
            scope_truncated = true;
            break;
        }
        files.push(canonical);
    }

    Ok(ScopeWalk {
        files,
        errors,
        files_discovered,
        files_inconclusive,
        scope_truncated,
        omitted_errors,
    })
}

fn push_error(
    errors: &mut Vec<HuntScanError>,
    omitted_errors: &mut usize,
    max_errors: usize,
    error: HuntScanError,
) {
    if errors.len() < max_errors {
        errors.push(error);
    } else {
        *omitted_errors += 1;
    }
}

fn compare_findings(left: &HuntFinding, right: &HuntFinding) -> Ordering {
    evidence_role_key(left.role)
        .cmp(&evidence_role_key(right.role))
        .then_with(|| right.strength.cmp(&left.strength))
        .then_with(|| {
            right
                .supporting_path
                .rank
                .weakest_source_confidence
                .cmp(&left.supporting_path.rank.weakest_source_confidence)
        })
        .then_with(|| {
            left.supporting_path
                .rank
                .hop_count
                .cmp(&right.supporting_path.rank.hop_count)
        })
        .then_with(|| left.artifact_path.cmp(&right.artifact_path))
}

fn candidate_evaluation_is_partial(
    resolved: &relationship_contract::ResolvedVerdict,
    target_kind: nsic_core::models::RelationshipKind,
    target: &str,
) -> bool {
    resolved.orion_trace.bounds.input_relationships_truncated
        || resolved.orion_trace.bounds.paths_truncated
        || resolved
            .verdict
            .threat_relationships
            .iter()
            .any(|relationship| {
                relationship.kind == target_kind && relationship.target == target
            })
        || resolved
            .orion_trace
            .untraced_relationships
            .iter()
            .any(|relationship| {
                relationship.target_kind == target_kind && relationship.target == target
            })
}

fn evidence_role_key(role: HuntEvidenceRole) -> u8 {
    match role {
        HuntEvidenceRole::Confirming => 0,
        HuntEvidenceRole::Contradicting => 1,
        HuntEvidenceRole::Contextual => 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn scope_walk_is_bounded_deterministic_and_excludes_seed() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let seed = root.join("seed.bin");
        fs::write(&seed, b"seed").unwrap();
        fs::write(root.join("b.bin"), b"b").unwrap();
        fs::write(root.join("a.bin"), b"a").unwrap();
        fs::write(root.join("c.bin"), b"c").unwrap();

        let walked = collect_scope_files_bounded(&root, &seed, 2, 100, 10).unwrap();
        let names: Vec<String> = walked
            .files
            .iter()
            .map(|path| path.file_name().unwrap().to_string_lossy().to_string())
            .collect();
        assert_eq!(names, vec!["a.bin", "b.bin"]);
        assert_eq!(walked.files_discovered, 3);
        assert!(walked.scope_truncated);
        assert!(!walked.files.contains(&seed));
    }

    #[cfg(unix)]
    #[test]
    fn scope_walk_does_not_follow_symbolic_links() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("outside.bin"), b"outside").unwrap();
        symlink(outside.path(), temp.path().join("escape")).unwrap();
        let root = temp.path().canonicalize().unwrap();
        let seed = root.join("seed.bin");
        fs::write(&seed, b"seed").unwrap();

        let walked = collect_scope_files_bounded(&root, &seed, 10, 100, 10).unwrap();
        assert!(walked.files.is_empty());
        assert!(!walked.scope_truncated);
    }
}
