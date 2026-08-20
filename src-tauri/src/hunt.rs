//! Local execution adapter for Orion's first relationship pivot.
//!
//! The frontend supplies only an opaque path selector, an expected seed hash,
//! and an explicit subtree root. This module reconstructs the authoritative
//! RELATE/TRACE state under one intel snapshot, validates the selector, walks
//! a bounded non-symlink scope, and classifies only evidence-backed matches.

use anyhow::{bail, Context, Result};
use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt};
use cap_std::ambient_authority;
use cap_std::fs::{Dir, OpenOptions};
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

use crate::analysis_coverage::{YaraCoverage, YaraCoverageState};
use crate::bloom::{BloomState, IntelGate};
use crate::relationship_contract::{self, RecentYaraHits};
use crate::yara_scan::YaraEngine;

struct ScopeWalk {
    files: Vec<CandidateSnapshot>,
    errors: Vec<HuntScanError>,
    files_discovered: usize,
    files_inconclusive: usize,
    scope_truncated: bool,
    omitted_errors: usize,
}

struct CandidateSnapshot {
    display_path: PathBuf,
    relative_path: PathBuf,
    snapshot: nsic_core::hashing::FileSnapshot,
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
    let scope_root = Dir::open_ambient_dir(&canonical_root, ambient_authority())
        .with_context(|| format!("open authorized hunt root {}", canonical_root.display()))?;
    let candidates = std::mem::take(&mut walked.files);
    for candidate in candidates {
        if let Err(error) = candidate_is_still_bound(&scope_root, &candidate) {
            walked.files_inconclusive += 1;
            push_error(
                &mut walked.errors,
                &mut walked.omitted_errors,
                DEFAULT_MAX_HUNT_ERRORS,
                HuntScanError {
                    path: candidate.display_path.to_string_lossy().to_string(),
                    error: format!("candidate is inconclusive before analysis: {error}"),
                },
            );
            continue;
        }
        let candidate_path = candidate.display_path.clone();
        let expected_size = candidate.snapshot.size_at_open;
        let expected_modified = candidate.snapshot.modified_at_open;
        match relationship_contract::resolve_opened_snapshot_in_intel_snapshot(
            pool,
            bloom,
            yara,
            yara_coverage,
            &observation_scope,
            &candidate_path,
            candidate.snapshot,
        )
        .await
        {
            Ok(resolved) => {
                if let Err(error) = candidate_path_is_still_bound(
                    &scope_root,
                    &candidate.relative_path,
                    expected_size,
                    expected_modified,
                ) {
                    walked.files_inconclusive += 1;
                    push_error(
                        &mut walked.errors,
                        &mut walked.omitted_errors,
                        DEFAULT_MAX_HUNT_ERRORS,
                        HuntScanError {
                            path: candidate_path.to_string_lossy().to_string(),
                            error: format!("candidate is inconclusive after analysis: {error}"),
                        },
                    );
                    continue;
                }
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
                        path: candidate_path.to_string_lossy().to_string(),
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
        "The initial execution scope is a bounded local subtree. Candidates are opened beneath one authorized root without following a final symlink, then hashing and analysis consume that one immutable snapshot."
            .to_string(),
        "The scope is live, while each accepted candidate is analyzed from one immutable snapshot. Replacement, mutation, or boundary uncertainty is inconclusive; no clean-scope claim is made."
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

    let root_handle = Dir::open_ambient_dir(root, ambient_authority())
        .with_context(|| format!("open authorized hunt root {}", root.display()))?;
    let seed_relative = canonical_seed.strip_prefix(root).ok().map(Path::to_path_buf);
    let mut pending = vec![(root_handle, PathBuf::new())];
    let mut walk_entries = 0usize;

    while let Some((directory, directory_relative)) = pending.pop() {
        let mut entries = match directory.entries() {
            Ok(entries) => entries.filter_map(std::result::Result::ok).collect::<Vec<_>>(),
            Err(error) => {
                files_inconclusive += 1;
                push_error(&mut errors, &mut omitted_errors, max_errors, HuntScanError {
                    path: root.join(&directory_relative).to_string_lossy().to_string(),
                    error: format!("enumerate authorized directory handle: {error}"),
                });
                continue;
            }
        };
        entries.sort_by_key(|entry| entry.file_name());
        let mut child_directories = Vec::new();

        for entry in entries {
            if walk_entries >= max_walk_entries {
                scope_truncated = true;
                break;
            }
            walk_entries += 1;
            let relative = directory_relative.join(entry.file_name());
            let display_path = root.join(&relative);
            let file_type = match entry.file_type() {
                Ok(file_type) => file_type,
                Err(error) => {
                    files_inconclusive += 1;
                    push_error(&mut errors, &mut omitted_errors, max_errors, HuntScanError {
                        path: display_path.to_string_lossy().to_string(),
                        error: format!("inspect root-relative directory entry: {error}"),
                    });
                    continue;
                }
            };
            if file_type.is_symlink() {
                continue;
            }
            if file_type.is_dir() {
                match entry.open_dir() {
                    Ok(child) => child_directories.push((child, relative)),
                    Err(error) => {
                        files_inconclusive += 1;
                        push_error(&mut errors, &mut omitted_errors, max_errors, HuntScanError {
                            path: display_path.to_string_lossy().to_string(),
                            error: format!("open child beneath authorized root: {error}"),
                        });
                    }
                }
                continue;
            }
            if !file_type.is_file() || seed_relative.as_ref() == Some(&relative) {
                continue;
            }
            files_discovered += 1;
            if files.len() == max_files {
                scope_truncated = true;
                break;
            }
            let mut options = OpenOptions::new();
            options.read(true).follow(FollowSymlinks::No);
            let opened = match entry.open_with(&options) {
                Ok(file) => file.into_std(),
                Err(error) => {
                    files_inconclusive += 1;
                    push_error(&mut errors, &mut omitted_errors, max_errors, HuntScanError {
                        path: display_path.to_string_lossy().to_string(),
                        error: format!("open candidate from authorized directory handle: {error}"),
                    });
                    continue;
                }
            };
            let snapshot = match crate::hashing::read_opened_snapshot(opened, &display_path) {
                Ok(snapshot) => snapshot,
                Err(error) => {
                    files_inconclusive += 1;
                    push_error(&mut errors, &mut omitted_errors, max_errors, HuntScanError {
                        path: display_path.to_string_lossy().to_string(),
                        error: format!("acquire immutable candidate snapshot: {error}"),
                    });
                    continue;
                }
            };
            files.push(CandidateSnapshot {
                display_path,
                relative_path: relative,
                snapshot,
            });
        }
        if scope_truncated {
            break;
        }
        child_directories.reverse();
        pending.extend(child_directories);
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

fn candidate_is_still_bound(root: &Dir, candidate: &CandidateSnapshot) -> Result<()> {
    candidate_path_is_still_bound(
        root,
        &candidate.relative_path,
        candidate.snapshot.size_at_open,
        candidate.snapshot.modified_at_open,
    )?;
    Ok(())
}

fn candidate_path_is_still_bound(
    root: &Dir,
    relative: &Path,
    expected_size: u64,
    expected_modified: std::time::SystemTime,
) -> Result<()> {
    let metadata = root
        .symlink_metadata(relative)
        .context("root-relative no-follow stability check failed")?;
    if !metadata.is_file()
        || metadata.len() != expected_size
        || metadata.modified()? != expected_modified
    {
        bail!("candidate pathname was replaced or the opened object was mutated");
    }
    Ok(())
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
            .map(|candidate| {
                candidate
                    .display_path
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .to_string()
            })
            .collect();
        assert_eq!(names, vec!["a.bin", "b.bin"]);
        assert_eq!(walked.files_discovered, 3);
        assert!(walked.scope_truncated);
        assert!(!walked.files.iter().any(|candidate| candidate.display_path == seed));
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

    #[cfg(unix)]
    #[test]
    fn final_candidate_replaced_with_external_symlink_is_inconclusive_and_external_is_unread() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        fs::write(outside.path(), b"OUTSIDE-MUST-NEVER-BE-ANALYZED").unwrap();
        let root = temp.path().canonicalize().unwrap();
        let seed = root.join("seed.bin");
        let candidate = root.join("candidate.bin");
        fs::write(&seed, b"seed").unwrap();
        fs::write(&candidate, b"authorized-inside").unwrap();

        let mut walked = collect_scope_files_bounded(&root, &seed, 10, 100, 10).unwrap();
        let acquired = walked.files.pop().unwrap();
        fs::remove_file(&candidate).unwrap();
        symlink(outside.path(), &candidate).unwrap();

        let root_handle = Dir::open_ambient_dir(&root, ambient_authority()).unwrap();
        assert!(candidate_is_still_bound(&root_handle, &acquired).is_err());
        assert_eq!(acquired.snapshot.bytes, b"authorized-inside");
        assert_ne!(acquired.snapshot.bytes, fs::read(outside.path()).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn intermediate_directory_replaced_with_external_symlink_is_inconclusive() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("candidate.bin"), b"outside").unwrap();
        let root = temp.path().canonicalize().unwrap();
        let seed = root.join("seed.bin");
        let nested = root.join("nested");
        fs::create_dir(&nested).unwrap();
        fs::write(&seed, b"seed").unwrap();
        fs::write(nested.join("candidate.bin"), b"inside").unwrap();

        let mut walked = collect_scope_files_bounded(&root, &seed, 10, 100, 10).unwrap();
        let acquired = walked.files.pop().unwrap();
        fs::remove_dir_all(&nested).unwrap();
        symlink(outside.path(), &nested).unwrap();

        let root_handle = Dir::open_ambient_dir(&root, ambient_authority()).unwrap();
        assert!(candidate_is_still_bound(&root_handle, &acquired).is_err());
        assert_eq!(acquired.snapshot.bytes, b"inside");
    }

    #[test]
    fn mutation_between_snapshot_and_analysis_is_inconclusive() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let seed = root.join("seed.bin");
        let candidate = root.join("candidate.bin");
        fs::write(&seed, b"seed").unwrap();
        fs::write(&candidate, b"before").unwrap();

        let mut walked = collect_scope_files_bounded(&root, &seed, 10, 100, 10).unwrap();
        let acquired = walked.files.pop().unwrap();
        fs::write(&candidate, b"mutated-and-longer").unwrap();

        let root_handle = Dir::open_ambient_dir(&root, ambient_authority()).unwrap();
        assert!(candidate_is_still_bound(&root_handle, &acquired).is_err());
        assert_eq!(acquired.snapshot.bytes, b"before");
    }

    #[test]
    fn unchanged_in_scope_regular_file_remains_bound() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let seed = root.join("seed.bin");
        let candidate = root.join("candidate.bin");
        fs::write(&seed, b"seed").unwrap();
        fs::write(&candidate, b"stable").unwrap();

        let mut walked = collect_scope_files_bounded(&root, &seed, 10, 100, 10).unwrap();
        let acquired = walked.files.pop().unwrap();
        let root_handle = Dir::open_ambient_dir(&root, ambient_authority()).unwrap();
        candidate_is_still_bound(&root_handle, &acquired).unwrap();
        assert_eq!(acquired.snapshot.bytes, b"stable");
    }
}
