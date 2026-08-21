//! Local execution adapter for Orion's first relationship pivot.
//!
//! The frontend supplies only an opaque path selector, an expected seed hash,
//! and an explicit subtree root. This module reconstructs the authoritative
//! RELATE/TRACE state under one intel snapshot, validates the selector, walks
//! a bounded non-symlink scope, and classifies only evidence-backed matches.

use anyhow::{bail, Context, Result};
use cap_fs_ext::{DirExt, FollowSymlinks, MetadataExt, OpenOptionsFollowExt};
use cap_std::ambient_authority;
use cap_std::fs::{Dir, OpenOptions};
use chrono::Utc;
use nsic_core::hunt::{
    finding_role, same_hunt_concept, select_hypothesis, HuntBounds, HuntEvidenceRole, HuntFinding,
    HuntRequest, HuntResult, HuntScanError, HuntScope, HuntScopeKind, HuntSummary,
    DEFAULT_MAX_HUNT_ERRORS, DEFAULT_MAX_HUNT_FILES, DEFAULT_MAX_HUNT_FINDINGS,
    DEFAULT_MAX_HUNT_WALK_ENTRIES,
};
use nsic_core::orion::TracePath;
use sqlx::PgPool;
use std::cmp::Ordering;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use crate::analysis_coverage::{YaraCoverage, YaraCoverageState};
use crate::bloom::{BloomState, IntelGate};
use crate::relationship_contract::{self, RecentYaraHits};
use crate::yara_scan::YaraEngine;

struct ScopeWalk {
    root: AuthorizedRoot,
    files: Vec<CandidatePath>,
    errors: Vec<HuntScanError>,
    files_discovered: usize,
    files_inconclusive: usize,
    scope_truncated: bool,
    omitted_errors: usize,
}

struct AuthorizedRoot {
    dir: Dir,
    path: PathBuf,
    identity: ObjectIdentity,
}

impl AuthorizedRoot {
    fn try_clone(&self) -> Result<Self> {
        Ok(Self {
            dir: self.dir.try_clone()?,
            path: self.path.clone(),
            identity: self.identity,
        })
    }

    fn ensure_path_stable(&self) -> Result<()> {
        let metadata = std::fs::symlink_metadata(&self.path)
            .with_context(|| format!("revalidate authorized root {}", self.path.display()))?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || std_metadata_identity(&metadata) != self.identity
        {
            bail!("authorized root pathname was replaced; hunt result is inconclusive");
        }
        Ok(())
    }
}

struct CandidatePath {
    display_path: PathBuf,
    relative_path: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ObjectIdentity {
    device: u64,
    inode: u64,
}

struct OpenedCandidate {
    candidate: CandidatePath,
    file: cap_std::fs::File,
    identity: ObjectIdentity,
    size: u64,
    modified: std::time::SystemTime,
    change: ChangeIdentity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ChangeIdentity {
    changed_seconds: i64,
    changed_nanoseconds: i64,
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
    let requested_root = PathBuf::from(&request.scope.root);
    let root_parent = requested_root
        .parent()
        .context("hunt scope must name a directory")?;
    let root_name = requested_root
        .file_name()
        .context("filesystem-root hunt scopes are not supported")?;
    let root_parent = if root_parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        root_parent
    };
    let canonical_root = tokio::fs::canonicalize(root_parent)
        .await
        .with_context(|| format!("canonicalize hunt scope parent {}", root_parent.display()))?
        .join(root_name);
    let root_metadata = tokio::fs::symlink_metadata(&canonical_root)
        .await
        .with_context(|| format!("stat hunt scope {}", canonical_root.display()))?;
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        bail!(
            "hunt scope {} is not a non-symlink directory",
            canonical_root.display()
        );
    }
    let authorized_seed = if requested_seed.is_absolute() {
        requested_seed.clone()
    } else {
        std::env::current_dir()?.join(&requested_seed)
    };
    if !authorized_seed.starts_with(&canonical_root) {
        bail!(
            "seed {} is outside hunt scope {}",
            authorized_seed.display(),
            canonical_root.display()
        );
    }

    let root_for_walk = canonical_root.clone();
    let seed_for_walk = authorized_seed.clone();
    let seed_relative = authorized_seed
        .strip_prefix(&canonical_root)
        .context("derive root-relative hunt seed")?
        .to_path_buf();
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

    // Bind the seed to the same retained authorized-root capability used by
    // discovery and candidate execution. The resulting immutable snapshot is
    // accepted only while that capability remains bound to the authorized
    // root pathname; replacement is inconclusive before analysis effects.
    let seed_root = walked.root.try_clone()?;
    let seed_display_path = authorized_seed.clone();
    let seed_snapshot = tokio::task::spawn_blocking(move || {
        let seed_opened = open_candidate(
            &seed_root,
            CandidatePath {
                display_path: seed_display_path,
                relative_path: seed_relative,
            },
        )
        .context("open hunt seed through authorized root")?;
        acquire_stable_snapshot(&seed_root, seed_opened)
            .context("acquire stable hunt seed snapshot")
    })
    .await
    .context("hunt seed snapshot task panicked")??;
    walked.root.ensure_path_stable()?;

    // One read guard spans seed reconstruction and every candidate. A feed
    // sync cannot make half the hunt use one corpus and half use another.
    // The specialized resolver below deliberately does not reacquire this
    // fair RwLock, avoiding self-deadlock behind a queued writer.
    let _intel_snapshot = intel_gate.read().await;
    walked.root.ensure_path_stable()?;
    let observation_scope = RecentYaraHits::new();
    let seed =
        relationship_contract::resolve_opened_snapshot_in_intel_snapshot_with_expected_sha256(
            pool,
            bloom,
            yara,
            yara_coverage,
            &observation_scope,
            &authorized_seed,
            seed_snapshot,
            &request.expected_seed_sha256,
        )
        .await
        .with_context(|| format!("re-resolve hunt seed {}", requested_seed.display()))?;
    let hypothesis = select_hypothesis(&seed.orion_trace, &request.trace_path_id)?;

    let mut findings = Vec::new();
    let mut files_analyzed = 0usize;
    let scope_root = walked.root.try_clone()?;
    let candidates = std::mem::take(&mut walked.files);
    for candidate in candidates {
        let candidate_path = candidate.display_path.clone();
        let candidate_root = scope_root.try_clone()?;
        let snapshot = match tokio::task::spawn_blocking(move || {
            let opened = open_candidate(&candidate_root, candidate)?;
            acquire_stable_snapshot(&candidate_root, opened)
        })
        .await
        .context("candidate snapshot task panicked")?
        {
            Ok(snapshot) => snapshot,
            Err(error) => {
                walked.files_inconclusive += 1;
                push_error(
                    &mut walked.errors,
                    &mut walked.omitted_errors,
                    DEFAULT_MAX_HUNT_ERRORS,
                    HuntScanError {
                        path: candidate_path.to_string_lossy().to_string(),
                        error: format!("candidate is inconclusive before analysis: {error}"),
                    },
                );
                continue;
            }
        };
        scope_root.ensure_path_stable()?;
        match relationship_contract::resolve_opened_snapshot_in_intel_snapshot(
            pool,
            bloom,
            yara,
            yara_coverage,
            &observation_scope,
            &candidate_path,
            snapshot,
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

    let expected_root = std::fs::symlink_metadata(root)
        .with_context(|| format!("validate authorized hunt root {}", root.display()))?;
    if expected_root.file_type().is_symlink() || !expected_root.is_dir() {
        bail!("authorized hunt root must be a non-symlink directory");
    }
    let expected_identity = std_metadata_identity(&expected_root);
    let authorized_root = open_authorized_root(root, expected_identity)?;
    let seed_relative = canonical_seed
        .strip_prefix(root)
        .ok()
        .map(Path::to_path_buf);
    let mut pending = vec![(authorized_root.dir.try_clone()?, PathBuf::new())];
    let mut walk_entries = 0usize;

    while let Some((directory, directory_relative)) = pending.pop() {
        let mut entries = match directory.entries() {
            Ok(entries) => {
                let mut collected = Vec::new();
                for entry in entries {
                    match entry {
                        Ok(entry) => collected.push(entry),
                        Err(error) => {
                            files_inconclusive += 1;
                            push_error(
                                &mut errors,
                                &mut omitted_errors,
                                max_errors,
                                HuntScanError {
                                    path: root
                                        .join(&directory_relative)
                                        .to_string_lossy()
                                        .to_string(),
                                    error: format!("enumerate authorized directory entry: {error}"),
                                },
                            );
                        }
                    }
                }
                collected
            }
            Err(error) => {
                files_inconclusive += 1;
                push_error(
                    &mut errors,
                    &mut omitted_errors,
                    max_errors,
                    HuntScanError {
                        path: root.join(&directory_relative).to_string_lossy().to_string(),
                        error: format!("enumerate authorized directory handle: {error}"),
                    },
                );
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
                    push_error(
                        &mut errors,
                        &mut omitted_errors,
                        max_errors,
                        HuntScanError {
                            path: display_path.to_string_lossy().to_string(),
                            error: format!("inspect root-relative directory entry: {error}"),
                        },
                    );
                    continue;
                }
            };
            if file_type.is_symlink() {
                continue;
            }
            if file_type.is_dir() {
                match directory.open_dir_nofollow(entry.file_name()) {
                    Ok(child) => child_directories.push((child, relative)),
                    Err(error) => {
                        files_inconclusive += 1;
                        push_error(
                            &mut errors,
                            &mut omitted_errors,
                            max_errors,
                            HuntScanError {
                                path: display_path.to_string_lossy().to_string(),
                                error: format!("open child beneath authorized root: {error}"),
                            },
                        );
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
            files.push(CandidatePath {
                display_path,
                relative_path: relative,
            });
        }
        if scope_truncated {
            break;
        }
        child_directories.reverse();
        pending.extend(child_directories);
    }

    Ok(ScopeWalk {
        root: authorized_root,
        files,
        errors,
        files_discovered,
        files_inconclusive,
        scope_truncated,
        omitted_errors,
    })
}

fn open_authorized_root(root: &Path, expected_identity: ObjectIdentity) -> Result<AuthorizedRoot> {
    let root_handle = Dir::open_ambient_dir(root, ambient_authority())
        .with_context(|| format!("open authorized hunt root {}", root.display()))?;
    if metadata_identity(&root_handle.dir_metadata()?) != expected_identity {
        bail!("authorized root changed during capability acquisition");
    }
    let authorized_root = AuthorizedRoot {
        dir: root_handle,
        path: root.to_path_buf(),
        identity: expected_identity,
    };
    authorized_root.ensure_path_stable()?;
    Ok(authorized_root)
}

fn open_candidate(root: &AuthorizedRoot, candidate: CandidatePath) -> Result<OpenedCandidate> {
    root.ensure_path_stable()?;
    let (parent, file_name) = open_parent_nofollow(&root.dir, &candidate.relative_path)?;
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    #[cfg(windows)]
    {
        use cap_std::fs::OpenOptionsExt;
        // Permit concurrent readers but deny write/delete sharing while the
        // snapshot is acquired. Windows enforces this lease in the kernel.
        options.share_mode(0x0000_0001);
    }
    let file = parent.open_with(file_name, &options).with_context(|| {
        format!(
            "open {} beneath authorized root",
            candidate.display_path.display()
        )
    })?;
    let metadata = file
        .metadata()
        .with_context(|| format!("fstat {}", candidate.display_path.display()))?;
    if !metadata.is_file() {
        bail!("{} is not a regular file", candidate.display_path.display());
    }
    let std_metadata = file.try_clone()?.into_std().metadata()?;
    Ok(OpenedCandidate {
        candidate,
        identity: metadata_identity(&metadata),
        size: metadata.len(),
        modified: metadata.modified()?.into_std(),
        change: change_identity(&std_metadata),
        file,
    })
}

fn open_parent_nofollow(root: &Dir, relative: &Path) -> Result<(Dir, std::ffi::OsString)> {
    let mut components = relative.components().peekable();
    let mut directory = root.try_clone()?;
    while let Some(component) = components.next() {
        let Component::Normal(name) = component else {
            bail!("candidate path contains a non-normal component");
        };
        if components.peek().is_none() {
            return Ok((directory, name.to_os_string()));
        }
        directory = directory
            .open_dir_nofollow(name)
            .context("open intermediate candidate directory without following links")?;
    }
    bail!("candidate path does not name a file")
}

fn acquire_stable_snapshot(
    root: &AuthorizedRoot,
    opened: OpenedCandidate,
) -> Result<nsic_core::hashing::FileSnapshot> {
    root.ensure_path_stable()?;
    let std_file = opened.file.into_std();
    let proof_file = std_file.try_clone()?;
    if change_identity(&std_file.metadata()?) != opened.change {
        bail!("opened object changed before snapshot acquisition");
    }
    let snapshot = crate::hashing::read_opened_snapshot(std_file, &opened.candidate.display_path)?;
    if change_identity(&proof_file.metadata()?) != opened.change {
        bail!("opened object mutated while its immutable snapshot was acquired");
    }
    if snapshot.size_at_open != opened.size || snapshot.modified_at_open != opened.modified {
        bail!("opened object mutated before its immutable snapshot was acquired");
    }
    root.ensure_path_stable()?;
    let (parent, file_name) = open_parent_nofollow(&root.dir, &opened.candidate.relative_path)?;
    let metadata = parent
        .symlink_metadata(file_name)
        .context("root-relative no-follow stability check failed")?;
    if !metadata.is_file()
        || metadata_identity(&metadata) != opened.identity
        || metadata.len() != opened.size
        || metadata.modified()?.into_std() != opened.modified
    {
        bail!("candidate pathname was replaced or mutated during snapshot acquisition");
    }
    Ok(snapshot)
}

fn metadata_identity(metadata: &cap_std::fs::Metadata) -> ObjectIdentity {
    ObjectIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    }
}

#[cfg(unix)]
fn std_metadata_identity(metadata: &std::fs::Metadata) -> ObjectIdentity {
    use std::os::unix::fs::MetadataExt;
    ObjectIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    }
}

#[cfg(windows)]
fn std_metadata_identity(metadata: &std::fs::Metadata) -> ObjectIdentity {
    use std::os::windows::fs::MetadataExt;
    ObjectIdentity {
        device: metadata.volume_serial_number().unwrap_or(0) as u64,
        inode: metadata.file_index().unwrap_or(0),
    }
}

#[cfg(unix)]
fn change_identity(metadata: &std::fs::Metadata) -> ChangeIdentity {
    use std::os::unix::fs::MetadataExt;
    ChangeIdentity {
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
    }
}

#[cfg(not(unix))]
fn change_identity(_metadata: &std::fs::Metadata) -> ChangeIdentity {
    ChangeIdentity {
        changed_seconds: 0,
        changed_nanoseconds: 0,
    }
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
            .any(|relationship| relationship.kind == target_kind && relationship.target == target)
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

    fn root_relative_path(root: &Path, path: &Path) -> CandidatePath {
        CandidatePath {
            display_path: path.to_path_buf(),
            relative_path: path.strip_prefix(root).unwrap().to_path_buf(),
        }
    }

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
        assert!(!walked
            .files
            .iter()
            .any(|candidate| candidate.display_path == seed));
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
    fn candidate_access_rejects_replaced_authorized_root_path() {
        use std::os::unix::fs::symlink;

        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("authorized-root");
        let moved_root = parent.path().join("original-root");
        let outside = tempfile::tempdir().unwrap();
        fs::create_dir(&root).unwrap();
        let seed = root.join("seed.bin");
        let candidate = root.join("candidate.bin");
        fs::write(&seed, b"seed").unwrap();
        fs::write(&candidate, b"authorized-inside").unwrap();
        fs::write(outside.path().join("candidate.bin"), b"outside").unwrap();

        let canonical_root = root.canonicalize().unwrap();
        let mut walked = collect_scope_files_bounded(&canonical_root, &seed, 10, 100, 10).unwrap();
        let candidate_path = walked.files.pop().unwrap();
        fs::rename(&root, &moved_root).unwrap();
        symlink(outside.path(), &root).unwrap();

        assert!(open_candidate(&walked.root, candidate_path).is_err());
        assert_eq!(fs::read(root.join("candidate.bin")).unwrap(), b"outside");
    }

    #[cfg(unix)]
    #[test]
    fn root_replacement_between_validation_and_capability_acquisition_is_rejected() {
        use std::os::unix::fs::symlink;

        let parent = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let root = parent.path().join("authorized-root");
        let moved_root = parent.path().join("validated-root");
        fs::create_dir(&root).unwrap();
        let validated = fs::symlink_metadata(&root).unwrap();
        let expected_identity = std_metadata_identity(&validated);

        fs::rename(&root, &moved_root).unwrap();
        symlink(outside.path(), &root).unwrap();

        assert!(open_authorized_root(&root, expected_identity).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn final_seed_replaced_with_external_symlink_is_rejected() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let seed = root.join("seed.bin");
        fs::write(&seed, b"authorized-seed").unwrap();
        fs::write(outside.path(), b"external-seed").unwrap();

        let walked = collect_scope_files_bounded(&root, &seed, 10, 100, 10).unwrap();
        fs::remove_file(&seed).unwrap();
        symlink(outside.path(), &seed).unwrap();

        assert!(open_candidate(&walked.root, root_relative_path(&root, &seed)).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn external_seed_with_same_expected_hash_is_still_rejected() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let seed = root.join("seed.bin");
        let expected_bytes = b"same-hash-bytes";
        let expected_sha256 = nsic_core::hashing::hash_bytes(expected_bytes).sha256;
        fs::write(&seed, expected_bytes).unwrap();
        fs::write(outside.path(), expected_bytes).unwrap();
        assert_eq!(
            nsic_core::hashing::hash_bytes(&fs::read(outside.path()).unwrap()).sha256,
            expected_sha256
        );

        let walked = collect_scope_files_bounded(&root, &seed, 10, 100, 10).unwrap();
        fs::remove_file(&seed).unwrap();
        symlink(outside.path(), &seed).unwrap();

        assert!(open_candidate(&walked.root, root_relative_path(&root, &seed)).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn intermediate_seed_directory_replaced_with_external_symlink_is_rejected() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let seed_directory = root.join("seed-directory");
        let seed = seed_directory.join("seed.bin");
        fs::create_dir(&seed_directory).unwrap();
        fs::write(&seed, b"authorized-seed").unwrap();
        fs::write(outside.path().join("seed.bin"), b"external-seed").unwrap();

        let walked = collect_scope_files_bounded(&root, &seed, 10, 100, 10).unwrap();
        fs::remove_dir_all(&seed_directory).unwrap();
        symlink(outside.path(), &seed_directory).unwrap();

        assert!(open_candidate(&walked.root, root_relative_path(&root, &seed)).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn intermediate_seed_directory_replaced_with_in_scope_symlink_is_rejected() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let seed_directory = root.join("seed-directory");
        let alternate = root.join("alternate");
        let seed = seed_directory.join("seed.bin");
        fs::create_dir(&seed_directory).unwrap();
        fs::create_dir(&alternate).unwrap();
        fs::write(&seed, b"authorized-seed").unwrap();
        fs::write(alternate.join("seed.bin"), b"different-seed").unwrap();

        let walked = collect_scope_files_bounded(&root, &seed, 10, 100, 10).unwrap();
        fs::remove_dir_all(&seed_directory).unwrap();
        symlink(&alternate, &seed_directory).unwrap();

        assert!(open_candidate(&walked.root, root_relative_path(&root, &seed)).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn seed_access_rejects_replaced_authorized_root_path() {
        use std::os::unix::fs::symlink;

        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("authorized-root");
        let moved_root = parent.path().join("original-root");
        let outside = tempfile::tempdir().unwrap();
        fs::create_dir(&root).unwrap();
        let seed = root.join("seed.bin");
        fs::write(&seed, b"authorized-seed").unwrap();
        fs::write(outside.path().join("seed.bin"), b"external-seed").unwrap();

        let canonical_root = root.canonicalize().unwrap();
        let walked = collect_scope_files_bounded(&canonical_root, &seed, 10, 100, 10).unwrap();
        fs::rename(&root, &moved_root).unwrap();
        symlink(outside.path(), &root).unwrap();

        assert!(open_candidate(&walked.root, root_relative_path(&canonical_root, &seed),).is_err());
        assert_eq!(fs::read(root.join("seed.bin")).unwrap(), b"external-seed");
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
        let candidate_path = walked.files.pop().unwrap();
        fs::remove_file(&candidate).unwrap();
        symlink(outside.path(), &candidate).unwrap();

        assert!(open_candidate(&walked.root, candidate_path).is_err());
        assert_eq!(
            fs::read(outside.path()).unwrap(),
            b"OUTSIDE-MUST-NEVER-BE-ANALYZED"
        );
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
        let candidate_path = walked.files.pop().unwrap();
        fs::remove_dir_all(&nested).unwrap();
        symlink(outside.path(), &nested).unwrap();

        assert!(open_candidate(&walked.root, candidate_path).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn intermediate_directory_replaced_with_in_scope_symlink_is_inconclusive() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let seed = root.join("seed.bin");
        let nested = root.join("nested");
        let alternate = root.join("alternate");
        fs::create_dir(&nested).unwrap();
        fs::create_dir(&alternate).unwrap();
        fs::write(&seed, b"seed").unwrap();
        fs::write(nested.join("candidate.bin"), b"inside").unwrap();
        fs::write(alternate.join("candidate.bin"), b"different-inside").unwrap();

        let mut walked = collect_scope_files_bounded(&root, &seed, 10, 100, 10).unwrap();
        let candidate_path = walked.files.pop().unwrap();
        fs::remove_dir_all(&nested).unwrap();
        symlink(&alternate, &nested).unwrap();

        assert!(open_candidate(&walked.root, candidate_path).is_err());
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
        let candidate_path = walked.files.pop().unwrap();
        let opened = open_candidate(&walked.root, candidate_path).unwrap();
        fs::write(&candidate, b"mutated-and-longer").unwrap();

        assert!(acquire_stable_snapshot(&walked.root, opened).is_err());
    }

    #[test]
    fn same_size_same_mtime_replacement_is_inconclusive_by_object_identity() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let seed = root.join("seed.bin");
        let candidate = root.join("candidate.bin");
        fs::write(&seed, b"seed").unwrap();
        fs::write(&candidate, b"before").unwrap();

        let mut walked = collect_scope_files_bounded(&root, &seed, 10, 100, 10).unwrap();
        let candidate_path = walked.files.pop().unwrap();
        let opened = open_candidate(&walked.root, candidate_path).unwrap();
        let original_modified = opened.modified;
        fs::remove_file(&candidate).unwrap();
        fs::write(&candidate, b"after!").unwrap();
        std::fs::File::open(&candidate)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(original_modified))
            .unwrap();

        assert!(acquire_stable_snapshot(&walked.root, opened).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn same_inode_mutation_with_restored_size_and_mtime_is_inconclusive() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let seed = root.join("seed.bin");
        let candidate = root.join("candidate.bin");
        fs::write(&seed, b"seed").unwrap();
        fs::write(&candidate, b"before").unwrap();

        let mut walked = collect_scope_files_bounded(&root, &seed, 10, 100, 10).unwrap();
        let candidate_path = walked.files.pop().unwrap();
        let opened = open_candidate(&walked.root, candidate_path).unwrap();
        let original_modified = opened.modified;
        fs::write(&candidate, b"after!").unwrap();
        std::fs::File::open(&candidate)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(original_modified))
            .unwrap();

        assert!(acquire_stable_snapshot(&walked.root, opened).is_err());
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
        let candidate_path = walked.files.pop().unwrap();
        let opened = open_candidate(&walked.root, candidate_path).unwrap();
        let snapshot = acquire_stable_snapshot(&walked.root, opened).unwrap();
        assert_eq!(snapshot.bytes, b"stable");
    }
}
