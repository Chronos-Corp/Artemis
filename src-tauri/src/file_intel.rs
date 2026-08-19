//! The File Intelligence Model (Artemis Product Constitution §6): answers "what is
//! this file, and what is it for," independent of the threat-intel graph.
//! `verdict::resolve` answers "is this file threat-relevant"; this module
//! answers the FILE and UNDERSTAND stages of the interaction loop that
//! come before RELATE. Deliberately does not touch Postgres or the intel
//! graph at all -- every signal here comes from the local filesystem and
//! the OS package manager, so it stays available even when the intel
//! database is unreachable (see `commands::db_unavailable`).
//!
//! Purpose-source hierarchy (Artemis Product Constitution §6, HYPOTHESIS): prefer
//! deterministic, curated sources before any model-only classification.
//! This module only implements the deterministic tier -- OS package-manager
//! catalogs -- and reports `Unknown` honestly when no such source applies,
//! rather than guessing.
//!
//! v1 scope: only Debian/Ubuntu's `dpkg` is implemented, since that's the
//! package manager on every environment this codebase currently tests
//! against (this sandbox and `ubuntu-latest` in CI). `rpm`-based systems,
//! macOS, and Windows all fall back to `AuthenticityStatus::Unknown`
//! rather than a guess -- extending package-manager support is future
//! work, not something to fake for platforms nothing here can verify.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileIdentity {
    pub file_type: String,
    pub extension: Option<String>,
    /// Unix dotfile convention only -- there is no portable, dependency-free
    /// way to read the Windows/NTFS hidden attribute, and this desktop app
    /// currently only ships for Linux/macOS (see README "Locked architecture
    /// decisions" #4). A leading-dot check is meaningful on both.
    pub is_hidden: bool,
    pub is_executable: bool,
    /// True when the selected path itself (not some ancestor directory) is
    /// a symlink. Kept as part of Identity rather than silently resolved
    /// away, because a symlink's own location and name are a real part of
    /// what it is -- see `dpkg_lookup`'s doc comment for why package
    /// ownership must never be attributed through this boundary.
    pub is_symlink: bool,
    /// The symlink's literal target, unresolved (i.e. exactly what
    /// `readlink` returns), when `is_symlink` is true.
    pub symlink_target: Option<String>,
    pub created: Option<DateTime<Utc>>,
    pub modified: Option<DateTime<Utc>>,
    pub accessed: Option<DateTime<Utc>>,
}

// ---------------------------------------------------------------------
// Authenticity / Product context
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthenticityStatus {
    /// The owning package's recorded checksum matches the file on disk.
    Verified,
    /// A package claims this path, but the on-disk content no longer
    /// matches the checksum recorded at install time.
    Modified,
    /// No installed package claims this path. Common and unremarkable on
    /// its own -- most user-installed, hand-built, or downloaded software
    /// is unpackaged -- so this alone is not a red flag.
    Unpackaged,
    /// No supported package manager is available on this platform, or the
    /// lookup itself failed (e.g. permissions). Distinguished from
    /// `Unpackaged` because it carries no signal at all, positive or
    /// negative.
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileAuthenticity {
    pub status: AuthenticityStatus,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProductContext {
    pub package: Option<String>,
    pub version: Option<String>,
    pub vendor: Option<String>,
    /// The package's short description (dpkg's `Description` field, first
    /// line only -- the extended multi-line body is discarded). This is
    /// package-level ("GNU core utilities"), not necessarily specific to
    /// this individual file's own role within the package -- `derive_purpose`
    /// words its summary to make that distinction explicit rather than
    /// implying Artemis identified this exact file's function.
    pub description: Option<String>,
}

// ---------------------------------------------------------------------
// Purpose
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PurposeSource {
    PackageCatalog,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilePurpose {
    pub summary: String,
    pub source: PurposeSource,
}

// ---------------------------------------------------------------------
// Expectedness
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpectednessStatus {
    Expected,
    Unexpected,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileExpectedness {
    pub status: ExpectednessStatus,
    pub reasons: Vec<String>,
}

// ---------------------------------------------------------------------
// Local context
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalContext {
    /// Files in the same directory, this file excluded. Single directory
    /// level only -- a recursive scope-wide search is the Recursive Hunt
    /// Engine's job (Artemis Product Constitution §8 / PR #20), not this module's.
    pub sibling_count: usize,
    /// Other filenames in the same directory that are suspiciously close
    /// to this one (near-miss casing, digit-for-letter substitution,
    /// stray characters) -- a classic masquerading signal, e.g. `svchost.exe`
    /// next to `svch0st.exe`.
    pub similarly_named_siblings: Vec<String>,
    /// False when the parent directory could not be listed at all
    /// (permission denied, vanished mid-scan, or has no parent). Exists so
    /// "we could not check" stays distinguishable from "we checked and
    /// found nothing" -- an empty `similarly_named_siblings` means
    /// something different depending on which of those actually happened,
    /// and `derive_expectedness` treats them differently.
    pub available: bool,
}

// ---------------------------------------------------------------------
// Aggregate
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileIntelligence {
    pub identity: FileIdentity,
    pub authenticity: FileAuthenticity,
    pub product_context: ProductContext,
    pub purpose: FilePurpose,
    pub expectedness: FileExpectedness,
    pub local_context: LocalContext,
}

/// Resolves the full File Intelligence Object for one path. Entirely local
/// and DB-free: metadata, a bounded content sniff, a single package-manager
/// lookup, and a single-level directory listing.
pub async fn resolve(path: &Path) -> Result<FileIntelligence> {
    let meta = tokio::fs::metadata(path)
        .await
        .with_context(|| format!("stat {}", path.display()))?;

    let file_type = sniff_path(path).await?;
    let symlink_meta = tokio::fs::symlink_metadata(path).await.ok();
    let is_symlink = symlink_meta
        .as_ref()
        .is_some_and(|m| m.file_type().is_symlink());
    let symlink_target = if is_symlink {
        tokio::fs::read_link(path)
            .await
            .ok()
            .map(|t| t.to_string_lossy().to_string())
    } else {
        None
    };
    let identity = build_identity(
        path,
        &meta,
        symlink_meta.as_ref(),
        file_type,
        is_symlink,
        symlink_target,
    );

    let path_owned = path.to_path_buf();
    let (authenticity, product_context) = tokio::task::spawn_blocking(move || {
        dpkg_lookup(&path_owned, is_symlink).unwrap_or_else(|| {
            (
                FileAuthenticity {
                    status: AuthenticityStatus::Unknown,
                    detail: Some("no supported package manager found on this platform".into()),
                },
                ProductContext::default(),
            )
        })
    })
    .await
    .context("package lookup task panicked")?;

    let purpose = derive_purpose(&product_context);
    let local_context = build_local_context(path).await?;
    let expectedness = derive_expectedness(&identity, &authenticity, &local_context);

    Ok(FileIntelligence {
        identity,
        authenticity,
        product_context,
        purpose,
        expectedness,
        local_context,
    })
}

fn build_identity(
    path: &Path,
    meta: &std::fs::Metadata,
    symlink_meta: Option<&std::fs::Metadata>,
    file_type: String,
    is_symlink: bool,
    symlink_target: Option<String>,
) -> FileIdentity {
    let extension = path.extension().map(|e| e.to_string_lossy().to_lowercase());
    let is_hidden = path
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.starts_with('.'));

    // `is_executable` intentionally still comes from `meta` (which follows
    // the symlink) even for a symlink -- whether running the selected path
    // executes something is a fact about the resolved target, and a
    // symlink's own permission bits are meaningless on Linux (always shown
    // as rwxrwxrwx regardless of the target's real mode).
    #[cfg(unix)]
    let is_executable = {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o111 != 0
    };
    #[cfg(not(unix))]
    let is_executable = extension
        .as_deref()
        .is_some_and(|e| matches!(e, "exe" | "bat" | "cmd" | "com" | "ps1" | "msi"));

    // Identity timestamps must describe the *selected* artifact, not
    // whatever it happens to point at. A follow-up review caught this
    // live: `meta` (which follows the final symlink) made a symlink
    // created moments ago report its target's timestamps -- a symlink to
    // a year-2000-mtime file looked "modified" in 2000, not today, which
    // is exactly the kind of identity/history misstatement that matters
    // for incident-response context.
    let timestamps = if is_symlink {
        symlink_meta.unwrap_or(meta)
    } else {
        meta
    };

    FileIdentity {
        file_type,
        extension,
        is_hidden,
        is_executable,
        is_symlink,
        symlink_target,
        created: timestamps.created().ok().map(Into::into),
        modified: timestamps.modified().ok().map(Into::into),
        accessed: timestamps.accessed().ok().map(Into::into),
    }
}

async fn sniff_path(path: &Path) -> Result<String> {
    use tokio::io::AsyncReadExt;
    let mut file = tokio::fs::File::open(path)
        .await
        .with_context(|| format!("open {} for type sniffing", path.display()))?;
    let mut buf = [0u8; 512];
    // A read error is not evidence the file is empty -- propagate it
    // rather than silently reporting "Empty file" for what might be a
    // permission error or a mid-read I/O failure (a follow-up review
    // caught this: the previous `.unwrap_or(0)` here made those
    // indistinguishable). A genuinely empty file still reads `Ok(0)`
    // without error, so `sniff_file_type(&[])` -> "Empty file" is
    // unaffected for the real empty-file case.
    let n = file
        .read(&mut buf)
        .await
        .with_context(|| format!("read {} for type sniffing", path.display()))?;
    Ok(sniff_file_type(&buf[..n]))
}

/// Identifies a file's type from its leading bytes. Pure and dependency-free
/// on purpose: this is Artemis's own deterministic first tier, not a wrapper
/// around a third-party magic-number database.
pub(crate) fn sniff_file_type(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "Empty file".to_string();
    }
    if bytes.len() >= 4 && &bytes[0..4] == b"\x7fELF" {
        return "ELF executable/library".to_string();
    }
    if bytes.len() >= 2 && &bytes[0..2] == b"MZ" {
        return "Windows PE executable".to_string();
    }
    const MACHO_MAGICS: [[u8; 4]; 4] = [
        [0xFE, 0xED, 0xFA, 0xCE],
        [0xCE, 0xFA, 0xED, 0xFE],
        [0xFE, 0xED, 0xFA, 0xCF],
        [0xCF, 0xFA, 0xED, 0xFE],
    ];
    if bytes.len() >= 4 && MACHO_MAGICS.contains(&bytes[0..4].try_into().unwrap()) {
        return "Mach-O executable/library".to_string();
    }
    if bytes.len() >= 4 && bytes[0..4] == [0xCA, 0xFE, 0xBA, 0xBE] {
        // 0xCAFEBABE is shared between Mach-O universal binaries and Java
        // class files; disambiguating reliably needs more than the magic
        // number (a fat binary's next field is a small arch count, a class
        // file's is a major version, and both ranges overlap in practice).
        // Report both possibilities rather than silently guessing one.
        return "Mach-O universal binary or Java class file (ambiguous magic)".to_string();
    }
    if let Some(interpreter) = parse_shebang(bytes) {
        return format!("Script ({interpreter})");
    }
    if bytes.len() >= 4 && &bytes[0..4] == b"PK\x03\x04" {
        return "ZIP-family archive (zip/jar/apk/docx/xlsx/...)".to_string();
    }
    if bytes.len() >= 2 && bytes[0..2] == [0x1F, 0x8B] {
        return "gzip archive".to_string();
    }
    if bytes.len() >= 4 && &bytes[0..4] == b"%PDF" {
        return "PDF document".to_string();
    }
    if is_mostly_printable(bytes) {
        return "Text data".to_string();
    }
    "Unknown binary data".to_string()
}

/// Extracts the interpreter from a shebang line (`#!/bin/bash`,
/// `#!/usr/bin/env python3`), stripping a leading `env` wrapper so the
/// reported name is the actual interpreter rather than always "env".
fn parse_shebang(bytes: &[u8]) -> Option<String> {
    if !bytes.starts_with(b"#!") {
        return None;
    }
    let line_end = bytes
        .iter()
        .position(|&b| b == b'\n')
        .unwrap_or(bytes.len());
    let line = std::str::from_utf8(&bytes[2..line_end]).ok()?.trim();
    let mut parts = line.split_whitespace();
    let mut first = parts.next()?;
    if first.ends_with("/env") || first == "env" {
        first = parts.next().unwrap_or(first);
    }
    let interpreter = first.rsplit('/').next().unwrap_or(first);
    if interpreter.is_empty() {
        None
    } else {
        Some(interpreter.to_string())
    }
}

fn is_mostly_printable(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return true;
    }
    let printable = bytes
        .iter()
        .filter(|&&b| b == b'\n' || b == b'\r' || b == b'\t' || (0x20..0x7f).contains(&b))
        .count();
    (printable as f64 / bytes.len() as f64) > 0.95
}

// ---------------------------------------------------------------------
// dpkg-backed authenticity / product context
// ---------------------------------------------------------------------

/// Resolves the path to query dpkg's ownership database with, without ever
/// resolving a symlink at the *final* path component. A symlinked *parent*
/// directory (e.g. Ubuntu's `/bin` -> `/usr/bin`) is still safe to
/// normalize, since dpkg's manifest stores canonical paths and that's just
/// a different spelling of the same file, not a different file.
///
/// This distinction is the fix for a real bug a follow-up review caught:
/// canonicalizing the whole path before the ownership lookup meant a
/// symlink like `/tmp/update-service -> /usr/bin/ls` inherited coreutils'
/// package identity and a matching checksum, reporting `Verified`/
/// `Expected` for a path no package actually owns. `dpkg -S` on the
/// literal symlink path correctly reports "not found" for a path like
/// that (confirmed live in this sandbox) -- the bug was entirely in
/// resolving the symlink away before ever asking.
pub(crate) fn ownership_lookup_path(path: &Path, is_symlink: bool) -> PathBuf {
    if !is_symlink {
        return std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    }
    match (path.parent(), path.file_name()) {
        (Some(parent), Some(name)) if !parent.as_os_str().is_empty() => {
            std::fs::canonicalize(parent)
                .map(|p| p.join(name))
                .unwrap_or_else(|_| path.to_path_buf())
        }
        _ => path.to_path_buf(),
    }
}

/// Runs the dpkg lookup chain for one path: which package (if any) owns
/// it, that package's version/maintainer/description, and whether the
/// on-disk content still matches the checksum dpkg recorded at install
/// time. Synchronous (spawns processes and reads files); callers run this
/// on the blocking pool. Returns `None` if `dpkg` itself is not present on
/// this system -- distinct from `dpkg` running and reporting "not owned by
/// any package."
fn dpkg_lookup(path: &Path, is_symlink: bool) -> Option<(FileAuthenticity, ProductContext)> {
    let lookup_path = ownership_lookup_path(path, is_symlink);
    let path_str = lookup_path.to_string_lossy().to_string();

    let search = std::process::Command::new("dpkg")
        .arg("-S")
        .arg(&path_str)
        .output();
    let search = match search {
        Ok(output) => output,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(_) => return None,
    };

    let package = match classify_dpkg_search(
        search.status.code(),
        &String::from_utf8_lossy(&search.stdout),
        &String::from_utf8_lossy(&search.stderr),
        &path_str,
    ) {
        DpkgSearchOutcome::Owned(package) => package,
        DpkgSearchOutcome::Unowned => {
            return Some((
                FileAuthenticity {
                    status: AuthenticityStatus::Unpackaged,
                    detail: Some("no installed package owns this path".into()),
                },
                ProductContext::default(),
            ));
        }
        DpkgSearchOutcome::LookupFailed(detail) => {
            return Some((
                FileAuthenticity {
                    status: AuthenticityStatus::Unknown,
                    detail: Some(detail),
                },
                ProductContext::default(),
            ));
        }
    };

    let query = std::process::Command::new("dpkg-query")
        .arg("-W")
        .arg("-f=${Version}\t${Maintainer}\n")
        .arg(&package)
        .output()
        .ok();
    let (version, vendor) = query
        .filter(|o| o.status.success())
        .map(|o| parse_dpkg_query_output(&String::from_utf8_lossy(&o.stdout)))
        .unwrap_or((None, None));

    let description = std::process::Command::new("dpkg-query")
        .arg("-W")
        .arg("-f=${Description}\n")
        .arg(&package)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| parse_dpkg_description(&String::from_utf8_lossy(&o.stdout)));

    let product_context = ProductContext {
        package: Some(package.clone()),
        version,
        vendor,
        description,
    };

    // Checksum verification reads the *selected* path's content -- letting
    // a plain file read follow a symlink to its target is normal, correct
    // I/O (this is about which bytes exist at this location, not a trust
    // decision), whereas the ownership lookup above deliberately does not
    // resolve a symlink at the final component.
    let authenticity = verify_dpkg_checksum(&package, path, &path_str);
    Some((authenticity, product_context))
}

/// What a `dpkg -S` invocation resolved to, before any process-spawning is
/// involved -- kept separate from `dpkg_lookup` specifically so the exit-
/// code classification can be unit-tested with simulated codes rather than
/// requiring a real dpkg database to exercise (a follow-up review's own
/// suggestion).
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum DpkgSearchOutcome {
    Owned(String),
    Unowned,
    LookupFailed(String),
}

/// Classifies a completed `dpkg -S` invocation per `dpkg-query(1)`'s
/// documented exit-status contract: 0 is success, 1 is the *documented*
/// "no file/package found" negative result, and anything else (2, or a
/// signal with no exit code at all) is a fatal/unrecoverable query error
/// -- database inaccessible or corrupt, out-of-memory, invalid invocation.
/// A follow-up review caught that the previous version of this code
/// collapsed every non-success exit into `Unpackaged`, misreporting a
/// failed lookup ("we don't know") as a real negative result ("we know
/// this isn't package-owned"). Absence of evidence is not evidence of
/// absence.
fn classify_dpkg_search(
    status_code: Option<i32>,
    stdout: &str,
    stderr: &str,
    path: &str,
) -> DpkgSearchOutcome {
    match status_code {
        Some(0) => match parse_dpkg_search_output(stdout, path) {
            Some(package) => DpkgSearchOutcome::Owned(package),
            // Exit 0 but no line exactly matches the queried path -- dpkg's
            // own glob matching found something, but not the exact file we
            // asked about (see `parse_dpkg_search_output`'s doc comment).
            // Still a real negative result, not a failure.
            None => DpkgSearchOutcome::Unowned,
        },
        Some(1) => DpkgSearchOutcome::Unowned,
        other => DpkgSearchOutcome::LookupFailed(format!(
            "dpkg -S exited with {} querying the package database -- {}",
            other
                .map(|c| c.to_string())
                .unwrap_or_else(|| "no exit code (killed by a signal)".to_string()),
            stderr.trim()
        )),
    }
}

/// Parses `dpkg -S <path>` output: lines of `package[:arch]: /abs/path`,
/// possibly several when multiple packages divert the same path. Takes the
/// first, which is what dpkg itself treats as authoritative.
/// `dpkg -S` performs its own glob-style pattern matching on the queried
/// string -- `*`, `?`, `[`, and `\` are all pattern metacharacters to it,
/// and all are legal characters in a real filename. Confirmed live: a
/// literal query of `/usr/bin/*` returns dozens of unrelated real
/// packages, not "not found." Without an exact-path check, a selected
/// file whose name happens to contain one of those characters could match
/// a *different* installed file's manifest entry, and Artemis would
/// attribute that other file's package/version/description as this one's
/// Product Context and Purpose -- a real misattribution, not just a
/// missed match. `path` is the literal path that was queried; only a line
/// whose reported path is byte-for-byte identical to it is accepted.
fn parse_dpkg_search_output(stdout: &str, path: &str) -> Option<String> {
    for line in stdout.lines() {
        // "pkgname[:arch]: /absolute/path" -- split on ": " (colon-space),
        // not a bare colon, since a multi-arch package's own name already
        // contains one colon (e.g. "libc6:amd64") before the real
        // separator.
        let Some((pkg, reported_path)) = line.split_once(": ") else {
            continue;
        };
        if reported_path.trim() != path {
            continue;
        }
        let pkg = pkg.trim();
        if !pkg.is_empty() {
            return Some(pkg.to_string());
        }
    }
    None
}

/// Parses `dpkg-query -W -f='${Version}\t${Maintainer}\n' <pkg>` output.
fn parse_dpkg_query_output(stdout: &str) -> (Option<String>, Option<String>) {
    let line = stdout.lines().next().unwrap_or("");
    let mut parts = line.splitn(2, '\t');
    let version = parts.next().map(str::trim).filter(|s| !s.is_empty());
    let vendor = parts.next().map(str::trim).filter(|s| !s.is_empty());
    (version.map(str::to_string), vendor.map(str::to_string))
}

/// Parses `dpkg-query -W -f='${Description}\n' <pkg>` output. dpkg's
/// `Description` field is multi-line -- a short summary on the first line,
/// then an extended body with each line prefixed by a space (Debian
/// control-file convention). Only the first line is a real short
/// description; the rest is discarded rather than folded into a
/// one-sentence purpose summary.
fn parse_dpkg_description(stdout: &str) -> Option<String> {
    let first_line = stdout.lines().next()?.trim();
    if first_line.is_empty() {
        None
    } else {
        Some(first_line.to_string())
    }
}

/// Compares the file's current MD5 against the checksum dpkg recorded at
/// install time in `/var/lib/dpkg/info/<pkg>.md5sums`. That file is a
/// dpkg-maintained artifact of any Debian/Ubuntu install, so this needs no
/// extra tooling (`debsums` is not installed in this sandbox or on
/// `ubuntu-latest`, so this deliberately does not depend on it).
///
/// `content_path` is deliberately the *selected* path (not a canonicalized
/// one) -- reading its content follows a symlink naturally if it is one,
/// which is correct here (this is "what bytes exist at this location,"
/// not the ownership-attribution question `ownership_lookup_path` guards).
fn verify_dpkg_checksum(package: &str, content_path: &Path, path_str: &str) -> FileAuthenticity {
    let candidates = [
        PathBuf::from(format!("/var/lib/dpkg/info/{package}.md5sums")),
        // Multi-arch packages are recorded as e.g. "libc6:amd64" by
        // `dpkg -S` but the info file drops the arch suffix.
        PathBuf::from(format!(
            "/var/lib/dpkg/info/{}.md5sums",
            package.split(':').next().unwrap_or(package)
        )),
    ];
    let Some(md5sums) = candidates
        .iter()
        .find_map(|p| std::fs::read_to_string(p).ok())
    else {
        return FileAuthenticity {
            status: AuthenticityStatus::Unknown,
            detail: Some(format!(
                "package '{package}' owns this path but no md5sums record was found for it"
            )),
        };
    };

    let relative = path_str.trim_start_matches('/');
    let Some(recorded_md5) = parse_md5sums_file(&md5sums, relative) else {
        return FileAuthenticity {
            status: AuthenticityStatus::Unknown,
            detail: Some(format!(
                "package '{package}' has no recorded checksum for this exact path"
            )),
        };
    };

    let actual = std::process::Command::new("md5sum")
        .arg(content_path)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| {
            String::from_utf8_lossy(&o.stdout)
                .split_whitespace()
                .next()
                .map(str::to_string)
        });

    compare_checksums(package, &recorded_md5, actual.as_deref())
}

/// Decides what a recorded-vs-actual checksum comparison means. Pulled out
/// of `verify_dpkg_checksum` as its own pure function specifically so the
/// `Modified` (mismatch) branch can be unit-tested directly -- a follow-up
/// review noted the previous test claiming to cover this branch didn't
/// actually exercise it, and constructing a real mismatched dpkg
/// environment isn't safe to do against this sandbox's actual
/// `/var/lib/dpkg/info` (real, root-owned system state).
fn compare_checksums(
    package: &str,
    recorded_md5: &str,
    actual_md5: Option<&str>,
) -> FileAuthenticity {
    match actual_md5 {
        Some(actual) if actual.eq_ignore_ascii_case(recorded_md5) => FileAuthenticity {
            status: AuthenticityStatus::Verified,
            detail: Some(format!("matches the checksum recorded by '{package}'")),
        },
        Some(_) => FileAuthenticity {
            status: AuthenticityStatus::Modified,
            detail: Some(format!(
                "content no longer matches the checksum '{package}' recorded at install time"
            )),
        },
        None => FileAuthenticity {
            status: AuthenticityStatus::Unknown,
            detail: Some(
                "could not compute a checksum to compare against the package record".into(),
            ),
        },
    }
}

/// Parses a dpkg `.md5sums` file: lines of `<md5>␠␠<path-relative-to-root>`.
fn parse_md5sums_file(contents: &str, relative_path: &str) -> Option<String> {
    for line in contents.lines() {
        let mut parts = line.splitn(2, char::is_whitespace);
        let md5 = parts.next()?.trim();
        let path = parts.next()?.trim();
        if path == relative_path {
            return Some(md5.to_string());
        }
    }
    None
}

// ---------------------------------------------------------------------
// Purpose
// ---------------------------------------------------------------------

fn derive_purpose(product_context: &ProductContext) -> FilePurpose {
    match (&product_context.package, &product_context.description) {
        // A real package description is genuine purpose content (what the
        // package normally does), not just product-context metadata --
        // but it describes the package as a whole, not necessarily this
        // specific file's individual role within it, so the summary says
        // so explicitly rather than implying Artemis identified this exact
        // file's function. A follow-up review caught the previous version
        // of this function synthesizing a purpose-shaped sentence purely
        // from the package *name*, with no actual description text behind
        // it, while still claiming `PurposeSource::PackageCatalog`.
        (Some(package), Some(description)) => FilePurpose {
            summary: format!(
                "Part of the '{package}' package: {description}. This describes the package \
                 as a whole, not necessarily this specific file's individual role within it."
            ),
            source: PurposeSource::PackageCatalog,
        },
        // Package identity without a description is product context, not
        // purpose -- there is no genuine "what does this do" content to
        // report, so this is `Unknown`, not `PackageCatalog`.
        (Some(package), None) => FilePurpose {
            summary: format!(
                "Installed as part of the '{package}' package; no package description was \
                 available to describe its purpose."
            ),
            source: PurposeSource::Unknown,
        },
        (None, _) => FilePurpose {
            summary: "No package catalog entry matched this artifact; purpose is unknown."
                .to_string(),
            source: PurposeSource::Unknown,
        },
    }
}

// ---------------------------------------------------------------------
// Local context
// ---------------------------------------------------------------------

async fn build_local_context(path: &Path) -> Result<LocalContext> {
    let Some(parent) = path.parent() else {
        return Ok(LocalContext {
            sibling_count: 0,
            similarly_named_siblings: Vec::new(),
            available: false,
        });
    };
    let Some(target_name) = path.file_name().and_then(|n| n.to_str()) else {
        return Ok(LocalContext {
            sibling_count: 0,
            similarly_named_siblings: Vec::new(),
            available: false,
        });
    };

    // Distinguishes "the directory could not be listed at all" (available
    // stays false) from "listed successfully but iteration hit a
    // transient per-entry error partway through" (available stays true --
    // whatever was collected before the error is still real data, unlike
    // never having listed anything). A follow-up review noted the
    // previous version made both of these indistinguishable from "listed
    // successfully, found nothing."
    let mut sibling_names = Vec::new();
    let available = match tokio::fs::read_dir(parent).await {
        Ok(mut read_dir) => {
            loop {
                match read_dir.next_entry().await {
                    Ok(Some(entry)) => {
                        let name = entry.file_name().to_string_lossy().to_string();
                        if name != target_name {
                            sibling_names.push(name);
                        }
                    }
                    Ok(None) => break,
                    Err(_) => break,
                }
            }
            true
        }
        Err(_) => false,
    };

    let similarly_named_siblings = find_similarly_named(target_name, &sibling_names);
    Ok(LocalContext {
        sibling_count: sibling_names.len(),
        similarly_named_siblings,
        available,
    })
}

/// Below this length, a small edit distance is meaningless as a
/// masquerading signal -- e.g. `/usr/bin` alone has 44 filenames within
/// edit distance 2 of "ls" (`rm`, `cp`, `ps`, `w`, ...), because almost
/// any short string is "close" to any other short string. Realistic
/// masquerading targets (`svchost.exe`, `explorer.exe`, `lsass.exe`) are
/// all comfortably longer than this.
const MIN_MASQUERADE_NAME_LEN: usize = 5;

/// Flags sibling filenames within a small edit-distance window of the
/// target -- close enough to be a plausible masquerade (case swap,
/// digit-for-letter substitution, stray character) but never identical
/// (the filesystem already guarantees no two siblings share a name).
pub(crate) fn find_similarly_named(target_name: &str, sibling_names: &[String]) -> Vec<String> {
    let target_lower = target_name.to_lowercase();
    if target_lower.chars().count() < MIN_MASQUERADE_NAME_LEN {
        return Vec::new();
    }
    sibling_names
        .iter()
        .filter(|name| {
            let name_lower = name.to_lowercase();
            if name_lower.chars().count() < MIN_MASQUERADE_NAME_LEN {
                return false;
            }
            let distance = levenshtein(&target_lower, &name_lower);
            (1..=2).contains(&distance)
        })
        .cloned()
        .collect()
}

/// Classic dynamic-programming Levenshtein distance. Small, pure, and
/// self-contained rather than a dependency -- this is only ever run
/// against filenames within a single directory listing.
pub(crate) fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let (la, lb) = (a.len(), b.len());
    let mut row: Vec<usize> = (0..=lb).collect();

    for i in 1..=la {
        let mut prev_diag = row[0];
        row[0] = i;
        for j in 1..=lb {
            let cost = if a[i - 1] == b[j - 1] { 0 } else { 1 };
            let deletion = row[j] + 1;
            let insertion = row[j - 1] + 1;
            let substitution = prev_diag + cost;
            prev_diag = row[j];
            row[j] = deletion.min(insertion).min(substitution);
        }
    }
    row[lb]
}

// ---------------------------------------------------------------------
// Expectedness
// ---------------------------------------------------------------------

fn derive_expectedness(
    identity: &FileIdentity,
    authenticity: &FileAuthenticity,
    local: &LocalContext,
) -> FileExpectedness {
    // Checksum mismatch is the strongest, most direct negative signal
    // available -- it always wins regardless of anything else.
    if authenticity.status == AuthenticityStatus::Modified {
        return FileExpectedness {
            status: ExpectednessStatus::Unexpected,
            reasons: vec![
                "Content differs from the owning package's recorded checksum.".to_string(),
            ],
        };
    }

    let mut unexpected_reasons = Vec::new();

    // A same-directory name-similarity match is weak, contextual evidence
    // -- it must not override a Verified checksum, which is direct,
    // corroborated evidence. Legitimate tool families genuinely sit within
    // edit distance 1-2 of each other -- `mount`/`umount` and
    // `expand`/`unexpand`, both pairs owned by the same real package,
    // confirmed live in this sandbox -- so a review caught that the
    // previous version of this function let that weak signal override
    // `Verified` unconditionally. Only surface it as a reason for
    // `Unexpected` when there is no stronger, direct evidence already
    // saying otherwise.
    if authenticity.status != AuthenticityStatus::Verified
        && identity.is_executable
        && !local.similarly_named_siblings.is_empty()
    {
        unexpected_reasons.push(format!(
            "Filename closely resembles other files in the same directory (possible masquerading): {}.",
            local.similarly_named_siblings.join(", ")
        ));
    }
    // Same reasoning as the masquerading check above, and for the same
    // reason a follow-up review gave: `Verified` here doesn't just mean
    // "these bytes happen to match some checksum somewhere" -- it means
    // `dpkg -S` says the *exact selected path* is package-owned, and that
    // exact path's recorded checksum matches. If a package legitimately
    // ships an executable dotfile at that exact path, hiddenness alone
    // must not override that direct package/path evidence, any more than
    // a same-directory name collision should.
    if authenticity.status != AuthenticityStatus::Verified
        && identity.is_hidden
        && identity.is_executable
    {
        unexpected_reasons.push("Hidden executable file.".to_string());
    }

    if !unexpected_reasons.is_empty() {
        return FileExpectedness {
            status: ExpectednessStatus::Unexpected,
            reasons: unexpected_reasons,
        };
    }

    if authenticity.status == AuthenticityStatus::Verified {
        return FileExpectedness {
            status: ExpectednessStatus::Expected,
            reasons: vec!["Matches the checksum recorded by the owning package.".to_string()],
        };
    }

    let mut reasons = vec![
        "Insufficient deterministic signal to classify as expected or unexpected.".to_string(),
    ];
    if !local.available {
        reasons.push(
            "Same-directory listing was unavailable, so a masquerading check could not run."
                .to_string(),
        );
    }
    FileExpectedness {
        status: ExpectednessStatus::Unknown,
        reasons,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- sniff_file_type ----

    #[test]
    fn sniffs_elf() {
        assert_eq!(
            sniff_file_type(b"\x7fELF\x02\x01\x01\x00rest"),
            "ELF executable/library"
        );
    }

    #[test]
    fn sniffs_pe() {
        assert_eq!(sniff_file_type(b"MZ\x90\x00rest"), "Windows PE executable");
    }

    #[test]
    fn sniffs_macho() {
        assert_eq!(
            sniff_file_type(&[0xFE, 0xED, 0xFA, 0xCE, 0, 0, 0, 0]),
            "Mach-O executable/library"
        );
        assert_eq!(
            sniff_file_type(&[0xCF, 0xFA, 0xED, 0xFE, 0, 0, 0, 0]),
            "Mach-O executable/library"
        );
    }

    #[test]
    fn flags_cafebabe_as_ambiguous_not_a_guess() {
        let sniffed = sniff_file_type(&[0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 2]);
        assert!(sniffed.contains("Mach-O"));
        assert!(sniffed.contains("Java class"));
    }

    #[test]
    fn sniffs_shebang_bash() {
        assert_eq!(sniff_file_type(b"#!/bin/bash\necho hi\n"), "Script (bash)");
    }

    #[test]
    fn sniffs_shebang_env_wrapped() {
        assert_eq!(
            sniff_file_type(b"#!/usr/bin/env python3\nprint(1)\n"),
            "Script (python3)"
        );
    }

    #[test]
    fn sniffs_zip_family() {
        assert_eq!(
            sniff_file_type(b"PK\x03\x04rest"),
            "ZIP-family archive (zip/jar/apk/docx/xlsx/...)"
        );
    }

    #[test]
    fn sniffs_gzip() {
        assert_eq!(sniff_file_type(&[0x1F, 0x8B, 0x08, 0x00]), "gzip archive");
    }

    #[test]
    fn sniffs_pdf() {
        assert_eq!(sniff_file_type(b"%PDF-1.7\n"), "PDF document");
    }

    #[test]
    fn sniffs_text() {
        assert_eq!(
            sniff_file_type(b"hello world, this is plain ASCII text\n"),
            "Text data"
        );
    }

    #[test]
    fn sniffs_unknown_binary() {
        assert_eq!(
            sniff_file_type(&[0x00, 0x01, 0x02, 0x03, 0xff, 0xfe, 0x00, 0x00]),
            "Unknown binary data"
        );
    }

    #[test]
    fn sniffs_empty() {
        assert_eq!(sniff_file_type(&[]), "Empty file");
    }

    // ---- levenshtein / find_similarly_named ----

    #[test]
    fn levenshtein_identical_is_zero() {
        assert_eq!(levenshtein("svchost.exe", "svchost.exe"), 0);
    }

    #[test]
    fn levenshtein_single_substitution() {
        assert_eq!(levenshtein("svchost.exe", "svch0st.exe"), 1);
    }

    #[test]
    fn levenshtein_unrelated_strings_are_far_apart() {
        assert!(levenshtein("svchost.exe", "readme.txt") > 3);
    }

    #[test]
    fn finds_masquerading_sibling() {
        let siblings = vec!["svch0st.exe".to_string(), "unrelated.dll".to_string()];
        let found = find_similarly_named("svchost.exe", &siblings);
        assert_eq!(found, vec!["svch0st.exe".to_string()]);
    }

    #[test]
    fn does_not_flag_unrelated_siblings() {
        let siblings = vec!["readme.txt".to_string(), "license.md".to_string()];
        assert!(find_similarly_named("svchost.exe", &siblings).is_empty());
    }

    // ---- dpkg output parsing ----

    #[test]
    fn parses_dpkg_search_output() {
        let stdout = "coreutils: /usr/bin/ls\n";
        assert_eq!(
            parse_dpkg_search_output(stdout, "/usr/bin/ls"),
            Some("coreutils".to_string())
        );
    }

    #[test]
    fn parses_dpkg_search_output_with_multiarch_suffix() {
        let stdout = "libc6:amd64: /usr/lib/x86_64-linux-gnu/libc.so.6\n";
        assert_eq!(
            parse_dpkg_search_output(stdout, "/usr/lib/x86_64-linux-gnu/libc.so.6"),
            Some("libc6:amd64".to_string())
        );
    }

    // ---- classify_dpkg_search (the fatal-error-vs-not-found fix) ----

    #[test]
    fn classify_dpkg_search_success_with_exact_match_is_owned() {
        let outcome = classify_dpkg_search(Some(0), "coreutils: /usr/bin/ls\n", "", "/usr/bin/ls");
        assert_eq!(outcome, DpkgSearchOutcome::Owned("coreutils".to_string()));
    }

    #[test]
    fn classify_dpkg_search_success_without_exact_match_is_unowned() {
        // Exit 0 but the only line doesn't exactly match -- dpkg's glob
        // matching found something else, which is correctly rejected by
        // parse_dpkg_search_output, and that's a real negative result,
        // not a failure.
        let outcome = classify_dpkg_search(Some(0), "coreutils: /usr/bin/ls\n", "", "/usr/bin/*");
        assert_eq!(outcome, DpkgSearchOutcome::Unowned);
    }

    #[test]
    fn classify_dpkg_search_exit_1_is_the_documented_not_found_case() {
        let outcome = classify_dpkg_search(
            Some(1),
            "",
            "dpkg-query: no path found matching pattern /tmp/x",
            "/tmp/x",
        );
        assert_eq!(outcome, DpkgSearchOutcome::Unowned);
    }

    #[test]
    fn classify_dpkg_search_exit_2_is_a_fatal_lookup_failure_not_unpackaged() {
        // The review's merge-blocking finding: dpkg-query(1) documents
        // exit 2 as a fatal/unrecoverable error (database inaccessible or
        // corrupt, out of memory, invalid invocation) -- categorically
        // different from exit 1's documented "no file found." Collapsing
        // both into Unpackaged reports "we don't know" as "we know this
        // isn't package-owned."
        let outcome = classify_dpkg_search(Some(2), "", "dpkg-query: error: ...", "/usr/bin/ls");
        assert!(matches!(outcome, DpkgSearchOutcome::LookupFailed(_)));
    }

    #[test]
    fn classify_dpkg_search_no_exit_code_is_also_a_fatal_lookup_failure() {
        // A process killed by a signal reports no exit code at all --
        // also must not be treated as "not found."
        let outcome = classify_dpkg_search(None, "", "", "/usr/bin/ls");
        assert!(matches!(outcome, DpkgSearchOutcome::LookupFailed(_)));
    }

    #[test]
    fn rejects_a_returned_path_that_does_not_exactly_match_the_query() {
        // The review's merge-blocking finding: `dpkg -S` does its own
        // glob-style matching on `*`/`?`/`[`/`\`, all legal filename
        // characters, so a real selected path containing one of those
        // could cause dpkg to match and return an entirely different
        // installed file. Confirmed live: `dpkg -S /usr/bin/*` returns
        // dozens of unrelated real packages, not "not found." This
        // simulates exactly that: the query looked like a path containing
        // a wildcard, dpkg pattern-matched it against a real but
        // different file, and the parser must not accept that match.
        let stdout = "coreutils: /usr/bin/ls\n";
        assert_eq!(parse_dpkg_search_output(stdout, "/usr/bin/*"), None);
    }

    #[test]
    fn accepts_the_first_exact_match_among_multiple_lines() {
        // A pattern query can return several lines; only the one whose
        // reported path exactly equals the query is acceptable.
        let stdout = "pkg-a: /usr/bin/aaa\npkg-b: /usr/bin/target\npkg-c: /usr/bin/ccc\n";
        assert_eq!(
            parse_dpkg_search_output(stdout, "/usr/bin/target"),
            Some("pkg-b".to_string())
        );
    }

    #[test]
    fn parses_dpkg_query_output() {
        let stdout = "5.2.5-2ubuntu1\tMichael Stone <mstone@debian.org>\n";
        assert_eq!(
            parse_dpkg_query_output(stdout),
            (
                Some("5.2.5-2ubuntu1".to_string()),
                Some("Michael Stone <mstone@debian.org>".to_string())
            )
        );
    }

    #[test]
    fn parses_md5sums_file() {
        let contents = "1adf6740fd2848bc1cbcbad4cb97a027  usr/bin/ls\nabc123  usr/bin/other\n";
        assert_eq!(
            parse_md5sums_file(contents, "usr/bin/ls"),
            Some("1adf6740fd2848bc1cbcbad4cb97a027".to_string())
        );
        assert_eq!(parse_md5sums_file(contents, "usr/bin/missing"), None);
    }

    #[test]
    fn parses_dpkg_description_takes_first_line_only() {
        let stdout = "GNU core utilities\n This package contains the basic file, shell\n and text manipulation utilities.\n";
        assert_eq!(
            parse_dpkg_description(stdout),
            Some("GNU core utilities".to_string())
        );
    }

    #[test]
    fn parses_dpkg_description_empty_is_none() {
        assert_eq!(parse_dpkg_description(""), None);
        assert_eq!(parse_dpkg_description("\n"), None);
    }

    // ---- compare_checksums (the authenticity decision, isolated from any
    // real filesystem/dpkg state -- a follow-up review noted the previous
    // test claiming to cover the Modified branch didn't actually exercise
    // it, and constructing a real mismatched dpkg environment isn't safe
    // to do against this sandbox's actual /var/lib/dpkg/info) ----

    #[test]
    fn compare_checksums_matching_is_verified() {
        let result = compare_checksums("coreutils", "abc123", Some("abc123"));
        assert_eq!(result.status, AuthenticityStatus::Verified);
    }

    #[test]
    fn compare_checksums_matching_is_case_insensitive() {
        let result = compare_checksums("coreutils", "ABC123", Some("abc123"));
        assert_eq!(result.status, AuthenticityStatus::Verified);
    }

    #[test]
    fn compare_checksums_mismatch_is_modified() {
        let result = compare_checksums("coreutils", "abc123", Some("def456"));
        assert_eq!(result.status, AuthenticityStatus::Modified);
        assert!(result.detail.unwrap().contains("coreutils"));
    }

    #[test]
    fn compare_checksums_no_actual_checksum_is_unknown() {
        let result = compare_checksums("coreutils", "abc123", None);
        assert_eq!(result.status, AuthenticityStatus::Unknown);
    }

    // ---- ownership_lookup_path (the symlink-identity fix) ----

    #[test]
    fn ownership_lookup_path_resolves_a_non_symlink() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let target = dir.path().join("real-file");
        std::fs::write(&target, b"content").unwrap();

        let resolved = ownership_lookup_path(&target, false);
        assert_eq!(resolved, std::fs::canonicalize(&target).unwrap());
    }

    #[test]
    fn ownership_lookup_path_does_not_resolve_the_final_symlink() {
        // This is the exact fix for the review's finding: a symlink's own
        // path must be what gets queried against dpkg's ownership
        // database, not wherever it happens to point.
        let dir = tempfile::tempdir().expect("create temp dir");
        let link = dir.path().join("suspicious-name");
        std::os::unix::fs::symlink("/usr/bin/ls", &link).unwrap();

        let resolved = ownership_lookup_path(&link, true);
        let fully_resolved = std::fs::canonicalize(&link).unwrap();

        assert_ne!(
            resolved, fully_resolved,
            "must not silently resolve through to the symlink's target"
        );
        assert_eq!(resolved.file_name(), link.file_name());
    }

    // ---- purpose / expectedness derivation ----

    #[test]
    fn purpose_uses_real_package_description_when_available() {
        let ctx = ProductContext {
            package: Some("coreutils".to_string()),
            version: Some("9.4-2".to_string()),
            vendor: None,
            description: Some("GNU core utilities".to_string()),
        };
        let purpose = derive_purpose(&ctx);
        assert_eq!(purpose.source, PurposeSource::PackageCatalog);
        assert!(purpose.summary.contains("coreutils"));
        assert!(purpose.summary.contains("GNU core utilities"));
    }

    #[test]
    fn purpose_is_unknown_when_package_found_but_no_description() {
        // The review's finding: package identity alone (name/version) is
        // product context, not purpose -- claiming `PackageCatalog` here
        // without real description text would misrepresent what Artemis
        // actually knows.
        let ctx = ProductContext {
            package: Some("some-pkg".to_string()),
            version: Some("1.0".to_string()),
            vendor: None,
            description: None,
        };
        let purpose = derive_purpose(&ctx);
        assert_eq!(purpose.source, PurposeSource::Unknown);
    }

    #[test]
    fn purpose_unknown_without_package() {
        let purpose = derive_purpose(&ProductContext::default());
        assert_eq!(purpose.source, PurposeSource::Unknown);
    }

    fn identity(is_hidden: bool, is_executable: bool) -> FileIdentity {
        FileIdentity {
            file_type: "ELF executable/library".to_string(),
            extension: None,
            is_hidden,
            is_executable,
            is_symlink: false,
            symlink_target: None,
            created: None,
            modified: None,
            accessed: None,
        }
    }

    fn local_context(similarly_named_siblings: Vec<String>) -> LocalContext {
        LocalContext {
            sibling_count: similarly_named_siblings.len() + 2,
            similarly_named_siblings,
            available: true,
        }
    }

    #[test]
    fn expectedness_verified_and_clean_is_expected() {
        let authenticity = FileAuthenticity {
            status: AuthenticityStatus::Verified,
            detail: None,
        };
        let local = local_context(Vec::new());
        let result = derive_expectedness(&identity(false, true), &authenticity, &local);
        assert_eq!(result.status, ExpectednessStatus::Expected);
    }

    #[test]
    fn expectedness_modified_is_unexpected() {
        let authenticity = FileAuthenticity {
            status: AuthenticityStatus::Modified,
            detail: None,
        };
        let local = local_context(Vec::new());
        let result = derive_expectedness(&identity(false, true), &authenticity, &local);
        assert_eq!(result.status, ExpectednessStatus::Unexpected);
        assert!(result.reasons[0].contains("checksum"));
    }

    #[test]
    fn expectedness_masquerading_sibling_is_unexpected_when_unpackaged() {
        let authenticity = FileAuthenticity {
            status: AuthenticityStatus::Unpackaged,
            detail: None,
        };
        let local = local_context(vec!["svch0st.exe".to_string()]);
        let result = derive_expectedness(&identity(false, true), &authenticity, &local);
        assert_eq!(result.status, ExpectednessStatus::Unexpected);
        assert!(result.reasons[0].contains("svch0st.exe"));
    }

    #[test]
    fn expectedness_masquerading_sibling_does_not_override_verified() {
        // The review's merge-blocking finding: a Verified checksum is
        // direct, corroborated evidence and must not be overridden by a
        // same-directory name-similarity match alone. Legitimate tool
        // families (mount/umount, expand/unexpand) genuinely sit within
        // edit distance 1-2 of each other -- see the live end-to-end
        // version of this test below using the real pair on this sandbox.
        let authenticity = FileAuthenticity {
            status: AuthenticityStatus::Verified,
            detail: None,
        };
        let local = local_context(vec!["umount".to_string()]);
        let result = derive_expectedness(&identity(false, true), &authenticity, &local);
        assert_eq!(result.status, ExpectednessStatus::Expected);
    }

    #[test]
    fn expectedness_hidden_executable_is_unexpected() {
        let authenticity = FileAuthenticity {
            status: AuthenticityStatus::Unpackaged,
            detail: None,
        };
        let local = local_context(Vec::new());
        let result = derive_expectedness(&identity(true, true), &authenticity, &local);
        assert_eq!(result.status, ExpectednessStatus::Unexpected);
    }

    #[test]
    fn expectedness_hidden_executable_does_not_override_verified() {
        // A follow-up review corrected this: `Verified` here means
        // `dpkg -S` says the *exact selected path* is package-owned and
        // its checksum matches -- if a package legitimately ships an
        // executable dotfile at that exact path, hiddenness alone must
        // not override that direct evidence, matching how a same-
        // directory name collision is already treated above.
        let authenticity = FileAuthenticity {
            status: AuthenticityStatus::Verified,
            detail: None,
        };
        let local = local_context(Vec::new());
        let result = derive_expectedness(&identity(true, true), &authenticity, &local);
        assert_eq!(result.status, ExpectednessStatus::Expected);
    }

    #[test]
    fn expectedness_unpackaged_alone_is_unknown_not_unexpected() {
        // Being unpackaged is common and unremarkable on its own -- most
        // hand-built or user-installed software has no owning package.
        let authenticity = FileAuthenticity {
            status: AuthenticityStatus::Unpackaged,
            detail: None,
        };
        let local = local_context(Vec::new());
        let result = derive_expectedness(&identity(false, false), &authenticity, &local);
        assert_eq!(result.status, ExpectednessStatus::Unknown);
    }

    #[test]
    fn expectedness_notes_when_local_context_was_unavailable() {
        let authenticity = FileAuthenticity {
            status: AuthenticityStatus::Unpackaged,
            detail: None,
        };
        let local = LocalContext {
            sibling_count: 0,
            similarly_named_siblings: Vec::new(),
            available: false,
        };
        let result = derive_expectedness(&identity(false, false), &authenticity, &local);
        assert_eq!(result.status, ExpectednessStatus::Unknown);
        assert!(result.reasons.iter().any(|r| r.contains("unavailable")));
    }

    // ---- end-to-end, live against this sandbox's real dpkg state ----
    // Not #[ignore] -- dpkg is guaranteed present here and on CI's
    // ubuntu-latest runner (see module doc comment), so this is a normal
    // part of the suite, not an opt-in integration test.

    #[tokio::test]
    async fn resolves_a_real_dpkg_owned_unmodified_binary() {
        let intel = resolve(Path::new("/usr/bin/ls"))
            .await
            .expect("resolve file intelligence for /usr/bin/ls");

        assert_eq!(intel.authenticity.status, AuthenticityStatus::Verified);
        assert_eq!(intel.product_context.package.as_deref(), Some("coreutils"));
        assert!(intel.product_context.version.is_some());
        assert_eq!(intel.purpose.source, PurposeSource::PackageCatalog);
        assert!(
            intel.purpose.summary.contains("GNU core utilities"),
            "expected the real dpkg package description in the purpose summary, got: {}",
            intel.purpose.summary
        );
        assert!(intel.identity.is_executable);
        assert!(!intel.identity.is_symlink);
        assert_eq!(intel.expectedness.status, ExpectednessStatus::Expected);
    }

    #[tokio::test]
    async fn resolves_an_unpackaged_temp_file_as_unpackaged() {
        let tmp = tempfile::NamedTempFile::new().expect("create temp file");
        std::fs::write(tmp.path(), b"just some scratch content").unwrap();

        let intel = resolve(tmp.path())
            .await
            .expect("resolve file intelligence for a temp file");

        assert_eq!(intel.authenticity.status, AuthenticityStatus::Unpackaged);
        assert!(intel.product_context.package.is_none());
        assert_eq!(intel.purpose.source, PurposeSource::Unknown);
    }

    #[tokio::test]
    async fn a_verified_pair_of_legitimately_similar_names_is_expected_not_unexpected() {
        // The review's merge-blocking finding, reproduced end-to-end
        // against this sandbox's real dpkg state rather than only a
        // constructed unit test: /usr/bin/mount and /usr/bin/umount are
        // edit-distance 1 apart, both executable, and both genuinely owned
        // (with matching checksums) by the same real "mount" package.
        // Before the fix, resolving either one reported `Unexpected`
        // purely because of the other's presence as a sibling, even
        // though the checksum was already Verified.
        let mount_owner = dpkg_query_owner("/usr/bin/mount");
        let umount_owner = dpkg_query_owner("/usr/bin/umount");
        if mount_owner.is_none() || umount_owner.is_none() || mount_owner != umount_owner {
            eprintln!("skipping: /usr/bin/mount and /usr/bin/umount are not both dpkg-owned by the same package on this system");
            return;
        }

        let intel = resolve(Path::new("/usr/bin/mount"))
            .await
            .expect("resolve file intelligence for /usr/bin/mount");

        assert_eq!(intel.authenticity.status, AuthenticityStatus::Verified);
        assert!(
            intel
                .local_context
                .similarly_named_siblings
                .contains(&"umount".to_string()),
            "expected 'umount' to be flagged as a similarly named sibling by local_context \
             (this test's premise), got: {:?}",
            intel.local_context.similarly_named_siblings
        );
        assert_eq!(
            intel.expectedness.status,
            ExpectednessStatus::Expected,
            "a Verified checksum must not be overridden by a same-package sibling's \
             similar name, got reasons: {:?}",
            intel.expectedness.reasons
        );
    }

    /// Test-only helper mirroring the ownership half of `dpkg_lookup`,
    /// used only to confirm the live-system premise of the test above
    /// (that mount/umount are actually owned by the same package on
    /// *this* machine) without duplicating production assertions into
    /// the test itself.
    fn dpkg_query_owner(path: &str) -> Option<String> {
        let output = std::process::Command::new("dpkg")
            .arg("-S")
            .arg(path)
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        parse_dpkg_search_output(&String::from_utf8_lossy(&output.stdout), path)
    }

    #[tokio::test]
    async fn a_symlink_to_a_packaged_binary_does_not_inherit_its_package_identity() {
        // The review's other merge-blocking finding, reproduced live: a
        // symlink whose target is package-owned must not itself be
        // reported as package-owned/Verified/Expected purely because its
        // target is. Before the fix, canonicalizing the path before the
        // dpkg lookup made a symlink like this indistinguishable from the
        // real /usr/bin/ls for ownership-attribution purposes.
        let dir = tempfile::tempdir().expect("create temp dir");
        let link = dir.path().join("update-service");
        std::os::unix::fs::symlink("/usr/bin/ls", &link).unwrap();

        let intel = resolve(&link)
            .await
            .expect("resolve file intelligence for the symlink");

        assert!(intel.identity.is_symlink);
        assert_eq!(
            intel.identity.symlink_target.as_deref(),
            Some("/usr/bin/ls")
        );
        assert_eq!(
            intel.authenticity.status,
            AuthenticityStatus::Unpackaged,
            "a symlink must not inherit its target's package identity"
        );
        assert!(intel.product_context.package.is_none());
    }

    #[tokio::test]
    async fn a_new_symlink_to_an_old_file_reports_its_own_recent_timestamp() {
        // The review's merge-blocking finding, reproduced live: creates a
        // symlink *today* pointing at a target file whose mtime is
        // deliberately set to year 2000. Before the fix, `resolve()`'s
        // `meta` (which follows the symlink) meant the freshly-created
        // symlink's `modified` field reported year 2000 -- its target's
        // age, not its own. For incident-response context ("was this
        // artifact just planted here?") that's a material misstatement.
        let dir = tempfile::tempdir().expect("create temp dir");
        let old_target = dir.path().join("old-target.txt");
        std::fs::write(&old_target, b"old content").unwrap();
        let status = std::process::Command::new("touch")
            .arg("-d")
            .arg("2000-01-01")
            .arg(&old_target)
            .status()
            .expect("run touch");
        assert!(
            status.success(),
            "touch -d must succeed to set up this test"
        );

        let link = dir.path().join("freshly-created-link");
        std::os::unix::fs::symlink(&old_target, &link).unwrap();

        let intel = resolve(&link).await.expect("resolve file intelligence");

        let modified = intel
            .identity
            .modified
            .expect("a freshly created symlink must have a modified timestamp");
        let age = chrono::Utc::now().signed_duration_since(modified);
        assert!(
            age.num_minutes() < 5,
            "expected the symlink's own recent creation time, got a timestamp {age} old \
             (i.e. inherited from the year-2000 target): {modified}"
        );
    }

    #[tokio::test]
    async fn a_pathname_with_dpkg_pattern_characters_resolves_without_crashing_or_hanging() {
        // NOT a reproduction of the misattribution bug itself -- that's
        // covered by the pure unit tests above
        // (`rejects_a_returned_path_that_does_not_exactly_match_the_query`,
        // confirmed via revert-and-reproduce as a real detector). A
        // temp-dir path can't actually reproduce the misattribution live:
        // `dpkg -S`'s glob matching only ever matches paths dpkg actually
        // tracks, and nothing under a freshly created tempdir is tracked,
        // so a query like `<tempdir>/note*.txt` structurally cannot
        // collide with a real package file regardless of whether the
        // exact-match fix is present -- confirmed by running this exact
        // test against the pre-fix parser and observing it still passed.
        // Constructing genuine live collision would require creating
        // files under a real package directory (e.g. /usr/bin), which
        // this suite deliberately does not do to real system state. What
        // this test actually verifies: a pattern-character filename is a
        // legal, unremarkable input that must resolve cleanly to
        // Unpackaged, not error, hang, or crash.
        let dir = tempfile::tempdir().expect("create temp dir");
        let weird_name = dir.path().join("note*.txt");
        std::fs::write(&weird_name, b"not a package file").unwrap();

        let intel = resolve(&weird_name)
            .await
            .expect("resolve file intelligence for a pattern-char filename");

        assert_eq!(intel.authenticity.status, AuthenticityStatus::Unpackaged);
        assert!(intel.product_context.package.is_none());
    }

    #[tokio::test]
    async fn local_context_reports_unavailable_when_the_directory_cannot_be_listed() {
        let unreachable = Path::new("/nonexistent-dir-xyz-artemis-test/somefile");
        let local = build_local_context(unreachable)
            .await
            .expect("build_local_context itself should not error");
        assert!(!local.available);
        assert_eq!(local.sibling_count, 0);
    }

    #[tokio::test]
    async fn sniff_path_propagates_a_real_read_error_instead_of_reporting_empty() {
        // Reading a directory as a file is a genuine, portable way to
        // trigger an I/O read error (EISDIR) without needing permission
        // tricks that root would bypass anyway in this sandbox. Before
        // the fix, `sniff_path`'s `.unwrap_or(0)` turned this into a
        // silent "Empty file" instead of surfacing the failure.
        let dir = tempfile::tempdir().expect("create temp dir");
        let err = sniff_path(dir.path()).await.unwrap_err();
        assert!(
            !err.to_string().is_empty(),
            "expected a real error, not a swallowed one"
        );
    }

    #[tokio::test]
    async fn local_context_counts_siblings() {
        let dir = tempfile::tempdir().expect("create temp dir");
        std::fs::write(dir.path().join("target.txt"), b"a").unwrap();
        std::fs::write(dir.path().join("sibling-one.txt"), b"b").unwrap();
        std::fs::write(dir.path().join("sibling-two.txt"), b"c").unwrap();

        let intel = resolve(&dir.path().join("target.txt"))
            .await
            .expect("resolve file intelligence");

        assert_eq!(intel.local_context.sibling_count, 2);
    }

    #[tokio::test]
    async fn local_context_flags_masquerading_sibling_end_to_end() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let target = dir.path().join("svchost.exe");
        std::fs::write(&target, b"#!/bin/sh\necho hi\n").unwrap();
        std::fs::write(dir.path().join("svch0st.exe"), b"decoy").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        let intel = resolve(&target).await.expect("resolve file intelligence");

        assert_eq!(
            intel.local_context.similarly_named_siblings,
            vec!["svch0st.exe".to_string()]
        );
        assert_eq!(intel.expectedness.status, ExpectednessStatus::Unexpected);
    }
}
