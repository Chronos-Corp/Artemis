use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

// The inner module deliberately retains a few helper/test-only items from
// the scanner implementation. They are private implementation detail behind
// this facade, so keep lint exceptions scoped here rather than weakening the
// crate/workspace lint policy.
#[allow(dead_code, unused_imports)]
#[path = "yara_scan_inner.rs"]
mod inner;

pub use inner::{BoundedYaraMatches, YaraMatch, MAX_YARA_MATCHES_PER_VERDICT};

// `yara::Rules` does not implement Debug. The preserved inner scanner's own
// unit tests use `Result::expect_err`, which requires the success type to be
// debuggable even though the compiled rule object should remain opaque.
// Mirror the public facade's safe Debug view rather than dropping those tests
// or exposing libyara internals.
impl std::fmt::Debug for inner::YaraEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("YaraEngine")
            .field("rules_dir", &self.rules_dir)
            .field("rule_count", &self.rule_count)
            .field("ruleset_fingerprint", &self.ruleset_fingerprint)
            .finish_non_exhaustive()
    }
}

// These mirror the inner loader's hard ceilings. The facade performs a
// security preflight before libyara sees any source so an `include` cannot
// escape those ceilings; the inner loader then enforces the same bounds again
// while fingerprinting and compiling the exact bytes it owns.
const MAX_YARA_RULE_FILES: usize = 1024;
const MAX_YARA_RULE_FILE_BYTES: usize = 2 * 1024 * 1024;
const MAX_YARA_RULESET_BYTES: usize = 16 * 1024 * 1024;

/// Public YARA engine facade.
///
/// The inner engine owns compilation, source fingerprints, and scanning. This
/// layer owns two additional trust-boundary contracts:
///
/// 1. preflight must happen *before* libyara parses source, so YARA `include`
///    cannot escape Artemis's file/byte/open-handle controls; and
/// 2. durable rule **behavior identity** must not be confused with a rule's
///    own source identity. YARA rules can depend on helper/private/global rules,
///    so an unchanged rule source block can behave differently when the
///    compiled ruleset changes. `rule_source_fingerprints` preserves the exact
///    per-rule source hash for explainability; `rule_fingerprints` is the
///    conservative effective-version identity used for durable observation and
///    CVE coverage gating.
pub struct YaraEngine {
    inner: inner::YaraEngine,
    pub rules_dir: PathBuf,
    pub rule_count: usize,
    pub ruleset_fingerprint: String,
    /// Effective behavior/version identity used for durable edges. Today this
    /// conservatively combines the exact rule source identity with the whole
    /// compiled ruleset identity. That can over-invalidate when an unrelated
    /// rule changes, but it fails safe: it cannot let version-scoped evidence
    /// survive a helper/global semantic change that altered effective behavior.
    pub rule_fingerprints: HashMap<String, String>,
    /// Exact source-span hash for each rule declaration/body. Useful for
    /// explainability and future dependency-aware versioning, but deliberately
    /// *not* sufficient by itself as durable behavior identity.
    pub rule_source_fingerprints: HashMap<String, String>,
}

impl YaraEngine {
    pub fn empty(rules_dir: &Path) -> Self {
        Self::from_inner(inner::YaraEngine::empty(rules_dir))
    }

    pub fn load(rules_dir: &Path) -> Result<Self> {
        validate_ruleset_source_boundary(rules_dir)?;
        inner::YaraEngine::load(rules_dir).map(Self::from_inner)
    }

    /// Conservative effective behavior/version identity for durable
    /// observations and version-scoped coverage assertions.
    pub fn rule_fingerprint(&self, rule_name: &str) -> Option<&str> {
        self.rule_fingerprints.get(rule_name).map(String::as_str)
    }

    /// Exact source-block identity for explanation/debugging. This is not the
    /// durable behavior identity because helper/private/global rule changes can
    /// alter a rule's effective behavior while leaving its own source unchanged.
    pub fn rule_source_fingerprint(&self, rule_name: &str) -> Option<&str> {
        self.rule_source_fingerprints
            .get(rule_name)
            .map(String::as_str)
    }

    pub fn scan(&self, file_path: &Path) -> Result<Vec<YaraMatch>> {
        let matches = self.inner.scan(file_path)?;
        self.validate_match_identities(&matches)?;
        Ok(matches)
    }

    pub fn scan_bytes(&self, data: &[u8]) -> Result<Vec<YaraMatch>> {
        let matches = self.inner.scan_bytes(data)?;
        self.validate_match_identities(&matches)?;
        Ok(matches)
    }

    pub fn scan_bytes_bounded(&self, data: &[u8]) -> Result<BoundedYaraMatches> {
        let bounded = self.inner.scan_bytes_bounded(data)?;
        self.validate_match_identities(&bounded.matches)?;
        Ok(bounded)
    }

    fn validate_match_identities(&self, matches: &[YaraMatch]) -> Result<()> {
        for hit in matches {
            if !self.rule_fingerprints.contains_key(&hit.rule_name) {
                // `""` is a real schema sentinel meaning "applies to any
                // version" on coverage edges. A compiler/source-identity
                // invariant failure must never broaden into that wildcard.
                // Fail closed before the observation reaches persistence.
                bail!(
                    "compiled YARA match '{}' has no effective rule fingerprint; refusing to persist an unversioned observation",
                    hit.rule_name
                );
            }
        }
        Ok(())
    }

    fn from_inner(inner: inner::YaraEngine) -> Self {
        let ruleset_fingerprint = inner.ruleset_fingerprint.clone();
        let rule_source_fingerprints = inner.rule_fingerprints.clone();
        let rule_fingerprints = rule_source_fingerprints
            .iter()
            .map(|(name, source_fingerprint)| {
                (
                    name.clone(),
                    effective_rule_fingerprint(source_fingerprint, &ruleset_fingerprint),
                )
            })
            .collect();

        Self {
            rules_dir: inner.rules_dir.clone(),
            rule_count: inner.rule_count,
            ruleset_fingerprint,
            rule_fingerprints,
            rule_source_fingerprints,
            inner,
        }
    }
}

fn effective_rule_fingerprint(source_fingerprint: &str, ruleset_fingerprint: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"apollo-yara-effective-rule-v1\0");
    digest.update(source_fingerprint.as_bytes());
    digest.update(b"\0ruleset\0");
    digest.update(ruleset_fingerprint.as_bytes());
    hex::encode(digest.finalize())
}

/// Preflights exactly the source tree Artemis is willing to hand to the inner
/// loader. This is intentionally safe on hostile filesystems: the pathname is
/// opened nonblocking on Unix, the opened handle is then type-checked, and the
/// read itself is capped so growth after metadata cannot exceed the budget.
fn validate_ruleset_source_boundary(rules_dir: &Path) -> Result<()> {
    if !rules_dir.exists() {
        return Ok(());
    }

    let mut file_count = 0usize;
    let mut total_bytes = 0usize;
    for entry in WalkDir::new(rules_dir) {
        let entry = entry.with_context(|| {
            format!(
                "walking YARA rules directory during preflight {}",
                rules_dir.display()
            )
        })?;
        if !entry.file_type().is_file() {
            continue;
        }
        if !matches!(
            entry.path().extension().and_then(|s| s.to_str()),
            Some("yar") | Some("yara")
        ) {
            continue;
        }

        file_count += 1;
        if file_count > MAX_YARA_RULE_FILES {
            bail!(
                "YARA rules directory contains more than {MAX_YARA_RULE_FILES} rule files; refusing unbounded ruleset"
            );
        }

        let bytes = read_rule_source_preflight(entry.path())?;
        total_bytes = total_bytes
            .checked_add(bytes.len())
            .context("YARA preflight byte count overflow")?;
        if total_bytes > MAX_YARA_RULESET_BYTES {
            bail!(
                "YARA ruleset exceeds {MAX_YARA_RULESET_BYTES} bytes of source; refusing unbounded ruleset"
            );
        }

        let source = std::str::from_utf8(&bytes).with_context(|| {
            format!("YARA rule file {} is not valid UTF-8", entry.path().display())
        })?;
        if contains_source_token(source, "include") {
            bail!(
                "YARA include directives are not supported in {}; place included rules directly under the configured rules directory so Artemis can bound and fingerprint them",
                entry.path().display()
            );
        }
    }
    Ok(())
}

fn read_rule_source_preflight(path: &Path) -> Result<Vec<u8>> {
    let file = open_rule_source_preflight(path)?;
    let mut bytes = Vec::new();
    file.take(MAX_YARA_RULE_FILE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("reading YARA rule file during preflight {}", path.display()))?;
    if bytes.len() > MAX_YARA_RULE_FILE_BYTES {
        bail!(
            "YARA rule file {} exceeded the {MAX_YARA_RULE_FILE_BYTES}-byte limit during preflight",
            path.display()
        );
    }
    Ok(bytes)
}

fn open_rule_source_preflight(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC);
    }

    let file = options
        .open(path)
        .with_context(|| format!("opening YARA rule file during preflight {}", path.display()))?;
    let metadata = file.metadata().with_context(|| {
        format!(
            "inspecting opened YARA rule file during preflight {}",
            path.display()
        )
    })?;
    if !metadata.file_type().is_file() {
        bail!(
            "refusing non-regular YARA rule file {} during preflight",
            path.display()
        );
    }
    if metadata.len() > MAX_YARA_RULE_FILE_BYTES as u64 {
        bail!(
            "YARA rule file {} exceeds the {MAX_YARA_RULE_FILE_BYTES}-byte limit",
            path.display()
        );
    }
    Ok(file)
}

fn contains_source_token(source: &str, token: &str) -> bool {
    strip_comments_strings_and_regexes(source)
        .split(|c: char| !(c.is_alphanumeric() || c == '_'))
        .any(|candidate| candidate == token)
}

/// Blanks comments, quoted strings, and regex literals before token scanning.
/// The include path itself is a quoted string, so after this pass a real
/// directive still leaves the reserved `include` token while harmless text
/// like `"include"`, `/include foo/`, or a comment does not.
fn strip_comments_strings_and_regexes(source: &str) -> String {
    let mut out = String::with_capacity(source.len());
    let mut chars = source.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '/' && chars.peek() == Some(&'/') {
            chars.next();
            out.push_str("  ");
            for c2 in chars.by_ref() {
                if c2 == '\n' {
                    out.push('\n');
                    break;
                }
                out.push(' ');
            }
            continue;
        }
        if c == '/' && chars.peek() == Some(&'*') {
            chars.next();
            out.push_str("  ");
            let mut prev = ' ';
            for c2 in chars.by_ref() {
                if prev == '*' && c2 == '/' {
                    out.push(' ');
                    break;
                }
                out.push(if c2 == '\n' { '\n' } else { ' ' });
                prev = c2;
            }
            continue;
        }
        if c == '/' {
            out.push(' ');
            let mut escaped = false;
            for c2 in chars.by_ref() {
                if escaped {
                    escaped = false;
                    out.push(' ');
                    continue;
                }
                if c2 == '\\' {
                    escaped = true;
                    out.push(' ');
                    continue;
                }
                out.push(' ');
                if c2 == '/' {
                    break;
                }
            }
            while let Some(&next) = chars.peek() {
                if next.is_ascii_alphabetic() {
                    out.push(' ');
                    chars.next();
                } else {
                    break;
                }
            }
            continue;
        }
        if c == '"' {
            out.push(' ');
            let mut escaped = false;
            for c2 in chars.by_ref() {
                if escaped {
                    escaped = false;
                    out.push(' ');
                    continue;
                }
                if c2 == '\\' {
                    escaped = true;
                    out.push(' ');
                    continue;
                }
                out.push(' ');
                if c2 == '"' {
                    break;
                }
            }
            continue;
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn include_directive_is_rejected_before_compilation() {
        let dir = tempfile::tempdir().expect("create temp rules dir");
        std::fs::write(
            dir.path().join("include.yar"),
            "include \"/outside/artemis/unbounded.yar\"\nrule Local { condition: true }\n",
        )
        .expect("write include rule");

        let err = YaraEngine::load(dir.path()).expect_err("include must fail closed");
        assert!(
            err.to_string().contains("include directives are not supported"),
            "expected Artemis include-boundary rejection, got: {err:#}"
        );
    }

    #[test]
    fn literal_include_text_is_not_rejected() {
        let dir = tempfile::tempdir().expect("create temp rules dir");
        std::fs::write(
            dir.path().join("literal.yar"),
            r#"
                // include "/not/a/directive.yar"
                rule IncludeLiteral {
                    meta:
                        note = "include /still/not/a/directive.yar"
                    strings:
                        $a = "include"
                        $b = /include [a-z]+/
                    condition:
                        $a or $b
                }
            "#,
        )
        .expect("write literal include text");

        let engine = YaraEngine::load(dir.path()).expect("literal text must remain valid");
        assert_eq!(engine.rule_count, 1);
    }

    #[cfg(unix)]
    #[test]
    fn preflight_rejects_fifo_without_waiting_for_writer() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        let dir = tempfile::tempdir().expect("create temp dir");
        let fifo = dir.path().join("swapped.yar");
        let c_path = CString::new(fifo.as_os_str().as_bytes()).expect("fifo path has no nul");
        let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) };
        assert_eq!(rc, 0, "mkfifo failed: {}", std::io::Error::last_os_error());

        let err = read_rule_source_preflight(&fifo).expect_err("FIFO must be rejected");
        assert!(err.to_string().contains("non-regular"));
    }

    #[test]
    fn helper_change_updates_effective_identity_without_changing_rule_source_identity() {
        let dir = tempfile::tempdir().expect("create rules dir");
        let path = dir.path().join("helpers.yar");
        std::fs::write(
            &path,
            r#"
                private rule Helper { strings: $a = "AAA" condition: $a }
                rule RuleA { condition: Helper }
            "#,
        )
        .expect("write v1 rules");
        let before = YaraEngine::load(dir.path()).expect("load v1 rules");
        let source_before = before
            .rule_source_fingerprint("RuleA")
            .expect("RuleA source fingerprint")
            .to_string();
        let effective_before = before
            .rule_fingerprint("RuleA")
            .expect("RuleA effective fingerprint")
            .to_string();

        std::fs::write(
            &path,
            r#"
                private rule Helper { strings: $a = "BBB" condition: $a }
                rule RuleA { condition: Helper }
            "#,
        )
        .expect("write v2 rules");
        let after = YaraEngine::load(dir.path()).expect("load v2 rules");

        assert_eq!(
            after.rule_source_fingerprint("RuleA"),
            Some(source_before.as_str()),
            "RuleA source text did not change"
        );
        assert_ne!(
            after.rule_fingerprint("RuleA"),
            Some(effective_before.as_str()),
            "helper semantics changed, so RuleA durable behavior identity must change"
        );
    }

    #[test]
    fn global_rule_change_updates_effective_identity_without_changing_rule_source_identity() {
        let dir = tempfile::tempdir().expect("create rules dir");
        let path = dir.path().join("global.yar");
        std::fs::write(
            &path,
            r#"
                global rule Gate { condition: filesize < 1024 }
                rule RuleA { condition: true }
            "#,
        )
        .expect("write v1 rules");
        let before = YaraEngine::load(dir.path()).expect("load v1 rules");
        let source_before = before
            .rule_source_fingerprint("RuleA")
            .expect("RuleA source fingerprint")
            .to_string();
        let effective_before = before
            .rule_fingerprint("RuleA")
            .expect("RuleA effective fingerprint")
            .to_string();

        std::fs::write(
            &path,
            r#"
                global rule Gate { condition: filesize < 16 }
                rule RuleA { condition: true }
            "#,
        )
        .expect("write v2 rules");
        let after = YaraEngine::load(dir.path()).expect("load v2 rules");

        assert_eq!(after.rule_source_fingerprint("RuleA"), Some(source_before.as_str()));
        assert_ne!(after.rule_fingerprint("RuleA"), Some(effective_before.as_str()));
    }

    #[test]
    fn missing_effective_identity_fails_closed_before_observation_persistence() {
        let dir = tempfile::tempdir().expect("create rules dir");
        std::fs::write(
            dir.path().join("one.yar"),
            "rule RuleA { strings: $a = \"AAA\" condition: $a }",
        )
        .expect("write rule");
        let mut engine = YaraEngine::load(dir.path()).expect("load rules");
        engine.rule_fingerprints.remove("RuleA");

        let error = engine
            .scan_bytes_bounded(b"AAA")
            .expect_err("missing effective identity must fail closed");
        assert!(error.to_string().contains("no effective rule fingerprint"));
    }
}
