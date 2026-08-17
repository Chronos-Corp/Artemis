use anyhow::{bail, Context, Result};
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
/// The inner engine owns compilation, fingerprints, and scanning. This layer
/// owns the trust-boundary preflight that must happen *before* libyara parses
/// source. YARA's `include` directive can make the compiler perform its own
/// filesystem reads, including absolute paths; Apollo already owns recursive
/// rule discovery, size bounds, and provenance, so includes are rejected
/// rather than allowing a second unbounded/unfingerprinted traversal.
pub struct YaraEngine {
    inner: inner::YaraEngine,
    pub rules_dir: PathBuf,
    pub rule_count: usize,
    pub ruleset_fingerprint: String,
    pub rule_fingerprints: HashMap<String, String>,
}

impl YaraEngine {
    pub fn empty(rules_dir: &Path) -> Self {
        Self::from_inner(inner::YaraEngine::empty(rules_dir))
    }

    pub fn load(rules_dir: &Path) -> Result<Self> {
        validate_ruleset_source_boundary(rules_dir)?;
        inner::YaraEngine::load(rules_dir).map(Self::from_inner)
    }

    pub fn rule_fingerprint(&self, rule_name: &str) -> Option<&str> {
        self.rule_fingerprints.get(rule_name).map(String::as_str)
    }

    pub fn scan(&self, file_path: &Path) -> Result<Vec<YaraMatch>> {
        self.inner.scan(file_path)
    }

    pub fn scan_bytes(&self, data: &[u8]) -> Result<Vec<YaraMatch>> {
        self.inner.scan_bytes(data)
    }

    pub fn scan_bytes_bounded(&self, data: &[u8]) -> Result<BoundedYaraMatches> {
        self.inner.scan_bytes_bounded(data)
    }

    fn from_inner(inner: inner::YaraEngine) -> Self {
        Self {
            rules_dir: inner.rules_dir.clone(),
            rule_count: inner.rule_count,
            ruleset_fingerprint: inner.ruleset_fingerprint.clone(),
            rule_fingerprints: inner.rule_fingerprints.clone(),
            inner,
        }
    }
}

/// Preflights exactly the source tree Apollo is willing to hand to the inner
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
                "YARA include directives are not supported in {}; place included rules directly under the configured rules directory so Apollo can bound and fingerprint them",
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
            "include \"/outside/apollo/unbounded.yar\"\nrule Local { condition: true }\n",
        )
        .expect("write include rule");

        let err = YaraEngine::load(dir.path()).expect_err("include must fail closed");
        assert!(
            err.to_string().contains("include directives are not supported"),
            "expected Apollo include-boundary rejection, got: {err:#}"
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
}
