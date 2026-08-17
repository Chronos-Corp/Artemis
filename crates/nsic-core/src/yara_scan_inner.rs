use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// Maximum distinct YARA detections one desktop verdict will materialize,
/// persist, and expose as pivots. The active ruleset itself is separately
/// bounded, so this is not a cosmetic truncation after unbounded work.
pub const MAX_YARA_MATCHES_PER_VERDICT: usize = 200;

const MAX_YARA_RULE_FILES: usize = 1024;
const MAX_YARA_RULE_FILE_BYTES: usize = 2 * 1024 * 1024;
const MAX_YARA_RULESET_BYTES: usize = 16 * 1024 * 1024;
const MAX_YARA_RULES: usize = 2048;

#[derive(Debug, Clone)]
pub struct YaraMatch {
    pub rule_name: String,
}

#[derive(Debug, Clone)]
pub struct BoundedYaraMatches {
    pub matches: Vec<YaraMatch>,
    pub truncated: bool,
}

/// Compiled local YARA rules plus stable content identity.
///
/// The rules directory is attacker-influenced on a potentially compromised
/// host. Loading therefore owns all filesystem reads, bounds every resource
/// dimension, fingerprints the exact bytes handed to libyara, and disables
/// YARA `include` handling on the compiler before any source is added. The
/// latter is important: include resolution would otherwise let libyara
/// perform an implicit second filesystem traversal outside Apollo's file,
/// byte, opened-handle, and fingerprint controls.
pub struct YaraEngine {
    rules: Option<yara::Rules>,
    pub rules_dir: PathBuf,
    pub rule_count: usize,
    pub ruleset_fingerprint: String,
    pub rule_fingerprints: HashMap<String, String>,
}

impl YaraEngine {
    pub fn empty(rules_dir: &Path) -> Self {
        Self {
            rules: None,
            rules_dir: rules_dir.to_path_buf(),
            rule_count: 0,
            ruleset_fingerprint: hex::encode(Sha256::digest(b"")),
            rule_fingerprints: HashMap::new(),
        }
    }

    pub fn rule_fingerprint(&self, rule_name: &str) -> Option<&str> {
        self.rule_fingerprints.get(rule_name).map(String::as_str)
    }

    /// Load all `.yar`/`.yara` files under `rules_dir` under finite resource
    /// bounds. A missing or empty directory is a valid empty ruleset.
    pub fn load(rules_dir: &Path) -> Result<Self> {
        if !rules_dir.exists() {
            return Ok(Self::empty(rules_dir));
        }

        let mut rule_files = Vec::new();
        for entry in WalkDir::new(rules_dir) {
            let entry = entry.with_context(|| {
                format!("walking YARA rules directory {}", rules_dir.display())
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
            if rule_files.len() >= MAX_YARA_RULE_FILES {
                bail!(
                    "YARA rules directory contains more than {MAX_YARA_RULE_FILES} rule files; refusing unbounded ruleset"
                );
            }
            rule_files.push(entry.path().to_path_buf());
        }
        rule_files.sort();

        if rule_files.is_empty() {
            return Ok(Self::empty(rules_dir));
        }

        let mut compiler = yara::Compiler::new().context("initializing YARA compiler")?;
        // yara 0.29 exposes this exact control. It installs no include
        // callback on the underlying libyara compiler, so an `include`
        // directive cannot cause a filesystem read behind Apollo's back.
        // This happens before the first add_rules_str and therefore protects
        // the exact source bytes actually compiled, with no check/use gap.
        compiler.disable_include_directive();

        let mut ruleset_fingerprint = Sha256::new();
        let mut rule_fingerprints = HashMap::new();
        let mut loaded_rules = 0usize;
        let mut total_rule_bytes = 0usize;

        for file in &rule_files {
            let bytes = read_rule_file_bounded(file)?;
            total_rule_bytes = total_rule_bytes
                .checked_add(bytes.len())
                .context("YARA ruleset byte count overflow")?;
            if total_rule_bytes > MAX_YARA_RULESET_BYTES {
                bail!(
                    "YARA ruleset exceeds {MAX_YARA_RULESET_BYTES} bytes of source; refusing unbounded ruleset"
                );
            }

            let file_fingerprint = hex::encode(Sha256::digest(&bytes));
            let relative = file.strip_prefix(rules_dir).unwrap_or(file);
            ruleset_fingerprint.update(relative.to_string_lossy().as_bytes());
            ruleset_fingerprint.update(b"\0");
            ruleset_fingerprint.update(file_fingerprint.as_bytes());
            ruleset_fingerprint.update(b"\n");

            let source = std::str::from_utf8(&bytes)
                .with_context(|| format!("YARA rule file {} is not valid UTF-8", file.display()))?;
            let names = extract_rule_names(source);
            loaded_rules = loaded_rules
                .checked_add(names.len())
                .context("YARA rule declaration count overflow")?;
            if loaded_rules > MAX_YARA_RULES {
                bail!(
                    "YARA ruleset contains more than {MAX_YARA_RULES} rule declarations; refusing unbounded ruleset"
                );
            }
            for name in names {
                rule_fingerprints.insert(name, file_fingerprint.clone());
            }

            // The same `source` bytes above feed both the fingerprints and
            // compiler. libyara never reopens this path.
            compiler = compiler
                .add_rules_str(source)
                .with_context(|| format!("loading YARA rule file {}", file.display()))?;
        }

        let rules = compiler.compile_rules().context("compiling YARA rules")?;
        Ok(Self {
            rules: Some(rules),
            rules_dir: rules_dir.to_path_buf(),
            rule_count: loaded_rules,
            ruleset_fingerprint: hex::encode(ruleset_fingerprint.finalize()),
            rule_fingerprints,
        })
    }

    pub fn scan(&self, file_path: &Path) -> Result<Vec<YaraMatch>> {
        let Some(rules) = &self.rules else {
            return Ok(vec![]);
        };
        let results = rules
            .scan_file(file_path, 30)
            .with_context(|| format!("scanning {}", file_path.display()))?;
        Ok(to_matches(results))
    }

    /// Scan an already-read byte snapshot. Verdict callers hash these same
    /// bytes, so the persisted hash and YARA observation cannot come from two
    /// different versions of a concurrently-changing path.
    pub fn scan_bytes(&self, data: &[u8]) -> Result<Vec<YaraMatch>> {
        let Some(rules) = &self.rules else {
            return Ok(vec![]);
        };
        let results = rules
            .scan_mem(data, 30)
            .context("scanning in-memory buffer")?;
        Ok(to_matches(results))
    }

    /// Deterministically bound current rule hits. Rule names are sorted and
    /// deduplicated before truncation, so an omitted hit is an omitted
    /// Detection target, not duplicate evidence for a target already shown.
    pub fn scan_bytes_bounded(&self, data: &[u8]) -> Result<BoundedYaraMatches> {
        let mut matches = self.scan_bytes(data)?;
        matches.sort_by(|a, b| a.rule_name.cmp(&b.rule_name));
        matches.dedup_by(|a, b| a.rule_name == b.rule_name);
        let truncated = matches.len() > MAX_YARA_MATCHES_PER_VERDICT;
        matches.truncate(MAX_YARA_MATCHES_PER_VERDICT);
        Ok(BoundedYaraMatches { matches, truncated })
    }
}

/// Open first, then make the type/size safety decision on that exact handle.
/// On Unix the nonblocking flag prevents an attacker-swapped FIFO from
/// hanging during open before we can reject it.
fn open_rule_file(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC);
    }

    let file = options
        .open(path)
        .with_context(|| format!("opening YARA rule file {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("inspecting opened YARA rule file {}", path.display()))?;
    if !metadata.file_type().is_file() {
        bail!(
            "refusing non-regular YARA rule file {} after open",
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

fn read_rule_file_bounded(path: &Path) -> Result<Vec<u8>> {
    let file = open_rule_file(path)?;
    let mut bytes = Vec::new();
    file.take(MAX_YARA_RULE_FILE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("reading YARA rule file {}", path.display()))?;
    // A regular file can grow after metadata(). The actual read remains the
    // authority for the memory/source ceiling.
    if bytes.len() > MAX_YARA_RULE_FILE_BYTES {
        bail!(
            "YARA rule file {} exceeded the {MAX_YARA_RULE_FILE_BYTES}-byte limit while reading",
            path.display()
        );
    }
    Ok(bytes)
}

fn extract_rule_names(source: &str) -> Vec<String> {
    let cleaned = strip_comments_and_strings(source);
    let tokens: Vec<&str> = cleaned
        .split(|c: char| !(c.is_alphanumeric() || c == '_'))
        .filter(|s| !s.is_empty())
        .collect();
    let mut names = Vec::new();
    let mut i = 0;
    while i < tokens.len() {
        if tokens[i] == "rule" && i + 1 < tokens.len() {
            names.push(tokens[i + 1].to_string());
            i += 2;
        } else {
            i += 1;
        }
    }
    names
}

/// Blanks comments, quoted strings, and regex literals before the lightweight
/// rule-declaration scan. This prevents rule-shaped text in patterns from
/// claiming another file's rule fingerprint.
fn strip_comments_and_strings(source: &str) -> String {
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

fn to_matches(results: Vec<yara::Rule<'_>>) -> Vec<YaraMatch> {
    results
        .into_iter()
        .map(|rule| YaraMatch {
            rule_name: rule.identifier.to_string(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn eicar_bytes() -> &'static [u8] {
        br"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    }

    fn bundled_rules_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|p| p.parent())
            .expect("repo root")
            .join("yara-rules")
    }

    #[test]
    fn loads_bundled_rules_and_detects_eicar() {
        let engine = YaraEngine::load(&bundled_rules_dir()).expect("load bundled rules");
        assert!(engine.rule_count > 0);
        let hits = engine.scan_bytes(eicar_bytes()).expect("scan EICAR bytes");
        assert!(hits.iter().any(|h| h.rule_name == "Example_EICAR_Test_File"));
    }

    #[test]
    fn bounded_scan_is_deterministic_and_reports_truncation() {
        let dir = tempfile::tempdir().unwrap();
        let mut source = String::new();
        for n in 0..(MAX_YARA_MATCHES_PER_VERDICT + 5) {
            source.push_str(&format!("rule Rule_{n:04} {{ condition: true }}\n"));
        }
        std::fs::write(dir.path().join("many.yar"), source).unwrap();
        let engine = YaraEngine::load(dir.path()).unwrap();
        let bounded = engine.scan_bytes_bounded(b"irrelevant").unwrap();
        assert!(bounded.truncated);
        assert_eq!(bounded.matches.len(), MAX_YARA_MATCHES_PER_VERDICT);
        assert_eq!(bounded.matches.first().unwrap().rule_name, "Rule_0000");
        assert_eq!(
            bounded.matches.last().unwrap().rule_name,
            format!("Rule_{:04}", MAX_YARA_MATCHES_PER_VERDICT - 1)
        );
    }

    #[test]
    fn compiler_itself_rejects_include_directives() {
        let dir = tempfile::tempdir().unwrap();
        // The included file exists and is valid. The test therefore proves
        // includes were disabled on the compiler, not merely that resolution
        // happened to fail because the target was missing.
        std::fs::write(
            dir.path().join("other.yar"),
            "rule IncludedRule { condition: true }\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("top.yar"),
            "include \"other.yar\"\nrule TopRule { condition: true }\n",
        )
        .unwrap();

        let result = YaraEngine::load(dir.path());
        assert!(result.is_err(), "disabled include directive must fail compilation");
    }

    #[test]
    fn rejects_oversized_rule_file_without_buffering_it_in_full() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("large.yar"),
            vec![b' '; MAX_YARA_RULE_FILE_BYTES + 1],
        )
        .unwrap();
        assert!(YaraEngine::load(dir.path()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn rule_reader_rejects_fifo_without_waiting_for_writer() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("swapped.yar");
        let path = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        let rc = unsafe { libc::mkfifo(path.as_ptr(), 0o600) };
        assert_eq!(rc, 0, "mkfifo failed: {}", std::io::Error::last_os_error());
        assert!(read_rule_file_bounded(&fifo).is_err());
    }

    #[test]
    fn rejects_ruleset_with_too_many_rule_declarations() {
        let dir = tempfile::tempdir().unwrap();
        let mut source = String::new();
        for n in 0..=MAX_YARA_RULES {
            source.push_str(&format!("rule TooMany_{n:04} {{ condition: false }}\n"));
        }
        std::fs::write(dir.path().join("too-many.yar"), source).unwrap();
        assert!(YaraEngine::load(dir.path()).is_err());
    }

    #[test]
    fn editing_unrelated_rule_file_does_not_change_other_rules_fingerprint() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("a.yar"),
            "rule RuleA { strings: $a = \"AAA\" condition: $a }",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("b.yar"),
            "rule RuleB { strings: $b = \"BBB\" condition: $b }",
        )
        .unwrap();
        let before = YaraEngine::load(dir.path()).unwrap();
        let a_before = before.rule_fingerprint("RuleA").unwrap().to_string();
        let whole_before = before.ruleset_fingerprint.clone();

        std::fs::write(
            dir.path().join("b.yar"),
            "rule RuleB { strings: $b = \"BBB_CHANGED\" condition: $b }",
        )
        .unwrap();
        let after = YaraEngine::load(dir.path()).unwrap();
        assert_eq!(after.rule_fingerprint("RuleA"), Some(a_before.as_str()));
        assert_ne!(after.ruleset_fingerprint, whole_before);
    }

    #[test]
    fn regex_rule_shaped_text_cannot_hijack_another_files_fingerprint() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("a_target.yar"),
            "rule TargetRule { condition: true }",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("z_decoy.yar"),
            "rule Decoy { strings: $r = /rule TargetRule/ condition: $r }",
        )
        .unwrap();
        let engine = YaraEngine::load(dir.path()).unwrap();
        let expected = hex::encode(Sha256::digest(
            std::fs::read(dir.path().join("a_target.yar")).unwrap(),
        ));
        assert_eq!(engine.rule_fingerprint("TargetRule"), Some(expected.as_str()));
    }

    #[test]
    fn missing_rules_dir_is_empty_not_error() {
        let engine = YaraEngine::load(Path::new("/nonexistent/apollo-yara-test")).unwrap();
        assert_eq!(engine.rule_count, 0);
    }
}
