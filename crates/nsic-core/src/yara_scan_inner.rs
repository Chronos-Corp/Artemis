use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::ops::Range;
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
/// perform an implicit second filesystem traversal outside Artemis's file,
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
        // directive cannot cause a filesystem read behind Artemis's back.
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
            let rule_spans = extract_rule_spans(source)
                .with_context(|| format!("parsing YARA rule boundaries in {}", file.display()))?;
            loaded_rules = loaded_rules
                .checked_add(rule_spans.len())
                .context("YARA rule declaration count overflow")?;
            if loaded_rules > MAX_YARA_RULES {
                bail!(
                    "YARA ruleset contains more than {MAX_YARA_RULES} rule declarations; refusing unbounded ruleset"
                );
            }

            // Round 11: rule version identity must be scoped to the exact
            // declaration/body for that rule, not to the whole file that
            // happens to contain it. A single .yar file often contains many
            // rules; hashing the whole file made editing RuleB invalidate an
            // unchanged RuleA -> CVE coverage assertion. The span parser below
            // finds each rule's own source block while ignoring braces/tokens
            // inside comments, strings, and regex literals, then hashes only
            // that exact slice of the bytes also handed to libyara.
            for rule in rule_spans {
                let rule_fingerprint =
                    hex::encode(Sha256::digest(&bytes[rule.source_range.clone()]));
                if rule_fingerprints
                    .insert(rule.name.clone(), rule_fingerprint)
                    .is_some()
                {
                    bail!("duplicate YARA rule identifier: {}", rule.name);
                }
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

#[derive(Debug, Clone)]
struct RuleSourceSpan {
    name: String,
    source_range: Range<usize>,
}

/// Finds the exact source range for every YARA rule in one source file.
///
/// This is deliberately a small lexical boundary scanner rather than a
/// second YARA parser. It only needs two facts: where a real `rule <name>`
/// declaration begins, and where that declaration's outer brace closes. The
/// byte mask blanks comments, quoted strings, and regex literals *without
/// changing offsets*, so rule-shaped text and brace quantifiers inside those
/// regions cannot affect either decision. Hex-string braces remain visible;
/// they are balanced nested braces and therefore compose correctly with the
/// outer rule body depth.
fn extract_rule_spans(source: &str) -> Result<Vec<RuleSourceSpan>> {
    let bytes = source.as_bytes();
    let masked = mask_non_code_preserving_offsets(source);
    let mut rules = Vec::new();
    let mut i = 0usize;

    while i < masked.len() {
        if !word_at(&masked, i, b"rule") {
            i += 1;
            continue;
        }

        let declaration_start = include_rule_modifiers(&masked, i);
        let mut cursor = i + b"rule".len();
        skip_ascii_whitespace(&masked, &mut cursor);
        let name_start = cursor;
        while cursor < masked.len() && is_identifier_byte(masked[cursor]) {
            cursor += 1;
        }
        if cursor == name_start {
            bail!("YARA rule declaration at byte {i} has no identifier");
        }
        let name = std::str::from_utf8(&bytes[name_start..cursor])
            .context("YARA rule identifier is not valid UTF-8")?
            .to_string();

        while cursor < masked.len() && masked[cursor] != b'{' {
            cursor += 1;
        }
        if cursor == masked.len() {
            bail!("YARA rule {name} has no opening body brace");
        }

        let mut depth = 0usize;
        let mut end = None;
        for (offset, byte) in masked[cursor..].iter().copied().enumerate() {
            match byte {
                b'{' => depth += 1,
                b'}' => {
                    if depth == 0 {
                        bail!("YARA rule {name} has an unmatched closing brace");
                    }
                    depth -= 1;
                    if depth == 0 {
                        end = Some(cursor + offset + 1);
                        break;
                    }
                }
                _ => {}
            }
        }
        let end = end.with_context(|| format!("YARA rule {name} has no closing body brace"))?;

        rules.push(RuleSourceSpan {
            name,
            source_range: declaration_start..end,
        });
        i = end;
    }

    Ok(rules)
}

fn include_rule_modifiers(masked: &[u8], rule_start: usize) -> usize {
    let mut start = rule_start;
    loop {
        let mut cursor = start;
        while cursor > 0 && masked[cursor - 1].is_ascii_whitespace() {
            cursor -= 1;
        }
        let word_end = cursor;
        while cursor > 0 && is_identifier_byte(masked[cursor - 1]) {
            cursor -= 1;
        }
        if word_end == cursor {
            break;
        }
        match &masked[cursor..word_end] {
            b"private" | b"global" => start = cursor,
            _ => break,
        }
    }
    start
}

fn skip_ascii_whitespace(bytes: &[u8], cursor: &mut usize) {
    while *cursor < bytes.len() && bytes[*cursor].is_ascii_whitespace() {
        *cursor += 1;
    }
}

fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn word_at(bytes: &[u8], index: usize, word: &[u8]) -> bool {
    let Some(end) = index.checked_add(word.len()) else {
        return false;
    };
    if end > bytes.len() || &bytes[index..end] != word {
        return false;
    }
    let left_ok = index == 0 || !is_identifier_byte(bytes[index - 1]);
    let right_ok = end == bytes.len() || !is_identifier_byte(bytes[end]);
    left_ok && right_ok
}

/// Blanks comments, quoted strings, and regex literals byte-for-byte while
/// preserving source offsets for `extract_rule_spans`.
fn mask_non_code_preserving_offsets(source: &str) -> Vec<u8> {
    let bytes = source.as_bytes();
    let mut masked = bytes.to_vec();
    let mut i = 0usize;

    while i < bytes.len() {
        if bytes[i] == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
            let start = i;
            i += 2;
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            blank_range(&mut masked, start, i);
            continue;
        }

        if bytes[i] == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'*' {
            let start = i;
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                i += 1;
            }
            if i + 1 < bytes.len() {
                i += 2;
            } else {
                i = bytes.len();
            }
            blank_range(&mut masked, start, i);
            continue;
        }

        if bytes[i] == b'"' {
            let start = i;
            i += 1;
            let mut escaped = false;
            while i < bytes.len() {
                let byte = bytes[i];
                i += 1;
                if escaped {
                    escaped = false;
                    continue;
                }
                if byte == b'\\' {
                    escaped = true;
                } else if byte == b'"' {
                    break;
                }
            }
            blank_range(&mut masked, start, i);
            continue;
        }

        if bytes[i] == b'/' && regex_literal_starts(&masked, i) {
            let start = i;
            i += 1;
            let mut escaped = false;
            while i < bytes.len() {
                let byte = bytes[i];
                i += 1;
                if escaped {
                    escaped = false;
                    continue;
                }
                if byte == b'\\' {
                    escaped = true;
                } else if byte == b'/' {
                    break;
                }
            }
            while i < bytes.len() && bytes[i].is_ascii_alphabetic() {
                i += 1;
            }
            blank_range(&mut masked, start, i);
            continue;
        }

        i += 1;
    }

    masked
}

fn regex_literal_starts(masked: &[u8], slash_index: usize) -> bool {
    let mut cursor = slash_index;
    while cursor > 0 && masked[cursor - 1].is_ascii_whitespace() {
        cursor -= 1;
    }
    if cursor > 0 && masked[cursor - 1] == b'=' {
        return true;
    }

    let word_end = cursor;
    while cursor > 0 && is_identifier_byte(masked[cursor - 1]) {
        cursor -= 1;
    }
    &masked[cursor..word_end] == b"matches"
}

fn blank_range(masked: &mut [u8], start: usize, end: usize) {
    for byte in &mut masked[start..end] {
        if *byte != b'\n' && *byte != b'\r' {
            *byte = b' ';
        }
    }
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
        assert!(hits
            .iter()
            .any(|h| h.rule_name == "Example_EICAR_Test_File"));
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
    fn editing_sibling_rule_in_same_file_only_changes_that_rules_fingerprint() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pack.yar");
        std::fs::write(
            &path,
            r#"
                rule RuleA {
                    strings: $a = "AAA"
                    condition: $a
                }

                rule RuleB {
                    strings: $b = /B{2,4}/
                    condition: $b
                }
            "#,
        )
        .unwrap();

        let before = YaraEngine::load(dir.path()).unwrap();
        let a_before = before.rule_fingerprint("RuleA").unwrap().to_string();
        let b_before = before.rule_fingerprint("RuleB").unwrap().to_string();
        let whole_before = before.ruleset_fingerprint.clone();

        std::fs::write(
            &path,
            r#"
                rule RuleA {
                    strings: $a = "AAA"
                    condition: $a
                }

                rule RuleB {
                    strings: $b = /B{3,5}/
                    condition: $b
                }
            "#,
        )
        .unwrap();

        let after = YaraEngine::load(dir.path()).unwrap();
        assert_eq!(
            after.rule_fingerprint("RuleA"),
            Some(a_before.as_str()),
            "editing RuleB in the same source file must not invalidate unchanged RuleA coverage"
        );
        assert_ne!(after.rule_fingerprint("RuleB"), Some(b_before.as_str()));
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
    fn private_and_global_modifiers_are_part_of_rule_version_identity() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("modifiers.yar");
        std::fs::write(&path, "private rule Scoped { condition: true }").unwrap();
        let private = YaraEngine::load(dir.path()).unwrap();
        let private_fp = private.rule_fingerprint("Scoped").unwrap().to_string();

        std::fs::write(&path, "rule Scoped { condition: true }").unwrap();
        let ordinary = YaraEngine::load(dir.path()).unwrap();
        assert_ne!(ordinary.rule_fingerprint("Scoped"), Some(private_fp.as_str()));
    }

    #[test]
    fn missing_rules_dir_is_empty_not_error() {
        let engine = YaraEngine::load(Path::new("/nonexistent/artemis-yara-test")).unwrap();
        assert_eq!(engine.rule_count, 0);
    }
}
