use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

#[derive(Debug, Clone)]
pub struct YaraMatch {
    pub rule_name: String,
}

/// Wraps a compiled set of YARA rules loaded from a rules directory.
/// Compiled rules are safe to scan with concurrently, so this is shared
/// behind an Arc in app state rather than recompiled per scan.
pub struct YaraEngine {
    rules: Option<yara::Rules>,
    pub rules_dir: PathBuf,
    pub rule_count: usize,
    /// SHA-256, hex-encoded, over a canonical manifest of every rule file
    /// that went into this compiled ruleset: for each file, in sorted
    /// relative-path order, the manifest entry is the file's relative path,
    /// then a NUL byte, then the hex SHA-256 of its contents, then a
    /// newline. The per-file separators make this unambiguous (naive
    /// concatenation of file A followed by file B is not distinguishable
    /// from some other split X followed by Y with the same total bytes;
    /// framing each entry closes that off). Identifies *which version* of
    /// the rules produced a match: a rule's name alone is not enough to
    /// reconstruct what it actually checked for once the rule file has
    /// since been edited. Callers that persist a match durably (e.g. a
    /// fleet sighting) should persist this alongside it.
    pub ruleset_fingerprint: String,
}

impl YaraEngine {
    /// An engine with no compiled rules: every scan returns no matches.
    /// Used as the startup fallback when rule loading fails or the rules
    /// directory doesn't exist, so a bad rules directory degrades to
    /// hash-only verdicts instead of preventing the app from starting.
    pub fn empty(rules_dir: &Path) -> Self {
        Self {
            rules: None,
            rules_dir: rules_dir.to_path_buf(),
            rule_count: 0,
            ruleset_fingerprint: hex::encode(Sha256::digest(b"")),
        }
    }

    /// Loads every .yar/.yara file under rules_dir. A missing or empty
    /// directory is not an error: Phase 0 ships with no bundled rules, and
    /// callers should still work with hash-only verdicts until an analyst
    /// drops rules in.
    pub fn load(rules_dir: &Path) -> Result<Self> {
        if !rules_dir.exists() {
            return Ok(Self::empty(rules_dir));
        }

        let mut rule_files: Vec<PathBuf> = WalkDir::new(rules_dir)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .filter(|e| {
                matches!(
                    e.path().extension().and_then(|s| s.to_str()),
                    Some("yar") | Some("yara")
                )
            })
            .map(|e| e.path().to_path_buf())
            .collect();
        // Sorted so both the compile order and the fingerprint below are
        // deterministic; WalkDir's own iteration order is not guaranteed.
        rule_files.sort();

        if rule_files.is_empty() {
            return Ok(Self::empty(rules_dir));
        }

        // yara::Compiler::add_rules_str consumes self and does not hand it
        // back on error, so a single malformed rule file aborts the whole
        // batch. That is surfaced as a load error rather than silently
        // dropping rules the analyst thinks are active.
        //
        // Each file is read exactly once here and those same bytes both
        // feed the fingerprint and get compiled (via add_rules_str, not
        // add_rules_file, so the compiler never reopens the path itself).
        // Reading once and fingerprinting/compiling the read bytes is the
        // same TOCTOU fix `nsic-agent scan` applies to the scanned file:
        // fingerprinting bytes at one instant and letting the compiler
        // independently reopen the path an instant later could fingerprint
        // version A of a rule while actually compiling version B if the
        // file changed in between.
        let mut compiler = yara::Compiler::new().context("initializing YARA compiler")?;
        let mut fingerprint = Sha256::new();
        let mut loaded = 0usize;
        for file in &rule_files {
            let bytes = std::fs::read(file)
                .with_context(|| format!("reading YARA rule file {}", file.display()))?;

            let relative = file.strip_prefix(rules_dir).unwrap_or(file);
            fingerprint.update(relative.to_string_lossy().as_bytes());
            fingerprint.update(b"\0");
            fingerprint.update(hex::encode(Sha256::digest(&bytes)).as_bytes());
            fingerprint.update(b"\n");

            let source = std::str::from_utf8(&bytes)
                .with_context(|| format!("YARA rule file {} is not valid UTF-8", file.display()))?;
            compiler = compiler
                .add_rules_str(source)
                .with_context(|| format!("loading YARA rule file {}", file.display()))?;
            loaded += 1;
        }

        let rules = compiler.compile_rules().context("compiling YARA rules")?;
        Ok(Self {
            rules: Some(rules),
            rules_dir: rules_dir.to_path_buf(),
            rule_count: loaded,
            ruleset_fingerprint: hex::encode(fingerprint.finalize()),
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

    /// Scans an already-in-memory buffer instead of reopening a path.
    /// Callers that also need a hash of the same content (e.g. to report a
    /// sighting) should hash this same buffer rather than re-reading the
    /// file separately -- two reads of "the same" path can observe
    /// different bytes if the file changes in between, which for a
    /// detection this hashes and persists durably is an evidence-integrity
    /// problem, not just a race.
    pub fn scan_bytes(&self, data: &[u8]) -> Result<Vec<YaraMatch>> {
        let Some(rules) = &self.rules else {
            return Ok(vec![]);
        };
        let results = rules
            .scan_mem(data, 30)
            .context("scanning in-memory buffer")?;
        Ok(to_matches(results))
    }
}

fn to_matches(results: Vec<yara::Rule<'_>>) -> Vec<YaraMatch> {
    results
        .into_iter()
        .map(|r| YaraMatch {
            rule_name: r.identifier.to_string(),
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
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|p| p.parent())
            .expect("crates/nsic-core has a repo root two levels up")
            .join("yara-rules")
    }

    /// Loads the repo's bundled example rule (yara-rules/example_eicar.yar)
    /// and confirms it actually detects the EICAR test string. No DB, no
    /// network -- unlike most of this crate's other DB-backed tests, this
    /// one runs on every `cargo test`, not just `--ignored`, since local
    /// YARA scanning is exactly the capability the agent needs standalone.
    #[test]
    fn loads_bundled_rules_and_detects_eicar() {
        let engine = YaraEngine::load(&bundled_rules_dir()).expect("load bundled yara rules");
        assert!(
            engine.rule_count > 0,
            "expected the bundled EICAR rule to load from {}",
            bundled_rules_dir().display()
        );

        let mut tmp = tempfile::NamedTempFile::new().expect("create temp file");
        tmp.write_all(eicar_bytes()).expect("write eicar bytes");
        tmp.flush().unwrap();

        let matches = engine.scan(tmp.path()).expect("scan eicar file");
        assert!(
            matches
                .iter()
                .any(|m| m.rule_name == "Example_EICAR_Test_File"),
            "expected a match for the bundled EICAR rule, got: {matches:?}"
        );
    }

    #[test]
    fn scan_bytes_matches_scan_file_for_the_same_content() {
        let engine = YaraEngine::load(&bundled_rules_dir()).expect("load bundled yara rules");

        let matches = engine
            .scan_bytes(eicar_bytes())
            .expect("scan eicar bytes in memory");
        assert!(
            matches
                .iter()
                .any(|m| m.rule_name == "Example_EICAR_Test_File"),
            "expected a match for the bundled EICAR rule, got: {matches:?}"
        );
    }

    #[test]
    fn missing_rules_dir_is_not_an_error() {
        let engine = YaraEngine::load(Path::new("/nonexistent/does-not-exist-nsic-test"))
            .expect("a missing rules dir should not error");
        assert_eq!(engine.rule_count, 0);
    }

    #[test]
    fn ruleset_fingerprint_is_deterministic_and_distinguishes_rulesets() {
        let loaded = YaraEngine::load(&bundled_rules_dir()).expect("load bundled yara rules");
        let loaded_again =
            YaraEngine::load(&bundled_rules_dir()).expect("load bundled yara rules again");
        assert_eq!(
            loaded.ruleset_fingerprint, loaded_again.ruleset_fingerprint,
            "loading the same rules directory twice should fingerprint identically"
        );

        let empty = YaraEngine::empty(Path::new("/nonexistent/does-not-exist-nsic-test"));
        assert_ne!(
            loaded.ruleset_fingerprint, empty.ruleset_fingerprint,
            "a real ruleset and an empty one must not share a fingerprint"
        );

        let missing = YaraEngine::load(Path::new("/nonexistent/does-not-exist-nsic-test"))
            .expect("a missing rules dir should not error");
        assert_eq!(
            missing.ruleset_fingerprint, empty.ruleset_fingerprint,
            "a missing rules dir degrades to the same fingerprint as an explicitly empty engine"
        );
    }
}
