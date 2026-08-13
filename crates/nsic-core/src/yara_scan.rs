use anyhow::{Context, Result};
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

        let rule_files: Vec<PathBuf> = WalkDir::new(rules_dir)
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

        if rule_files.is_empty() {
            return Ok(Self::empty(rules_dir));
        }

        // yara::Compiler::add_rules_file consumes self and does not hand it
        // back on error, so a single malformed rule file aborts the whole
        // batch. That is surfaced as a load error rather than silently
        // dropping rules the analyst thinks are active.
        let mut compiler = yara::Compiler::new().context("initializing YARA compiler")?;
        let mut loaded = 0usize;
        for file in &rule_files {
            compiler = compiler
                .add_rules_file(file)
                .with_context(|| format!("loading YARA rule file {}", file.display()))?;
            loaded += 1;
        }

        let rules = compiler.compile_rules().context("compiling YARA rules")?;
        Ok(Self {
            rules: Some(rules),
            rules_dir: rules_dir.to_path_buf(),
            rule_count: loaded,
        })
    }

    pub fn scan(&self, file_path: &Path) -> Result<Vec<YaraMatch>> {
        let Some(rules) = &self.rules else {
            return Ok(vec![]);
        };
        let results = rules
            .scan_file(file_path, 30)
            .with_context(|| format!("scanning {}", file_path.display()))?;
        Ok(results
            .into_iter()
            .map(|r| YaraMatch {
                rule_name: r.identifier.to_string(),
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn eicar_bytes() -> &'static [u8] {
        br"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    }

    /// Loads the repo's bundled example rule (yara-rules/example_eicar.yar)
    /// and confirms it actually detects the EICAR test string. No DB, no
    /// network -- unlike most of this crate's other DB-backed tests, this
    /// one runs on every `cargo test`, not just `--ignored`, since local
    /// YARA scanning is exactly the capability the agent needs standalone.
    #[test]
    fn loads_bundled_rules_and_detects_eicar() {
        let rules_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|p| p.parent())
            .expect("crates/nsic-core has a repo root two levels up")
            .join("yara-rules");
        let engine = YaraEngine::load(&rules_dir).expect("load bundled yara rules");
        assert!(
            engine.rule_count > 0,
            "expected the bundled EICAR rule to load from {}",
            rules_dir.display()
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
    fn missing_rules_dir_is_not_an_error() {
        let engine = YaraEngine::load(Path::new("/nonexistent/does-not-exist-nsic-test"))
            .expect("a missing rules dir should not error");
        assert_eq!(engine.rule_count, 0);
    }
}
