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
    /// the file manager should still work with hash-only verdicts until an
    /// analyst drops rules in.
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
