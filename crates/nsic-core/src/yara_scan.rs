use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
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
    /// Per-rule content identity: for each compiled rule identifier, the
    /// SHA-256 (hex) of the *one file* that declared it -- not the whole
    /// ruleset. A review caught that `ruleset_fingerprint` above, hashing
    /// every rule file in the directory together, is the wrong identity
    /// for scoping a `detection_covers_cve` assertion to "this rule's
    /// content": editing an unrelated rule B elsewhere in the directory
    /// changes `ruleset_fingerprint` even though rule A's own definition
    /// never changed, which would falsely invalidate A's coverage evidence
    /// on every unrelated edit. Scoping by the declaring file's own content
    /// hash instead means A's identity only changes when A's file actually
    /// does. Two rules that happen to share one file share that file's
    /// fingerprint too (edits to either invalidate both) -- an accepted
    /// coarseness given `yara::Rules` exposes no finer-grained provenance
    /// than "which compiled rule identifier fired," not "which file"; the
    /// existing test fixtures (and the one-rule-per-file convention the
    /// bundled rules already follow) keep this precise in practice.
    /// Populated by lightly parsing each file's own source for `rule
    /// <identifier>` declarations (see `extract_rule_names`) -- best-effort
    /// on unusual formatting, not a full YARA grammar; a rule whose
    /// declaration this miss falls back to no entry, and callers treat a
    /// missing entry as "version unknown" (empty string, read the same as
    /// the wildcard `detection_covers_cve.rule_fingerprint = ''`) rather
    /// than erroring.
    pub rule_fingerprints: HashMap<String, String>,
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
            rule_fingerprints: HashMap::new(),
        }
    }

    /// The content identity of one specific rule -- see
    /// `rule_fingerprints`'s doc comment. `None` when the rule name isn't
    /// known at all (never compiled) *or* its declaration wasn't found by
    /// the lightweight parser; callers should treat both the same way
    /// (version-unknown, i.e. the wildcard).
    pub fn rule_fingerprint(&self, rule_name: &str) -> Option<&str> {
        self.rule_fingerprints.get(rule_name).map(String::as_str)
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
        let mut rule_fingerprints = HashMap::new();
        let mut loaded = 0usize;
        for file in &rule_files {
            let bytes = std::fs::read(file)
                .with_context(|| format!("reading YARA rule file {}", file.display()))?;
            let file_fingerprint = hex::encode(Sha256::digest(&bytes));

            let relative = file.strip_prefix(rules_dir).unwrap_or(file);
            fingerprint.update(relative.to_string_lossy().as_bytes());
            fingerprint.update(b"\0");
            fingerprint.update(file_fingerprint.as_bytes());
            fingerprint.update(b"\n");

            let source = std::str::from_utf8(&bytes)
                .with_context(|| format!("YARA rule file {} is not valid UTF-8", file.display()))?;
            for rule_name in extract_rule_names(source) {
                rule_fingerprints.insert(rule_name, file_fingerprint.clone());
            }
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

/// Extracts every `rule <identifier>` declaration from a YARA source file,
/// for building `rule_fingerprints`. A lightweight lexer, not a real YARA
/// grammar: strips `//`/`/* */` comments, `"..."` string literals, and
/// `/.../ ` regex literals first (replacing their contents with spaces, so
/// surrounding token structure and line numbers survive), then scans the
/// remaining identifier-like tokens for `rule` followed by its identifier.
///
/// A round-7 review caught a real false-positive in an earlier version of
/// this function that did *not* strip regex literals: a YARA string
/// pattern like `$r = /rule TargetRule/` is a completely ordinary,
/// syntactically valid regex string definition, and the un-stripped
/// `rule TargetRule` substring inside it was indistinguishable from a real
/// declaration -- worse, since `rule_fingerprints` is a plain `HashMap`
/// keyed by identifier, a false match in file B could silently overwrite
/// the correct mapping for a same-named rule genuinely declared in file A,
/// corrupting that rule's actual version identity. `strip_comments_and_strings`
/// now also recognizes and blanks regex literals.
///
/// This is still a lexer, not a parser, so it remains best-effort on truly
/// unusual formatting -- a name this misses degrades to "version unknown"
/// for that rule, `rule_fingerprint` returning `None`, never a hard
/// failure or a silently wrong identity.
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

/// Replaces the contents of `//`/`/* */` comments, `"..."` string
/// literals, and `/.../ ` regex literals with spaces, character-by-character
/// (not byte-by-byte, to stay UTF-8 safe on non-ASCII content) so a
/// `rule`-like substring inside any of them (a comment, a quoted string
/// containing the literal text "rule engine", or -- the case a round-7
/// review caught missing -- a regex pattern like `$r = /rule TargetRule/`)
/// can't be mistaken for an actual declaration by `extract_rule_names`.
///
/// A bare `/` is *not* ambiguous in YARA the way it is in languages like
/// JavaScript: YARA's arithmetic division operator is a backslash (`\`),
/// specifically so that `/` can unconditionally mean "start of a regex
/// literal" outside a comment or string -- confirmed empirically while
/// fixing this (an earlier version of this function tried to disambiguate
/// `/` division from `/` regex using a same-line heuristic; every test
/// rule using `/` for arithmetic failed to compile with libyara's own
/// "unterminated regular expression" error, which is libyara telling us
/// `/` was never a valid division operator to begin with). So every `/`
/// reaching this point that isn't the start of `//` or `/*` begins a
/// regex literal, full stop.
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
            // Regex literal: blank up to the closing unescaped `/`, then
            // any trailing single-letter modifiers (e.g. the `i` in
            // `/foo/i`), which YARA allows immediately after with no
            // separator.
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

    /// Round 6 review finding: `ruleset_fingerprint` hashes every rule file
    /// in the directory together, so editing an unrelated rule invalidates
    /// every other rule's version identity too. `rule_fingerprint` must be
    /// scoped to the one file that actually declared the rule -- editing a
    /// sibling file must not change it.
    #[test]
    fn editing_one_rule_file_does_not_change_an_unrelated_rules_fingerprint() {
        let dir = tempfile::tempdir().expect("create temp rules dir");
        std::fs::write(
            dir.path().join("rule_a.yar"),
            "rule RuleA { strings: $s = \"AAA\" condition: $s }",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("rule_b.yar"),
            "rule RuleB { strings: $s = \"BBB\" condition: $s }",
        )
        .unwrap();

        let before = YaraEngine::load(dir.path()).expect("load rules");
        let fp_a_before = before
            .rule_fingerprint("RuleA")
            .expect("RuleA should have a fingerprint")
            .to_string();
        let fp_b_before = before
            .rule_fingerprint("RuleB")
            .expect("RuleB should have a fingerprint")
            .to_string();
        assert_ne!(
            fp_a_before, fp_b_before,
            "two rules in different files must not share a fingerprint"
        );

        // Edit only rule B's file.
        std::fs::write(
            dir.path().join("rule_b.yar"),
            "rule RuleB { strings: $s = \"BBB_CHANGED\" condition: $s }",
        )
        .unwrap();

        let after = YaraEngine::load(dir.path()).expect("reload rules");
        assert_eq!(
            after.rule_fingerprint("RuleA"),
            Some(fp_a_before.as_str()),
            "editing an unrelated rule file must not change RuleA's fingerprint"
        );
        assert_ne!(
            after.rule_fingerprint("RuleB"),
            Some(fp_b_before.as_str()),
            "RuleB's own fingerprint must change since its file's content changed"
        );

        // The whole-ruleset fingerprint, by contrast, is expected to change
        // on *any* file edit -- that's the coarser identity Phase 1's fleet
        // sighting path deliberately wants (see host_sighted_indicator's
        // migration comment), distinct from what rule_fingerprint is for.
        assert_ne!(
            before.ruleset_fingerprint, after.ruleset_fingerprint,
            "the whole-directory fingerprint is still expected to change on any edit"
        );
    }

    #[test]
    fn rule_fingerprint_is_unknown_for_a_rule_that_was_never_loaded() {
        let engine = YaraEngine::load(&bundled_rules_dir()).expect("load bundled yara rules");
        assert_eq!(engine.rule_fingerprint("NoSuchRule"), None);
    }

    /// Round 7 review finding: a YARA regex literal (`/pattern/`) inside
    /// one file's `strings:` block can contain the literal text
    /// `rule <identifier>` as ordinary pattern content -- a fully valid,
    /// unremarkable regex definition, not an edge case. An earlier version
    /// of `strip_comments_and_strings` didn't recognize regex literals at
    /// all, so that text passed through unstripped and `extract_rule_names`
    /// mistook it for a real declaration; since `rule_fingerprints` is a
    /// plain `HashMap`, the decoy file's fingerprint then silently
    /// overwrote the real rule's correct one. This reproduces the review's
    /// exact scenario: `a_target.yar` genuinely declares `TargetRule`;
    /// `z_decoy.yar` (sorted after it, so processed second and able to
    /// overwrite) declares an unrelated `Decoy` rule whose only pattern is
    /// the regex `/rule TargetRule/`.
    #[test]
    fn a_regex_literal_containing_rule_syntax_does_not_hijack_another_files_fingerprint() {
        let dir = tempfile::tempdir().expect("create temp rules dir");
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

        let engine = YaraEngine::load(dir.path()).expect("load rules");
        assert_eq!(engine.rule_count, 2, "expected both rules to load");

        let target_fp = engine
            .rule_fingerprint("TargetRule")
            .expect("TargetRule should have a fingerprint")
            .to_string();
        let target_file_fp = hex::encode(Sha256::digest(
            std::fs::read(dir.path().join("a_target.yar")).unwrap(),
        ));
        assert_eq!(
            target_fp, target_file_fp,
            "TargetRule's fingerprint must be a_target.yar's own content hash, not \
             z_decoy.yar's (which the regex literal could otherwise hijack it to)"
        );

        // Editing only the decoy's regex must not change TargetRule's
        // fingerprint -- proves the hijack is closed in both directions,
        // not just that the initial load happened to pick the right file.
        std::fs::write(
            dir.path().join("z_decoy.yar"),
            "rule Decoy { strings: $r = /rule TargetRule CHANGED/ condition: $r }",
        )
        .unwrap();
        let reloaded = YaraEngine::load(dir.path()).expect("reload rules");
        assert_eq!(
            reloaded.rule_fingerprint("TargetRule"),
            Some(target_fp.as_str()),
            "editing only the decoy's regex must not change TargetRule's fingerprint"
        );

        // Editing the real TargetRule file, conversely, must change its
        // fingerprint even with the decoy regex still present and
        // unchanged.
        std::fs::write(
            dir.path().join("a_target.yar"),
            "rule TargetRule { condition: filesize > 0 }",
        )
        .unwrap();
        let after_real_edit = YaraEngine::load(dir.path()).expect("reload rules again");
        assert_ne!(
            after_real_edit.rule_fingerprint("TargetRule"),
            Some(target_fp.as_str()),
            "editing TargetRule's real file must change its fingerprint"
        );
    }

    /// Sanity check for the claim in `strip_comments_and_strings`'s doc
    /// comment: YARA's real arithmetic division operator is a backslash
    /// (`\`), not `/`, precisely so `/` can unambiguously mean "regex" --
    /// discovered while building the round-7 fix, when a `/`-based
    /// division test rule failed to compile with libyara's own
    /// "unterminated regular expression" error. Confirms an ordinary rule
    /// using real (backslash) division still compiles and gets a
    /// fingerprint.
    #[test]
    fn a_rule_using_real_division_still_loads_and_fingerprints() {
        let dir = tempfile::tempdir().expect("create temp rules dir");
        std::fs::write(
            dir.path().join("div.yar"),
            "rule DivRule\n{\n    condition:\n        filesize \\ 2 > 0\n}\n",
        )
        .unwrap();
        let engine = YaraEngine::load(dir.path()).expect("load rule using division");
        assert_eq!(
            engine.rule_count, 1,
            "expected the division rule to compile and load"
        );
        assert!(engine.rule_fingerprint("DivRule").is_some());
    }
}
