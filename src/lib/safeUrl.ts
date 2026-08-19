/**
 * Render-boundary validation for external URLs (docs/threat-model.md, TB-3).
 *
 * The backend already drops unsafe stored URLs on read
 * (`nsic_core::sanitize::sanitize_stored_url`), so in the normal path
 * `report_url` arrives here already validated. This is deliberately a second,
 * independent check at the point where a URL actually becomes an `href`.
 *
 * A review round established why one layer is not enough: `report.url` is
 * partly community-submitted third-party data, rows written before ingest
 * validation existed were never backfilled, and the graph can acquire other
 * writers. The final sink should not be safe only *because* some upstream
 * layer promised it was -- especially not in a webview holding the Tauri IPC
 * bridge. React does neutralize `javascript:` hrefs specifically, but that is
 * one scheme and a framework implementation detail rather than a control this
 * project owns, which is exactly the reasoning the threat model rejects.
 *
 * Kept deliberately in lockstep with the Rust `safe_external_url`: same
 * allowlist, same trim, same control-character rejection, same `://`
 * requirement. If you change one, change the other.
 */

/**
 * The only schemes Artemis will turn into a clickable link. Allowlist, not
 * denylist: the set of dangerous schemes is open-ended, the set needed here is
 * exactly these two.
 */
const ALLOWED_URL_SCHEMES = ["http", "https"];

/**
 * Whether the value contains a Unicode control character (category Cc: C0
 * 0x00-0x1F, DEL 0x7F, and C1 0x80-0x9F). Such characters can split or hide a
 * scheme from a naive check while a URL parser still honors them, so they are
 * rejected outright rather than stripped.
 *
 * Written as an explicit code-point range rather than a regex literal so no
 * control characters appear in this source file, and so the range visibly
 * matches the Rust side's `char::is_control()`.
 */
function hasControlChar(value: string): boolean {
  for (const character of value) {
    const code = character.codePointAt(0);
    if (code === undefined) continue;
    if (code <= 0x1f || (code >= 0x7f && code <= 0x9f)) return true;
  }
  return false;
}

/**
 * Returns the URL when it is safe to use as an `href`, or `null` when it is
 * not. Callers render the link text as plain text on `null`, so a rejected URL
 * degrades to a non-clickable label rather than disappearing entirely.
 */
export function safeExternalUrl(candidate: string | null | undefined): string | null {
  if (candidate == null) return null;
  const trimmed = candidate.trim();
  if (trimmed.length === 0) return null;
  if (hasControlChar(trimmed)) return null;

  const separator = trimmed.indexOf("://");
  if (separator === -1) return null;
  const scheme = trimmed.slice(0, separator).toLowerCase();
  const rest = trimmed.slice(separator + 3);
  if (rest.length === 0) return null;

  return ALLOWED_URL_SCHEMES.includes(scheme) ? trimmed : null;
}
