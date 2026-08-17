# Apollo / 4NSIC threat model and security review checklist

This document exists because of a process failure worth naming: PR #19
went through seven rounds of external review, each round surfacing
merge-blocking correctness and trust-boundary defects that the authoring
pass should have found first. The fixes were real, but the loop was
reactive -- defects were found by a reviewer reading finished code, not by
the author threat-modeling the surface before and during the work.

The purpose of this file is to make that review *repeatable and
pre-emptive*: the trust boundaries below are the things every PR touching
the verdict, ingest, or relationship path gets checked against, by the
author, before review.

## What Apollo is, in security terms

Apollo is DFIR tooling. Its defining assumption -- see the Constitution's
locked decision #1, "live agent model" -- is that it runs **on hosts that
may already be compromised**, and analyzes **content supplied by
attackers**. That inverts the usual desktop-app trust posture: the
filesystem it reads, and much of the intel it ingests, are hostile inputs
by default, not incidental ones.

## Assets

| Asset | Why it matters |
|---|---|
| Analyst workstation / agent host integrity | Compromise here defeats the investigation and hands the attacker the responder's access |
| Verdict and relationship **provenance** | The Constitution's core promise: never collapse to a boolean, always carry why. Fabricated or mis-attributed provenance is a correctness *and* trust failure |
| The intel graph in Postgres | Poisoned edges silently steer every future verdict and (from PR #20) every recursive hunt |
| Agent credentials / fleet control plane (Phase 1) | Lateral movement into every enrolled host |

## Trust boundaries

Anything crossing one of these is untrusted until validated **at the
crossing**, not at some later consumer.

### TB-1: Scanned filesystem → verdict engine
The path, its metadata, and its bytes are attacker-influenced on a
compromised host.
- Reads must be **bounded** (size cap) and **type-checked on the opened
  handle**, never on a prior path `stat` (TOCTOU).
- Special files (FIFO, device) must be rejected without a blocking open.
- Hash and YARA scan must observe **one** byte snapshot, never two reads.

*Current controls:* `hashing::hash_and_read_file` (`open_regular` +
`O_NONBLOCK` + `fstat` on the handle + 256 MiB cap + single buffer).

### TB-2: Third-party intel feeds → intel graph
MalwareBazaar and ThreatFox content is **partly community-submitted**.
ThreatFox's `reference` field in particular is attacker-supplyable by
anyone who can submit an IOC.
- Every feed string that becomes a **URL** must be scheme-validated before
  storage. Do not rely on a downstream renderer to neutralize it.
- Every feed string that becomes a **pattern** (LIKE, regex, glob) must be
  escaped for that pattern language.
- Feed-claimed timestamps and confidences are claims, not facts; store
  them as the source's own values on the edge, never merged into Apollo's.

*Current controls:* `nsic_core::sanitize::safe_external_url` at both
ingest sites; `escape_like_pattern` in `db::indicators`; per-edge
provenance columns.

### TB-3: Intel graph → analyst UI (Tauri webview)
The webview holds Tauri's IPC bridge, so script execution there can invoke
backend commands (`list_directory`, `get_verdict`, ...) with analyst
privileges. This is the highest-consequence render surface in the product.
- A restrictive **CSP** must be configured (`app.security.csp`), not left
  `null`.
- Feed-supplied values must never reach `href`/`src`/`dangerouslySetInnerHTML`
  unvalidated. React's own escaping is defense in depth, not the control.

*Current controls:* CSP set in `tauri.conf.json`; URLs validated at
ingest (TB-2) and re-checked at render.

### TB-4: YARA rules directory → detection identity
On a compromised host the rules directory is itself tamperable, and rule
identity feeds durable CVE-coverage evidence.
- A rule's **content** identity must come from the file that declared it,
  not the whole directory (or unrelated edits invalidate it).
- Source parsing must not let one file's text claim another file's rule
  name.

*Current controls:* `YaraEngine::rule_fingerprints` (per declaring-file
SHA-256); `strip_comments_and_strings` blanks comments, strings, **and**
regex literals before scanning for declarations.

### TB-5: Agent → console (Phase 1)
Out of scope for PR #19; see `docs/phase1-design.md`. Per-agent
credentials, replay/clock-skew bounds, and server-controlled `received_at`
anchors already exist there.

## Review checklist

Run this against any PR touching ingest, the verdict path, the relationship
model, or the UI. Each item is phrased as the *class*, because the review
history shows single instances get fixed while siblings survive.

**Input validation at the boundary**
- [ ] Every new feed field: where does it end up (URL? pattern? render?), and is it validated at TB-2 rather than downstream?
- [ ] Every new pattern-matching query: are LIKE/regex metacharacters escaped?
- [ ] Every new SQL query: parameterized via `sqlx` macros (never format!)?

**Resource bounds**
- [ ] Every new read of attacker-influenced data: size-capped?
- [ ] Every new query returning rows to the UI: `LIMIT`ed?
- [ ] Every new in-memory accumulation: bounded by something an attacker can't inflate?

**Races and TOCTOU**
- [ ] Any check-then-use on a path: does the use operate on the *same handle* that was checked?
- [ ] Any decision cached across an `await`: can the underlying state change under it, and does that matter?
- [ ] Any two-step read of shared state: is it one atomic acquisition?

**Provenance integrity**
- [ ] Does every emitted evidence field carry the value the *source edge* actually asserted, or is anything synthesized/borrowed from a different edge or from "now"?
- [ ] Can historical data surface as if it were a current observation?
- [ ] Is timing labeled as what it is (observation window vs. receipt time)?

**Render surface**
- [ ] Any new `href`/`src`/raw-HTML sink fed by stored data?
- [ ] Does the CSP still cover the new surface?

**Supply chain**
- [ ] `cargo audit` / `npm audit` clean, or triaged with a written reason?
- [ ] Open Dependabot alerts reviewed (do not merge past them silently)?

## Known accepted risks

- **Coarse locking over the intel corpus.** `IntelGate` serializes a whole
  verdict read against a whole feed sync rather than using a
  generation/epoch scheme. Accepted: Phase 0 is a single-analyst desktop
  process and a sync is a rare explicit action. Revisit if verdicts become
  concurrent at fleet scale.
- **Rule-declaration parsing is a lexer, not a YARA parser.** Unusual
  formatting can leave a rule's fingerprint unknown; that degrades to the
  permissive wildcard, never to a silently wrong identity. Revisit if
  per-rule identity ever gates something stricter than CVE coverage.
- **Feed URLs are shown to the analyst.** Even scheme-validated, a feed can
  reference an attacker-chosen `https://` host. Apollo shows it as
  provenance, does not fetch it, and the analyst opens it deliberately.
- **RUSTSEC-2023-0071 (`rsa`, Marvin timing sidechannel), not reachable.**
  Pulled in only by `sqlx-mysql`; Apollo enables solely sqlx's `postgres`
  driver in all three consuming crates, so the crate is a `Cargo.lock`
  entry that is never compiled or linked (`cargo tree -i rsa -e normal
  --target all` resolves to nothing). No patched version exists upstream.
  Tracked as an exception with a re-check condition in `.cargo/audit.toml`.
  Locked decision #7 (Postgres for the intel store) means this is not
  expected to change.

## Findings from the first self-review pass

Recorded so the next pass can tell what was already looked at, and so the
*classes* stay on the checklist above even after the instances are fixed.

| # | Finding | Boundary | Disposition |
|---|---|---|---|
| S-1 | ThreatFox's community-submitted `reference` stored as `report.url` and rendered as an `href` with no scheme validation | TB-2 → TB-3 | Fixed: `safe_external_url` allowlist at both ingest sites, canonical-URL fallback |
| S-2 | Webview ran with `csp: null` | TB-3 | Fixed: restrictive CSP in `tauri.conf.json` |
| S-3 | Path indicator interpolated unescaped into an `ILIKE` pattern -- a `%` indicator matches every scanned file | TB-2 | Fixed: SQL-side `replace` escaping; regression test |
| S-4 | Five of six verdict queries returned unbounded rows to the UI | resource bounds | Fixed: `MAX_VERDICT_ROWS` |
| S-5 | Open Dependabot alert unread for seven review rounds; no dependency scanning in CI | supply chain | Fixed: `cargo audit` + `npm audit` CI job, triaged exception file |

S-1 is worth being precise about, because overstating it would be its own
failure: React 19 does neutralize `javascript:` hrefs specifically, so this
was not a live code-execution path in the current UI. The defect is that
the *only* thing standing between a community-submitted string and an
`href` in an IPC-privileged webview was a framework implementation detail
covering one scheme -- with no CSP behind it, no validation at the
boundary, and the raw value persisted for other consumers (the Phase 1
console renders with maud, and PR #20's hunt engine will read these
programmatically). The control belongs at the boundary; it is there now.
