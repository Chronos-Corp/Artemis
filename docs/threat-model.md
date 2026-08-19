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

*Current controls:* `nsic_core::sanitize::safe_external_url` at both ingest
sites, and `sanitize_stored_url` on every read path (ingest validation alone
does not cover rows written before it existed or by other producers);
per-edge provenance columns.

LIKE-pattern escaping is worth stating precisely, because a review noted the
earlier wording invited a wrong conclusion. Two separate things exist:

- `sanitize::escape_like_pattern` — escapes a value being passed *as a bind
  parameter* into a LIKE pattern. Tested, and available for callers in that
  situation. **It is not the control used by `path_pattern_matches`.**
- `path_pattern_matches` — the pattern operand there is a *column*
  (`i.value`), not a bind parameter, so no Rust-side helper can reach it.
  That query does the equivalent escaping SQL-side with nested `replace`
  (backslash first, then `%` and `_`).

Both must exist, and a future reviewer should not assume the Rust helper is
what protects that query.

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

### TB-4: YARA rules directory → detection identity and analysis coverage
On a compromised host the rules directory is itself tamperable, and rule
identity feeds durable CVE-coverage evidence.
- A rule's **content** identity must come from the file that declared it,
  not the whole directory (or unrelated edits invalidate it).
- Source parsing must not let one file's text claim another file's rule
  name.
- A ruleset **load failure must remain distinguishable from a successful
  empty ruleset**. Falling back to an empty engine for availability is
  acceptable only if the verdict and UI retain `failed` coverage state;
  otherwise "no YARA hit" overstates what was actually checked.

*Current controls:* `YaraEngine::rule_fingerprints` (per declaring-file
SHA-256); `strip_comments_and_strings` blanks comments, strings, **and**
regex literals before scanning for declarations; `analysis_coverage`
retains `loaded` / `empty` / `failed` state and carries it through both
`yara_status` and the analyst-facing verdict response.

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
- [ ] Every outbound request: does it have an explicit total timeout? (No
      library's default can be assumed -- reqwest's is *no* timeout.)
- [ ] Is any lock or guard held across a network round trip?

*Added after R8-1 and R8-4: a cap is only half a control.*
- [ ] Does the cap bound the thing the *caller* counts (conceptual results),
      or just the rows the database happened to return before grouping?
- [ ] Can one item's volume consume another item's budget?
- [ ] Does the result say when a cap fired, or does a bounded result look
      byte-for-byte identical to a complete one?
- [ ] Is there a total `ORDER BY`, so *which* rows survive the cap is
      deterministic rather than plan-dependent?
- [ ] Does crossing a resource threshold preserve the **same wire-object
      semantics**, or does the meaning/cardinality of one returned object
      change only because a fallback path activated?

**Races and TOCTOU**
- [ ] Any check-then-use on a path: does the use operate on the *same handle* that was checked?
- [ ] Any decision cached across an `await`: can the underlying state change under it, and does that matter?
- [ ] Any two-step read of shared state: is it one atomic acquisition?

**Provenance integrity**
- [ ] Does every emitted evidence field carry the value the *source edge* actually asserted, or is anything synthesized/borrowed from a different edge or from "now"?
- [ ] Can historical data surface as if it were a current observation?
- [ ] Is timing labeled as what it is (observation window vs. receipt time)?
- [ ] If several assertions support one relationship concept, are their
      evidence paths preserved without turning them into duplicate hunt
      pivots or changing object identity at a cardinality threshold?

**Analysis coverage honesty**
- [ ] Can "not checked", "checked with zero configured sources/rules", and
      "checked successfully with no match" be distinguished by the machine
      contract and the analyst UI?
- [ ] Does a degraded/fallback engine preserve the failure state that caused
      the degradation instead of presenting itself as healthy empty coverage?

**Render surface**
- [ ] Any new `href`/`src`/raw-HTML sink fed by stored data?
- [ ] Does the CSP still cover the new surface?

**Supply chain**
- [ ] `cargo audit` / `npm audit` clean, or triaged with a written reason?
- [ ] Open Dependabot alerts reviewed (do not merge past them silently)?

**CI/CD (the build system is part of the attack surface)**
- [ ] Does every workflow declare an explicit least-privilege `permissions` block?
- [ ] Does any job that handles a secret grant more token scope than it needs?
- [ ] Are new third-party actions pinned and from a source worth trusting?
- [ ] Could a PR from a fork reach a job that holds secrets?

> This section exists because the first version of this checklist did not
> have it, and CodeQL immediately caught a missing `permissions` block in
> the very CI job added to *implement* the supply-chain item above. A
> checklist that only covers the boundaries you already thought of is the
> same reactive failure at one remove; when a tool finds a class this file
> is silent on, the class gets added here, not just the instance fixed.

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

## Findings from round 8 review

The pattern in this round is worth naming, because it is different from the
earlier rounds: every finding was an *interaction between two controls that
were each individually reasonable*. Adding a control is not the same as
finishing it, and a new control's edges are now themselves on the checklist.

| # | Finding | Boundary | Disposition |
|---|---|---|---|
| R8-1 | Row caps turned resource bounds into silently incomplete evidence: `LIMIT` applied to *joined* rows before Rust grouped them, so one heavily-supported CVE edge could starve an entirely distinct edge, with nothing on the wire saying so. Four of five capped queries also had no `ORDER BY`, making *which* evidence survived plan-dependent | resource bounds / provenance integrity | Fixed: separate relationship vs evidence budgets enforced in SQL via window functions, `Bounded<T>` + `VerdictBounds` + `has_more_evidence` on the wire and in the UI, total ordering on every capped query |
| R8-2 | `safe_external_url` guarded ingest but not the render boundary or legacy rows -- TB-3's claimed "re-checked at render" control did not exist | TB-3 | Fixed: `sanitize_stored_url` on every read path, `safeExternalUrl` at both `href` sinks, plus a guard test that fails if a raw dynamic `href` is reintroduced |
| R8-3 | `ABUSECH_API_KEY` sat in job-level `env`, exposed to every step including third-party actions referenced by mutable tags | CI/CD | Fixed: secret scoped to the one step that needs it (the presence check gets a boolean, not the value); all third-party actions pinned to verified commit SHAs |
| R8-4 | Feed HTTP requests had **no** timeout, so `IntelGate`'s write guard could be held indefinitely and block every verdict; response bodies were unbounded | availability | Fixed: explicit total/connect timeouts and a streamed 64 MiB body ceiling |

R8-4 is a correction, not just a fix. The review classified the `IntelGate`
lock as non-blocking *on the premise* that "with reqwest 0.12 there is a
default request timeout, so this is bounded rather than an indefinite
deadlock." That premise is false: reqwest 0.12.28 defaults both `timeout`
and `read_timeout` to `None`, and `ClientBuilder::timeout`'s own
documentation says "Default is no timeout." The Linux-only 30s
`tcp_user_timeout` default bounds unacknowledged TCP writes, not an
application-layer peer that keeps a connection healthy while sending almost
nothing. So the deadlock really was unbounded. Explicit timeouts now make
the premise true; whether the fetch/parse-vs-mutation split is still worth
doing is a live question rather than a settled deferral.

## Findings from round 10 review

Round 10 found two second-order contract failures after the Round 9 bounds
work itself had held up:

| # | Finding | Boundary | Disposition |
|---|---|---|---|
| R10-1 | `ThreatRelationship` changed semantic identity when relationship-assertion cardinality crossed the safety cap: normal queries returned one object per assertion, while only the high-cardinality fallback grouped a target into one object with several evidence paths | RELATE wire contract / resource bounds | Fixed: `relationship_contract::finalize_verdict` normalizes the analyst-facing contract at every cardinality. One object represents one `(kind, target, strength, typed evidence-route shape)` concept; assertions remain independent evidence paths, with a separate per-concept evidence cap and `has_more_evidence`. Mixed/malformed route shapes fail conservative and do not coalesce. |
| R10-2 | Any YARA load failure was converted to `YaraEngine::empty`, making a rejected/unsafe/malformed ruleset indistinguishable from a successful zero-rule configuration and allowing empty-verdict prose to overstate negative YARA coverage | TB-4 / analysis coverage | Fixed: `analysis_coverage` retains `loaded` / `empty` / `failed` state and a bounded display-safe reason. Both status and verdict response expose it; UI/no-match language never claims YARA was checked when loading failed. |

The R10-1 fix intentionally makes **evidence mechanism** part of conceptual
identity, not only `(kind, target)`. Two routes to the same target that have
different strengths or typed relation sequences remain separate because they
make different evidentiary claims. This is the contract Orion should consume:
dedupe supporting assertions without erasing the path semantics that justify
the pivot.

## Findings from Artemis Engineering hardening

| ID | Finding | Boundary | Status |
| --- | --- | --- | --- |
| AE-1 | Desktop analysis, agent hashing/scanning, and sample retrieval used different file-open and size controls; agent scan was unbounded, and sample retrieval validated a path before opening it separately | TB-1 / evidence integrity / availability | Fixed: `nsic_core::hashing::read_regular_file_bounded` performs nonblocking open on Unix, same-handle regular-file validation, pre-read size enforcement, and an independently capped read. Every current file-content inspection path consumes the same primitive. |

### Deferred, with reasons

- **`IntelGate` holds its write guard across fetch/parse as well as the
  local mutation.** Now bounded by `FEED_REQUEST_TIMEOUT` (60s) rather than
  unbounded, but a slow feed still pauses all verdicts for up to that long.
  Splitting the remote work out of the critical section is the real fix.
  Deferred as a Phase-0 tradeoff, not forgotten.
- **High-cardinality fallback bounds returned targets/evidence, but the SQL
  may still rank a large matching assertion set before applying those
  output budgets.** Current Rust memory and IPC payload are bounded. Revisit
  query shape/indexing before Hunt Pack or fleet cardinality makes this an
  availability concern rather than a local Phase-0 tradeoff.
