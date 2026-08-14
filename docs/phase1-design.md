# Phase 1 design: agent plus console

Status: enrollment, heartbeat, sighting submission, and reading sightings
back out are all authenticated end to end; most of the phase is still not
built. This document tracks
what Phase 1 actually is, what's landed so far, and what's deliberately
deferred, in the same spirit as the README's Phase 0 "what works today /
what's stubbed" split.

Per the README's build order, Phase 1 is: agent plus console, file-to-IOC
across a fleet, sample retrieval. That's a lot; this document exists so
each PR against it has a shared map instead of improvising scope. The
sequence, and why it's ordered this way:

1. **PR #3 — wire plumbing.** Prove the agent and console can be two
   genuinely separate deployable artifacts that agree on a schema and a
   protocol. No auth.
2. **PR #4 — agent identity.** Establish who is on that wire, before
   anything the wire carries is trusted. Bootstrap enrollment
   authorization, per-agent credentials, `/api/v1` versioning.
3. **PR #5 — local YARA on the agent.** Give the agent something
   meaningful to observe. Depends on #4 existing so what it observes can
   eventually be attributed to a specific, authenticated host.
4. **PR #6 — sighting protocol.** Securely report those observations:
   "host X observed indicator Y," as an authenticated
   `/api/v1/agents/{host_id}/sightings` endpoint and a new graph edge.
   Depended on both #4 (who's reporting) and #5 (what there is to
   report).
5. **PR #7 — reading sightings back out.** #6 could only write. A new
   console-operator credential, distinct from both credentials #4
   introduced, gates two read endpoints: sightings for a given host, and
   every host that's sighted a given indicator. Depended on #6 existing so
   there's a graph to query.
6. **Later, not started:** sample retrieval, fleet UI, TLS/deployment
   hardening.

Auth before telemetry, deliberately: once YARA and sighting submission
exist, the agent starts producing intelligence the console has to trust.
At that point, knowing which endpoint actually sent something stops being
mere access control and becomes evidence integrity.

## What's landed

### PR #3: wire plumbing

- **`crates/nsic-core`**: the pure, DB-free file hashing (`compute_hashes`)
  and the intel-graph vocabulary (`IndicatorKind`, `DetectionKind`,
  `VerdictTier`, `ProvenanceEntry`, `Verdict`) extracted out of
  `src-tauri`, so the agent can depend on exactly the same digest logic and
  types without linking Tauri or, by default, Postgres. A `db` feature
  (off by default) adds `connect_and_migrate`, shared by `src-tauri` and
  `crates/console` so they can never drift onto separate schemas.
- **`crates/agent`**: a CLI binary (`nsic-agent`) with `hash`, `enroll`,
  and `heartbeat` subcommands. No local YARA scanning, no verdict
  submission, no file monitoring.
- **`crates/console`**: an HTTP service (`nsic-console`, axum), backed by a
  new `host` table (`src-tauri/migrations/0003_hosts.sql`) in the same
  Postgres instance `src-tauri` already uses.
- No authentication, no API versioning. `crates/console`'s default bind
  is loopback-only (`127.0.0.1:8787`), added during review, since this is
  unauthenticated HTTP with no TLS.

### PR #4: agent identity, enrollment security, API versioning

Two distinct credentials, per the ordering principle above (bootstrap
authorization is a different question from per-agent identity, and one
token must not answer both):

- **Bootstrap enrollment authorization.** A single, console-operator-
  configured secret (`NSIC_ENROLLMENT_SECRET`, required at console
  startup — the console refuses to start without it rather than silently
  running with enrollment open to anyone). Presented as a bearer token on
  `POST /api/v1/agents/enroll` only. Missing or wrong secret: `401`.
  Never stored per-host.
- **Per-agent credential.** Minted fresh (32 random bytes, hex-encoded) on
  every successful enrollment, returned exactly once in
  `EnrollResponse::credential`. The console stores only its SHA-256 hash
  (`host.credential_hash`, renamed from the unused
  `enrollment_token_hash` placeholder in
  `src-tauri/migrations/0004_host_credential.sql`, now `NOT NULL`). The
  agent presents it as a bearer token on `POST /api/v1/agents/{host_id}/
  heartbeat`; the console checks it against that specific `host_id`, not
  just "is this any valid credential" — one host's credential does not
  authenticate a heartbeat for a different host's id. Missing, wrong, or
  wrong-host credential: `401` in all cases (including an unknown
  `host_id`), so this endpoint can't be used to enumerate valid ids.
- **`/api/v1` prefix** on both routes, ahead of the API surface actually
  growing (sightings, rule sync, sample retrieval), so those additions
  don't have to retrofit versioning onto routes already in use.
- Secret comparisons go through a constant-time equality check
  (`crates/console/src/auth.rs`), for the bootstrap secret (compared
  directly) and, out of caution, for credential-hash comparisons too.
- The agent CLI's `--enrollment-secret` and `--credential` flags both fall
  back to environment variables (`NSIC_ENROLLMENT_SECRET`,
  `NSIC_AGENT_CREDENTIAL`) so a real secret doesn't have to appear in
  shell history or `ps` output.
- Tests (`crates/console/src/host.rs`, DB-backed, run with `--ignored`):
  enroll with a missing/wrong bootstrap secret, enroll-then-heartbeat
  happy path, heartbeat with a missing/forged credential, heartbeat with
  one host's credential against a different host's id, heartbeat against
  an unknown `host_id`.
- **Upgrade path for pre-existing PR #3 host rows.** The first draft of
  `0004_host_credential.sql` renamed the unused, nullable
  `enrollment_token_hash` column and immediately applied `NOT NULL` —
  which fails against any host enrolled under PR #3, since that row has
  no credential to satisfy the constraint. CI's fresh, empty database
  never exercised this, so it shipped green. Fixed (caught in review) by
  backfilling any pre-existing NULL with a sentinel
  (`'legacy-host-requires-re-enrollment'`) that can never equal a real
  credential hash, before applying `NOT NULL` — those hosts simply can't
  authenticate until they re-enroll, but their row isn't dropped. See
  `crates/nsic-core/src/db.rs`'s
  `migration_0004_backfills_legacy_hosts_without_a_credential` test,
  which applies `0003_hosts.sql` and `0004_host_credential.sql` verbatim
  against an isolated schema seeded with a legacy row, so this upgrade
  path is exercised rather than assumed.

Everything here is still single-machine-testable: run the console, enroll
one agent against it locally, heartbeat it. There is no fleet yet.

### PR #5: local YARA scanning on the agent

`src-tauri/src/yara_scan.rs` (`YaraEngine`, `YaraMatch`) moved into
`nsic-core` verbatim — it was already DB-free — behind a new `yara-scan`
feature, kept separate from the `db` feature so `crates/console` (which
needs neither Postgres-free scanning nor YARA) doesn't pick up a
`libyara-dev` build dependency it has no use for. `src-tauri` enables
`yara-scan` alongside `db`, same re-export pattern as `hashing`/`models`;
existing `crate::yara_scan::X` call sites are unaffected.

- **`nsic-agent scan <path> [--rules-dir <dir>]`**: loads local `.yar`/
  `.yara` rules (default `yara-rules/`, or `NSIC_YARA_RULES_DIR`, matching
  `src-tauri`'s existing convention) and scans one file, printing matches
  as JSON. Local-only — nothing is sent to the console yet; that's PR #6.
- Real test coverage, not just "it compiles": `crates/nsic-core/src/
  yara_scan.rs` has a test that loads the repo's bundled
  `yara-rules/example_eicar.yar` and confirms it actually flags an EICAR
  test string, plus a test that a missing rules directory degrades to
  zero rules rather than erroring. Both are plain `#[test]`s (no DB, no
  network), so unlike most of this crate's other tests they run on every
  `cargo test`, not just `--ignored`.
- CI's `workspace-crates` job now installs `libyara-dev` (only that,
  still no GTK/WebKitGTK — `crates/console` still doesn't need it, only
  `nsic-core`/`crates/agent` do once `yara-scan` is enabled).

PR #5 shipped local-only, same caveat as PR #4's per-agent credential
persistence: nothing there sent a YARA hit anywhere. PR #6 is what turns
"the agent noticed something" into "the console knows about it."

### PR #6: sighting protocol

`POST /api/v1/agents/{host_id}/sightings` (`crates/console/src/
sighting.rs`), authenticated the same way heartbeat is — the per-agent
credential check was pulled out of `host.rs`'s `heartbeat` into a shared
`authenticate_host` helper (`crates/console/src/auth.rs`) so both
endpoints use the exact same check rather than two copies drifting.

- **Deliberately narrow request shape.** `SightingRequest` (`nsic_core::
  proto`) is `{ sha256, detection_name, ruleset_fingerprint,
  path: Option<String>, observed_at }` — exactly what `nsic-agent scan`
  produces today, not a generic multi-indicator-kind sighting.
  Generalizing (a `kind` field, non-YARA detection types) is deferred
  until something other than local YARA scanning produces a sighting —
  Phase 0's still-unpopulated tier 2 (fuzzy hashing) would be the next
  candidate.
- **Source and confidence are not client-supplied.** The endpoint always
  writes `source = "agent:yara_scan"`, `confidence = 65` — matching
  `src-tauri`'s existing convention for local YARA hits
  (`"local:yara_scan"`, also 65; see `verdict.rs`), `agent:` instead of
  `local:` so fleet- and desktop-sourced hits stay distinguishable in the
  graph. An agent asserting its own trust level would be circular; the
  console decides confidence based on the evidence mechanism, the same
  way `src-tauri` already does for its own local scans.
- **What a sighting actually writes.** Reusing the intel graph's existing
  shape rather than inventing a side channel: `upsert_indicator` (the
  file's sha256, creating it if the console has never seen this hash),
  `upsert_detection` (the YARA rule, by name), a
  `detection_detects_indicator` edge (so a fleet hit joins the exact same
  graph a local desktop scan populates), and the new
  `host_sighted_indicator` edge carrying the full authenticated claim:
  which host, through which detection, saw which indicator, from where,
  and under which ruleset version (see Data model below). All four
  writes happen inside one Postgres transaction (`state.pool.begin()`);
  the three shared upsert helpers are generic over `sqlx::PgExecutor`
  (mirroring `src-tauri`'s own `upsert_report`/`upsert_indicator`
  signatures) specifically so they can run against either a bare pool or
  a transaction. A failure partway through rolls back the whole sighting
  rather than leaving, say, a new indicator and detection recorded with
  no host tied to them.
- **These four upserts are reimplemented in `crates/console/src/
  sighting.rs`** with runtime-checked queries (no `sqlx::query!` macro),
  not shared from `src-tauri/src/db/indicators.rs` where three of the
  four already exist. `src-tauri`'s versions use compile-time-checked
  macros backed by a checked-in `.sqlx` offline cache; moving them into
  `nsic-core` would mean either preparing that cache for a second crate
  location (needs a live, migrated database to generate) or losing local
  compilability without one. Given PR #4 already made this same call for
  `host.rs`'s queries, staying consistent won. Both write the identical
  SQL shape (same tables, same `ON CONFLICT` targets) as `src-tauri`'s
  macro versions; drift between them is the accepted cost, flagged in
  code comments at each reimplemented function.
- **Ruleset provenance, fingerprinted the same way the target file is.**
  A rule's name alone doesn't identify what it actually checked for once
  the rule file has since been edited, so `YaraEngine`
  (`crates/nsic-core/src/yara_scan.rs`) now carries a
  `ruleset_fingerprint`. First draft computed it by reading each rule
  file once for the fingerprint and letting `yara::Compiler::
  add_rules_file` reopen the same path a moment later to compile it —
  the exact TOCTOU class the file-evidence fix below closes, just moved
  one level up: a rule edited between those two reads could fingerprint
  as version A while what actually got compiled (and produced the match)
  was version B. Fixed the same way: each rule file is read exactly
  once, and those same bytes both feed the fingerprint and get compiled
  (`add_rules_str`, not `add_rules_file`, so the compiler never reopens
  the path). The fingerprint itself is a SHA-256 over a canonical
  manifest — for each file, in sorted relative-path order, its relative
  path, a NUL byte, the hex SHA-256 of its contents, and a newline — not
  a naive concatenation of file bytes, which is ambiguous (file A's bytes
  followed by file B's are not distinguishable from some other split X
  followed by Y with the same total length; the per-file framing closes
  that off). The agent includes it in every `SightingRequest`, and it's
  part of `host_sighted_indicator`'s primary key, not just a plain column
  — the same host reporting the same indicator+detection again under a
  materially different ruleset creates a new, distinct row instead of
  silently merging into (and losing the provenance of) an earlier one.
  This is an agent-reported value from an authenticated host, not
  something the console independently verifies against real rule content
  — the console only checks it's shaped like a SHA-256 (see input
  validation below). It becomes console-verifiable only once the console
  itself distributes or maintains known rulesets, not yet the case.
- **Which detection produced which sighting is preserved, not just which
  indicator.** First draft's `host_sighted_indicator` had no
  `detection_id` — it recorded "host H saw indicator X" and, separately
  via `detection_detects_indicator`, "detection R flags indicator X," but
  nothing tying a *specific host's* sighting to the *specific rule* that
  produced it. Two hosts matching the same hash through two different
  rules were indistinguishable from the console's perspective: the graph
  could reconstruct that both hosts saw the hash and that both rules
  detect it, but not which host matched which rule. `detection_id` is now
  part of the row and the primary key
  (`host_id, detection_id, indicator_id, source, ruleset_fingerprint`),
  so the full authenticated claim — host H observed indicator X through
  detection R under ruleset V — survives intact.
- **Same bytes, hashed and scanned once.** The agent used to open the
  scanned file twice: once for `YaraEngine::scan(path)`, and — only if
  reporting was enabled — again via `compute_hashes(path)` to get the
  sha256 for the sighting. Two separate reads of the same path can
  observe different content if the file changes in between, which for a
  match this may persist durably and attribute to a specific host is an
  evidence-integrity defect, not just a race. `nsic-agent scan` now reads
  the file into memory exactly once (`std::fs::read`) and both hashes
  (`nsic_core::hashing::hash_bytes`) and scans
  (`YaraEngine::scan_bytes`, using the `yara` crate's `scan_mem` instead
  of `scan_file`) that same buffer, so the reported hash is provably the
  hash of whatever YARA actually inspected. `scan`/`scan_file`
  (path-based) stay as they were for `src-tauri`'s own callers, which
  don't (yet) share this problem in the same way; see below.
- **Input validation at the trust boundary.** Authentication proves which
  agent sent a request, not that the agent is bug-free or uncompromised.
  `report_sighting` now rejects (`400`) a `sha256` or
  `ruleset_fingerprint` that isn't exactly 64 lowercase hex characters,
  an empty or over-256-character `detection_name`, and an `observed_at`
  either more than 5 minutes ahead of the console's clock or before
  2020-01-01 (a floor sanity bound, not a moving target) — all before
  anything touches the database. Without this, `"sha256": "banana"`
  would have become a real `IndicatorKind::Sha256` row, corrupting the
  graph's type invariant.
- **Idempotency and stale-observation ordering.** Resubmitting the same
  sighting is an upsert (matching primary key), not a duplicate row.
  `first_seen` takes `LEAST`, `last_seen` takes `GREATEST` (the exact
  pattern every other edge in `0001_init.sql` already uses); `path`
  advances to the newly reported value only when that report's
  observation is at least as recent as what's already stored (`CASE WHEN
  EXCLUDED.last_seen >= host_sighted_indicator.last_seen`), not
  unconditionally — otherwise a report arriving out of order could
  regress "where it was last seen" to a stale path even while
  `last_seen` itself correctly kept advancing.
- **`received_at` bounds, but doesn't eliminate, a bad endpoint clock.**
  `host_sighted_indicator` records when the console first accepted a
  given fact (`DEFAULT now()`, set once, never updated on conflict),
  independent of the agent-claimed `first_seen`/`last_seen`. Combined
  with the `observed_at` bounds check above, this limits how far a
  misconfigured or compromised endpoint clock can distort
  `first_seen`/`last_seen` — but it's a bound, not a guarantee: an
  endpoint can still report any `observed_at` within the accepted window
  (2020-01-01 through 5 minutes ahead of the console's clock), and
  nothing here verifies that claim is honest. What `received_at` actually
  buys is provenance: a server-controlled anchor analysts can compare the
  endpoint's claim against, not proof the claim is true.
- **Batching is out of scope.** One HTTP request per (indicator,
  detection) pair; the agent loops client-side if a single scan matches
  multiple rules. `nsic-agent scan` still only scans one file per
  invocation, so there's nothing to batch yet — revisit once the agent
  does bulk or continuous scanning.
- **`nsic-agent scan`** gained `--console-url` / `--host-id` /
  `--credential` (env fallbacks `NSIC_CONSOLE_URL` / `NSIC_HOST_ID` /
  `NSIC_AGENT_CREDENTIAL`); if all three are given and the scan found any
  matches, each is reported as a sighting after the local JSON is
  printed (which now also includes the `sha256`, a side effect of always
  hashing the buffer YARA scanned). Given none of them, `scan` behaves
  exactly as it did in PR #5. Given some but not all, the agent prints a
  warning and skips reporting rather than silently doing nothing or
  guessing.
- Tests (`crates/console/src/sighting.rs`, DB-backed, `--ignored`):
  missing/forged credential and unknown `host_id`; malformed and
  uppercase `sha256`; empty `detection_name`; `observed_at` too far in
  the future and predating the earliest-plausible bound; a combined
  happy-path test that submits the same sighting twice with different
  `observed_at` values and asserts against the database directly that
  `first_seen`/`last_seen` follow `LEAST`/`GREATEST`, exactly one edge
  row exists (not two), and `detection_detects_indicator` was populated
  too; a different-`ruleset_fingerprint` test confirming two distinct
  edge rows result instead of one merged row; a stale-observation test
  confirming an out-of-order report can't regress `path`; and a
  two-hosts-two-rules test (`report_sighting_preserves_which_rule_each_
  host_saw`) confirming host A's sighting stays joined to the rule it
  actually matched even when host B matches a different rule against the
  identical hash. Plus new `nsic-core` tests (plain `#[test]`s, no DB):
  `scan_bytes` matches `scan` for identical content, `hash_bytes` matches
  `compute_hashes` for identical content, and `ruleset_fingerprint` is
  deterministic across reloads and distinguishes a real ruleset from an
  empty one. `loads_bundled_rules_and_detects_eicar` (unchanged) now also
  covers `load()`'s new single-read-then-compile-via-add_rules_str path,
  since that's what it exercises today.

### PR #7: reading sightings back out

PR #6 only wrote. `crates/console/src/sighting.rs` gains two read
endpoints, both returning `nsic_core::proto::SightingListResponse` (a list
of `SightingView`, each row denormalized with a hostname, sha256, and rule
name resolved so a caller doesn't have to look up `indicator_id`/
`detection_id` itself):

- `GET /api/v1/hosts/{host_id}/sightings` — every sighting recorded for a
  given host.
- `GET /api/v1/indicators/{sha256}/sightings` — every host that's sighted
  a given hash, the cross-fleet "who else has seen this" pivot the
  product's core idea (see the README) depends on.

**A third credential, not a reuse of either existing one.** Neither
credential PR #4 introduced fits: the bootstrap enrollment secret only
ever authorizes a machine to join, and a per-agent credential proves "I am
this one host, reporting my own observations" -- not "I may read what any
host in the fleet has reported." Reusing either would conflate concerns
the same way PR #4 was built specifically to avoid. A new
`NSIC_OPERATOR_SECRET`, required at console startup (the console refuses
to start without it, matching the bootstrap secret's fail-fast behavior),
gates both endpoints via a new `authenticate_operator` in
`crates/console/src/auth.rs` -- a direct constant-time comparison against
the configured value, no database lookup, since (unlike a per-agent
credential) there's nothing per-row to check against. Verified a
compromised agent's own per-agent credential does *not* authenticate
these endpoints (`list_host_sightings_rejects_per_agent_credential`) --
the failure mode a shared or reused credential would silently allow.

**Route prefix split reflects the trust boundary, not just REST taste.**
Agent-facing routes stay under `/api/v1/agents/...` (bootstrap or
per-agent credential); the new operator-facing read routes live under
`/api/v1/hosts/...` and `/api/v1/indicators/...` (operator credential
only) -- the URL shape itself signals which credential a given endpoint
expects.

**An unknown `host_id` returns `200` with an empty list, not `404`.**
There's no "list all hosts" endpoint yet (see below) for an operator to
have confirmed an id exists in the first place, so treating "no
sightings" and "no such host" identically doesn't leak anything an
operator couldn't already tell another way once one exists.

**A fixed row cap, not real pagination.** Both endpoints `LIMIT 1000`.
That's a ceiling against an unbounded response, not a cursor -- there's no
way to reach rows past the cap. Real pagination is deferred until a fleet
actually produces enough sightings per host or per hash to hit it (see
below).

**This is the first PR in this sequence with DB-backed tests actually
executed, not just reviewed.** A local Postgres 16 instance was available
in this sandbox (unlike prior PRs, where none was), so all 34 tests
(`cargo test -- --include-ignored`) ran for real, including the 9 new
tests for these two endpoints -- missing/wrong operator credential, a
per-agent credential rejected, an unknown host returning an empty list,
malformed sha256 rejected, and the full round trip confirming every
denormalized field on the response actually matches what was reported.
The write-then-read path was also exercised end to end against the real
binaries (`nsic-console` + `nsic-agent`), not just the in-process test
harness: enroll, scan-and-report a real EICAR match, then `curl` both new
endpoints with the operator credential and confirm the JSON matches, and
confirm the console still refuses to start without
`NSIC_OPERATOR_SECRET` set.

## What's deliberately not here yet

- **Sensor health / scan coverage.** PR #6 only sends positive sightings
  -- a match. Zero active YARA rules and zero YARA detections currently
  look identical from the console's side: both are just an absence of
  sightings for that host. That's fine as long as nothing downstream
  treats "no sightings from host H" as "host H is clean" -- a host that
  never scanned anything, or whose rules failed to load, is
  indistinguishable from a genuinely clean one today. Sensor health /
  scan coverage reporting needs to land before a future fleet UI is
  allowed to make that inference.
- **Ruleset fingerprint is not yet path-separator-portable.** The
  canonical manifest in `YaraEngine::load` includes each rule file's
  relative path as raw text. On Windows that path uses `\`, on Unix `/`,
  so an identical rules directory fingerprints differently depending on
  which OS the agent runs on. Normalizing relative paths to `/` before
  they enter the manifest would make ruleset identity comparable across
  a mixed-OS fleet; not done yet since Phase 1 has no Windows agent to
  observe the mismatch against.
- **`scan` buffers the whole target file into memory.** Reading the file
  once and hashing/scanning those same bytes is the right evidence-
  integrity call for a one-shot, one-file Phase 1 CLI invocation, but a
  persistent scanner (Phase 2+) that watches many files should not
  blindly buffer arbitrarily large ones. That needs either a file-size
  policy (skip or chunk-hash above a threshold) or a stable-handle
  strategy (e.g. hold an open handle and read from it for both hashing
  and scanning) instead of `std::fs::read`'s single full-file buffer.
- **Transport security.** Still HTTP, not HTTPS. The bootstrap secret,
  per-agent credentials, and now sighting data all cross the wire in
  plaintext today. Real TLS (or at minimum a documented "put this behind
  a VPN/reverse proxy for now") is required before this talks to a real
  fleet.
- **Credential rotation and revocation.** A compromised or decommissioned
  host's credential can't currently be invalidated short of deleting its
  `host` row outright. No rotation flow exists either.
- **Rate limiting on `/api/v1/agents/enroll`.** The bootstrap secret is a
  single shared value; nothing currently throttles guesses against it.
- **Bootstrap-secret strength enforcement.** `NSIC_ENROLLMENT_SECRET` is
  taken as-is; the console doesn't reject a short or weak value. Fine for
  local testing, not before a real deployment.
- **Protected agent-side credential persistence.** The CLI prints the
  per-agent credential and leaves storing it to the caller (`scan
  --credential` still has to be passed explicitly, or via
  `NSIC_AGENT_CREDENTIAL`); there's no agent-managed credential file
  (with correct permissions, per OS) yet. That needs a design once the
  agent stops being a one-shot CLI and becomes a persistent process --
  storing a long-lived credential insecurely at that point is a real
  vulnerability, not just a rough edge.
- **Reading sightings back out by rule/detection name.** PR #7 covers
  querying by host and by indicator; there's no
  `GET /api/v1/detections/{name}/sightings` yet. Straightforward to add
  the same way once there's a real need for it.
- **No "list all hosts" endpoint.** An operator currently has no way to
  discover valid `host_id`s through the API at all -- only from an
  enroll response at enrollment time, or by querying Postgres directly.
  PR #7's read endpoints assume the caller already has a `host_id` or a
  sha256 in hand from somewhere; a host directory is its own PR.
- **Real pagination on the PR #7 list endpoints.** Both currently
  `LIMIT 1000` with no cursor -- a ceiling against an unbounded response,
  not a way to reach rows past it. Fine while no fleet has produced that
  many sightings for one host or hash; not fine indefinitely.
- **Operator-credential rotation.** Same gap as per-agent credentials
  below, for the new `NSIC_OPERATOR_SECRET`: it's a single static value
  with no rotation flow, and (unlike per-agent credentials) isn't even
  hashed before comparison -- there's nothing per-row to hash it against.
- **The same hash/scan TOCTOU exists in `src-tauri`'s desktop verdict
  engine, unfixed.** `verdict.rs`'s `resolve()` still hashes a file
  (`hash_file_cached`) and separately opens it again to YARA-scan it
  (`yara_for_scan.scan(&path_owned)`) — two reads of the same path, same
  class of issue `nsic-agent scan` fixed in PR #6 by reading once and
  calling `hash_bytes`/`scan_bytes` on the same buffer. Left alone here
  deliberately: it predates this PR, and the desktop app's interactive,
  single-analyst click-to-verdict flow has different risk
  characteristics than an authenticated, durably-persisted fleet
  sighting. Worth the same fix eventually, but out of scope for this PR.
- **Sample retrieval.** Locked architecture decision #3: file contents
  leave the host only on explicit analyst request, logged and attributed.
  No part of that request/audit flow exists yet.
- **Fleet console UI.** No frontend for any of this; `crates/console` is
  API-only.
- **Windows-specific agent internals.** USN journal, Amcache, etc. are
  Phase 4 territory per the README and untouched here.
- **Migrations still live under `src-tauri/migrations/`.** That predates
  this crate split and `nsic-core::db::connect_and_migrate` points there
  by relative path (see `crates/nsic-core/src/db.rs`) purely to avoid
  disturbing `src-tauri`'s existing sqlx offline query cache and CI steps.
  Longer-term the migrations directory should move to a location that
  isn't nested inside the Phase 0 desktop app, since the console now owns
  and runs them just as much as `src-tauri` does.

## Data model

`host` (`src-tauri/migrations/0003_hosts.sql`, amended by
`0004_host_credential.sql`): id, hostname, os, agent_version,
`credential_hash` (SHA-256 hex of the per-agent credential, `NOT NULL`),
enrolled_at, last_heartbeat_at. Additive to the Phase 0 schema in
`0001_init.sql` / `0002_verdict_indexes.sql`, not a redesign of it.

`host_sighted_indicator` (`src-tauri/migrations/
0005_host_sighted_indicator.sql`): the edge PR #6 adds, carrying the full
authenticated claim a sighting makes -- host H observed indicator X
through detection R under ruleset V -- rather than splitting it across
two edges that can't be joined back together. `host_id`, `detection_id`
(which specific rule produced this host's sighting; without it, two
hosts matching the same hash via two different rules would be
indistinguishable -- see PR #6 above), `indicator_id`, `source`,
`confidence`, `path` (nullable, only advances on a conflict when the new
observation is at least as recent as what's stored), `ruleset_fingerprint`
(SHA-256 hex over a canonical manifest of the loaded rule files, part of
the primary key so a materially different ruleset creates a new row
instead of merging into an old one), `received_at` (console-controlled
ingestion time, set once, never updated -- see PR #6 above for what this
does and doesn't guarantee about a misbehaving endpoint clock),
`first_seen`, `last_seen`. Primary keyed on `(host_id, detection_id,
indicator_id, source, ruleset_fingerprint)` -- the same edge shape every
other edge in `0001_init.sql` uses, extended by two columns for the
reasons above.

No schema changes in PR #7 -- it only reads `host_sighted_indicator`,
joined against `host` (for `hostname`), `indicator` (for the sha256
`value`), and `detection` (for the rule `name`), via
`SightingView` (`nsic_core::proto`).

## Running it locally

```bash
docker compose up -d                       # Postgres, same as Phase 0
export DATABASE_URL=postgres://nsic:nsic@localhost:5432/nsic
export NSIC_ENROLLMENT_SECRET=dev-secret   # pick anything for local testing
export NSIC_OPERATOR_SECRET=dev-operator-secret  # ditto -- gates the read endpoints below

cargo run -p console --bin nsic-console &  # listens on 127.0.0.1:8787

cargo run -p agent --bin nsic-agent -- enroll \
  --console-url http://localhost:8787 --hostname "$(hostname)" \
  --enrollment-secret "$NSIC_ENROLLMENT_SECRET"
# -> enrolled: host_id=<uuid>
# -> credential (store this securely, the console will not show it again): <token>

cargo run -p agent --bin nsic-agent -- heartbeat \
  --console-url http://localhost:8787 --host-id <uuid> --credential <token>
# -> heartbeat ok: received_at=...

cargo run -p agent --bin nsic-agent -- scan path/to/file --rules-dir yara-rules
# -> {"path": "...", "rules_dir": "yara-rules", "rule_count": 1, "sha256": "...", "matches": [...]}

cargo run -p agent --bin nsic-agent -- scan path/to/file --rules-dir yara-rules \
  --console-url http://localhost:8787 --host-id <uuid> --credential <token>
# -> (same JSON as above, then, for each match:)
# -> reported sighting: indicator_id=<uuid> rule=<rule name>

curl -H "Authorization: Bearer $NSIC_OPERATOR_SECRET" \
  http://localhost:8787/api/v1/hosts/<uuid>/sightings
curl -H "Authorization: Bearer $NSIC_OPERATOR_SECRET" \
  http://localhost:8787/api/v1/indicators/<sha256>/sightings
# -> {"sightings": [{"host_id": "...", "hostname": "...", "sha256": "...",
#     "detection_name": "...", "source": "agent:yara_scan", "confidence": 65,
#     "path": "...", "ruleset_fingerprint": "...", "first_seen": "...",
#     "last_seen": "...", "received_at": "..."}]}
```

`--enrollment-secret` and `--credential` both fall back to
`NSIC_ENROLLMENT_SECRET` / `NSIC_AGENT_CREDENTIAL` if omitted. The two
read endpoints have no dedicated CLI command yet -- `curl` (or any HTTP
client) with the operator credential as a bearer token, as above.

`crates/agent` and `crates/console` do not need the WebKitGTK/GTK system
libraries `src-tauri` requires on Linux (`libwebkit2gtk-4.1-dev` etc.);
they're plain Rust binaries. `crates/nsic-core` needs nothing beyond a
Rust toolchain by default; the `db` feature needs the same Postgres
driver `src-tauri` already needs, and the `yara-scan` feature needs
`libyara-dev` (also already required by `src-tauri`). `crates/agent`
enables `yara-scan` (for `scan`) but not `db`; `crates/console` enables
`db` but not `yara-scan` — neither links what it doesn't use.
