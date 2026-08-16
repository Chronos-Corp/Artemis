# Phase 1 design: agent plus console

Status: enrollment, heartbeat, sighting submission, reading sightings back
out, both halves of sample retrieval (request + agent fulfillment, and
reading the retrieved content back out), TLS, credential rotation/
revocation, and a browser-facing fleet UI covering all of the above are
authenticated end to end; most of the phase is still not built. This
document tracks what Phase 1 actually is, what's landed so far, and
what's deliberately deferred, in the same spirit as the README's Phase 0
"what works today / what's stubbed" split.

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
6. **PR #8 — sample retrieval, write path.** The third Phase 1 pillar per
   the README. An operator requests a specific file from a specific host
   (the console-operator credential again -- this is an analyst action,
   not something an agent initiates); the agent polls for its own pending
   requests and uploads the bytes, or reports why it couldn't. Reading
   retrieved sample content back out is deferred to a follow-up PR, the
   same split #6/#7 already established for sightings.
7. **PR #9 — sample-retrieval concurrency and safety fixes.** A
   post-merge review of #8 found a real race in how a pending request
   gets resolved (two concurrent fulfillments, or a fulfillment racing a
   failure report, could both pass the "is it still pending" check and
   both write, silently corrupting the outcome), plus an unbounded
   client-side file read with no local size cap to match the console's.
   Both fixed before starting the read half, deliberately: this is
   exactly the kind of evidence-integrity bug that gets harder to unwind
   the more gets built on top of it.
8. **PR #10 — reading sample content back out.** The read half #8
   deferred. Two operator-credential download endpoints: by a specific
   sample request (for an operator already looking at
   `list_sample_requests`), and directly by sha256 (content-addressed,
   independent of which request or host originally supplied it -- the
   same "pivot from a hash you already have" pattern #7 established for
   sightings). Raw bytes, not JSON, same reasoning as the upload side.
9. **PR #11 — TLS/deployment hardening.** Everything through PR #10 talks
   plain HTTP -- credentials and retrieved sample content (including
   actual malware bytes) crossed the wire in plaintext. Opt-in TLS
   termination in the console, and a matching way for the agent to trust
   a self-signed or internal-CA console certificate, so a real deployment
   isn't forced to sit behind a separate TLS-terminating proxy just to
   stop shipping secrets in the clear.
10. **PR #12 — credential rotation and revocation.** Until now, a
    compromised or decommissioned host's per-agent credential could only
    be invalidated by deleting its `host` row outright, discarding its
    sighting/sample-request audit trail to do it. Two new
    operator-credential-gated endpoints let an operator replace a host's
    credential in place, or lock it out without issuing a new one, while
    keeping the host's id and history intact.
11. **PR #13 — fleet UI.** `crates/console` was API-only through PR #12 --
    every read and write required `curl` or a script. This PR adds a
    server-rendered HTML console (no Node/npm, no build step) covering
    the whole operator workflow built so far: browse the fleet, drill
    into a host's sightings and sample requests, request a new sample,
    download retrieved content, and rotate or revoke a credential. Also
    fills a long-documented gap along the way: `GET /api/v1/hosts` and
    `GET /api/v1/hosts/{host_id}`, the "list all hosts" endpoint noted as
    missing since PR #7.
12. **PR #14 — sensor health / scan coverage.** A gap flagged since PR
    #6: a sighting only ever fires on a YARA match, so zero active rules
    and zero detections looked identical from the console's side -- a
    host that never scanned, or whose rules directory failed to load,
    was indistinguishable from one that scanned and genuinely found
    nothing. `nsic-agent scan` now reports scan coverage (rule count,
    ruleset fingerprint, match count) to the console unconditionally,
    not only on a match, and the fleet UI surfaces it as a "never
    scanned" / "0 rules loaded" / healthy badge per host.
13. **PR #15 — scan staleness alerting.** The follow-on gap PR #14 itself
    named: the fleet UI showed *when* a host last scanned but never
    flagged an old one as needing attention, so an operator still had to
    notice every timestamp themselves. `HostView::scan_stale`, computed
    at read time against a configurable threshold
    (`NSIC_SCAN_STALENESS_HOURS`, default 24h), adds a fourth badge state
    -- "stale" -- to the three PR #14 introduced.
14. **Later, not started:** plugin/scripting support (see "What's
    deliberately not here yet" below for the near-term answer already
    available without building anything new).

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

**A fixed row cap, not real pagination -- and callers can tell when
they've hit it.** Both endpoints fetch `SIGHTING_LIST_LIMIT + 1` (1001)
rows, and if that extra row shows up, trim it back off and set
`SightingListResponse::truncated = true`. Without the extra-row probe, a
response capped at exactly 1000 rows is indistinguishable from a host or
hash that genuinely has exactly 1000 sightings -- `truncated` is what lets
a caller tell "this is everything" from "there's more, and this endpoint
can't hand it to you yet." Still not a cursor -- there's no way to reach
the rows past the cap, only a signal that they exist. The off-by-one trim
logic (`truncate_to_limit`) is a small generic helper specifically so it
can be unit-tested directly on a plain `Vec` without a database, rather
than only indirectly by seeding 1000+ rows through the real endpoint.
Real pagination is deferred until a fleet actually produces enough
sightings per host or per hash to make the cap a real problem (see
below).

**`ORDER BY last_seen DESC` alone doesn't guarantee a stable order for
ties.** Two sightings for the same host observed at the exact same
instant used to sort however Postgres felt like breaking the tie, which
is fine for a one-off read but means two separate calls to the same
endpoint over unchanged data weren't guaranteed to return rows in the
same order -- silently inconsistent with the row that happened to land
at the cap potentially differing between two truncated responses of the
same query. Both queries now tie-break on the rest of the relevant
primary-key columns (whichever ones the `WHERE` clause doesn't already
fix), so the full sort key is unique per row and the order is
deterministic. Verified with a test that submits two sightings with
identical `last_seen`, calls the endpoint twice, and asserts the two
responses return rows in the same order.

**This is the first PR in this sequence with DB-backed tests actually
executed, not just reviewed.** A local Postgres 16 instance was available
in this sandbox (unlike prior PRs, where none was), so the full DB-backed
suite (`cargo test -- --include-ignored`) ran for real, including tests
for missing/wrong operator credential, a per-agent credential rejected,
an unknown host returning an empty list, malformed sha256 rejected, the
full round trip confirming every denormalized field on the response
actually matches what was reported, and the tie-break/ordering-stability
test above. The write-then-read path was also exercised end to end
against the real binaries (`nsic-console` + `nsic-agent`), not just the
in-process test harness: enroll, scan-and-report a real EICAR match, then
`curl` both new endpoints with the operator credential and confirm the
JSON (including `truncated: false`) matches, and confirm the console
still refuses to start without `NSIC_OPERATOR_SECRET` set, or with
`NSIC_ENROLLMENT_SECRET`/`NSIC_OPERATOR_SECRET` empty or equal to each
other (`validate_secret_configuration` in `main.rs` -- see below).

**Bootstrap and operator secrets can't silently collapse into the same
value.** The console now refuses to start if either
`NSIC_ENROLLMENT_SECRET` or `NSIC_OPERATOR_SECRET` is empty, or if the
two are equal. Nothing upstream of this PR would have caught an operator
setting both to the same value in their environment -- every check this
design relies on (`authenticate_host`'s per-agent lookup aside)
ultimately reduces to "does the presented token equal the configured
one," so if the two configured values are equal, a valid *bootstrap*
secret would also pass the *operator* check, quietly reopening exactly
the read-access-via-enrollment-secret conflation this PR's whole
credential design exists to avoid. Plain `==`, not `auth::secrets_match`'s
constant-time comparison: this runs once at process startup on two local
config values, not a request path an attacker can measure timing on.
Unit-tested directly (`validate_secret_configuration` in
`crates/console/src/main.rs`) rather than only via the console's startup
behavior, and confirmed live: starting the binary with
`NSIC_ENROLLMENT_SECRET=same NSIC_OPERATOR_SECRET=same` fails fast with a
clear error before touching Postgres.

### PR #8: sample retrieval, write path

Locked architecture decision #3 (README): file contents leave a host only
on explicit analyst request, logged and attributed. Nothing before this
PR let an analyst actually get bytes off a host -- sightings only ever
carry a hash, never content. This PR is that request/fulfillment flow;
reading the retrieved content back out is deferred to a follow-up PR, the
same split #6/#7 already established for sightings (write first, read
once there's something to read).

**Push isn't possible, so this is poll.** The agent only ever makes
outbound requests to the console -- it doesn't listen for anything, and
there's no persistent daemon (`nsic-agent` is still a one-shot CLI, same
as every other subcommand). So an operator's request can't be delivered
to a specific agent directly; instead the agent polls
`GET /api/v1/agents/{host_id}/sample-requests` for its own pending work
and acts on whatever it finds. `nsic-agent fulfill-samples` does this in
one invocation: list pending, then for each one, read the requested path
and upload it (or report why that read failed), matching `scan`'s
"one CLI call does the whole job" shape.

**A new, third database table, not a repurposed sightings edge.**
`sample_request` (`src-tauri/migrations/0006_sample_request.sql`) is its
own row per analyst request -- host, path, optional asserted hash,
status, and how it was resolved -- because a sample request has a
lifecycle (`pending` → `fulfilled`/`mismatched`/`failed`) that a sighting
never had. `sample_blob` stores the actual bytes, content-addressed by
sha256 the same way `indicator` already is, so the same file retrieved
from two hosts (or the same host twice) is stored once. Raw `BYTEA` in
Postgres, not a separate object store -- the simplest thing that works
for Phase 1 (see below for what that doesn't cover).

**Operator-authenticated to create and list; per-agent-authenticated to
poll and resolve.** `POST`/`GET /api/v1/hosts/{host_id}/sample-requests`
(create a request; list every request for a host, any status) require the
operator credential -- requesting a file off a host is an analyst
action, not something a host does to itself, exactly the same reasoning
that already gates reading sightings. `GET /api/v1/agents/{host_id}/
sample-requests` (poll pending only) and the two resolution endpoints
(`POST .../content`, `POST .../failure`) require that specific host's
per-agent credential. Verified both directions: a host's own credential
does not authorize creating or listing requests
(`create_sample_request_rejects_per_agent_credential`), and the operator
credential does not authorize polling
(`list_pending_sample_requests_rejects_operator_credential`) -- neither
credential works in the other's place, the same mutual check PR #7
established for sightings.

**Raw bytes, not JSON.** Every other request/response in this API is
JSON; `POST .../content`'s body is the sample's raw bytes
(`axum::body::Bytes`), `Content-Type: application/octet-stream`. Base64-
encoding a multi-megabyte sample into a JSON field would inflate it by
roughly a third for no benefit once nothing else in the payload needs to
be structured.

**A size cap, enforced twice.** `sample::MAX_SAMPLE_SIZE_BYTES` (100 MiB)
is applied as an `axum::extract::DefaultBodyLimit` on the upload route
specifically -- not globally, so a misbehaving JSON client on some other
endpoint can't force the server to buffer up to 100 MiB before rejecting
it -- and checked again explicitly inside the handler, belt-and-
suspenders in case that layer is ever misconfigured or dropped in a
future refactor. Not exercised with an actual 100 MiB+ transfer in
either the automated tests or the live smoke test below (the cost of
generating and uploading that much data on every run/verification isn't
worth it for a straightforward length comparison); verified by code
review that the layer is present and the check is correct, not by
observing the rejection happen.

**A pending request can't be silently overwritten.** Fulfilling or
failing a request first confirms it's still `pending`
(`claim_pending_request`, shared by both resolution paths) and returns
`409 Conflict` otherwise. Without this, a stale or replayed upload could
quietly rewrite an already-resolved request's outcome -- exactly the
kind of already-recorded-evidence tampering this project has been
careful to close off elsewhere (e.g. `host_sighted_indicator`'s
stale-observation-can't-regress-`path` rule in PR #6). Verified with
`fulfill_sample_request_rejects_already_resolved_request` and
`fail_sample_request_rejects_already_resolved_request`.

**A wrong or unknown request id looks the same from an agent's
perspective.** `claim_pending_request` looks a request up by `(id,
host_id)` together, so a request belonging to a different host returns
the same `404` as a request id that doesn't exist at all -- a request id
can't be used to probe whether it belongs to some other host, the same
"don't leak existence" property `authenticate_host` already has for
credential checks.

**Mismatches are a distinct, visible outcome, not silently upgraded to
success.** `SampleRequestCreate::expected_sha256` lets an analyst pivoting
from a known hash assert what they expect to receive. If the agent
uploads something that hashes to something else -- wrong file, changed
since the hash was recorded, or worse -- the request resolves to
`mismatched`, not `fulfilled`, and that status is what the operator's
list view shows. Verified with
`fulfill_sample_request_mismatched_expected_sha256_marks_mismatched`,
which confirms the mismatch is visible through the real list endpoint,
not just in the immediate response.

**Row cap and deterministic ordering applied from the start, not added in
a second review round.** Both list endpoints use the same
`truncate_to_limit`/`truncated`-flag pattern PR #7 added after review
(now shared via `crates/console/src/pagination.rs` rather than
duplicated), and order by `requested_at` with `id` as an explicit
tie-break. `validate_lowercase_sha256`/`bad_request` similarly moved to a
new `crates/console/src/validate.rs`, shared between `sighting.rs` and
the new `sample.rs`, once there were two real consumers instead of one.

**Verified against a live Postgres and the real binaries again.** The
full DB-backed suite (22 new tests in `sample.rs`, 57 total across
`console`) ran for real, twice, to confirm rerun-safety. The complete
write-then-poll-then-fulfill flow was also exercised against the actual
`nsic-console`/`nsic-agent` binaries: created a real sample request via
`curl` with the operator credential, ran `nsic-agent fulfill-samples`
against a real file, confirmed the uploaded content's sha256 matches
`sha256sum` run directly against the same file, confirmed a second
`fulfill-samples` run correctly reports nothing pending, and confirmed
the failure path (a request for a path that doesn't exist on the host)
resolves to `failed` with a clear reason instead of hanging or silently
dropping the request.

### PR #9: sample-retrieval concurrency and safety fixes

A post-merge review of PR #8 found a real, high-priority race condition
plus a strong follow-up worth fixing before building the read half on
top of either. Fixed here, before any download endpoint exists.

**The race: two concurrent resolutions of the same request could both
write.** `claim_pending_request` originally ran a plain `SELECT` to check
a request was still `pending`, outside any transaction, before a
*separate* transaction did the actual `INSERT`/`UPDATE` -- and that final
`UPDATE` had no `WHERE status = 'pending'` condition of its own. Two
concurrent fulfillments could both pass the initial check before either
had written anything, then both write, with whichever committed second
silently overwriting the first's forensic result. Racing a fulfillment
against a failure report was worse: the two updates touch different
columns (`sha256` vs. `failure_reason`), so depending on ordering the row
could end up `failed` while `sha256` still pointed at successfully
uploaded bytes, or `fulfilled` with a stale `failure_reason` left
attached -- a self-contradictory row, directly contradicting the code
comment that promised an already-resolved request couldn't be
overwritten.

Fixed with `SELECT ... FOR UPDATE`: `claim_pending_request` now locks the
row for the remainder of the caller's transaction. A second transaction
trying to claim the same row *blocks* at the database level until the
first commits or rolls back, then observes the post-resolution status
and correctly gets `409`. The final `UPDATE` (factored into a shared
`resolve_claimed_request`) still carries `AND status = 'pending'` as
defense-in-depth, but the lock is the actual guarantee -- if that
`UPDATE` ever affected zero rows, that would mean the locking invariant
itself broke, and it's logged and surfaced as a `500` rather than
silently ignored.

Verified two ways. First, negatively: temporarily swapped in the
original unlocked code with the new tests still attached and ran them
repeatedly -- they failed a real fraction of runs (assertions like
"exactly one of these two concurrent attempts should succeed" failing
because both succeeded, or the row ending up in a self-contradictory
state), confirming the tests actually catch the bug rather than passing
vacuously. Then, positively: the fixed code passed the same tests
consistently across repeated runs. The two new tests
(`fulfill_sample_request_concurrent_attempts_exactly_one_succeeds`,
`fulfill_and_fail_concurrent_attempts_leave_a_self_consistent_row`) fire
real concurrent requests from separate `tokio::spawn`ed tasks sharing the
same connection pool via `tokio::join!`, not a sequential
double-resolution check -- the previous tests with "resolved" in their
name predate this fix and only ever exercised the sequential case, which
was never the part that was actually broken.

**The follow-up: the agent had no size cap of its own.** The console's
100 MiB cap (`nsic_core::proto::MAX_SAMPLE_SIZE_BYTES`, moved there from
`console::sample` so both sides reference the same constant instead of
each hardcoding a copy that can drift) only protects the console -- it
rejects an oversized upload, but by the time that rejection happens the
agent has already read the whole file into memory via an unbounded
`std::fs::read`. A multi-gigabyte file named by a request's `path` would
exhaust agent memory before the console ever got a chance to say no; an
endless special file (a device node, a FIFO) named by that path could be
far worse than merely large. Fixed with `read_bounded_sample`
(`crates/agent/src/main.rs`): checks `std::fs::metadata(path).is_file()`
first (rejecting directories and special files, but still following
symlinks to an ordinary file's final target, since a legitimate request
path being a symlink shouldn't be penalized), then reads at most
`MAX_SAMPLE_SIZE_BYTES + 1` bytes via `Read::take` and rejects anything
that hits that ceiling -- never buffers meaningfully more than the limit
regardless of how large or strange the target actually is. Six new,
DB-free unit tests in `crates/agent/src/main.rs` cover within-limit,
exactly-at-limit, over-limit, a directory, and (on Unix) a symlink to an
ordinary file being correctly accepted.

**Documentation correction: attribution was overstated.**
`SampleRequestCreate`'s doc comment used to say a `sample_request` row
records "host, path, requester, and eventual outcome," listing
"requester" as something the row tracks. It doesn't -- there is no
per-user operator identity (see the deferred RBAC note below), only the
shared operator credential as an undifferentiated whole. The migration's
own comment already said this correctly; the Rust doc comment didn't
match it. Fixed to describe only what's actually stored.

**Not fixed here, logged as deferred instead: `ON DELETE CASCADE` on
`sample_request.host_id`.** Deleting a host currently deletes its entire
retrieval-request history along with it -- for a table that's explicitly
the audit trail locked architecture decision #3 requires, that's a real
tension, but there's no host deletion/decommissioning workflow yet for
it to bite in practice. See below.

**Also not fixed here, also logged as deferred: a smaller TOCTOU in
`read_bounded_sample` itself.** It checks `std::fs::metadata(path)
.is_file()`, then separately calls `std::fs::File::open(path)` -- a
local process could in theory swap what that path resolves to (a FIFO,
a device node, a different symlink target) in the gap between those two
calls. `Read::take(max_bytes + 1)` still bounds memory use regardless,
so the actual problem this PR set out to fix (unbounded reads) stays
fixed either way; the residual risk is narrower -- mainly that a swap to
something blocking (a FIFO with no writer) could hang the one-shot
agent process while opening or reading it, not a memory-safety issue.
Worth tightening once the agent is more than a one-shot CLI: handle-
based identity/type validation (open first, then check the open file
descriptor's metadata, rather than checking a path and trusting a
second open of "the same" path) rather than a path check followed by a
separate open, and on Unix, nonblocking open flags are worth
considering against hostile special files. Not worth the added
complexity for Phase 1's one-shot invocation model yet.

### PR #10: reading sample content back out

The read half of sample retrieval PR #8 deferred, following the same
write-then-read split #6/#7 already used for sightings. No schema
changes -- both endpoints read `sample_blob`, which #8 already wrote.

**Two access patterns, both operator-credential only.**
`GET /api/v1/hosts/{host_id}/sample-requests/{request_id}/content`
downloads via a specific request -- the natural next step after
`list_sample_requests`, which already hands back a request's `id`.
`GET /api/v1/samples/{sha256}/content` downloads directly by hash,
independent of which request or host originally supplied the content --
the same "pivot from a hash you already have" pattern
`list_indicator_sightings` established for sightings, and the more
useful pattern once content is deduplicated: an operator who already has
a sha256 (from a sighting, or from another host's already-fulfilled
request) shouldn't need to know or care which specific request first
retrieved it.

**Serving by hash doesn't reopen locked architecture decision #3's
gate.** "File contents leave a host only on explicit analyst request" is
enforced once, at upload time -- only a `pending`, per-agent-
credentialed request can add anything to `sample_blob` in the first
place (see PR #8/#9). Once content is legitimately stored there, which
authenticated operator query later reads it back out isn't a second
gate the design ever depended on.

**Availability is a `JOIN`, not a separate status check.** The
per-request endpoint joins `sample_request` to `sample_blob` on
`sr.sha256 = sb.sha256`; since that column is only ever non-`NULL` once
a request has resolved to `fulfilled` or `mismatched` (see the
migration), a `pending` or `failed` request simply has no matching row.
Same `404` as a request that doesn't exist at all -- an operator already
has full visibility into *why* via `list_sample_requests`'s `status`
field, so there's nothing this endpoint needs to explain that the list
view hasn't already shown. Verified with tests covering both non-
available statuses (`pending`, `failed`) returning `404`, and both
content-bearing statuses (`fulfilled`, `mismatched`) returning the
actual bytes -- a mismatched request still has real, successfully-
uploaded content; the mismatch is between what was expected and what
arrived, not a failure to store anything.

**Raw bytes, not JSON, named by hash.** Same reasoning as the upload
side: base64-encoding a multi-megabyte sample for no benefit is wasted
overhead. Responses set `Content-Type: application/octet-stream` and
`Content-Disposition: attachment; filename="<sha256>"` -- named by the
hash rather than the path the agent originally reported, since an
arbitrary analyst-supplied path could contain characters that don't
belong in a header value while a hex-encoded sha256 always does.

**Verified against a live Postgres and the real binaries.** 13 new
tests in `sample.rs` (85 total across the workspace), covering both
endpoints' credential checks (including the same mutual-exclusion
property verified everywhere else: a per-agent credential doesn't
authorize operator-facing reads, and vice versa), malformed-sha256
rejection, unknown-id/unknown-hash `404`s, both non-available statuses
returning `404`, both content-bearing statuses returning bytes, and
content-addressing working across hosts (content uploaded fulfilling
one host's request downloads correctly by hash with no reference to
that host or request at all). The full write-then-download round trip
was also exercised against the actual `nsic-console`/`nsic-agent`
binaries: created a request, fulfilled it via `nsic-agent
fulfill-samples`, downloaded the content both ways (`curl` by request
id and by sha256), and confirmed both downloads are byte-identical to
the original file via `diff` and to each other, with the response
headers matching exactly what's documented above. Also confirmed live:
missing credential (`401`), unknown hash (`404`), and unknown request id
(`404`).

### PR #11: TLS/deployment hardening

Every PR through #10 ran the console over plain HTTP. That meant the
bootstrap secret, per-agent credentials, the operator secret, sighting
data, and now retrieved sample content -- actual malware bytes -- all
crossed the wire unencrypted. This PR makes TLS available end to end,
opt-in on the console side and matched by a corresponding trust option on
the agent side, without breaking any existing plain-HTTP deployment.

**Opt-in, both-or-neither, same shape as the existing secret
validation.** TLS activates only when both `NSIC_TLS_CERT_PATH` and
`NSIC_TLS_KEY_PATH` are set (`validate_tls_configuration` in
`crates/console/src/main.rs`); setting exactly one fails fast at startup
with a clear error, the same "half-configured is refused, not silently
downgraded" pattern `validate_secret_configuration` already established
for the bootstrap/operator secrets. Setting neither serves plain HTTP,
now with an explicit `tracing::warn!` naming exactly what's exposed
(credentials, sample content) and pointing at the two env vars that turn
it off. Existing local setups keep working unchanged; enabling TLS is a
deliberate operator choice.

**`axum-server` + `rustls`, not a bolt-on reverse proxy.** The console
serves HTTPS directly (`axum_server::bind_rustls`, config loaded via
`RustlsConfig::from_pem_file`) rather than requiring every deployment to
stand up its own TLS-terminating proxy in front of a plaintext console.
A proxy is still a reasonable choice for a real production deployment
(cert rotation, ACME, etc. -- see below); this just means it's no longer
the *only* way to get encryption in transit.

**A genuine bug, found only by actually starting the console with TLS
configured.** rustls needs exactly one process-level crypto provider
selected before anything builds a `ServerConfig`. `sqlx`'s
`runtime-tokio-rustls` feature pulls in rustls's `ring` provider;
`axum-server`'s `tls-rustls` feature pulls in rustls's `aws-lc-rs`
provider by default. Cargo's workspace-wide feature unification means
*both* ended up compiled into the same `console` binary
(`cargo tree -p console -e features -i aws-lc-rs` confirmed both paths),
and rustls refuses to guess between them -- the console panicked at the
first TLS handshake attempt with "Could not automatically determine the
process-level CryptoProvider." `cargo check`/`clippy`/the full test suite
never exercised this at all; nothing short of actually starting the
binary with TLS configured surfaced it. Fixed by adding a direct
`rustls` dependency to `console/Cargo.toml` with only the `ring` feature
enabled, and calling
`rustls::crypto::ring::default_provider().install_default()` as the
first statement in `main()`, before any secret or TLS-path validation --
cheap and harmless even on a run where TLS ends up disabled. Verified by
rebuilding and starting the console with TLS configured: it now logs
"console listening on `<addr>` (HTTPS)" and serves real HTTPS instead of
panicking.

**The agent trusts an additional root, it doesn't skip verification.**
A console operator running TLS with a self-signed or internal-CA
certificate needs some way for the agent to trust it, since that
certificate won't chain to a public root. Every console-talking
subcommand (`enroll`, `heartbeat`, `scan`, `fulfill-samples`) gained a
`--tls-ca-cert` / `NSIC_TLS_CA_CERT` option
(`crates/agent/src/main.rs`). `build_http_client` reads that PEM file and
adds it via `reqwest::Client::builder().add_root_certificate(cert)` --
*in addition to* the platform's normal CA store, never a flag that
disables certificate validation entirely. There is deliberately no
`--insecure`/skip-verification escape hatch: an operator without a real
or internal CA still gets a hard failure rather than a silent downgrade
to an unauthenticated channel. Verified live: an `enroll` attempt against
the TLS-enabled console *without* `--tls-ca-cert` fails with
`invalid peer certificate: UnknownIssuer` (the handshake genuinely
rejects an untrusted cert), and the same call *with* `--tls-ca-cert`
pointing at the console's certificate succeeds.

**`reqwest::Certificate::from_pem` doesn't validate content at parse
time -- confirmed directly, not assumed.** An initial test asserted that
`build_http_client` given a garbage (non-PEM) CA cert file should return
an `Err`. It didn't -- `from_pem` returned `Ok`. Checked directly via a
standalone throwaway Cargo project: plain garbage text, empty input, PEM
markers wrapping garbage, and PEM markers wrapping syntactically-invalid-
but-plausible-looking DER all parsed as `Ok`. Real validation only
happens later, during an actual TLS handshake against a server presenting
a certificate. `build_http_client`'s doc comment says this explicitly now,
and the test was renamed from an incorrect `_fails` expectation to
`build_http_client_with_malformed_ca_cert_still_succeeds_at_this_stage`,
asserting `.is_ok()` and documenting real `reqwest` behavior instead of
an assumption about it.

**Verified against a live Postgres and the real binaries, over real
HTTPS.** A self-signed certificate was generated locally (`openssl req
-x509 -newkey rsa:2048 ...`) and used to run the console with TLS
enabled. The complete flow was exercised end to end over
`https://localhost:8787`: `enroll --tls-ca-cert`, `heartbeat`, creating a
sample request via `curl --cacert`, `fulfill-samples`, `scan` plus
sighting report, and downloading the retrieved sample -- all succeeding,
with the downloaded content byte-identical to the original file via
`diff`. Also verified: plain-HTTP backward compatibility (console started
with neither TLS env var set serves HTTP exactly as before, `enroll`
over `http://` unaffected), and both halves of the half-configured
fail-fast case (`NSIC_TLS_CERT_PATH` set without `NSIC_TLS_KEY_PATH`, and
the reverse), each producing the expected startup error rather than
starting in some ambiguous state. The full 91-test suite (`nsic-core`,
`console`, `agent`) was run twice for rerun-safety.

**Not addressed here, worth flagging:** the `axum-server`
`tls-rustls` feature transitively pulls in `aws-lc-sys`, which needs
`cmake` to build -- present in this sandbox and expected to be present on
GitHub Actions' standard `ubuntu-latest` runner image, but not yet
confirmed against a real CI run at the time this was written.

### PR #12: credential rotation and revocation

Until this PR, a compromised or decommissioned host's per-agent
credential could only be invalidated by deleting its `host` row
outright -- which also deletes every sighting and sample request tied to
that host, since `sample_request.host_id` (and, transitively, sightings
via `host_sighted_indicator`) cascade on host deletion. For a design
whose whole premise is an evidence trail (locked architecture decision
#3), "revoke a credential" and "destroy the audit trail" being the same
operation was a real gap. Two new operator-credential-gated endpoints
close it without touching that trail:

- `POST /api/v1/hosts/{host_id}/credential/rotate` -- mints a fresh
  per-agent credential the same way `enroll` does, overwrites
  `host.credential_hash` with its hash, and returns the raw value exactly
  once (`CredentialRotated::credential`), the identical shown-once
  contract `EnrollResponse::credential` already has. Whatever credential
  the host was presenting before this call, compromised or not,
  immediately stops authenticating -- there's only ever one valid
  credential per host at a time, so rotating *is* revoking the old one as
  a side effect.
- `POST /api/v1/hosts/{host_id}/credential/revoke` -- locks the host out
  without handing back anything usable, for the case where an operator
  wants a suspected-compromised host stopped *now* and doesn't yet want
  to issue it a working replacement (or is decommissioning it and never
  will).

**Both reuse the enroll-vs-heartbeat sentinel trick, not a new
mechanism.** `authenticate_host` already only ever compares a presented
credential's hash against one stored value; there's no separate
"is this credential revoked" flag to add or forget to check. `revoke`
writes a fixed, non-hash-shaped sentinel string
(`revoked-requires-credential-rotation`) into `credential_hash` --
`hash_credential` always produces exactly 64 lowercase hex characters, so
no real credential can ever collide with it, and every subsequent
`authenticate_host` call for that host fails the same way a wrong
credential always did. This is the same trick `0004_host_credential.sql`
already used for hosts enrolled before the per-agent credential concept
existed (`legacy-host-requires-re-enrollment`), and `rotate` treats both
sentinels identically: `set_host_credential`'s `UPDATE` overwrites
whatever `credential_hash` currently holds without inspecting it first,
so rotating a legacy-sentinel host recovers it in place exactly the same
way it recovers a revoked one -- re-enrolling under a brand-new host id
is not the only way to give a legacy host a working credential, only the
only way to recover its *original* enrollment record if that ever
matters. (An earlier draft of this doc claimed re-enrollment was the
legacy sentinel's only recovery path; that was wrong about what the code
actually does, caught in review, and fixed here rather than by changing
the code to match the incorrect claim -- keeping "any operator can
recover any host in place via rotate" was judged the more useful
behavior.) The two sentinel strings still differ so a database inspection
of `credential_hash` can tell "never had a real credential" from
"explicitly revoked" apart, in case that distinction matters for an
incident writeup.

**An append-only `host_credential_event` log, not a single "last
changed" column.** An earlier draft of this PR added a nullable
`credential_rotated_at` timestamp to `host`, overwritten by both `rotate`
and `revoke`. Caught in review: overwriting one column on every call
means only the *most recent* event survives -- revoke during a
compromise, rotate during recovery, rotate again later would leave the
database showing only the final rotation, with no record a revocation
ever happened or when, directly undermining the audit trail this PR
exists to preserve (locked architecture decision #3). Fixed by replacing
that column with `host_credential_event` (`id`, `host_id`, `event_type`
-- `'rotated'` or `'revoked'` -- `occurred_at`), an append-only table
`set_host_credential` inserts into rather than updates, in the same
transaction as the `credential_hash` write so the two can't drift apart
on a crash between them. Still doesn't capture *who* triggered an event
or *why* (per the operator-identity gap already logged above, there's no
per-analyst identity yet to attribute it to) -- just that a specific kind
of event happened and when, which is enough to answer "was this host
ever revoked, and did it recover" without losing history to the next
rotation.

**Existence is checked explicitly, not inferred from `rows_affected`.**
An `UPDATE ... WHERE id = $1` that touches zero rows can't distinguish
"no such host" from "host exists, value happened to already be identical
to what was written" -- the latter never actually occurs here (a fresh
random credential or the fixed revoke sentinel are never equal to
whatever was already stored by pure chance), but relying on that would
be a coincidence load-bearing enough to be worth not depending on.
`set_host_credential` (`crates/console/src/host.rs`, shared by both
handlers) treats zero rows affected as "unknown host_id" and returns
`404` -- the same "operator is already privileged, nothing left to hide
by returning 401 instead" reasoning `create_sample_request` already
established for its own unknown-`host_id` case, not the
existence-hiding `401` agent-facing endpoints like `heartbeat` use.

**`Cache-Control: no-store` on both credential-bearing responses.**
`enroll` and `rotate` are the only two responses in this API that hand
back a raw, usable secret; both now set `Cache-Control: no-store` so an
intermediate cache or the calling HTTP client's own response cache can't
retain a value that's shown exactly once and never recoverable from the
console again. Added during review, alongside the other two fixes above,
rather than as a separate follow-up PR -- cheap, small, and touches
exactly the two handlers this PR already modifies.

**`revoke`'s doc comment was tightened to not overclaim retroactive
cancellation.** It now says explicitly what was previously implied
loosely by "locks the host out immediately": revocation changes what
`authenticate_host` accepts on *subsequent* calls, and has no effect on
a request that already passed that check before revocation completed --
there is no in-flight-request cancellation anywhere in this API, and the
wording should not have suggested otherwise.

**Verified against a live Postgres, and against the real binaries.** Tests
in `crates/console/src/host.rs` cover: rotating replaces the old
credential (old one stops authenticating a heartbeat, new one works);
rotating twice leaves only the second credential valid; rotate/revoke
both reject a missing operator credential, a wrong operator credential, a
host's own per-agent credential, and an unknown `host_id`; revoking locks
out the host's existing, otherwise-still-correct credential; revoke
followed by rotate recovers the host with a fresh working credential,
without re-enrolling; a cross-host test confirms rotating one host's
credential doesn't disturb a second, unrelated host's; revoke-then-
rotate-then-rotate leaves three separate rows in `host_credential_event`
rather than one overwritten row (the direct regression test for the
column-vs-log review finding above); a legacy-sentinel host recovers in
place via `rotate` (the direct test for the recovery-path documentation
fix above); and both `enroll` and `rotate` set `Cache-Control: no-store`.
Full workspace suite (`nsic-core`, `console`, `agent`; 107 tests) run
twice for rerun-safety. Also exercised against the real
`nsic-console`/`nsic-agent` binaries: enrolled a host, revoked it and
confirmed its original credential now gets `401`, rotated it and
confirmed the new credential works, rotated a second time and confirmed
all three events (`revoked`, `rotated`, `rotated`) persisted in
`host_credential_event` with distinct timestamps in order, seeded a
legacy-sentinel host directly via SQL and confirmed `rotate` recovers it
in place, and confirmed `rotate`'s response carries
`Cache-Control: no-store` over the wire.

**Deliberately out of scope:** rotating `NSIC_OPERATOR_SECRET` itself
(still a restart-with-a-new-env-var operation, see below) and any CLI
subcommand for calling these endpoints -- consistent with every other
operator-only action so far (creating/listing sample requests, reading
sightings back out), which are `curl`-with-a-bearer-token only, not
wrapped in `nsic-agent`.

### PR #13: fleet UI

`crates/console` was API-only through PR #12 -- every read and every
write required `curl`, a script, or `nsic-agent`. This PR adds a
browser-facing UI covering the operator workflow built so far: browse
every enrolled host, drill into one host's sightings and sample
requests, request a new sample, download retrieved content, and rotate
or revoke that host's credential.

**Server-rendered Rust, not a second npm project.** The Phase 0 desktop
app already has a React/Vite frontend (`src/`), but reusing that stack
here would mean a second toolchain, a second CI job, and a build step
`crates/console`'s binary has never needed -- undercutting the "plain
Rust binary, no Node/npm" pitch this crate has made since PR #3. Chosen
instead: `maud`'s `html!` macro renders HTML directly in Rust, compiled
into the same binary, with no template files and no runtime template
parser. Every page and form is plain HTML; write actions are plain
`<form method="post">` submissions, not JS-driven `fetch()` calls --
`crates/console` still ships zero client-side JavaScript. `maud`'s own
`axum` integration feature was tried first and dropped: it pulls a newer
`axum-core` than this workspace's `axum 0.8` depends on, so two
incompatible `axum-core` versions ended up in the same binary and
`IntoResponse` failed to resolve across the boundary. Rendering
`Markup::into_string()` into `axum::response::Html` directly avoids
needing that feature at all.

**`maud` auto-escapes, which is load-bearing here, not incidental.**
Hostnames, paths, detection names, and failure reasons are all agent- or
analyst-supplied strings with no character restrictions (`sighting.rs`'s
`validate_sighting_request` checks length and emptiness, never content;
`host::enroll` doesn't validate `hostname` at all) -- every one of them
lands directly in this UI's markup. Verified, not assumed: two tests
(`host_directory_escapes_a_hostile_hostname`,
`host_detail_escapes_hostile_sighting_fields`) enroll a host named
`<script>alert(1)</script>` and report a sighting with `<img
src=x onerror=alert(1)>` as its detection name, then assert the raw tag
never appears in the rendered response and the escaped form
(`&lt;script&gt;...`) does -- a real XSS regression test, not just
trusting the templating library's documentation.

**HTTP Basic auth against the same operator secret, not a new
credential or a session.** The UI needs *some* way for a browser to
authenticate as the operator, and `NSIC_OPERATOR_SECRET` already exists
for exactly that role -- the question was only how to present it. Basic
auth (`auth::authenticate_operator_ui`, checked against a `WWW-
Authenticate: Basic` challenge, distinct from `authenticate_operator`'s
Bearer check the JSON API still uses exclusively) gets a browser's native
credential prompt for free, and once entered, the browser resends it
automatically on every subsequent request to this origin -- which is
what lets plain `<a href>` navigation, plain form POSTs, and plain
download links all work with zero JavaScript and no session/cookie
machinery to build (no cookie store, no CSRF-token-per-form
infrastructure, no login/logout routes). The tradeoff, accepted and
logged below: no logout short of closing the browser, and the same
ambient-credential CSRF exposure a cookie-based session would have had
anyway (see below).

**A fresh credential is rendered directly, never redirected through a
URL.** Rotating a host's credential from the UI (`rotate_credential_
action`) renders a minimal, standalone success page directly as the POST
response (`200`), with the new credential in a banner, instead of the
more typical redirect-after-POST pattern the other two write actions
(create sample request, revoke) use. Not a redirect: a redirect would
need to carry the new credential somewhere for the next request to
display it, and the only place available -- the URL's query string -- is
a bad place to put a secret: it lands in browser history and can be
logged by any proxy in front of the console. Not the full host detail
page either -- an earlier draft rendered that directly, which meant three
more database reads (host metadata, sightings, sample requests) happened
*after* the credential had already been committed; if any of those three
failed, the response would be a `500` with the old credential already
invalidated and the new one never shown, recoverable only by rotating
again. Caught in review. The success page now needs nothing beyond
`host_id` and the credential already in hand, so nothing between the
commit and the response can fail. The accepted remaining cost: refreshing
that response (F5) prompts the browser to ask about resubmitting the
form, since it's a direct POST response.

**Two new JSON endpoints, useful independent of the UI.** `GET
/api/v1/hosts` and `GET /api/v1/hosts/{host_id}` fill a gap flagged since
PR #7 ("no way to discover valid host_ids through the API at all") --
needed for the UI's host directory and detail pages, but available to
any operator-credentialed caller (a script, `curl`) the same way every
other list/get endpoint is. New `nsic_core::proto::HostView`/
`HostListResponse` types; `HostView` deliberately never includes
`credential_hash` -- nothing operator-facing has a reason to read that
back, hashed or not.

**Read queries are shared with the JSON API, not duplicated.**
`sighting::fetch_host_sightings`, `sample::fetch_sample_requests`,
`sample::fetch_content_by_request`, `host::fetch_all_hosts`, and
`host::fetch_host` were factored out of the existing JSON handlers
(`list_host_sightings`, `list_sample_requests`,
`download_sample_by_request`, and the two new host endpoints above) into
`pub(crate)` functions returning plain Rust values, called by both the
JSON handler and the corresponding UI page. The alternative -- writing a
second, UI-specific copy of each query -- would let the JSON response and
the HTML page silently drift apart on what "every sighting for this
host" actually returns. Write paths took the same approach:
`sample::insert_sample_request` and `host::set_host_credential` (already
shared by `rotate_credential`/`revoke_credential` since PR #12) are
called directly by the UI's form handlers, so a rotate/revoke/sample-
request performed through the browser goes through the exact same
validation, transaction, and audit-event logic as the one performed
through `curl`.

**CSRF protection: a single per-process token, not a session.** An
earlier draft of this PR shipped with no CSRF defense at all, reasoning
that "loopback-only by default" made it unnecessary -- caught in review
as wrong: a malicious page can target `http://localhost:8787` (or
`127.0.0.1`) directly regardless of what network serves the attacker's
own page, and the browser attaches a cached Basic Auth credential to a
cross-origin form submission exactly as readily as it would a same-origin
one. Basic Auth alone is not CSRF protection -- it proves the request
carries a valid operator credential, not that the operator actually
intended to submit it. Fixed with `AppState::csrf_token`: one high-entropy
value (`auth::generate_csrf_token`) generated once at console startup,
rendered as a hidden field in all three UI POST forms, and checked
(`auth::verify_csrf`, `ui::require_csrf`) before any of the three
handlers does anything else. This doesn't require per-user sessions or
even per-request rotation -- the token's only job is being unreadable to
a cross-origin attacker, and the Same-Origin Policy already guarantees
that regardless of whether the token ever changes: an attacker's page can
*submit* a form to this console, but it cannot *read* this console's
authenticated HTML to discover what value belongs in the hidden field, so
it cannot construct a request `verify_csrf` accepts.

**`Content-Security-Policy` and `X-Frame-Options`, applied as a layer
over the whole UI sub-router.** `security_headers`
(`crates/console/src/ui.rs`) sets `default-src 'none'` with no
`script-src` exception -- since this module ships no client-side
JavaScript, a CSP that would block any acts as a standing correctness
check on that claim, not just hardening (`style-src 'unsafe-inline'` is
the one exception, needed only because `layout` inlines its stylesheet
rather than serving a separate file). `frame-ancestors 'none'` plus the
legacy `X-Frame-Options: DENY` stop the authenticated console from being
embedded in another page's `<iframe>` for a clickjacking attack.
`Cache-Control: no-store` moved from a single hand-set header on the old
rotate response to this same layer, so it now covers every fleet UI
response, not only the one that used to show a raw credential --
sightings, paths, and downloaded sample bytes are all sensitive enough
not to belong in a shared or browser cache either.

**The revoke form's inline `onsubmit="return confirm(...)"` was
removed, not kept alongside a looser CSP.** An earlier draft had this on
the revoke button for a native "are you sure?" browser dialog -- flagged
in review as inline JavaScript contradicting this PR's own "zero
client-side JavaScript" claim, and incompatible with a strict CSP that
disallows scripts entirely. Removed rather than carved out an exception:
the CSRF token now also gates this action (an accidental double-submit
without a deliberate page load can't happen the way a lone confirmation
dialog was guarding against), and the claim is now literally
enforced by the CSP, not just true by convention.

**Verified against a live Postgres and the real binaries.** 25 new tests
(19 in `ui.rs` -- including the two XSS-escaping tests, dedicated
CSRF-rejection tests for both the create-sample-request and rotate
actions, and a test confirming the security headers are actually present
on a response rather than just configured -- plus 6 host-listing tests in
`host.rs`) -- full workspace suite now **132 tests**, run twice for
rerun-safety. Live end to end against the real `nsic-console` binary and
`curl` in place of a browser: an unauthenticated request to `/` returns
`401` with a `WWW-Authenticate: Basic` header (confirming a real browser
would be prompted, not shown a bare error); a `GET /hosts` response
carries `Cache-Control: no-store`, a `Content-Security-Policy` blocking
scripts, and `X-Frame-Options: DENY`; a forged cross-site-style POST with
no `csrf_token` field is rejected (`422`, from the form extractor itself)
and one with a wrong token value is rejected (`403`, from `require_csrf`)
-- both confirmed to leave the target host's credential untouched; a
legitimate revoke using the real token extracted from the rendered page
succeeds (`303`) and the credential is then locked out (`401` on
heartbeat); a legitimate rotate using the real token renders the new
credential directly and it authenticates while the old one no longer
does; and the rendered page contains no `onsubmit`/`confirm(` text
anywhere, confirming the removed inline handler is actually gone, not
just removed from one code path. Also re-verified from the prior round:
enrolled a host and confirmed it appears on `/hosts`; created a sample
request through the UI form and confirmed the `303` redirect and the
pending row; fulfilled it via `nsic-agent fulfill-samples` against a real
file and downloaded it back through the UI's download link,
byte-identical via `diff`; and confirmed `host_credential_event`
accumulated both events (`rotated`, then `revoked`) in order, the same
accumulation property PR #12 already established.

### PR #14: sensor health / scan coverage

Flagged as a gap since PR #6: `nsic-agent scan` only ever tells the
console about a *match* -- `report_sightings` is a no-op when nothing
matched, so a clean scan sends nothing at all. That made zero active
YARA rules and zero detections look identical from the console's side:
both are just an absence of sightings for that host. A host that never
scanned anything, or whose rules directory failed to load (an empty or
missing `--rules-dir`, `YaraEngine::load` degrading silently to zero
rules per its own documented behavior), was indistinguishable from a
genuinely clean one -- exactly the "no sightings from host H" ==
"host H is clean" inference the fleet UI was explicitly not allowed to
make until this landed.

**A snapshot on `host`, not an append-only log.** `0008_scan_coverage.sql`
adds five nullable columns -- `last_scan_at`, `last_scan_received_at`,
`last_scan_rule_count`, `last_scan_ruleset_fingerprint`,
`last_scan_matched_count` -- the same "most recent state" shape
`last_heartbeat_at` already has, not the accumulating-history shape
`host_credential_event` uses. The two aren't analogous: a credential
rotation or revocation is a security-relevant event worth a durable
record of *when it happened*, but a scan report is closer to a
heartbeat -- "is the sensor alive and loaded with rules right now,"
where only the latest answer matters. If scan-cadence history over time
becomes a real need later, that's a distinct feature, not something this
PR builds ahead of an actual use for it. (`last_scan_at` and
`last_scan_received_at` are updated conditionally, not unconditionally --
see the review-round writeup below.)

**The agent sends one coverage report per scan invocation,
unconditionally -- separate from, and in addition to, per-match sighting
reports.** `report_scan_coverage` (`crates/agent/src/main.rs`) fires
every time `scan` runs with console reporting configured, whether or not
`matches` is empty; `report_sightings` is unchanged, still a no-op when
there's nothing to report. `POST /api/v1/agents/{host_id}/scans`
(`host::report_scan`), per-agent credential, same as heartbeat and
sightings.

**Validation reuses, rather than reimplements, the sighting endpoint's
timestamp bounds.** `ScanReport::scanned_at` needed the identical
"reject more than 5 minutes in the future, or before 2020-01-01" check
`SightingRequest::observed_at` already had -- rather than a second copy
of that logic in `host.rs`, both constants and the check itself moved
from `sighting.rs` into a new `validate::validate_observed_at`, called
by both `sighting::validate_sighting_request` and
`host::validate_scan_report`. `rule_count`/`matched_count` are validated
non-negative explicitly rather than relying on the wire type (`i32`, not
`u32` -- chosen to match the Postgres `INTEGER` columns directly,
avoiding a cast at the query-binding boundary), consistent with this
codebase's posture of validating at the trust boundary rather than
leaning on a type-level constraint alone.

**Two new JSON fields, not a new endpoint, for reading it back.** Rather
than a separate "sensor health" endpoint, the four coverage columns were
added directly to the existing `HostView`/`GET /api/v1/hosts`/
`GET /api/v1/hosts/{host_id}` (added one PR ago) -- the natural place an
operator or script already looks to answer "what's this host's current
state," not a fact that needed its own read path.

**The fleet UI is where this actually pays off.** A `scan_status_badge`
helper (`ui.rs`) renders one of three states per host: "never scanned"
(no coverage report ever received -- `badge-err`), "0 rules loaded" (a
report was received, but the ruleset was empty -- also `badge-err`,
and deliberately distinguished from "never scanned" rather than lumped
together, since a broken rules directory and a genuinely absent sensor
call for different operator responses), or a healthy badge showing the
last-scan time and rule count. Shown as a column on the fleet directory
and a dedicated "Sensor" section on the host detail page (rule count,
ruleset fingerprint, match count, last-scan time).

**Verified against a live Postgres and the real binaries.** 20 new tests
(10 in `host.rs` covering `report_scan`'s auth, validation, the
zero-matches-still-updates-coverage case, the never-reported-means-all-
fields-None case, and overwrite-not-accumulate semantics across two
reports; 4 in `ui.rs` covering the three badge states and that both the
fleet directory and host detail page surface reported coverage) --
full workspace suite now **145 tests** at the time this PR was opened
(see the review-round writeup below for two more added after review),
run twice for rerun-safety. Live
end to end against the real `nsic-console`/`nsic-agent` binaries:
enrolled a host, scanned a genuinely benign file with console reporting
configured, and confirmed the agent printed "reported scan coverage"
with *no* corresponding sighting -- exactly the case that used to be
silent -- while `GET /api/v1/hosts/{host_id}` and the fleet UI both
showed `last_scan_rule_count: 1`, `last_scan_matched_count: 0`; scanned
an EICAR test string on the same host and confirmed both a coverage
report and a sighting fired, and the host detail page showed both;
enrolled a second host and scanned it with an empty rules directory,
confirming the fleet UI showed "0 rules loaded" specifically, not "never
scanned"; confirmed a third, freshly enrolled host with no scan yet
showed "never scanned"; and confirmed an unauthenticated `POST .../scans`
is rejected (`401`).

**A real test-authoring pitfall, caught and fixed, not just avoided by
luck:** the first draft of the two new fleet-UI badge tests asserted
`!body.contains("never scanned")` against the *entire* fleet directory
page. Since the directory lists every host in this sandbox's persistent,
shared-across-test-runs local Postgres instance, that assertion could
fail depending on which unrelated hosts earlier test runs happened to
leave behind -- a different flakiness shape than the "same fixed sha256
seed accumulates rows" issue PR #6's tests already had to account for,
but the same root cause (a local dev database that persists across runs,
not a fresh one per test). Fixed with `extract_host_row`, which scopes
an assertion to the specific `<tr>` containing the host under test
rather than the whole page.

### PR #14 review round: independent reporting and monotonic scan snapshots

Review on PR #15 (opened for this feature) found two real correctness bugs
in the first draft above, plus one non-blocking provenance suggestion
that was cheap enough to fold in immediately rather than defer.

**Bug: a failed coverage report used to suppress an already-found
sighting.** `Command::Scan`'s original call site awaited
`report_scan_coverage(...)?` immediately before `report_sightings(...)?`
-- an early `?` on the lower-priority telemetry call meant a coverage
POST failing (a network blip, the console briefly down) would abort
the function before the higher-priority sighting report was even
attempted, silently dropping a real detection because of an unrelated
reporting failure. Fixed with a new `report_scan_results`
(`crates/agent/src/main.rs`) that attempts both independently and
propagates the sighting outcome as authoritative, only surfacing the
coverage failure as a `warning:` printed to stderr:
```rust
let coverage_result = report_scan_coverage(...).await;
if let Err(e) = &coverage_result {
    eprintln!("warning: failed to report scan coverage: {e:#}");
}
let sightings_result = report_sightings(...).await;
sightings_result?;
coverage_result?;
```
Verified with a new wiremock-based test,
`a_failed_coverage_report_does_not_prevent_sighting_submission` -- a
mock console returning `500` for `.../scans` but `200` for
`.../sightings`, asserting the sighting POST still landed exactly once.
Confirmed this is a real regression detector, not a vacuous assertion,
by temporarily reverting `report_scan_results` to the original
sequential-with-early-`?` logic, rerunning the test (it failed), and
restoring the fix (it passed again). `wiremock` is new to the agent
crate's dev-dependencies for this -- the agent previously had zero tests
of its own console-talking behavior, only live smoke tests.

**Bug: an out-of-order scan report could regress the stored snapshot.**
`last_scan_at` is agent-claimed (bounds-checked for a 5-minute-future/
2020-01-01 window, not otherwise trusted), unlike `last_heartbeat_at`,
which is always the console's own clock and therefore inherently
monotonic. The original unconditional `UPDATE` treated `last_scan_at`
the same way, so a delayed retry or a race between overlapping scan
invocations could deliver an older `scanned_at` after a newer one was
already recorded, silently regressing the "most recent scan" snapshot an
operator relies on. Fixed by guarding the `UPDATE` in `host::report_scan`
with `WHERE id = $6 AND (last_scan_at IS NULL OR $1 > last_scan_at)` --
a stale report is still authenticated and well-formed, so it still gets
its usual `200`, but the guard silently declines to let it move the
snapshot backwards (no `rows_affected` check needed: zero rows from the
guard not matching is an expected, not an erroneous, outcome, unlike
`set_host_credential`'s use of `rows_affected` to detect an unknown
host). Verified with a new test,
`a_stale_out_of_order_scan_report_does_not_overwrite_a_newer_snapshot`
(submits a report with `scanned_at = now`, then a second with
`scanned_at = now - 1h`, and confirms the stored snapshot still reflects
the first report's values) -- confirmed as a real regression detector the
same way as the agent-side fix, by reverting the `WHERE` clause's guard
back to unconditional, rerunning (it failed), and restoring the fix (it
passed). Live-verified against the real `nsic-console` binary with the
same forward/backward/forward sequence via `curl`, confirming both that
a stale report is silently ignored and that a genuinely newer report
after it still updates the snapshot correctly.

**Provenance suggestion, folded in: `last_scan_received_at`.** Alongside
the agent-claimed `last_scan_at`, `report_scan` now also stores the
console's own clock at write time in a new `last_scan_received_at`
column -- the same "provenance an analyst can compare the claim against"
role `host_sighted_indicator.received_at` already plays for sightings.
Not blocking on its own, but directly strengthens the exact out-of-order
scenario this review round was about, so it went in in the same pass
rather than as a follow-up.

Full workspace suite after this round: **147 tests** (145 from the
original PR, plus the two new regression tests above), run twice for
rerun-safety.

### PR #15: scan staleness alerting

The follow-on gap PR #14 itself named in its own "what's deliberately not
here yet" list: the fleet UI showed *when* a host last scanned, but never
flagged a host whose last scan was old (a week ago, a month ago) as
needing attention -- an operator had to notice the timestamp themselves.

**Computed at read time, not a new column.** `HostView::scan_stale`
(`nsic_core::proto`) is `true` when `last_scan_at` is older than
`AppState::scan_staleness_threshold`, computed fresh against `Utc::now()`
inside `host::host_view_from_row` on every `fetch_all_hosts`/`fetch_host`
call -- no migration, no schema change. A snapshot column would have gone
stale itself the moment enough wall-clock time passed without a write to
refresh it, which would defeat the entire point of a staleness signal;
recomputing on read is the only version of this that stays honest without
a background job. `false` when `last_scan_at` is `None`: "never scanned"
is already its own, worse condition, not a special case of "stale."

**Threshold is configurable, with a documented-as-arbitrary default.**
`NSIC_SCAN_STALENESS_HOURS` (default `DEFAULT_SCAN_STALENESS_HOURS` = 24,
`crates/console/src/main.rs`), parsed and validated (rejects negative
values, fails fast at startup) the same way the bootstrap/operator
secrets and TLS paths already are. 24 hours is a sane ceiling for a fleet
scanned roughly daily via cron or a scheduled task, not derived from any
real workload -- the same "arbitrary but explicit" posture
`MAX_SAMPLE_SIZE_BYTES` already takes elsewhere in this codebase.

**A fourth badge state, not a new page.** `ui::scan_status_badge` (shared
by the fleet directory and host detail page, per PR #14) now renders one
of four states instead of three: "never scanned" and "0 rules loaded"
still take priority when they apply -- each names a strictly worse, more
specific problem than "ran recently enough with rules loaded, just a
while ago" -- followed by "stale (last scan `<time>`, N rules)" in a new
`badge-warn` style (already defined in this file's CSS, previously used
only for a mismatched sample-request status), and finally the existing
healthy badge.

**Surfaced in the JSON API too, not just the UI.** `scan_stale` is a
plain field on `HostView`, so `GET /api/v1/hosts` and
`GET /api/v1/hosts/{host_id}` carry it directly -- a monitoring script
polling the fleet doesn't need to separately know the console's
configured threshold to answer "which hosts need attention," the console
already did that arithmetic.

**Verified against a live Postgres and the real binary.** 5 new tests (3
in `host.rs`/`main.rs` covering a fresh scan reading as not-stale, an
old one reading as stale, and the config validation function; 2 in
`ui.rs` covering the new badge's HTML and that it doesn't fire on a
recent scan) -- full workspace suite now **152 tests**, run twice for
rerun-safety. Both new regression tests (the staleness computation and
the badge rendering) were confirmed as real detectors the same way as
every fix so far this session: reverted `scan_stale`'s computation to a
hardcoded `false`, reran, watched both tests fail, restored the fix,
watched them pass again. Live-verified against the real `nsic-console`
binary with `NSIC_SCAN_STALENESS_HOURS=1`: enrolled a host (never
scanned, `scan_stale: false`), submitted a scan report timestamped two
hours in the past (`scan_stale: true`, fleet UI and host detail page both
showed `badge-warn` "stale (last scan ..., 7 rules)"), then submitted a
fresh report (`scan_stale: false` again, badge back to healthy). Also
confirmed a negative `NSIC_SCAN_STALENESS_HOURS` fails the console at
startup with a clear error rather than starting with a nonsensical
threshold.

## What's deliberately not here yet

- **Scan coverage is per-invocation, not continuous.** PR #14 makes a
  single `nsic-agent scan` call report whether it happened and what it
  found, but the agent is still a one-shot CLI -- there's no scheduled or
  continuous scanning yet, so "sensor health" currently only answers "did
  the last invocation this host was run for succeed," not "is this host
  being scanned on any kind of cadence." That needs the agent to stop
  being one-shot first (see below).
- **Staleness alerting has a fixed, global policy, not a per-host or
  per-fleet-segment one.** PR #15 added `NSIC_SCAN_STALENESS_HOURS`, but
  it's one threshold for every host in the fleet. A deployment mixing
  hosts scanned hourly with ones scanned weekly by design would need a
  per-host or per-group override to avoid false "stale" alerts on the
  slower-cadence hosts; not built since Phase 1 has no such mixed fleet to
  motivate the extra complexity yet.
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
- **TLS is opt-in and mutually exclusive with plain HTTP, not dual-mode.**
  PR #11 added HTTPS support, but a single console process serves either
  plain HTTP or HTTPS on one port, never both at once -- there's no
  automatic HTTP-to-HTTPS redirect or dual-listener setup. An operator
  who wants both would need two console processes on two ports (or a
  proxy in front), not something this PR set out to build.
- **No automatic certificate renewal, no mTLS.** The console loads
  whatever cert/key `NSIC_TLS_CERT_PATH`/`NSIC_TLS_KEY_PATH` point to once
  at startup; rotating a certificate means restarting the process with
  new paths, no ACME/Let's Encrypt integration. TLS as added here also
  only authenticates the *console* to callers -- there's no client
  certificate requirement, so it doesn't replace or strengthen the
  existing bearer-credential model, just stops those credentials
  travelling in plaintext.
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
  sha256 in hand from somewhere; a host directory is its own PR. (An
  unknown `host_id` returning `200` with an empty list rather than `404`
  was reconsidered during review and kept deliberately, for exactly this
  reason -- see PR #7 above.)
- **Real pagination on the PR #7 list endpoints.** Both currently
  `LIMIT 1000`, with a `truncated` flag signaling when a response was cut
  short (see PR #7 above) but still no cursor to actually reach the rows
  past the cap. Fine while no fleet has produced that many sightings for
  one host or hash; not fine indefinitely.
- **Operator-credential rotation.** PR #12 covers the per-agent
  credential; `NSIC_OPERATOR_SECRET` itself still has no rotation flow.
  It's a single static value with no per-row state to update, so
  "rotating" it today just means changing the environment variable and
  restarting the console -- every operator loses access simultaneously,
  there's no staged handoff. It also isn't hashed before comparison
  (unlike per-agent credentials) -- there's nothing per-row to hash it
  against.
- **Operator identity is a single shared secret, not per-user.** Every
  holder of `NSIC_OPERATOR_SECRET` looks identical to the console --
  there's no way to tell which analyst issued a given read, let alone
  restrict what any individual analyst can see. Fine for one operator
  running this locally; a real multi-user fleet UI needs per-user
  identity and RBAC before this credential model is adequate for it.
- **`sample_request.host_id` is `ON DELETE CASCADE`, which deletes the
  audit trail along with the host.** For a table that's explicitly the
  audit log locked architecture decision #3 requires (see PR #8/#9),
  losing that history the moment a host row is deleted is a real
  tension -- but there's no host deletion/decommissioning workflow yet
  for it to matter in practice. Needs a retention-safe strategy (soft-
  deleting hosts, or changing the FK behavior so retrieval history
  outlives the host record) before deletion becomes a supported
  operation, not before.
- **`SightingView.sha256` assumes every indicator is a sha256.** True
  today (`SightingRequest` only ever carries a sha256, per PR #6), so the
  read side mirrors that narrowness rather than generalizing ahead of
  need. Once a non-sha256 indicator kind can produce a sighting, this
  field needs to become something like a `(kind, value)` pair instead of
  assuming the one kind that exists right now.
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
- **No encryption at rest for stored sample content.** `sample_blob.
  content` sits in Postgres as plain `BYTEA` -- raw malware bytes,
  unencrypted, readable by anyone with database access. Consistent with
  everything else in Phase 1 not being hardened yet (no TLS in transit
  either), but a real gap once this holds actual malicious samples
  rather than test fixtures.
- **No retention or TTL policy for sample content.** Nothing ever deletes
  a `sample_blob` row; storage grows unbounded as samples accumulate.
  Fine for early testing, not for a long-running console.
- **`MAX_SAMPLE_SIZE_BYTES` (100 MiB) is arbitrary and untested at the
  boundary.** Chosen as a documented, sane-sounding ceiling for storing
  raw bytes directly in Postgres, not derived from any real workload;
  verified by code review that the `DefaultBodyLimit` layer and the
  redundant in-handler check are both present and correct, not by
  actually uploading something at or past the limit (see PR #8 above).
- **Sample-request read/write share the same operator-RBAC gap sightings
  already have.** Every holder of `NSIC_OPERATOR_SECRET` can request a
  file from any host and see every request's status and outcome; there's
  no per-user identity or audit trail beyond "the operator, as a whole"
  did this. Same deferred item PR #7 logged for sighting reads, now also
  true of sample requests.
- **The fleet UI's CSRF token is a single per-process value, not
  per-user or rotatable without a restart.** PR #13's three POST actions
  are protected by `AppState::csrf_token` (see PR #13 above for why one
  unrotated value is sufficient against the actual threat it defends
  against). What it doesn't provide: per-analyst attribution of who took
  a given action (the same single-shared-operator-identity gap logged
  above for the read side), or a way to invalidate the token without
  restarting the console. Neither matters yet for Phase 1's
  single-operator framing; both would matter for a real multi-analyst
  deployment.
- **No indicator-centric pivot view in the fleet UI.** PR #7's
  `GET /api/v1/indicators/{sha256}/sightings` (which hosts have sighted a
  given hash) has no UI page yet -- the fleet UI only pivots the other
  direction, host to its sightings. Straightforward to add the same way
  once there's a real need for it.
- **Plugin/scripting support.** Nothing here today, but nothing here
  needs to be built for the near-term case either: `crates/console`'s
  JSON API (operator-credential, documented throughout this file) is
  already usable from any scripting language, Python included, with
  nothing more than an HTTP client -- a Python script driving bulk sample
  requests, enrichment, or custom triage logic works today with zero new
  engineering. What doesn't exist is a *formal* plugin system (the
  console itself discovering, loading, and calling into plugin code as
  part of handling a request) -- that's a real design effort, most
  commonly done as external subprocesses over a stdio/JSON protocol
  rather than an embedded interpreter, since embedding one (e.g. Python
  via `pyo3`) would mean shipping a language runtime and giving up the
  "single static Rust binary, no runtime dependencies" property this
  project has protected everywhere else (no GTK for `crates/console`, no
  Node/npm, see PR #13 above). Worth designing deliberately once a
  concrete use case is pulling for it, not before.
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
`0004_host_credential.sql` and `0008_scan_coverage.sql`): id, hostname,
os, agent_version, `credential_hash` (SHA-256 hex of the per-agent
credential, `NOT NULL` -- or one of two sentinel strings that can never
match a real hash, marking a pre-credential legacy host or an explicitly
revoked one; see PR #12 above), enrolled_at, last_heartbeat_at,
`last_scan_at`/`last_scan_received_at`/`last_scan_rule_count`/
`last_scan_ruleset_fingerprint`/`last_scan_matched_count` (all nullable,
all `NULL` together until the host's agent reports its first scan;
overwritten -- not accumulated -- on every subsequent report whose
`scanned_at` is strictly newer than what's already stored, so a stale
or out-of-order report can't regress the snapshot; see PR #14 above).
`HostView::scan_stale` (PR #15 above) is *not* a column here -- it's
computed at read time from `last_scan_at` against the console's
configured staleness threshold, so it can't itself go stale between
writes. Additive to the Phase 0
schema in `0001_init.sql` / `0002_verdict_indexes.sql`, not a redesign of
it.

`host_credential_event` (`src-tauri/migrations/
0007_credential_rotation.sql`): an append-only log of `rotate`/`revoke`
events against a host's credential, added by PR #12 specifically because
a single overwritten column on `host` would have lost this history on
every subsequent call (see PR #12 above). `id`, `host_id` (`ON DELETE
CASCADE`, same tension already logged for `sample_request.host_id`
below), `event_type` (`'rotated'` or `'revoked'`), `occurred_at`.

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

`sample_blob` (`src-tauri/migrations/0006_sample_request.sql`): `sha256`
(primary key -- content-addressed, the same convention `indicator`
already uses, so identical content retrieved from two hosts is stored
once), `content` (`BYTEA`, the raw bytes), `size_bytes`, `stored_at`.

`sample_request` (same migration): one row per analyst request to pull a
specific file off a specific host -- the audit trail locked architecture
decision #3 requires. `id`, `host_id`, `path` (as requested, not
verified against anything until an agent responds), `expected_sha256`
(nullable -- set when the analyst already knows the hash they're
expecting), `status` (`pending` / `fulfilled` / `mismatched` / `failed`),
`failure_reason` (set only on `failed`), `sha256` (nullable until
resolved, references `sample_blob` once it is), `requested_at`,
`resolved_at` (nullable until resolved). Not an edge in the intel graph
like `host_sighted_indicator` -- a sample request isn't a fact about an
indicator, it's a workflow record with its own lifecycle.

## Running it locally

```bash
docker compose up -d                       # Postgres, same as Phase 0
export DATABASE_URL=postgres://nsic:nsic@localhost:5432/nsic
export NSIC_ENROLLMENT_SECRET=dev-secret   # pick anything for local testing
export NSIC_OPERATOR_SECRET=dev-operator-secret  # ditto -- gates the read endpoints below
export NSIC_SCAN_STALENESS_HOURS=24        # optional, this is the default -- see PR #15 below

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
# -> (same JSON as above, then, always:)
# -> reported scan coverage: received_at=...
# -> (then, only if something matched:)
# -> reported sighting: indicator_id=<uuid> rule=<rule name>

curl -H "Authorization: Bearer $NSIC_OPERATOR_SECRET" \
  http://localhost:8787/api/v1/hosts
# -> {"hosts": [{"id": "...", "hostname": "...", "os": "...",
#     "agent_version": "...", "enrolled_at": "...", "last_heartbeat_at": "...",
#     "last_scan_at": "...", "last_scan_received_at": "...",
#     "last_scan_rule_count": 1, "last_scan_ruleset_fingerprint": "...",
#     "last_scan_matched_count": 0, "scan_stale": false}], "truncated": false}
curl -H "Authorization: Bearer $NSIC_OPERATOR_SECRET" \
  http://localhost:8787/api/v1/hosts/<uuid>
# -> {"id": "...", "hostname": "...", ...}  -- same shape, one host
# -> last_scan_at is null until the agent's first scan-coverage report;
#    the fleet UI's "/hosts" and "/hosts/<uuid>" pages render this as a
#    "never scanned" / "0 rules loaded" / "stale" / healthy badge, see
#    PR #14 and PR #15 above. scan_stale is computed fresh on every
#    request against NSIC_SCAN_STALENESS_HOURS, not stored.

curl -H "Authorization: Bearer $NSIC_OPERATOR_SECRET" \
  http://localhost:8787/api/v1/hosts/<uuid>/sightings
curl -H "Authorization: Bearer $NSIC_OPERATOR_SECRET" \
  http://localhost:8787/api/v1/indicators/<sha256>/sightings
# -> {"sightings": [{"host_id": "...", "hostname": "...", "sha256": "...",
#     "detection_name": "...", "source": "agent:yara_scan", "confidence": 65,
#     "path": "...", "ruleset_fingerprint": "...", "first_seen": "...",
#     "last_seen": "...", "received_at": "..."}], "truncated": false}

curl -X POST -H "Authorization: Bearer $NSIC_OPERATOR_SECRET" \
  -H "Content-Type: application/json" \
  -d '{"path": "/path/on/the/host", "expected_sha256": null}' \
  http://localhost:8787/api/v1/hosts/<uuid>/sample-requests
# -> {"request_id": "<uuid>"}

cargo run -p agent --bin nsic-agent -- fulfill-samples \
  --console-url http://localhost:8787 --host-id <uuid> --credential <token>
# -> fulfilled sample request <uuid>: path=... status=Fulfilled sha256=... size_bytes=...
# -> (or, if the path doesn't exist on this host:)
# -> reported failure for sample request <uuid>: path=... reason=...

curl -H "Authorization: Bearer $NSIC_OPERATOR_SECRET" \
  http://localhost:8787/api/v1/hosts/<uuid>/sample-requests
# -> {"requests": [{"id": "...", "host_id": "...", "path": "...",
#     "expected_sha256": null, "status": "fulfilled", "failure_reason": null,
#     "sha256": "...", "size_bytes": ..., "requested_at": "...",
#     "resolved_at": "..."}], "truncated": false}

curl -o retrieved-sample.bin -H "Authorization: Bearer $NSIC_OPERATOR_SECRET" \
  http://localhost:8787/api/v1/hosts/<uuid>/sample-requests/<request-uuid>/content
# -> (raw bytes, Content-Type: application/octet-stream)

curl -o retrieved-sample.bin -H "Authorization: Bearer $NSIC_OPERATOR_SECRET" \
  http://localhost:8787/api/v1/samples/<sha256>/content
# -> same content, looked up by hash instead of by request

curl -X POST -H "Authorization: Bearer $NSIC_OPERATOR_SECRET" \
  http://localhost:8787/api/v1/hosts/<uuid>/credential/rotate
# -> {"credential": "<new-token>"}  -- old credential stops working immediately

curl -X POST -H "Authorization: Bearer $NSIC_OPERATOR_SECRET" \
  http://localhost:8787/api/v1/hosts/<uuid>/credential/revoke
# -> 200, empty body -- host locked out until an operator rotates it a new one
```

`--enrollment-secret` and `--credential` both fall back to
`NSIC_ENROLLMENT_SECRET` / `NSIC_AGENT_CREDENTIAL` if omitted. The
sighting- and sample-request-list endpoints, both download endpoints, and
the credential rotate/revoke endpoints have no dedicated CLI command yet
-- `curl` (or any HTTP client) with the operator credential as a bearer
token, as above.

### Running it locally, with TLS

```bash
# Generate a self-signed cert for local testing -- a real deployment
# should use a certificate from a real or internal CA instead.
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout console-key.pem -out console-cert.pem \
  -days 365 -subj "/CN=localhost"

export NSIC_TLS_CERT_PATH="$PWD/console-cert.pem"
export NSIC_TLS_KEY_PATH="$PWD/console-key.pem"
cargo run -p console --bin nsic-console &
# -> console listening on 127.0.0.1:8787 (HTTPS)

# The agent needs to be told to trust this cert, since it isn't signed
# by a public CA -- every subcommand below accepts --tls-ca-cert
# (or NSIC_TLS_CA_CERT), added *alongside* the normal system CA store,
# never a flag that skips verification.
cargo run -p agent --bin nsic-agent -- enroll \
  --console-url https://localhost:8787 --hostname "$(hostname)" \
  --enrollment-secret "$NSIC_ENROLLMENT_SECRET" \
  --tls-ca-cert "$PWD/console-cert.pem"

curl --cacert console-cert.pem \
  -H "Authorization: Bearer $NSIC_OPERATOR_SECRET" \
  https://localhost:8787/api/v1/hosts/<uuid>/sightings
```

Omitting both `NSIC_TLS_CERT_PATH` and `NSIC_TLS_KEY_PATH` (the default)
runs the console over plain HTTP exactly as shown above; setting only one
of the two fails the console at startup rather than silently running
without TLS.

### Running it locally, with the fleet UI

With the console running (either plain HTTP or TLS, as above), point a
browser at it directly -- no separate build step, no `npm install`:

```
http://localhost:8787/
```

The browser will prompt for credentials (HTTP Basic) the first time a
page under the operator's control is loaded; leave the username blank
and enter `$NSIC_OPERATOR_SECRET` as the password. From there:

- `/` and `/hosts` -- every enrolled host, linked through to its detail
  page.
- `/hosts/<uuid>` -- that host's metadata, sightings, and sample
  requests, plus three forms: request a sample, rotate the host's
  credential, revoke it.
- Sample content download links appear next to any request that
  resolved to `fulfilled` or `mismatched`.

The same thing with `curl` standing in for a browser (useful for
scripting or for confirming the UI is reachable without a GUI). GET
requests need nothing beyond the operator credential; every POST also
needs the console's CSRF token, which isn't a secret an operator
configures -- it's generated once at startup and only ever shows up
embedded as a hidden field in the UI's own rendered forms, so pulling it
out of the page is the only way to get it (this is the point: an
attacker's cross-origin page has no way to read it either):

```bash
curl -u ":$NSIC_OPERATOR_SECRET" http://localhost:8787/hosts
curl -u ":$NSIC_OPERATOR_SECRET" http://localhost:8787/hosts/<uuid>

TOKEN=$(curl -s -u ":$NSIC_OPERATOR_SECRET" http://localhost:8787/hosts/<uuid> \
  | grep -oP 'name="csrf_token" value="\K[a-f0-9]+' | head -1)

curl -u ":$NSIC_OPERATOR_SECRET" -X POST \
  -d "path=/path/on/the/host&expected_sha256=&csrf_token=$TOKEN" \
  http://localhost:8787/hosts/<uuid>/sample-requests
curl -u ":$NSIC_OPERATOR_SECRET" -X POST \
  -d "csrf_token=$TOKEN" \
  http://localhost:8787/hosts/<uuid>/credential/rotate
```

`crates/agent` and `crates/console` do not need the WebKitGTK/GTK system
libraries `src-tauri` requires on Linux (`libwebkit2gtk-4.1-dev` etc.);
they're plain Rust binaries. `crates/nsic-core` needs nothing beyond a
Rust toolchain by default; the `db` feature needs the same Postgres
driver `src-tauri` already needs, and the `yara-scan` feature needs
`libyara-dev` (also already required by `src-tauri`). `crates/agent`
enables `yara-scan` (for `scan`) but not `db`; `crates/console` enables
`db` but not `yara-scan` — neither links what it doesn't use.
