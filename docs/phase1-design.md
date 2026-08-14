# Phase 1 design: agent plus console

Status: enrollment, heartbeat, sighting submission, reading sightings back
out, and sample retrieval's write path (request + agent fulfillment) are
all authenticated end to end; most of the phase is still not built. This
document tracks
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
8. **Later, not started:** reading sample content back out, fleet UI,
   TLS/deployment hardening.

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
  sha256 in hand from somewhere; a host directory is its own PR. (An
  unknown `host_id` returning `200` with an empty list rather than `404`
  was reconsidered during review and kept deliberately, for exactly this
  reason -- see PR #7 above.)
- **Real pagination on the PR #7 list endpoints.** Both currently
  `LIMIT 1000`, with a `truncated` flag signaling when a response was cut
  short (see PR #7 above) but still no cursor to actually reach the rows
  past the cap. Fine while no fleet has produced that many sightings for
  one host or hash; not fine indefinitely.
- **Operator-credential rotation.** Same gap as per-agent credentials
  below, for the new `NSIC_OPERATOR_SECRET`: it's a single static value
  with no rotation flow, and (unlike per-agent credentials) isn't even
  hashed before comparison -- there's nothing per-row to hash it against.
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
- **Reading retrieved sample content back out.** PR #8 covers requesting
  and fulfilling; there's no endpoint that returns a retrieved sample's
  actual bytes to an operator yet -- `SampleRequestView` deliberately
  never carries `sample_blob.content`. The same write-then-read split #6
  and #7 went through for sightings; the operator-facing "list requests
  and their status" endpoint already exists (PR #8), only "download the
  bytes" is missing.
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
```

`--enrollment-secret` and `--credential` both fall back to
`NSIC_ENROLLMENT_SECRET` / `NSIC_AGENT_CREDENTIAL` if omitted. The
sighting- and sample-request-list endpoints have no dedicated CLI command
yet -- `curl` (or any HTTP client) with the operator credential as a
bearer token, as above. There is no command to download a retrieved
sample's actual content yet either (see "What's deliberately not here
yet").

`crates/agent` and `crates/console` do not need the WebKitGTK/GTK system
libraries `src-tauri` requires on Linux (`libwebkit2gtk-4.1-dev` etc.);
they're plain Rust binaries. `crates/nsic-core` needs nothing beyond a
Rust toolchain by default; the `db` feature needs the same Postgres
driver `src-tauri` already needs, and the `yara-scan` feature needs
`libyara-dev` (also already required by `src-tauri`). `crates/agent`
enables `yara-scan` (for `scan`) but not `db`; `crates/console` enables
`db` but not `yara-scan` — neither links what it doesn't use.
