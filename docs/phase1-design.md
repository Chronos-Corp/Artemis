# Phase 1 design: agent plus console

Status: enrollment, heartbeat, and sighting submission are authenticated
end to end; most of the phase is still not built. This document tracks
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
5. **Later, not started:** sample retrieval, fleet UI, TLS/deployment
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
  proto`) is `{ sha256, detection_name, path: Option<String>,
  observed_at }` — exactly what `nsic-agent scan` produces today, not a
  generic multi-indicator-kind sighting. Generalizing (a `kind` field,
  non-YARA detection types) is deferred until something other than local
  YARA scanning produces a sighting — Phase 0's still-unpopulated tier 2
  (fuzzy hashing) would be the next candidate.
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
  `host_sighted_indicator` edge (which host, specifically, saw it, and
  from where — see Data model below).
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
- **Idempotency.** `PRIMARY KEY (host_id, indicator_id, source)` on
  `host_sighted_indicator` — resubmitting the same sighting is an upsert,
  not a duplicate row. `first_seen` takes `LEAST`, `last_seen` takes
  `GREATEST` (the exact pattern every other edge in `0001_init.sql`
  already uses); `path` is always overwritten with the latest reported
  value ("last seen at" is the useful semantic, not "first seen at").
- **Batching is out of scope.** One HTTP request per (indicator,
  detection) pair; the agent loops client-side if a single scan matches
  multiple rules. `nsic-agent scan` still only scans one file per
  invocation, so there's nothing to batch yet — revisit once the agent
  does bulk or continuous scanning.
- **`nsic-agent scan`** gained `--console-url` / `--host-id` /
  `--credential` (env fallbacks `NSIC_CONSOLE_URL` / `NSIC_HOST_ID` /
  `NSIC_AGENT_CREDENTIAL`); if all three are given and the scan found any
  matches, each is reported as a sighting after the local JSON is
  printed. Given none of them, `scan` behaves exactly as it did in PR #5.
  Given some but not all, the agent prints a warning and skips
  reporting rather than silently doing nothing or guessing.
- Tests (`crates/console/src/sighting.rs`, DB-backed, `--ignored`):
  missing/forged credential, unknown `host_id`, and a combined happy-path
  test that submits the same sighting twice with different
  `observed_at` values and asserts against the database directly that
  `first_seen`/`last_seen` follow `LEAST`/`GREATEST`, exactly one edge
  row exists (not two), and `detection_detects_indicator` was populated
  too.

## What's deliberately not here yet

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
- **Reading sightings back out.** PR #6 only writes; there's no endpoint
  or query to list what's been reported for a host, a hash, or a rule.
  The data is in the same Postgres graph `src-tauri`'s verdict engine
  already queries, so it's reachable by hand, just not through any
  Phase 1-specific API yet.
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
0005_host_sighted_indicator.sql`): the host<->indicator edge PR #6 adds.
`host_id`, `indicator_id`, `source`, `confidence`, `path` (nullable,
always overwritten with the latest value), `first_seen`, `last_seen`,
primary keyed on `(host_id, indicator_id, source)` -- same edge shape as
every other edge in `0001_init.sql`, just between a host and an
indicator instead of, say, a report and an indicator.

## Running it locally

```bash
docker compose up -d                       # Postgres, same as Phase 0
export DATABASE_URL=postgres://nsic:nsic@localhost:5432/nsic
export NSIC_ENROLLMENT_SECRET=dev-secret   # pick anything for local testing

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
# -> {"path": "...", "rules_dir": "yara-rules", "rule_count": 1, "matches": [...]}

cargo run -p agent --bin nsic-agent -- scan path/to/file --rules-dir yara-rules \
  --console-url http://localhost:8787 --host-id <uuid> --credential <token>
# -> (same JSON as above, then, for each match:)
# -> reported sighting: indicator_id=<uuid> rule=<rule name>
```

`--enrollment-secret` and `--credential` both fall back to
`NSIC_ENROLLMENT_SECRET` / `NSIC_AGENT_CREDENTIAL` if omitted.

`crates/agent` and `crates/console` do not need the WebKitGTK/GTK system
libraries `src-tauri` requires on Linux (`libwebkit2gtk-4.1-dev` etc.);
they're plain Rust binaries. `crates/nsic-core` needs nothing beyond a
Rust toolchain by default; the `db` feature needs the same Postgres
driver `src-tauri` already needs, and the `yara-scan` feature needs
`libyara-dev` (also already required by `src-tauri`). `crates/agent`
enables `yara-scan` (for `scan`) but not `db`; `crates/console` enables
`db` but not `yara-scan` — neither links what it doesn't use.
