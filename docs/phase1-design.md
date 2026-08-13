# Phase 1 design: agent plus console

Status: enrollment and heartbeat are authenticated end to end; most of the
phase is still not built. This document tracks what Phase 1 actually is,
what's landed so far, and what's deliberately deferred, in the same spirit
as the README's Phase 0 "what works today / what's stubbed" split.

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
3. **PR #5 (not started) — local YARA on the agent.** Give the agent
   something meaningful to observe. Depends on #4 existing so what it
   observes can eventually be attributed to a specific, authenticated
   host.
4. **PR #6 (not started) — sighting protocol.** Securely report those
   observations: "host X observed indicator Y," as an authenticated
   `/api/v1/.../sightings` endpoint and a new graph edge. Depends on both
   #4 (who's reporting) and #5 (what there is to report).
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

## What's deliberately not here yet

- **Local YARA scanning on the agent** (PR #5). `src-tauri/src/
  yara_scan.rs` is already DB-free and the candidate to move into
  `nsic-core` next to `hashing`.
- **Verdict / sighting submission** (PR #6). The agent doesn't send
  anything about what it finds yet, only that it exists and is alive
  (and, as of PR #4, that it can prove which host it is). The next real
  payload is "host X saw indicator Y," which needs a `sighting` edge in
  the intel graph (host <-> indicator, with source/confidence/
  first-last-seen, same pattern as every other edge in `0001_init.sql`),
  plus deduplication/idempotency and batching semantics — none of that is
  designed yet.
- **Transport security.** Still HTTP, not HTTPS. Both the bootstrap
  secret and per-agent credential cross the wire in plaintext today. Real
  TLS (or at minimum a documented "put this behind a VPN/reverse proxy
  for now") is required before this talks to a real fleet.
- **Credential rotation and revocation.** A compromised or decommissioned
  host's credential can't currently be invalidated short of deleting its
  `host` row outright. No rotation flow exists either.
- **Rate limiting on `/api/v1/agents/enroll`.** The bootstrap secret is a
  single shared value; nothing currently throttles guesses against it.
- **Bootstrap-secret strength enforcement.** `NSIC_ENROLLMENT_SECRET` is
  taken as-is; the console doesn't reject a short or weak value. Fine for
  local testing, not before a real deployment.
- **Protected agent-side credential persistence.** The CLI prints the
  per-agent credential and leaves storing it to the caller; there's no
  agent-managed credential file (with correct permissions, per OS) yet.
  That needs a design once the agent stops being a one-shot CLI and
  becomes a persistent process sending authenticated telemetry (PR #6 and
  after) — storing a long-lived credential insecurely at that point is a
  real vulnerability, not just a rough edge.
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
`0001_init.sql` / `0002_verdict_indexes.sql`, not a redesign of it. The
next data-model addition, once PR #6 designs sighting submission, is an
edge table between `host` and `indicator`.

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
```

`--enrollment-secret` and `--credential` both fall back to
`NSIC_ENROLLMENT_SECRET` / `NSIC_AGENT_CREDENTIAL` if omitted.

`crates/agent` and `crates/console` do not need the WebKitGTK/GTK system
libraries `src-tauri` requires on Linux (`libwebkit2gtk-4.1-dev` etc.);
they're plain Rust binaries. `crates/nsic-core` needs nothing beyond a
Rust toolchain unless built with the `db` feature, which needs the same
Postgres driver `src-tauri` already needs.
