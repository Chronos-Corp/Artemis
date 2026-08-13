# Phase 1 design: agent plus console

Status: scaffolding landed, most of the phase not yet built. This document
tracks what Phase 1 actually is, what the first PR contains, and what's
deliberately deferred, in the same spirit as the README's Phase 0
"what works today / what's stubbed" split.

Per the README's build order, Phase 1 is: agent plus console, file-to-IOC
across a fleet, sample retrieval. That's a lot; this document exists so
each PR against it has a shared map instead of improvising scope.

## What this first PR contains

- **`crates/nsic-core`**: the pure, DB-free file hashing (`compute_hashes`)
  and the intel-graph vocabulary (`IndicatorKind`, `DetectionKind`,
  `VerdictTier`, `ProvenanceEntry`, `Verdict`) extracted out of
  `src-tauri`, so the agent can depend on exactly the same digest logic and
  types without linking Tauri or, by default, Postgres. A `db` feature
  (off by default) adds `connect_and_migrate`, shared by `src-tauri` and
  `crates/console` so they can never drift onto separate schemas.
- **`crates/agent`**: a CLI binary (`nsic-agent`) with three subcommands:
  `hash <path>` (local, no network), `enroll --console-url --hostname`,
  and `heartbeat --console-url --host-id`. No local YARA scanning, no
  verdict submission, no file monitoring. It proves the wire plumbing
  end to end and nothing more.
- **`crates/console`**: an HTTP service (`nsic-console`, axum) with
  `POST /agents/enroll` and `POST /agents/{host_id}/heartbeat`, backed by a
  new `host` table (`src-tauri/migrations/0003_hosts.sql`) in the same
  Postgres instance `src-tauri` already uses.

Everything here is single-machine-testable: run the console, enroll one
agent against it locally, heartbeat it. There is no fleet yet, just the
two ends of a wire talking to each other correctly.

## What's deliberately not here yet

- **Authentication.** `EnrollRequest` carries no pre-shared secret;
  `EnrollResponse` returns a bare `host_id`, not an issued credential.
  Anyone who can reach the console can enroll a host and heartbeat as any
  existing one. This is fine for a scaffold nobody points at a real
  network; it is a hard blocker before Phase 1 goes further. The shape is
  already anticipated in the schema (`host.enrollment_token_hash`, unused
  so far) — next step is the console minting a bearer credential at
  enroll time and every subsequent request (heartbeat, and later event
  submission) requiring it. That credential has to be a distinct concern
  from *authorizing the enrollment itself* — an arbitrary client being
  able to complete enrollment and walk away with a legitimate agent
  identity is the same gap by another name, so bootstrap authorization
  (who's allowed to enroll at all) and per-agent credentials (what an
  already-enrolled agent presents afterward) need separate designs, not
  one token doing both jobs.
- **Transport security.** HTTP, not HTTPS. Fine for localhost testing,
  not for anything crossing a real network. The console's default bind is
  loopback-only (`127.0.0.1:8787`) precisely because of this; reaching it
  from another host requires deliberately overriding `NSIC_CONSOLE_ADDR`.
- **Protocol versioning.** `/agents/enroll` and `/agents/{id}/heartbeat`
  are unversioned. Once sighting submission, rule sync, or sample
  retrieval start expanding this API, it needs a `/api/v1/...` prefix
  (or equivalent) before this scaffold's two routes calcify into an
  unversioned surface everything else has to stay compatible with.
  `agent_version` (already in the wire types) is a separate concern from
  protocol version and should stay that way.
- **Local YARA scanning on the agent.** `src-tauri/src/yara_scan.rs` is
  already DB-free and a good candidate to move into `nsic-core` next to
  `hashing`, once the agent actually needs to run rule matches locally
  instead of just computing hashes.
- **Verdict / sighting submission.** The agent doesn't send anything
  about what it finds yet, only that it exists and is alive. The next
  real payload is "host X saw indicator Y," which needs a `sighting` edge
  in the intel graph (host <-> indicator, with source/confidence/
  first-last-seen, same pattern as every other edge in
  `0001_init.sql`) — not designed yet.
- **Sample retrieval.** Locked architecture decision #3: file contents
  leave the host only on explicit analyst request, logged and attributed.
  No part of that request/audit flow exists yet.
- **Fleet console UI.** No frontend for any of this; `crates/console` is
  API-only.
- **Windows-specific agent internals.** USN journal, Amcache, etc. are
  Phase 4 territory per the README and untouched here. The current agent
  is intentionally cross-platform-trivial (it hashes a file and speaks
  HTTP) so Phase 1's wire protocol and data model can be proven before any
  platform-specific collection logic gets added on top.
- **Migrations still live under `src-tauri/migrations/`.** That predates
  this crate split and `nsic-core::db::connect_and_migrate` points there
  by relative path (see `crates/nsic-core/src/db.rs`) purely to avoid
  disturbing `src-tauri`'s existing sqlx offline query cache and CI steps
  in this PR. Longer-term the migrations directory should move to a
  location that isn't nested inside the Phase 0 desktop app, since the
  console now owns and runs them just as much as `src-tauri` does.

## Data model addition

One new table, `host` (`src-tauri/migrations/0003_hosts.sql`): id,
hostname, os, agent_version, enrollment_token_hash (unused for now),
enrolled_at, last_heartbeat_at. This is additive to the Phase 0 schema in
`0001_init.sql` / `0002_verdict_indexes.sql`, not a redesign of it. The
next data-model addition, once sighting submission is designed, is an
edge table between `host` and `indicator` — deliberately not started here.

## Why enroll/heartbeat first, not something more useful

Matches the README's own logic for why folder correlation scoring waits
for Phase 3: building sighting submission, sample retrieval, or a fleet UI
before the enrollment plumbing is proven correct is building on sand. This
PR's job is narrow: confirm the agent and console can be two genuinely
separate deployable artifacts (the agent has no Postgres dependency, no
GTK dependency, nothing Tauri needs) that agree on a schema and a wire
protocol, before anything depends on that being true.

## Running it locally

```bash
docker compose up -d                       # Postgres, same as Phase 0
export DATABASE_URL=postgres://nsic:nsic@localhost:5432/nsic

cargo run -p console --bin nsic-console &  # listens on :8787 by default

cargo run -p agent --bin nsic-agent -- enroll \
  --console-url http://localhost:8787 --hostname "$(hostname)"
# -> enrolled: host_id=<uuid>

cargo run -p agent --bin nsic-agent -- heartbeat \
  --console-url http://localhost:8787 --host-id <uuid>
# -> heartbeat ok: received_at=...
```

`crates/agent` and `crates/console` do not need the WebKitGTK/GTK system
libraries `src-tauri` requires on Linux (`libwebkit2gtk-4.1-dev` etc.);
they're plain Rust binaries. `crates/nsic-core` needs nothing beyond a
Rust toolchain unless built with the `db` feature, which needs the same
Postgres driver `src-tauri` already needs.
