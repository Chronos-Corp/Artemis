# 4NSIC

DFIR triage and threat hunting tool -- codenamed **Apollo**, the first
committed product of the Chronos Corp portfolio thesis. See
[`docs/apollo-constitution.md`](docs/apollo-constitution.md) for the
product-level source of truth on what Apollo is, what it isn't, and what's
still genuinely open (and
[`docs/chronos-constitution.md`](docs/chronos-constitution.md) for the
company-level thesis it sits under); this README covers the technical
state of the repo, kept consistent with those documents rather than
repeating them. "4NSIC" is this repo's working name and shows up in the
crate names (`nsic-core`/`nsic-agent`/`nsic-console`); "Apollo" is the
product name.

**Apollo's non-negotiable product promise:** selecting a file should
progressively answer what it is, what it's for, whether it's expected here,
and whether it's related to known IOCs, CVEs, APTs, campaigns, malware, or
other risk-based threats. Selecting one of those relationships should let
an analyst hunt the chosen recursive scope for associated evidence, then
see what the combined evidence means. File &rarr; understand &rarr; relate
&rarr; pivot &rarr; hunt &rarr; explain. An analyst-facing correlation
layer that sits alongside existing EDR, not a replacement for it -- EDR
tells you a file is bad, Apollo tells you which campaign it belongs to,
which CVE it relates to, and what else on the host clusters with it.

## Current phase: Phase 0, with Phase 1 scaffolding underway

Phase 0 is a single-machine desktop app: no agent, no server, no fleet.
This proves the file-manager-with-verdicts UX on one box using abuse.ch
feeds (MalwareBazaar, ThreatFox) and local YARA. See "Build order" below
for what comes next.

Phase 1 (agent plus console) has an initial scaffold in `crates/` --
authenticated enrollment, heartbeat, and sighting-submission plumbing;
the agent can run local YARA scans and report matches to the console. See
[`docs/phase1-design.md`](docs/phase1-design.md).

What works today:

- File manager: browse directories, select a file.
- Verdict engine: hashes the file (cached by path + size + mtime), checks a
  local bloom filter of known-bad hashes, runs a local YARA pass, and checks
  path-pattern and contextual signals. Every match is returned with its
  tier, source, and confidence; nothing collapses to a boolean. Every
  verdict also carries per-source intel freshness (`last_successful_sync_at`
  for each configured feed), so an empty result is distinguishable from "no
  intel source has synced recently enough to trust this" -- an absence of
  matches against an 11-day-stale feed is not the same fact as an absence
  of matches against a feed that synced 18 minutes ago, and the UI now
  shows the difference instead of only hedging about it in prose.
- Intel graph in Postgres: Indicator / Report / CVE / Actor / Detection
  nodes with source, confidence, and first/last-seen on the edges, so the
  same hash arriving from multiple feeds with different confidence is
  preserved instead of flattened.
- Feed ingestion: MalwareBazaar and ThreatFox recent submissions, folded
  into the graph with provenance back to the source report.
- **File Intelligence Model (PR #18).** Every selected file also gets a
  File Intelligence Object (`get_file_intelligence`, `src-tauri/src/file_intel.rs`)
  -- identity (content-sniffed file type, not just extension; hidden/
  executable/symlink flags; timestamps), authenticity (package-manager
  checksum verification against the file's install-time record, keyed to
  the *selected* path -- a symlink never inherits its target's package
  identity), product context (owning package/version), purpose (the
  package's real short description when one exists, worded explicitly as
  package-level rather than claiming Apollo identified this specific
  file's individual role), expectedness (a rollup with explicit reasons --
  checksum mismatch always wins; a same-directory masquerading check for
  near-miss filenames like `svch0st.exe` beside `svchost.exe` is treated
  as weak contextual evidence that cannot override a Verified checksum,
  since legitimate tool families like `mount`/`umount` genuinely sit
  within a small edit distance of each other), and local context. This
  answers "what is this file and what's it for," independent of
  `get_verdict`'s "is this file threat-relevant" -- see Apollo
  Constitution &sect;5. v1 package-manager support is dpkg-only
  (Debian/Ubuntu); other platforms report authenticity as `unknown`
  rather than guessing -- see the module doc comment. Deliberately does
  not touch Postgres at all, so it keeps working even when the intel
  database is unreachable.
- **Threat Relationship Model (PR #19).** `get_verdict` now also returns
  `threat_relationships: ThreatRelationship[]` (`crates/nsic-core/src/models.rs`)
  -- the Apollo Constitution &sect;6 RELATE-stage structured view, distinct
  from `entries`' verdict-tier framing ("why did this file get flagged").
  Every relationship carries an explicit `kind` (IOC / CVE / threat actor /
  campaign / malware family / ATT&amp;CK technique / detection / risk-based)
  and `strength` (direct/strong/contextual/weak -- Open &middot; 3's
  requested vocabulary, `derive_strength`, a first HYPOTHESIS-level answer
  banded from confidence values already in real use across the codebase,
  not a locked one), plus an `explanation` stating what a hunt on it would
  look for. Most relationships are pure-derived from existing provenance
  entries (`derive_relationships`); **malware family attribution is newly
  real data**, not just restructured existing data -- MalwareBazaar's
  `signature` and ThreatFox's `malware_printable` fields were previously
  only used as report title text, now upserted as their own graph node and
  edge (`malware_family` / `indicator_attributed_to_malware_family`,
  migration `0009`). CVE/threat-actor/campaign relationship kinds are
  structurally supported (the graph tables already existed) but correctly
  surface no data yet, since no ingestion populates them until later
  hunt-pack work; ATT&amp;CK technique has no data source at all yet and is
  declared in the vocabulary without a code path, the same precedent
  `DetectionKind::Sigma` already sets for detection content this codebase
  doesn't ingest either.

What's stubbed or deliberately not built yet, in build order (see
[`docs/apollo-constitution.md`](docs/apollo-constitution.md#12-current-product-build-doctrine)
for the full sequencing rationale):

- **Recursive Hunt Engine (PR #20) -- the other half of Apollo's core
  product promise.** Today's verdict engine only goes one direction: file
  in, correlation out. There is no command that goes the other way --
  pick a relationship a file surfaced, and scan the chosen directory scope
  recursively for every other file associated with it. `fs_browse.rs`
  lists one directory level at a time; nothing walks a tree looking for
  matches. The Threat Relationship Model (PR #19, done -- see "What works
  today" above) is what a recursive hunt now has to pivot on.
- Fuzzy hashing (imphash / TLSH / ssdeep). The indicator kind and query
  path exist; nothing computes these values yet, so tier 2 (fuzzy match)
  never fires in Phase 0.
- CVE linkage. MalwareBazaar and ThreatFox do not carry an authoritative
  CVE mapping, so ingestion does not populate `cve` / `report_references_cve`.
  That mapping is curated in Phase 2's hunt packs; see the CVE hunting
  section below.
- Everything past Phase 0: agent, fleet console, sample retrieval, hunt
  packs, folder correlation scoring, change timeline.

## Locked architecture decisions

These are settled; do not redesign around them without an explicit
conversation.

1. **Live agent model.** Running systems, not disk images. Dead-box image
   analysis is out of scope indefinitely.
2. **Userland only.** No kernel driver, no minifilter, no kernel callbacks.
3. **Hashes and metadata leave the host. File contents do not.** Sample
   retrieval happens only on explicit analyst request, logged and
   attributed.
4. **Windows first.** macOS and Linux come later. (This repo is developed
   cross-platform; Phase 0 runs on Linux and macOS too, but Windows-specific
   artifacts in later phases, such as the USN journal and Amcache, are not
   portable and are not being designed around a lowest common denominator.)
5. **Single static binary agent.** No runtime dependency, once there is an
   agent (Phase 1). The Phase 0 desktop app itself is not that agent.
6. **YARA and Sigma are the rule formats.** Never invent a bespoke rule
   language.
7. **Postgres for the intel store.** Recursive CTEs are sufficient at
   internal-IR scale. Do not reach for a graph database without demonstrated
   need.

## Intel graph shape

```
Indicator (hash | path | regkey | mutex | domain | ip)
  --observed_in--> Report
Report --references--> CVE
CVE --attributed_to--> Actor/Campaign
Detection (YARA | Sigma) --detects--> Indicator
Detection --covers--> CVE
```

Source, confidence, and first/last-seen live on edges, not nodes. See
`src-tauri/migrations/0001_init.sql` for the full schema.

## Verdict tiers

Never a boolean. Strongest to weakest:

1. Exact hash match
2. Fuzzy match (imphash, TLSH, ssdeep): wired, not yet populated in Phase 0
3. YARA rule hit
4. Path or naming pattern only
5. Contextual association only

Every verdict carries provenance back to the source that produced it.

## Tech stack

- **Backend:** Rust, Tauri 2. Chosen to share code with the eventual
  Windows agent (YARA bindings, hashing, eventually USN / MFT / VSS
  parsing) and to match the "single static binary, userland only" ethos.
- **Frontend:** React + TypeScript + Vite.
- **Intel store:** Postgres 16+.
- **Rule engine:** YARA (via the `yara` crate, binding to libyara).

## Setup

### Prerequisites

- Rust (stable) and Cargo.
- Node.js 18+ and npm.
- Postgres 16+, or Docker to run the bundled `docker-compose.yml`.
- `libyara-dev` (Linux) so the `yara` crate can bind to libyara.
- On Linux, Tauri's WebKitGTK dependencies: `libwebkit2gtk-4.1-dev`,
  `libgtk-3-dev`, `libayatana-appindicator3-dev`, `librsvg2-dev`.
- An abuse.ch account and API key (free) for feed sync: MalwareBazaar and
  ThreatFox both require an `Auth-Key` header as of their current API.
  Register at https://auth.abuse.ch/ and set `ABUSECH_API_KEY`.

### Run it

```bash
docker compose up -d          # starts Postgres on localhost:5432
cp .env.example .env          # DATABASE_URL, adjust if not using docker-compose
export ABUSECH_API_KEY=...    # only needed to use the "Sync feeds" button
npm install
npm run tauri dev
```

Migrations run automatically on startup against `DATABASE_URL`
(`sqlx::migrate!`). If Postgres is not reachable, the app still launches;
verdict and sync commands report a clear error instead of crashing.

Drop your own YARA rules (`.yar` / `.yara`) into `yara-rules/` (or point
`NSIC_YARA_RULES_DIR` elsewhere) and restart to pick them up. A single
example rule (EICAR test-string detection) ships so YARA scanning has
something to demonstrate out of the box.

### Tests

```bash
cd src-tauri
cargo test                              # unit tests, no DB required
cargo test -- --ignored --nocapture     # integration test, requires DATABASE_URL
```

The ignored test hashes a synthetic EICAR file, runs it through the local
YARA engine, persists the hit to Postgres, and asserts it comes back out of
the verdict engine as a `YaraHit` entry with provenance, exercising the
same path a real file-manager click does.

### Live abuse.ch ingestion check

`ingest/mod.rs` has a second ignored test, `live_abusech_sync_works`, that
calls the real MalwareBazaar and ThreatFox APIs (not a mock) and asserts the
sync actually touches indicators/reports. It requires a real
`ABUSECH_API_KEY` and is excluded from every normal test run:

```bash
cd src-tauri
export ABUSECH_API_KEY=...
cargo test live_abusech_sync_works -- --ignored --nocapture
```

This also runs in CI on a weekly schedule (`.github/workflows/live-ingest-check.yml`)
and via manual dispatch, separately from the PR merge gate, so API drift or
outages get caught without ever blocking a routine merge. It requires an
`ABUSECH_API_KEY` repository secret (Settings -> Secrets and variables ->
Actions -> New repository secret; get a free key at
[auth.abuse.ch](https://auth.abuse.ch/)). Without that secret the workflow
reports it plainly and exits rather than failing confusingly.

### Phase 1 scaffold (agent + console)

`crates/agent` and `crates/console` are plain Rust workspace members, no
Node/npm and (unlike `src-tauri`) no GTK system libraries needed on Linux.
`crates/agent` (and `crates/nsic-core`'s own test suite) does need
`libyara-dev` to build, same as `src-tauri`; `crates/console` needs
neither GTK nor `libyara-dev`.

```bash
cargo test -p nsic-core -p agent -p console          # unit tests, no DB required
cargo test -p nsic-core -p agent -p console -- --ignored --nocapture  # DB-backed
```

The console can optionally serve HTTPS (`NSIC_TLS_CERT_PATH`/
`NSIC_TLS_KEY_PATH`, both or neither) instead of plain HTTP, and the
agent has a matching `--tls-ca-cert`/`NSIC_TLS_CA_CERT` option to trust a
self-signed or internal-CA console certificate. An operator can also
rotate or revoke a host's per-agent credential in place, without deleting
the host and losing its sighting/sample-request history. The console
also serves a browser-facing fleet UI (server-rendered, no separate
build step) at its root -- browse enrolled hosts, drill into a host's
sightings and sample requests, request a new sample, and rotate/revoke
credentials, gated by the same operator credential presented as HTTP
Basic auth. Every scan (whether or not it matches anything) reports
coverage back to the console, so the fleet UI can flag a host that's
never scanned or whose rules failed to load, distinctly from one that's
scanning fine and genuinely finding nothing -- and distinctly again from
one whose last scan is simply old, flagged as "stale" once it passes a
configurable threshold (`NSIC_SCAN_STALENESS_HOURS`, default 24h). See
[`docs/phase1-design.md`](docs/phase1-design.md) for how to run the agent
against the console locally (with or without TLS) and what this scaffold
does and doesn't do yet.

### Working with sqlx offline mode

Queries are checked at compile time against the live schema in
`src-tauri/migrations/`. The `.sqlx/` directory is a checked-in query cache
so `cargo build` works without a live database (`SQLX_OFFLINE=true` is the
default behavior when `DATABASE_URL` is unset). After changing a query,
regenerate the cache with a live, migrated database:

```bash
cd src-tauri
export DATABASE_URL=postgres://nsic:nsic@localhost:5432/nsic
cargo sqlx prepare
```

## Intel source licensing

Redistributable: abuse.ch feeds, CISA KEV, NVD, MISP communities.
**Not** redistributable: VirusTotal verdicts (terms prohibit use in a
competing product). Nothing in this repo integrates VirusTotal. Confirm
redistribution rights before architecting around any new feed.

## CVE hunting: hunt packs (PR #21, not yet built)

There is no authoritative CVE-to-IOC feed; that mapping has to be curated.
Curated relationship knowledge is a durable moat, but hunt packs
themselves are machinery, not the product -- see
[`docs/apollo-constitution.md`](docs/apollo-constitution.md#7-recursive-hunting-and-hunt-packs).
What Apollo actually sells is the file &rarr; understand &rarr; relate
&rarr; pivot &rarr; hunt &rarr; explain loop; a hunt pack is one mechanism
that feeds the pivot/hunt steps by turning a threat concept into an
executable hunt. A hunt pack will be a per-CVE bundle (YARA rules, Sigma
rules, file path and name patterns, registry keys, version checks), every
element carrying provenance to the advisory or report it came from,
ingested through an analyst review queue and never auto-published. Seed
corpus: the CISA KEV list. Sequenced as PR #21, after the File Intelligence
Model, Threat Relationship Model, and Recursive Hunt Engine it depends on
-- a hunt pack needs a hunt engine to prove itself against, not the other
way around.

## Build order

Do not jump ahead; each phase de-risks the next.

- **Phase 0 (current):** this repo. Single-machine desktop app proving the
  file-manager-with-verdicts UX. Success criteria: an IR analyst uses it on
  a real case and wants it again.
- **Phase 1 (fleet substrate, frozen for now):** Agent plus console.
  File-to-IOC across a fleet. Sample retrieval. `crates/nsic-core` (shared
  hashing, YARA scanning, and intel-graph types, extracted out of
  `src-tauri`), `crates/agent` (a CLI that can hash a file, run a local
  YARA scan, enroll/heartbeat against a console, report scan matches as
  sightings and per-invocation scan coverage, and fulfill an operator's
  sample-retrieval requests), `crates/console` (an HTTP service and
  server-rendered fleet UI, `/api/v1`, recording
  enrollment/heartbeats/sightings/sample requests/scan coverage in the
  same Postgres intel graph; per-agent credentials with operator-driven
  rotation and revocation; reading sightings, sample-request status, and
  fleet-wide host/sensor-health state back out; downloading a retrieved
  sample's actual content). See
  [`docs/phase1-design.md`](docs/phase1-design.md) for exactly what's
  covered and what's deliberately deferred. This is enough infrastructure
  to prove the agent architecture works; further fleet-administration
  expansion (scheduling, richer deployment management, and the like) is
  deliberately paused here rather than continued out of momentum -- see
  the roadmap correction below.
- **Roadmap correction (current focus, superseded by
  [`docs/apollo-constitution.md`](docs/apollo-constitution.md#12-current-product-build-doctrine)
  -- read that first if this bullet and that document ever disagree):**
  an external review of the codebase pointed out that Phase 1 is the
  harder commercial sell -- "please deploy another endpoint agent" --
  while nothing on the intelligence/hunting path had been built yet.
  Endpoint fleet management is real, useful infrastructure, but it isn't
  the wedge. Two earlier passes at this correction each over-rotated:
  the first toward hunt packs specifically (corrected -- hunt packs are
  machinery, not the product); the second toward "agentless-first"
  specifically, which the Apollo Constitution demotes from a decided
  strategy to an open question -- external EDR/SIEM integration may
  reduce adoption friction later, but it should not redefine Apollo's
  actual CORE wedge, which is the *local, single-machine* filesystem
  experience. Apollo Sensor (the existing agent) is a PROVEN FOUNDATION
  backend, not a rejected one; EDR/SIEM connectors are just an OPEN/LATER
  alternative backend, decided by customer evidence, not by assumption.
  Current build sequence, in order: intel freshness surfaced on every
  verdict (PR #17, done -- see "What works today" above), a File
  Intelligence Model (PR #18, done -- see "What works today" above --
  what a file is actually *for*, not just its hash/reputation), a
  Threat Relationship Model (PR #19, done -- see "What works today" above
  -- CVE/IOC/APT/campaign/malware/risk associations as structured,
  actionable objects with an explicit strength vocabulary), a Recursive
  Hunt Engine
  (PR #20 -- the actual missing pivot: today's verdict engine only goes
  file-in, correlation-out, never indicator-in, matching-files-out), a
  first real KEV-seeded Hunt Pack to prove the engine (PR #21), then Hunt
  Scope Expansion from subtree to drive/host, still entirely local (PR
  #22). Remote/fleet/external-execution backends (an adapter boundary,
  agentless hunt execution, evidence-graph normalization across sources)
  are explicitly **Later**, undecided in shape, and deliberately not
  sequenced as near-term numbered work -- they scale the same hunt model
  only after the local product thesis is proven, per Expansion Gate 7.
  The endpoint agent remains infrastructure either way, not the
  definition of Apollo -- the intel graph, provenance model, verdict
  engine, and console APIs all survive this sequencing change unchanged.
- **Phase 2:** CVE hunt packs, KEV first -- see the roadmap correction
  above for sequencing relative to the core interaction loop.
- **Phase 3:** Folder correlation scoring. Must come after real hunt/fleet
  telemetry exists because the scoring model cannot be tuned without it;
  building it early ships a false-positive generator.
- **Phase 4:** Change history and timeline, from the USN Journal, $MFT
  ($STANDARD_INFO vs $FILE_NAME to detect timestomping), VSS, Prefetch, and
  Amcache. This is timeline reconstruction with gaps, not true versioning;
  do not describe it as versioning in UI copy or docs.

## Prior art this integrates with, not reimplements

Velociraptor, YARA, Sigma, Chainsaw, Hayabusa, Plaso. The bet is on
correlation UX and the CVE-to-indicator graph, not on primitives that
already exist.

## Project layout

The Rust side is a Cargo workspace (root `Cargo.toml`) so `src-tauri` (the
Phase 0 desktop app) and the Phase 1 `crates/` share one dependency tree
and one `target/` without depending on each other's platform requirements.

```
src/                    React frontend (file manager UI, verdict panel)
src-tauri/src/
  models.rs              Phase 0-only types (FileEntry, SyncSummary); re-exports
                          the shared intel-graph types from nsic-core
  db/                     Postgres query layer; connect_and_migrate is re-exported
                          from nsic-core
  ingest/                 MalwareBazaar and ThreatFox feed sync
  yara_scan.rs            Re-exports YaraEngine from nsic-core
  hashing.rs              Postgres-cached file hashing (path + size + mtime);
                          the actual digest computation is in nsic-core
  bloom.rs                Bloom filter of known-bad hashes
  verdict.rs              Ties hashing + bloom + YARA + DB into a verdict
  fs_browse.rs            Directory listing for the file manager
  commands.rs             Tauri IPC commands exposed to the frontend
src-tauri/migrations/    Postgres schema (intel graph), shared with crates/console
yara-rules/               Local YARA rules loaded at startup, by both
                          src-tauri and crates/agent

crates/nsic-core/src/    Shared, minimal by default: hashing and intel-graph
                          vocabulary always on; `db` feature adds
                          connect_and_migrate, `yara-scan` feature adds
                          YARA rule loading/scanning (yara_scan.rs).
crates/agent/src/        Phase 1 fleet agent CLI (nsic-agent): hash / scan /
                          enroll / heartbeat, and scan can report matches
                          as sightings. No Postgres, no GTK, single static
                          binary; links libyara (yara-scan feature).
crates/console/src/      Phase 1 fleet console (nsic-console): HTTP service,
                          axum, backed by the same Postgres intel graph.
                          host.rs (enroll/heartbeat), sighting.rs (sighting
                          submission), auth.rs (shared credential checks).
                          No YARA linked -- it doesn't scan anything itself.

docs/phase1-design.md   What Phase 1's scaffold covers and what's deferred.
```
