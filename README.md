# 4NSIC

DFIR triage and threat hunting tool. An analyst-facing correlation layer that
sits alongside existing EDR, not a replacement for it.

Core idea: a file manager where selecting a file surfaces everything known
about it (IOC verdicts, campaign attribution, related CVEs, detection
provenance). EDR tells you a file is bad. 4NSIC tells you which campaign it
belongs to, which CVE it relates to, and what else on the host clusters
with it.

## Current phase: Phase 0

Single-machine desktop app. No agent, no server, no fleet. This proves the
file-manager-with-verdicts UX on one box using abuse.ch feeds (MalwareBazaar,
ThreatFox) and local YARA. See "Build order" below for what comes next and
why later phases are deliberately not started yet.

What works today:

- File manager: browse directories, select a file.
- Verdict engine: hashes the file (cached by path + size + mtime), checks a
  local bloom filter of known-bad hashes, runs a local YARA pass, and checks
  path-pattern and contextual signals. Every match is returned with its
  tier, source, and confidence; nothing collapses to a boolean.
- Intel graph in Postgres: Indicator / Report / CVE / Actor / Detection
  nodes with source, confidence, and first/last-seen on the edges, so the
  same hash arriving from multiple feeds with different confidence is
  preserved instead of flattened.
- Feed ingestion: MalwareBazaar and ThreatFox recent submissions, folded
  into the graph with provenance back to the source report.

What's stubbed or deliberately not built yet:

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

## CVE hunting: hunt packs (Phase 2, not yet built)

There is no authoritative CVE-to-IOC feed; that mapping has to be curated,
and it is the product's actual moat. A hunt pack will be a per-CVE bundle
(YARA rules, Sigma rules, file path and name patterns, registry keys,
version checks), every element carrying provenance to the advisory or
report it came from, ingested through an analyst review queue and never
auto-published. Seed corpus: the CISA KEV list.

## Build order

Do not jump ahead; each phase de-risks the next.

- **Phase 0 (current):** this repo. Single-machine desktop app proving the
  file-manager-with-verdicts UX. Success criteria: an IR analyst uses it on
  a real case and wants it again.
- **Phase 1:** Agent plus console. File-to-IOC across a fleet. Sample
  retrieval.
- **Phase 2:** CVE hunt packs, KEV first.
- **Phase 3:** Folder correlation scoring. Must come after Phase 1 because
  the scoring model cannot be tuned without real telemetry; building it
  early ships a false-positive generator.
- **Phase 4:** Change history and timeline, from the USN Journal, $MFT
  ($STANDARD_INFO vs $FILE_NAME to detect timestomping), VSS, Prefetch, and
  Amcache. This is timeline reconstruction with gaps, not true versioning;
  do not describe it as versioning in UI copy or docs.

## Prior art this integrates with, not reimplements

Velociraptor, YARA, Sigma, Chainsaw, Hayabusa, Plaso. The bet is on
correlation UX and the CVE-to-indicator graph, not on primitives that
already exist.

## Project layout

```
src/                    React frontend (file manager UI, verdict panel)
src-tauri/src/
  models.rs              Shared types: indicators, verdict tiers, provenance
  db/                     Postgres pool, migrations runner, query layer
  ingest/                 MalwareBazaar and ThreatFox feed sync
  yara_scan.rs            YARA rule loading and scanning
  hashing.rs              Cached file hashing (path + size + mtime)
  bloom.rs                Bloom filter of known-bad hashes
  verdict.rs              Ties hashing + bloom + YARA + DB into a verdict
  fs_browse.rs            Directory listing for the file manager
  commands.rs             Tauri IPC commands exposed to the frontend
src-tauri/migrations/    Postgres schema (intel graph)
yara-rules/               Local YARA rules loaded at startup
```
