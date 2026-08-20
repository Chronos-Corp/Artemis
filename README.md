# 4NSIC

DFIR triage and threat hunting tool -- **Artemis**, the first committed
product of the Chronos Corp portfolio thesis (codenamed Apollo during early
development; see `docs/apollo-constitution.md`, retained as retired,
historical product doctrine, not current authority). See
[`docs/artemis-product-constitution.md`](docs/artemis-product-constitution.md)
for the current product-level source of truth on what Artemis is, what it
isn't, and what's still genuinely open (and
[`docs/chronos-constitution.md`](docs/chronos-constitution.md) for the
company-level thesis it sits under); this README covers the technical
state of the repo, kept consistent with those documents rather than
repeating them. "4NSIC" is this repo's working name and shows up in the
crate names (`nsic-core`/`nsic-agent`/`nsic-console`); "Artemis" is the
product name.

**Artemis's non-negotiable product promise:** selecting a file should
progressively answer what it is, what it's for, whether it's expected here,
and whether it's related to known IOCs, CVEs, APTs, campaigns, malware, or
other risk-based threats. Selecting one of those relationships should let
an analyst hunt the chosen recursive scope for associated evidence, then
see what the combined evidence means. File &rarr; understand &rarr; relate
&rarr; pivot &rarr; hunt &rarr; explain. An analyst-facing correlation
layer that sits alongside existing EDR, not a replacement for it -- EDR
tells you a file is bad, Artemis tells you which campaign it belongs to,
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
  package-level rather than claiming Artemis identified this specific
  file's individual role), expectedness (a rollup with explicit reasons --
  checksum mismatch always wins; a same-directory masquerading check for
  near-miss filenames like `svch0st.exe` beside `svchost.exe` is treated
  as weak contextual evidence that cannot override a Verified checksum,
  since legitimate tool families like `mount`/`umount` genuinely sit
  within a small edit distance of each other), and local context. This
  answers "what is this file and what's it for," independent of
  `get_verdict`'s "is this file threat-relevant" -- see Artemis Product
  Constitution &sect;6. v1 package-manager support is dpkg-only
  (Debian/Ubuntu); other platforms report authenticity as `unknown`
  rather than guessing -- see the module doc comment. Deliberately does
  not touch Postgres at all, so it keeps working even when the intel
  database is unreachable.
- **Threat Relationship Model (PR #19).** `get_verdict` now also returns
  `threat_relationships: ThreatRelationship[]` (`crates/nsic-core/src/models.rs`)
  -- the Artemis Product Constitution &sect;7 RELATE-stage structured view, distinct
  from `entries`' verdict-tier framing ("why did this file get flagged").
  Every relationship carries an explicit `kind` (IOC / CVE / threat actor /
  campaign / malware family / ATT&amp;CK technique / detection / risk-based)
  and `strength` (direct/strong/contextual/weak -- Open &middot; 2's
  requested vocabulary). `strength` is set as a literal at each construction
  site based on the *evidence mechanism* -- an exact hash match is `Direct`,
  a YARA rule firing is a `Detection` (not an `Ioc`) at `Direct`, a
  two-hop CVE inference through report co-occurrence is `Contextual` -- and
  is never derived from a source's confidence number, which is an
  orthogonal dimension (a low-confidence exact match is still `Direct`; a
  high-confidence filename-only match is still `Weak`). Most relationships
  are pure-derived from existing provenance entries
  (`derive_relationships`), and only for tiers that are genuine
  indicator-table lookups (`ExactHash`/`FuzzyHash`/`PathPattern`); a YARA
  hit produces a `Detection` relationship only, and a contextual filename
  match produces a `RiskBased` relationship only, since neither ever
  touched the indicator table. **Malware family attribution is newly real
  data**, not just restructured existing data -- MalwareBazaar's
  `signature` and ThreatFox's `malware_printable` fields were previously
  only used as report title text, now upserted as their own graph node and
  edge (`malware_family` / `indicator_attributed_to_malware_family`,
  migration `0009`), checked against both sha256 and md5 indicators, with
  the supporting report's ID stored directly on the edge rather than
  reconstructed later -- reconstructing it via a join back to
  `indicator_observed_in_report` on `(indicator_id, source)` alone can
  cross-attribute or duplicate whenever a source has filed more than one
  report for the same indicator.
  Every `ThreatRelationship` carries an
  `evidence_paths: RelationshipEvidence[][]` list rather than one flat
  `source`/`confidence`/timestamp set: Postgres stores provenance per
  *edge*, not per relationship, so a single-hop relationship (IOC,
  Detection, RiskBased, MalwareFamily) carries exactly one path with one
  evidence item, while a CVE relationship carries the full multi-hop chain
  it was inferred through, each hop with its own provenance. Each inner
  array is one complete, independently-walkable path from the file to the
  target -- a CVE relationship inferred through report co-occurrence can
  have *more than one* path when the report observed this file under more
  than one hash (or via more than one source) before converging on the
  same `report_references_cve` assertion: those are two real, parallel
  first hops sharing one second hop, not one longer linear chain, so
  flattening them into a single array would either misrepresent the
  topology or force a consumer to infer the branch from repeated
  `report_id`s. CVE relationships come from two dedicated queries
  (`db::indicators::cve_matches_via_report` / `cve_matches_via_detection`),
  each anchored on the CVE-specific edge (not the parent indicator/detection
  edge), so one real `report -> cve` or `detection -> cve` assertion can't
  materialize as two relationships just because the file has two hash
  representations or multiple source rows for the same edge --
  deduplicating the *relationship* without discarding any real supporting
  *evidence*: `cve_matches_via_report` groups every matching
  `indicator_observed_in_report` row (sha256, md5, or more than one source)
  under the one CVE edge it supports, then emits one evidence path per
  parent row (each ending at its own copy of the shared CVE hop), so all of
  them survive as separate, self-contained paths rather than a `LIMIT 1`
  silently keeping only one and throwing the rest away.
  `report_references_cve --> Contextual` (a two-hop report co-occurrence
  inference) and `detection_covers_cve --> Strong` (one hop tighter: the
  detection matched this exact file, though covering a CVE is still the
  detection's own documented scope, not a per-file assertion).
  `cve_matches_via_detection` is scoped to the detection names that
  actually fired in the *current* scan, not any `detection_detects_indicator`
  edge ever persisted for the hash -- a detection recorded historically (a
  rule that has since changed, or one curated from another source) must not
  resurface as though it matched this exact file just because a *different*
  rule genuinely fired, or because the hash happens to be bloom-known for an
  unrelated reason. `detection` rows are keyed by `(kind, name)`, so editing
  a rule's body while keeping its name reuses the same row -- a
  `rule_fingerprint` column (migration `0010`, `NOT NULL DEFAULT ''` and
  part of both edge tables' primary keys, so a new rule-content version
  gets its own row rather than overwriting the previous version's history
  on conflict) is stamped on both `detection_detects_indicator` and
  `detection_covers_cve` edges as they're written, and
  `cve_matches_via_detection` filters on it per rule (`'' `= "applies to
  any version"), so a CVE coverage assertion made against one revision of
  a rule's content can't silently carry over to a later revision that
  reuses the same rule name. Scoped by `YaraEngine::rule_fingerprint` --
  the SHA-256 of the *one file* that declared that specific rule,
  deliberately not `YaraEngine::ruleset_fingerprint`'s whole-directory hash
  (that value is Phase 1's fleet-sighting identity, a legitimate but
  different concept -- see `host_sighted_indicator`'s migration comment):
  scoping CVE coverage by the whole compiled ruleset meant editing one
  unrelated rule elsewhere in the directory falsely invalidated every other
  rule's own unchanged coverage. Which rule a file declares is found by a
  lightweight lexer (`extract_rule_names`) that blanks out comments, string
  literals, *and* regex literals before scanning for `rule <identifier>`
  text -- regex literals matter because a YARA string pattern like
  `$r = /rule TargetRule/` is completely ordinary, valid syntax, and
  without stripping it the literal text inside the pattern was
  indistinguishable from a real declaration, letting one file's
  `rule_fingerprints` entry silently overwrite another's. The YARA-hit provenance entry and
  CVE-via-detection's first evidence hop are supplied directly from the
  current scan's own known values (rule name, its own fingerprint, source,
  confidence, timestamp, and the scanned indicator's kind/value) rather
  than reconstructed by reading back whatever row a database query happened
  to pick; the second hop preserves the coverage edge's own true stored
  fingerprint (including the wildcard) rather than presenting it as though
  asserted against whatever rule fired in the current scan.
  Hashing and YARA scanning read a file's bytes exactly once
  (`hashing::hash_and_read_file`) instead of two separate reads, closing a
  TOCTOU race where a file changing between the hash read and the scan
  read could bind a YARA hit's persisted edge to the wrong hash --
  mirrors the read-once-then-hash-and-scan-the-same-buffer pattern
  `crates/agent/src/main.rs` already used. That same function refuses
  anything that isn't a regular file (a FIFO can block a read
  indefinitely; a character device can return unbounded data regardless of
  what `len()` reports) and caps the read at 256 MiB, reported as a clear
  error rather than an OOM or an indefinite hang on a live filesystem
  `fs_browse::list_dir` otherwise exposes with no type/size information at
  all. It validates the object it actually opened, not a separate path
  stat: `open_regular` opens with `O_NONBLOCK` on Unix (a no-op once a
  regular file is confirmed, but it keeps opening a FIFO from blocking
  indefinitely for a writer) and every subsequent check --
  regular-file-or-not, size -- reads from an `fstat` on that same handle,
  so there's no window between "stat says this path is safe" and "open
  this path" for the underlying object to change.
  The bloom filter tracks its own validity (`BloomState::check`, one
  lock acquisition covering both the validity check and the membership
  check together): a bloom miss only short-circuits the indicator-table
  lookups when the filter is known to be in sync with the intel store, so a
  refresh failure degrades to doing the DB round trip on every scan rather
  than silently turning into false negatives. `sync_feeds` calls
  `BloomState::invalidate` *before* `ingest::run_all` starts committing new
  indicators/edges, not only after a failed post-sync refresh; `refresh`
  holds one write lock across both its DB query and the filter swap so a
  concurrent `insert` (a fresh local YARA hit) can't be silently discarded
  by the swap. Beyond the bloom filter itself, `IntelGate`
  (`src-tauri/src/bloom.rs`) serializes a verdict's *entire* intel-corpus
  read (its bloom check through its final `intel_freshness` read) against a
  feed sync's entire write (invalidate, ingest, refresh) as two mutually
  exclusive units: `verdict::resolve` holds a read guard for its whole
  duration, `commands::sync_feeds` holds the write guard around all three
  of its steps, so a verdict can never observe a mix of pre-sync and
  post-sync state -- a bloom-miss decision made against one corpus
  generation paired with `intel_freshness` read back from a *different*,
  newer one, purely because a sync happened to land in between. Many
  verdicts can still resolve concurrently (shared read access); only a sync
  excludes them, and only for its own short, explicit, manually-triggered
  duration. `RelationshipEvidence.relation` is a closed `EvidenceRelation` enum
  (one variant per edge table: `observed_in_report`,
  `report_references_cve`, `detects_indicator`, `detection_covers_cve`,
  `attributed_to_malware_family`, `contextual_filename_match`) rather than
  a free-form string, and each hop carries the specific node it traversed
  -- `indicator_kind`/`indicator_value` or `detection_name`/
  `rule_fingerprint` -- so the full evidence chain is reconstructable from
  the wire object alone, which PR #20's hunt engine will need to walk
  programmatically rather than parsing prose. Every `ProvenanceEntry` and
  `RelationshipEvidence` also carries `timing: EvidenceTiming` (`Observed`
  or `ReceivedOnly`): every edge-backed tier has a genuine claimed
  observation window for `first_seen`/`last_seen`, but the `Contextual`
  tier has no backing edge at all, so its timestamps are only Artemis's own
  report-receipt time (`report.ingested_at`) -- `ReceivedOnly` keeps that
  labeled honestly on the wire instead of letting one field name silently
  mean two different things depending on which tier produced it.
  Threat-actor and campaign relationship kinds are
  structurally supported (the graph tables already existed) but correctly
  surface no data yet, since no ingestion populates them until later
  hunt-pack work; ATT&amp;CK technique has no data source at all yet and is
  declared in the vocabulary without a code path, the same precedent
  `DetectionKind::Sigma` already sets for detection content this codebase
  doesn't ingest either.

What's stubbed or deliberately not built yet, in build order (see
[`docs/artemis-product-constitution.md`](docs/artemis-product-constitution.md#17-current-build-interpretation)
for the full sequencing rationale):

- **Recursive Hunt Engine (PR #20) -- the other half of Artemis's core
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

- [rustup](https://rustup.rs/). The checked-in `rust-toolchain.toml`
  automatically selects Rust stable with Cargo, Clippy, and rustfmt. A shell
  with no `rustup`/`cargo` is not an Artemis verification environment; install
  rustup before changing or publishing Rust code.
- Node.js 18+ and npm.
- Postgres 16+, or Docker to run the bundled `docker-compose.yml`.
- `libyara-dev` (Linux) so the `yara` crate can bind to libyara.
- On Linux, Tauri's WebKitGTK dependencies: `libwebkit2gtk-4.1-dev`,
  `libgtk-3-dev`, `libayatana-appindicator3-dev`, `librsvg2-dev`.
- An abuse.ch account and API key (free) for feed sync: MalwareBazaar and
  ThreatFox both require an `Auth-Key` header as of their current API.
  Register at https://auth.abuse.ch/ and set `ABUSECH_API_KEY`.

### Run it

Confirm the repository toolchain before making backend changes:

```bash
rustup show active-toolchain
cargo --version
cargo fmt --all -- --check
```

If any command is unavailable, stop before publication and provision Rust.
Remote CI is still mandatory, but it must not be treated as a substitute for
every locally available compilation and formatting check.

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
[`docs/artemis-product-constitution.md`](docs/artemis-product-constitution.md#8-execute-guided-relational-and-analyst-defined-hunting).
What Artemis actually sells is the file &rarr; understand &rarr; relate
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
  [`docs/artemis-product-constitution.md`](docs/artemis-product-constitution.md#17-current-build-interpretation)
  -- read that first if this bullet and that document ever disagree):**
  an external review of the codebase pointed out that Phase 1 is the
  harder commercial sell -- "please deploy another endpoint agent" --
  while nothing on the intelligence/hunting path had been built yet.
  Endpoint fleet management is real, useful infrastructure, but it isn't
  the wedge. Two earlier passes at this correction each over-rotated:
  the first toward hunt packs specifically (corrected -- hunt packs are
  machinery, not the product); the second toward "agentless-first"
  specifically, which the retired Apollo Constitution (&sect;10) demotes from
  a decided strategy to an open question -- not carried forward into the
  current Artemis Product Constitution, which does not yet re-address
  execution-backend choice explicitly -- external EDR/SIEM integration may
  reduce adoption friction later, but it should not redefine Artemis's
  actual CORE wedge, which is the *local, single-machine* filesystem
  experience. Artemis Sensor (the existing agent) is a PROVEN FOUNDATION
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
  definition of Artemis -- the intel graph, provenance model, verdict
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
