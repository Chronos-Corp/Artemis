# Artemis Threat Intelligence Source Registry

*Baseline registry · Rev. 0.1 · 19 August 2026*

This registry records the threat-intelligence and detection sources currently used by Artemis. It operationalizes the source-governance requirements in the Artemis Threat Intelligence Constitution.

A source appearing here is not automatically authoritative for every claim it supplies. Each source profile defines what Artemis may conclude from the source, which facts remain source assertions, and what must remain visible to the analyst.

## Registry rules

1. Source identity, licensing, time semantics, confidence semantics, and failure state must remain explicit.
2. Source-specific fields must not be silently assigned universal meaning.
3. Ingestion must preserve sufficient identity to trace a normalized assertion back to its source record.
4. A failed or never-completed synchronization must not look like an empty source.
5. Source absence is not evidence of safety.
6. Claims from different sources may coexist and conflict.
7. Redistribution rights must be confirmed before source-derived content is packaged or redistributed.
8. Source changes require revalidation of parsers, mappings, and affected assertions.

## Baseline status vocabulary

| Status | Meaning |
| --- | --- |
| Active | Implemented and currently intended for use |
| Qualification Required | Implemented, but a documented validation gap remains |
| Candidate | Not an Artemis dependency; evaluation may be planned |
| Suspended | Temporarily excluded from trusted use |
| Retired | No longer used for new intelligence; history remains |

## Current source summary

| Source | Class | Status | Current Artemis use | Primary limitation |
| --- | --- | --- | --- | --- |
| MalwareBazaar | External malware intelligence | Active / Qualification Required | Recent malware submissions, file indicators, source reports, malware-family assertions | Source-provided family labels remain assertions, not Artemis-proven attribution |
| ThreatFox | External IOC intelligence | Active / Qualification Required | Recent indicators, reports, and malware-name assertions | IOC and family fields require source-specific interpretation |
| Local YARA | Local detection content | Active / Qualification Required | Deterministic content matching against selected or hunted files | A rule match proves rule conditions matched, not malware identity or compromise by itself |

---

## Source profile: MalwareBazaar

### Identity

- **Publisher:** abuse.ch
- **Source class:** Malware sample and malware metadata intelligence
- **Artemis status:** Active / Qualification Required
- **Current access:** abuse.ch API using the configured authentication key
- **Current implementation role:** Artemis retrieves recent submissions and normalizes supported hashes, reports, timing, and malware-family assertions into its intelligence store.

### Allowed uses

Artemis may use MalwareBazaar records to support:

- exact file-hash intelligence relationships;
- source-report provenance;
- source-provided malware-family or signature assertions;
- first-seen and last-seen claims when their source semantics are known;
- pivots into related Artemis hunts.

A MalwareBazaar family or signature value remains an attribution asserted through that source record. Artemis must not present it as independently verified merely because it was normalized into a malware-family node.

### Normalization requirements

For each supported record, preserve or derive:

- source name;
- stable source-record identity where supplied;
- source URL or retrievable reference where permitted;
- supported hash kind and value;
- report identity;
- malware-family/signature text as a source assertion;
- source confidence or explicit absence of source confidence;
- source observation timestamps where supplied;
- Artemis receipt/ingestion time;
- parser and mapping version where available;
- licensing and redistribution classification.

Do not reconstruct family attribution by joining only on source and indicator when multiple reports can exist for the same indicator. The exact supporting report must remain attached to the attribution edge.

### Time semantics

Source-reported observation times and Artemis ingestion time are distinct. When Artemis only knows when it received the record, the field must use receipt-only semantics.

Per-source freshness is based on the last successful synchronization, not the time of the most recent failed attempt.

### Confidence semantics

> **OPEN — MalwareBazaar does not establish one universal Artemis confidence value for every field.**

Hash equality determines relationship mechanism strength. It does not automatically validate every family, campaign, or behavioral assertion contained in the same record.

### Failure behavior

- Authentication, network, schema, parsing, or persistence failure must be visible.
- A failed synchronization must not advance the last-successful-sync time.
- A stale or never-synchronized corpus must remain visible on verdicts and hunts.
- Partial ingestion must report partiality and must not appear fully current.

### Licensing and redistribution

The repository currently treats abuse.ch feeds as redistributable, but every external release or packaged derivative must confirm the then-current source terms.

> **EVIDENCE REQUIRED — Record the exact governing terms, retrieval date, and permitted redistribution behavior before Artemis distributes source-derived intelligence or bundled Hunt Packs externally.**

### Qualification evidence required

- Idempotent replay of representative records
- Duplicate reports for one indicator
- Conflicting family assertions
- Missing and malformed optional fields
- Source schema drift
- Partial-page or partial-run failure
- Timestamp-semantic tests
- Authentication and rate-limit failure behavior
- Provenance reconstruction from normalized assertion to source record

---

## Source profile: ThreatFox

### Identity

- **Publisher:** abuse.ch
- **Source class:** IOC and malware intelligence
- **Artemis status:** Active / Qualification Required
- **Current access:** abuse.ch API using the configured authentication key
- **Current implementation role:** Artemis retrieves recent ThreatFox submissions and normalizes supported indicators, reports, timing, and malware-name assertions into its intelligence store.

### Allowed uses

Artemis may use ThreatFox records to support:

- exact or typed IOC relationships;
- source-report provenance;
- source-provided malware-name assertions;
- infrastructure or artifact pivots when the indicator kind is supported;
- first-seen and last-seen claims when their source semantics are known.

A source malware-name field is not independent proof of family attribution. Indicator presence does not prove the indicator is currently malicious, exclusively attacker-controlled, or relevant to the investigated system without time and context.

### Normalization requirements

Preserve or derive:

- source name;
- stable source-record identity where supplied;
- source URL or retrievable reference where permitted;
- indicator kind and exact value;
- report identity;
- malware-name text as a source assertion;
- source confidence or explicit absence;
- source observation timestamps where supplied;
- Artemis receipt/ingestion time;
- parser and mapping version where available;
- licensing and redistribution classification.

Indicator normalization must remain type-aware. Domain, IP, URL, hash, and other indicator kinds must not collapse into an untyped value field for comparison or deduplication.

### Time semantics

Infrastructure can be reassigned, cleaned, sinkholed, or reused. Historical observation remains valuable, but operational reliance must consider age and indicator class.

> **OPEN — Decay policy by ThreatFox indicator type.**

> **EVIDENCE REQUIRED — Measure reassignment and analyst false-positive impact before setting default validity periods.**

### Confidence semantics

ThreatFox source fields must be interpreted according to documented source semantics. Artemis must not convert an absent or source-specific confidence value into a fabricated universal score.

Relationship strength continues to describe match mechanism. Exact comparison may be Direct while the source assertion remains low confidence or stale.

### Failure behavior

- Authentication, network, schema, parsing, or persistence failure must be visible.
- A failed synchronization must not advance the last-successful-sync time.
- Partial ingestion must remain distinguishable from a complete successful sync.
- Parser rejection counts and unsupported indicator kinds must be observable.
- Source staleness must accompany verdict and hunt interpretation.

### Licensing and redistribution

The repository currently treats abuse.ch feeds as redistributable, but every external release or packaged derivative must confirm the then-current source terms.

> **EVIDENCE REQUIRED — Record the exact governing terms, retrieval date, attribution requirements, and redistribution permissions before external distribution.**

### Qualification evidence required

- One value represented under different indicator kinds
- Duplicate and conflicting reports
- Reassigned or stale infrastructure scenarios
- Unsupported indicator types
- Malformed indicator values
- Missing confidence and time fields
- Schema drift
- Partial-run failure
- Provenance reconstruction from normalized assertion to source record

---

## Source profile: Local YARA

### Identity

- **Publisher:** Local operator, Artemis distribution, or other identified rule publisher
- **Source class:** Detection content
- **Artemis status:** Active / Qualification Required
- **Current access:** Local rule files loaded by the Artemis YARA engine
- **Current implementation role:** Artemis applies compiled YARA rules to bounded file bytes and records rule matches with rule identity and fingerprint.

Local YARA is not one publisher. Every rule or ruleset must retain its actual publisher and provenance when known. "Local YARA" describes an execution source, not a universal authority.

### Allowed uses

A YARA match supports:

- a Detection relationship;
- direct evidence that the scanned bytes satisfied the compiled rule conditions;
- pivots through explicitly curated detection coverage relationships;
- Hunt Pack execution when the rule is included or referenced by a qualified pack.

A YARA match does not, by itself, prove:

- malware-family identity;
- exploitation of a CVE;
- actor or campaign attribution;
- system compromise;
- malicious intent.

Those conclusions require separate, provenance-bearing assertions.

### Rule identity and versioning

Artemis must preserve:

- rule name;
- rule publisher or source where known;
- source rule file;
- fingerprint of the specific rule-bearing file or canonical rule content;
- ruleset identity where separately relevant;
- compilation status;
- execution time;
- scan target identity;
- hash of the bytes actually scanned;
- rule metadata used for additional assertions;
- license and redistribution classification.

A relationship curated for one rule revision must not silently apply to a later revision that merely reuses the same rule name.

Rule source identity and effective behavior identity are different concepts:

- `rule_source_fingerprint` identifies the exact parsed source for one rule and remains stable when that rule's own source is unchanged.
- The current Phase-0 `rule_fingerprint` deliberately combines the rule source fingerprint with the whole compiled-ruleset fingerprint. A helper, private, global, or unrelated rule change therefore changes the effective identity today.
> **DECIDED CURRENT STATE — Conservative whole-ruleset effective identity.** The current Phase-0 `rule_fingerprint` intentionally over-invalidates: changing any compiled rule changes the effective identity of every rule in that ruleset. This can require revalidation of an unchanged rule, but it fails closed rather than allowing version-scoped evidence to survive a possible helper, private, global, module, engine, or other ruleset semantic change.

An unrelated ruleset change must not rewrite the unchanged rule's `rule_source_fingerprint` or historical assertion record. It does invalidate the current effective-version match until coverage is requalified.

> **OPEN IMPROVEMENT — Dependency-aware effective identity.** A later design may narrow `rule_fingerprint` to the rule's transitive dependencies plus relevant global, module, engine, and compiler context. This is a target precision improvement, not current behavior and not authorization to weaken fail-closed version gating.
>
> **EVIDENCE REQUIRED —** A dependency model must prove that it captures helper/private references, global-rule gates, module and external-variable behavior, includes or equivalent source composition, compiler/libyara version effects, and ambiguous or unresolvable dependencies. Any unresolved dependency must retain conservative invalidation.

### Execution integrity

Hashing and YARA evaluation must operate on the same bounded bytes. Artemis must not bind a rule match to a hash calculated from different file contents.

Unsupported files, non-regular objects, files exceeding bounds, read errors, and live-file changes remain inconclusive. They must not become clean results or contradicting evidence.

### Confidence and strength

The rule match mechanism is Direct evidence of a Detection relationship. The detection's quality, specificity, publisher credibility, and downstream attribution are separate questions.

Rule metadata must not silently promote a Detection relationship into malware, CVE, actor, or campaign attribution. Those mappings require explicit reviewed assertions.

### Qualification evidence required

Every trusted rule or Hunt Pack ruleset must include, as applicable:

- positive samples or fixtures;
- negative samples;
- ambiguous near-matches;
- adversarial cases;
- compilation validation;
- bounded execution validation;
- expected false-positive analysis;
- supported file types and size limits;
- rule-version and fingerprint tests, including unchanged source identity with changed effective ruleset identity;
- license and redistribution review;
- human approval after assessment.

Approval time must be greater than or equal to assessment time.

### Failure behavior

- Rule load or compilation failure must be visible.
- Successful scanning with no match must remain distinct from rules not loading.
- Coverage must identify which rules or rulesets actually executed.
- Truncated or partial execution must remain explicit.
- The last successful load must not conceal a current load failure.

### Licensing and redistribution

Rules may have different licenses even when stored in the same local directory. Artemis must not assume that local availability permits redistribution in a Hunt Pack or registry.

> **EVIDENCE REQUIRED — Attach publisher, source, and license metadata before redistributing any non-original rule.**

---

## Cross-source conflict behavior

When two sources disagree:

1. Preserve each assertion and its provenance.
2. Do not overwrite by arrival order.
3. Do not average incompatible categorical claims.
4. Show time, source, method, and confidence separately.
5. Permit Orion to trace each supported path.
6. Require an explicit reviewed assertion to resolve or supersede the conflict.
7. Preserve prior conclusions and the intelligence version that produced them.

## Current governance gaps

### EVIDENCE REQUIRED

- Exact abuse.ch terms and retrieval-date records for MalwareBazaar and ThreatFox
- Source-field mapping tables tied to the implemented parser version
- Explicit parser schema-drift behavior
- Measured confidence semantics rather than inherited numeric assumptions
- Indicator-type-specific decay policy
- Rule-level publisher and license metadata for all shipped YARA content
- Qualification corpus covering positive, negative, ambiguous, and adversarial cases
- Documented retraction and deletion propagation behavior

## Candidate sources

These sources are candidates, not current authoritative dependencies:

| Candidate | Intended value | Entry gate |
| --- | --- | --- |
| CISA KEV | Seed vulnerability-centered Hunt Pack work | One end-to-end qualified CVE hunt specification |
| NVD | Vulnerability and product context | Proven mapping quality and source-specific time semantics |
| Vendor advisories | Authoritative product and exploitation details | Stable provenance and version/product mapping |
| MITRE ATT&CK | Actor, software, campaign, and technique knowledge | Demonstrated hunt value without unbounded association |
| Approved MISP communities | Additional reports and indicators | Licensing, trust, conflict, and sharing-policy validation |
| Sigma repositories | Portable behavioral detection content | Execution backend and rule qualification path |

Candidate status does not authorize implementation by momentum. Each source must demonstrate a measurable contribution to a validated Artemis hunt outcome.

## Review cadence

Review this registry when:

- a source changes terms, authentication, schema, or semantics;
- parser behavior changes;
- a material source outage or integrity defect occurs;
- Artemis begins redistributing derived intelligence;
- a new source is proposed;
- a source is suspended or retired;
- qualification evidence changes an OPEN question.

Changes to source status, permitted use, or trust semantics require review by the Artemis Threat Intelligence owner and any affected engineering or legal owner.
