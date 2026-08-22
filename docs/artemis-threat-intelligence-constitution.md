# Artemis Threat Intelligence Constitution

*Artemis Threat Intelligence · Rev. 0.1 · 19 August 2026*

> Turn sourced threat knowledge into evidence-bearing hunts.

## 1. Authority and purpose

This document governs threat-intelligence knowledge used by Artemis. It inherits the Chronos Constitution and the Artemis Product Constitution. If a lower-level implementation or roadmap conflicts with those governing documents, the governing documents win until the conflict is explicitly resolved.

Artemis is the committed Chronos threat-hunting platform. Orion is Artemis's relational hunt engine. Apollo is reserved for future Chronos use.

> **DECIDED — Artemis Threat Intelligence owns the lifecycle of threat knowledge used by Artemis.**

The workstream turns external reporting, vulnerability information, detection content, and analyst knowledge into typed, provenance-preserving assertions that Artemis can inspect, relate through Orion, and apply as hunt hypotheses.

Threat intelligence is not a separate portal attached to Artemis. It exists to strengthen the Artemis lifecycle:

**Analyze → Relate → Trace → Execute → Model → Interpret → Sustain**

## 2. Owned responsibilities

Artemis Threat Intelligence owns:

- source evaluation, licensing, intake requirements, and source-specific semantics;
- normalization of threat entities and assertions without erasing source meaning;
- provenance, source confidence, freshness, observation and receipt timing;
- intelligence conflicts, corrections, supersession, retraction, and expiration;
- IOC, CVE, software, malware, actor, campaign, infrastructure, ATT&CK, detection, and risk knowledge used by Artemis;
- Hunt Pack research, curation, qualification, publication, versioning, and retirement;
- analyst-authored intelligence derived from investigations;
- measurement of whether intelligence materially improves hunt outcomes.

It does not own:

- Orion graph traversal, path construction, ranking implementation, or query execution;
- endpoint scanning, storage implementation, hostile-file handling, or product UI;
- full generic detection-engineering lifecycle;
- malware detonation, continuous endpoint monitoring, or generic SIEM operation;
- model-generated attribution presented as observed fact.

## 3. Laws of Artemis Threat Intelligence

### LOCKED

1. **No assertion outranks its provenance.** A material intelligence assertion must identify its source, method, time semantics, and evidence path.
2. **Observation is not inference.** Observation, evidence, inference, conclusion, and action remain distinct.
3. **Absence is bounded.** "No matching intelligence" or "no matching evidence found" never means safe, benign, disproven, or contradictory.
4. **AI is not an evidentiary authority.** AI may extract, summarize, correlate, and propose. It may not become the source of an observed fact.
5. **Portable detection content remains portable.** YARA and Sigma remain established rule formats. Hunt Packs do not create a proprietary detection language.
6. **Conflicts remain visible.** Artemis must not silently flatten incompatible claims into one truth.
7. **Free Artemis truth is not weakened.** Commercial packaging may add organizational governance and distribution, but it must not degrade provenance, relationship truth, or local evidentiary value in Free Artemis.
8. **Intelligence must serve hunts.** Ingestion volume, graph size, and feed count are not measures of intelligence value by themselves.

### DECIDED

1. Threat knowledge is represented through typed entities and typed, temporal assertions.
2. Relationship strength and source confidence are orthogonal.
3. Source freshness is tracked per source where sources can age independently.
4. Parallel evidence paths remain independently inspectable.
5. Curated intelligence requires qualification and human approval before trusted publication.
6. Hunt Packs are executable knowledge packages, not the Artemis product itself.
7. CISA KEV will seed the first vulnerability-centered Hunt Pack after the executable local hunt path is ready.

## 4. Epistemic layers

| Layer | Meaning | Example |
| --- | --- | --- |
| Observation | What Artemis or a source actually saw or returned | SHA-256 X exists at path Y |
| Evidence | Why the observation may matter | Source Z reports X; YARA rule Q matched |
| Inference | What the evidence suggests | Artifacts are consistent with exploitation |
| Conclusion | Current judgment with visible uncertainty | Probable compromise, confidence high |
| Action | Human or authorized system decision | Expand hunt, acquire sample, escalate |

A record may advance through these layers only when the transition is explicit. Explanatory prose must not make an inference look like an observation.

## 5. Intelligence assertion contract

Every material assertion should carry, directly or through a stable referenced record:

- stable assertion identity;
- subject, predicate, and object;
- source identity and source record identifier;
- source URL or retrievable reference where licensing permits;
- evidence or extraction method;
- source confidence;
- relationship strength;
- first and last observed time where genuinely claimed;
- received or ingested time;
- valid-from and valid-until when applicable;
- publication and review state;
- supersession or retraction lineage;
- supporting evidence paths;
- known limitations;
- license and redistribution classification.

The contract must distinguish an observation time reported by the source from the time Artemis received the report. If only receipt time is known, it must be labeled as receipt time.

## 6. Strength and confidence

### Relationship strength

Relationship strength describes the mechanism connecting two concepts:

| Strength | Meaning |
| --- | --- |
| Direct | Exact or deterministic evidence directly establishes the relationship |
| Strong | Evidence tightly supports the relationship but does not directly prove it |
| Contextual | Evidence supports a relevant association or multi-hop inference |
| Weak | A low-specificity association worth exposing only with clear limitations |

### Source confidence

Source confidence describes confidence in the source assertion, not graph distance or match mechanism.

A low-confidence exact hash assertion remains **Direct**. A high-confidence filename resemblance remains **Weak**. Neither dimension may silently overwrite the other.

> **OPEN — Canonical source-confidence vocabulary and calibration.**

> **EVIDENCE REQUIRED — Compare current source semantics and real analyst decisions before standardizing a universal scale.**

## 7. Time, freshness, and validity

Artemis distinguishes:

- **observed time** — when the reported activity or fact was observed;
- **received time** — when Artemis obtained the record;
- **published time** — when the source published it;
- **valid time** — when an assertion is intended to apply;
- **superseded time** — when a newer assertion replaced it;
- **retracted time** — when the publisher or reviewer withdrew it.

A source sync failure must not look like an empty source. A stale source must not support a normal-looking "no match" result without its age being visible.

Indicators and infrastructure can decay or be reassigned. Expiration must reduce operational reliance without deleting historical truth.

> **OPEN — Default decay and expiration rules by intelligence class.**

## 8. Conflict, correction, and lineage

Artemis preserves conflicting assertions when they come from distinct sources or evidence paths. It must not use last-write-wins to select an attribution.

Lifecycle states:

- Draft
- Under Review
- Published
- Superseded
- Retracted
- Expired

A correction creates explicit lineage to the prior assertion. Retraction prevents continued trusted use while preserving the historical record needed to explain previous decisions.

## 9. Orion boundary

Threat Intelligence supplies Orion with typed knowledge, assertion semantics, temporal meaning, and complete evidence paths.

Orion owns reconstruction and traversal of those paths. Artemis hunt execution must select an authoritative Orion path or other authoritative intelligence object, not accept client-authored target, proof, graph direction, confidence, or evidence roles as truth.

A hunt result may be:

- confirming when positive evidence supports the hypothesis;
- contextual when evidence adds relevant but non-confirmatory context;
- contradicting only when actual falsifying evidence exists;
- inconclusive when coverage, access, freshness, scope, or evidence is insufficient.

A non-match, scan error, changed file, excluded path, stale source, or truncated scope is not contradicting evidence.

## 10. Hunt Pack doctrine

A Hunt Pack packages executable knowledge around a threat concept. It may reference:

- YARA and Sigma content;
- hashes and other indicators;
- paths and filename patterns;
- product and version conditions;
- registry and configuration checks;
- exploitation, persistence, and post-exploitation artifacts;
- relationships to CVEs, malware, actors, campaigns, and techniques;
- provenance and known limitations.

A Hunt Pack must not be trusted merely because it parses. Qualification must include:

- positive cases;
- negative cases;
- ambiguous cases;
- adversarial cases;
- schema and provenance validation;
- rule compilation;
- bounded performance;
- false-positive review;
- dependency and compatibility checks;
- human approval;
- versioning, rollback, expiration, and requalification.

Approval cannot precede the assessment it approves.

## 11. Source governance

No source becomes an authoritative Artemis dependency without a documented source profile covering:

- identity and publisher;
- purpose and expected value;
- access and authentication;
- licensing and redistribution;
- schema and normalization;
- timestamp and confidence semantics;
- provenance retention;
- correction and deletion behavior;
- freshness and failure handling;
- known limitations;
- validation evidence;
- owner and review cadence.

The source registry is the operational record for these profiles.

## 12. AI doctrine

Permitted uses include:

- extracting candidate entities and assertions for review;
- mapping source-specific fields into proposed normalized objects;
- summarizing multiple evidence paths;
- proposing hunt hypotheses and missing evidence;
- identifying possible conflicts or stale assertions.

Prohibited uses include:

- inventing a source, observation, indicator, attribution, or timestamp;
- automatically publishing unreviewed extracted assertions as trusted truth;
- collapsing source disagreement into an opaque score;
- presenting model confidence as source confidence;
- allowing generated prose to replace inspectable evidence.

Model output must be labeled, attributable to a model/version where material, and separable from authoritative evidence.

## 13. Commercial boundary

Free Artemis retains local intelligence inspection, provenance, source freshness, relationship truth, Hunt Pack creation and execution, qualification, import, and export.

Commercial Artemis may add organizational capabilities such as private registries, RBAC, approvals, audit, managed distribution, policy, fleet-scale governance, support, and licensed intelligence integrations.

> **OPEN — Licensing, registry operation, paid intelligence offerings, and third-party feed packaging.**

## 14. Immediate milestones

1. Publish the source-governance baseline for MalwareBazaar, ThreatFox, and local YARA.
2. Reconcile this Constitution with the Artemis and Chronos governing documents during the Apollo-to-Artemis constitutional migration.
3. Review the first executable HUNT pivot for evidence-role and absence semantics after it is updated from current main.
4. Define and qualify one CISA KEV-centered Hunt Pack.
5. Add sources only when they advance a validated hunt outcome.

## 15. Do not build yet

Until evidence and dependencies justify them, do not build:

- a generic threat-feed dashboard;
- a large Hunt Pack catalog before one pack is qualified end to end;
- a public marketplace or publisher reputation economy;
- opaque global confidence scoring;
- automatic actor or campaign attribution;
- AI-autopublished intelligence;
- a proprietary detection language;
- broad paid-feed integrations without buyer evidence;
- an unbounded ontology whose value is measured by graph size.

## 16. Open questions

### OPEN — Initial source portfolio

Which sources beyond the current baseline materially improve Artemis hunts?

**EVIDENCE REQUIRED:** Demonstrated improvement in a qualified hunt outcome, not feed popularity.

### OPEN — Intelligence expiration

Which assertion classes require expiration, decay, or continued historical availability?

**EVIDENCE REQUIRED:** Source behavior, indicator reassignment patterns, and analyst impact.

### OPEN — Registry model

Should Chronos operate a public Hunt Pack or intelligence registry?

**EVIDENCE REQUIRED:** Repeated external demand to publish, subscribe, share, or govern content.

### OPEN — Community trust

How should community contributions be reviewed without turning popularity into truth?

**EVIDENCE REQUIRED:** A working contribution flow and measured reviewer agreement.

## 17. Revision discipline

This Constitution changes only when the threat-intelligence trust model, workstream ownership, or core knowledge-to-hunt doctrine changes. Implementation details and source selections belong in roadmaps and source profiles.

Revise the epistemic drawer that changed. Do not promote a hypothesis to a decision merely because code exists for it.
