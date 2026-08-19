# RELATE → Orion Contract

Status: **implemented input contract on `main` through PR #21**

This document narrows the handoff between Artemis RELATE and Orion TRACE. It exists specifically so the relationship model does not accidentally promise directed graph semantics that belong to Orion.

Where older PR #19 comments, README prose, or implementation notes describe `evidence_paths` as literal file-to-target traversal paths, or describe `rule_fingerprint` as only the declaring-file/source identity, **this document is the authoritative post-#19 handoff contract**. Those descriptions record earlier implementation stages and must not be used as Orion API semantics.

## 1. Responsibility boundary

**RELATE owns:**

- evidence-backed relationship concepts;
- relationship strength as evidence-mechanism semantics, independent from source confidence;
- provenance, timing, source identity, and bounds/partiality;
- supporting evidence/proof chains that show why the relationship exists.

**Orion / TRACE owns:**

- directed graph node identity;
- explicit edge direction;
- forward/reverse traversal;
- path finding and path ranking;
- observed-path versus possible-path semantics;
- traversal APIs consumed by Hunt/Execute.

A `ThreatRelationship` is therefore **not itself an Orion path**.

## 2. `evidence_paths` are proof chains, not traversal paths

`ThreatRelationship.evidence_paths` carries one or more independently inspectable chains of evidence assertions supporting the relationship concept.

The `EvidenceRelation` value retains the native assertion direction of the evidence source/schema. For example:

- `DetectsIndicator` means `Detection → Indicator` in the evidence model;
- `ObservedInReport` means `Indicator → Report`;
- `ReportReferencesCve` means `Report → CVE`;
- `DetectionCoversCve` means `Detection → CVE`.

A Detection relationship for a selected file can therefore be supported by a `DetectsIndicator` assertion even though an Orion traversal from the selected artifact toward the Detection would traverse that evidence in reverse.

**Orion must never infer a directed traversal merely from the ordering of `evidence_paths` or from an `EvidenceRelation` name.** TRACE will construct explicit nodes/edges/directions while retaining the RELATE proof chain as evidence.

## 3. Relationship concept identity

The stable RELATE wire identity is:

`(kind, canonical target, strength, evidence-proof relation shape)`

Supporting source assertions become separate evidence paths under the same concept, subject to the explicit per-concept evidence budget.

### Contextual filenames

Contextual filename lookup is case-insensitive. RELATE therefore canonicalizes the relationship target to lowercase before coalescing and bounds propagation.

Example:

- source report: `FOO.EXE`
- source report: `foo.exe`
- selected file: `Foo.exe`

These are one weak contextual concept: `foo.exe`.

Original report/source spelling remains available in verdict provenance; casing does not create separate pivots.

## 4. YARA identity: source versus effective behavior

Two identities are deliberately distinct.

### Rule source identity

`rule_source_fingerprint` is the SHA-256 identity of the exact parsed source span for that rule declaration/body. It is useful for explanation and future dependency-aware versioning.

It is **not sufficient** as durable behavior identity because YARA permits rule-to-rule dependencies and global rules can gate other rules.

### Effective behavior/version identity

`rule_fingerprint` is the conservative durable identity used by live observations and version-scoped `Detection → CVE` coverage.

Current Phase-0 definition:

`SHA256(version-tag || rule_source_fingerprint || compiled_ruleset_fingerprint)`

Consequences:

- changing the rule itself changes effective identity;
- changing a helper/private rule changes effective identity for dependent rules;
- changing a global rule changes effective identity for other rules;
- changing an unrelated rule also changes effective identity today.

That last case is conservative over-invalidation, accepted intentionally for the current phase. It can create a false negative for old version-scoped coverage, but it cannot carry evidence across a ruleset semantic change without revalidation.

A later dependency-aware identity may narrow the ruleset component to the rule's transitive dependencies plus relevant global/module/engine context.

## 5. Version scope must fail closed

The database sentinel `rule_fingerprint = ''` means an assertion deliberately applies to **any rule version**.

It must never mean “the current observation's version could not be determined.”

The public YARA facade therefore validates that every compiled match has an effective fingerprint. If a matched rule lacks identity, the scan fails before that observation can be persisted. An internal identity failure cannot broaden into an `AnyVersion` assertion.

## 6. Current observation versus durable history

Each analyst-initiated live resolve is a new observation event.

PR #19's process-lifetime `RecentYaraHits` optimization is no longer allowed to suppress persistence across separate resolve calls. The authoritative RELATE resolver scopes that cache to one resolve invocation so repeated scans can advance durable `last_seen`.

This is required before Sustain/Retrohunt treats persisted observation windows as temporal truth.

## 7. UI attribution invariant

Analysis results must render only under the file selection that initiated them.

Frontend detail requests use a monotonically increasing selection epoch. A response/error/loading completion from an older file is ignored after a newer selection or directory navigation supersedes it.

This prevents an asynchronous response for file A from being displayed under file B.

## 8. Orion consumption gate

Before First Useful Trace treats RELATE as traversal input, Orion must:

1. create explicit node identities for artifact/indicator/report/detection/CVE/etc.;
2. create explicit directed edges rather than reusing `evidence_paths` as if they were already directed;
3. retain the supporting RELATE proof chain and its provenance on/alongside the traversal edge;
4. preserve observed-versus-inferred/possible-path distinctions;
5. honor `has_more_evidence` and verdict relationship partiality rather than treating bounded results as exhaustive.

## 9. Validation discipline

Issue #20 hardening is implemented outside PR #19's frozen scope. The stacked implementation must receive exact-head Rust, frontend, database-migration, and supply-chain checks before it can be retargeted to `main` after PR #19 merges.

Regression tests should protect semantic boundaries rather than only implementation branches: case-insensitive contextual identity, YARA source-versus-effective identity, fail-closed version identity, and stable proof-chain semantics are contract tests for Orion's future consumer boundary.

During PR #21 validation, the supply-chain gate detected newly published `RUSTSEC-2026-0258` against locked `h2 0.4.15`. The repository takes the fixed `h2 0.4.16` lockfile update rather than adding an audit suppression. The committed lockfile delta is intentionally limited to the `h2` version and checksum so unrelated resolver churn is not smuggled into the hardening PR. This dependency change is security maintenance discovered by the gate, not part of the RELATE ontology itself.

The governing rule remains:

> **Artemis observes and structures evidence. Orion traces relationships. Evidence proves.**

## 10. First Useful Trace consumer

`crates/nsic-core/src/orion.rs` is the first consumer of this contract. It
projects the normalized RELATE result into typed nodes and explicitly directed
edges, records native versus reversed assertion orientation, preserves each
supporting proof chain alongside the traversal, separates observed from
possible paths, and carries both RELATE and Orion bounds forward.

See `docs/orion-architecture.md` for the governing Orion decisions and the
next Hunt/Execute boundary.
