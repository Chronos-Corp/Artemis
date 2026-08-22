# Orion Constitutional Reconciliation

*Architecture assessment · Orion / Artemis · 22 August 2026*

Baseline: Artemis `main` at `31e41e98f6cc643de2a2ae7f8ac58cf60b423231`.

This assessment reconciles the merged First Executable HUNT Pivot with the
Artemis Product Constitution, especially sections 4, 7, 8, 10, 13, and 15
through 17. It records architectural state. It does not convert staged scope
into a product defect or silently promote an open constitutional question into
a settled product decision.

## 1. Governing boundary

> **LOCKED: Artemis hunts. Orion traces. Chronos reasons.**

Orion is the relational subsystem inside Artemis. It owns typed graph
semantics, path identity, traversal, selector integrity, and the contract by
which a trace becomes an executable hunt hypothesis. It does not own Threat
Intelligence assertions, provider approval, the analyst interface, evidence
collection backends, or Chronos cognitive memory.

## 2. Reconciliation result

The merged implementation is **CONFORMING WITH DECLARED PARTIAL SCOPE**. No
constitutional contradiction requires reopening PR #23. The implementation
delivers the first safe vertical slice and explicitly refuses unsupported
semantics. The Constitution describes a larger destination that remains
partially implemented.

| Constitutional requirement | Current state | Disposition |
| --- | --- | --- |
| Orion remains inside Artemis | Implemented | **CONFORMING** |
| Typed, directed, evidence-aware paths | Implemented for safe RELATE proof shapes | **CONFORMING, PARTIAL ONTOLOGY** |
| Source, confidence, time, method, and freshness remain explainable | Supporting RELATE proof is retained and proof-backed edges index it | **CONFORMING FOR PATH RESULTS** |
| Possible and observed paths remain distinct | `TracePathState::{Possible, Observed}` and assertion orientation are explicit | **CONFORMING** |
| Important relationships are navigable | IOC, Detection, CVE, Malware Family, and contextual risk projections are navigable; unsupported shapes fail closed | **CONFORMING, PARTIAL COVERAGE** |
| A trace can become a scoped hunt | Opaque selector, pinned seed, server reconstruction, and bounded subtree execution are implemented | **CONFORMING** |
| Recursive scope is first-class | Local filesystem subtree is implemented with explicit bounds and partiality | **CONFORMING, LOCAL ONLY** |
| No match is not safe | Non-match, uncertainty, truncation, and scan failure remain inconclusive | **CONFORMING** |
| Analyst-defined Hunt Query | Not implemented | **OPEN IMPLEMENTATION GAP** |
| Cross-layer evidence | Not implemented | **OPEN EXPANSION GATE** |
| Retrotrace and historical reinterpretation | Not implemented | **OPEN, DEPENDS ON SUSTAIN** |
| Typed contradiction | Reserved in the result model but not emitted | **OPEN SEMANTIC GAP** |

## 3. Node semantics

The Constitution's node families are an ontology envelope, not a requirement
that every representative entity become a concrete enum variant immediately.
The current projection implements these concrete kinds:

- `Artifact`
- `Indicator`
- `Report`
- `Detection`
- `Cve`
- `MalwareFamily`
- `RiskConcept`

These map into the constitutional ARTIFACT, THREAT, BEHAVIOR, and TIME / SOURCE
families. `Report` is currently a provenance-bearing source object. Time,
freshness, and rule version are currently evidence attributes rather than
standalone vertices. That is valid when no traversal needs an independent
time or source vertex.

### Node identity rule

A node identity is the stable identity of a typed entity, not its display
label, current confidence, freshness, or latest observation time.

Every future node kind must define:

1. a namespace;
2. a canonical identity key;
3. normalization rules;
4. the authority that supplied the key;
5. whether identity is local, tenant-scoped, source-scoped, or global;
6. collision and missing-identity behavior;
7. version semantics when the entity is mutable.

If those rules are not defined, Orion must refuse the projection with a
machine-readable reason. It must not derive identity from prose, array
position, or a UI label.

### Family expansion gate

A new node kind is admitted only when at least one accepted hunt requires it,
its identity can be made deterministic, and its evidence authority is known.
This prevents the constitutional ontology envelope from becoming a noisy list
of unused labels.

## 4. Edge semantics

An Orion edge is a directed traversal statement. It is not automatically the
same thing as the source assertion that supports traversal.

Every reusable edge envelope must make available:

- typed `from` and `to` node identities;
- a typed relation;
- native, reversed, or synthetic assertion orientation;
- zero or more evidence references, or an explicit reason why the edge is a
  synthetic bridge;
- the path state contributed by that edge;
- partiality inherited from its evidence.

The current wire representation satisfies these semantics in the context of
one `TracePath`: `TraceEdge.proof_hop_index` points to the complete sourced
proof retained beside the path, while the containing path carries state and
partiality. It is not yet a reusable graph-edge envelope because those values
and references are path-local. Before Orion merges edges across paths,
sessions, hosts, or retained history, the implementation must replace
path-local indexes with durable evidence references and preserve each
assertion's source, time, confidence, freshness, method, version, and scope.

### Assertion classes

Orion will not overload relationship strength as epistemic state. The graph
must keep these dimensions separate:

| Dimension | Current or target values | Meaning |
| --- | --- | --- |
| Traversal state | `observed`, `possible` | Whether typed sourced assertions support the traversed path |
| Assertion orientation | `native`, `reversed`, `synthetic` | How traversal relates to the source assertion |
| Relationship strength | `direct`, `strong`, `contextual`, `weak` | RELATE's evidence-mechanism classification |
| Source confidence | Numeric, per proof hop | The source's confidence, not a replacement for strength |
| Falsification | future typed assertion | Evidence that contradicts a claim, never mere absence |

Relationship-strength vocabulary remains constitutionally **OPEN** pending
practitioner evidence. Current enum values are an implemented contract, not a
claim that the UI wording is permanently settled.

## 5. Trace and selector identity

`TracePath.id` is an integrity-sensitive opaque selector for an exact
reconstructed path. It is not an authorization capability, database primary
key, user-authored identifier, or promise that a changed evidentiary claim
remains selectable.

The identity rules are:

1. include seed identity, canonical relationship identity, path state, rank,
   typed nodes and edges, assertion orientation, proof identity, effective
   detection identity, and declared partiality;
2. exclude display labels, relationship ordering, and observation-window
   timestamps;
3. change when evidence semantics, effective rule identity, path state, rank,
   or declared completeness changes;
4. remain stable when unrelated relationship ordering or a new observation of
   unchanged evidence changes;
5. carry a namespace version so a future identity definition cannot silently
   reinterpret an older selector;
6. be reconstructed and matched server-side exactly once;
7. fail closed as stale or ambiguous, with no fallback to target text.

These rules are implemented by the `orion-trace-path-v2` identity and the
selector-only HUNT request.

## 6. Hunt Query architecture disposition

The Constitution requires both guided relational pivots and analyst-defined
queries. PR #23 implements the first mode only. The next Orion architecture
gate is therefore the structured Hunt Query contract in
`docs/orion-hunt-query-contract.md`.

The contract is a versioned typed request and result model, not a textual
query language. It uses a field registry, ordinary boolean composition, typed
operators, explicit scope, explicit bounds, backend capability negotiation,
and evidence-preserving results. Backends may translate the structure into
their native query systems. Artemis will not invent a proprietary textual
syntax or make Hunt Packs depend on one.

## 7. Ownership and sequencing

### Orion Architecture owns

- node and edge admission rules;
- trace and selector identity;
- path stability and ranking semantics;
- structured Hunt Query request, plan, and result contracts;
- evidence-role, partiality, and typed-falsification boundaries;
- architecture review of execution implementations.

### Artemis Engineering owns

- implementation of accepted Orion and Hunt Query contracts;
- filesystem, process, identity, network, cloud, and external backend adapters;
- authorization enforcement, bounded execution, persistence effects, IPC, and
  UI integration;
- regression tests and CI for those implementations.

### Artemis Threat Intelligence owns

- assertions, sources, provenance quality, confidence, timing, conflicts, and
  Hunt Pack content qualification;
- the first governed KEV-backed Hunt Pack.

OA reviews Hunt Pack execution shape and Orion compatibility but does not
approve the truth of Threat Intelligence content.

## 8. Acceptance gates for the next implementation slice

An implementation of the structured Hunt Query contract is not acceptance
ready until it proves:

1. unknown fields, operators, versions, and scope kinds fail closed;
2. query execution never assigns confirming or contradicting roles without
   typed evidence;
3. backend translation reports unsupported clauses instead of weakening them;
4. field types and normalization are validated before execution;
5. authorization, scope, time, resource bounds, truncation, and corpus
   snapshots are returned;
6. the plan fingerprint is stable for the same normalized request and changes
   for semantic changes;
7. results can enter Orion without losing provenance or confusing observation
   with inference;
8. an imported Hunt Pack uses existing standards and checks rather than a new
   Artemis detection DSL;
9. all supported platforms and affected backends pass exact-head CI.

## 9. Deferred questions

The following remain **OPEN** or **EVIDENCE REQUIRED** and are not decided by
this reconciliation:

- practitioner-facing relationship-strength vocabulary;
- which cross-layer adapter should be first;
- BloodHound integration shape;
- retained graph versus on-demand projection;
- Retrotrace retention;
- remote execution transport;
- commercial packaging;
- whether practitioner demand justifies adopting an existing textual query
  language in addition to the structured contract.
