# Orion Structured Hunt Query Contract

*Architecture contract · Orion / Artemis · v0.1 draft · 22 August 2026*

Status: **PROPOSED, IMPLEMENTATION NOT AUTHORIZED**

This contract defines the stable boundary for analyst-defined Artemis hunts.
It complements the selector-only guided pivot in
`docs/orion-hunt-contract.md`. It does not define a proprietary textual query
language, a detection-rule language, or a backend-specific syntax.

## 1. Design doctrine

> A Hunt Query is a typed hypothesis applied to explicit evidence scope.

The transport is structured data. A visual builder, API client, Hunt Pack, or
standards adapter may produce it. Analysts do not need to learn an Artemis
syntax. Each execution backend translates the normalized structure into its
native capability or reports that it cannot execute a clause safely.

The contract preserves five separations:

1. request from execution plan;
2. observation from evidence and interpretation;
3. field selection from backend storage syntax;
4. query match from confirming or contradicting evidence;
5. Hunt Pack content from the engine contract that executes it.

## 2. Versioning and strictness

Every request carries `contract_version`. The first value is
`artemis.hunt-query/v1alpha1`.

Implementations must:

- reject an unknown version;
- reject duplicate JSON object keys before deserialization;
- reject unknown fields in contract-owned objects;
- reject null where a field is required or where omission has distinct
  meaning;
- reject values that do not match the registered field type;
- reject empty boolean groups, empty scopes, unbounded requests, and limits
  above policy;
- normalize before planning and fingerprint the normalized request;
- never silently discard or weaken an unsupported clause.

Canonicalization for hashing and signatures must use the organization's
adopted hardened JSON profile. A plan fingerprint is not computed from
whitespace, input key order, or UI labels.

## 3. Request model

The normative shape is shown as JSON for clarity. JSON is the wire encoding,
not a user-facing query language.

```json
{
  "contract_version": "artemis.hunt-query/v1alpha1",
  "hypothesis": {
    "statement": "Unsigned DLLs were recently introduced under ProgramData",
    "origin": "analyst"
  },
  "scope": {
    "kind": "local_filesystem",
    "roots": ["C:\\ProgramData"],
    "recursive": true
  },
  "where": {
    "all": [
      { "field": "artifact.type", "op": "eq", "value": "pe_dll" },
      { "field": "artifact.signature.status", "op": "eq", "value": "unsigned" },
      { "field": "artifact.observed_at", "op": "gte", "value": "2026-08-15T00:00:00Z" },
      {
        "not": {
          "field": "artifact.expectedness.class",
          "op": "eq",
          "value": "expected"
        }
      }
    ]
  },
  "select": [
    "artifact.identity",
    "artifact.path",
    "artifact.sha256",
    "artifact.signature.status",
    "artifact.observed_at"
  ],
  "bounds": {
    "max_examined": 20000,
    "max_results": 500,
    "max_errors": 100,
    "timeout_ms": 30000
  }
}
```

### 3.1 Hypothesis

`hypothesis.statement` is analyst-facing context. It is not executable and
must never be parsed to add predicates. `origin` is one of:

- `analyst`
- `orion_pivot`
- `hunt_pack`
- `standards_adapter`

An origin may add a typed `origin_ref`, such as an opaque `trace_path_id`, a
versioned Hunt Pack identifier, or an imported rule identifier. The reference
does not grant authority to alter the executable clauses.

### 3.2 Scope

Scope is mandatory and authorized independently from the filter.

Initial scope kind:

- `local_filesystem`: one or more explicit roots plus recursive or direct-child
  traversal.

Reserved future kinds include host, fleet, process, identity, network, cloud,
and external evidence source. A reserved name is not implemented capability.
Unknown or unavailable kinds fail before execution.

The normalized execution plan must bind scope to authorized object identities
or backend snapshot identifiers. A pathname, host label, tenant label, or
source name alone is not sufficient authorization evidence.

### 3.3 Boolean expression

The `where` tree has only four node shapes:

- predicate: `field`, `op`, `value`;
- `all`: every child must match;
- `any`: at least one child must match;
- `not`: the child must not match.

Maximum depth, node count, value size, and list cardinality are policy-bounded
and disclosed by the planner. Groups preserve boolean meaning but input order
does not affect plan identity after normalization.

### 3.4 Evaluation semantics

Predicate evaluation has three outcomes: `match`, `no_match`, and `unknown`.
Missing, inaccessible, malformed, stale, or source-partial values evaluate to
`unknown`, not `no_match`.

Boolean composition uses these rules:

- `not unknown` is `unknown`;
- `all` is `no_match` when any child is `no_match`, `match` when every child
  is `match`, and otherwise `unknown`;
- `any` is `match` when any child is `match`, `no_match` when every child is
  `no_match`, and otherwise `unknown`;
- `neq` and `not_in` require a present, valid value. They do not match a
  missing field;
- only `exists` tests presence directly.

An `unknown` top-level result is counted as inconclusive. It is never returned
as a positive match or interpreted as falsification. This prevents negation
from turning absent telemetry into apparent evidence.

### 3.5 Operators

The core operator registry is intentionally small:

| Operator | Valid field types | Meaning |
| --- | --- | --- |
| `eq`, `neq` | scalar | Typed equality or inequality |
| `in`, `not_in` | scalar against bounded list | Typed membership |
| `lt`, `lte`, `gt`, `gte` | number, timestamp, version where registered | Typed ordering |
| `contains` | string, typed set | Literal containment |
| `starts_with`, `ends_with` | string | Literal prefix or suffix |
| `matches` | fields whose registry explicitly permits patterns | Bounded registered pattern engine |
| `exists` | any registered field | Presence, not truthiness |

Operators do not accept executable code, backend fragments, shell syntax, SQL,
regular expressions unless the field registry names a bounded common pattern
profile, or arbitrary functions. An adapter cannot reinterpret `contains` as a
backend-specific token search if that changes semantics.

### 3.6 Field registry

Fields are stable semantic identifiers, independent from database columns,
UI labels, and backend-native field names. Every registered field declares:

- identifier and description;
- scalar or collection type;
- normalization and comparison rules;
- allowed operators;
- evidence layer and node family;
- source authority and provenance requirements;
- sensitivity and egress classification;
- backend mappings and known semantic loss;
- version and deprecation state.

The initial implementation may admit only fields already produced
authoritatively by Artemis. Candidate domains include artifact identity, path,
hashes, type, size, timestamps, signature status, product context,
expectedness, and typed RELATE relationships, but each field must pass the
registry gate independently. Expectedness or product context cannot be exposed
merely because a display model or constitutional example names it. A UI-only
display value cannot become queryable until it has an authoritative field
definition.

## 4. Normalized execution plan

The backend compiles an accepted request into a plan. The request is analyst
intent; the plan is the exact authorized work Artemis intends to perform.

The plan must contain:

- contract version and normalized request fingerprint;
- plan version and plan fingerprint;
- authorized scope bindings;
- resolved field and operator definitions;
- selected backend adapters and their versions;
- intelligence, rule, catalog, and corpus snapshot identities;
- pushdown clauses and locally evaluated clauses;
- explicit unsupported clauses;
- time and resource bounds;
- result field projection;
- expected partiality before execution;
- authorization decision reference and audit context.

Execution is prohibited when any required clause is unsupported. A future
explicit best-effort mode would be a separate contract decision and must never
be inferred from backend limitations.

### Plan identity

The plan fingerprint includes every semantic input that can change what is
examined or matched. It excludes display labels, serialization whitespace,
object key order, and non-semantic diagnostic text. A backend, field registry,
scope binding, policy bound, corpus snapshot, or normalized predicate change
must change the fingerprint.

## 5. Result model

A result returns structured evidence, not a generic row list.

```text
HuntQueryResult
  contract_version
  request_fingerprint
  plan_fingerprint
  started_at / completed_at
  scope_receipt
  corpus_receipts[]
  observations[]
  errors[]
  summary
  bounds
  limitations[]
```

Every observation must include:

- stable observation identity;
- typed subject identity and node family;
- the fields that matched and their normalized values;
- source and collection method;
- event time when known, observation time, and receipt time;
- backend and corpus snapshot identity;
- field-level provenance where values came from different authorities;
- applicable rule or Hunt Pack version;
- scope receipt and plan fingerprint;
- partiality, uncertainty, and collection errors affecting interpretation.

A matched predicate means only that the observation satisfied the executed
condition. It does not automatically mean malicious, confirming,
contradicting, or safe.

### Result selection and ordering

Scope enumeration, observation comparison, and response truncation must be
deterministic for the same plan and corpus receipts. `max_results` applies
after matching observations are compared by a stable typed key, not by thread
completion, database accident, or backend arrival order. If a remote backend
applies its own earlier limit, Artemis records that limit as upstream
partiality and does not claim the returned set is the globally first or best
set.

### Evidence roles

Evidence roles require an explicit typed assertion supplied by a qualified
Hunt Pack, an authoritative Orion path, or another governed source:

- `confirming`: the observation satisfies a typed support condition;
- `contradicting`: the observation satisfies a typed falsification condition;
- `contextual`: the observation is relevant but neither proves nor falsifies;
- no role: the query matched, with interpretation left open.

Absence, an empty result, an unsupported clause, an inaccessible source, a
timeout, or truncation can never create contradicting evidence.

## 6. Orion integration

Query results enter Orion through the same evidence discipline as guided
pivots:

1. observations become typed INVESTIGATION or domain nodes only when identity
   rules exist;
2. edges reference the exact observation and source evidence;
3. query match is not promoted to an observed threat path without a typed
   relationship assertion;
4. plan and corpus fingerprints remain attached to supporting evidence;
5. partial execution remains partial after graph projection;
6. an Orion Pivot may produce a structured query by binding a path selector to
   a scope and registered predicates, but the client cannot rewrite the path's
   target, proof, or orientation.

## 7. Standards and backend interoperability

Artemis owns this typed boundary because it must preserve evidence semantics
across backends. It does not own a replacement for established query and
detection ecosystems.

- YARA remains the portable file-content rule format.
- Sigma remains a portable detection rule format.
- Backend adapters may target SQL, KQL, EQL, osquery SQL, SIEM APIs, EDR APIs,
  or other established systems.
- Imports preserve original content identity, version, source, and translation
  diagnostics.
- A translation that cannot preserve semantics fails or reports the clause as
  unsupported. It does not silently approximate.
- Native backend escape hatches are outside this core contract. If later
  required, they must be isolated, labeled non-portable, separately
  authorized, and never embedded into portable Hunt Packs.

This structured representation is therefore an interoperability IR and API
contract, not a proprietary practitioner language.

## 8. Hunt Pack binding

A Hunt Pack may bind:

- a versioned structured query template;
- YARA or Sigma content by immutable identity;
- required field and operator capabilities;
- parameter types and constraints;
- support, falsification, and contextual evidence conditions;
- source, authorship, qualification, expiry, and conflict metadata;
- safe default bounds.

Threat Intelligence owns whether those assertions and contents are qualified.
Orion owns whether the resulting graph and selector semantics are valid.
Artemis Engineering owns safe execution. A pack cannot include arbitrary
Artemis script or untyped backend text in the portable contract.

## 9. Failure and partiality

Failures are machine-readable and phase-specific:

- request validation;
- authorization;
- field or operator resolution;
- backend capability;
- plan construction;
- collection;
- local evaluation;
- result normalization;
- Orion projection.

The result reports examined, matched, returned, inconclusive, omitted, and
errored counts where knowable. Every fired bound is explicit. A failed or
partial source cannot disappear from the response merely because another
source returned matches.

## 10. Security requirements

- File contents remain local unless an explicit authorized action permits
  egress.
- Hashes and metadata follow source and tenant policy.
- Scope authorization is evaluated before planning and revalidated at the
  execution boundary.
- Backends receive only the fields and predicates necessary for their plan.
- Query text, patterns, paths, and imported content are untrusted input.
- Pattern matching, recursion, fan-out, result size, execution time, and memory
  are bounded.
- Secrets and credentials never enter the portable request, plan fingerprint,
  result, or Hunt Pack.
- Audit records bind actor, authorization, normalized request, plan, scope,
  backend, corpus, and outcome.

## 11. First implementation slice

The first implementation should be a local-filesystem structured query over
the existing immutable snapshot resolver. It should reuse PR #23's capability
root, no-follow traversal, mutation detection, bounded hashing, intelligence
read snapshot, and partiality rules.

Minimum acceptance demonstration:

1. express the Constitution's unsigned-recent-DLL-under-ProgramData example;
2. validate and normalize the request strictly;
3. produce a stable plan fingerprint and authorized scope receipt;
4. execute only registered fields and operators;
5. return evidence-bearing observations with explicit bounds and limitations;
6. reject an unsupported field or operator without weakening the query;
7. prove that an empty or truncated result is not labeled safe or
   contradicting;
8. show how a qualified Hunt Pack binds typed support or falsification without
   introducing a new detection language.

UI design and Hunt Pack intelligence content are separate workstreams. The
first slice may expose an API and test fixtures before a visual builder exists.

## 12. Deferred decisions

The following remain **OPEN** pending practitioner or implementation evidence:

- adoption of any practitioner-facing textual query language;
- the first non-filesystem backend;
- cross-backend joins and distributed planning;
- saved-query lifecycle and sharing;
- best-effort execution semantics;
- graph persistence;
- query cost estimation beyond hard bounds;
- commercial entitlements.
