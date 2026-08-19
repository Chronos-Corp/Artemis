# Orion Executable HUNT Contract

Status: **first local executable pivot**

This contract governs how one analyst-selected Orion TRACE path becomes a
bounded Artemis HUNT over a local filesystem subtree. It is deliberately
narrow: proving the evidence boundary matters more than introducing a general
query language or remote executor.

## 1. Request authority

The desktop command accepts exactly:

| Field | Meaning | Security property |
| --- | --- | --- |
| `seed_path` | Selected local artifact | Re-resolved by the backend |
| `expected_seed_sha256` | Hash shown with the selected TRACE | Fails if the seed changed |
| `trace_path_id` | Opaque ID of one server-built path | Must match exactly one reconstructed path |
| `scope.kind` | `subtree` | Unknown kinds fail deserialization |
| `scope.root` | Explicit local directory | Canonicalized; seed must be contained |

The caller cannot submit a relationship kind, target, edge direction, proof
chain, source confidence, or evidence role. Those values come only from the
fresh Rust-side RELATE and TRACE result.

`TracePath.id` is a SHA-256 identity over the seed artifact identity,
relationship identity, path state and rank, typed node/edge identities,
assertion orientation, proof identity, effective detection fingerprint, and
declared partiality. Display labels and observation-window timestamps are
excluded so a new observation of unchanged evidence does not immediately
invalidate an analyst selection.

## 2. Execution sequence

1. Validate the request and lowercase SHA-256 form.
2. Canonicalize seed and scope; require a directory scope containing the seed.
3. Discover regular files deterministically without following symbolic links.
4. Acquire one intelligence read snapshot for the complete hunt.
5. Revalidate and re-resolve the original seed path, then require the expected
   hash.
6. Reconstruct TRACE and require one exact `trace_path_id` match.
7. Revalidate each candidate and run the existing authoritative resolver.
8. Match the selected typed relationship kind and canonical target.
9. Return the best matching safe path with complete RELATE proof and disclose
   every partiality or execution error.

The original seed is excluded from candidate findings. File contents remain on
the host.

The seed hash pin is enforced immediately after the resolver's atomic file
read and before YARA scanning or observation persistence. A changed seed can
update the ordinary path/hash cache with its accurately observed digest, but
it cannot write hunt-derived detection evidence before the request fails.

## 3. Evidence roles

| Matching candidate path | HUNT role | Meaning |
| --- | --- | --- |
| `observed` | `confirming` | Typed sourced assertions support the same concept |
| `possible` | `contextual` | A contextual association is worth analyst attention |
| No matching safe path | no finding | Inconclusive; not contradiction and not clean |

`contradicting` is reserved in the result schema but the initial executor does
not emit it. Contradiction requires a future typed falsification primitive; an
absence, scan failure, unwalked file, or truncated scope cannot supply one.
If RELATE omitted concepts, TRACE omitted paths, or the matching relationship
cannot be safely projected, that candidate is explicitly counted as
inconclusive rather than disappearing as a plain non-match.

## 4. Bounds and partiality

| Bound | Initial value |
| --- | ---: |
| Candidate files | 1,000 |
| Walked filesystem entries | 20,000 |
| Returned findings | 100 |
| Returned errors | 100 |

The response contains fired-bound flags and omitted finding/error counts.
Summary finding counts are computed before response truncation. RELATE and
TRACE partiality also remain attached to every supporting path.

## 5. Consistency and filesystem safety

One `IntelGate` read guard spans seed and candidate resolution. Feed sync must
wait, preventing a single hunt from combining different intelligence corpora.
The resolver variant used inside that guard does not reacquire the fair lock,
which avoids a self-deadlock behind a queued writer.

Filesystem discovery is bounded and deterministic. Symbolic links are not
followed, canonical paths must remain under the scope root, and each candidate
is canonicalized again immediately before analysis. The existing file resolver
then opens only a bounded regular file and rejects special or changed final
objects.

The filesystem is nevertheless live, not an immutable snapshot. A concurrent
rename or intermediate-path replacement can make a candidate change between
checks. Such failures are returned as inconclusive. This version makes no
race-free snapshot or complete-scope claim.

## 6. Result contract

The response returns:

- the server-reconstructed seed node and selected path;
- the canonical execution scope;
- ranked findings with artifact path, hashes, role, strength, complete best
  supporting path, and an additional-matching-path count;
- per-item scan errors up to the error bound;
- analyzed, inconclusive, and evidence-role counts;
- resource bounds, truncation state, and omitted counts;
- explicit interpretation limitations and execution timestamps.

Findings sort by evidence role, relationship strength, weakest source
confidence, hop count, then artifact path. Ranking components remain separate
and inspectable.

## 7. Exclusions

This slice adds no general Hunt Pack language, database migration, persisted
graph, remote agent transport, cross-host identity, AI inference, automatic
remediation, or compromise verdict. Those require separate architecture and
authorization decisions.
