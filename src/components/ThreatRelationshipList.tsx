import type { RelationshipStrength, ThreatRelationship } from "../types";
import {
  EVIDENCE_RELATION_LABELS,
  RELATIONSHIP_KIND_LABELS,
  RELATIONSHIP_STRENGTH_LABELS,
  RELATIONSHIP_STRENGTH_ORDER,
} from "../types";

interface Props {
  relationships: ThreatRelationship[];
}

function strengthClass(strength: RelationshipStrength): string {
  if (strength === "direct") return "strength-direct";
  if (strength === "strong") return "strength-strong";
  if (strength === "contextual") return "strength-contextual";
  return "strength-weak";
}

// Groups by kind (IOC, CVE, Malware family, ...), strongest relationship
// first within each group -- the Constitution's Open·3 concern is exactly
// this: "related to" must not flatten into an unbounded, unordered list an
// analyst has to triage by hand.
export function ThreatRelationshipList({ relationships }: Props) {
  if (relationships.length === 0) {
    return null;
  }

  const byKind = new Map<string, ThreatRelationship[]>();
  for (const r of relationships) {
    const group = byKind.get(r.kind) ?? [];
    group.push(r);
    byKind.set(r.kind, group);
  }
  for (const group of byKind.values()) {
    group.sort(
      (a, b) =>
        RELATIONSHIP_STRENGTH_ORDER.indexOf(a.strength) -
        RELATIONSHIP_STRENGTH_ORDER.indexOf(b.strength)
    );
  }

  return (
    <div className="threat-relationships">
      <div className="threat-relationships-label">Threat relationships</div>
      {Array.from(byKind.entries()).map(([kind, group]) => (
        <div key={kind} className="relationship-group">
          <div className="relationship-group-label">
            {RELATIONSHIP_KIND_LABELS[kind as ThreatRelationship["kind"]]}
          </div>
          <ul className="relationship-list">
            {group.map((r, i) => (
              <li key={i} className="relationship-entry">
                <div className="relationship-header">
                  <code className="relationship-target">{r.target}</code>
                  <span className={`strength-badge ${strengthClass(r.strength)}`}>
                    {RELATIONSHIP_STRENGTH_LABELS[r.strength]}
                  </span>
                </div>
                <div className="relationship-explanation">{r.explanation}</div>
                {/* One block per evidence path -- most relationships have
                    exactly one, but a Cve relationship can have more than
                    one when a report observed this file under more than
                    one hash (or via more than one source) before
                    converging on the same CVE assertion. Rendering each
                    path as its own block (rather than flattening every
                    hop across every path into one list) keeps each
                    path's own chain reconstructable -- a review caught
                    that flattening made two parallel first hops sharing
                    one second hop look like a single, longer linear
                    chain. */}
                <div className="relationship-evidence">
                  {r.evidence_paths.map((path, pi) => (
                    <div key={pi} className="evidence-path">
                      {r.evidence_paths.length > 1 && (
                        <div className="evidence-path-label">Path {pi + 1}</div>
                      )}
                      {path.map((e, j) => (
                        <div key={j} className="evidence-hop">
                          {path.length > 1 && (
                            <span className="evidence-relation">
                              {EVIDENCE_RELATION_LABELS[e.relation]}:{" "}
                            </span>
                          )}
                          {e.source} -- {e.confidence}% confidence
                          {e.detection_name && ` -- ${e.detection_name}`}
                          {e.indicator_value && ` -- ${e.indicator_value}`}
                          {e.report_title &&
                            (e.report_url ? (
                              <>
                                {" -- "}
                                <a href={e.report_url} target="_blank" rel="noreferrer">
                                  {e.report_title}
                                </a>
                              </>
                            ) : (
                              ` -- ${e.report_title}`
                            ))}
                        </div>
                      ))}
                    </div>
                  ))}
                </div>
              </li>
            ))}
          </ul>
        </div>
      ))}
    </div>
  );
}
