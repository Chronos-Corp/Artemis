import type { RelationshipStrength, ThreatRelationship } from "../types";
import {
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
                <div className="relationship-source">
                  {r.source} -- {r.confidence}% confidence
                  {r.report_title &&
                    (r.report_url ? (
                      <>
                        {" -- "}
                        <a href={r.report_url} target="_blank" rel="noreferrer">
                          {r.report_title}
                        </a>
                      </>
                    ) : (
                      ` -- ${r.report_title}`
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
