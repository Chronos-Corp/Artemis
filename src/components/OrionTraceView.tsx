import type {
  OrionTrace,
  TracePath,
  UntracedRelationship,
} from "../types";
import { TRACE_EDGE_LABELS } from "../types";

interface Props {
  relationshipIndex: number;
  trace: OrionTrace;
}

const UNTRACED_LABELS: Record<UntracedRelationship["reason"], string> = {
  empty_proof: "RELATE supplied no proof chain.",
  mixed_proof_shape: "Supporting proof paths do not share one safe typed shape.",
  unsupported_relationship_shape: "This relationship shape is not supported by First Useful Trace yet.",
  missing_node_identity: "A required typed node identity is missing.",
  inconsistent_proof_endpoints: "The proof hops disagree about a shared endpoint.",
};

function TracePathView({ path, ordinal }: { path: TracePath; ordinal: number }) {
  return (
    <div className={`orion-path orion-path-${path.state}`}>
      <div className="orion-path-header">
        <span className="orion-path-number">Path {ordinal}</span>
        <span className={`orion-state orion-state-${path.state}`}>
          {path.state === "observed" ? "Evidence-backed" : "Possible"}
        </span>
        <span className="orion-rank">
          weakest source {path.rank.weakest_source_confidence}%
        </span>
      </div>
      <div className="orion-chain">
        {path.nodes.map((node, index) => (
          <span key={node.id} className="orion-chain-segment">
            <span className={`orion-node orion-node-${node.kind}`}>
              <span className="orion-node-kind">{node.kind.replace(/_/g, " ")}</span>
              <code>{node.label}</code>
            </span>
            {index < path.edges.length && (
              <span className="orion-edge">
                <span aria-hidden="true">→</span>
                <span>{TRACE_EDGE_LABELS[path.edges[index].relation]}</span>
                {path.edges[index].assertion_orientation === "reversed" && (
                  <span className="orion-reversed">native assertion reversed</span>
                )}
              </span>
            )}
          </span>
        ))}
      </div>
      {path.supporting_evidence_partial && (
        <div className="evidence-truncated" role="status">
          More proof exists for this relationship than RELATE supplied to Orion.
        </div>
      )}
    </div>
  );
}

export function OrionTraceView({ relationshipIndex, trace }: Props) {
  const paths = trace.paths.filter((path) => path.relationship_index === relationshipIndex);
  const untraced = trace.untraced_relationships.find(
    (item) => item.relationship_index === relationshipIndex
  );

  return (
    <details className="orion-trace">
      <summary>
        Orion trace
        {paths.length > 0 && ` (${paths.length} ${paths.length === 1 ? "path" : "paths"})`}
      </summary>
      <div className="orion-trace-body">
        {paths.map((path, index) => (
          <TracePathView
            key={`${path.relationship_index}-${index}-${path.target}`}
            path={path}
            ordinal={index + 1}
          />
        ))}
        {untraced && (
          <div className="orion-untraced" role="status">
            <strong>Not traced.</strong> {UNTRACED_LABELS[untraced.reason]}
            Orion did not guess a path.
          </div>
        )}
        {trace.bounds.paths_truncated && (
          <div className="evidence-truncated" role="status">
            Orion reached its {trace.bounds.max_paths}-path budget and omitted {" "}
            {trace.bounds.omitted_paths} otherwise valid {trace.bounds.omitted_paths === 1 ? "path" : "paths"}.
          </div>
        )}
      </div>
    </details>
  );
}
