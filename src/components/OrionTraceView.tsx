import type {
  HuntFinding,
  HuntResult,
  OrionTrace,
  TracePath,
  UntracedRelationship,
} from "../types";
import { TRACE_EDGE_LABELS } from "../types";

interface Props {
  relationshipIndex: number;
  trace: OrionTrace;
  huntResult?: HuntResult | null;
  huntingPathId?: string | null;
  huntSubjectPathId?: string | null;
  huntError?: string | null;
  huntScopeRoot?: string | null;
  onRunHunt?: (path: TracePath) => void;
}

const UNTRACED_LABELS: Record<UntracedRelationship["reason"], string> = {
  empty_proof: "RELATE supplied no proof chain.",
  mixed_proof_shape: "Supporting proof paths do not share one safe typed shape.",
  unsupported_relationship_shape: "This relationship shape is not supported by First Useful Trace yet.",
  missing_node_identity: "A required typed node identity is missing.",
  inconsistent_proof_endpoints: "The proof hops disagree about a shared endpoint.",
};

function HuntFindingView({ finding }: { finding: HuntFinding }) {
  const sources = Array.from(
    new Set(finding.supporting_path.supporting_proof.map((hop) => hop.source))
  );
  return (
    <li className={`hunt-finding hunt-finding-${finding.role}`}>
      <div className="hunt-finding-header">
        <span className={`hunt-role hunt-role-${finding.role}`}>{finding.role}</span>
        <code>{finding.artifact_path}</code>
      </div>
      <div className="hunt-finding-meta">
        {finding.strength} relationship · weakest source {" "}
        {finding.supporting_path.rank.weakest_source_confidence}% · {sources.join(", ")}
        {finding.additional_matching_paths > 0 &&
          ` · ${finding.additional_matching_paths} additional matching path${
            finding.additional_matching_paths === 1 ? "" : "s"
          }`}
      </div>
    </li>
  );
}

function HuntResultView({ result }: { result: HuntResult }) {
  return (
    <div className="hunt-result">
      <div className="hunt-result-title">Hunt complete</div>
      <div className="hunt-summary">
        Analyzed {result.summary.files_analyzed} of {result.summary.files_discovered} discovered
        files · {result.summary.confirming_findings} confirming · {" "}
        {result.summary.contextual_findings} contextual · {result.summary.files_inconclusive} {" "}
        inconclusive
      </div>
      {result.findings.length > 0 ? (
        <ul className="hunt-findings">
          {result.findings.map((finding) => (
            <HuntFindingView
              key={`${finding.artifact_path}-${finding.supporting_path.id}`}
              finding={finding}
            />
          ))}
        </ul>
      ) : (
        <div className="hunt-no-findings">
          No matching evidence was found in the analyzed portion of this scope. This is not a
          contradiction and not a clean verdict.
        </div>
      )}
      {(result.bounds.scope_truncated ||
        result.bounds.findings_truncated ||
        result.bounds.errors_truncated) && (
        <div className="evidence-truncated" role="status">
          Results are partial.
          {result.bounds.scope_truncated && ` The ${result.bounds.max_files}-file scope bound fired.`}
          {result.bounds.findings_truncated &&
            ` ${result.bounds.omitted_findings} ranked findings were omitted.`}
          {result.bounds.errors_truncated &&
            ` ${result.bounds.omitted_errors} item errors were omitted.`}
        </div>
      )}
      {result.scan_errors.length > 0 && (
        <details className="hunt-errors">
          <summary>
            {result.summary.files_inconclusive} inconclusive filesystem {" "}
            {result.summary.files_inconclusive === 1 ? "item" : "items"}
          </summary>
          <ul>
            {result.scan_errors.map((error, index) => (
              <li key={`${error.path}-${index}`}>
                <code>{error.path}</code>: {error.error}
              </li>
            ))}
          </ul>
        </details>
      )}
      <details className="hunt-limitations">
        <summary>Interpretation limits</summary>
        <ul>
          {result.limitations.map((limitation) => (
            <li key={limitation}>{limitation}</li>
          ))}
        </ul>
      </details>
    </div>
  );
}

function TracePathView({
  path,
  ordinal,
  huntResult,
  hunting,
  huntInProgress,
  huntError,
  huntScopeRoot,
  onRunHunt,
}: {
  path: TracePath;
  ordinal: number;
  huntResult?: HuntResult | null;
  hunting: boolean;
  huntInProgress: boolean;
  huntError?: string | null;
  huntScopeRoot?: string | null;
  onRunHunt?: (path: TracePath) => void;
}) {
  const resultForPath = huntResult?.hypothesis.selected_path.id === path.id ? huntResult : null;
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
      {onRunHunt && huntScopeRoot && (
        <div className="hunt-action">
          <button type="button" disabled={huntInProgress} onClick={() => onRunHunt(path)}>
            {hunting ? "Hunting…" : "Hunt current subtree"}
          </button>
          <span>
            Scope: <code>{huntScopeRoot}</code> · local reads only · bounded to 1,000 files
          </span>
        </div>
      )}
      {hunting && <div className="hunt-running">Applying this hypothesis to the subtree…</div>}
      {huntError && <div className="verdict-status verdict-error">{huntError}</div>}
      {resultForPath && <HuntResultView result={resultForPath} />}
    </div>
  );
}

export function OrionTraceView({
  relationshipIndex,
  trace,
  huntResult,
  huntingPathId,
  huntSubjectPathId,
  huntError,
  huntScopeRoot,
  onRunHunt,
}: Props) {
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
            huntResult={huntResult}
            hunting={huntingPathId === path.id}
            huntInProgress={huntingPathId !== null && huntingPathId !== undefined}
            huntError={huntSubjectPathId === path.id ? huntError : null}
            huntScopeRoot={huntScopeRoot}
            onRunHunt={onRunHunt}
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
