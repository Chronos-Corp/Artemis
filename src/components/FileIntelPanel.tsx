import type { ExpectednessStatus, FileIntelligence } from "../types";
import { formatDate } from "../format";

interface Props {
  intel: FileIntelligence | null;
  loading: boolean;
  error: string | null;
}

const AUTHENTICITY_LABELS: Record<FileIntelligence["authenticity"]["status"], string> = {
  verified: "Verified against package",
  modified: "Modified since install",
  unpackaged: "Not owned by any package",
  unknown: "Unknown",
};

const EXPECTEDNESS_LABELS: Record<ExpectednessStatus, string> = {
  expected: "Expected",
  unexpected: "Unexpected",
  unknown: "Unknown",
};

function expectednessClass(status: ExpectednessStatus): string {
  if (status === "expected") return "expectedness-ok";
  if (status === "unexpected") return "expectedness-warn";
  return "expectedness-unknown";
}

function authenticityClass(status: FileIntelligence["authenticity"]["status"]): string {
  if (status === "verified") return "authenticity-ok";
  if (status === "modified") return "authenticity-warn";
  return "authenticity-unknown";
}

export function FileIntelPanel({ intel, loading, error }: Props) {
  if (loading) {
    return <div className="verdict-status">Reading file identity and package catalog...</div>;
  }
  if (error) {
    return <div className="verdict-status verdict-error">{error}</div>;
  }
  if (!intel) {
    return null;
  }

  const { identity, authenticity, product_context, purpose, expectedness, local_context } = intel;

  return (
    <div className="file-intel">
      <div className="file-intel-grid">
        <div className="file-intel-field">
          <span className="file-intel-label">Type</span> {identity.file_type}
        </div>
        <div className="file-intel-field">
          <span className="file-intel-label">Modified</span> {formatDate(identity.modified)}
        </div>
        {identity.is_hidden && <div className="file-intel-flag">Hidden</div>}
        {identity.is_executable && <div className="file-intel-flag">Executable</div>}
        {identity.is_symlink && <div className="file-intel-flag">Symlink</div>}
      </div>

      {identity.is_symlink && (
        <div className="file-intel-field">
          <span className="file-intel-label">Points to</span> {identity.symlink_target}
          <span className="file-intel-detail">
            {" "}
            -- authenticity below reflects this exact path, not the target
          </span>
        </div>
      )}

      <div className={`file-intel-status ${authenticityClass(authenticity.status)}`}>
        <span className="file-intel-status-label">Authenticity:</span>{" "}
        {AUTHENTICITY_LABELS[authenticity.status]}
        {authenticity.detail && <span className="file-intel-detail"> -- {authenticity.detail}</span>}
      </div>

      {product_context.package && (
        <div className="file-intel-field">
          <span className="file-intel-label">Package</span> {product_context.package}
          {product_context.version && ` (${product_context.version})`}
        </div>
      )}

      <div className="file-intel-purpose">{purpose.summary}</div>

      <div className={`file-intel-status ${expectednessClass(expectedness.status)}`}>
        <span className="file-intel-status-label">Expectedness:</span>{" "}
        {EXPECTEDNESS_LABELS[expectedness.status]}
        <ul className="file-intel-reasons">
          {expectedness.reasons.map((reason, i) => (
            <li key={i}>{reason}</li>
          ))}
        </ul>
      </div>

      {local_context.similarly_named_siblings.length > 0 && (
        <div
          className={`file-intel-status ${
            expectedness.status === "unexpected" ? "expectedness-warn" : "expectedness-unknown"
          }`}
        >
          <span className="file-intel-status-label">Similarly named nearby:</span>{" "}
          {local_context.similarly_named_siblings.join(", ")}
        </div>
      )}
    </div>
  );
}
