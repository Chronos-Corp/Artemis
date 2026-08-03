import type { FileEntry, Verdict } from "../types";
import { TIER_LABELS } from "../types";
import { formatDate } from "../format";

interface Props {
  file: FileEntry | null;
  verdict: Verdict | null;
  loading: boolean;
  error: string | null;
}

export function VerdictPanel({ file, verdict, loading, error }: Props) {
  if (!file) {
    return (
      <div className="verdict-panel verdict-empty">
        Select a file to see everything known about it.
      </div>
    );
  }

  return (
    <div className="verdict-panel">
      <h2 className="verdict-file-name">{file.name}</h2>
      <div className="verdict-path">{file.path}</div>

      {loading && <div className="verdict-status">Hashing and checking indicators...</div>}
      {error && <div className="verdict-status verdict-error">{error}</div>}

      {verdict && !loading && (
        <>
          <div className="verdict-hashes">
            <div>
              <span className="hash-label">SHA-256</span>
              <code>{verdict.sha256}</code>
            </div>
            <div>
              <span className="hash-label">MD5</span>
              <code>{verdict.md5}</code>
            </div>
          </div>

          {verdict.entries.length === 0 ? (
            <div className="verdict-clean">
              No matches in any tier checked (exact hash, fuzzy hash, YARA, path
              pattern, contextual). Not a guarantee the file is clean, only that
              nothing in the current intel store or local rules flagged it.
            </div>
          ) : (
            <ul className="provenance-list">
              {verdict.entries.map((entry, i) => (
                <li key={i} className={`provenance-entry tier-${entry.tier}`}>
                  <div className="provenance-header">
                    <span className="tier-badge">{TIER_LABELS[entry.tier]}</span>
                    <span className="confidence">{entry.confidence}% confidence</span>
                  </div>
                  <div className="provenance-body">
                    <div>
                      <strong>Source:</strong> {entry.source}
                    </div>
                    <div>
                      <strong>Matched:</strong> <code>{entry.matched_value}</code>
                    </div>
                    {entry.detection_name && (
                      <div>
                        <strong>Rule:</strong> {entry.detection_name}
                      </div>
                    )}
                    {entry.report_title && (
                      <div>
                        <strong>Report:</strong>{" "}
                        {entry.report_url ? (
                          <a href={entry.report_url} target="_blank" rel="noreferrer">
                            {entry.report_title}
                          </a>
                        ) : (
                          entry.report_title
                        )}
                      </div>
                    )}
                    {entry.cve_ids.length > 0 && (
                      <div>
                        <strong>CVEs:</strong> {entry.cve_ids.join(", ")}
                      </div>
                    )}
                    <div className="provenance-dates">
                      First seen {formatDate(entry.first_seen)}, last seen{" "}
                      {formatDate(entry.last_seen)}
                    </div>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </>
      )}
    </div>
  );
}
