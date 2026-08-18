import type { VerdictWithCoverage } from "../analysisCoverage";
import type { FileEntry, FileIntelligence, IntelSourceFreshness } from "../types";
import { TIER_LABELS } from "../types";
import { formatDate, formatRelativeTime } from "../format";
import { safeExternalUrl } from "../lib/safeUrl";
import { FileIntelPanel } from "./FileIntelPanel";
import { ThreatRelationshipList } from "./ThreatRelationshipList";

interface Props {
  file: FileEntry | null;
  verdict: VerdictWithCoverage | null;
  loading: boolean;
  error: string | null;
  fileIntel: FileIntelligence | null;
  fileIntelLoading: boolean;
  fileIntelError: string | null;
}

const INTEL_STALENESS_HOURS = 24;

function isStale(freshness: IntelSourceFreshness): boolean {
  if (!freshness.last_successful_sync_at) return false;
  const syncedAt = new Date(freshness.last_successful_sync_at).getTime();
  if (Number.isNaN(syncedAt)) return false;
  const ageHours = (Date.now() - syncedAt) / (60 * 60 * 1000);
  return ageHours > INTEL_STALENESS_HOURS;
}

function IntelCoverage({ sources }: { sources: IntelSourceFreshness[] }) {
  if (sources.length === 0) {
    return (
      <div className="intel-coverage intel-coverage-empty">
        No feed has completed a sync yet -- this verdict has no threat-intel
        feed coverage. Local analysis coverage is reported separately below.
      </div>
    );
  }
  return (
    <div className="intel-coverage">
      <div className="intel-coverage-label">Intel coverage</div>
      <ul>
        {sources.map((s) => {
          const never = !s.last_successful_sync_at;
          const stale = !never && isStale(s);
          const status = never ? "err" : stale ? "warn" : "ok";
          const icon = never ? "✗" : stale ? "⚠" : "✓";
          return (
            <li key={s.source} className={`intel-source intel-source-${status}`}>
              <span className="intel-source-icon">{icon}</span> {s.source} --{" "}
              {never
                ? "never successfully synced"
                : `synced ${formatRelativeTime(s.last_successful_sync_at)}`}
            </li>
          );
        })}
      </ul>
    </div>
  );
}

function YaraCoverageNotice({ verdict }: { verdict: VerdictWithCoverage }) {
  if (verdict.yara_coverage.status === "failed") {
    return (
      <div className="verdict-truncated" role="status">
        <strong>YARA coverage unavailable.</strong> The configured ruleset
        failed to load, so this verdict cannot make a negative claim about
        local YARA detections. Hash, path, contextual, and available
        relationship evidence are still shown.
        {verdict.yara_coverage.failure_reason && (
          <div>
            <strong>Reason:</strong> {verdict.yara_coverage.failure_reason}
          </div>
        )}
      </div>
    );
  }

  if (verdict.yara_coverage.status === "empty") {
    return (
      <div className="intel-coverage intel-coverage-empty" role="status">
        YARA coverage: no local rules are configured. This is a successful
        zero-rule configuration, not a failed ruleset, so this verdict has no
        YARA detection coverage.
      </div>
    );
  }

  return null;
}

export function VerdictPanel({
  file,
  verdict,
  loading,
  error,
  fileIntel,
  fileIntelLoading,
  fileIntelError,
}: Props) {
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

      <FileIntelPanel intel={fileIntel} loading={fileIntelLoading} error={fileIntelError} />

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

          <IntelCoverage sources={verdict.intel_freshness} />
          <YaraCoverageNotice verdict={verdict} />

          <ThreatRelationshipList
            relationships={verdict.threat_relationships}
            relationshipsTruncated={verdict.bounds.relationships_truncated}
          />

          {verdict.bounds.truncated_entry_tiers.length > 0 && (
            <div className="verdict-truncated" role="status">
              <strong>Partial evidence.</strong> More matching evidence exists
              than is shown for:{" "}
              {verdict.bounds.truncated_entry_tiers
                .map((tier) => TIER_LABELS[tier])
                .join(", ")}
              . This list is bounded, not complete -- treat it as a sample
              rather than the full picture.
            </div>
          )}

          {verdict.entries.length === 0 ? (
            <div className="verdict-no-match">
              {verdict.yara_coverage.status === "failed" ? (
                <>
                  No matching hash evidence, path pattern, or contextual
                  association was found in the available tiers. YARA was not
                  successfully checked because the configured ruleset failed
                  to load, so absence of a YARA detection is unknown. This is
                  not a guarantee the file is clean. See coverage above for
                  the exact analysis state.
                </>
              ) : verdict.yara_coverage.status === "empty" ? (
                <>
                  No matching hash evidence, path pattern, or contextual
                  association was found in the available tiers. No YARA rules
                  are configured, so this verdict contains no YARA detection
                  coverage. This is not a guarantee the file is clean. See
                  coverage above for the exact analysis state.
                </>
              ) : (
                <>
                  No matching hash evidence, YARA hit, path pattern, or
                  contextual association in any tier checked. Not a guarantee
                  the file is clean -- only that nothing in the current intel
                  store or loaded local rules flagged it. See intel coverage
                  above for how current that intel actually is.
                </>
              )}
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
                        {safeExternalUrl(entry.report_url) ? (
                          <a
                            href={safeExternalUrl(entry.report_url)!}
                            target="_blank"
                            rel="noreferrer"
                          >
                            {entry.report_title}
                          </a>
                        ) : (
                          entry.report_title
                        )}
                      </div>
                    )}
                    <div className="provenance-dates">
                      {entry.timing === "received_only" ? (
                        <>Report received {formatDate(entry.first_seen)}</>
                      ) : (
                        <>
                          First seen {formatDate(entry.first_seen)}, last seen{" "}
                          {formatDate(entry.last_seen)}
                        </>
                      )}
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
