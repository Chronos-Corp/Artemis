import type { YaraStatusWithCoverage } from "../analysisCoverage";
import type { DbStatus, FeedSyncResult, IntelSourceFreshness } from "../types";
import { formatDate } from "../format";

interface Props {
  dbStatus: DbStatus | null;
  yaraStatus: YaraStatusWithCoverage | null;
  syncStates: IntelSourceFreshness[];
  syncing: boolean;
  lastSyncResults: FeedSyncResult[] | null;
  onSync: () => void;
}

export function StatusBar({
  dbStatus,
  yaraStatus,
  syncStates,
  syncing,
  lastSyncResults,
  onSync,
}: Props) {
  const yaraClass =
    yaraStatus?.status === "failed"
      ? "bad"
      : yaraStatus?.status === "loaded"
        ? "ok"
        : "";
  const yaraLabel = !yaraStatus
    ? "loading"
    : yaraStatus.status === "failed"
      ? "unavailable"
      : yaraStatus.status === "empty"
        ? "0 rules configured"
        : `${yaraStatus.rule_count} rule file(s)`;

  return (
    <div className="status-bar">
      <div className="status-items">
        <span className={`status-pill ${dbStatus?.connected ? "ok" : "bad"}`}>
          Intel store: {dbStatus?.connected ? "connected" : "not connected"}
        </span>
        <span
          className={`status-pill ${yaraClass}`}
          title={yaraStatus?.failure_reason ?? undefined}
        >
          YARA: {yaraLabel}
        </span>
        {syncStates.map((s) => (
          <span className="status-pill" key={s.source}>
            {s.source}: last synced {formatDate(s.last_successful_sync_at)}
          </span>
        ))}
      </div>
      <button onClick={onSync} disabled={syncing || !dbStatus?.connected}>
        {syncing ? "Syncing..." : "Sync feeds"}
      </button>
      {lastSyncResults && (
        <div className="sync-results">
          {lastSyncResults.map((r) => (
            <div key={r.source} className={r.ok ? "sync-ok" : "sync-error"}>
              {r.source}:{" "}
              {r.ok
                ? `${r.summary?.indicators_added ?? 0} new, ${
                    r.summary?.indicators_updated ?? 0
                  } updated, ${r.summary?.reports_added ?? 0} reports`
                : r.error}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
