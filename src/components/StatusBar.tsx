import type { DbStatus, FeedSyncResult, SyncState, YaraStatus } from "../types";
import { formatDate } from "../format";

interface Props {
  dbStatus: DbStatus | null;
  yaraStatus: YaraStatus | null;
  syncStates: SyncState[];
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
  return (
    <div className="status-bar">
      <div className="status-items">
        <span className={`status-pill ${dbStatus?.connected ? "ok" : "bad"}`}>
          Intel store: {dbStatus?.connected ? "connected" : "not connected"}
        </span>
        <span className="status-pill">
          YARA: {yaraStatus ? `${yaraStatus.rule_count} rule file(s)` : "loading"}
        </span>
        {syncStates.map((s) => (
          <span className="status-pill" key={s.source}>
            {s.source}: last synced {formatDate(s.last_synced_at)}
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
