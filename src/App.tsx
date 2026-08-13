import { useCallback, useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import "./App.css";
import { FileList } from "./components/FileList";
import { VerdictPanel } from "./components/VerdictPanel";
import { StatusBar } from "./components/StatusBar";
import type {
  DbStatus,
  FeedSyncResult,
  FileEntry,
  SyncState,
  Verdict,
  YaraStatus,
} from "./types";
import { parentPath, pathSegments } from "./format";

function App() {
  const [currentDir, setCurrentDir] = useState<string | null>(null);
  const [entries, setEntries] = useState<FileEntry[]>([]);
  const [dirLoading, setDirLoading] = useState(false);
  const [dirError, setDirError] = useState<string | null>(null);
  const dirRequestId = useRef(0);

  const [selectedFile, setSelectedFile] = useState<FileEntry | null>(null);
  const [verdict, setVerdict] = useState<Verdict | null>(null);
  const [verdictLoading, setVerdictLoading] = useState(false);
  const [verdictError, setVerdictError] = useState<string | null>(null);
  const verdictRequestId = useRef(0);

  const [dbStatus, setDbStatus] = useState<DbStatus | null>(null);
  const [yaraStatus, setYaraStatus] = useState<YaraStatus | null>(null);
  const [syncStates, setSyncStates] = useState<SyncState[]>([]);
  const [syncing, setSyncing] = useState(false);
  const [lastSyncResults, setLastSyncResults] = useState<FeedSyncResult[] | null>(null);

  const refreshStatus = useCallback(async () => {
    const [db, yara, sync] = await Promise.all([
      invoke<DbStatus>("db_status"),
      invoke<YaraStatus>("yara_status"),
      invoke<SyncState[]>("feed_sync_status").catch(() => []),
    ]);
    setDbStatus(db);
    setYaraStatus(yara);
    setSyncStates(sync);
  }, []);

  useEffect(() => {
    (async () => {
      const home = await invoke<string>("default_start_dir");
      setCurrentDir(home);
      await refreshStatus();
    })();
  }, [refreshStatus]);

  const loadDir = useCallback(async (path: string) => {
    const requestId = ++dirRequestId.current;
    setDirLoading(true);
    setDirError(null);
    try {
      const result = await invoke<FileEntry[]>("list_directory", { path });
      if (requestId === dirRequestId.current) {
        setEntries(result);
      }
    } catch (e) {
      if (requestId === dirRequestId.current) {
        setDirError(String(e));
        setEntries([]);
      }
    } finally {
      if (requestId === dirRequestId.current) {
        setDirLoading(false);
      }
    }
  }, []);

  useEffect(() => {
    if (currentDir) {
      verdictRequestId.current += 1;
      setVerdictLoading(false);
      loadDir(currentDir);
      setSelectedFile(null);
      setVerdict(null);
      setVerdictError(null);
    }
  }, [currentDir, loadDir]);

  async function handleSelectFile(entry: FileEntry) {
    const requestId = ++verdictRequestId.current;
    setSelectedFile(entry);
    setVerdict(null);
    setVerdictError(null);
    setVerdictLoading(true);
    try {
      const result = await invoke<Verdict>("get_verdict", { path: entry.path });
      if (requestId === verdictRequestId.current) {
        setVerdict(result);
      }
    } catch (e) {
      if (requestId === verdictRequestId.current) {
        setVerdictError(String(e));
      }
    } finally {
      if (requestId === verdictRequestId.current) {
        setVerdictLoading(false);
      }
    }
  }

  async function handleSync() {
    setSyncing(true);
    try {
      const results = await invoke<FeedSyncResult[]>("sync_feeds");
      setLastSyncResults(results);
      await refreshStatus();
    } catch (e) {
      setLastSyncResults([{ source: "sync", ok: false, summary: null, error: String(e) }]);
    } finally {
      setSyncing(false);
    }
  }

  return (
    <div className="app">
      <header className="app-header">
        <h1>4NSIC</h1>
        <p className="tagline">
          Click a file to see its indicator verdicts, campaign attribution, and provenance.
        </p>
      </header>

      <StatusBar
        dbStatus={dbStatus}
        yaraStatus={yaraStatus}
        syncStates={syncStates}
        syncing={syncing}
        lastSyncResults={lastSyncResults}
        onSync={handleSync}
      />

      <div className="breadcrumb">
        {currentDir && (
          <>
            <button
              className="breadcrumb-up"
              onClick={() => setCurrentDir(parentPath(currentDir))}
            >
              Up
            </button>
            {pathSegments(currentDir).map((seg) => (
              <span key={seg.path}>
                {" / "}
                <button className="breadcrumb-segment" onClick={() => setCurrentDir(seg.path)}>
                  {seg.label}
                </button>
              </span>
            ))}
          </>
        )}
      </div>

      <main className="main-layout">
        <section className="file-pane">
          {dirError && <div className="verdict-error">{dirError}</div>}
          <FileList
            entries={entries}
            selectedPath={selectedFile?.path ?? null}
            loading={dirLoading}
            onOpenDir={setCurrentDir}
            onSelectFile={handleSelectFile}
          />
        </section>
        <section className="detail-pane">
          <VerdictPanel
            file={selectedFile}
            verdict={verdict}
            loading={verdictLoading}
            error={verdictError}
          />
        </section>
      </main>
    </div>
  );
}

export default App;
