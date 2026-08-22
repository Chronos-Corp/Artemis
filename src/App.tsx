import { useCallback, useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import "./App.css";
import { FileList } from "./components/FileList";
import { VerdictPanel } from "./components/VerdictPanel";
import { StatusBar } from "./components/StatusBar";
import type { VerdictWithCoverage, YaraStatusWithCoverage } from "./analysisCoverage";
import type {
  DbStatus,
  FeedSyncResult,
  FileEntry,
  FileIntelligence,
  HuntResult,
  IntelSourceFreshness,
  TracePath,
} from "./types";
import { parentPath, pathSegments } from "./format";

function App() {
  const [currentDir, setCurrentDir] = useState<string | null>(null);
  const [entries, setEntries] = useState<FileEntry[]>([]);
  const [dirLoading, setDirLoading] = useState(false);
  const [dirError, setDirError] = useState<string | null>(null);

  const [selectedFile, setSelectedFile] = useState<FileEntry | null>(null);
  const [verdict, setVerdict] = useState<VerdictWithCoverage | null>(null);
  const [verdictLoading, setVerdictLoading] = useState(false);
  const [verdictError, setVerdictError] = useState<string | null>(null);

  const [fileIntel, setFileIntel] = useState<FileIntelligence | null>(null);
  const [fileIntelLoading, setFileIntelLoading] = useState(false);
  const [fileIntelError, setFileIntelError] = useState<string | null>(null);

  const [huntResult, setHuntResult] = useState<HuntResult | null>(null);
  const [huntingPathId, setHuntingPathId] = useState<string | null>(null);
  const [huntSubjectPathId, setHuntSubjectPathId] = useState<string | null>(null);
  const [huntError, setHuntError] = useState<string | null>(null);

  const [dbStatus, setDbStatus] = useState<DbStatus | null>(null);
  const [yaraStatus, setYaraStatus] = useState<YaraStatusWithCoverage | null>(null);
  const [syncStates, setSyncStates] = useState<IntelSourceFreshness[]>([]);
  const [syncing, setSyncing] = useState(false);
  const [lastSyncResults, setLastSyncResults] = useState<FeedSyncResult[] | null>(null);

  // Every file selection/navigation invalidates all older asynchronous detail
  // requests. Without this epoch, click A then B quickly and A's slower
  // response can land last, rendering A's evidence under B's selected name.
  // Evidence attribution must follow the request that produced it, not the
  // order promises happen to resolve.
  const analysisRequestEpoch = useRef(0);
  const huntRequestEpoch = useRef(0);

  const refreshStatus = useCallback(async () => {
    const [db, yara, sync] = await Promise.all([
      invoke<DbStatus>("db_status"),
      invoke<YaraStatusWithCoverage>("yara_status"),
      invoke<IntelSourceFreshness[]>("feed_sync_status").catch(() => []),
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
    setDirLoading(true);
    setDirError(null);
    try {
      const result = await invoke<FileEntry[]>("list_directory", { path });
      setEntries(result);
    } catch (e) {
      setDirError(String(e));
      setEntries([]);
    } finally {
      setDirLoading(false);
    }
  }, []);

  useEffect(() => {
    if (currentDir) {
      analysisRequestEpoch.current += 1;
      huntRequestEpoch.current += 1;
      loadDir(currentDir);
      setSelectedFile(null);
      setVerdict(null);
      setVerdictError(null);
      setVerdictLoading(false);
      setFileIntel(null);
      setFileIntelError(null);
      setFileIntelLoading(false);
      setHuntResult(null);
      setHuntError(null);
      setHuntingPathId(null);
      setHuntSubjectPathId(null);
    }
  }, [currentDir, loadDir]);

  function handleSelectFile(entry: FileEntry) {
    const requestEpoch = ++analysisRequestEpoch.current;
    huntRequestEpoch.current += 1;
    const isCurrentRequest = () => analysisRequestEpoch.current === requestEpoch;

    setSelectedFile(entry);
    setVerdict(null);
    setVerdictError(null);
    setVerdictLoading(true);
    setFileIntel(null);
    setFileIntelError(null);
    setFileIntelLoading(true);
    setHuntResult(null);
    setHuntError(null);
    setHuntingPathId(null);
    setHuntSubjectPathId(null);

    // Independent requests, independent failure: get_file_intelligence
    // never touches the database (see its Rust doc comment), so it can
    // succeed even when get_verdict fails because Postgres is
    // unreachable, and neither should block or hide the other's result.
    // Each completion is request-scoped so a superseded file can never
    // overwrite the detail state of the currently selected file.
    invoke<VerdictWithCoverage>("get_verdict", { path: entry.path })
      .then((result) => {
        if (isCurrentRequest()) setVerdict(result);
      })
      .catch((e) => {
        if (isCurrentRequest()) setVerdictError(String(e));
      })
      .finally(() => {
        if (isCurrentRequest()) setVerdictLoading(false);
      });

    invoke<FileIntelligence>("get_file_intelligence", { path: entry.path })
      .then((result) => {
        if (isCurrentRequest()) setFileIntel(result);
      })
      .catch((e) => {
        if (isCurrentRequest()) setFileIntelError(String(e));
      })
      .finally(() => {
        if (isCurrentRequest()) setFileIntelLoading(false);
      });
  }

  function handleRunHunt(path: TracePath) {
    if (!selectedFile || !verdict || !currentDir) return;

    const requestEpoch = ++huntRequestEpoch.current;
    const isCurrentRequest = () => huntRequestEpoch.current === requestEpoch;
    setHuntingPathId(path.id);
    setHuntSubjectPathId(path.id);
    setHuntResult(null);
    setHuntError(null);

    invoke<HuntResult>("run_hunt", {
      request: {
        seed_path: selectedFile.path,
        expected_seed_sha256: verdict.sha256,
        trace_path_id: path.id,
        scope: {
          kind: "subtree",
          root: currentDir,
        },
      },
    })
      .then((result) => {
        if (isCurrentRequest()) setHuntResult(result);
      })
      .catch((error) => {
        if (isCurrentRequest()) setHuntError(String(error));
      })
      .finally(() => {
        if (isCurrentRequest()) setHuntingPathId(null);
      });
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
            fileIntel={fileIntel}
            fileIntelLoading={fileIntelLoading}
            fileIntelError={fileIntelError}
            huntResult={huntResult}
            huntingPathId={huntingPathId}
            huntSubjectPathId={huntSubjectPathId}
            huntError={huntError}
            huntScopeRoot={currentDir}
            onRunHunt={handleRunHunt}
          />
        </section>
      </main>
    </div>
  );
}

export default App;
