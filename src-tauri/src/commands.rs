use serde::Serialize;
use tauri::State;

use crate::analysis_coverage::YaraCoverageState;
use crate::models::{FileEntry, SyncSummary};
use crate::AppState;

fn db_unavailable() -> String {
    "Database not connected. Start it with `docker compose up -d` in the project root, then restart 4NSIC.".to_string()
}

#[tauri::command]
pub fn default_start_dir() -> String {
    dirs::home_dir()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|| "/".to_string())
}

#[tauri::command]
pub async fn list_directory(state: State<'_, AppState>, path: String) -> Result<Vec<FileEntry>, String> {
    let _ = &state;
    crate::fs_browse::list_dir(std::path::Path::new(&path))
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_verdict(
    state: State<'_, AppState>,
    path: String,
) -> Result<crate::relationship_contract::ResolvedVerdict, String> {
    let pool = state.pool.as_ref().ok_or_else(db_unavailable)?;

    // The relationship-contract module owns the only exposed resolver. It
    // returns an already-normalized RELATE result with YARA coverage attached,
    // so this Tauri adapter cannot be the only place Orion-critical semantics
    // become true.
    crate::relationship_contract::resolve(
        pool,
        &state.bloom,
        &state.intel_gate,
        &state.yara,
        &state.yara_coverage,
        &state.recent_yara_hits,
        std::path::Path::new(&path),
    )
    .await
    .map_err(|e| e.to_string())
}

/// FILE/UNDERSTAND-stage intelligence, independent of `get_verdict`'s
/// RELATE-stage (threat-intel graph) lookup -- see `file_intel`'s module
/// doc comment. Does not take `state` at all, deliberately: this command
/// works even when `state.pool` is `None` (database unreachable), since
/// it never touches Postgres.
#[tauri::command]
pub async fn get_file_intelligence(
    path: String,
) -> Result<crate::file_intel::FileIntelligence, String> {
    crate::file_intel::resolve(std::path::Path::new(&path))
        .await
        .map_err(|e| e.to_string())
}

#[derive(Debug, Serialize)]
pub struct FeedSyncResult {
    pub source: String,
    pub ok: bool,
    pub summary: Option<SyncSummary>,
    pub error: Option<String>,
}

#[tauri::command]
pub async fn sync_feeds(state: State<'_, AppState>) -> Result<Vec<FeedSyncResult>, String> {
    let pool = state.pool.as_ref().ok_or_else(db_unavailable)?;
    if state.api_key.trim().is_empty() {
        return Err(
            "No abuse.ch API key configured. Set ABUSECH_API_KEY and restart 4NSIC.".to_string(),
        );
    }

    // Held for invalidation + ingestion + refresh as one unit -- see
    // `IntelGate`'s doc comment. A round-6 review already established that
    // the bloom must be invalidated *before* `ingest::run_all` starts
    // committing (not just after a failed post-sync refresh); a round-7
    // review went further and caught that even with that ordering, a
    // verdict running concurrently could still see the bloom decision from
    // *before* this sync and the freshness state from *after* it, since
    // nothing previously excluded a `resolve()` call from interleaving
    // with these three steps. Holding this write guard blocks any
    // concurrent `resolve()` (which takes the matching read guard for its
    // whole duration) until the sync -- invalidate, ingest, refresh -- has
    // completed as one atomic-from-the-outside unit.
    let _intel_write_guard = state.intel_gate.write().await;

    state.bloom.invalidate().await;
    let results = crate::ingest::run_all(pool, &state.api_key).await;
    let mapped: Vec<FeedSyncResult> = results
        .into_iter()
        .map(|(source, result)| match result {
            Ok(summary) => FeedSyncResult {
                source: source.to_string(),
                ok: true,
                summary: Some(summary),
                error: None,
            },
            Err(e) => FeedSyncResult {
                source: source.to_string(),
                ok: false,
                summary: None,
                error: Some(e.to_string()),
            },
        })
        .collect();

    if let Err(e) = state.bloom.refresh(pool).await {
        tracing::warn!("bloom filter refresh failed after sync: {e}");
    }

    Ok(mapped)
}

#[derive(Debug, Serialize)]
pub struct YaraStatus {
    pub rules_dir: String,
    pub rule_count: usize,
    pub status: YaraCoverageState,
    pub failure_reason: Option<String>,
}

#[tauri::command]
pub fn yara_status(state: State<'_, AppState>) -> YaraStatus {
    YaraStatus {
        rules_dir: state.yara.rules_dir.to_string_lossy().to_string(),
        rule_count: state.yara_coverage.rule_count,
        status: state.yara_coverage.status,
        failure_reason: state.yara_coverage.failure_reason.clone(),
    }
}

#[derive(Debug, Serialize)]
pub struct DbStatus {
    pub connected: bool,
}

#[tauri::command]
pub fn db_status(state: State<'_, AppState>) -> DbStatus {
    DbStatus {
        connected: state.pool.is_some(),
    }
}

#[tauri::command]
pub async fn feed_sync_status(
    state: State<'_, AppState>,
) -> Result<Vec<crate::models::IntelSourceFreshness>, String> {
    let pool = state.pool.as_ref().ok_or_else(db_unavailable)?;
    crate::db::indicators::all_sync_states(pool)
        .await
        .map_err(|e| e.to_string())
}
