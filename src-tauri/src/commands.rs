use serde::Serialize;
use tauri::State;

use crate::models::{FileEntry, SyncSummary, Verdict};
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
pub async fn get_verdict(state: State<'_, AppState>, path: String) -> Result<Verdict, String> {
    let pool = state.pool.as_ref().ok_or_else(db_unavailable)?;
    crate::verdict::resolve(
        pool,
        &state.bloom,
        &state.yara,
        &state.recent_yara_hits,
        std::path::Path::new(&path),
    )
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
}

#[tauri::command]
pub fn yara_status(state: State<'_, AppState>) -> YaraStatus {
    YaraStatus {
        rules_dir: state.yara.rules_dir.to_string_lossy().to_string(),
        rule_count: state.yara.rule_count,
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
