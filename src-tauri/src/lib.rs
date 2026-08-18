mod analysis_coverage;
mod bloom;
mod commands;
mod db;
mod file_intel;
mod fs_browse;
mod hashing;
mod ingest;
mod models;
mod relationship_contract;
mod yara_scan;

use std::path::PathBuf;
use std::sync::Arc;

use analysis_coverage::YaraCoverage;
use bloom::{BloomState, IntelGate};
use relationship_contract::RecentYaraHits;
use sqlx::PgPool;
use tauri::Manager;
use yara_scan::YaraEngine;

pub struct AppState {
    pub pool: Option<PgPool>,
    pub bloom: Arc<BloomState>,
    /// Serializes a verdict's intel-corpus reads against a feed sync's
    /// writes -- see `IntelGate`'s doc comment.
    pub intel_gate: Arc<IntelGate>,
    pub yara: Arc<YaraEngine>,
    /// Retains whether the configured ruleset loaded successfully. The
    /// engine may deliberately degrade to an empty fallback so hash/intel
    /// analysis remains usable, but callers must still be able to tell
    /// `failed` from a legitimate zero-rule configuration.
    pub yara_coverage: YaraCoverage,
    pub recent_yara_hits: Arc<RecentYaraHits>,
    pub api_key: String,
}

fn default_rules_dir() -> PathBuf {
    std::env::var("NSIC_YARA_RULES_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("yara-rules"))
}

fn default_database_url() -> String {
    std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://nsic:nsic@localhost:5432/nsic".to_string())
}

async fn init_state() -> AppState {
    let database_url = default_database_url();
    let pool = match db::connect_and_migrate(&database_url).await {
        Ok(pool) => Some(pool),
        Err(e) => {
            tracing::error!("startup: could not connect to Postgres at {database_url}: {e:#}");
            None
        }
    };

    let bloom = Arc::new(BloomState::empty());
    if let Some(pool) = &pool {
        match bloom.refresh(pool).await {
            Ok(n) => tracing::info!("bloom filter loaded with {n} known-bad hashes"),
            Err(e) => tracing::warn!("bloom filter initial load failed: {e}"),
        }
    }

    let rules_dir = default_rules_dir();
    let (yara, yara_coverage) = analysis_coverage::load_yara_with_coverage(&rules_dir);

    let api_key = std::env::var("ABUSECH_API_KEY").unwrap_or_default();

    AppState {
        pool,
        bloom,
        intel_gate: Arc::new(IntelGate::new()),
        yara,
        yara_coverage,
        recent_yara_hits: Arc::new(RecentYaraHits::new()),
        api_key,
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tracing_subscriber::fmt::init();

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            let state = tauri::async_runtime::block_on(init_state());
            app.manage(state);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::default_start_dir,
            commands::list_directory,
            commands::get_verdict,
            commands::get_file_intelligence,
            commands::sync_feeds,
            commands::yara_status,
            commands::db_status,
            commands::feed_sync_status,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
