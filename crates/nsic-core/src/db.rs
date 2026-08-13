use anyhow::{Context, Result};
use sqlx::postgres::{PgPool, PgPoolOptions};

/// Connects to Postgres and runs the shared intel-graph migrations. The
/// migrations directory lives under `src-tauri/migrations` (that predates
/// this crate and the desktop app's sqlx offline query cache is keyed
/// against it), so the path here is relative to this crate's own
/// `CARGO_MANIFEST_DIR`. Both the Phase 0 desktop app and the Phase 1
/// console call this so they can never drift onto separate schemas.
pub async fn connect_and_migrate(database_url: &str) -> Result<PgPool> {
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(database_url)
        .await
        .with_context(|| format!("connecting to postgres at {database_url}"))?;

    sqlx::migrate!("../../src-tauri/migrations")
        .run(&pool)
        .await
        .context("running database migrations")?;

    Ok(pool)
}
