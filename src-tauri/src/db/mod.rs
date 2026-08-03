use anyhow::{Context, Result};
use sqlx::postgres::{PgPool, PgPoolOptions};

pub mod indicators;

/// Connects to Postgres and runs any pending migrations. DATABASE_URL must
/// point at a reachable Postgres instance; see docker-compose.yml for a
/// local dev instance and .env.example for the expected connection string.
pub async fn connect_and_migrate(database_url: &str) -> Result<PgPool> {
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(database_url)
        .await
        .with_context(|| format!("connecting to postgres at {database_url}"))?;

    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .context("running database migrations")?;

    Ok(pool)
}
