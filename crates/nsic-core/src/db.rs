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

#[cfg(test)]
mod tests {
    /// The sentinel `0004_host_credential.sql` backfills onto any pre-PR #4
    /// host row with no credential. Kept in sync with the literal in that
    /// migration file by the test below actually applying the migration's
    /// SQL, not a hand-copied guess of what it does.
    const LEGACY_HOST_SENTINEL: &str = "legacy-host-requires-re-enrollment";

    /// Simulates upgrading a database that already has a PR #3-era host row
    /// (enrolled before the credential concept existed) through the PR #4
    /// migration that renames `enrollment_token_hash` to `credential_hash`
    /// and makes it `NOT NULL`. A naive `SET NOT NULL` fails against that
    /// row; a fresh CI database never exposes this because the `host`
    /// table starts empty, which is exactly how this bug shipped in PR #4's
    /// first draft.
    ///
    /// Runs in an isolated schema on the same Postgres instance other
    /// DB-backed tests use, so it doesn't collide with the fully-migrated
    /// `public` schema those tests run against. Requires a live Postgres
    /// reachable at DATABASE_URL; run explicitly with `cargo test --
    /// --ignored`.
    #[tokio::test]
    #[ignore]
    async fn migration_0004_backfills_legacy_hosts_without_a_credential() {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://nsic:nsic@localhost:5432/nsic".to_string());
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&database_url)
            .await
            .expect("connect to test database");
        let mut conn = pool.acquire().await.expect("acquire connection");

        let schema = "phase1_pr4_migration_upgrade_test";
        sqlx::raw_sql(&format!(
            "DROP SCHEMA IF EXISTS {schema} CASCADE; CREATE SCHEMA {schema};"
        ))
        .execute(&mut *conn)
        .await
        .expect("create isolated schema");
        sqlx::raw_sql(&format!("SET search_path TO {schema}"))
            .execute(&mut *conn)
            .await
            .expect("set search_path");

        // The PR #3-era `host` table, verbatim: credential_hash didn't
        // exist yet, the column was still named enrollment_token_hash and
        // nullable.
        sqlx::raw_sql(include_str!("../../../src-tauri/migrations/0003_hosts.sql"))
            .execute(&mut *conn)
            .await
            .expect("apply 0003 (pre-PR #4 host table)");

        // A host enrolled under PR #3, before any credential concept
        // existed -- enrollment_token_hash is NULL, exactly the row shape
        // that broke a naive `SET NOT NULL`.
        sqlx::raw_sql(
            "INSERT INTO host (hostname, os, agent_version) \
             VALUES ('legacy-host', 'linux', '0.1.0')",
        )
        .execute(&mut *conn)
        .await
        .expect("insert legacy PR #3 host row");

        // The actual migration this PR ships, executed verbatim -- not a
        // reimplementation of it.
        sqlx::raw_sql(include_str!(
            "../../../src-tauri/migrations/0004_host_credential.sql"
        ))
        .execute(&mut *conn)
        .await
        .expect("migration 0004 must succeed against a pre-existing legacy host row");

        let credential_hash: String =
            sqlx::query_scalar("SELECT credential_hash FROM host WHERE hostname = 'legacy-host'")
                .fetch_one(&mut *conn)
                .await
                .expect("legacy host row survives the migration");
        assert_eq!(
            credential_hash, LEGACY_HOST_SENTINEL,
            "legacy hosts should be backfilled with a sentinel that can never match a real \
             credential, forcing re-enrollment rather than silently authenticating"
        );

        sqlx::raw_sql(&format!("DROP SCHEMA {schema} CASCADE"))
            .execute(&mut *conn)
            .await
            .expect("cleanup isolated schema");
    }
}
