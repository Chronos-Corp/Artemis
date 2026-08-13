pub mod malwarebazaar;
pub mod threatfox;

use anyhow::Result;
use chrono::{DateTime, NaiveDateTime, Utc};
use sqlx::PgPool;

use crate::models::SyncSummary;

/// abuse.ch feeds format timestamps as naive `YYYY-MM-DD HH:MM:SS` strings
/// (implicitly UTC); shared by every feed module rather than duplicated.
pub(crate) fn parse_abusech_time(s: Option<&str>) -> Option<DateTime<Utc>> {
    let s = s?;
    NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S")
        .ok()
        .map(|naive| naive.and_utc())
}

/// Runs every configured feed sync and returns a (source, result) pair per
/// feed. The source label travels with its own result instead of being
/// reconstructed positionally against a separately maintained list, so
/// adding a feed here can't silently desync the labeling in `sync_feeds`.
/// A feed that fails (network error, missing API key) is reported as an
/// error rather than silently skipped, since a partial sync must be visible
/// to the analyst, not hidden.
pub async fn run_all(pool: &PgPool, api_key: &str) -> Vec<(&'static str, Result<SyncSummary>)> {
    vec![
        ("malwarebazaar", malwarebazaar::sync(pool, api_key).await),
        ("threatfox", threatfox::sync(pool, api_key).await),
    ]
}

#[cfg(test)]
mod live_tests {
    //! These hit the real abuse.ch APIs and are excluded from every normal
    //! test run. They only run when explicitly filtered for (`cargo test
    //! live_abusech_ -- --ignored`) with both DATABASE_URL and
    //! ABUSECH_API_KEY set; see .github/workflows/live-ingest-check.yml,
    //! which is the only place that filter is used. This sandbox's own
    //! network egress is policy-blocked to abuse.ch, so this test cannot be
    //! run here — it runs in CI, where the runner has normal internet
    //! access. See project issue #3.
    use super::*;

    #[tokio::test]
    #[ignore]
    async fn live_abusech_sync_works() {
        let api_key = std::env::var("ABUSECH_API_KEY")
            .expect("ABUSECH_API_KEY must be set to run this test");
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://nsic:nsic@localhost:5432/nsic".to_string());
        let pool = crate::db::connect_and_migrate(&database_url)
            .await
            .expect("connect to test database");

        let results = run_all(&pool, &api_key).await;
        assert_eq!(results.len(), 2, "expected one result per configured feed");

        for (source, result) in results {
            let summary = result.unwrap_or_else(|e| {
                panic!("live sync against {source} failed: {e:#}");
            });
            assert_eq!(summary.source, source);
            let total_touched = summary.indicators_added + summary.indicators_updated;
            assert!(
                total_touched > 0 || summary.reports_added > 0,
                "{source} sync completed but touched nothing; abuse.ch response \
                 shape may have changed (got {summary:?})"
            );
            println!(
                "{source}: +{} indicators, {} updated, +{} reports",
                summary.indicators_added, summary.indicators_updated, summary.reports_added
            );
        }
    }
}
