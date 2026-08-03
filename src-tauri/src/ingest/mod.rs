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
