pub mod malwarebazaar;
pub mod threatfox;

use anyhow::{bail, Context, Result};
use chrono::{DateTime, NaiveDateTime, Utc};
use sqlx::PgPool;
use std::time::Duration;

use crate::models::SyncSummary;

/// Total deadline for one feed request, connect through last body byte.
///
/// Explicit because `reqwest::Client::new()` has **no** request timeout:
/// verified against reqwest 0.12.28, whose `ClientConfig` defaults both
/// `timeout` and `read_timeout` to `None` (`ClientBuilder::timeout`'s own
/// docs say "Default is no timeout"). A round-8 review assumed a default
/// existed and, on that basis, treated `IntelGate` holding its write guard
/// across the feed fetch as bounded. It was not: a feed endpoint that
/// accepted the connection and then trickled or withheld bytes could stall
/// the request indefinitely, and because `sync_feeds` holds the `IntelGate`
/// write guard across `run_all`, every concurrent verdict would block for
/// exactly as long.
///
/// The Linux-only `tcp_user_timeout` default (30s) does not cover this: it
/// bounds unacknowledged TCP writes, not an application-layer server that
/// keeps a connection healthy while sending almost nothing.
///
/// 60s is generous for these endpoints while still guaranteeing the lock is
/// released.
const FEED_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

/// Deadline for establishing the connection specifically, so an
/// unreachable-but-not-refusing host fails fast rather than consuming the
/// whole request budget.
const FEED_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// Ceiling on a decoded feed response body.
///
/// `Response::json()` materializes the entire body in memory before
/// deserializing, and the body length is chosen by the remote feed, not by
/// Apollo -- so an unexpectedly (or maliciously) large response is an
/// availability problem on the analyst's workstation. Enforced while
/// streaming, so an oversized body is abandoned partway rather than fully
/// buffered and then rejected.
///
/// 64 MiB is far above either feed's real payload (a few MiB at most) and
/// far below a size that would threaten the host.
const MAX_FEED_BODY_BYTES: usize = 64 * 1024 * 1024;

/// The shared HTTP client for feed requests: bounded, and identically
/// bounded for every feed rather than each module choosing its own.
pub(crate) fn feed_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(FEED_REQUEST_TIMEOUT)
        .connect_timeout(FEED_CONNECT_TIMEOUT)
        .build()
        .context("building the feed HTTP client")
}

/// Reads a response body with an enforced size ceiling, then deserializes.
///
/// Streams via `chunk()` and aborts as soon as the accumulated size would
/// exceed `MAX_FEED_BODY_BYTES`, which is the point: checking
/// `content_length()` alone would be advisory (a server can omit or
/// understate it), and `json()`/`bytes()` would buffer the whole thing
/// first.
pub(crate) async fn decode_bounded_json<T: serde::de::DeserializeOwned>(
    mut resp: reqwest::Response,
    what: &str,
) -> Result<T> {
    // Cheap pre-check when the server does declare an oversized body: no
    // reason to start streaming something already known to be too big.
    if let Some(declared) = resp.content_length() {
        if declared > MAX_FEED_BODY_BYTES as u64 {
            bail!(
                "{what}: response declares {declared} bytes, over the {MAX_FEED_BODY_BYTES}-byte limit"
            );
        }
    }

    let mut body: Vec<u8> = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .with_context(|| format!("reading {what} response body"))?
    {
        if body.len() + chunk.len() > MAX_FEED_BODY_BYTES {
            bail!("{what}: response exceeded the {MAX_FEED_BODY_BYTES}-byte limit");
        }
        body.extend_from_slice(&chunk);
    }

    serde_json::from_slice(&body).with_context(|| format!("parsing {what} response"))
}

/// abuse.ch feeds format timestamps as naive `YYYY-MM-DD HH:MM:SS` strings
/// (implicitly UTC); shared by every feed module rather than duplicated.
pub(crate) fn parse_abusech_time(s: Option<&str>) -> Option<DateTime<Utc>> {
    let s = s?;
    NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S")
        .ok()
        .map(|naive| naive.and_utc())
}

/// The configured feed set -- the source of truth for "which feeds does
/// Apollo know about," independent of `feed_sync_state`, which only gains
/// a row for a source once it has completed at least one successful sync
/// (see `db::indicators::set_sync_cursor`). A feed that has never
/// succeeded has no row there at all, so anything reading feed coverage
/// (`db::indicators::all_sync_states`) must start from this list, not from
/// the sync-state table, or a never-synced feed goes silently missing
/// instead of showing up as never-synced.
pub(crate) const CONFIGURED_SOURCES: &[&str] = &[malwarebazaar::SOURCE, threatfox::SOURCE];

/// Runs every configured feed sync and returns a (source, result) pair per
/// feed. The source label travels with its own result instead of being
/// reconstructed positionally against a separately maintained list, so
/// adding a feed here can't silently desync the labeling in `sync_feeds`.
/// A feed that fails (network error, missing API key) is reported as an
/// error rather than silently skipped, since a partial sync must be visible
/// to the analyst, not hidden.
pub async fn run_all(pool: &PgPool, api_key: &str) -> Vec<(&'static str, Result<SyncSummary>)> {
    vec![
        (
            malwarebazaar::SOURCE,
            malwarebazaar::sync(pool, api_key).await,
        ),
        (threatfox::SOURCE, threatfox::sync(pool, api_key).await),
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
        let api_key =
            std::env::var("ABUSECH_API_KEY").expect("ABUSECH_API_KEY must be set to run this test");
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
