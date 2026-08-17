use bloomfilter::Bloom;
use sqlx::PgPool;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::RwLock;

use crate::db::indicators as db;

const FALSE_POSITIVE_RATE: f64 = 0.001;

/// Local first-pass lookup for known-bad hashes. A local hit means "worth an
/// async server round trip for full attribution"; a local miss means clean,
/// no network call needed. This is what makes clicking a file feel instant
/// instead of waiting on a query per click.
///
/// A miss is only trustworthy when the filter is actually in step with the
/// intel store -- `valid` tracks that. A review caught that neither
/// `init_state`'s startup refresh nor `sync_feeds`'s post-sync refresh
/// propagated failure beyond a log warning: either could leave the filter
/// empty or stale while Postgres genuinely contains matching indicators, and
/// `resolve()` was trusting a miss as proof no DB round trip was needed
/// regardless. That turns an optimization into a silent evidentiary
/// false-negative gate. `is_valid()` lets `resolve()` fall back to the DB
/// whenever the filter's own state isn't known-good, instead of returning a
/// normal-looking but incomplete verdict.
pub struct BloomState {
    inner: RwLock<Bloom<str>>,
    valid: AtomicBool,
}

impl BloomState {
    /// Not valid by construction: nothing has refreshed it from the intel
    /// store yet, so a miss here proves nothing.
    pub fn empty() -> Self {
        Self {
            inner: RwLock::new(Bloom::new_for_fp_rate(1, FALSE_POSITIVE_RATE).expect("bloom init")),
            valid: AtomicBool::new(false),
        }
    }

    pub async fn contains(&self, hash: &str) -> bool {
        self.inner.read().await.check(hash)
    }

    /// True only once a `refresh` has succeeded and no later `refresh` has
    /// failed since -- see the struct doc comment for why a failed refresh
    /// must revoke trust rather than silently keep serving the last-known
    /// filter as though it still matched the current intel store.
    pub fn is_valid(&self) -> bool {
        self.valid.load(Ordering::Acquire)
    }

    /// Sets a single hash into the live filter without rebuilding it. Used
    /// right after a local YARA hit adds a new indicator row, so the next
    /// lookup for that hash sees it without waiting for a full refresh.
    /// Does not affect `valid`: inserting one known-fresh hash is always
    /// safe regardless of the filter's broader synchronization state.
    pub async fn insert(&self, hash: &str) {
        self.inner.write().await.set(hash);
    }

    /// Rebuilds the filter from every known-bad hash in the intel store.
    /// Call after every feed sync, since a sync can add many hashes at once
    /// and also changes the ideal filter capacity; single new hashes from a
    /// local YARA hit go through `insert` instead.
    ///
    /// Marks the filter valid on success and, critically, invalid on
    /// failure -- even if an earlier refresh had previously succeeded. A
    /// filter built from a now-stale successful refresh cannot be trusted
    /// to reflect hashes a just-failed refresh was supposed to add.
    pub async fn refresh(&self, pool: &PgPool) -> anyhow::Result<usize> {
        let outcome = self.refresh_inner(pool).await;
        self.valid.store(outcome.is_ok(), Ordering::Release);
        outcome
    }

    async fn refresh_inner(&self, pool: &PgPool) -> anyhow::Result<usize> {
        let hashes = db::all_known_bad_hashes(pool).await?;
        let capacity = hashes.len().max(1); // Bloom::new_for_fp_rate rejects 0
        let mut bloom = Bloom::new_for_fp_rate(capacity, FALSE_POSITIVE_RATE)
            .map_err(|e| anyhow::anyhow!("bloom build: {e}"))?;
        for h in &hashes {
            bloom.set(h.as_str());
        }
        let mut guard = self.inner.write().await;
        *guard = bloom;
        Ok(hashes.len())
    }
}
