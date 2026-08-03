use bloomfilter::Bloom;
use sqlx::PgPool;
use tokio::sync::RwLock;

use crate::db::indicators as db;

const FALSE_POSITIVE_RATE: f64 = 0.001;

/// Local first-pass lookup for known-bad hashes. A local hit means "worth an
/// async server round trip for full attribution"; a local miss means clean,
/// no network call needed. This is what makes clicking a file feel instant
/// instead of waiting on a query per click.
pub struct BloomState {
    inner: RwLock<Bloom<str>>,
}

impl BloomState {
    pub fn empty() -> Self {
        Self {
            inner: RwLock::new(Bloom::new_for_fp_rate(1, FALSE_POSITIVE_RATE).expect("bloom init")),
        }
    }

    pub async fn contains(&self, hash: &str) -> bool {
        self.inner.read().await.check(hash)
    }

    /// Sets a single hash into the live filter without rebuilding it. Used
    /// right after a local YARA hit adds a new indicator row, so the next
    /// lookup for that hash sees it without waiting for a full refresh.
    pub async fn insert(&self, hash: &str) {
        self.inner.write().await.set(hash);
    }

    /// Rebuilds the filter from every known-bad hash in the intel store.
    /// Call after every feed sync, since a sync can add many hashes at once
    /// and also changes the ideal filter capacity; single new hashes from a
    /// local YARA hit go through `insert` instead.
    pub async fn refresh(&self, pool: &PgPool) -> anyhow::Result<usize> {
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
