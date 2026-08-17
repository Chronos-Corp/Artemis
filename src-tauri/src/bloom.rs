use bloomfilter::Bloom;
use sqlx::PgPool;
use tokio::sync::RwLock;

use crate::db::indicators as db;

const FALSE_POSITIVE_RATE: f64 = 0.001;

/// Local first-pass lookup for known-bad hashes. A local hit means "worth an
/// async server round trip for full attribution"; a local miss means clean,
/// no network call needed. This is what makes clicking a file feel instant
/// instead of waiting on a query per click.
///
/// A miss is only trustworthy when the filter is actually in step with the
/// intel store. A round-5 review caught that neither `init_state`'s startup
/// refresh nor `sync_feeds`'s post-sync refresh propagated failure beyond a
/// log warning; a round-6 review went further and caught three sharper
/// problems even after `valid` existed:
///
/// 1. **The DB-mutation-vs-invalidation window.** `sync_feeds` used to call
///    `ingest::run_all` (which commits new indicators/edges to Postgres
///    immediately, per feed) and only *afterward* refresh the bloom. A
///    verdict resolved mid-sync could see `is_valid() == true` (the *last*
///    refresh, against the *previous* corpus, succeeded) while Postgres
///    already contains a new match the filter has no way to know about --
///    the worst case, a clean-looking miss backed by data that is about to
///    report itself as freshly synced. `bloom.invalidate()` is now called
///    by `commands::sync_feeds` *before* `ingest::run_all` starts, so any
///    verdict resolved during a sync correctly falls back to the DB for the
///    whole window, not just after a failed refresh.
/// 2. **`is_valid()` and `contains()` as two separate lock acquisitions.**
///    A refresh landing between them could make a caller observe validity
///    from one filter generation and membership from another. `check()`
///    below takes one read-lock covering both together.
/// 3. **A lost-insert race in `refresh`.** The previous version built the
///    replacement filter from a DB snapshot, then acquired the write lock
///    only to swap it in -- a `insert()` racing in between the snapshot and
///    the swap would be silently discarded by the swap. `refresh` now holds
///    the write lock for the DB query as well as the swap, so `insert` and
///    `refresh` are fully serialized against each other: a concurrent
///    `insert` simply waits and then applies to whichever filter comes out
///    on top, but is never lost. This blocks local hash lookups for the
///    duration of the (rare, explicitly-triggered) refresh query rather
///    than the far more common lookup path -- an accepted tradeoff for a
///    single-analyst desktop process where correctness matters more than a
///    sync click's exact latency; a true multi-writer generation/epoch
///    design is more than Phase 0 needs.
pub struct BloomState {
    inner: RwLock<Inner>,
}

struct Inner {
    bloom: Bloom<str>,
    /// True only once a `refresh` has succeeded, no later `refresh` has
    /// failed since, and no explicit `invalidate()` has fired since -- see
    /// the struct doc comment for why a failed refresh (or an in-progress
    /// mutation the filter hasn't caught up to yet) must revoke trust
    /// rather than silently keep serving the last-known filter as though
    /// it still matched the current intel store.
    valid: bool,
}

pub enum LookupResult {
    /// The filter is not known to be in sync with the intel store, so a
    /// miss here proves nothing -- the caller must query the DB directly.
    FilterInvalid,
    Hit,
    Miss,
}

impl BloomState {
    /// Not valid by construction: nothing has refreshed it from the intel
    /// store yet, so a miss here proves nothing.
    pub fn empty() -> Self {
        Self {
            inner: RwLock::new(Inner {
                bloom: Bloom::new_for_fp_rate(1, FALSE_POSITIVE_RATE).expect("bloom init"),
                valid: false,
            }),
        }
    }

    /// Reports, from one lock acquisition, whether the filter can be
    /// trusted at all and, if so, whether any of `hashes` is present. Two
    /// separate calls (`is_valid()` then `contains()`) would let a refresh
    /// land in between them -- see point 2 in the struct doc comment.
    pub async fn check(&self, hashes: &[&str]) -> LookupResult {
        let guard = self.inner.read().await;
        if !guard.valid {
            return LookupResult::FilterInvalid;
        }
        if hashes.iter().any(|h| guard.bloom.check(h)) {
            LookupResult::Hit
        } else {
            LookupResult::Miss
        }
    }

    /// Sets a single hash into the live filter without rebuilding it. Used
    /// right after a local YARA hit adds a new indicator row, so the next
    /// lookup for that hash sees it without waiting for a full refresh.
    /// Does not affect `valid`: inserting one known-fresh hash is always
    /// safe regardless of the filter's broader synchronization state.
    /// Serialized against a concurrent `refresh` by sharing the same write
    /// lock -- see point 3 in the struct doc comment.
    pub async fn insert(&self, hash: &str) {
        self.inner.write().await.bloom.set(hash);
    }

    /// Marks the filter untrusted immediately, without touching its
    /// contents. Call this *before* starting any operation that mutates
    /// the intel store the filter is supposed to reflect (see point 1 in
    /// the struct doc comment) -- a miss reported between this call and
    /// the next successful `refresh` correctly forces the DB fallback
    /// path instead of risking a stale-filter false negative.
    pub async fn invalidate(&self) {
        self.inner.write().await.valid = false;
    }

    /// Rebuilds the filter from every known-bad hash in the intel store.
    /// Call after every feed sync, since a sync can add many hashes at once
    /// and also changes the ideal filter capacity; single new hashes from a
    /// local YARA hit go through `insert` instead.
    ///
    /// Marks the filter valid on success and, critically, invalid on
    /// failure -- even if an earlier refresh had previously succeeded. A
    /// filter built from a now-stale successful refresh cannot be trusted
    /// to reflect hashes a just-failed refresh was supposed to add. Holds
    /// the write lock for the query itself, not just the swap -- see point
    /// 3 in the struct doc comment.
    pub async fn refresh(&self, pool: &PgPool) -> anyhow::Result<usize> {
        let mut guard = self.inner.write().await;
        match Self::build(pool).await {
            Ok((bloom, count)) => {
                guard.bloom = bloom;
                guard.valid = true;
                Ok(count)
            }
            Err(e) => {
                guard.valid = false;
                Err(e)
            }
        }
    }

    async fn build(pool: &PgPool) -> anyhow::Result<(Bloom<str>, usize)> {
        let hashes = db::all_known_bad_hashes(pool).await?;
        let capacity = hashes.len().max(1); // Bloom::new_for_fp_rate rejects 0
        let mut bloom = Bloom::new_for_fp_rate(capacity, FALSE_POSITIVE_RATE)
            .map_err(|e| anyhow::anyhow!("bloom build: {e}"))?;
        for h in &hashes {
            bloom.set(h.as_str());
        }
        Ok((bloom, hashes.len()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_fresh_state_is_invalid() {
        let bloom = BloomState::empty();
        assert!(matches!(
            bloom.check(&["anything"]).await,
            LookupResult::FilterInvalid
        ));
    }

    /// Round 6 review finding: `insert()` alone must never make an
    /// unsynchronized filter look trustworthy -- it's for keeping an
    /// already-valid filter current with one new known-fresh hash, not for
    /// bootstrapping validity from nothing.
    #[tokio::test]
    async fn insert_alone_does_not_make_the_filter_valid() {
        let bloom = BloomState::empty();
        bloom.insert("deadbeef").await;
        assert!(matches!(
            bloom.check(&["deadbeef"]).await,
            LookupResult::FilterInvalid
        ));
    }

    /// `invalidate()` is what `commands::sync_feeds` calls *before*
    /// starting ingestion, so a verdict resolved mid-sync can't trust a
    /// filter that was valid for the *previous* corpus -- see the struct
    /// doc comment, point 1.
    #[tokio::test]
    async fn invalidate_clears_validity_immediately() {
        let bloom = BloomState::empty();
        // Simulate a prior successful refresh without needing a live DB:
        // directly flip the internal flag the way a real `refresh` would.
        bloom.inner.write().await.valid = true;
        assert!(matches!(
            bloom.check(&["anything"]).await,
            LookupResult::Miss
        ));

        bloom.invalidate().await;
        assert!(matches!(
            bloom.check(&["anything"]).await,
            LookupResult::FilterInvalid
        ));
    }
}
