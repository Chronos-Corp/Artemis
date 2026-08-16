use anyhow::{Context, Result};
use chrono::Utc;
use sqlx::PgPool;
use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::bloom::BloomState;
use crate::db::indicators as db;
use crate::hashing;
use crate::models::{DetectionKind, IndicatorKind, Verdict, VerdictTier};
use crate::yara_scan::YaraEngine;

/// Tracks (sha256, rule_name) pairs already persisted this session, so
/// re-clicking a file already known to match a rule doesn't re-run the same
/// three idempotent-but-pointless upserts on every click.
pub struct RecentYaraHits {
    seen: Mutex<HashSet<(String, String)>>,
}

impl RecentYaraHits {
    pub fn new() -> Self {
        Self {
            seen: Mutex::new(HashSet::new()),
        }
    }

    /// Records the pair and returns true if it was newly seen (i.e. the
    /// caller should persist it), false if already recorded this session.
    async fn record_if_new(&self, sha256: &str, rule_name: &str) -> bool {
        self.seen
            .lock()
            .await
            .insert((sha256.to_string(), rule_name.to_string()))
    }
}

impl Default for RecentYaraHits {
    fn default() -> Self {
        Self::new()
    }
}

/// Resolves the full verdict for a file: hash the file (cached), consult the
/// bloom filter before touching the hash tables at all, run a local YARA
/// pass, and check path-pattern and contextual signals. Every tier that
/// fires is returned with its provenance; nothing here collapses to a
/// boolean.
pub async fn resolve(
    pool: &PgPool,
    bloom: &BloomState,
    yara: &Arc<YaraEngine>,
    recent_yara_hits: &RecentYaraHits,
    path: &Path,
) -> Result<Verdict> {
    let hash = hashing::hash_file_cached(pool, path).await?;
    let mut entries = Vec::new();

    // Tiers 1/2: a bloom miss on both hashes means no matching hash
    // evidence exists in the currently available local intelligence
    // corpus -- not that the file is clean, a distinction `intel_freshness`
    // below exists to make visible -- so no DB round trip is needed. This
    // is the local-miss-skips-the-round-trip path the agent model depends
    // on for instant clicks at fleet scale.
    let bloom_hit = bloom.contains(&hash.sha256).await || bloom.contains(&hash.md5).await;
    if bloom_hit {
        let sha_rows = db::hash_matches(pool, IndicatorKind::Sha256, &hash.sha256).await?;
        entries.extend(db::hash_matches_to_provenance(
            sha_rows,
            VerdictTier::ExactHash,
        ));
        let md5_rows = db::hash_matches(pool, IndicatorKind::Md5, &hash.md5).await?;
        entries.extend(db::hash_matches_to_provenance(
            md5_rows,
            VerdictTier::ExactHash,
        ));
    }

    // Tier 3: YARA is orthogonal to known-bad hash status, always runs.
    // Scanning is synchronous CPU/IO-bound work, so it runs on tokio's
    // blocking pool rather than an async worker thread.
    let yara_for_scan = Arc::clone(yara);
    let path_owned = path.to_path_buf();
    let yara_hits = tokio::task::spawn_blocking(move || yara_for_scan.scan(&path_owned))
        .await
        .context("yara scan task panicked")??;
    for hit in &yara_hits {
        if recent_yara_hits
            .record_if_new(&hash.sha256, &hit.rule_name)
            .await
        {
            record_yara_hit(pool, bloom, &hash.sha256, &yara.rules_dir, &hit.rule_name).await?;
        }
    }
    if !yara_hits.is_empty() {
        entries.extend(db::yara_matches(pool, &hash.sha256).await?);
    }

    // Tier 4: path/naming pattern.
    let path_str = path.to_string_lossy().to_string();
    entries.extend(db::path_pattern_matches(pool, &path_str).await?);

    // Tier 5: contextual only, and only when nothing stronger already fired.
    let has_strong_match = entries
        .iter()
        .any(|e| matches!(e.tier, VerdictTier::ExactHash | VerdictTier::YaraHit));
    if !has_strong_match {
        if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
            entries.extend(db::contextual_matches(pool, file_name).await?);
        }
    }

    entries.sort_by_key(|e| e.tier);

    // Carried on every verdict, not just an empty one: even a verdict with
    // real matches is only as current as the feeds that produced them, and
    // an analyst comparing two verdicts benefits from seeing the same
    // freshness context either way.
    let intel_freshness = db::all_sync_states(pool).await?;

    Ok(Verdict {
        path: path_str,
        sha256: hash.sha256,
        md5: hash.md5,
        entries,
        intel_freshness,
    })
}

async fn record_yara_hit(
    pool: &PgPool,
    bloom: &BloomState,
    sha256: &str,
    rules_dir: &Path,
    rule_name: &str,
) -> Result<()> {
    let (indicator_id, indicator_inserted) =
        db::upsert_indicator(pool, IndicatorKind::Sha256, sha256).await?;
    let rule_source = rules_dir.to_string_lossy().to_string();
    let detection_id = db::upsert_detection(
        pool,
        DetectionKind::Yara,
        rule_name,
        Some(&rule_source),
        None,
        None,
    )
    .await?;
    let now = Utc::now();
    db::upsert_detection_detects_indicator(
        pool,
        detection_id,
        indicator_id,
        "local:yara_scan",
        65,
        now,
        now,
    )
    .await?;

    // The indicator table just gained this hash (or already had it); keep
    // the in-memory bloom filter in step so a future exact-hash lookup for
    // the same file (here or on another host, once there's fleet sync)
    // sees it without waiting for the next full feed sync.
    if indicator_inserted {
        bloom.insert(sha256).await;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bloom::BloomState;
    use crate::yara_scan::YaraEngine;
    use std::io::Write;

    /// Guards every test that mutates `feed_sync_state` rows for real
    /// configured sources (`malwarebazaar`, `threatfox`). Rust runs `#[test]`
    /// functions concurrently by default, and two such tests racing on the
    /// same primary key is a real, reproduced bug: on a fresh database (no
    /// prior row for a source), one test's capture-then-restore cleanup
    /// deletes that source's row to put it back the way it found it, which
    /// can land mid-flight through a sibling test that also depends on that
    /// row being present. Reproduced locally by clearing `malwarebazaar`'s
    /// row and looping `cargo test`, which flaked exactly like CI did on
    /// `307ae09`. A lock scoped to this module only (not a process-wide
    /// `--test-threads=1`) keeps the rest of the suite parallel.
    fn feed_sync_state_lock() -> &'static tokio::sync::Mutex<()> {
        static LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
    }

    /// End-to-end smoke test of the click-a-file pipeline: hash, YARA scan,
    /// DB persistence of the hit, and provenance query all in one path.
    /// Requires a live Postgres reachable at DATABASE_URL (see
    /// docker-compose.yml); run explicitly with `cargo test -- --ignored`.
    #[tokio::test]
    #[ignore]
    async fn eicar_file_resolves_to_yara_hit() {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://nsic:nsic@localhost:5432/nsic".to_string());
        let pool = crate::db::connect_and_migrate(&database_url)
            .await
            .expect("connect to test database");

        let rules_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("yara-rules");
        let yara = Arc::new(YaraEngine::load(&rules_dir).expect("load yara rules"));
        assert!(
            yara.rule_count > 0,
            "expected the bundled EICAR rule to load"
        );

        let bloom = BloomState::empty();
        let recent_yara_hits = RecentYaraHits::new();

        let mut tmp = tempfile_eicar();
        tmp.flush().unwrap();

        let verdict = resolve(&pool, &bloom, &yara, &recent_yara_hits, tmp.path())
            .await
            .expect("resolve verdict");

        assert!(
            verdict
                .entries
                .iter()
                .any(|e| e.tier == VerdictTier::YaraHit
                    && e.detection_name.as_deref() == Some("Example_EICAR_Test_File")),
            "expected a YaraHit entry for the EICAR rule, got: {:?}",
            verdict.entries
        );
    }

    /// `intel_freshness` must reflect `feed_sync_state`, not just exist as
    /// an empty placeholder -- seeds a real configured source
    /// (`malwarebazaar`) and confirms `resolve` surfaces it as
    /// `Some(...)`. This is the actual fix: previously an empty `entries`
    /// carried no signal at all about whether the intel behind it was
    /// current.
    ///
    /// Seeds a real configured source rather than a uniquely named fake
    /// one deliberately: `all_sync_states` (see `db::indicators`) now
    /// derives its result from `ingest::CONFIGURED_SOURCES`, not from
    /// whatever happens to be in `feed_sync_state`, so a fake source name
    /// would no longer appear in `intel_freshness` at all -- an earlier
    /// version of this test used a random UUID-suffixed name for exactly
    /// the isolation reason a fake source can't provide anymore.
    #[tokio::test]
    #[ignore]
    async fn intel_freshness_reflects_feed_sync_state() {
        let _guard = feed_sync_state_lock().lock().await;
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://nsic:nsic@localhost:5432/nsic".to_string());
        let pool = crate::db::connect_and_migrate(&database_url)
            .await
            .expect("connect to test database");

        crate::db::indicators::set_sync_cursor(&pool, "malwarebazaar", Some("cursor"))
            .await
            .expect("seed feed_sync_state");

        let rules_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("yara-rules");
        let yara = Arc::new(YaraEngine::load(&rules_dir).expect("load yara rules"));
        let bloom = BloomState::empty();
        let recent_yara_hits = RecentYaraHits::new();

        let mut tmp = tempfile::NamedTempFile::new().expect("create temp file");
        tmp.write_all(b"irrelevant content, not eicar").unwrap();
        tmp.flush().unwrap();

        let verdict = resolve(&pool, &bloom, &yara, &recent_yara_hits, tmp.path())
            .await
            .expect("resolve verdict");

        let freshness = verdict
            .intel_freshness
            .iter()
            .find(|f| f.source == "malwarebazaar")
            .unwrap_or_else(|| {
                panic!(
                    "expected malwarebazaar in intel_freshness, got: {:?}",
                    verdict.intel_freshness
                )
            });
        assert!(
            freshness.last_successful_sync_at.is_some(),
            "a source with a feed_sync_state row must report Some(...), not None"
        );
    }

    /// A previously read `feed_sync_state` row, captured so it can be put
    /// back exactly as it was.
    struct PriorSyncState {
        last_synced_at: Option<chrono::DateTime<Utc>>,
        last_cursor: Option<String>,
    }

    async fn capture_sync_state(pool: &PgPool, source: &str) -> Option<PriorSyncState> {
        sqlx::query!(
            "SELECT last_synced_at, last_cursor FROM feed_sync_state WHERE source = $1",
            source
        )
        .fetch_optional(pool)
        .await
        .expect("read existing sync state")
        .map(|r| PriorSyncState {
            last_synced_at: r.last_synced_at,
            last_cursor: r.last_cursor,
        })
    }

    /// Puts a captured row back exactly as it was (including "there was no
    /// row"), regardless of whatever the test body did to `source` in the
    /// meantime.
    async fn restore_sync_state(pool: &PgPool, source: &str, prior: Option<PriorSyncState>) {
        match prior {
            Some(row) => {
                sqlx::query(
                    "INSERT INTO feed_sync_state (source, last_synced_at, last_cursor) \
                     VALUES ($1, $2, $3) \
                     ON CONFLICT (source) DO UPDATE \
                     SET last_synced_at = EXCLUDED.last_synced_at, \
                         last_cursor = EXCLUDED.last_cursor",
                )
                .bind(source)
                .bind(row.last_synced_at)
                .bind(row.last_cursor)
                .execute(pool)
                .await
                .expect("restore prior sync state");
            }
            None => {
                sqlx::query("DELETE FROM feed_sync_state WHERE source = $1")
                    .bind(source)
                    .execute(pool)
                    .await
                    .expect("clear seeded sync state");
            }
        }
    }

    /// The review-caught bug: a configured feed that has *never*
    /// successfully synced must still appear in `intel_freshness` --
    /// with `last_successful_sync_at: None` -- rather than being silently
    /// absent because it has no `feed_sync_state` row to select. Exercises
    /// the exact partial-success case: one configured source has a
    /// successful sync state (asserted `Some`, not just "present" -- a
    /// follow-up review caught that the first version of this test only
    /// checked presence), the other has none (asserted `None`).
    ///
    /// Restores both `malwarebazaar`'s and `threatfox`'s prior state (row
    /// present or absent) no matter how the test body ends -- including a
    /// panicking assertion -- since a second follow-up review noted the
    /// previous version only restored `threatfox` and only did so on the
    /// success path, so a panic partway through, or the never-restored
    /// `malwarebazaar` row, would permanently mutate a developer's local
    /// sync history on this sandbox's persistent, shared local Postgres
    /// instance. The test body runs inside `tokio::spawn` so its outcome
    /// (success or panic) can be observed via the returned `JoinError`
    /// *before* deciding whether to restore -- restoration always runs,
    /// and if the body panicked, `resume_unwind` re-raises that same panic
    /// afterward so the test still fails with its original message.
    #[tokio::test]
    #[ignore]
    async fn intel_freshness_includes_a_never_synced_configured_source() {
        let _guard = feed_sync_state_lock().lock().await;
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://nsic:nsic@localhost:5432/nsic".to_string());
        let pool = crate::db::connect_and_migrate(&database_url)
            .await
            .expect("connect to test database");

        let prior_malwarebazaar_state = capture_sync_state(&pool, "malwarebazaar").await;
        let prior_threatfox_state = capture_sync_state(&pool, "threatfox").await;

        crate::db::indicators::set_sync_cursor(&pool, "malwarebazaar", Some("cursor"))
            .await
            .expect("seed malwarebazaar sync state");
        sqlx::query("DELETE FROM feed_sync_state WHERE source = 'threatfox'")
            .execute(&pool)
            .await
            .expect("clear threatfox sync state");

        let body_pool = pool.clone();
        let outcome = tokio::spawn(async move {
            let rules_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .unwrap()
                .join("yara-rules");
            let yara = Arc::new(YaraEngine::load(&rules_dir).expect("load yara rules"));
            let bloom = BloomState::empty();
            let recent_yara_hits = RecentYaraHits::new();

            let mut tmp = tempfile::NamedTempFile::new().expect("create temp file");
            tmp.write_all(b"irrelevant content, still not eicar").unwrap();
            tmp.flush().unwrap();

            let verdict = resolve(&body_pool, &bloom, &yara, &recent_yara_hits, tmp.path())
                .await
                .expect("resolve verdict");

            let malwarebazaar = verdict
                .intel_freshness
                .iter()
                .find(|f| f.source == "malwarebazaar")
                .unwrap_or_else(|| {
                    panic!(
                        "expected malwarebazaar in intel_freshness, got: {:?}",
                        verdict.intel_freshness
                    )
                });
            assert!(
                malwarebazaar.last_successful_sync_at.is_some(),
                "malwarebazaar was just seeded with a successful sync -- must report Some(...)"
            );

            let threatfox = verdict
                .intel_freshness
                .iter()
                .find(|f| f.source == "threatfox")
                .unwrap_or_else(|| {
                    panic!(
                        "expected threatfox in intel_freshness even though it has never synced, got: {:?}",
                        verdict.intel_freshness
                    )
                });
            assert!(
                threatfox.last_successful_sync_at.is_none(),
                "a configured source with no feed_sync_state row must report None, not be missing"
            );
        })
        .await;

        restore_sync_state(&pool, "malwarebazaar", prior_malwarebazaar_state).await;
        restore_sync_state(&pool, "threatfox", prior_threatfox_state).await;

        if let Err(join_err) = outcome {
            std::panic::resume_unwind(join_err.into_panic());
        }
    }

    fn tempfile_eicar() -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().expect("create temp file");
        f.write_all(br"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
            .expect("write eicar bytes");
        f
    }
}
