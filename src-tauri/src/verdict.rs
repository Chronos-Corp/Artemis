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

    // Tiers 1/2: bloom miss on both hashes means "clean" for the hash-based
    // tiers, no DB round trip needed. This is the local-miss-means-clean
    // path the agent model depends on for instant clicks at fleet scale.
    let bloom_hit = bloom.contains(&hash.sha256).await || bloom.contains(&hash.md5).await;
    if bloom_hit {
        let sha_rows = db::hash_matches(pool, IndicatorKind::Sha256, &hash.sha256).await?;
        entries.extend(db::hash_matches_to_provenance(sha_rows, VerdictTier::ExactHash));
        let md5_rows = db::hash_matches(pool, IndicatorKind::Md5, &hash.md5).await?;
        entries.extend(db::hash_matches_to_provenance(md5_rows, VerdictTier::ExactHash));
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

    Ok(Verdict {
        path: path_str,
        sha256: hash.sha256,
        md5: hash.md5,
        entries,
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
        assert!(yara.rule_count > 0, "expected the bundled EICAR rule to load");

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

    fn tempfile_eicar() -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().expect("create temp file");
        f.write_all(
            br"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
        )
        .expect("write eicar bytes");
        f
    }
}
