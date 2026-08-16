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
use crate::models::{derive_relationships, DetectionKind, IndicatorKind, Verdict, VerdictTier};
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
    let mut dedicated_relationships = Vec::new();
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

        // Malware-family attribution and CVE relationships can only exist
        // for a hash the bloom filter already knows about: both edge
        // tables foreign-key onto the same `indicator` row
        // `all_known_bad_hashes` (the bloom filter's own source) is built
        // from. A bloom miss therefore provably means neither kind of edge
        // exists either, so both stay inside the same skip-the-round-trip
        // path as the hash matches above rather than always running.
        // Checked against both hash kinds -- ThreatFox can source an MD5
        // indicator with its own family/CVE edges, and checking sha256
        // alone would silently omit them.
        dedicated_relationships = db::malware_family_matches(pool, &hash.sha256, &hash.md5).await?;
        dedicated_relationships.extend(db::cve_matches(pool, &hash.sha256, &hash.md5).await?);
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

    // The RELATE-stage structured relationship view (Apollo Constitution
    // §6): most kinds are pure-derived from the provenance entries already
    // gathered above, but malware-family attribution and CVE relationships
    // each have their own edge tables with their own provenance (populated
    // by ingestion, not derivable from provenance entries alone) so they
    // need their own queries, fetched above alongside the other hash
    // lookups.
    let mut threat_relationships = derive_relationships(&entries);
    threat_relationships.extend(dedicated_relationships);

    Ok(Verdict {
        path: path_str,
        sha256: hash.sha256,
        md5: hash.md5,
        entries,
        intel_freshness,
        threat_relationships,
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

        // PR #19: the same YARA hit must also surface as a structured
        // Detection relationship, not just a ProvenanceEntry -- proving
        // `derive_relationships` actually runs inside `resolve()`, not
        // just in isolation against constructed inputs (see nsic-core's
        // unit tests for that).
        assert!(
            verdict
                .threat_relationships
                .iter()
                .any(|r| r.kind == crate::models::RelationshipKind::Detection
                    && r.target == "Example_EICAR_Test_File"),
            "expected a Detection relationship for the EICAR rule, got: {:?}",
            verdict.threat_relationships
        );
    }

    /// Malware-family attribution has its own edge table (not derivable
    /// from provenance entries alone -- see `derive_relationships`'s doc
    /// comment), so it needs its own live test proving `resolve()` and
    /// `db::malware_family_matches` actually connect end to end. Seeds a
    /// fresh, uniquely-named family against a freshly hashed temp file (a
    /// new random-content file each run means a new indicator row each
    /// run, so this can't collide with any other test or real data in
    /// this shared sandbox database).
    #[tokio::test]
    #[ignore]
    async fn malware_family_attribution_surfaces_as_a_threat_relationship() {
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
        let bloom = BloomState::empty();
        let recent_yara_hits = RecentYaraHits::new();

        let mut tmp = tempfile::NamedTempFile::new().expect("create temp file");
        let unique_marker = uuid::Uuid::new_v4();
        tmp.write_all(format!("malware family test content {unique_marker}").as_bytes())
            .unwrap();
        tmp.flush().unwrap();

        let hash = crate::hashing::hash_file_cached(&pool, tmp.path())
            .await
            .expect("hash temp file");

        let (indicator_id, _) =
            crate::db::indicators::upsert_indicator(&pool, IndicatorKind::Sha256, &hash.sha256)
                .await
                .expect("seed indicator");
        let now = Utc::now();
        let (report_id, _) = crate::db::indicators::upsert_report(
            &pool,
            "test-source",
            Some(&unique_marker.to_string()),
            Some("Test report"),
            None,
            Some(now),
            &serde_json::json!({}),
        )
        .await
        .expect("seed report");
        let family_name = format!("TestFamily-{unique_marker}");
        let (family_id, _) = crate::db::indicators::upsert_malware_family(&pool, &family_name)
            .await
            .expect("seed malware family");
        crate::db::indicators::upsert_indicator_attributed_to_malware_family(
            &pool,
            indicator_id,
            family_id,
            report_id,
            "test-source",
            90,
            now,
            now,
        )
        .await
        .expect("seed attribution edge");

        // Malware-family attribution is gated behind the same bloom check
        // as the other hash-match queries (see resolve()'s comment on
        // why that's provably safe, not lossy) -- seed it directly rather
        // than waiting for a full refresh.
        bloom.insert(&hash.sha256).await;

        let verdict = resolve(&pool, &bloom, &yara, &recent_yara_hits, tmp.path())
            .await
            .expect("resolve verdict");

        let relationship = verdict
            .threat_relationships
            .iter()
            .find(|r| r.kind == crate::models::RelationshipKind::MalwareFamily)
            .unwrap_or_else(|| {
                panic!(
                    "expected a MalwareFamily relationship, got: {:?}",
                    verdict.threat_relationships
                )
            });
        assert_eq!(relationship.target, family_name);
        // Strength is a literal Direct for family attribution -- a
        // single-hop, explicitly sourced assertion -- not derived from
        // confidence (see RelationshipStrength's doc comment for why
        // those are kept separate).
        assert_eq!(
            relationship.strength,
            crate::models::RelationshipStrength::Direct
        );
        assert_eq!(relationship.report_id, Some(report_id));
    }

    /// Review finding 4A: `malware_family_matches` originally hardcoded
    /// `i.kind = 'sha256'`, silently omitting family attribution edges
    /// sourced from an MD5-only indicator -- something ThreatFox actually
    /// does (`md5_hash` IOC type). Seeds the attribution edge against the
    /// *MD5* indicator only and inserts the bloom filter under the file's
    /// MD5 (not its sha256), so this can only pass if the query genuinely
    /// checks both hash kinds rather than sha256 alone.
    #[tokio::test]
    #[ignore]
    async fn md5_sourced_family_attribution_surfaces_as_a_threat_relationship() {
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
        let bloom = BloomState::empty();
        let recent_yara_hits = RecentYaraHits::new();

        let mut tmp = tempfile::NamedTempFile::new().expect("create temp file");
        let unique_marker = uuid::Uuid::new_v4();
        tmp.write_all(format!("md5 family test content {unique_marker}").as_bytes())
            .unwrap();
        tmp.flush().unwrap();

        let hash = crate::hashing::hash_file_cached(&pool, tmp.path())
            .await
            .expect("hash temp file");

        let (indicator_id, _) =
            crate::db::indicators::upsert_indicator(&pool, IndicatorKind::Md5, &hash.md5)
                .await
                .expect("seed md5 indicator");
        let now = Utc::now();
        let (report_id, _) = crate::db::indicators::upsert_report(
            &pool,
            "test-source",
            Some(&unique_marker.to_string()),
            Some("Test report"),
            None,
            Some(now),
            &serde_json::json!({}),
        )
        .await
        .expect("seed report");
        let family_name = format!("Md5TestFamily-{unique_marker}");
        let (family_id, _) = crate::db::indicators::upsert_malware_family(&pool, &family_name)
            .await
            .expect("seed malware family");
        crate::db::indicators::upsert_indicator_attributed_to_malware_family(
            &pool,
            indicator_id,
            family_id,
            report_id,
            "test-source",
            90,
            now,
            now,
        )
        .await
        .expect("seed attribution edge");

        // Deliberately the MD5, not the sha256 -- proves the bloom gate and
        // the query both actually check MD5, not just sha256.
        bloom.insert(&hash.md5).await;

        let verdict = resolve(&pool, &bloom, &yara, &recent_yara_hits, tmp.path())
            .await
            .expect("resolve verdict");

        let relationship = verdict
            .threat_relationships
            .iter()
            .find(|r| r.kind == crate::models::RelationshipKind::MalwareFamily)
            .unwrap_or_else(|| {
                panic!(
                    "expected a MalwareFamily relationship sourced from the MD5 indicator, got: {:?}",
                    verdict.threat_relationships
                )
            });
        assert_eq!(relationship.target, family_name);
    }

    /// Review finding 4B: the original `malware_family_matches` query
    /// reconstructed the supporting report by joining
    /// `indicator_observed_in_report` back on `(indicator_id, source)`
    /// alone, instead of trusting the `report_id` already stored on the
    /// attribution edge. That reconstruction is unsound whenever one source
    /// has filed *two* reports observing the same indicator: it could
    /// attribute the family to whichever report the join happened to pick,
    /// including one that never asserted the family at all. This test
    /// creates exactly that shape -- one indicator, two same-source
    /// reports, and a family attribution edge that names only one of them
    /// -- and asserts the surfaced relationship points at the *correct*
    /// report, with no duplicate relationship pointing at the other.
    #[tokio::test]
    #[ignore]
    async fn malware_family_attribution_does_not_cross_attribute_across_same_source_reports() {
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
        let bloom = BloomState::empty();
        let recent_yara_hits = RecentYaraHits::new();

        let mut tmp = tempfile::NamedTempFile::new().expect("create temp file");
        let unique_marker = uuid::Uuid::new_v4();
        tmp.write_all(format!("cross attribution test content {unique_marker}").as_bytes())
            .unwrap();
        tmp.flush().unwrap();

        let hash = crate::hashing::hash_file_cached(&pool, tmp.path())
            .await
            .expect("hash temp file");

        let (indicator_id, _) =
            crate::db::indicators::upsert_indicator(&pool, IndicatorKind::Sha256, &hash.sha256)
                .await
                .expect("seed indicator");
        let now = Utc::now();

        // Two reports from the *same* source, both observing this
        // indicator -- exactly the shape that broke the old
        // `(indicator_id, source)` reconstruction join.
        let (report_a_id, _) = crate::db::indicators::upsert_report(
            &pool,
            "test-source",
            Some(&format!("A-{unique_marker}")),
            Some("Report A -- does not assert the family"),
            None,
            Some(now),
            &serde_json::json!({}),
        )
        .await
        .expect("seed report A");
        let (report_b_id, _) = crate::db::indicators::upsert_report(
            &pool,
            "test-source",
            Some(&format!("B-{unique_marker}")),
            Some("Report B -- asserts the family"),
            None,
            Some(now),
            &serde_json::json!({}),
        )
        .await
        .expect("seed report B");
        crate::db::indicators::upsert_indicator_observed_in_report(
            &pool,
            indicator_id,
            report_a_id,
            "test-source",
            50,
            now,
            now,
        )
        .await
        .expect("seed indicator observed in report A");
        crate::db::indicators::upsert_indicator_observed_in_report(
            &pool,
            indicator_id,
            report_b_id,
            "test-source",
            50,
            now,
            now,
        )
        .await
        .expect("seed indicator observed in report B");

        let family_name = format!("CrossAttributionFamily-{unique_marker}");
        let (family_id, _) = crate::db::indicators::upsert_malware_family(&pool, &family_name)
            .await
            .expect("seed malware family");
        // Only report B's edge names the family.
        crate::db::indicators::upsert_indicator_attributed_to_malware_family(
            &pool,
            indicator_id,
            family_id,
            report_b_id,
            "test-source",
            90,
            now,
            now,
        )
        .await
        .expect("seed attribution edge for report B only");

        bloom.insert(&hash.sha256).await;

        let verdict = resolve(&pool, &bloom, &yara, &recent_yara_hits, tmp.path())
            .await
            .expect("resolve verdict");

        let matches: Vec<_> = verdict
            .threat_relationships
            .iter()
            .filter(|r| r.kind == crate::models::RelationshipKind::MalwareFamily)
            .collect();
        assert_eq!(
            matches.len(),
            1,
            "expected exactly one MalwareFamily relationship (no cross-attribution or \
             duplication across the two same-source reports), got: {:?}",
            matches
        );
        assert_eq!(
            matches[0].report_id,
            Some(report_b_id),
            "the relationship must point at report B, the only report whose edge actually \
             asserts the family -- not report A, which merely observed the same indicator \
             from the same source"
        );
    }

    /// Review finding 3: CVE relationships must carry the CVE-specific
    /// edge's own provenance (`report_references_cve` / `detection_covers_cve`),
    /// never the parent edge's (`indicator_observed_in_report` /
    /// `detection_detects_indicator`). Both parent and CVE edges below are
    /// deliberately seeded with different source names, confidences, and
    /// timestamps so a flattening bug (copying the parent edge's
    /// provenance, as the pre-review code did for the now-removed
    /// `cve_ids` loop) cannot pass by coincidence.
    #[tokio::test]
    #[ignore]
    async fn cve_relationship_carries_its_own_edge_provenance_not_the_parent_edges() {
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
        let bloom = BloomState::empty();
        let recent_yara_hits = RecentYaraHits::new();

        // Truncated to microsecond precision: Postgres TIMESTAMPTZ stores
        // microseconds, but `Utc::now()` carries nanoseconds, so comparing
        // an as-constructed value against one round-tripped through the
        // database would spuriously fail on the truncated nanosecond tail.
        use chrono::SubsecRound;
        let parent_first_seen = (Utc::now() - chrono::Duration::days(30)).trunc_subsecs(6);
        let parent_last_seen = (Utc::now() - chrono::Duration::days(29)).trunc_subsecs(6);
        let cve_first_seen = (Utc::now() - chrono::Duration::days(2)).trunc_subsecs(6);
        let cve_last_seen = (Utc::now() - chrono::Duration::days(1)).trunc_subsecs(6);

        // --- Two-hop path: indicator --observed_in--> report --references--> cve ---
        let mut tmp_report = tempfile::NamedTempFile::new().expect("create temp file");
        let marker_report = uuid::Uuid::new_v4();
        tmp_report
            .write_all(format!("cve via report test content {marker_report}").as_bytes())
            .unwrap();
        tmp_report.flush().unwrap();
        let hash_report = crate::hashing::hash_file_cached(&pool, tmp_report.path())
            .await
            .expect("hash temp file");

        let (indicator_report_id, _) = crate::db::indicators::upsert_indicator(
            &pool,
            IndicatorKind::Sha256,
            &hash_report.sha256,
        )
        .await
        .expect("seed indicator");
        let (report_id, _) = crate::db::indicators::upsert_report(
            &pool,
            "test-source",
            Some(&marker_report.to_string()),
            Some("Test report"),
            None,
            Some(parent_first_seen),
            &serde_json::json!({}),
        )
        .await
        .expect("seed report");
        crate::db::indicators::upsert_indicator_observed_in_report(
            &pool,
            indicator_report_id,
            report_id,
            "parent-edge-source",
            20,
            parent_first_seen,
            parent_last_seen,
        )
        .await
        .expect("seed indicator observed in report");

        let cve_via_report_id = format!("CVE-TEST-{}", marker_report.simple());
        crate::db::indicators::upsert_cve(&pool, &cve_via_report_id, None, None, None)
            .await
            .expect("seed cve");
        crate::db::indicators::upsert_report_references_cve(
            &pool,
            report_id,
            &cve_via_report_id,
            "cve-edge-source",
            77,
            cve_first_seen,
            cve_last_seen,
        )
        .await
        .expect("seed report references cve");

        bloom.insert(&hash_report.sha256).await;
        let verdict_report = resolve(&pool, &bloom, &yara, &recent_yara_hits, tmp_report.path())
            .await
            .expect("resolve verdict for report path");

        let via_report = verdict_report
            .threat_relationships
            .iter()
            .find(|r| {
                r.kind == crate::models::RelationshipKind::Cve && r.target == cve_via_report_id
            })
            .unwrap_or_else(|| {
                panic!(
                    "expected a Cve relationship for {cve_via_report_id}, got: {:?}",
                    verdict_report.threat_relationships
                )
            });
        assert_eq!(
            via_report.source, "cve-edge-source",
            "must carry report_references_cve's own source, not indicator_observed_in_report's"
        );
        assert_eq!(
            via_report.confidence, 77,
            "must carry report_references_cve's own confidence, not indicator_observed_in_report's"
        );
        assert_eq!(via_report.first_seen, cve_first_seen);
        assert_eq!(via_report.last_seen, cve_last_seen);
        assert_eq!(
            via_report.strength,
            crate::models::RelationshipStrength::Contextual,
            "report co-occurrence is a two-hop inference, not a direct per-file assertion"
        );

        // --- One-hop path: detection --detects--> indicator, detection --covers--> cve ---
        let mut tmp_detection = tempfile::NamedTempFile::new().expect("create temp file");
        let marker_detection = uuid::Uuid::new_v4();
        tmp_detection
            .write_all(format!("cve via detection test content {marker_detection}").as_bytes())
            .unwrap();
        tmp_detection.flush().unwrap();
        let hash_detection = crate::hashing::hash_file_cached(&pool, tmp_detection.path())
            .await
            .expect("hash temp file");

        let (indicator_detection_id, _) = crate::db::indicators::upsert_indicator(
            &pool,
            IndicatorKind::Sha256,
            &hash_detection.sha256,
        )
        .await
        .expect("seed indicator");
        let detection_id = crate::db::indicators::upsert_detection(
            &pool,
            DetectionKind::Yara,
            &format!("TestRule-{marker_detection}"),
            None,
            None,
            None,
        )
        .await
        .expect("seed detection");
        crate::db::indicators::upsert_detection_detects_indicator(
            &pool,
            detection_id,
            indicator_detection_id,
            "parent-edge-source",
            35,
            parent_first_seen,
            parent_last_seen,
        )
        .await
        .expect("seed detection detects indicator");

        let cve_via_detection_id = format!("CVE-TEST-{}", marker_detection.simple());
        crate::db::indicators::upsert_cve(&pool, &cve_via_detection_id, None, None, None)
            .await
            .expect("seed cve");
        crate::db::indicators::upsert_detection_covers_cve(
            &pool,
            detection_id,
            &cve_via_detection_id,
            "covers-edge-source",
            88,
            cve_first_seen,
            cve_last_seen,
        )
        .await
        .expect("seed detection covers cve");

        bloom.insert(&hash_detection.sha256).await;
        let verdict_detection = resolve(
            &pool,
            &bloom,
            &yara,
            &recent_yara_hits,
            tmp_detection.path(),
        )
        .await
        .expect("resolve verdict for detection path");

        let via_detection = verdict_detection
            .threat_relationships
            .iter()
            .find(|r| {
                r.kind == crate::models::RelationshipKind::Cve && r.target == cve_via_detection_id
            })
            .unwrap_or_else(|| {
                panic!(
                    "expected a Cve relationship for {cve_via_detection_id}, got: {:?}",
                    verdict_detection.threat_relationships
                )
            });
        assert_eq!(
            via_detection.source, "covers-edge-source",
            "must carry detection_covers_cve's own source, not detection_detects_indicator's"
        );
        assert_eq!(
            via_detection.confidence, 88,
            "must carry detection_covers_cve's own confidence, not detection_detects_indicator's"
        );
        assert_eq!(via_detection.first_seen, cve_first_seen);
        assert_eq!(via_detection.last_seen, cve_last_seen);
        assert_eq!(
            via_detection.strength,
            crate::models::RelationshipStrength::Strong,
            "a detection matching this exact file is one hop tighter than report \
             co-occurrence, but covering a CVE is still the detection's own documented \
             scope, not a per-file assertion, so this must not be Direct"
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

        let prior_malwarebazaar_state = capture_sync_state(&pool, "malwarebazaar").await;

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

        restore_sync_state(&pool, "malwarebazaar", prior_malwarebazaar_state).await;
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
