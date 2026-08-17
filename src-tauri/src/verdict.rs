use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::bloom::{BloomState, IntelGate};
use crate::db::indicators as db;
use crate::hashing;
use crate::models::{
    derive_relationships, DetectionKind, IndicatorKind, ProvenanceEntry, Verdict, VerdictTier,
};
use crate::yara_scan::YaraEngine;

/// Source/confidence for a `detection_detects_indicator` edge (and the
/// matching current-scan `RelationshipEvidence` hop) written by this
/// desktop app's own live YARA pass, as opposed to some other source that
/// might someday write to the same table. Named constants rather than
/// literals repeated at each of the three sites that need to agree on
/// them exactly (`record_yara_hit`'s persistence, the current `YaraHit`
/// `ProvenanceEntry`s, and `cve_matches_via_detection`'s hop 1).
pub(crate) const LOCAL_YARA_SOURCE: &str = "local:yara_scan";
pub(crate) const LOCAL_YARA_CONFIDENCE: i16 = 65;

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

    /// True if this pair's persistence has already succeeded this session.
    async fn contains(&self, sha256: &str, rule_name: &str) -> bool {
        self.seen
            .lock()
            .await
            .contains(&(sha256.to_string(), rule_name.to_string()))
    }

    /// Records the pair as persisted. Callers must only call this *after*
    /// the corresponding DB write has actually succeeded -- a review
    /// caught a previous version of this type (via its since-removed
    /// `record_if_new`) marking the pair seen *before* attempting
    /// persistence, so a transient failure partway through the DB writes
    /// left the in-memory cache permanently believing the work was done,
    /// suppressing every future retry for that (file, rule) pair for the
    /// rest of the process's life even though the edge was never written.
    async fn mark_seen(&self, sha256: &str, rule_name: &str) {
        self.seen
            .lock()
            .await
            .insert((sha256.to_string(), rule_name.to_string()));
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
    intel_gate: &IntelGate,
    yara: &Arc<YaraEngine>,
    recent_yara_hits: &RecentYaraHits,
    path: &Path,
) -> Result<Verdict> {
    // Held for this call's entire duration -- see `IntelGate`'s doc
    // comment. A round-7 review caught that the bloom-miss decision below
    // and the `intel_freshness` read at the bottom of this function could
    // otherwise straddle a concurrent feed sync: the decision correctly
    // valid at the moment `bloom.check` ran, but a sync invalidating,
    // committing new matching data, and refreshing before this function
    // reaches `all_sync_states` would return a verdict claiming
    // post-sync freshness for a relationship decision silently still made
    // against the pre-sync corpus. Holding this guard for the whole
    // function excludes `commands::sync_feeds`'s write guard for that
    // entire span, so every read below -- the bloom check, the hash/family/
    // report-CVE queries, and the final freshness read -- sees one
    // consistent corpus.
    let _intel_read_guard = intel_gate.read().await;

    // Read the file's bytes exactly once and hash + YARA-scan the identical
    // buffer -- see `hashing::hash_and_read_file`'s doc comment for why:
    // two separate reads (one to hash, one to scan) can observe different
    // content if the file changes in between, silently binding a YARA hit's
    // persisted edge to the wrong hash.
    let (hash, file_data) = hashing::hash_and_read_file(pool, path).await?;
    let mut entries = Vec::new();

    // Tiers 1/2: a bloom miss on both hashes means no matching hash
    // evidence exists in the currently available local intelligence
    // corpus -- not that the file is clean, a distinction `intel_freshness`
    // below exists to make visible -- so no DB round trip is needed. This
    // is the local-miss-skips-the-round-trip path the agent model depends
    // on for instant clicks at fleet scale.
    //
    // Only trusted when the filter itself is known valid: a review caught
    // that neither startup's nor `sync_feeds`'s bloom refresh propagated
    // failure beyond a log warning, so an empty/stale filter could
    // otherwise make a real match look like a clean miss. A single
    // `check()` call covers both the validity check and the membership
    // check under one lock acquisition -- see `BloomState`'s doc comment
    // for the race a round-6 review caught in two separate calls.
    let bloom_hit = !matches!(
        bloom.check(&[&hash.sha256, &hash.md5]).await,
        crate::bloom::LookupResult::Miss
    );
    let mut dedicated_relationships = Vec::new();
    if bloom_hit {
        let sha_rows = db::hash_matches(pool, IndicatorKind::Sha256, &hash.sha256).await?;
        entries.extend(db::hash_matches_to_provenance(
            sha_rows,
            VerdictTier::ExactHash,
            IndicatorKind::Sha256,
        ));
        let md5_rows = db::hash_matches(pool, IndicatorKind::Md5, &hash.md5).await?;
        entries.extend(db::hash_matches_to_provenance(
            md5_rows,
            VerdictTier::ExactHash,
            IndicatorKind::Md5,
        ));

        // Malware-family attribution and CVE-via-report relationships can
        // only exist for a hash the bloom filter already knows about: both
        // edge tables foreign-key onto the same `indicator` row
        // `all_known_bad_hashes` (the bloom filter's own source) is built
        // from, and both are populated exclusively by feed ingestion (which
        // always runs before the bloom filter is rebuilt from that same
        // table) -- never created live during `resolve` itself. A bloom
        // miss therefore provably means neither kind of edge exists either,
        // so both stay inside this skip-the-round-trip path. Checked
        // against both hash kinds -- ThreatFox can source an MD5 indicator
        // with its own family/CVE edges, and checking sha256 alone would
        // silently omit them.
        //
        // CVE-via-*detection* is deliberately NOT fetched here -- see the
        // comment below, after the YARA tier, for why that one can't reuse
        // this same bloom-gated fast path.
        dedicated_relationships = db::malware_family_matches(pool, &hash.sha256, &hash.md5).await?;
        dedicated_relationships
            .extend(db::cve_matches_via_report(pool, &hash.sha256, &hash.md5).await?);
    }

    // Tier 3: YARA is orthogonal to known-bad hash status, always runs.
    // Scanning is synchronous CPU/IO-bound work, so it runs on tokio's
    // blocking pool rather than an async worker thread. Scans the same
    // `file_data` buffer that was just hashed -- see the read-once comment
    // at the top of this function.
    let yara_for_scan = Arc::clone(yara);
    let yara_hits = tokio::task::spawn_blocking(move || yara_for_scan.scan_bytes(&file_data))
        .await
        .context("yara scan task panicked")??;

    // One timestamp for every observation this scan produces (the
    // persisted edge and the current-scan evidence hops below), so they
    // can't drift apart into "the edge says one time, the relationship
    // says another" for what is definitionally the same event.
    let now = Utc::now();
    for hit in &yara_hits {
        if !recent_yara_hits
            .contains(&hash.sha256, &hit.rule_name)
            .await
        {
            // "" (the wildcard/version-unknown value, never fabricated as
            // a real fingerprint) if the lightweight rule-declaration
            // parser somehow missed this rule's own declaration -- see
            // `YaraEngine::rule_fingerprints`'s doc comment. Should not
            // happen for a rule that just matched (it had to have been
            // compiled from a file that was scanned for declarations too),
            // but degrades safely rather than panicking if it ever does.
            let rule_fingerprint = yara.rule_fingerprint(&hit.rule_name).unwrap_or("");
            // Only marked seen *after* this succeeds -- see
            // `RecentYaraHits::mark_seen`'s doc comment for why persisting
            // first and caching second (not the other way around) matters.
            record_yara_hit(
                pool,
                bloom,
                &hash.sha256,
                &yara.rules_dir,
                rule_fingerprint,
                &hit.rule_name,
                now,
            )
            .await?;
            recent_yara_hits
                .mark_seen(&hash.sha256, &hit.rule_name)
                .await;
        }
    }

    // Current YaraHit provenance is built directly from this scan's own
    // result -- source/confidence/timestamp are exactly what was just
    // persisted above, not reconstructed by re-querying
    // `detection_detects_indicator` (which a review caught could pick up a
    // historical or differently-sourced row for the same
    // (detection, indicator) pair rather than the observation that just
    // occurred).
    if !yara_hits.is_empty() {
        entries.extend(yara_hits.iter().map(|hit| ProvenanceEntry {
            tier: VerdictTier::YaraHit,
            source: LOCAL_YARA_SOURCE.to_string(),
            confidence: LOCAL_YARA_CONFIDENCE,
            first_seen: now,
            last_seen: now,
            timing: crate::models::EvidenceTiming::Observed,
            report_id: None,
            report_title: None,
            report_url: None,
            detection_name: Some(hit.rule_name.clone()),
            indicator_kind: Some(IndicatorKind::Sha256),
            // `None` (honestly "version unknown"), not fabricated, when
            // the rule's own fingerprint couldn't be determined -- see the
            // matching comment above this loop.
            rule_fingerprint: yara.rule_fingerprint(&hit.rule_name).map(str::to_string),
            matched_value: hash.sha256.clone(),
        }));
    }

    // Each rule that fired paired with *its own* content fingerprint (not
    // one shared whole-ruleset value) -- see `cve_matches_via_detection`'s
    // doc comment for why per-rule scoping matters.
    let scanned_rules: Vec<(String, String)> = yara_hits
        .iter()
        .map(|h| {
            (
                h.rule_name.clone(),
                yara.rule_fingerprint(&h.rule_name)
                    .unwrap_or("")
                    .to_string(),
            )
        })
        .collect();

    // CVE-via-detection has to be checked *after* the YARA tier above, not
    // folded into the bloom-gated block before it: a review caught that on
    // a file whose hash was never seen before this call (`bloom_hit` false
    // at the top), a YARA rule firing right here creates this file's first
    // `indicator` row and its `detection_detects_indicator` edge live, via
    // `record_yara_hit`. If a pre-existing `detection_covers_cve` edge
    // already documents that rule as covering a CVE, the relationship must
    // surface on this exact call -- the analyst's first look at a freshly
    // discovered file is exactly when it matters most, not on a second
    // click after `record_yara_hit`'s bloom insert makes the fast path
    // above start firing.
    //
    // Gated purely on `!yara_hits.is_empty()`, not `bloom_hit ||
    // !yara_hits.is_empty()` as an earlier version had it: a follow-up
    // review caught that `bloom_hit` reflects unrelated hash-table
    // knowledge (an exact-hash match from ingestion, say) and would let a
    // detection historically recorded for this hash surface a "matched
    // this exact file" CVE relationship even when zero rules fired in the
    // current scan. `cve_matches_via_detection` is additionally scoped per
    // rule to `scanned_rules` -- see its doc comment for why a rule name
    // alone isn't durable version identity, and why the whole-ruleset
    // fingerprint isn't the right scope either. Report/family lookups
    // don't need the same treatment since ingestion, not `resolve`, is the
    // only thing that ever creates those edges.
    if !yara_hits.is_empty() {
        dedicated_relationships.extend(
            db::cve_matches_via_detection(
                pool,
                &scanned_rules,
                LOCAL_YARA_SOURCE,
                LOCAL_YARA_CONFIDENCE,
                now,
                IndicatorKind::Sha256,
                &hash.sha256,
            )
            .await?,
        );
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

#[allow(clippy::too_many_arguments)]
async fn record_yara_hit(
    pool: &PgPool,
    bloom: &BloomState,
    sha256: &str,
    rules_dir: &Path,
    rule_fingerprint: &str,
    rule_name: &str,
    now: DateTime<Utc>,
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
    db::upsert_detection_detects_indicator(
        pool,
        detection_id,
        indicator_id,
        LOCAL_YARA_SOURCE,
        LOCAL_YARA_CONFIDENCE,
        now,
        now,
        rule_fingerprint,
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
        let intel_gate = IntelGate::new();
        let recent_yara_hits = RecentYaraHits::new();

        let mut tmp = tempfile_eicar();
        tmp.flush().unwrap();

        let verdict = resolve(
            &pool,
            &bloom,
            &intel_gate,
            &yara,
            &recent_yara_hits,
            tmp.path(),
        )
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
        let intel_gate = IntelGate::new();
        let recent_yara_hits = RecentYaraHits::new();

        let mut tmp = tempfile::NamedTempFile::new().expect("create temp file");
        let unique_marker = uuid::Uuid::new_v4();
        tmp.write_all(format!("malware family test content {unique_marker}").as_bytes())
            .unwrap();
        tmp.flush().unwrap();

        let (hash, _) = crate::hashing::hash_and_read_file(&pool, tmp.path())
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

        let verdict = resolve(
            &pool,
            &bloom,
            &intel_gate,
            &yara,
            &recent_yara_hits,
            tmp.path(),
        )
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
        assert_eq!(relationship.evidence_paths.len(), 1);
        assert_eq!(relationship.evidence_paths[0].len(), 1);
        assert_eq!(relationship.evidence_paths[0][0].report_id, Some(report_id));
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
        let intel_gate = IntelGate::new();
        let recent_yara_hits = RecentYaraHits::new();

        let mut tmp = tempfile::NamedTempFile::new().expect("create temp file");
        let unique_marker = uuid::Uuid::new_v4();
        tmp.write_all(format!("md5 family test content {unique_marker}").as_bytes())
            .unwrap();
        tmp.flush().unwrap();

        let (hash, _) = crate::hashing::hash_and_read_file(&pool, tmp.path())
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

        let verdict = resolve(
            &pool,
            &bloom,
            &intel_gate,
            &yara,
            &recent_yara_hits,
            tmp.path(),
        )
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
        let intel_gate = IntelGate::new();
        let recent_yara_hits = RecentYaraHits::new();

        let mut tmp = tempfile::NamedTempFile::new().expect("create temp file");
        let unique_marker = uuid::Uuid::new_v4();
        tmp.write_all(format!("cross attribution test content {unique_marker}").as_bytes())
            .unwrap();
        tmp.flush().unwrap();

        let (hash, _) = crate::hashing::hash_and_read_file(&pool, tmp.path())
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

        let verdict = resolve(
            &pool,
            &bloom,
            &intel_gate,
            &yara,
            &recent_yara_hits,
            tmp.path(),
        )
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
            matches[0].evidence_paths[0][0].report_id,
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
        let intel_gate = IntelGate::new();
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
        let (hash_report, _) = crate::hashing::hash_and_read_file(&pool, tmp_report.path())
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
        let verdict_report = resolve(
            &pool,
            &bloom,
            &intel_gate,
            &yara,
            &recent_yara_hits,
            tmp_report.path(),
        )
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
            via_report.evidence_paths.len(),
            1,
            "only one real parent observation was seeded, so this must not branch: {:?}",
            via_report.evidence_paths
        );
        let path = &via_report.evidence_paths[0];
        assert_eq!(
            path.len(),
            2,
            "the two-hop chain must be preserved, not collapsed to one flat value: {path:?}"
        );
        assert_eq!(
            path[0].relation,
            crate::models::EvidenceRelation::ObservedInReport
        );
        assert_eq!(
            path[0].source, "parent-edge-source",
            "the first hop must carry indicator_observed_in_report's own provenance"
        );
        assert_eq!(path[0].confidence, 20);
        assert_eq!(path[0].first_seen, parent_first_seen);
        assert_eq!(path[0].last_seen, parent_last_seen);
        assert_eq!(
            path[1].relation,
            crate::models::EvidenceRelation::ReportReferencesCve
        );
        assert_eq!(
            path[1].source, "cve-edge-source",
            "must carry report_references_cve's own source, not indicator_observed_in_report's"
        );
        assert_eq!(
            path[1].confidence, 77,
            "must carry report_references_cve's own confidence, not indicator_observed_in_report's"
        );
        assert_eq!(path[1].first_seen, cve_first_seen);
        assert_eq!(path[1].last_seen, cve_last_seen);
        assert_eq!(
            via_report.strength,
            crate::models::RelationshipStrength::Contextual,
            "report co-occurrence is a two-hop inference, not a direct per-file assertion"
        );

        // Review finding 2, folded into this same fixture: `ProvenanceEntry`
        // no longer carries a `cve_ids` field at all (it used to aggregate
        // `report_references_cve.cve_id` under the *parent*
        // `indicator_observed_in_report` edge's source/confidence, telling
        // a second, conflicting story about the same CVE next to the
        // correctly-sourced `ThreatRelationship` above). That the type has
        // no such field is enforced at compile time; this asserts the
        // surfaced `ExactHash` entry only ever carries its own parent
        // edge's values ("parent-edge-source" / 20), never the CVE edge's
        // ("cve-edge-source" / 77) -- there is no path left, structurally
        // or in this data, for the two to blend.
        let exact_hash_entry = verdict_report
            .entries
            .iter()
            .find(|e| e.tier == VerdictTier::ExactHash)
            .unwrap_or_else(|| {
                panic!(
                    "expected an ExactHash provenance entry, got: {:?}",
                    verdict_report.entries
                )
            });
        assert_eq!(exact_hash_entry.source, "parent-edge-source");
        assert_eq!(exact_hash_entry.confidence, 20);
        // Checked at the wire-serialization level, not just against known
        // field names: this is what `VerdictPanel` actually receives and
        // renders, so it catches a reintroduction of CVE data on this
        // entry even via a differently-named field, not just a literal
        // `cve_ids` field with this exact name.
        let exact_hash_entry_json =
            serde_json::to_string(exact_hash_entry).expect("serialize provenance entry");
        assert!(
            !exact_hash_entry_json.contains(&cve_via_report_id),
            "the ExactHash provenance entry (what VerdictPanel renders) must not mention the \
             CVE ID at all -- that would resurrect the two-conflicting-provenance-stories bug \
             even if ProvenanceEntry gained a new field carrying it, got: {exact_hash_entry_json}"
        );

        // --- One-hop path: detection --detects--> indicator, detection --covers--> cve ---
        //
        // Uses the real bundled EICAR rule and a real live YARA scan, not a
        // manually seeded detection_detects_indicator edge: a later review
        // caught that cve_matches_via_detection is now scoped to detections
        // that actually fired in the current scan (see its doc comment), so
        // a synthetic edge for a rule that never runs would no longer
        // surface at all under the fixed code -- exactly the behavior that
        // fix is supposed to produce, but it means this test has to
        // exercise a rule that genuinely matches to keep verifying the
        // *provenance* (not just the presence) of the resulting
        // relationship.
        let marker_detection = uuid::Uuid::new_v4();
        let mut tmp_detection = tempfile_eicar();
        tmp_detection.flush().unwrap();

        let detection_id = crate::db::indicators::upsert_detection(
            &pool,
            DetectionKind::Yara,
            "Example_EICAR_Test_File",
            None,
            None,
            None,
        )
        .await
        .expect("seed detection");

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
            "",
        )
        .await
        .expect("seed detection covers cve");

        let verdict_detection = resolve(
            &pool,
            &bloom,
            &intel_gate,
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
            via_detection.evidence_paths.len(),
            1,
            "cve_matches_via_detection's hop 1 always comes from exactly one live scan, so \
             this must never branch: {:?}",
            via_detection.evidence_paths
        );
        let path = &via_detection.evidence_paths[0];
        assert_eq!(
            path.len(),
            2,
            "the two-hop chain must be preserved, not collapsed to one flat value: {path:?}"
        );
        assert_eq!(
            path[0].relation,
            crate::models::EvidenceRelation::DetectsIndicator
        );
        assert_eq!(
            path[0].source, "local:yara_scan",
            "the first hop must carry the live scan's own detection_detects_indicator \
             provenance (record_yara_hit's), not detection_covers_cve's"
        );
        assert_eq!(path[0].confidence, 65);
        // Round 6 review finding 3B: hop 1 must identify the indicator it
        // detected -- `resolve()` knows the scanned hash, so this hop
        // should never be a structurally incomplete
        // `Detection --detects--> ???`.
        assert_eq!(path[0].indicator_kind, Some(IndicatorKind::Sha256));
        assert_eq!(
            path[0].indicator_value,
            Some(verdict_detection.sha256.clone())
        );
        assert_eq!(
            path[1].relation,
            crate::models::EvidenceRelation::DetectionCoversCve
        );
        assert_eq!(
            path[1].source, "covers-edge-source",
            "must carry detection_covers_cve's own source, not detection_detects_indicator's"
        );
        assert_eq!(
            path[1].confidence, 88,
            "must carry detection_covers_cve's own confidence, not detection_detects_indicator's"
        );
        assert_eq!(path[1].first_seen, cve_first_seen);
        assert_eq!(path[1].last_seen, cve_last_seen);
        // Round 6 review finding 3A: this coverage edge was seeded with the
        // wildcard ("" -> None) rule_fingerprint, meaning "applies to any
        // version" -- hop 2 must preserve that true edge value, not
        // fabricate the current scan's own fingerprint as though the edge
        // had actually been asserted against it.
        assert_eq!(
            path[1].rule_fingerprint, None,
            "a wildcard coverage edge's evidence must stay a wildcard, not be presented as \
             though asserted against the current scan's specific rule fingerprint"
        );
        assert_eq!(
            via_detection.strength,
            crate::models::RelationshipStrength::Strong,
            "a detection matching this exact file is one hop tighter than report \
             co-occurrence, but covering a CVE is still the detection's own documented \
             scope, not a per-file assertion, so this must not be Direct"
        );
        assert!(
            via_detection
                .explanation
                .contains("Example_EICAR_Test_File"),
            "the explanation must name the specific detection that forms the \
             file -> detection -> cve path, not just assert a detection did, got: {:?}",
            via_detection.explanation
        );
    }

    /// Review finding 1: `cve_matches_via_detection` must surface on the
    /// *first* `resolve()` call against a previously unseen file, not just
    /// on a second click once the bloom filter has been warmed by the
    /// first. Deliberately uses a fresh, empty `BloomState` and the real
    /// bundled EICAR YARA rule (not a manually seeded detection edge) so
    /// the `detection_detects_indicator` edge is created live, inside this
    /// very `resolve()` call, by `record_yara_hit` -- exactly the sequence
    /// the review described: a pre-existing `detection_covers_cve` edge
    /// (e.g. from a hunt pack) plus a fresh YARA hit on an unseen file must
    /// combine into a CVE relationship without requiring a second scan.
    #[tokio::test]
    #[ignore]
    async fn cve_via_detection_surfaces_on_the_first_scan_of_a_previously_unseen_file() {
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
        // Deliberately empty, not seeded: this call must not depend on the
        // bloom filter already knowing this file's hash.
        let bloom = BloomState::empty();
        let intel_gate = IntelGate::new();
        let recent_yara_hits = RecentYaraHits::new();

        // A hunt pack has already documented the bundled EICAR rule as
        // covering a CVE, *before* this file is ever scanned.
        let detection_id = crate::db::indicators::upsert_detection(
            &pool,
            DetectionKind::Yara,
            "Example_EICAR_Test_File",
            None,
            None,
            None,
        )
        .await
        .expect("seed detection");
        let unique_marker = uuid::Uuid::new_v4();
        let cve_id = format!("CVE-TEST-{}", unique_marker.simple());
        crate::db::indicators::upsert_cve(&pool, &cve_id, None, None, None)
            .await
            .expect("seed cve");
        let now = Utc::now();
        crate::db::indicators::upsert_detection_covers_cve(
            &pool,
            detection_id,
            &cve_id,
            "test-source",
            80,
            now,
            now,
            "",
        )
        .await
        .expect("seed detection covers cve");

        let mut tmp = tempfile_eicar();
        tmp.flush().unwrap();

        // First-ever resolve() call against this exact file/hash pairing
        // in this test's bloom -- the sha256 indicator and its
        // detection_detects_indicator edge do not exist in this bloom's
        // view of the world until record_yara_hit persists them partway
        // through this very call.
        let verdict = resolve(
            &pool,
            &bloom,
            &intel_gate,
            &yara,
            &recent_yara_hits,
            tmp.path(),
        )
        .await
        .expect("resolve verdict");

        assert!(
            verdict
                .threat_relationships
                .iter()
                .any(|r| r.kind == crate::models::RelationshipKind::Cve && r.target == cve_id),
            "expected the CVE relationship to surface on the first scan of this file, not \
             require a second click after the bloom filter warms up, got: {:?}",
            verdict.threat_relationships
        );
    }

    /// Review finding 3 (round 4): `cve_matches_via_report` previously
    /// joined outward from `indicator`, so a single `report_references_cve`
    /// edge could surface twice when the same report observed *both* the
    /// file's sha256 and md5 -- exactly the shape MalwareBazaar's ingestion
    /// produces for any sample with both hash fields present. One real
    /// `report -> cve` assertion must produce exactly one relationship, not
    /// one per hash representation of the file.
    #[tokio::test]
    #[ignore]
    async fn one_report_with_both_hash_kinds_produces_exactly_one_cve_relationship() {
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
        let intel_gate = IntelGate::new();
        let recent_yara_hits = RecentYaraHits::new();

        let mut tmp = tempfile::NamedTempFile::new().expect("create temp file");
        let marker = uuid::Uuid::new_v4();
        tmp.write_all(format!("dual hash cve dedup test content {marker}").as_bytes())
            .unwrap();
        tmp.flush().unwrap();
        let (hash, _) = crate::hashing::hash_and_read_file(&pool, tmp.path())
            .await
            .expect("hash temp file");

        let (sha256_id, _) =
            crate::db::indicators::upsert_indicator(&pool, IndicatorKind::Sha256, &hash.sha256)
                .await
                .expect("seed sha256 indicator");
        let (md5_id, _) =
            crate::db::indicators::upsert_indicator(&pool, IndicatorKind::Md5, &hash.md5)
                .await
                .expect("seed md5 indicator");

        let now = Utc::now();
        let (report_id, _) = crate::db::indicators::upsert_report(
            &pool,
            "test-source",
            Some(&marker.to_string()),
            Some("Test report"),
            None,
            Some(now),
            &serde_json::json!({}),
        )
        .await
        .expect("seed report");

        // The same report observed BOTH hash kinds for this one file.
        crate::db::indicators::upsert_indicator_observed_in_report(
            &pool,
            sha256_id,
            report_id,
            "test-source",
            90,
            now,
            now,
        )
        .await
        .expect("seed sha256 observed in report");
        crate::db::indicators::upsert_indicator_observed_in_report(
            &pool,
            md5_id,
            report_id,
            "test-source",
            90,
            now,
            now,
        )
        .await
        .expect("seed md5 observed in report");

        let cve_id = format!("CVE-TEST-{}", marker.simple());
        crate::db::indicators::upsert_cve(&pool, &cve_id, None, None, None)
            .await
            .expect("seed cve");
        crate::db::indicators::upsert_report_references_cve(
            &pool,
            report_id,
            &cve_id,
            "test-source",
            77,
            now,
            now,
        )
        .await
        .expect("seed report references cve");

        bloom.insert(&hash.sha256).await;
        let verdict = resolve(
            &pool,
            &bloom,
            &intel_gate,
            &yara,
            &recent_yara_hits,
            tmp.path(),
        )
        .await
        .expect("resolve verdict");

        let matches: Vec<_> = verdict
            .threat_relationships
            .iter()
            .filter(|r| r.kind == crate::models::RelationshipKind::Cve && r.target == cve_id)
            .collect();
        assert_eq!(
            matches.len(),
            1,
            "one report_references_cve edge must produce exactly one relationship, not one per \
             hash kind the file happens to have, got: {matches:?}"
        );

        // Round 6 review finding 4: deduplicating the *relationship* must
        // not come at the cost of discarding either hash's real supporting
        // evidence -- both indicator_observed_in_report hops are genuine,
        // independent facts (the report really did observe this file under
        // both hash representations) and both must still be reconstructable.
        // Round 7 review finding 3 went further: those two hops converging
        // on one shared report_references_cve hop are not one linear
        // chain, they're two parallel paths -- `evidence_paths` must carry
        // them as two separate, independently-walkable paths rather than
        // one flat vec that leaves a consumer to infer the branch.
        assert_eq!(
            matches[0].evidence_paths.len(),
            2,
            "both the sha256 and md5 observed_in_report hops must be preserved as separate \
             evidence *paths*, not collapsed into one linear chain, got: {:?}",
            matches[0].evidence_paths
        );
        for path in &matches[0].evidence_paths {
            assert_eq!(
                path.len(),
                2,
                "each path must be a complete, self-contained two-hop chain: {path:?}"
            );
            assert_eq!(
                path[0].relation,
                crate::models::EvidenceRelation::ObservedInReport
            );
            assert_eq!(
                path[1].relation,
                crate::models::EvidenceRelation::ReportReferencesCve,
                "every path must end at the shared report_references_cve hop, not just one of \
                 them"
            );
        }
        let observed_values: Vec<Option<String>> = matches[0]
            .evidence_paths
            .iter()
            .map(|path| path[0].indicator_value.clone())
            .collect();
        assert!(
            observed_values.contains(&Some(hash.sha256.clone())),
            "expected a path whose first hop observed the sha256, got: {observed_values:?}"
        );
        assert!(
            observed_values.contains(&Some(hash.md5.clone())),
            "expected a path whose first hop observed the md5, got: {observed_values:?}"
        );
    }

    /// Review finding 3 (round 3): when two detections both matched a hash
    /// but only one is documented to cover a CVE, the surfaced CVE
    /// relationship must identify *which* detection supports it -- not
    /// just that some detection does. Without this, an analyst with two
    /// YARA hits on one file cannot tell which rule the
    /// `file -> detection -> cve` path actually runs through.
    ///
    /// Uses two real, temporary YARA rules (not manually seeded
    /// `detection_detects_indicator` edges) so both genuinely fire in a
    /// live scan: a later review (round 4) scoped `cve_matches_via_detection`
    /// to only the detections that actually fired in the current scan, so a
    /// synthetic edge for a rule that never runs would no longer surface at
    /// all -- this test needs two rules that both really match to keep
    /// testing "which one" rather than "does it show up".
    #[tokio::test]
    #[ignore]
    async fn cve_via_detection_identifies_the_correct_supporting_detection_among_several() {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://nsic:nsic@localhost:5432/nsic".to_string());
        let pool = crate::db::connect_and_migrate(&database_url)
            .await
            .expect("connect to test database");

        let marker = uuid::Uuid::new_v4().simple().to_string();
        let rule_a_name = format!("RuleA_{marker}");
        let rule_b_name = format!("RuleB_{marker}");

        let temp_rules_dir = tempfile::tempdir().expect("create temp rules dir");
        std::fs::write(
            temp_rules_dir.path().join("rule_a.yar"),
            format!("rule {rule_a_name} {{ strings: $s = \"MARKERA_{marker}\" condition: $s }}"),
        )
        .expect("write rule a");
        std::fs::write(
            temp_rules_dir.path().join("rule_b.yar"),
            format!("rule {rule_b_name} {{ strings: $s = \"MARKERB_{marker}\" condition: $s }}"),
        )
        .expect("write rule b");
        let yara = Arc::new(YaraEngine::load(temp_rules_dir.path()).expect("load test rules"));
        assert_eq!(
            yara.rule_count, 2,
            "expected both temporary test rules to load"
        );

        let bloom = BloomState::empty();
        let intel_gate = IntelGate::new();
        let recent_yara_hits = RecentYaraHits::new();

        let mut tmp = tempfile::NamedTempFile::new().expect("create temp file");
        tmp.write_all(format!("MARKERA_{marker} MARKERB_{marker}").as_bytes())
            .unwrap();
        tmp.flush().unwrap();

        // Only rule B is documented to cover the CVE.
        let detection_b_id = crate::db::indicators::upsert_detection(
            &pool,
            DetectionKind::Yara,
            &rule_b_name,
            None,
            None,
            None,
        )
        .await
        .expect("seed detection B");
        let cve_id = format!("CVE-TEST-{marker}");
        crate::db::indicators::upsert_cve(&pool, &cve_id, None, None, None)
            .await
            .expect("seed cve");
        let now = Utc::now();
        crate::db::indicators::upsert_detection_covers_cve(
            &pool,
            detection_b_id,
            &cve_id,
            "test-source",
            80,
            now,
            now,
            "",
        )
        .await
        .expect("seed detection B covers cve");

        let verdict = resolve(
            &pool,
            &bloom,
            &intel_gate,
            &yara,
            &recent_yara_hits,
            tmp.path(),
        )
        .await
        .expect("resolve verdict");

        // Sanity: both rules genuinely fired this scan, not just B.
        let yara_hit_names: Vec<_> = verdict
            .entries
            .iter()
            .filter(|e| e.tier == VerdictTier::YaraHit)
            .filter_map(|e| e.detection_name.clone())
            .collect();
        assert!(
            yara_hit_names.contains(&rule_a_name) && yara_hit_names.contains(&rule_b_name),
            "expected both rules to fire on this file, got: {yara_hit_names:?}"
        );

        let relationship = verdict
            .threat_relationships
            .iter()
            .find(|r| r.kind == crate::models::RelationshipKind::Cve && r.target == cve_id)
            .unwrap_or_else(|| {
                panic!(
                    "expected a Cve relationship for {cve_id}, got: {:?}",
                    verdict.threat_relationships
                )
            });
        assert!(
            relationship.explanation.contains(&rule_b_name),
            "expected the explanation to identify the supporting detection ({rule_b_name}), \
             got: {:?}",
            relationship.explanation
        );
        assert!(
            !relationship.explanation.contains(&rule_a_name),
            "must not implicate rule A, which does not cover this CVE, got: {:?}",
            relationship.explanation
        );
        assert_eq!(
            relationship.evidence_paths[0][1].detection_name,
            Some(rule_b_name),
            "the structured evidence hop, not just the explanation prose, must identify rule B"
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
        let intel_gate = IntelGate::new();
        let recent_yara_hits = RecentYaraHits::new();

        let mut tmp = tempfile::NamedTempFile::new().expect("create temp file");
        tmp.write_all(b"irrelevant content, not eicar").unwrap();
        tmp.flush().unwrap();

        let verdict = resolve(
            &pool,
            &bloom,
            &intel_gate,
            &yara,
            &recent_yara_hits,
            tmp.path(),
        )
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
            let intel_gate = IntelGate::new();
            let recent_yara_hits = RecentYaraHits::new();

            let mut tmp = tempfile::NamedTempFile::new().expect("create temp file");
            tmp.write_all(b"irrelevant content, still not eicar").unwrap();
            tmp.flush().unwrap();

            let verdict = resolve(&body_pool, &bloom, &intel_gate, &yara, &recent_yara_hits, tmp.path())
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

    /// Review finding 4: `RecentYaraHits` used to mark a `(hash, rule)`
    /// pair as persisted *before* attempting the DB writes (via the since-
    /// removed `record_if_new`), so a transient failure partway through
    /// `record_yara_hit` left the pair permanently "seen" in memory even
    /// though its `detection_detects_indicator` edge was never actually
    /// written -- a retry in the same process would see `contains()`
    /// return true and skip persistence forever, silently losing the
    /// Detection relationship (and any detection-backed CVE relationship)
    /// on every future scan of that file.
    ///
    /// Forces `record_yara_hit` to fail by calling it against a pool this
    /// test closes itself -- a second, independent connection to the same
    /// database, not the one used for the retry/verification steps below,
    /// so this can't affect any other test (each test's pool is its own
    /// connection; see `db::connect_and_migrate`). Confirms the pair is
    /// *not* marked seen after that failure, then confirms a second
    /// attempt against a live pool actually persists the edge.
    #[tokio::test]
    #[ignore]
    async fn a_failed_yara_hit_persistence_does_not_permanently_suppress_retry() {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://nsic:nsic@localhost:5432/nsic".to_string());
        let pool = crate::db::connect_and_migrate(&database_url)
            .await
            .expect("connect to test database");
        let broken_pool = crate::db::connect_and_migrate(&database_url)
            .await
            .expect("connect second test database handle");
        broken_pool.close().await;

        let rules_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("yara-rules");
        let bloom = BloomState::empty();
        let recent_yara_hits = RecentYaraHits::new();

        let unique_marker = uuid::Uuid::new_v4();
        let marker_hex = unique_marker.simple().to_string();
        let sha256 = format!("{marker_hex}{marker_hex}");
        let rule_name = format!("FakeRule-{unique_marker}");
        let ruleset_fingerprint = "test-fingerprint";
        let now = Utc::now();

        assert!(!recent_yara_hits.contains(&sha256, &rule_name).await);

        let first_attempt = record_yara_hit(
            &broken_pool,
            &bloom,
            &sha256,
            &rules_dir,
            ruleset_fingerprint,
            &rule_name,
            now,
        )
        .await;
        assert!(
            first_attempt.is_err(),
            "expected persistence against a closed pool to fail"
        );
        assert!(
            !recent_yara_hits.contains(&sha256, &rule_name).await,
            "a failed persistence attempt must not mark the pair as seen"
        );

        record_yara_hit(
            &pool,
            &bloom,
            &sha256,
            &rules_dir,
            ruleset_fingerprint,
            &rule_name,
            now,
        )
        .await
        .expect("retry against a live pool should succeed");
        recent_yara_hits.mark_seen(&sha256, &rule_name).await;

        // Confirm the edge actually landed.
        let exists = sqlx::query_scalar!(
            r#"
            SELECT EXISTS (
                SELECT 1 FROM detection_detects_indicator ddi
                JOIN detection d ON d.id = ddi.detection_id
                JOIN indicator i ON i.id = ddi.indicator_id
                WHERE d.kind = 'yara' AND d.name = $1 AND i.kind = 'sha256' AND i.value = $2
            ) AS "exists!"
            "#,
            rule_name,
            sha256,
        )
        .fetch_one(&pool)
        .await
        .expect("query detection edge");
        assert!(
            exists,
            "expected the detection edge to actually be persisted after the successful retry"
        );
    }

    /// Review finding 1 (round 4), first requested regression shape: a
    /// detection historically documented to cover a CVE, plus a hash
    /// that's already known to the bloom filter through an *unrelated*
    /// exact-hash match (not through that detection), must not surface a
    /// "a local detection ... matched this exact file" CVE relationship
    /// when the current scan's file doesn't match any rule at all.
    /// `bloom_hit` being true from the unrelated hash match is exactly the
    /// scenario the review flagged: it must not be enough on its own.
    #[tokio::test]
    #[ignore]
    async fn a_stale_detection_covers_cve_edge_does_not_surface_when_no_rule_fires_this_scan() {
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
        let intel_gate = IntelGate::new();
        let recent_yara_hits = RecentYaraHits::new();

        let mut tmp = tempfile::NamedTempFile::new().expect("create temp file");
        let marker = uuid::Uuid::new_v4();
        tmp.write_all(format!("stale detection test content {marker}").as_bytes())
            .unwrap();
        tmp.flush().unwrap();
        let (hash, _) = crate::hashing::hash_and_read_file(&pool, tmp.path())
            .await
            .expect("hash temp file");

        let (indicator_id, _) =
            crate::db::indicators::upsert_indicator(&pool, IndicatorKind::Sha256, &hash.sha256)
                .await
                .expect("seed indicator");
        let now = Utc::now();

        // Makes bloom_hit true via a real but unrelated exact-hash edge --
        // not via the stale detection below.
        let (report_id, _) = crate::db::indicators::upsert_report(
            &pool,
            "test-source",
            Some(&marker.to_string()),
            Some("Test report"),
            None,
            Some(now),
            &serde_json::json!({}),
        )
        .await
        .expect("seed report");
        crate::db::indicators::upsert_indicator_observed_in_report(
            &pool,
            indicator_id,
            report_id,
            "test-source",
            90,
            now,
            now,
        )
        .await
        .expect("seed indicator observed in report");

        // A detection historically recorded against this hash (e.g. from a
        // rule that later changed, or curated from another source) --
        // never fired in this test's actual scan below.
        let stale_rule_name = format!("StaleRule-{marker}");
        let detection_id = crate::db::indicators::upsert_detection(
            &pool,
            DetectionKind::Yara,
            &stale_rule_name,
            None,
            None,
            None,
        )
        .await
        .expect("seed stale detection");
        crate::db::indicators::upsert_detection_detects_indicator(
            &pool,
            detection_id,
            indicator_id,
            "historical-source",
            50,
            now,
            now,
            "",
        )
        .await
        .expect("seed stale detection detects indicator");
        let cve_id = format!("CVE-TEST-{}", marker.simple());
        crate::db::indicators::upsert_cve(&pool, &cve_id, None, None, None)
            .await
            .expect("seed cve");
        crate::db::indicators::upsert_detection_covers_cve(
            &pool,
            detection_id,
            &cve_id,
            "historical-source",
            80,
            now,
            now,
            "",
        )
        .await
        .expect("seed stale detection covers cve");

        bloom.insert(&hash.sha256).await;
        let verdict = resolve(
            &pool,
            &bloom,
            &intel_gate,
            &yara,
            &recent_yara_hits,
            tmp.path(),
        )
        .await
        .expect("resolve verdict");

        assert!(
            !verdict
                .threat_relationships
                .iter()
                .any(|r| r.kind == crate::models::RelationshipKind::Cve && r.target == cve_id),
            "a detection that did not fire in this scan must not produce a current \
             detection-backed CVE relationship, even when the hash is otherwise bloom-known, \
             got: {:?}",
            verdict.threat_relationships
        );
    }

    /// Self-review finding (threat model TB-2, pattern injection): a path
    /// indicator's value is interpolated into an `ILIKE` pattern, and
    /// Postgres treats `%`/`_` as wildcards there. An unescaped `%`
    /// indicator therefore matches *every* file the analyst clicks --
    /// one poisoned or malformed intel row presenting as a genuine
    /// path-indicator hit on everything, which is exactly the kind of
    /// silent trust failure the Constitution's provenance rules exist to
    /// prevent.
    ///
    /// Seeds a literal `%` path indicator (with real report provenance, so
    /// it would otherwise surface) against a scanned file whose path has
    /// nothing to do with it, and asserts it does not match. The companion
    /// assertion -- that a *legitimate* indicator containing a literal `%`
    /// still matches a path genuinely containing it -- guards the obvious
    /// wrong fix of stripping the characters instead of escaping them.
    #[tokio::test]
    #[ignore]
    async fn a_wildcard_path_indicator_does_not_match_every_scanned_file() {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://nsic:nsic@localhost:5432/nsic".to_string());
        let pool = crate::db::connect_and_migrate(&database_url)
            .await
            .expect("connect to test database");

        let marker = uuid::Uuid::new_v4();
        let now = Utc::now();
        let (report_id, _) = crate::db::indicators::upsert_report(
            &pool,
            "test-source",
            Some(&format!("wildcard-{marker}")),
            Some("Test report"),
            None,
            Some(now),
            &serde_json::json!({}),
        )
        .await
        .expect("seed report");

        // The hostile shape: a bare `%`, which as an unescaped LIKE
        // pattern matches anything at all.
        let (wildcard_id, _) =
            crate::db::indicators::upsert_indicator(&pool, IndicatorKind::Path, "%")
                .await
                .expect("seed wildcard path indicator");
        crate::db::indicators::upsert_indicator_observed_in_report(
            &pool,
            wildcard_id,
            report_id,
            "test-source",
            90,
            now,
            now,
        )
        .await
        .expect("seed observation for the wildcard indicator");

        // A legitimate indicator that happens to contain a literal `%`,
        // seeded with a unique marker so it can only match the second
        // file below.
        let literal_value = format!("lit%{}", marker.simple());
        let (literal_id, _) =
            crate::db::indicators::upsert_indicator(&pool, IndicatorKind::Path, &literal_value)
                .await
                .expect("seed literal-percent path indicator");
        crate::db::indicators::upsert_indicator_observed_in_report(
            &pool,
            literal_id,
            report_id,
            "test-source",
            90,
            now,
            now,
        )
        .await
        .expect("seed observation for the literal indicator");

        let unrelated = crate::db::indicators::path_pattern_matches(
            &pool,
            &format!("/home/analyst/unrelated-{marker}.txt"),
        )
        .await
        .expect("path pattern lookup");
        assert!(
            !unrelated.iter().any(|e| e.matched_value == "%"),
            "a `%` path indicator must not match an unrelated file -- LIKE wildcards in an \
             indicator value have to be escaped, got: {unrelated:?}"
        );

        let genuinely_matching = crate::db::indicators::path_pattern_matches(
            &pool,
            &format!("/opt/{literal_value}/payload.bin"),
        )
        .await
        .expect("path pattern lookup");
        assert!(
            genuinely_matching
                .iter()
                .any(|e| e.matched_value == literal_value),
            "escaping must not break a legitimate indicator that contains a literal `%` -- it \
             should still match a path genuinely containing that text, got: \
             {genuinely_matching:?}"
        );
    }

    /// Review finding 1 (round 4), second requested regression shape: a
    /// rule historically recorded as having matched this hash must not
    /// resurrect as a *current* `YaraHit`/`Detection` relationship just
    /// because a *different* rule genuinely fires in this scan.
    #[tokio::test]
    #[ignore]
    async fn a_stale_rule_edge_does_not_resurface_when_a_different_rule_fires_this_scan() {
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
        let intel_gate = IntelGate::new();
        let recent_yara_hits = RecentYaraHits::new();

        let mut tmp = tempfile_eicar();
        tmp.flush().unwrap();
        let (hash, _) = crate::hashing::hash_and_read_file(&pool, tmp.path())
            .await
            .expect("hash temp file");

        // A rule historically recorded against EICAR's hash that is not
        // one of the rules actually loaded/scanned here.
        let (indicator_id, _) =
            crate::db::indicators::upsert_indicator(&pool, IndicatorKind::Sha256, &hash.sha256)
                .await
                .expect("seed indicator");
        let unique_marker = uuid::Uuid::new_v4();
        let stale_rule_name = format!("StaleRule-{unique_marker}");
        let stale_detection_id = crate::db::indicators::upsert_detection(
            &pool,
            DetectionKind::Yara,
            &stale_rule_name,
            None,
            None,
            None,
        )
        .await
        .expect("seed stale detection");
        let now = Utc::now();
        crate::db::indicators::upsert_detection_detects_indicator(
            &pool,
            stale_detection_id,
            indicator_id,
            "historical-source",
            50,
            now,
            now,
            "",
        )
        .await
        .expect("seed stale detection detects indicator");

        let verdict = resolve(
            &pool,
            &bloom,
            &intel_gate,
            &yara,
            &recent_yara_hits,
            tmp.path(),
        )
        .await
        .expect("resolve verdict");

        assert!(
            verdict
                .entries
                .iter()
                .any(|e| e.tier == VerdictTier::YaraHit
                    && e.detection_name.as_deref() == Some("Example_EICAR_Test_File")),
            "expected the real EICAR rule to fire, got: {:?}",
            verdict.entries
        );
        assert!(
            !verdict
                .entries
                .iter()
                .any(|e| e.detection_name.as_deref() == Some(stale_rule_name.as_str())),
            "a rule that did not fire in this scan must not appear as a current YaraHit just \
             because a different rule fired, got: {:?}",
            verdict.entries
        );
        assert!(
            !verdict
                .threat_relationships
                .iter()
                .any(|r| r.kind == crate::models::RelationshipKind::Detection
                    && r.target == stale_rule_name),
            "a rule that did not fire in this scan must not surface as a current Detection \
             relationship either, got: {:?}",
            verdict.threat_relationships
        );
    }

    /// Review finding 2 (round 5): a bloom filter that has never
    /// successfully refreshed (or whose last refresh failed) must not be
    /// trusted to report a miss. Deliberately never calls `bloom.refresh`,
    /// so this `BloomState` stays exactly as invalid as the real one would
    /// be if startup's or `sync_feeds`'s refresh had failed -- see
    /// `BloomState`'s doc comment. Seeds a real exact-hash match and a
    /// real malware-family attribution directly in Postgres and confirms
    /// `resolve()` still surfaces both through the DB fallback path,
    /// proving a miss from an unsynchronized filter can't hide real
    /// evidence.
    #[tokio::test]
    #[ignore]
    async fn bloom_fallback_surfaces_db_evidence_when_the_filter_is_not_valid() {
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
        // Never refreshed -- must stay invalid.
        let bloom = BloomState::empty();
        let intel_gate = IntelGate::new();
        let recent_yara_hits = RecentYaraHits::new();
        assert!(
            matches!(
                bloom.check(&[]).await,
                crate::bloom::LookupResult::FilterInvalid
            ),
            "sanity: a fresh BloomState must start invalid"
        );

        let mut tmp = tempfile::NamedTempFile::new().expect("create temp file");
        let marker = uuid::Uuid::new_v4();
        tmp.write_all(format!("bloom fallback test content {marker}").as_bytes())
            .unwrap();
        tmp.flush().unwrap();
        let (hash, _) = crate::hashing::hash_and_read_file(&pool, tmp.path())
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
            Some(&marker.to_string()),
            Some("Test report"),
            None,
            Some(now),
            &serde_json::json!({}),
        )
        .await
        .expect("seed report");
        crate::db::indicators::upsert_indicator_observed_in_report(
            &pool,
            indicator_id,
            report_id,
            "test-source",
            90,
            now,
            now,
        )
        .await
        .expect("seed indicator observed in report");
        let family_name = format!("BloomFallbackFamily-{marker}");
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

        // Deliberately not calling bloom.insert either -- the point is
        // that the fallback works even when the filter genuinely has no
        // idea this hash exists.
        let verdict = resolve(
            &pool,
            &bloom,
            &intel_gate,
            &yara,
            &recent_yara_hits,
            tmp.path(),
        )
        .await
        .expect("resolve verdict");

        assert!(
            verdict
                .entries
                .iter()
                .any(|e| e.tier == VerdictTier::ExactHash),
            "expected the DB fallback path to surface the exact-hash match even though the \
             bloom filter was never valid, got: {:?}",
            verdict.entries
        );
        assert!(
            verdict
                .threat_relationships
                .iter()
                .any(|r| r.kind == crate::models::RelationshipKind::MalwareFamily
                    && r.target == family_name),
            "expected the DB fallback path to surface the malware-family relationship even \
             though the bloom filter was never valid, got: {:?}",
            verdict.threat_relationships
        );
    }

    /// Review finding 3 (round 5): `detection` rows are keyed by
    /// `(kind, name)`, so editing a YARA rule's body while keeping its
    /// name reuses the same row -- a `detection_covers_cve` edge attached
    /// to that row must not silently keep applying once the rule's
    /// content has actually changed. Loads two temporary rulesets sharing
    /// one rule *identifier* but with different bodies (matching different
    /// marker strings, so each only fires on its own content), attaches
    /// CVE coverage scoped to the v1 ruleset's fingerprint, then scans
    /// v2-matching content with the v2 engine and confirms the coverage
    /// does not transfer.
    #[tokio::test]
    #[ignore]
    async fn cve_coverage_does_not_transfer_across_a_rule_content_revision() {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://nsic:nsic@localhost:5432/nsic".to_string());
        let pool = crate::db::connect_and_migrate(&database_url)
            .await
            .expect("connect to test database");

        let marker = uuid::Uuid::new_v4().simple().to_string();
        let rule_name = format!("VersionedRule_{marker}");

        let v1_dir = tempfile::tempdir().expect("create v1 rules dir");
        std::fs::write(
            v1_dir.path().join("rule.yar"),
            format!("rule {rule_name} {{ strings: $s = \"MARKERV1_{marker}\" condition: $s }}"),
        )
        .expect("write v1 rule");
        let yara_v1 = Arc::new(YaraEngine::load(v1_dir.path()).expect("load v1 rules"));

        let v2_dir = tempfile::tempdir().expect("create v2 rules dir");
        std::fs::write(
            v2_dir.path().join("rule.yar"),
            format!("rule {rule_name} {{ strings: $s = \"MARKERV2_{marker}\" condition: $s }}"),
        )
        .expect("write v2 rule");
        let yara_v2 = Arc::new(YaraEngine::load(v2_dir.path()).expect("load v2 rules"));

        assert_ne!(
            yara_v1.rule_fingerprint(&rule_name),
            yara_v2.rule_fingerprint(&rule_name),
            "sanity: different rule bodies must produce different fingerprints"
        );

        let bloom = BloomState::empty();
        let intel_gate = IntelGate::new();

        // Scan v1-matching content with the v1 engine: persists a real
        // detects_indicator edge carrying v1's fingerprint.
        let mut tmp_v1 = tempfile::NamedTempFile::new().expect("create temp file");
        tmp_v1
            .write_all(format!("MARKERV1_{marker}").as_bytes())
            .unwrap();
        tmp_v1.flush().unwrap();
        let recent_yara_hits_v1 = RecentYaraHits::new();
        let verdict_v1 = resolve(
            &pool,
            &bloom,
            &intel_gate,
            &yara_v1,
            &recent_yara_hits_v1,
            tmp_v1.path(),
        )
        .await
        .expect("resolve v1 verdict");
        assert!(
            verdict_v1
                .entries
                .iter()
                .any(|e| e.tier == VerdictTier::YaraHit
                    && e.detection_name.as_deref() == Some(rule_name.as_str())),
            "expected the v1 rule to fire on v1 content, got: {:?}",
            verdict_v1.entries
        );

        // CVE coverage is scoped to v1's fingerprint specifically.
        let detection_id = crate::db::indicators::upsert_detection(
            &pool,
            DetectionKind::Yara,
            &rule_name,
            None,
            None,
            None,
        )
        .await
        .expect("seed detection");
        let cve_id = format!("CVE-TEST-{marker}");
        crate::db::indicators::upsert_cve(&pool, &cve_id, None, None, None)
            .await
            .expect("seed cve");
        let now = Utc::now();
        crate::db::indicators::upsert_detection_covers_cve(
            &pool,
            detection_id,
            &cve_id,
            "test-source",
            80,
            now,
            now,
            yara_v1
                .rule_fingerprint(&rule_name)
                .expect("v1 rule should have a fingerprint"),
        )
        .await
        .expect("seed detection covers cve scoped to v1");

        // Scan v2-matching content with the v2 engine: same rule
        // identifier, different body/fingerprint.
        let mut tmp_v2 = tempfile::NamedTempFile::new().expect("create temp file");
        tmp_v2
            .write_all(format!("MARKERV2_{marker}").as_bytes())
            .unwrap();
        tmp_v2.flush().unwrap();
        let recent_yara_hits_v2 = RecentYaraHits::new();
        let verdict_v2 = resolve(
            &pool,
            &bloom,
            &intel_gate,
            &yara_v2,
            &recent_yara_hits_v2,
            tmp_v2.path(),
        )
        .await
        .expect("resolve v2 verdict");
        assert!(
            verdict_v2
                .entries
                .iter()
                .any(|e| e.tier == VerdictTier::YaraHit
                    && e.detection_name.as_deref() == Some(rule_name.as_str())),
            "expected the v2 rule to fire on v2 content, got: {:?}",
            verdict_v2.entries
        );
        assert!(
            !verdict_v2
                .threat_relationships
                .iter()
                .any(|r| r.kind == crate::models::RelationshipKind::Cve && r.target == cve_id),
            "v1's CVE coverage must not transfer to a scan performed with a different ruleset \
             fingerprint, got: {:?}",
            verdict_v2.threat_relationships
        );
    }

    fn tempfile_eicar() -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().expect("create temp file");
        f.write_all(br"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
            .expect("write eicar bytes");
        f
    }
}
