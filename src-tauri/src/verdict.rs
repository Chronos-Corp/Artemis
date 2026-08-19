use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::bloom::{BloomState, IntelGate};
use crate::db::indicators as db;
use crate::db::relationship_bounds as bounded_relationships;
use crate::hashing;
use crate::models::{
    derive_relationships, DetectionKind, IndicatorKind, ProvenanceEntry, Verdict, VerdictBounds,
    VerdictTier,
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

    resolve_in_intel_snapshot(pool, bloom, yara, recent_yara_hits, path).await
}

/// Resolves one file while the caller already holds `IntelGate`'s read side.
/// Kept visible only to the parent relationship-contract module so a bounded
/// multi-file hunt can use one coherent intel snapshot without attempting a
/// nested read acquisition (which can deadlock behind a queued writer on a
/// fair `RwLock`). All external consumers still go through the normalized
/// relationship contract.
pub(super) async fn resolve_in_intel_snapshot(
    pool: &PgPool,
    bloom: &BloomState,
    yara: &Arc<YaraEngine>,
    recent_yara_hits: &RecentYaraHits,
    path: &Path,
) -> Result<Verdict> {
    resolve_in_intel_snapshot_inner(pool, bloom, yara, recent_yara_hits, path, None).await
}

/// Hash-pinned variant for HUNT's selected seed. The expected digest is
/// checked immediately after the resolver's single file read, before YARA
/// scanning or evidence persistence can observe a stale/replaced seed.
pub(super) async fn resolve_in_intel_snapshot_with_expected_sha256(
    pool: &PgPool,
    bloom: &BloomState,
    yara: &Arc<YaraEngine>,
    recent_yara_hits: &RecentYaraHits,
    path: &Path,
    expected_sha256: &str,
) -> Result<Verdict> {
    resolve_in_intel_snapshot_inner(
        pool,
        bloom,
        yara,
        recent_yara_hits,
        path,
        Some(expected_sha256),
    )
    .await
}

async fn resolve_in_intel_snapshot_inner(
    pool: &PgPool,
    bloom: &BloomState,
    yara: &Arc<YaraEngine>,
    recent_yara_hits: &RecentYaraHits,
    path: &Path,
    expected_sha256: Option<&str>,
) -> Result<Verdict> {
    // Read the file's bytes exactly once and hash + YARA-scan the identical
    // buffer -- see `hashing::hash_and_read_file`'s doc comment for why:
    // two separate reads (one to hash, one to scan) can observe different
    // content if the file changes in between, silently binding a YARA hit's
    // persisted edge to the wrong hash.
    let (hash, file_data) = hashing::hash_and_read_file(pool, path).await?;
    require_expected_sha256(&hash.sha256, expected_sha256)?;
    let mut entries = Vec::new();
    // Accumulates which parts of this verdict a cap made partial. Folded in
    // at each capped lookup rather than inferred at the end: "we returned
    // exactly the cap" is not the same fact as "more existed", and only the
    // query knows which one happened. See `VerdictBounds`.
    let mut bounds = VerdictBounds::default();

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
        // Both hash kinds feed the one ExactHash tier, so either being
        // capped makes that tier partial.
        let mut exact_hash_truncated = sha_rows.truncated;
        entries.extend(db::hash_matches_to_provenance(
            sha_rows.items,
            VerdictTier::ExactHash,
            IndicatorKind::Sha256,
        ));
        let md5_rows = db::hash_matches(pool, IndicatorKind::Md5, &hash.md5).await?;
        exact_hash_truncated |= md5_rows.truncated;
        entries.extend(db::hash_matches_to_provenance(
            md5_rows.items,
            VerdictTier::ExactHash,
            IndicatorKind::Md5,
        ));
        record_exact_hash_truncation(&mut bounds, exact_hash_truncated);

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
        // The concept-aware wrappers keep the existing sqlx-macro queries
        // as the fast path, but if their assertion-level safety cap fires
        // they rerun with a target-ranked query. That closes the round-9
        // case where 200 assertions about CVE-A/family-A consumed the
        // entire budget and hid CVE-B/family-B even though only two actual
        // hunt pivots existed.
        let families =
            bounded_relationships::malware_family_matches(pool, &hash.sha256, &hash.md5).await?;
        bounds.relationships_truncated |= families.truncated;
        dedicated_relationships = families.items;

        let cve_via_report =
            bounded_relationships::cve_matches_via_report(pool, &hash.sha256, &hash.md5).await?;
        bounds.relationships_truncated |= cve_via_report.truncated;
        dedicated_relationships.extend(cve_via_report.items);
    }

    // Tier 3: YARA is orthogonal to known-bad hash status, always runs.
    // Scanning is synchronous CPU-bound work, so it runs on tokio's
    // blocking pool rather than an async worker thread. Scans the same
    // `file_data` buffer that was just hashed -- see the read-once comment
    // at the top of this function.
    //
    // `scan_bytes_bounded` is deliberately used rather than `scan_bytes`:
    // the local rules directory is attacker-influenced on a compromised
    // host, so rule-hit cardinality cannot be allowed to dictate unbounded
    // DB writes, provenance entries, SQL arrays, or relationship objects.
    // The YARA engine separately bounds the active ruleset itself, so this
    // verdict cap is not merely applied after unbounded work has happened.
    let yara_for_scan = Arc::clone(yara);
    let yara_scan = tokio::task::spawn_blocking(move || yara_for_scan.scan_bytes_bounded(&file_data))
        .await
        .context("yara scan task panicked")??;
    let yara_truncated = yara_scan.truncated;
    let yara_hits = yara_scan.matches;
    if yara_truncated {
        bounds.truncated_entry_tiers.push(VerdictTier::YaraHit);
        // Every retained YARA hit is deduplicated by rule identifier before
        // the cap, so an omitted hit is definitionally an omitted Detection
        // target, not merely another evidence row for a target we already
        // returned. The relationship pivot set is therefore incomplete too.
        bounds.relationships_truncated = true;
    }

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
        let cve_via_detection = bounded_relationships::cve_matches_via_detection(
            pool,
            &scanned_rules,
            LOCAL_YARA_SOURCE,
            LOCAL_YARA_CONFIDENCE,
            now,
            IndicatorKind::Sha256,
            &hash.sha256,
        )
        .await?;
        bounds.relationships_truncated |= cve_via_detection.truncated;
        dedicated_relationships.extend(cve_via_detection.items);
    }

    // Tier 4: path/naming pattern.
    let path_str = path.to_string_lossy().to_string();
    let path_matches = db::path_pattern_matches(pool, &path_str).await?;
    if path_matches.truncated {
        bounds.truncated_entry_tiers.push(VerdictTier::PathPattern);
        let visible_targets: HashSet<String> = path_matches
            .items
            .iter()
            .map(|entry| entry.matched_value.clone())
            .collect();
        bounds.relationships_truncated |= bounded_relationships::path_relationships_incomplete(
            pool,
            &path_str,
            &visible_targets,
        )
        .await?;
    }
    entries.extend(path_matches.items);

    // Tier 5: contextual only, and only when nothing stronger already fired.
    let has_strong_match = entries
        .iter()
        .any(|e| matches!(e.tier, VerdictTier::ExactHash | VerdictTier::YaraHit));
    if !has_strong_match {
        if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
            let contextual = db::contextual_matches(pool, file_name).await?;
            if contextual.truncated {
                bounds.truncated_entry_tiers.push(VerdictTier::Contextual);
            }
            entries.extend(contextual.items);
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

    // Tiers are collected in query order; sorted so the wire value is
    // stable regardless of which lookups ran for this particular file.
    bounds.truncated_entry_tiers.sort();
    bounds.truncated_entry_tiers.dedup();

    Ok(Verdict {
        path: path_str,
        sha256: hash.sha256,
        md5: hash.md5,
        entries,
        intel_freshness,
        threat_relationships,
        bounds,
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

fn require_expected_sha256(actual: &str, expected: Option<&str>) -> Result<()> {
    if let Some(expected) = expected {
        if actual != expected {
            anyhow::bail!(
                "hunt seed changed since TRACE: expected SHA-256 {expected}, observed {actual}; select the file again"
            );
        }
    }
    Ok(())
}

fn record_exact_hash_truncation(bounds: &mut VerdictBounds, truncated: bool) {
    if truncated {
        bounds.truncated_entry_tiers.push(VerdictTier::ExactHash);
        // Exact-hash provenance rows are also the source of IOC
        // relationships. Omitted rows may contain distinct pivots that were
        // never materialized, so HUNT must treat a non-match as inconclusive
        // rather than as evidence of absence.
        bounds.relationships_truncated = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bloom::BloomState;
    use crate::yara_scan::YaraEngine;
    use std::io::Write;

    #[test]
    fn hash_pin_rejects_changed_seed_before_resolution_continues() {
        let error = require_expected_sha256("observed", Some("expected")).unwrap_err();
        assert!(error.to_string().contains("hunt seed changed since TRACE"));
        assert!(require_expected_sha256("same", Some("same")).is_ok());
        assert!(require_expected_sha256("anything", None).is_ok());
    }

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

    /// Round 9: YARA hit cardinality is attacker-influenced through the
    /// local rules directory. A single file matching more rules than the
    /// verdict budget must bound persistence/provenance/pivots and say that
    /// both the YARA tier and relationship set are partial.
    #[tokio::test]
    #[ignore]
    async fn yara_hit_budget_is_explicit_in_verdict_bounds() {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://nsic:nsic@localhost:5432/nsic".to_string());
        let pool = crate::db::connect_and_migrate(&database_url)
            .await
            .expect("connect to test database");

        let marker = uuid::Uuid::new_v4().simple().to_string();
        let rules_dir = tempfile::tempdir().expect("create temp rules dir");
        let mut source = String::new();
        for n in 0..(crate::yara_scan::MAX_YARA_MATCHES_PER_VERDICT + 5) {
            source.push_str(&format!(
                "rule Bound_{marker}_{n:04} {{ condition: true }}\n"
            ));
        }
        std::fs::write(rules_dir.path().join("many.yar"), source).expect("write test rules");
        let yara = Arc::new(YaraEngine::load(rules_dir.path()).expect("load test rules"));

        let bloom = BloomState::empty();
        let intel_gate = IntelGate::new();
        let recent_yara_hits = RecentYaraHits::new();
        let mut tmp = tempfile::NamedTempFile::new().expect("create temp file");
        tmp.write_all(format!("bounded-yara-{marker}").as_bytes())
            .unwrap();
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
        .expect("resolve bounded YARA verdict");

        let yara_entries = verdict
            .entries
            .iter()
            .filter(|entry| entry.tier == VerdictTier::YaraHit)
            .count();
        assert_eq!(
            yara_entries,
            crate::yara_scan::MAX_YARA_MATCHES_PER_VERDICT,
            "only the deterministic YARA hit budget may be materialized"
        );
        assert!(
            verdict
                .bounds
                .truncated_entry_tiers
                .contains(&VerdictTier::YaraHit),
            "the YARA provenance tier must say it is partial"
        );
        assert!(
            verdict.bounds.relationships_truncated,
            "omitted rule identifiers are omitted Detection pivots, so the relationship set is partial too"
        );
    }

    /// Malware-family attribution has its own edge table (not derivable
    /// from provenance entries alone -- see `derive_relationships`'s doc
    /// comment), so it needs its own live test proving `resolve()` and
    /// `db::malware_family_matches` actually connect end to end.
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
        assert_eq!(
            relationship.strength,
            crate::models::RelationshipStrength::Direct
        );
        assert_eq!(relationship.evidence_paths.len(), 1);
        assert_eq!(relationship.evidence_paths[0].len(), 1);
        assert_eq!(relationship.evidence_paths[0][0].report_id, Some(report_id));
    }

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
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].evidence_paths[0][0].report_id, Some(report_b_id));
    }

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

        use chrono::SubsecRound;
        let parent_first_seen = (Utc::now() - chrono::Duration::days(30)).trunc_subsecs(6);
        let parent_last_seen = (Utc::now() - chrono::Duration::days(29)).trunc_subsecs(6);
        let cve_first_seen = (Utc::now() - chrono::Duration::days(2)).trunc_subsecs(6);
        let cve_last_seen = (Utc::now() - chrono::Duration::days(1)).trunc_subsecs(6);

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
            .unwrap();
        assert_eq!(via_report.evidence_paths.len(), 1);
        let path = &via_report.evidence_paths[0];
        assert_eq!(path.len(), 2);
        assert_eq!(path[0].relation, crate::models::EvidenceRelation::ObservedInReport);
        assert_eq!(path[0].source, "parent-edge-source");
        assert_eq!(path[0].confidence, 20);
        assert_eq!(path[0].first_seen, parent_first_seen);
        assert_eq!(path[0].last_seen, parent_last_seen);
        assert_eq!(path[1].relation, crate::models::EvidenceRelation::ReportReferencesCve);
        assert_eq!(path[1].source, "cve-edge-source");
        assert_eq!(path[1].confidence, 77);
        assert_eq!(path[1].first_seen, cve_first_seen);
        assert_eq!(path[1].last_seen, cve_last_seen);
        assert_eq!(via_report.strength, crate::models::RelationshipStrength::Contextual);

        let exact_hash_entry = verdict_report
            .entries
            .iter()
            .find(|e| e.tier == VerdictTier::ExactHash)
            .unwrap();
        assert_eq!(exact_hash_entry.source, "parent-edge-source");
        assert_eq!(exact_hash_entry.confidence, 20);
        let exact_hash_entry_json =
            serde_json::to_string(exact_hash_entry).expect("serialize provenance entry");
        assert!(!exact_hash_entry_json.contains(&cve_via_report_id));

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
            .unwrap();
        let path = &via_detection.evidence_paths[0];
        assert_eq!(path.len(), 2);
        assert_eq!(path[0].relation, crate::models::EvidenceRelation::DetectsIndicator);
        assert_eq!(path[0].source, "local:yara_scan");
        assert_eq!(path[0].confidence, 65);
        assert_eq!(path[0].indicator_kind, Some(IndicatorKind::Sha256));
        assert_eq!(path[0].indicator_value, Some(verdict_detection.sha256.clone()));
        assert_eq!(path[1].relation, crate::models::EvidenceRelation::DetectionCoversCve);
        assert_eq!(path[1].source, "covers-edge-source");
        assert_eq!(path[1].confidence, 88);
        assert_eq!(path[1].first_seen, cve_first_seen);
        assert_eq!(path[1].last_seen, cve_last_seen);
        assert_eq!(path[1].rule_fingerprint, None);
        assert_eq!(via_detection.strength, crate::models::RelationshipStrength::Strong);
        assert!(via_detection.explanation.contains("Example_EICAR_Test_File"));
    }

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
        let bloom = BloomState::empty();
        let intel_gate = IntelGate::new();
        let recent_yara_hits = RecentYaraHits::new();

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
                .any(|r| r.kind == crate::models::RelationshipKind::Cve && r.target == cve_id)
        );
    }

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
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].evidence_paths.len(), 2);
        for path in &matches[0].evidence_paths {
            assert_eq!(path.len(), 2);
            assert_eq!(path[0].relation, crate::models::EvidenceRelation::ObservedInReport);
            assert_eq!(path[1].relation, crate::models::EvidenceRelation::ReportReferencesCve);
        }
        let observed_values: Vec<Option<String>> = matches[0]
            .evidence_paths
            .iter()
            .map(|path| path[0].indicator_value.clone())
            .collect();
        assert!(observed_values.contains(&Some(hash.sha256.clone())));
        assert!(observed_values.contains(&Some(hash.md5.clone())));
    }

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
        assert_eq!(yara.rule_count, 2);

        let bloom = BloomState::empty();
        let intel_gate = IntelGate::new();
        let recent_yara_hits = RecentYaraHits::new();

        let mut tmp = tempfile::NamedTempFile::new().expect("create temp file");
        tmp.write_all(format!("MARKERA_{marker} MARKERB_{marker}").as_bytes())
            .unwrap();
        tmp.flush().unwrap();

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

        let yara_hit_names: Vec<_> = verdict
            .entries
            .iter()
            .filter(|e| e.tier == VerdictTier::YaraHit)
            .filter_map(|e| e.detection_name.clone())
            .collect();
        assert!(yara_hit_names.contains(&rule_a_name) && yara_hit_names.contains(&rule_b_name));

        let relationship = verdict
            .threat_relationships
            .iter()
            .find(|r| r.kind == crate::models::RelationshipKind::Cve && r.target == cve_id)
            .unwrap();
        assert!(relationship.explanation.contains(&rule_b_name));
        assert!(!relationship.explanation.contains(&rule_a_name));
        assert_eq!(
            relationship.evidence_paths[0][1].detection_name,
            Some(rule_b_name)
        );
    }

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
            .unwrap();
        assert!(freshness.last_successful_sync_at.is_some());

        restore_sync_state(&pool, "malwarebazaar", prior_malwarebazaar_state).await;
    }

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
                .unwrap();
            assert!(malwarebazaar.last_successful_sync_at.is_some());

            let threatfox = verdict
                .intel_freshness
                .iter()
                .find(|f| f.source == "threatfox")
                .unwrap();
            assert!(threatfox.last_successful_sync_at.is_none());
        })
        .await;

        restore_sync_state(&pool, "malwarebazaar", prior_malwarebazaar_state).await;
        restore_sync_state(&pool, "threatfox", prior_threatfox_state).await;

        if let Err(join_err) = outcome {
            std::panic::resume_unwind(join_err.into_panic());
        }
    }

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
        assert!(first_attempt.is_err());
        assert!(!recent_yara_hits.contains(&sha256, &rule_name).await);

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
        assert!(exists);
    }

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
                .any(|r| r.kind == crate::models::RelationshipKind::Cve && r.target == cve_id)
        );
    }

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
        assert!(!unrelated.items.iter().any(|e| e.matched_value == "%"));

        let genuinely_matching = crate::db::indicators::path_pattern_matches(
            &pool,
            &format!("/opt/{literal_value}/payload.bin"),
        )
        .await
        .expect("path pattern lookup");
        assert!(
            genuinely_matching
                .items
                .iter()
                .any(|e| e.matched_value == literal_value)
        );
    }

    /// Round 9: a row-level path cap can hide a different path indicator
    /// target when one heavily-observed pattern owns the newest rows. The
    /// tier partiality flag alone is insufficient because RELATE then lacks
    /// an IOC/RiskBased pivot. The helper must detect that distinct target
    /// omission and mark the relationship set partial too.
    #[tokio::test]
    #[ignore]
    async fn truncated_path_rows_mark_relationships_partial_when_a_target_is_hidden() {
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

        let marker = uuid::Uuid::new_v4();
        let mut tmp = tempfile::NamedTempFile::new().expect("create temp file");
        tmp.write_all(format!("path-bound-{marker}").as_bytes()).unwrap();
        tmp.flush().unwrap();
        let path_text = tmp.path().to_string_lossy().to_string();
        let noisy_pattern = "/";
        let hidden_pattern = tmp
            .path()
            .file_name()
            .unwrap()
            .to_string_lossy()
            .to_string();
        assert!(path_text.contains(noisy_pattern) && path_text.contains(&hidden_pattern));

        let (noisy_id, _) = crate::db::indicators::upsert_indicator(
            &pool,
            IndicatorKind::Path,
            noisy_pattern,
        )
        .await
        .expect("seed noisy path indicator");
        let (hidden_id, _) = crate::db::indicators::upsert_indicator(
            &pool,
            IndicatorKind::Path,
            &hidden_pattern,
        )
        .await
        .expect("seed hidden path indicator");

        let now = Utc::now();
        for n in 0..=crate::db::indicators::MAX_VERDICT_ROWS {
            let (report_id, _) = crate::db::indicators::upsert_report(
                &pool,
                "path-bound-test",
                Some(&format!("noisy-{marker}-{n}")),
                Some("Noisy path report"),
                None,
                Some(now),
                &serde_json::json!({}),
            )
            .await
            .expect("seed noisy report");
            crate::db::indicators::upsert_indicator_observed_in_report(
                &pool,
                noisy_id,
                report_id,
                "path-bound-test",
                50,
                now,
                now,
            )
            .await
            .expect("seed noisy path observation");
        }

        let older = now - chrono::Duration::days(1);
        let (hidden_report, _) = crate::db::indicators::upsert_report(
            &pool,
            "path-bound-test",
            Some(&format!("hidden-{marker}")),
            Some("Hidden path report"),
            None,
            Some(older),
            &serde_json::json!({}),
        )
        .await
        .expect("seed hidden report");
        crate::db::indicators::upsert_indicator_observed_in_report(
            &pool,
            hidden_id,
            hidden_report,
            "path-bound-test",
            50,
            older,
            older,
        )
        .await
        .expect("seed hidden path observation");

        let verdict = resolve(
            &pool,
            &bloom,
            &intel_gate,
            &yara,
            &recent_yara_hits,
            tmp.path(),
        )
        .await
        .expect("resolve path-bound verdict");

        assert!(
            verdict
                .bounds
                .truncated_entry_tiers
                .contains(&VerdictTier::PathPattern)
        );
        assert!(
            verdict.bounds.relationships_truncated,
            "the omitted path target means the RELATE pivot set is incomplete"
        );
        assert!(
            !verdict
                .threat_relationships
                .iter()
                .any(|relationship| relationship.target == hidden_pattern),
            "sanity: the older target should be outside the row-level sample in this fixture"
        );
    }

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
                    && e.detection_name.as_deref() == Some("Example_EICAR_Test_File"))
        );
        assert!(
            !verdict
                .entries
                .iter()
                .any(|e| e.detection_name.as_deref() == Some(stale_rule_name.as_str()))
        );
        assert!(
            !verdict
                .threat_relationships
                .iter()
                .any(|r| r.kind == crate::models::RelationshipKind::Detection
                    && r.target == stale_rule_name)
        );
    }

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
        let bloom = BloomState::empty();
        let intel_gate = IntelGate::new();
        let recent_yara_hits = RecentYaraHits::new();
        assert!(matches!(
            bloom.check(&[]).await,
            crate::bloom::LookupResult::FilterInvalid
        ));

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

        assert!(verdict.entries.iter().any(|e| e.tier == VerdictTier::ExactHash));
        assert!(
            verdict
                .threat_relationships
                .iter()
                .any(|r| r.kind == crate::models::RelationshipKind::MalwareFamily
                    && r.target == family_name)
        );
    }

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
            yara_v2.rule_fingerprint(&rule_name)
        );

        let bloom = BloomState::empty();
        let intel_gate = IntelGate::new();

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
        assert!(verdict_v1.entries.iter().any(|e| {
            e.tier == VerdictTier::YaraHit
                && e.detection_name.as_deref() == Some(rule_name.as_str())
        }));

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
            yara_v1.rule_fingerprint(&rule_name).unwrap(),
        )
        .await
        .expect("seed detection covers cve scoped to v1");

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
        assert!(verdict_v2.entries.iter().any(|e| {
            e.tier == VerdictTier::YaraHit
                && e.detection_name.as_deref() == Some(rule_name.as_str())
        }));
        assert!(
            !verdict_v2
                .threat_relationships
                .iter()
                .any(|r| r.kind == crate::models::RelationshipKind::Cve && r.target == cve_id)
        );
    }

    #[tokio::test]
    #[ignore]
    async fn one_over_supported_cve_edge_cannot_hide_another_or_its_own_omissions() {
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

        let marker = uuid::Uuid::new_v4();
        let mut tmp = tempfile::NamedTempFile::new().expect("create temp file");
        tmp.write_all(format!("evidence cap test content {marker}").as_bytes())
            .unwrap();
        tmp.flush().unwrap();
        let (hash, _) = crate::hashing::hash_and_read_file(&pool, tmp.path())
            .await
            .expect("hash temp file");

        let (indicator_id, _) =
            crate::db::indicators::upsert_indicator(&pool, IndicatorKind::Sha256, &hash.sha256)
                .await
                .expect("seed indicator");

        let seen = Utc::now() - chrono::Duration::days(3);
        let over_supported_parents = crate::db::indicators::MAX_VERDICT_ROWS + 5;
        let (report_a, _) = crate::db::indicators::upsert_report(
            &pool,
            "cap-test",
            Some(&format!("a-{marker}")),
            Some("Report A"),
            None,
            Some(seen),
            &serde_json::json!({}),
        )
        .await
        .expect("seed report A");
        for n in 0..over_supported_parents {
            crate::db::indicators::upsert_indicator_observed_in_report(
                &pool,
                indicator_id,
                report_a,
                &format!("parent-source-{n:03}"),
                40,
                seen,
                seen,
            )
            .await
            .expect("seed one of many parent observations");
        }
        let cve_a = format!("CVE-CAPA-{}", marker.simple());
        crate::db::indicators::upsert_cve(&pool, &cve_a, None, None, None)
            .await
            .expect("seed cve A");
        crate::db::indicators::upsert_report_references_cve(
            &pool, report_a, &cve_a, "cve-src", 70, seen, seen,
        )
        .await
        .expect("seed edge A");

        let (report_b, _) = crate::db::indicators::upsert_report(
            &pool,
            "cap-test",
            Some(&format!("b-{marker}")),
            Some("Report B"),
            None,
            Some(seen),
            &serde_json::json!({}),
        )
        .await
        .expect("seed report B");
        crate::db::indicators::upsert_indicator_observed_in_report(
            &pool,
            indicator_id,
            report_b,
            "parent-source-b",
            40,
            seen,
            seen,
        )
        .await
        .expect("seed parent observation for B");
        let cve_b = format!("CVE-CAPB-{}", marker.simple());
        crate::db::indicators::upsert_cve(&pool, &cve_b, None, None, None)
            .await
            .expect("seed cve B");
        crate::db::indicators::upsert_report_references_cve(
            &pool, report_b, &cve_b, "cve-src", 70, seen, seen,
        )
        .await
        .expect("seed edge B");

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

        let find = |target: &str| {
            verdict
                .threat_relationships
                .iter()
                .find(|r| r.kind == crate::models::RelationshipKind::Cve && r.target == target)
        };
        let rel_a = find(&cve_a).expect("CVE A should be present");
        assert!(find(&cve_b).is_some());
        assert_eq!(
            rel_a.evidence_paths.len() as i64,
            crate::db::indicators::MAX_EVIDENCE_PER_RELATIONSHIP
        );
        assert!(rel_a.has_more_evidence);
        assert!(!find(&cve_b).unwrap().has_more_evidence);
        assert!(!verdict.bounds.relationships_truncated);
        for path in &rel_a.evidence_paths {
            assert_eq!(path.len(), 2);
        }
    }

    #[tokio::test]
    #[ignore]
    async fn legacy_unsafe_report_url_never_reaches_the_analyst_as_a_link() {
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

        let marker = uuid::Uuid::new_v4();
        let mut tmp = tempfile::NamedTempFile::new().expect("create temp file");
        tmp.write_all(format!("legacy url test content {marker}").as_bytes())
            .unwrap();
        tmp.flush().unwrap();
        let (hash, _) = crate::hashing::hash_and_read_file(&pool, tmp.path())
            .await
            .expect("hash temp file");

        let (indicator_id, _) =
            crate::db::indicators::upsert_indicator(&pool, IndicatorKind::Sha256, &hash.sha256)
                .await
                .expect("seed indicator");

        let seen_at = Utc::now() - chrono::Duration::days(1);
        const LEGACY_URL: &str = "javascript:fetch('http://evil.test/'+document.cookie)";
        const SAFE_URL: &str = "https://legit.test/report/1";

        let (unsafe_report_id, _) = crate::db::indicators::upsert_report(
            &pool,
            "legacy-writer",
            Some(&format!("unsafe-{marker}")),
            Some("Legacy report with an unsafe URL"),
            Some(LEGACY_URL),
            Some(seen_at),
            &serde_json::json!({}),
        )
        .await
        .expect("seed legacy report");
        crate::db::indicators::upsert_indicator_observed_in_report(
            &pool,
            indicator_id,
            unsafe_report_id,
            "legacy-edge-source",
            30,
            seen_at,
            seen_at,
        )
        .await
        .expect("seed legacy observation");

        let (safe_report_id, _) = crate::db::indicators::upsert_report(
            &pool,
            "legacy-writer",
            Some(&format!("safe-{marker}")),
            Some("Ordinary report with a safe URL"),
            Some(SAFE_URL),
            Some(seen_at),
            &serde_json::json!({}),
        )
        .await
        .expect("seed safe report");
        crate::db::indicators::upsert_indicator_observed_in_report(
            &pool,
            indicator_id,
            safe_report_id,
            "legacy-edge-source",
            30,
            seen_at,
            seen_at,
        )
        .await
        .expect("seed safe observation");

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

        let mut exposed_urls: Vec<&str> = verdict
            .entries
            .iter()
            .filter_map(|e| e.report_url.as_deref())
            .collect();
        exposed_urls.extend(
            verdict
                .threat_relationships
                .iter()
                .flat_map(|r| r.evidence_paths.iter())
                .flatten()
                .filter_map(|hop| hop.report_url.as_deref()),
        );

        assert!(!exposed_urls.iter().any(|u| u.contains("javascript:")));
        assert!(exposed_urls.contains(&SAFE_URL));
    }

    #[test]
    fn every_frontend_href_is_routed_through_the_url_allowlist() {
        let src = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("src");

        let mut checked_files = 0;
        let mut offenders: Vec<String> = Vec::new();
        let mut stack = vec![src.clone()];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).expect("read frontend src dir") {
                let path = entry.expect("read dir entry").path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                if path.extension().and_then(|e| e.to_str()) != Some("tsx") {
                    continue;
                }
                let text = std::fs::read_to_string(&path).expect("read component source");
                checked_files += 1;
                for (lineno, line) in text.lines().enumerate() {
                    if line.contains("href={") && !line.contains("safeExternalUrl(") {
                        offenders.push(format!(
                            "{}:{}: {}",
                            path.file_name().unwrap().to_string_lossy(),
                            lineno + 1,
                            line.trim()
                        ));
                    }
                }
            }
        }

        assert!(checked_files > 0);
        assert!(
            offenders.is_empty(),
            "every dynamic href must go through safeExternalUrl() (src/lib/safeUrl.ts); unguarded: {offenders:?}"
        );
    }

    fn tempfile_eicar() -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().expect("create temp file");
        f.write_all(br"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
            .expect("write eicar bytes");
        f
    }

    #[test]
    fn exact_hash_truncation_marks_relationships_partial() {
        let mut bounds = VerdictBounds::default();
        record_exact_hash_truncation(&mut bounds, true);

        assert!(
            bounds
                .truncated_entry_tiers
                .contains(&VerdictTier::ExactHash)
        );
        assert!(
            bounds.relationships_truncated,
            "omitted exact-hash rows may hide IOC pivots"
        );
    }
}
