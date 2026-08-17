use anyhow::Result;
use chrono::{DateTime, Utc};
use serde_json::Value as Json;
use sqlx::{PgExecutor, PgPool};
use uuid::Uuid;

use nsic_core::sanitize::sanitize_stored_url;

use crate::models::{
    DetectionKind, EvidenceRelation, EvidenceTiming, IndicatorKind, IntelSourceFreshness,
    ProvenanceEntry, RelationshipEvidence, RelationshipKind, RelationshipStrength,
    ThreatRelationship, VerdictTier,
};

/// Ceiling on `ProvenanceEntry` rows any single verdict lookup returns.
///
/// Not real pagination (there is no cursor) -- a bound, so one file can't
/// produce an unbounded provenance list. The intel graph is populated from
/// third-party feeds, so "how many reports observe this one hash" is not a
/// number Apollo controls; without a cap, a hash that many reports
/// reference inflates the IPC payload to the webview and the list an
/// analyst has to scroll. `contextual_matches` already capped itself at 20;
/// the other lookups did not, which was an inconsistency rather than a
/// deliberate choice. 200 is far past what is readable and still safely
/// bounded.
///
/// Every capped query reports whether its cap fired, via `Bounded`, and
/// `Verdict::bounds` carries that to the analyst and to PR #20 -- see
/// `VerdictBounds`. See `docs/threat-model.md` (resource bounds).
pub(crate) const MAX_VERDICT_ROWS: i64 = 200;

/// Ceiling on distinct *conceptual relationships* one query returns -- one
/// per real related concept (a CVE edge, a malware-family attribution), not
/// one per supporting row.
///
/// Deliberately a different budget from `MAX_EVIDENCE_PER_RELATIONSHIP`. A
/// review caught that a single row cap applied to the *joined* rows let one
/// heavily-supported edge consume the entire allowance: with 200 matching
/// parent observations for CVE edge A, an entirely distinct and equally
/// real CVE edge B never reached the grouping code at all, and nothing on
/// the wire object said so. Bounding the two dimensions separately means a
/// relationship can never be lost to another relationship's evidence
/// volume.
const MAX_RELATIONSHIPS: i64 = 200;

/// Ceiling on supporting evidence paths carried per conceptual
/// relationship. Exceeding it sets `ThreatRelationship::has_more_evidence`
/// rather than silently shortening the list.
///
/// Lower than the relationship cap on purpose: past a handful, additional
/// parallel observations of the *same* relationship add little for an
/// analyst judging it, whereas an entirely missing relationship is a
/// different concept absent from the pivot set.
pub(crate) const MAX_EVIDENCE_PER_RELATIONSHIP: i64 = 20;

/// The contextual tier's own row cap. Tighter than `MAX_VERDICT_ROWS`
/// because this is the weakest evidence Apollo produces (a filename
/// coincidence), so a long list of it is the least worth an analyst's
/// scrolling. This was already 20 as a bare literal in the query; naming it
/// keeps it visible alongside the other budgets.
const MAX_CONTEXTUAL_ROWS: i64 = 20;

/// A result that was bounded by a cap, plus whether the cap actually fired.
///
/// Exists so "we found 12 things" and "we found 200 things and stopped
/// counting" cannot be represented identically. Every capped query returns
/// one of these; `verdict::resolve` folds `truncated` into
/// `Verdict::bounds`.
///
/// The detection technique throughout is fetch-one-past-the-cap: query
/// `LIMIT n + 1`, and if the extra row materializes, more data exists.
/// Cheaper than a second `COUNT(*)` and immune to drifting from it.
#[derive(Debug, Clone)]
pub struct Bounded<T> {
    pub items: Vec<T>,
    pub truncated: bool,
}

impl<T> Bounded<T> {
    /// Splits a `limit + 1` fetch into the capped items plus the truncation
    /// flag.
    fn from_overfetch(mut rows: Vec<T>, limit: i64) -> Self {
        let limit = limit.max(0) as usize;
        let truncated = rows.len() > limit;
        rows.truncate(limit);
        Self {
            items: rows,
            truncated,
        }
    }

    /// For a result that was never capped in the first place.
    fn exhaustive(items: Vec<T>) -> Self {
        Self {
            items,
            truncated: false,
        }
    }

    pub fn map<U>(self, f: impl FnMut(T) -> U) -> Bounded<U> {
        Bounded {
            items: self.items.into_iter().map(f).collect(),
            truncated: self.truncated,
        }
    }
}

/// Returns (report_id, was_inserted). was_inserted uses the `xmax = 0` trick
/// so callers can report accurate added-vs-updated counts after a sync.
///
/// Generic over the executor (rather than a concrete `&PgPool`) so ingest
/// loops can pass `&mut *tx` and run a whole sync as one transaction instead
/// of one auto-committed round trip per record.
pub async fn upsert_report<'e, E>(
    executor: E,
    source: &str,
    external_id: Option<&str>,
    title: Option<&str>,
    url: Option<&str>,
    published_at: Option<DateTime<Utc>>,
    raw: &Json,
) -> Result<(Uuid, bool)>
where
    E: PgExecutor<'e>,
{
    let rec = sqlx::query!(
        r#"
        INSERT INTO report (source, external_id, title, url, published_at, raw)
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (source, external_id) DO UPDATE SET
            title = EXCLUDED.title,
            url = EXCLUDED.url,
            published_at = EXCLUDED.published_at,
            raw = EXCLUDED.raw
        RETURNING id, (xmax = 0) AS "inserted!"
        "#,
        source,
        external_id,
        title,
        url,
        published_at,
        raw,
    )
    .fetch_one(executor)
    .await?;
    Ok((rec.id, rec.inserted))
}

/// Returns (indicator_id, was_inserted).
pub async fn upsert_indicator<'e, E>(
    executor: E,
    kind: IndicatorKind,
    value: &str,
) -> Result<(Uuid, bool)>
where
    E: PgExecutor<'e>,
{
    let rec = sqlx::query!(
        r#"
        INSERT INTO indicator (kind, value)
        VALUES ($1, $2)
        ON CONFLICT (kind, value) DO UPDATE SET value = EXCLUDED.value
        RETURNING id, (xmax = 0) AS "inserted!"
        "#,
        kind as IndicatorKind,
        value,
    )
    .fetch_one(executor)
    .await?;
    Ok((rec.id, rec.inserted))
}

#[allow(clippy::too_many_arguments)]
pub async fn upsert_indicator_observed_in_report<'e, E>(
    executor: E,
    indicator_id: Uuid,
    report_id: Uuid,
    source: &str,
    confidence: i16,
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
) -> Result<()>
where
    E: PgExecutor<'e>,
{
    sqlx::query!(
        r#"
        INSERT INTO indicator_observed_in_report
            (indicator_id, report_id, source, confidence, first_seen, last_seen)
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (indicator_id, report_id, source) DO UPDATE SET
            confidence = EXCLUDED.confidence,
            first_seen = LEAST(indicator_observed_in_report.first_seen, EXCLUDED.first_seen),
            last_seen = GREATEST(indicator_observed_in_report.last_seen, EXCLUDED.last_seen)
        "#,
        indicator_id,
        report_id,
        source,
        confidence,
        first_seen,
        last_seen,
    )
    .execute(executor)
    .await?;
    Ok(())
}

/// Returns (malware_family_id, was_inserted).
pub async fn upsert_malware_family<'e, E>(executor: E, name: &str) -> Result<(Uuid, bool)>
where
    E: PgExecutor<'e>,
{
    let rec = sqlx::query!(
        r#"
        INSERT INTO malware_family (name)
        VALUES ($1)
        ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
        RETURNING id, (xmax = 0) AS "inserted!"
        "#,
        name,
    )
    .fetch_one(executor)
    .await?;
    Ok((rec.id, rec.inserted))
}

/// `report_id` is part of the edge, not reconstructed later -- a review
/// caught that joining back to `indicator_observed_in_report` on just
/// `(indicator_id, source)` could attribute a family to a report that
/// never actually asserted it, or duplicate it once per matching report,
/// whenever the same source had filed more than one report for the same
/// indicator.
#[allow(clippy::too_many_arguments)]
pub async fn upsert_indicator_attributed_to_malware_family<'e, E>(
    executor: E,
    indicator_id: Uuid,
    malware_family_id: Uuid,
    report_id: Uuid,
    source: &str,
    confidence: i16,
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
) -> Result<()>
where
    E: PgExecutor<'e>,
{
    sqlx::query!(
        r#"
        INSERT INTO indicator_attributed_to_malware_family
            (indicator_id, malware_family_id, report_id, source, confidence, first_seen, last_seen)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        ON CONFLICT (indicator_id, malware_family_id, report_id) DO UPDATE SET
            source = EXCLUDED.source,
            confidence = EXCLUDED.confidence,
            first_seen = LEAST(indicator_attributed_to_malware_family.first_seen, EXCLUDED.first_seen),
            last_seen = GREATEST(indicator_attributed_to_malware_family.last_seen, EXCLUDED.last_seen)
        "#,
        indicator_id,
        malware_family_id,
        report_id,
        source,
        confidence,
        first_seen,
        last_seen,
    )
    .execute(executor)
    .await?;
    Ok(())
}

/// CVE and CVE-edge writers below are unused until Phase 2 hunt-pack
/// ingestion lands (see build order in the project README); MalwareBazaar
/// and ThreatFox deliberately do not populate CVE data in Phase 0, since
/// neither carries an authoritative CVE mapping. Kept here because the
/// tables are part of the locked graph shape and hunt packs will write
/// through this same conflict-handling pattern as the edges already in use.
#[allow(dead_code)]
pub async fn upsert_cve(
    pool: &PgPool,
    id: &str,
    description: Option<&str>,
    cvss_score: Option<f32>,
    published_at: Option<DateTime<Utc>>,
) -> Result<()> {
    sqlx::query!(
        r#"
        INSERT INTO cve (id, description, cvss_score, published_at)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (id) DO UPDATE SET
            description = COALESCE(EXCLUDED.description, cve.description),
            cvss_score = COALESCE(EXCLUDED.cvss_score, cve.cvss_score),
            published_at = COALESCE(EXCLUDED.published_at, cve.published_at),
            updated_at = now()
        "#,
        id,
        description,
        cvss_score,
        published_at,
    )
    .execute(pool)
    .await?;
    Ok(())
}

#[allow(clippy::too_many_arguments, dead_code)]
pub async fn upsert_report_references_cve(
    pool: &PgPool,
    report_id: Uuid,
    cve_id: &str,
    source: &str,
    confidence: i16,
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
) -> Result<()> {
    sqlx::query!(
        r#"
        INSERT INTO report_references_cve
            (report_id, cve_id, source, confidence, first_seen, last_seen)
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (report_id, cve_id, source) DO UPDATE SET
            confidence = EXCLUDED.confidence,
            first_seen = LEAST(report_references_cve.first_seen, EXCLUDED.first_seen),
            last_seen = GREATEST(report_references_cve.last_seen, EXCLUDED.last_seen)
        "#,
        report_id,
        cve_id,
        source,
        confidence,
        first_seen,
        last_seen,
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// CVE-edge writer, unused until Phase 2 hunt-pack ingestion lands -- see
/// the matching comment on `upsert_cve` above. Exercised today only by
/// `verdict.rs`'s live regression test proving `cve_matches_via_detection`
/// preserves this edge's own provenance rather than the parent
/// `detection_detects_indicator` edge's.
///
/// `rule_fingerprint` is `""` for "applies to any rule version" (the
/// permissive wildcard, since no real ingestion writes this table yet to
/// assert a specific one), never `Option` -- see migration `0010`'s
/// comment for why the column itself is `NOT NULL DEFAULT ''` and part of
/// the primary key: a round-6 review caught the original nullable,
/// non-key version silently merging (and losing) separate version
/// histories on conflict, since two different rule-content versions of
/// the same `(detection_id, cve_id, source)` upserted into the same row.
#[allow(clippy::too_many_arguments, dead_code)]
pub async fn upsert_detection_covers_cve(
    pool: &PgPool,
    detection_id: Uuid,
    cve_id: &str,
    source: &str,
    confidence: i16,
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
    rule_fingerprint: &str,
) -> Result<()> {
    sqlx::query!(
        r#"
        INSERT INTO detection_covers_cve
            (detection_id, cve_id, source, confidence, first_seen, last_seen, rule_fingerprint)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        ON CONFLICT (detection_id, cve_id, source, rule_fingerprint) DO UPDATE SET
            confidence = EXCLUDED.confidence,
            first_seen = LEAST(detection_covers_cve.first_seen, EXCLUDED.first_seen),
            last_seen = GREATEST(detection_covers_cve.last_seen, EXCLUDED.last_seen)
        "#,
        detection_id,
        cve_id,
        source,
        confidence,
        first_seen,
        last_seen,
        rule_fingerprint,
    )
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn upsert_detection(
    pool: &PgPool,
    kind: DetectionKind,
    name: &str,
    rule_source: Option<&str>,
    rule_body: Option<&str>,
    author: Option<&str>,
) -> Result<Uuid> {
    let rec = sqlx::query_scalar!(
        r#"
        INSERT INTO detection (kind, name, rule_source, rule_body, author)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (kind, name) DO UPDATE SET
            rule_source = EXCLUDED.rule_source,
            rule_body = COALESCE(EXCLUDED.rule_body, detection.rule_body)
        RETURNING id
        "#,
        kind as DetectionKind,
        name,
        rule_source,
        rule_body,
        author,
    )
    .fetch_one(pool)
    .await?;
    Ok(rec)
}

/// `rule_fingerprint` is `""` for "applies to any rule version" -- see
/// `upsert_detection_covers_cve`'s doc comment for why this is a plain
/// `&str`, not `Option`, and part of the conflict target.
#[allow(clippy::too_many_arguments)]
pub async fn upsert_detection_detects_indicator(
    pool: &PgPool,
    detection_id: Uuid,
    indicator_id: Uuid,
    source: &str,
    confidence: i16,
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
    rule_fingerprint: &str,
) -> Result<()> {
    sqlx::query!(
        r#"
        INSERT INTO detection_detects_indicator
            (detection_id, indicator_id, source, confidence, first_seen, last_seen, rule_fingerprint)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        ON CONFLICT (detection_id, indicator_id, source, rule_fingerprint) DO UPDATE SET
            confidence = EXCLUDED.confidence,
            first_seen = LEAST(detection_detects_indicator.first_seen, EXCLUDED.first_seen),
            last_seen = GREATEST(detection_detects_indicator.last_seen, EXCLUDED.last_seen)
        "#,
        detection_id,
        indicator_id,
        source,
        confidence,
        first_seen,
        last_seen,
        rule_fingerprint,
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Last-successful-sync timestamps for every *configured* feed, used both
/// to show "last synced" status in the global status bar (independent of
/// any one file lookup) and, via `verdict::resolve`, to tell an analyst
/// whether an empty verdict reflects current intelligence or a feed
/// that's gone quiet.
///
/// `crate::ingest::CONFIGURED_SOURCES`, not `feed_sync_state`, is the
/// source of truth for which feeds exist: that table only gains a row for
/// a source once `set_sync_cursor` has been called for it, which
/// `ingest::*::sync` only reaches after a full successful sync commits --
/// a source that has *never* succeeded (a bad API key from day one, every
/// attempt network-failing) has no row there at all. Querying
/// `feed_sync_state` alone, as an earlier version of this function did,
/// would silently drop that feed from the result entirely instead of
/// reporting it as never-synced -- exactly the ambiguity `intel_freshness`
/// exists to eliminate. Left-joining the configured list onto whatever
/// rows do exist (in application code, since the registry lives there,
/// not in Postgres) guarantees exactly one entry per configured feed,
/// `None` for one with no successful sync yet.
pub async fn all_sync_states(pool: &PgPool) -> Result<Vec<IntelSourceFreshness>> {
    let rows = sqlx::query!("SELECT source, last_synced_at FROM feed_sync_state")
        .fetch_all(pool)
        .await?;

    let mut synced: std::collections::HashMap<String, DateTime<Utc>> = rows
        .into_iter()
        .filter_map(|r| r.last_synced_at.map(|t| (r.source, t)))
        .collect();

    let mut result: Vec<IntelSourceFreshness> = crate::ingest::CONFIGURED_SOURCES
        .iter()
        .map(|&source| IntelSourceFreshness {
            last_successful_sync_at: synced.remove(source),
            source: source.to_string(),
        })
        .collect();
    result.sort_by(|a, b| a.source.cmp(&b.source));
    Ok(result)
}

#[allow(dead_code)]
pub async fn get_sync_cursor(pool: &PgPool, source: &str) -> Result<Option<String>> {
    let row = sqlx::query!(
        "SELECT last_cursor FROM feed_sync_state WHERE source = $1",
        source
    )
    .fetch_optional(pool)
    .await?;
    Ok(row.and_then(|r| r.last_cursor))
}

pub async fn set_sync_cursor(pool: &PgPool, source: &str, cursor: Option<&str>) -> Result<()> {
    sqlx::query!(
        r#"
        INSERT INTO feed_sync_state (source, last_synced_at, last_cursor)
        VALUES ($1, now(), $2)
        ON CONFLICT (source) DO UPDATE SET
            last_synced_at = now(),
            last_cursor = EXCLUDED.last_cursor
        "#,
        source,
        cursor,
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// All known-bad hash values (sha256 + md5), used to build the local bloom
/// filter for instant first-pass lookups.
pub async fn all_known_bad_hashes(pool: &PgPool) -> Result<Vec<String>> {
    let rows =
        sqlx::query_scalar!(r#"SELECT value FROM indicator WHERE kind IN ('sha256', 'md5')"#)
            .fetch_all(pool)
            .await?;
    Ok(rows)
}

pub struct HashMatchRow {
    matched_value: String,
    source: String,
    confidence: i16,
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
    report_id: Uuid,
    report_title: Option<String>,
    report_url: Option<String>,
}

/// Tier 1 / Tier 2: exact and fuzzy hash matches, joined out to the reports
/// that observed them. Deliberately does not also aggregate
/// `report_references_cve.cve_id` onto this row -- an earlier version did,
/// and a review caught that presenting those CVE IDs under *this* entry's
/// `source`/`confidence` (the `indicator_observed_in_report` edge's own)
/// told a second, conflicting provenance story about the same CVE next to
/// the correctly-sourced one in `ThreatRelationship`
/// (`cve_matches_via_report`). CVEs have exactly one presentation path now.
/// Ordered most-recently-observed first, then by stable identity
/// (`report_id`, `source`) -- the `indicator_observed_in_report` primary key
/// components, so the order is total rather than merely mostly-determined.
///
/// The `ORDER BY` is load-bearing, not cosmetic: a review caught that this
/// query (and three of its siblings) applied `LIMIT` with no ordering at
/// all, which in Postgres means an arbitrary subset. Two runs against
/// identical data could therefore keep *different* evidence, and the
/// evidence an analyst saw would depend on the plan rather than on
/// recency. A cap that chooses among equally valid rows must choose
/// deterministically.
pub async fn hash_matches(
    pool: &PgPool,
    kind: IndicatorKind,
    value: &str,
) -> Result<Bounded<HashMatchRow>> {
    let rows = sqlx::query_as!(
        HashMatchRow,
        r#"
        SELECT
            i.value AS matched_value,
            iorr.source,
            iorr.confidence,
            iorr.first_seen,
            iorr.last_seen,
            r.id AS report_id,
            r.title AS report_title,
            r.url AS report_url
        FROM indicator i
        JOIN indicator_observed_in_report iorr ON iorr.indicator_id = i.id
        JOIN report r ON r.id = iorr.report_id
        WHERE i.kind = $1 AND i.value = $2
        ORDER BY iorr.last_seen DESC, iorr.first_seen DESC, r.id, iorr.source
        LIMIT $3
        "#,
        kind as IndicatorKind,
        value,
        MAX_VERDICT_ROWS + 1,
    )
    .fetch_all(pool)
    .await?;
    Ok(Bounded::from_overfetch(rows, MAX_VERDICT_ROWS))
}

pub fn hash_matches_to_provenance(
    rows: Vec<HashMatchRow>,
    tier: VerdictTier,
    kind: IndicatorKind,
) -> Vec<ProvenanceEntry> {
    rows.into_iter()
        .map(|r| ProvenanceEntry {
            tier,
            source: r.source,
            confidence: r.confidence,
            first_seen: r.first_seen,
            last_seen: r.last_seen,
            report_id: Some(r.report_id),
            report_title: r.report_title,
            report_url: sanitize_stored_url(r.report_url),
            detection_name: None,
            indicator_kind: Some(kind),
            rule_fingerprint: None,
            timing: EvidenceTiming::Observed,
            matched_value: r.matched_value,
        })
        .collect()
}

// Note: there is no `yara_matches` query here. Current YaraHit provenance
// is built directly by `verdict::resolve` from the live `yara_hits` scan
// result (rule identity, `LOCAL_YARA_SOURCE`/`LOCAL_YARA_CONFIDENCE`, and
// one `now` shared with the persisted edge), not reconstructed by
// re-querying `detection_detects_indicator`. A review caught that
// reconstruction picking up a historical or differently-sourced row for
// the same (detection, indicator) pair -- via whatever the query's
// ordering happened to select -- rather than the observation that just
// occurred; the current scan's own in-memory result is the one thing that
// can't be stale or mis-attributed.

struct MalwareFamilyMatchRow {
    family_name: String,
    source: String,
    confidence: i16,
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
    report_id: Uuid,
    report_title: Option<String>,
    report_url: Option<String>,
    indicator_kind: IndicatorKind,
    indicator_value: String,
}

/// Malware-family attribution for this file, checked against both hash
/// kinds Apollo actually computes for verdict matching -- ThreatFox can
/// source an MD5 indicator with its own family edge, and checking sha256
/// alone would silently omit it even though the sha256/md5 pair belongs
/// to the same scanned file. Not derivable from `ProvenanceEntry` the way
/// most other relationship kinds are (see `models::derive_relationships`)
/// -- family attribution has its own edge table, populated directly by
/// ingestion from MalwareBazaar's `signature` and ThreatFox's
/// `malware_printable` fields.
///
/// Joins directly on the edge's own `report_id` rather than reconstructing
/// report context via `(indicator_id, source)` -- a review caught that
/// reconstruction as unsound (see the edge table's migration comment).
/// `report_id` is `NOT NULL` on the edge, so this is always an inner join;
/// there is no "family attribution with no report" case in this schema.
///
/// Strength is `Direct`, not confidence-derived: a family attribution is
/// a single-hop, explicitly sourced assertion about this exact indicator,
/// which is a fact about *how* the relationship was established, not
/// about how confident the source happens to be in it -- see
/// `RelationshipStrength`'s doc comment for why those are kept separate.
pub async fn malware_family_matches(
    pool: &PgPool,
    sha256: &str,
    md5: &str,
) -> Result<Bounded<ThreatRelationship>> {
    let rows = sqlx::query_as!(
        MalwareFamilyMatchRow,
        r#"
        SELECT
            mf.name AS family_name,
            iamf.source,
            iamf.confidence,
            iamf.first_seen,
            iamf.last_seen,
            r.id AS report_id,
            r.title AS report_title,
            r.url AS report_url,
            i.kind AS "indicator_kind: IndicatorKind",
            i.value AS indicator_value
        FROM indicator i
        JOIN indicator_attributed_to_malware_family iamf ON iamf.indicator_id = i.id
        JOIN malware_family mf ON mf.id = iamf.malware_family_id
        JOIN report r ON r.id = iamf.report_id
        WHERE (i.kind = 'sha256' AND i.value = $1) OR (i.kind = 'md5' AND i.value = $2)
        ORDER BY iamf.last_seen DESC, mf.name, r.id, iamf.source, i.kind
        LIMIT $3
        "#,
        sha256,
        md5,
        MAX_RELATIONSHIPS + 1,
    )
    .fetch_all(pool)
    .await?;

    Ok(
        Bounded::from_overfetch(rows, MAX_RELATIONSHIPS).map(|r| ThreatRelationship {
            kind: RelationshipKind::MalwareFamily,
            strength: RelationshipStrength::Direct,
            target: r.family_name,
            explanation:
                "This file's hash is attributed to a known malware family -- look for other \
                 variants, configs, payloads, and family-specific detections."
                    .to_string(),
            evidence_paths: vec![vec![RelationshipEvidence {
                relation: EvidenceRelation::AttributedToMalwareFamily,
                source: r.source,
                confidence: r.confidence,
                first_seen: r.first_seen,
                last_seen: r.last_seen,
                report_id: Some(r.report_id),
                report_title: r.report_title,
                report_url: sanitize_stored_url(r.report_url),
                indicator_kind: Some(r.indicator_kind),
                indicator_value: Some(r.indicator_value),
                detection_name: None,
                rule_fingerprint: None,
                timing: EvidenceTiming::Observed,
            }]],
            // One row *is* one attribution edge here, so a relationship's
            // evidence is never itself capped -- unlike the CVE-via-report
            // path, where many parent observations support one edge.
            has_more_evidence: false,
        }),
    )
}

struct CveViaReportRow {
    cve_id: String,
    cve_source: String,
    cve_confidence: i16,
    cve_first_seen: DateTime<Utc>,
    cve_last_seen: DateTime<Utc>,
    report_id: Uuid,
    report_title: Option<String>,
    report_url: Option<String>,
    parent_source: String,
    parent_confidence: i16,
    parent_first_seen: DateTime<Utc>,
    parent_last_seen: DateTime<Utc>,
    parent_indicator_kind: IndicatorKind,
    parent_indicator_value: String,
    /// This row's conceptual edge's position in the deterministic edge
    /// ordering. The query fetches one edge past the cap, so an
    /// `edge_rank > MAX_RELATIONSHIPS` row is the sentinel proving more
    /// distinct edges exist; it is counted and then dropped.
    edge_rank: i64,
    /// How many supporting parent observations this row's edge has in total,
    /// independent of how many were returned -- the source of
    /// `has_more_evidence`.
    parent_total: i64,
}

/// CVE relationships inferred through report co-occurrence: this file's
/// indicator was observed in a report, and that *same* report separately
/// references a CVE. That is two hops of evidence
/// (`indicator --observed_in--> report --references--> cve`), not one, and
/// both are carried on the relationship's `evidence` chain with each edge's
/// *own* source/confidence/timestamps -- a review caught two successive
/// defects here: first, a version that copied the *indicator* edge's
/// provenance onto the CVE relationship instead of the CVE edge's own;
/// then, once that was fixed by keeping only the CVE edge's values, a
/// second review caught that the fix silently discarded the first hop's
/// evidence entirely rather than preserving the full chain. `strength` is
/// `Contextual` specifically to keep this two-hop inference honest,
/// distinct from the one-hop `cve_matches_via_detection` case below.
///
/// Anchored on `report_references_cve` (not `indicator`): a review caught
/// the original indicator-anchored version returning the *same* CVE edge
/// twice whenever a report observed both the file's sha256 *and* md5 (as
/// MalwareBazaar's ingestion does) -- one real `report -> cve` assertion
/// was surfacing as two conceptual relationships just because the file has
/// two hash representations. A follow-up round-6 review caught that the
/// fix for *that* (a `LATERAL ... LIMIT 1` picking exactly one supporting
/// parent row) went too far the other way: it stopped the relationship
/// from duplicating by *discarding* whichever parent hop it didn't pick,
/// even when both were real, independently-sourced evidence (e.g. the
/// report legitimately observed both hash kinds, or two different sources
/// both reported the same indicator into the same report). The relationship
/// itself must be deduplicated (one row per real `report_references_cve`
/// edge); its supporting evidence must not be -- every matching
/// `indicator_observed_in_report` row becomes its own `ObservedInReport`
/// evidence hop, grouped under the one relationship its `report_references_cve`
/// edge belongs to, ordered sha256-then-md5 and most-recent-first within a
/// kind for determinism.
///
/// `pub(crate)` rather than private: `verdict::resolve` calls this and
/// `cve_matches_via_detection` separately rather than through a combined
/// wrapper, since the two run at different points in `resolve` -- see the
/// doc comment where `cve_matches_via_detection` is called in
/// `verdict.rs` for why.
/// ## Bounding
///
/// The two dimensions here -- how many distinct CVE edges, and how many
/// parent observations support each -- are capped separately, in SQL, using
/// window functions rather than a single `LIMIT` on the joined rows.
///
/// A review caught why a joined-row `LIMIT` is wrong for this shape: the
/// rows are grouped into conceptual relationships *after* the database
/// returns them, so a single row budget is spent before grouping happens.
/// With 200 matching `indicator_observed_in_report` rows for CVE edge A,
/// the ordered result consumed the entire budget on A and an entirely
/// distinct, equally real CVE edge B never reached the grouping code -- and
/// nothing on the returned object said the relationship set was partial.
/// That breaks both the promise that provenance is not silently discarded
/// and the promise that PR #20 can treat this as the authoritative pivot
/// set. Even at unusual cardinality, a bounded graph API has to represent
/// its bounds honestly.
///
/// So: `ranked_edges` numbers the distinct `(report_id, cve_id, cve_source)`
/// edges and keeps `MAX_RELATIONSHIPS + 1` of them (the extra one is the
/// sentinel that proves more exist); `ranked_parents` independently numbers
/// each kept edge's parents and keeps `MAX_EVIDENCE_PER_RELATIONSHIP`, while
/// `parent_total` counts them all so `has_more_evidence` can be set without
/// a second query. Both orderings are total, so which evidence survives a
/// cap is deterministic rather than plan-dependent.
pub(crate) async fn cve_matches_via_report(
    pool: &PgPool,
    sha256: &str,
    md5: &str,
) -> Result<Bounded<ThreatRelationship>> {
    let rows = sqlx::query_as!(
        CveViaReportRow,
        r#"
        WITH matched AS (
            SELECT
                rrc.cve_id,
                rrc.source AS cve_source,
                rrc.confidence AS cve_confidence,
                rrc.first_seen AS cve_first_seen,
                rrc.last_seen AS cve_last_seen,
                r.id AS report_id,
                r.title AS report_title,
                r.url AS report_url,
                iorr.source AS parent_source,
                iorr.confidence AS parent_confidence,
                iorr.first_seen AS parent_first_seen,
                iorr.last_seen AS parent_last_seen,
                i.kind AS parent_indicator_kind,
                i.value AS parent_indicator_value
            FROM report_references_cve rrc
            JOIN report r ON r.id = rrc.report_id
            JOIN indicator_observed_in_report iorr ON iorr.report_id = r.id
            JOIN indicator i ON i.id = iorr.indicator_id
            WHERE (i.kind = 'sha256' AND i.value = $1) OR (i.kind = 'md5' AND i.value = $2)
        ),
        ranked_edges AS (
            SELECT
                report_id,
                cve_id,
                cve_source,
                ROW_NUMBER() OVER (ORDER BY cve_id, cve_source, report_id) AS edge_rank
            FROM (SELECT DISTINCT report_id, cve_id, cve_source FROM matched) e
        ),
        kept_edges AS (
            SELECT * FROM ranked_edges WHERE edge_rank <= $3::bigint + 1
        ),
        ranked_parents AS (
            SELECT
                m.*,
                ke.edge_rank,
                ROW_NUMBER() OVER (
                    PARTITION BY m.report_id, m.cve_id, m.cve_source
                    ORDER BY (m.parent_indicator_kind = 'sha256') DESC,
                             m.parent_last_seen DESC,
                             m.parent_source,
                             m.parent_indicator_value
                ) AS parent_rank,
                COUNT(*) OVER (
                    PARTITION BY m.report_id, m.cve_id, m.cve_source
                ) AS parent_total
            FROM matched m
            JOIN kept_edges ke
              ON ke.report_id = m.report_id
             AND ke.cve_id = m.cve_id
             AND ke.cve_source = m.cve_source
        )
        SELECT
            cve_id,
            cve_source,
            cve_confidence,
            cve_first_seen,
            cve_last_seen,
            report_id,
            report_title,
            report_url,
            parent_source,
            parent_confidence,
            parent_first_seen,
            parent_last_seen,
            parent_indicator_kind AS "parent_indicator_kind: IndicatorKind",
            parent_indicator_value,
            edge_rank AS "edge_rank!",
            parent_total AS "parent_total!"
        FROM ranked_parents
        WHERE parent_rank <= $4::bigint
        ORDER BY edge_rank, parent_rank
        "#,
        sha256,
        md5,
        MAX_RELATIONSHIPS,
        MAX_EVIDENCE_PER_RELATIONSHIP,
    )
    .fetch_all(pool)
    .await?;

    // The query deliberately fetched one edge past the cap. If that
    // sentinel edge came back, more distinct CVE edges exist than this
    // result can carry -- recorded here, then dropped, so the sentinel is
    // never itself presented as a relationship.
    let relationships_truncated = rows.iter().any(|r| r.edge_rank > MAX_RELATIONSHIPS);
    let rows: Vec<CveViaReportRow> = rows
        .into_iter()
        .filter(|r| r.edge_rank <= MAX_RELATIONSHIPS)
        .collect();

    // Group by the specific report_references_cve edge each row's parent
    // hop supports -- (report_id, cve_id, cve_source) identifies exactly
    // one such edge, since that's its own primary key. Every row in a
    // group shares the same CVE-edge fields; only the parent hop differs.
    type CveGroupKey = (Uuid, String, String);
    let mut groups: Vec<(CveGroupKey, CveViaReportRow, Vec<RelationshipEvidence>)> = Vec::new();
    for r in rows {
        let key = (r.report_id, r.cve_id.clone(), r.cve_source.clone());
        let parent_hop = RelationshipEvidence {
            relation: EvidenceRelation::ObservedInReport,
            source: r.parent_source.clone(),
            confidence: r.parent_confidence,
            first_seen: r.parent_first_seen,
            last_seen: r.parent_last_seen,
            report_id: Some(r.report_id),
            report_title: r.report_title.clone(),
            report_url: sanitize_stored_url(r.report_url.clone()),
            indicator_kind: Some(r.parent_indicator_kind),
            indicator_value: Some(r.parent_indicator_value.clone()),
            detection_name: None,
            rule_fingerprint: None,
            timing: EvidenceTiming::Observed,
        };
        match groups.iter_mut().find(|(k, ..)| *k == key) {
            Some((_, _, hops)) => hops.push(parent_hop),
            None => groups.push((key, r, vec![parent_hop])),
        }
    }

    let items = groups
        .into_iter()
        .map(|(_, r, parent_hops)| {
            let cve_hop = RelationshipEvidence {
                relation: EvidenceRelation::ReportReferencesCve,
                source: r.cve_source,
                confidence: r.cve_confidence,
                first_seen: r.cve_first_seen,
                last_seen: r.cve_last_seen,
                report_id: Some(r.report_id),
                report_title: r.report_title,
                report_url: sanitize_stored_url(r.report_url),
                indicator_kind: None,
                indicator_value: None,
                detection_name: None,
                rule_fingerprint: None,
                timing: EvidenceTiming::Observed,
            };
            // One path per real parent observation, each ending at its
            // own copy of the shared `cve_hop` -- a review caught that
            // flattening every parent hop plus one shared tail into a
            // single `Vec<RelationshipEvidence>` reads as one linear
            // chain when a report observing this file under more than one
            // hash (or via more than one source) actually produces
            // several independent first hops converging on that one
            // shared second hop. Each path here is a genuine, complete,
            // independently-walkable file -> CVE chain, so a consumer
            // never has to infer the branch from repeated `report_id`s.
            let evidence_paths = parent_hops
                .into_iter()
                .map(|parent_hop| vec![parent_hop, cve_hop.clone()])
                .collect();
            ThreatRelationship {
                kind: RelationshipKind::Cve,
                strength: RelationshipStrength::Contextual,
                target: r.cve_id,
                explanation: "This file was observed in a report that also references a CVE -- an \
                     inferred association through report co-occurrence, not a direct per-file \
                     CVE assertion. Assess exposure and hunt for exploitation evidence before \
                     treating this as confirmed."
                    .to_string(),
                evidence_paths,
                // `parent_total` counted every supporting observation this
                // edge has, not just the ones returned, so this is exact
                // without a second query.
                has_more_evidence: r.parent_total > MAX_EVIDENCE_PER_RELATIONSHIP,
            }
        })
        .collect();

    Ok(Bounded {
        items,
        truncated: relationships_truncated,
    })
}

struct CveViaDetectionRow {
    cve_id: String,
    cve_source: String,
    cve_confidence: i16,
    cve_first_seen: DateTime<Utc>,
    cve_last_seen: DateTime<Utc>,
    detection_name: String,
    /// The *scanning rule's* current fingerprint (from the `scan` unnest
    /// below), used for hop 1 -- always concrete, since hop 1 describes
    /// what just happened in this live scan.
    scan_rule_fingerprint: String,
    /// The *coverage edge's own* stored fingerprint, used for hop 2 --
    /// `""` is the edge's genuine "applies to any version" wildcard value,
    /// preserved as-is rather than replaced with the current scan's
    /// fingerprint. See the function doc comment, finding 3A.
    edge_rule_fingerprint: String,
}

/// CVE relationships from a detection that fired against this *exact*
/// file, *in this scan*, and is separately documented to cover a CVE
/// (`detection --detects--> indicator`, `detection --covers--> cve`). One
/// hop tighter than the report-co-occurrence path above (the detection
/// matched this file directly, not merely a report that happens to mention
/// both), so `strength` is `Strong` rather than `Contextual` -- still not
/// `Direct`, since covering a CVE is the detection's own documented scope,
/// not a per-file assertion the way malware-family attribution is.
///
/// Unlike the report path, hop 1 (`detects_indicator`) is *not*
/// reconstructed from the database at all: `verdict::resolve` supplies it
/// directly as `observed_at`/`indicator_kind`/`indicator_value`, using
/// `LOCAL_YARA_SOURCE`/`LOCAL_YARA_CONFIDENCE` -- the exact values it just
/// persisted via `record_yara_hit` for this same scan. A review caught
/// that reading it back via `ORDER BY ddi.last_seen DESC LIMIT 1` could
/// select a different source's historical row for the same (detection,
/// indicator) pair rather than the observation that just occurred; a
/// follow-up round-6 review separately caught that this hop, even once
/// fixed to use the live scan's own values, still omitted the indicator
/// identity (`indicator_kind`/`indicator_value`) it obviously has
/// available -- `indicator_kind`/`indicator_value` here are the caller's
/// same scanned-hash values, so this hop is complete rather than a
/// structurally-incomplete `Detection --detects--> ???`.
///
/// `scanned_rules` restricts this to detections that actually fired in the
/// *current* scan -- a review caught that without this filter, a hash
/// already known to the bloom filter (from an unrelated earlier hash
/// match, not this scan's YARA pass) could surface a CVE relationship
/// whose explanation claims a detection "matched this exact file" when
/// zero rules actually fired this scan. Each `(rule_name, rule_fingerprint)`
/// pair is matched by name *and* scoped by that specific rule's own content
/// fingerprint (see `YaraEngine::rule_fingerprint`) -- deliberately per
/// rule, not one shared whole-ruleset value: a round-6 review caught an
/// earlier version scoping by the whole compiled ruleset's fingerprint,
/// which meant editing an entirely unrelated rule elsewhere in the
/// directory would falsely invalidate *this* rule's own unchanged CVE
/// coverage. `dcc.rule_fingerprint = '' OR dcc.rule_fingerprint = <this
/// rule's own current fingerprint>` excludes only a coverage edge asserted
/// against a genuinely different *content* of this same-named rule.
///
/// Hop 2's `rule_fingerprint` is the coverage edge's own stored value
/// (`""` mapped to `None`, its real "applies to any version" meaning),
/// never the current scan's fingerprint -- a round-6 review caught an
/// earlier version presenting a wildcard/unscoped edge's evidence as
/// though it had been asserted specifically against the rule that just
/// fired, which is provenance fabrication: the edge never said that.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn cve_matches_via_detection(
    pool: &PgPool,
    scanned_rules: &[(String, String)],
    observed_source: &str,
    observed_confidence: i16,
    observed_at: DateTime<Utc>,
    indicator_kind: IndicatorKind,
    indicator_value: &str,
) -> Result<Bounded<ThreatRelationship>> {
    if scanned_rules.is_empty() {
        return Ok(Bounded::exhaustive(vec![]));
    }
    let rule_names: Vec<String> = scanned_rules.iter().map(|(n, _)| n.clone()).collect();
    let rule_fingerprints: Vec<String> = scanned_rules.iter().map(|(_, f)| f.clone()).collect();

    let rows = sqlx::query_as!(
        CveViaDetectionRow,
        r#"
        SELECT
            dcc.cve_id,
            dcc.source AS cve_source,
            dcc.confidence AS cve_confidence,
            dcc.first_seen AS cve_first_seen,
            dcc.last_seen AS cve_last_seen,
            d.name AS detection_name,
            scan.rule_fingerprint AS "scan_rule_fingerprint!",
            dcc.rule_fingerprint AS edge_rule_fingerprint
        FROM detection_covers_cve dcc
        JOIN detection d ON d.id = dcc.detection_id
        JOIN UNNEST($1::text[], $2::text[]) AS scan(rule_name, rule_fingerprint)
            ON scan.rule_name = d.name
        WHERE d.kind = 'yara'
          AND (dcc.rule_fingerprint = '' OR dcc.rule_fingerprint = scan.rule_fingerprint)
        ORDER BY dcc.cve_id, dcc.source, d.name, dcc.rule_fingerprint
        LIMIT $3
        "#,
        &rule_names,
        &rule_fingerprints,
        MAX_RELATIONSHIPS + 1,
    )
    .fetch_all(pool)
    .await?;

    Ok(
        Bounded::from_overfetch(rows, MAX_RELATIONSHIPS).map(|r| ThreatRelationship {
            kind: RelationshipKind::Cve,
            strength: RelationshipStrength::Strong,
            target: r.cve_id,
            explanation: format!(
                "The local detection \"{}\", which matched this exact file in the current scan, \
                 is documented to cover this CVE -- assess exposure and hunt for exploitation \
                 evidence.",
                r.detection_name
            ),
            evidence_paths: vec![vec![
                RelationshipEvidence {
                    relation: EvidenceRelation::DetectsIndicator,
                    source: observed_source.to_string(),
                    confidence: observed_confidence,
                    first_seen: observed_at,
                    last_seen: observed_at,
                    report_id: None,
                    report_title: None,
                    report_url: None,
                    indicator_kind: Some(indicator_kind),
                    indicator_value: Some(indicator_value.to_string()),
                    detection_name: Some(r.detection_name.clone()),
                    rule_fingerprint: Some(r.scan_rule_fingerprint),
                    timing: EvidenceTiming::Observed,
                },
                RelationshipEvidence {
                    relation: EvidenceRelation::DetectionCoversCve,
                    source: r.cve_source,
                    confidence: r.cve_confidence,
                    first_seen: r.cve_first_seen,
                    last_seen: r.cve_last_seen,
                    report_id: None,
                    report_title: None,
                    report_url: None,
                    indicator_kind: None,
                    indicator_value: None,
                    detection_name: Some(r.detection_name),
                    rule_fingerprint: if r.edge_rule_fingerprint.is_empty() {
                        None
                    } else {
                        Some(r.edge_rule_fingerprint)
                    },
                    timing: EvidenceTiming::Observed,
                },
            ]],
            // One `detection_covers_cve` row is one complete two-hop path,
            // so this relationship's evidence is never itself capped.
            has_more_evidence: false,
        }),
    )
}

struct PathPatternRow {
    matched_value: String,
    source: String,
    confidence: i16,
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
    report_id: Option<Uuid>,
    report_title: Option<String>,
    report_url: Option<String>,
}

/// Tier 4: path or naming pattern indicators that the file's full path
/// contains. Patterns are stored as plain substrings in Phase 0. Inner
/// joins here are deliberate: a path indicator with no observed_in_report
/// edge has no provenance to show and should not surface a verdict.
///
/// The indicator value is escaped for LIKE before use. Postgres treats
/// `%` and `_` as wildcards inside a LIKE pattern, so an unescaped
/// indicator value of just `%` matches *every* scanned file -- one
/// poisoned or malformed intel row becoming a universal false positive
/// that would look, to an analyst, like a genuine path-indicator hit on
/// everything they click. Confirmed against Postgres directly
/// (`'/any/path' ILIKE '%' || '%' || '%'` is `true`). The escaping is done
/// SQL-side with `replace` rather than via `sanitize::escape_like_pattern`
/// because the value is a *column*, not a bind parameter -- backslash
/// first so it can't be used to escape the `%` delimiters this query adds.
/// See `docs/threat-model.md`, TB-2.
///
/// No feed currently writes path indicators (neither MalwareBazaar nor
/// ThreatFox produces them), so this is a latent defect rather than a
/// live one -- but Phase 2's hunt packs are specified to curate exactly
/// this indicator kind, and the same escaping is needed for plain
/// correctness on any legitimate path containing `%` or `_`.
pub async fn path_pattern_matches(
    pool: &PgPool,
    file_path: &str,
) -> Result<Bounded<ProvenanceEntry>> {
    let rows = sqlx::query_as!(
        PathPatternRow,
        r#"
        SELECT
            i.value AS matched_value,
            iorr.source,
            iorr.confidence,
            iorr.first_seen,
            iorr.last_seen,
            r.id AS "report_id?",
            r.title AS report_title,
            r.url AS report_url
        FROM indicator i
        JOIN indicator_observed_in_report iorr ON iorr.indicator_id = i.id
        JOIN report r ON r.id = iorr.report_id
        WHERE i.kind = 'path'
          AND $1 ILIKE '%' || replace(replace(replace(i.value, '\', '\\'), '%', '\%'), '_', '\_') || '%'
        ORDER BY iorr.last_seen DESC, iorr.first_seen DESC, i.value, r.id, iorr.source
        LIMIT $2
        "#,
        file_path,
        MAX_VERDICT_ROWS + 1,
    )
    .fetch_all(pool)
    .await?;

    Ok(
        Bounded::from_overfetch(rows, MAX_VERDICT_ROWS).map(|r| ProvenanceEntry {
            tier: VerdictTier::PathPattern,
            source: r.source,
            confidence: r.confidence,
            first_seen: r.first_seen,
            last_seen: r.last_seen,
            report_id: r.report_id,
            report_title: r.report_title,
            report_url: sanitize_stored_url(r.report_url),
            detection_name: None,
            indicator_kind: Some(IndicatorKind::Path),
            rule_fingerprint: None,
            timing: EvidenceTiming::Observed,
            matched_value: r.matched_value,
        }),
    )
}

struct ContextualRow {
    matched_value: Option<String>,
    source: String,
    report_id: Uuid,
    report_title: Option<String>,
    report_url: Option<String>,
    ingested_at: DateTime<Utc>,
}

/// Tier 5: contextual association. The scanned file's name matches a file
/// name recorded in a report's raw payload (e.g. a MalwareBazaar sample
/// name) without a direct hash or YARA match. Weakest tier; always shown
/// with its source so an analyst can judge it on sight.
/// Capped at `MAX_CONTEXTUAL_ROWS` (this tier's own, tighter budget -- it is
/// the weakest evidence, so a long list of it is the least useful), ordered
/// most-recently-received first with `r.id` as the tiebreak so the cap is
/// deterministic.
///
/// Note the cap applies to *rows*, while the returned entries are filtered
/// (a row whose `raw->>'file_name'` is NULL produces no entry). The
/// truncation flag therefore comes from the row count before filtering,
/// which is the honest reading: more matching rows existed than were
/// examined.
pub async fn contextual_matches(
    pool: &PgPool,
    file_name: &str,
) -> Result<Bounded<ProvenanceEntry>> {
    if file_name.trim().is_empty() {
        return Ok(Bounded::exhaustive(vec![]));
    }
    let rows = sqlx::query_as!(
        ContextualRow,
        r#"
        SELECT
            r.raw ->> 'file_name' AS matched_value,
            r.source,
            r.id AS report_id,
            r.title AS report_title,
            r.url AS report_url,
            r.ingested_at
        FROM report r
        WHERE lower(r.raw ->> 'file_name') = lower($1)
        ORDER BY r.ingested_at DESC, r.id
        LIMIT $2
        "#,
        file_name,
        MAX_CONTEXTUAL_ROWS + 1,
    )
    .fetch_all(pool)
    .await?;

    let bounded = Bounded::from_overfetch(rows, MAX_CONTEXTUAL_ROWS);
    let truncated = bounded.truncated;
    Ok(Bounded {
        truncated,
        items: bounded
            .items
            .into_iter()
            .filter_map(|r| {
                let matched_value = r.matched_value?;
                Some(ProvenanceEntry {
                    tier: VerdictTier::Contextual,
                    source: r.source,
                    confidence: 25,
                    // The report's own `ingested_at` -- a review caught an
                    // earlier version fabricating `Utc::now()` at query time as
                    // edge-style observation timing for a tier with no backing
                    // evidence edge at all. A round-6 review caught that even
                    // `ingested_at` is the wrong *label*, though it's the right
                    // *value*: it's when Apollo *received* this report, not any
                    // claimed first/last-observed window a source asserted --
                    // `timing: ReceivedOnly` below makes that distinction
                    // explicit on the wire instead of overloading
                    // `first_seen`/`last_seen` to mean two different things
                    // depending on which tier produced them.
                    first_seen: r.ingested_at,
                    last_seen: r.ingested_at,
                    timing: EvidenceTiming::ReceivedOnly,
                    report_id: Some(r.report_id),
                    report_title: r.report_title,
                    report_url: sanitize_stored_url(r.report_url),
                    detection_name: None,
                    indicator_kind: None,
                    rule_fingerprint: None,
                    matched_value,
                })
            })
            .collect(),
    })
}
