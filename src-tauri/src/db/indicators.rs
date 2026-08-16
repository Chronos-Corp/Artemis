use anyhow::Result;
use chrono::{DateTime, Utc};
use serde_json::Value as Json;
use sqlx::{PgExecutor, PgPool};
use uuid::Uuid;

use crate::models::{
    derive_strength, DetectionKind, IndicatorKind, IntelSourceFreshness, ProvenanceEntry,
    RelationshipKind, ThreatRelationship, VerdictTier,
};

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

#[allow(clippy::too_many_arguments)]
pub async fn upsert_indicator_attributed_to_malware_family<'e, E>(
    executor: E,
    indicator_id: Uuid,
    malware_family_id: Uuid,
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
            (indicator_id, malware_family_id, source, confidence, first_seen, last_seen)
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (indicator_id, malware_family_id, source) DO UPDATE SET
            confidence = EXCLUDED.confidence,
            first_seen = LEAST(indicator_attributed_to_malware_family.first_seen, EXCLUDED.first_seen),
            last_seen = GREATEST(indicator_attributed_to_malware_family.last_seen, EXCLUDED.last_seen)
        "#,
        indicator_id,
        malware_family_id,
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

#[allow(clippy::too_many_arguments)]
pub async fn upsert_detection_detects_indicator(
    pool: &PgPool,
    detection_id: Uuid,
    indicator_id: Uuid,
    source: &str,
    confidence: i16,
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
) -> Result<()> {
    sqlx::query!(
        r#"
        INSERT INTO detection_detects_indicator
            (detection_id, indicator_id, source, confidence, first_seen, last_seen)
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (detection_id, indicator_id, source) DO UPDATE SET
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
    let rows = sqlx::query_scalar!(
        r#"SELECT value FROM indicator WHERE kind IN ('sha256', 'md5')"#
    )
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
    cve_ids: Vec<String>,
}

/// Tier 1 / Tier 2: exact and fuzzy hash matches, joined out to the reports
/// that observed them and any CVEs those reports reference.
pub async fn hash_matches(
    pool: &PgPool,
    kind: IndicatorKind,
    value: &str,
) -> Result<Vec<HashMatchRow>> {
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
            r.url AS report_url,
            COALESCE(
                array_agg(rrc.cve_id) FILTER (WHERE rrc.cve_id IS NOT NULL),
                '{}'
            ) AS "cve_ids!"
        FROM indicator i
        JOIN indicator_observed_in_report iorr ON iorr.indicator_id = i.id
        JOIN report r ON r.id = iorr.report_id
        LEFT JOIN report_references_cve rrc ON rrc.report_id = r.id
        WHERE i.kind = $1 AND i.value = $2
        GROUP BY i.value, iorr.source, iorr.confidence, iorr.first_seen, iorr.last_seen,
                 r.id, r.title, r.url
        "#,
        kind as IndicatorKind,
        value,
    )
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

pub fn hash_matches_to_provenance(rows: Vec<HashMatchRow>, tier: VerdictTier) -> Vec<ProvenanceEntry> {
    rows.into_iter()
        .map(|r| ProvenanceEntry {
            tier,
            source: r.source,
            confidence: r.confidence,
            first_seen: r.first_seen,
            last_seen: r.last_seen,
            report_id: Some(r.report_id),
            report_title: r.report_title,
            report_url: r.report_url,
            detection_name: None,
            matched_value: r.matched_value,
            cve_ids: r.cve_ids,
        })
        .collect()
}

struct YaraMatchRow {
    detection_name: String,
    source: String,
    confidence: i16,
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
    cve_ids: Vec<String>,
}

/// Tier 3: YARA rule hits recorded against this hash's indicator, whether
/// from a live local scan or a previously ingested detection.
pub async fn yara_matches(pool: &PgPool, sha256: &str) -> Result<Vec<ProvenanceEntry>> {
    let rows = sqlx::query_as!(
        YaraMatchRow,
        r#"
        SELECT
            d.name AS detection_name,
            ddi.source,
            ddi.confidence,
            ddi.first_seen,
            ddi.last_seen,
            COALESCE(
                array_agg(dcc.cve_id) FILTER (WHERE dcc.cve_id IS NOT NULL),
                '{}'
            ) AS "cve_ids!"
        FROM indicator i
        JOIN detection_detects_indicator ddi ON ddi.indicator_id = i.id
        JOIN detection d ON d.id = ddi.detection_id
        LEFT JOIN detection_covers_cve dcc ON dcc.detection_id = d.id
        WHERE i.kind = 'sha256' AND i.value = $1 AND d.kind = 'yara'
        GROUP BY d.name, ddi.source, ddi.confidence, ddi.first_seen, ddi.last_seen
        "#,
        sha256,
    )
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|r| ProvenanceEntry {
            tier: VerdictTier::YaraHit,
            source: r.source,
            confidence: r.confidence,
            first_seen: r.first_seen,
            last_seen: r.last_seen,
            report_id: None,
            report_title: None,
            report_url: None,
            detection_name: Some(r.detection_name),
            matched_value: sha256.to_string(),
            cve_ids: r.cve_ids,
        })
        .collect())
}

struct MalwareFamilyMatchRow {
    family_name: String,
    source: String,
    confidence: i16,
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
    report_id: Option<Uuid>,
    report_title: Option<String>,
    report_url: Option<String>,
}

/// Malware-family attribution for this exact hash, joined to whichever
/// report the *same* source observed it in (if any) so the relationship
/// carries the same provenance a hash-match entry would. Not derivable
/// from `ProvenanceEntry` the way most other relationship kinds are (see
/// `models::derive_relationships`) -- family attribution has its own edge
/// table, populated directly by ingestion from MalwareBazaar's `signature`
/// and ThreatFox's `malware_printable` fields.
pub async fn malware_family_matches(
    pool: &PgPool,
    sha256: &str,
) -> Result<Vec<ThreatRelationship>> {
    let rows = sqlx::query_as!(
        MalwareFamilyMatchRow,
        r#"
        SELECT
            mf.name AS family_name,
            iamf.source,
            iamf.confidence,
            iamf.first_seen,
            iamf.last_seen,
            r.id AS "report_id?",
            r.title AS report_title,
            r.url AS report_url
        FROM indicator i
        JOIN indicator_attributed_to_malware_family iamf ON iamf.indicator_id = i.id
        JOIN malware_family mf ON mf.id = iamf.malware_family_id
        LEFT JOIN indicator_observed_in_report iorr
            ON iorr.indicator_id = i.id AND iorr.source = iamf.source
        LEFT JOIN report r ON r.id = iorr.report_id
        WHERE i.kind = 'sha256' AND i.value = $1
        "#,
        sha256,
    )
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|r| ThreatRelationship {
            kind: RelationshipKind::MalwareFamily,
            strength: derive_strength(r.confidence),
            target: r.family_name,
            explanation:
                "This file's hash is attributed to a known malware family -- look for other \
                 variants, configs, payloads, and family-specific detections."
                    .to_string(),
            source: r.source,
            confidence: r.confidence,
            first_seen: r.first_seen,
            last_seen: r.last_seen,
            report_id: r.report_id,
            report_title: r.report_title,
            report_url: r.report_url,
        })
        .collect())
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
pub async fn path_pattern_matches(pool: &PgPool, file_path: &str) -> Result<Vec<ProvenanceEntry>> {
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
        WHERE i.kind = 'path' AND $1 ILIKE '%' || i.value || '%'
        "#,
        file_path,
    )
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|r| ProvenanceEntry {
            tier: VerdictTier::PathPattern,
            source: r.source,
            confidence: r.confidence,
            first_seen: r.first_seen,
            last_seen: r.last_seen,
            report_id: r.report_id,
            report_title: r.report_title,
            report_url: r.report_url,
            detection_name: None,
            matched_value: r.matched_value,
            cve_ids: vec![],
        })
        .collect())
}

struct ContextualRow {
    matched_value: Option<String>,
    source: String,
    report_id: Uuid,
    report_title: Option<String>,
    report_url: Option<String>,
}

/// Tier 5: contextual association. The scanned file's name matches a file
/// name recorded in a report's raw payload (e.g. a MalwareBazaar sample
/// name) without a direct hash or YARA match. Weakest tier; always shown
/// with its source so an analyst can judge it on sight.
pub async fn contextual_matches(pool: &PgPool, file_name: &str) -> Result<Vec<ProvenanceEntry>> {
    if file_name.trim().is_empty() {
        return Ok(vec![]);
    }
    let rows = sqlx::query_as!(
        ContextualRow,
        r#"
        SELECT
            r.raw ->> 'file_name' AS matched_value,
            r.source,
            r.id AS report_id,
            r.title AS report_title,
            r.url AS report_url
        FROM report r
        WHERE lower(r.raw ->> 'file_name') = lower($1)
        LIMIT 20
        "#,
        file_name,
    )
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .filter_map(|r| {
            let matched_value = r.matched_value?;
            Some(ProvenanceEntry {
                tier: VerdictTier::Contextual,
                source: r.source,
                confidence: 25,
                first_seen: Utc::now(),
                last_seen: Utc::now(),
                report_id: Some(r.report_id),
                report_title: r.report_title,
                report_url: r.report_url,
                detection_name: None,
                matched_value,
                cve_ids: vec![],
            })
        })
        .collect())
}
