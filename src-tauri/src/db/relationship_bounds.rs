use anyhow::{bail, Result};
use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use uuid::Uuid;

use nsic_core::sanitize::sanitize_stored_url;

use crate::db::indicators::{self, Bounded, MAX_EVIDENCE_PER_RELATIONSHIP};
use crate::models::{
    EvidenceRelation, EvidenceTiming, IndicatorKind, RelationshipEvidence, RelationshipKind,
    RelationshipStrength, ThreatRelationship,
};

/// Maximum number of distinct `(kind, target)` concepts any one dedicated
/// relationship lookup will return.
///
/// The older query helpers in `indicators` predate the round-9 distinction
/// between "relationship assertion" and "relationship concept". They are
/// still the cheap fast path at normal cardinality. If their assertion-level
/// cap fires, this module reruns the lookup using a target-ranked query so a
/// noisy target cannot consume the entire budget and hide a different pivot.
const MAX_RELATIONSHIP_CONCEPTS: i64 = 200;

/// Malware-family lookup with concept-aware fallback.
///
/// At normal cardinality the existing macro-checked query is retained. Its
/// `truncated` flag means more than 200 attribution assertions existed; only
/// then do we pay for the target-ranked query below. The fallback groups all
/// returned assertions for the same family into one relationship with up to
/// `MAX_EVIDENCE_PER_RELATIONSHIP` independently-walkable evidence paths.
pub async fn malware_family_matches(
    pool: &PgPool,
    sha256: &str,
    md5: &str,
) -> Result<Bounded<ThreatRelationship>> {
    let fast = indicators::malware_family_matches(pool, sha256, md5).await?;
    if !fast.truncated {
        return Ok(fast);
    }

    let rows = sqlx::query(
        r#"
        WITH matched AS (
            SELECT
                mf.name AS family_name,
                iamf.source,
                iamf.confidence,
                iamf.first_seen,
                iamf.last_seen,
                r.id AS report_id,
                r.title AS report_title,
                r.url AS report_url,
                i.kind::text AS indicator_kind,
                i.value AS indicator_value
            FROM indicator i
            JOIN indicator_attributed_to_malware_family iamf ON iamf.indicator_id = i.id
            JOIN malware_family mf ON mf.id = iamf.malware_family_id
            JOIN report r ON r.id = iamf.report_id
            WHERE (i.kind = 'sha256' AND i.value = $1)
               OR (i.kind = 'md5' AND i.value = $2)
        ),
        ranked_targets AS (
            SELECT
                family_name,
                ROW_NUMBER() OVER (ORDER BY family_name) AS concept_rank
            FROM (SELECT DISTINCT family_name FROM matched) t
        ),
        kept_targets AS (
            SELECT * FROM ranked_targets
            WHERE concept_rank <= $3::bigint + 1
        ),
        ranked_evidence AS (
            SELECT
                m.*,
                kt.concept_rank,
                ROW_NUMBER() OVER (
                    PARTITION BY m.family_name
                    ORDER BY m.last_seen DESC, m.report_id, m.source,
                             m.indicator_kind, m.indicator_value
                ) AS evidence_rank,
                COUNT(*) OVER (PARTITION BY m.family_name) AS evidence_total
            FROM matched m
            JOIN kept_targets kt USING (family_name)
        )
        SELECT *
        FROM ranked_evidence
        WHERE evidence_rank <= $4::bigint
        ORDER BY concept_rank, evidence_rank
        "#,
    )
    .bind(sha256)
    .bind(md5)
    .bind(MAX_RELATIONSHIP_CONCEPTS)
    .bind(MAX_EVIDENCE_PER_RELATIONSHIP)
    .fetch_all(pool)
    .await?;

    let truncated = rows
        .iter()
        .any(|row| row.get::<i64, _>("concept_rank") > MAX_RELATIONSHIP_CONCEPTS);

    let mut grouped: BTreeMap<String, (Vec<Vec<RelationshipEvidence>>, bool)> = BTreeMap::new();
    for row in rows {
        let rank: i64 = row.try_get("concept_rank")?;
        if rank > MAX_RELATIONSHIP_CONCEPTS {
            continue;
        }
        let target: String = row.try_get("family_name")?;
        let evidence_total: i64 = row.try_get("evidence_total")?;
        let indicator_kind = parse_hash_kind(&row.try_get::<String, _>("indicator_kind")?)?;
        let evidence = RelationshipEvidence {
            relation: EvidenceRelation::AttributedToMalwareFamily,
            source: row.try_get("source")?,
            confidence: row.try_get("confidence")?,
            first_seen: row.try_get("first_seen")?,
            last_seen: row.try_get("last_seen")?,
            report_id: Some(row.try_get::<Uuid, _>("report_id")?),
            report_title: row.try_get("report_title")?,
            report_url: sanitize_stored_url(row.try_get("report_url")?),
            indicator_kind: Some(indicator_kind),
            indicator_value: Some(row.try_get("indicator_value")?),
            detection_name: None,
            rule_fingerprint: None,
            timing: EvidenceTiming::Observed,
        };
        let entry = grouped.entry(target).or_default();
        entry.0.push(vec![evidence]);
        entry.1 |= evidence_total > MAX_EVIDENCE_PER_RELATIONSHIP;
    }

    let items = grouped
        .into_iter()
        .map(
            |(target, (evidence_paths, has_more_evidence))| ThreatRelationship {
                kind: RelationshipKind::MalwareFamily,
                strength: RelationshipStrength::Direct,
                target,
                explanation:
                    "This file's hash is attributed to a known malware family -- look for other \
                 variants, configs, payloads, and family-specific detections."
                        .to_string(),
                evidence_paths,
                has_more_evidence,
            },
        )
        .collect();

    Ok(Bounded { items, truncated })
}

/// Report-derived CVE lookup with a budget on CVE *targets*, not on
/// `report_references_cve` assertions.
pub async fn cve_matches_via_report(
    pool: &PgPool,
    sha256: &str,
    md5: &str,
) -> Result<Bounded<ThreatRelationship>> {
    let fast = indicators::cve_matches_via_report(pool, sha256, md5).await?;
    if !fast.truncated {
        return Ok(fast);
    }

    let rows = sqlx::query(
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
                i.kind::text AS parent_indicator_kind,
                i.value AS parent_indicator_value
            FROM report_references_cve rrc
            JOIN report r ON r.id = rrc.report_id
            JOIN indicator_observed_in_report iorr ON iorr.report_id = r.id
            JOIN indicator i ON i.id = iorr.indicator_id
            WHERE (i.kind = 'sha256' AND i.value = $1)
               OR (i.kind = 'md5' AND i.value = $2)
        ),
        ranked_targets AS (
            SELECT
                cve_id,
                ROW_NUMBER() OVER (ORDER BY cve_id) AS concept_rank
            FROM (SELECT DISTINCT cve_id FROM matched) t
        ),
        kept_targets AS (
            SELECT * FROM ranked_targets
            WHERE concept_rank <= $3::bigint + 1
        ),
        ranked_evidence AS (
            SELECT
                m.*,
                kt.concept_rank,
                ROW_NUMBER() OVER (
                    PARTITION BY m.cve_id
                    ORDER BY m.cve_source, m.report_id,
                             (m.parent_indicator_kind = 'sha256') DESC,
                             m.parent_last_seen DESC, m.parent_source,
                             m.parent_indicator_value
                ) AS evidence_rank,
                COUNT(*) OVER (PARTITION BY m.cve_id) AS evidence_total
            FROM matched m
            JOIN kept_targets kt USING (cve_id)
        )
        SELECT *
        FROM ranked_evidence
        WHERE evidence_rank <= $4::bigint
        ORDER BY concept_rank, evidence_rank
        "#,
    )
    .bind(sha256)
    .bind(md5)
    .bind(MAX_RELATIONSHIP_CONCEPTS)
    .bind(MAX_EVIDENCE_PER_RELATIONSHIP)
    .fetch_all(pool)
    .await?;

    let truncated = rows
        .iter()
        .any(|row| row.get::<i64, _>("concept_rank") > MAX_RELATIONSHIP_CONCEPTS);

    let mut grouped: BTreeMap<String, (Vec<Vec<RelationshipEvidence>>, bool)> = BTreeMap::new();
    for row in rows {
        let rank: i64 = row.try_get("concept_rank")?;
        if rank > MAX_RELATIONSHIP_CONCEPTS {
            continue;
        }
        let target: String = row.try_get("cve_id")?;
        let evidence_total: i64 = row.try_get("evidence_total")?;
        let report_id: Uuid = row.try_get("report_id")?;
        let report_title: Option<String> = row.try_get("report_title")?;
        let report_url: Option<String> = row.try_get("report_url")?;
        let parent_indicator_kind =
            parse_hash_kind(&row.try_get::<String, _>("parent_indicator_kind")?)?;

        let parent_hop = RelationshipEvidence {
            relation: EvidenceRelation::ObservedInReport,
            source: row.try_get("parent_source")?,
            confidence: row.try_get("parent_confidence")?,
            first_seen: row.try_get("parent_first_seen")?,
            last_seen: row.try_get("parent_last_seen")?,
            report_id: Some(report_id),
            report_title: report_title.clone(),
            report_url: sanitize_stored_url(report_url.clone()),
            indicator_kind: Some(parent_indicator_kind),
            indicator_value: Some(row.try_get("parent_indicator_value")?),
            detection_name: None,
            rule_fingerprint: None,
            timing: EvidenceTiming::Observed,
        };
        let cve_hop = RelationshipEvidence {
            relation: EvidenceRelation::ReportReferencesCve,
            source: row.try_get("cve_source")?,
            confidence: row.try_get("cve_confidence")?,
            first_seen: row.try_get("cve_first_seen")?,
            last_seen: row.try_get("cve_last_seen")?,
            report_id: Some(report_id),
            report_title,
            report_url: sanitize_stored_url(report_url),
            indicator_kind: None,
            indicator_value: None,
            detection_name: None,
            rule_fingerprint: None,
            timing: EvidenceTiming::Observed,
        };

        let entry = grouped.entry(target).or_default();
        entry.0.push(vec![parent_hop, cve_hop]);
        entry.1 |= evidence_total > MAX_EVIDENCE_PER_RELATIONSHIP;
    }

    let items = grouped
        .into_iter()
        .map(
            |(target, (evidence_paths, has_more_evidence))| ThreatRelationship {
                kind: RelationshipKind::Cve,
                strength: RelationshipStrength::Contextual,
                target,
                explanation:
                    "This file was observed in one or more reports that also reference this \
                 CVE -- an inferred association through report co-occurrence, not a direct \
                 per-file CVE assertion. Assess exposure and hunt for exploitation evidence \
                 before treating this as confirmed."
                        .to_string(),
                evidence_paths,
                has_more_evidence,
            },
        )
        .collect();

    Ok(Bounded { items, truncated })
}

/// Detection-derived CVE lookup with a budget on CVE targets. The normal
/// macro-checked query remains the fast path. A high-cardinality result is
/// regrouped here so 200 separate detection assertions about CVE-A cannot
/// hide CVE-B from the pivot set.
#[allow(clippy::too_many_arguments)]
pub async fn cve_matches_via_detection(
    pool: &PgPool,
    scanned_rules: &[(String, String)],
    observed_source: &str,
    observed_confidence: i16,
    observed_at: DateTime<Utc>,
    indicator_kind: IndicatorKind,
    indicator_value: &str,
) -> Result<Bounded<ThreatRelationship>> {
    let fast = indicators::cve_matches_via_detection(
        pool,
        scanned_rules,
        observed_source,
        observed_confidence,
        observed_at,
        indicator_kind,
        indicator_value,
    )
    .await?;
    if !fast.truncated {
        return Ok(fast);
    }
    if scanned_rules.is_empty() {
        return Ok(Bounded {
            items: vec![],
            truncated: false,
        });
    }

    let rule_names: Vec<String> = scanned_rules.iter().map(|(name, _)| name.clone()).collect();
    let rule_fingerprints: Vec<String> = scanned_rules
        .iter()
        .map(|(_, fingerprint)| fingerprint.clone())
        .collect();

    let rows = sqlx::query(
        r#"
        WITH scan AS (
            SELECT *
            FROM UNNEST($1::text[], $2::text[]) AS s(rule_name, rule_fingerprint)
        ),
        matched AS (
            SELECT
                dcc.cve_id,
                dcc.source AS cve_source,
                dcc.confidence AS cve_confidence,
                dcc.first_seen AS cve_first_seen,
                dcc.last_seen AS cve_last_seen,
                d.name AS detection_name,
                scan.rule_fingerprint AS scan_rule_fingerprint,
                dcc.rule_fingerprint AS edge_rule_fingerprint
            FROM detection_covers_cve dcc
            JOIN detection d ON d.id = dcc.detection_id
            JOIN scan ON scan.rule_name = d.name
            WHERE d.kind = 'yara'
              AND (dcc.rule_fingerprint = '' OR dcc.rule_fingerprint = scan.rule_fingerprint)
        ),
        ranked_targets AS (
            SELECT
                cve_id,
                ROW_NUMBER() OVER (ORDER BY cve_id) AS concept_rank
            FROM (SELECT DISTINCT cve_id FROM matched) t
        ),
        kept_targets AS (
            SELECT * FROM ranked_targets
            WHERE concept_rank <= $3::bigint + 1
        ),
        ranked_evidence AS (
            SELECT
                m.*,
                kt.concept_rank,
                ROW_NUMBER() OVER (
                    PARTITION BY m.cve_id
                    ORDER BY m.cve_source, m.detection_name,
                             m.edge_rule_fingerprint, m.scan_rule_fingerprint
                ) AS evidence_rank,
                COUNT(*) OVER (PARTITION BY m.cve_id) AS evidence_total
            FROM matched m
            JOIN kept_targets kt USING (cve_id)
        )
        SELECT *
        FROM ranked_evidence
        WHERE evidence_rank <= $4::bigint
        ORDER BY concept_rank, evidence_rank
        "#,
    )
    .bind(&rule_names)
    .bind(&rule_fingerprints)
    .bind(MAX_RELATIONSHIP_CONCEPTS)
    .bind(MAX_EVIDENCE_PER_RELATIONSHIP)
    .fetch_all(pool)
    .await?;

    let truncated = rows
        .iter()
        .any(|row| row.get::<i64, _>("concept_rank") > MAX_RELATIONSHIP_CONCEPTS);

    let mut grouped: BTreeMap<String, (Vec<Vec<RelationshipEvidence>>, BTreeSet<String>, bool)> =
        BTreeMap::new();
    for row in rows {
        let rank: i64 = row.try_get("concept_rank")?;
        if rank > MAX_RELATIONSHIP_CONCEPTS {
            continue;
        }
        let target: String = row.try_get("cve_id")?;
        let evidence_total: i64 = row.try_get("evidence_total")?;
        let detection_name: String = row.try_get("detection_name")?;
        let scan_rule_fingerprint: String = row.try_get("scan_rule_fingerprint")?;
        let edge_rule_fingerprint: String = row.try_get("edge_rule_fingerprint")?;

        let path = vec![
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
                detection_name: Some(detection_name.clone()),
                rule_fingerprint: Some(scan_rule_fingerprint),
                timing: EvidenceTiming::Observed,
            },
            RelationshipEvidence {
                relation: EvidenceRelation::DetectionCoversCve,
                source: row.try_get("cve_source")?,
                confidence: row.try_get("cve_confidence")?,
                first_seen: row.try_get("cve_first_seen")?,
                last_seen: row.try_get("cve_last_seen")?,
                report_id: None,
                report_title: None,
                report_url: None,
                indicator_kind: None,
                indicator_value: None,
                detection_name: Some(detection_name.clone()),
                rule_fingerprint: if edge_rule_fingerprint.is_empty() {
                    None
                } else {
                    Some(edge_rule_fingerprint)
                },
                timing: EvidenceTiming::Observed,
            },
        ];

        let entry = grouped.entry(target).or_default();
        entry.0.push(path);
        entry.1.insert(detection_name);
        entry.2 |= evidence_total > MAX_EVIDENCE_PER_RELATIONSHIP;
    }

    let items = grouped
        .into_iter()
        .map(
            |(target, (evidence_paths, detection_names, has_more_evidence))| {
                let names: Vec<String> = detection_names.into_iter().collect();
                let explanation = if names.len() == 1 {
                    format!(
                        "The local detection \"{}\", which matched this exact file in the current \
                         scan, is documented to cover this CVE -- assess exposure and hunt for \
                         exploitation evidence.",
                        names[0]
                    )
                } else {
                    format!(
                        "The local detections {}, which matched this exact file in the current scan, \
                         are documented to cover this CVE -- inspect the evidence paths for each \
                         supporting rule, assess exposure, and hunt for exploitation evidence.",
                        names
                            .iter()
                            .map(|name| format!("\"{name}\""))
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                };
                ThreatRelationship {
                    kind: RelationshipKind::Cve,
                    strength: RelationshipStrength::Strong,
                    target,
                    explanation,
                    evidence_paths,
                    has_more_evidence,
                }
            },
        )
        .collect();

    Ok(Bounded { items, truncated })
}

/// When the path-pattern provenance row cap fires, determine whether the
/// omitted rows actually make the RELATE-stage concept set incomplete.
///
/// Multiple reports can support the same path indicator, so "more rows"
/// does not automatically mean "more IOC/RiskBased targets." Conversely,
/// recency ordering can spend all 200 visible rows on one heavily-observed
/// pattern and omit a second pattern entirely. This bounded distinct-target
/// query distinguishes those cases so `VerdictBounds.relationships_truncated`
/// remains literally true rather than either missing a partial pivot set or
/// conservatively claiming concepts were omitted when they were not.
pub async fn path_relationships_incomplete(
    pool: &PgPool,
    file_path: &str,
    visible_targets: &HashSet<String>,
) -> Result<bool> {
    let rows = sqlx::query(
        r#"
        SELECT DISTINCT i.value AS target
        FROM indicator i
        JOIN indicator_observed_in_report iorr ON iorr.indicator_id = i.id
        JOIN report r ON r.id = iorr.report_id
        WHERE i.kind = 'path'
          AND $1 ILIKE '%' || replace(replace(replace(i.value, '\', '\\'), '%', '\%'), '_', '\_') || '%'
        ORDER BY i.value
        LIMIT $2
        "#,
    )
    .bind(file_path)
    .bind(MAX_RELATIONSHIP_CONCEPTS + 1)
    .fetch_all(pool)
    .await?;

    if rows.len() as i64 > MAX_RELATIONSHIP_CONCEPTS {
        return Ok(true);
    }

    for row in rows {
        let target: String = row.try_get("target")?;
        if !visible_targets.contains(&target) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn parse_hash_kind(value: &str) -> Result<IndicatorKind> {
    match value {
        "sha256" => Ok(IndicatorKind::Sha256),
        "md5" => Ok(IndicatorKind::Md5),
        other => bail!("unexpected hash indicator kind in relationship lookup: {other}"),
    }
}
