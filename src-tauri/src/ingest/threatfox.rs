use anyhow::{bail, Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value as Json;
use sqlx::PgPool;

use crate::db::indicators as db;
use crate::ingest::parse_abusech_time;
use crate::models::{IndicatorKind, SyncSummary};

pub(crate) const SOURCE: &str = "threatfox";
const API_URL: &str = "https://threatfox-api.abuse.ch/api/v1/";

#[derive(Debug, Deserialize)]
struct TfResponse {
    query_status: String,
    #[serde(default)]
    data: Vec<TfIoc>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct TfIoc {
    id: String,
    ioc: String,
    ioc_type: String,
    #[serde(default)]
    malware_printable: Option<String>,
    /// ThreatFox supplies its own per-IOC confidence, unlike MalwareBazaar.
    /// Surfacing the source's own number is exactly the point of keeping
    /// confidence on the edge instead of flattening every feed to one scale.
    confidence_level: i16,
    first_seen: Option<String>,
    #[serde(default)]
    last_seen: Option<String>,
    #[serde(default)]
    reference: Option<String>,
}

/// Resolves a ThreatFox ioc_type/ioc pair to an indicator kind and the
/// normalized value to store. Kinds this project has no slot for yet
/// (URLs, ip:port pairs beyond a bare host) are skipped rather than
/// force-fit into the wrong bucket.
fn resolve_indicator(ioc_type: &str, ioc: &str) -> Option<(IndicatorKind, String)> {
    match ioc_type {
        "sha256_hash" => Some((IndicatorKind::Sha256, ioc.to_lowercase())),
        "md5_hash" => Some((IndicatorKind::Md5, ioc.to_lowercase())),
        "sha1_hash" => Some((IndicatorKind::Sha1, ioc.to_lowercase())),
        "domain" => Some((IndicatorKind::Domain, ioc.to_lowercase())),
        "ip:port" => ioc
            .split(':')
            .next()
            .map(|host| (IndicatorKind::Ip, host.to_string())),
        _ => None,
    }
}

/// Pulls recent ThreatFox IOCs and folds the ones this project's indicator
/// model can represent (hashes, domains, IPs) into the intel graph.
pub async fn sync(pool: &PgPool, api_key: &str) -> Result<SyncSummary> {
    let client = reqwest::Client::new();
    let resp = client
        .post(API_URL)
        .header("Auth-Key", api_key)
        .json(&serde_json::json!({ "query": "get_iocs", "days": 3 }))
        .send()
        .await
        .context("requesting ThreatFox recent IOCs")?;

    let body: TfResponse = resp.json().await.context("parsing ThreatFox response")?;

    if body.query_status != "ok" {
        bail!("ThreatFox query_status: {}", body.query_status);
    }

    let mut indicators_added = 0usize;
    let mut indicators_updated = 0usize;
    let mut reports_added = 0usize;

    // One transaction for the whole batch; see the matching comment in
    // malwarebazaar.rs for why.
    let mut tx = pool.begin().await?;

    for ioc in &body.data {
        let Some((kind, value)) = resolve_indicator(&ioc.ioc_type, &ioc.ioc) else {
            continue;
        };

        let raw: Json = serde_json::to_value(ioc.clone())?;
        let first_seen = parse_abusech_time(ioc.first_seen.as_deref()).unwrap_or_else(Utc::now);
        let last_seen = parse_abusech_time(ioc.last_seen.as_deref()).unwrap_or(first_seen);

        let title = ioc
            .malware_printable
            .clone()
            .unwrap_or_else(|| "ThreatFox IOC".to_string());
        let url = ioc
            .reference
            .clone()
            .unwrap_or_else(|| format!("https://threatfox.abuse.ch/ioc/{}/", ioc.id));

        let (report_id, report_inserted) = db::upsert_report(
            &mut *tx,
            SOURCE,
            Some(&ioc.id),
            Some(&title),
            Some(&url),
            Some(first_seen),
            &raw,
        )
        .await?;
        if report_inserted {
            reports_added += 1;
        }

        let (indicator_id, indicator_inserted) =
            db::upsert_indicator(&mut *tx, kind, &value).await?;
        if indicator_inserted {
            indicators_added += 1;
        } else {
            indicators_updated += 1;
        }

        db::upsert_indicator_observed_in_report(
            &mut *tx,
            indicator_id,
            report_id,
            SOURCE,
            ioc.confidence_level,
            first_seen,
            last_seen,
        )
        .await?;
    }

    tx.commit().await?;

    db::set_sync_cursor(pool, SOURCE, Some(&Utc::now().to_rfc3339())).await?;

    Ok(SyncSummary {
        source: SOURCE.to_string(),
        indicators_added,
        indicators_updated,
        reports_added,
        synced_at: Utc::now(),
    })
}
