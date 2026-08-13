use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Kind of indicator stored in the intel graph. Mirrors the Postgres
/// `indicator_kind` enum in `src-tauri/migrations/0001_init.sql`. The
/// `sqlx::Type` derive only applies when the `db` feature is on, so the
/// agent can use this enum in its wire protocol without linking sqlx.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "db", derive(sqlx::Type))]
#[cfg_attr(
    feature = "db",
    sqlx(type_name = "indicator_kind", rename_all = "lowercase")
)]
pub enum IndicatorKind {
    Sha256,
    Md5,
    Sha1,
    Imphash,
    Tlsh,
    Ssdeep,
    Path,
    Regkey,
    Mutex,
    Domain,
    Ip,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "db", derive(sqlx::Type))]
#[cfg_attr(
    feature = "db",
    sqlx(type_name = "detection_kind", rename_all = "lowercase")
)]
pub enum DetectionKind {
    Yara,
    Sigma,
}

/// Verdict tiers, ordered strongest to weakest. Never collapse a verdict to
/// a boolean; always carry the tier and the provenance that produced it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerdictTier {
    ExactHash,
    FuzzyHash,
    YaraHit,
    PathPattern,
    Contextual,
}

/// A single piece of evidence backing a verdict. One file can accumulate
/// several of these across tiers and sources; the UI shows all of them
/// rather than collapsing to one number.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceEntry {
    pub tier: VerdictTier,
    pub source: String,
    pub confidence: i16,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub report_id: Option<Uuid>,
    pub report_title: Option<String>,
    pub report_url: Option<String>,
    pub detection_name: Option<String>,
    pub matched_value: String,
    pub cve_ids: Vec<String>,
}

/// The full verdict for a file: every piece of evidence found, sorted
/// strongest tier first. No boolean "bad"/"clean" collapse happens here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verdict {
    pub path: String,
    pub sha256: String,
    pub md5: String,
    pub entries: Vec<ProvenanceEntry>,
}
