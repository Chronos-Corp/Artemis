use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Indicator kinds, verdict tiers, and provenance now live in `nsic-core`
/// so the Phase 1 agent/console can share the same intel-graph vocabulary
/// without depending on the desktop app. Re-exported here so existing
/// `crate::models::X` call sites in this crate are unaffected.
pub use nsic_core::models::{
    derive_relationships, DetectionKind, EvidenceRelation, EvidenceTiming, IndicatorKind,
    IntelSourceFreshness, ProvenanceEntry, RelationshipEvidence, RelationshipKind,
    RelationshipStrength, ThreatRelationship, Verdict, VerdictTier,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
    pub size: u64,
    pub modified: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncSummary {
    pub source: String,
    pub indicators_added: usize,
    pub indicators_updated: usize,
    pub reports_added: usize,
    pub synced_at: DateTime<Utc>,
}
