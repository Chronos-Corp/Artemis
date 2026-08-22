//! Shared wire contract for applying one authoritative Orion path as a hunt
//! hypothesis to an explicit execution scope.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::models::{RelationshipKind, RelationshipStrength};
use crate::orion::{OrionTrace, TraceNode, TracePath};

pub const DEFAULT_MAX_HUNT_FILES: usize = 1_000;
pub const DEFAULT_MAX_HUNT_FINDINGS: usize = 100;
pub const DEFAULT_MAX_HUNT_ERRORS: usize = 100;
pub const DEFAULT_MAX_HUNT_WALK_ENTRIES: usize = 20_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HuntScopeKind {
    Subtree,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HuntScope {
    pub kind: HuntScopeKind,
    pub root: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HuntRequest {
    pub seed_path: String,
    pub expected_seed_sha256: String,
    pub trace_path_id: String,
    pub scope: HuntScope,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuntHypothesis {
    pub seed_artifact: TraceNode,
    pub selected_path: TracePath,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HuntEvidenceRole {
    Confirming,
    Contradicting,
    Contextual,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuntFinding {
    pub artifact_path: String,
    pub sha256: String,
    pub md5: String,
    pub role: HuntEvidenceRole,
    pub strength: RelationshipStrength,
    /// Best safe directed path supporting this artifact-to-concept finding.
    /// Its complete RELATE proof remains attached.
    pub supporting_path: TracePath,
    pub additional_matching_paths: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HuntScanError {
    pub path: String,
    pub error: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HuntSummary {
    pub files_discovered: usize,
    pub files_analyzed: usize,
    pub files_inconclusive: usize,
    pub confirming_findings: usize,
    pub contradicting_findings: usize,
    pub contextual_findings: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HuntBounds {
    pub max_files: usize,
    pub max_findings: usize,
    pub max_errors: usize,
    pub max_walk_entries: usize,
    pub scope_truncated: bool,
    pub findings_truncated: bool,
    pub omitted_findings: usize,
    pub errors_truncated: bool,
    pub omitted_errors: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuntResult {
    pub hypothesis: HuntHypothesis,
    pub scope: HuntScope,
    pub findings: Vec<HuntFinding>,
    pub scan_errors: Vec<HuntScanError>,
    pub summary: HuntSummary,
    pub bounds: HuntBounds,
    /// Explicit limits on what this execution can safely conclude. Absence
    /// of a match is never silently upgraded into contradicting evidence.
    pub limitations: Vec<String>,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HuntSelectionError {
    MissingPath,
    AmbiguousPath,
}

impl std::fmt::Display for HuntSelectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingPath => write!(f, "selected Orion path is stale or unavailable"),
            Self::AmbiguousPath => write!(f, "selected Orion path identity is ambiguous"),
        }
    }
}

impl std::error::Error for HuntSelectionError {}

/// Selects exactly one server-reconstructed path. A missing or duplicate ID
/// fails closed instead of falling back to relationship target text.
pub fn select_hypothesis(
    trace: &OrionTrace,
    trace_path_id: &str,
) -> Result<HuntHypothesis, HuntSelectionError> {
    let mut matching = trace.paths.iter().filter(|path| path.id == trace_path_id);
    let selected_path = matching.next().ok_or(HuntSelectionError::MissingPath)?;
    if matching.next().is_some() {
        return Err(HuntSelectionError::AmbiguousPath);
    }
    Ok(HuntHypothesis {
        seed_artifact: trace.start.clone(),
        selected_path: selected_path.clone(),
    })
}

pub fn finding_role(path: &TracePath) -> HuntEvidenceRole {
    match path.state {
        crate::orion::TracePathState::Observed => HuntEvidenceRole::Confirming,
        crate::orion::TracePathState::Possible => HuntEvidenceRole::Contextual,
    }
}

pub fn same_hunt_concept(path: &TracePath, kind: RelationshipKind, target: &str) -> bool {
    path.target_kind == kind && path.target == target
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Verdict, VerdictBounds};
    use crate::orion::trace_verdict;

    fn empty_verdict() -> Verdict {
        Verdict {
            path: "/tmp/seed".to_string(),
            sha256: "a".repeat(64),
            md5: "b".repeat(32),
            entries: Vec::new(),
            intel_freshness: Vec::new(),
            threat_relationships: Vec::new(),
            bounds: VerdictBounds::default(),
        }
    }

    #[test]
    fn unknown_path_selector_fails_closed() {
        let trace = trace_verdict(&empty_verdict());
        assert_eq!(
            select_hypothesis(&trace, "trace_path:missing").unwrap_err(),
            HuntSelectionError::MissingPath
        );
    }

    #[test]
    fn duplicate_path_selector_fails_closed() {
        let mut trace = trace_verdict(&empty_verdict());
        let mut path = crate::orion::TracePath {
            id: "trace_path:duplicate".to_string(),
            relationship_index: 0,
            target_kind: RelationshipKind::Cve,
            target: "CVE-2026-0001".to_string(),
            state: crate::orion::TracePathState::Observed,
            rank: crate::orion::TracePathRank {
                relationship_strength: RelationshipStrength::Strong,
                weakest_source_confidence: 80,
                hop_count: 1,
            },
            nodes: Vec::new(),
            edges: Vec::new(),
            supporting_proof: Vec::new(),
            supporting_evidence_partial: false,
        };
        trace.paths.push(path.clone());
        path.relationship_index = 1;
        trace.paths.push(path);

        assert_eq!(
            select_hypothesis(&trace, "trace_path:duplicate").unwrap_err(),
            HuntSelectionError::AmbiguousPath
        );
    }

    #[test]
    fn exact_selector_returns_authoritative_path() {
        let mut verdict = empty_verdict();
        verdict
            .threat_relationships
            .push(crate::models::ThreatRelationship {
                kind: RelationshipKind::RiskBased,
                strength: RelationshipStrength::Weak,
                target: "seed".to_string(),
                explanation: "contextual filename match".to_string(),
                evidence_paths: vec![vec![crate::models::RelationshipEvidence {
                    relation: crate::models::EvidenceRelation::ContextualFilenameMatch,
                    source: "test".to_string(),
                    confidence: 10,
                    first_seen: Utc::now(),
                    last_seen: Utc::now(),
                    report_id: None,
                    report_title: None,
                    report_url: None,
                    indicator_kind: None,
                    indicator_value: None,
                    detection_name: None,
                    rule_fingerprint: None,
                    timing: crate::models::EvidenceTiming::ReceivedOnly,
                }]],
                has_more_evidence: false,
            });
        let trace = trace_verdict(&verdict);
        let selected = select_hypothesis(&trace, &trace.paths[0].id).unwrap();

        assert_eq!(selected.seed_artifact, trace.start);
        assert_eq!(selected.selected_path.id, trace.paths[0].id);
        assert_eq!(
            finding_role(&selected.selected_path),
            HuntEvidenceRole::Contextual
        );
    }

    #[test]
    fn selector_becomes_stale_when_authoritative_partiality_changes() {
        let mut verdict = empty_verdict();
        verdict
            .threat_relationships
            .push(crate::models::ThreatRelationship {
                kind: RelationshipKind::RiskBased,
                strength: RelationshipStrength::Weak,
                target: "seed".to_string(),
                explanation: "contextual filename match".to_string(),
                evidence_paths: vec![vec![crate::models::RelationshipEvidence {
                    relation: crate::models::EvidenceRelation::ContextualFilenameMatch,
                    source: "test".to_string(),
                    confidence: 10,
                    first_seen: Utc::now(),
                    last_seen: Utc::now(),
                    report_id: None,
                    report_title: None,
                    report_url: None,
                    indicator_kind: None,
                    indicator_value: None,
                    detection_name: None,
                    rule_fingerprint: None,
                    timing: crate::models::EvidenceTiming::ReceivedOnly,
                }]],
                has_more_evidence: false,
            });
        let complete = trace_verdict(&verdict);
        let selected_id = complete.paths[0].id.clone();

        verdict.threat_relationships[0].has_more_evidence = true;
        let partial = trace_verdict(&verdict);

        assert_ne!(selected_id, partial.paths[0].id);
        assert_eq!(
            select_hypothesis(&partial, &selected_id).unwrap_err(),
            HuntSelectionError::MissingPath
        );
    }
}
