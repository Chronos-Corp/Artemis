//! Orion's first directed TRACE projection.
//!
//! RELATE deliberately returns evidence-backed relationship concepts and
//! native proof assertions, not traversable graph paths. This module is the
//! boundary that turns that normalized contract into explicit, directed,
//! bounded paths without parsing explanation prose or guessing direction
//! from an `EvidenceRelation` name.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::models::{
    EvidenceRelation, EvidenceTiming, IndicatorKind, RelationshipEvidence,
    RelationshipKind, RelationshipStrength, ThreatRelationship, Verdict,
};

/// Orion's independent path budget. RELATE has its own concept and evidence
/// budgets; TRACE must not inherit those limits implicitly or present its own
/// bounded projection as exhaustive.
pub const DEFAULT_MAX_TRACE_PATHS: usize = 100;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TraceNodeKind {
    Artifact,
    Indicator,
    Report,
    Detection,
    Cve,
    MalwareFamily,
    RiskConcept,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceNode {
    /// Stable within the node's typed namespace. Components are length-
    /// prefixed so values containing separators cannot alias another node.
    pub id: String,
    pub kind: TraceNodeKind,
    pub label: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TraceEdgeRelation {
    ArtifactHasIndicator,
    IndicatorObservedInReport,
    ReportReferencesCve,
    IndicatorMatchedByDetection,
    DetectionCoversCve,
    IndicatorAttributedToMalwareFamily,
    ContextualFilenameMatch,
}

/// How a directed TRACE edge relates to the native assertion carried by its
/// supporting RELATE proof hop.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssertionOrientation {
    /// TRACE follows the assertion's native direction.
    Native,
    /// TRACE walks the assertion in reverse, explicitly and intentionally.
    Reversed,
    /// The edge is an Orion bridge from the selected artifact or a
    /// contextual possibility; it is not presented as a native graph fact.
    Synthetic,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceEdge {
    pub from: String,
    pub to: String,
    pub relation: TraceEdgeRelation,
    pub assertion_orientation: AssertionOrientation,
    /// Index into `TracePath.supporting_proof` when this edge is the explicit
    /// traversal of one proof assertion. Synthetic bridges use `None`.
    pub proof_hop_index: Option<usize>,
}

/// `Observed` means every non-synthetic traversal edge is backed by a typed,
/// sourced assertion. `Possible` is reserved for contextual relationships
/// that RELATE itself says have no backing edge table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TracePathState {
    Observed,
    Possible,
}

/// An explicit rank vector, not an opaque score. Relationship mechanism,
/// source confidence, and path length remain separate and inspectable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TracePathRank {
    pub relationship_strength: RelationshipStrength,
    pub weakest_source_confidence: i16,
    pub hop_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracePath {
    /// Stable identity for this exact seed, relationship, traversal, and
    /// supporting proof identity. Observation-window timestamps and display
    /// labels are excluded so a new live observation of unchanged evidence
    /// does not make an analyst's just-selected path stale. HUNT accepts this
    /// opaque selector and reconstructs it server-side rather than trusting
    /// target/proof fields supplied over IPC.
    pub id: String,
    /// Index in `Verdict.threat_relationships`, retained so an analyst can
    /// open the trace for the exact RELATE concept they selected.
    pub relationship_index: usize,
    pub target_kind: RelationshipKind,
    pub target: String,
    pub state: TracePathState,
    pub rank: TracePathRank,
    pub nodes: Vec<TraceNode>,
    pub edges: Vec<TraceEdge>,
    /// The complete RELATE proof chain remains alongside the traversal. An
    /// edge never has to pretend that proof assertions and traversal edges
    /// are the same thing in order to preserve provenance.
    pub supporting_proof: Vec<RelationshipEvidence>,
    pub supporting_evidence_partial: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UntracedReason {
    EmptyProof,
    MixedProofShape,
    UnsupportedRelationshipShape,
    MissingNodeIdentity,
    InconsistentProofEndpoints,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UntracedRelationship {
    pub relationship_index: usize,
    pub target_kind: RelationshipKind,
    pub target: String,
    pub reason: UntracedReason,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceBounds {
    /// RELATE omitted distinct concepts before Orion received the verdict.
    pub input_relationships_truncated: bool,
    /// At least one emitted relationship had upstream proof paths omitted.
    pub input_evidence_truncated: bool,
    /// Orion's own independent path budget omitted otherwise valid paths.
    pub paths_truncated: bool,
    pub omitted_paths: usize,
    pub max_paths: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrionTrace {
    pub start: TraceNode,
    pub paths: Vec<TracePath>,
    pub untraced_relationships: Vec<UntracedRelationship>,
    pub bounds: TraceBounds,
}

/// Build First Useful Trace from the already-normalized RELATE verdict.
pub fn trace_verdict(verdict: &Verdict) -> OrionTrace {
    trace_verdict_bounded(verdict, DEFAULT_MAX_TRACE_PATHS)
}

fn trace_verdict_bounded(verdict: &Verdict, max_paths: usize) -> OrionTrace {
    let start = artifact_node(&verdict.sha256, &verdict.path);
    let mut by_relationship: Vec<Vec<TracePath>> = Vec::new();
    let mut untraced_relationships = Vec::new();

    for (relationship_index, relationship) in verdict.threat_relationships.iter().enumerate() {
        let proof_shape = match uniform_proof_shape(relationship) {
            Ok(shape) => shape,
            Err(reason) => {
                untraced_relationships.push(untraced(relationship_index, relationship, reason));
                by_relationship.push(Vec::new());
                continue;
            }
        };

        let mut paths = Vec::new();
        let mut projection_error = None;
        for proof in &relationship.evidence_paths {
            match project_path(
                &start,
                relationship_index,
                relationship,
                proof,
                &proof_shape,
            ) {
                Ok(path) => paths.push(path),
                Err(reason) => {
                    projection_error = Some(reason);
                    break;
                }
            };
        }

        if let Some(reason) = projection_error {
            // One malformed proof path makes the relationship's outward
            // traversal contract partial in a way RELATE did not declare.
            // Reject the relationship as a unit rather than silently showing
            // only the paths that happened to project successfully.
            paths.clear();
            untraced_relationships.push(untraced(
                relationship_index,
                relationship,
                reason,
            ));
        } else if paths.is_empty() {
            untraced_relationships.push(untraced(
                relationship_index,
                relationship,
                UntracedReason::UnsupportedRelationshipShape,
            ));
        } else {
            // Fair allocation must consume each relationship's best path
            // first. Sorting only after applying the global budget could
            // preserve a weaker earlier proof while omitting a stronger one.
            paths.sort_by(compare_paths);
        }
        by_relationship.push(paths);
    }

    // Fair selection: take at most one path from every relationship before a
    // noisy concept can consume a second slot. Relationship order is ranked,
    // but distinct pivots are budgeted independently first.
    let mut relationship_order: Vec<usize> = (0..by_relationship.len()).collect();
    relationship_order.sort_by(|left, right| {
        match (by_relationship[*left].first(), by_relationship[*right].first()) {
            (Some(left_path), Some(right_path)) => compare_paths(left_path, right_path),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => left.cmp(right),
        }
    });

    let candidate_count: usize = by_relationship.iter().map(Vec::len).sum();
    let mut paths = Vec::with_capacity(candidate_count.min(max_paths));
    let max_rounds = by_relationship.iter().map(Vec::len).max().unwrap_or(0);
    'rounds: for round in 0..max_rounds {
        for relationship_index in &relationship_order {
            if let Some(path) = by_relationship[*relationship_index].get(round) {
                if paths.len() == max_paths {
                    break 'rounds;
                }
                paths.push(path.clone());
            }
        }
    }
    paths.sort_by(compare_paths);

    let omitted_paths = candidate_count.saturating_sub(paths.len());
    OrionTrace {
        start,
        paths,
        untraced_relationships,
        bounds: TraceBounds {
            input_relationships_truncated: verdict.bounds.relationships_truncated,
            input_evidence_truncated: verdict
                .threat_relationships
                .iter()
                .any(|relationship| relationship.has_more_evidence),
            paths_truncated: omitted_paths > 0,
            omitted_paths,
            max_paths,
        },
    }
}

fn compare_paths(left: &TracePath, right: &TracePath) -> std::cmp::Ordering {
    right
        .rank
        .relationship_strength
        .cmp(&left.rank.relationship_strength)
        .then_with(|| {
            right
                .rank
                .weakest_source_confidence
                .cmp(&left.rank.weakest_source_confidence)
        })
        .then_with(|| left.rank.hop_count.cmp(&right.rank.hop_count))
        .then_with(|| left.target_kind_sort_key().cmp(&right.target_kind_sort_key()))
        .then_with(|| left.target.cmp(&right.target))
        .then_with(|| left.relationship_index.cmp(&right.relationship_index))
}

impl TracePath {
    fn target_kind_sort_key(&self) -> u8 {
        match self.target_kind {
            RelationshipKind::Ioc => 0,
            RelationshipKind::Detection => 1,
            RelationshipKind::Cve => 2,
            RelationshipKind::MalwareFamily => 3,
            RelationshipKind::ThreatActor => 4,
            RelationshipKind::Campaign => 5,
            RelationshipKind::AttackTechnique => 6,
            RelationshipKind::RiskBased => 7,
        }
    }
}

fn uniform_proof_shape(
    relationship: &ThreatRelationship,
) -> Result<Vec<EvidenceRelation>, UntracedReason> {
    let first = relationship
        .evidence_paths
        .first()
        .ok_or(UntracedReason::EmptyProof)?;
    if first.is_empty() {
        return Err(UntracedReason::EmptyProof);
    }
    let shape: Vec<EvidenceRelation> = first.iter().map(|hop| hop.relation).collect();
    if relationship.evidence_paths.iter().any(|path| {
        path.len() != shape.len()
            || path
                .iter()
                .zip(shape.iter())
                .any(|(hop, expected)| hop.relation != *expected)
    }) {
        return Err(UntracedReason::MixedProofShape);
    }
    Ok(shape)
}

fn project_path(
    start: &TraceNode,
    relationship_index: usize,
    relationship: &ThreatRelationship,
    proof: &[RelationshipEvidence],
    shape: &[EvidenceRelation],
) -> Result<TracePath, UntracedReason> {
    if relationship.target.trim().is_empty() {
        return Err(UntracedReason::MissingNodeIdentity);
    }

    let (nodes, edges, state) = match (relationship.kind, shape) {
        (RelationshipKind::Ioc, [EvidenceRelation::ObservedInReport]) => {
            let indicator = indicator_from_evidence(&proof[0])?;
            if indicator.label != relationship.target {
                return Err(UntracedReason::InconsistentProofEndpoints);
            }
            (
                vec![start.clone(), indicator.clone()],
                vec![synthetic_edge(
                    start,
                    &indicator,
                    TraceEdgeRelation::ArtifactHasIndicator,
                )],
                TracePathState::Observed,
            )
        }
        (RelationshipKind::Detection, [EvidenceRelation::DetectsIndicator]) => {
            let indicator = indicator_from_evidence(&proof[0])?;
            let detection = detection_from_evidence(&proof[0])?;
            if detection.label != relationship.target {
                return Err(UntracedReason::InconsistentProofEndpoints);
            }
            (
                vec![start.clone(), indicator.clone(), detection.clone()],
                vec![
                    synthetic_edge(start, &indicator, TraceEdgeRelation::ArtifactHasIndicator),
                    proof_edge(
                        &indicator,
                        &detection,
                        TraceEdgeRelation::IndicatorMatchedByDetection,
                        AssertionOrientation::Reversed,
                        0,
                    ),
                ],
                TracePathState::Observed,
            )
        }
        (
            RelationshipKind::Cve,
            [EvidenceRelation::ObservedInReport, EvidenceRelation::ReportReferencesCve],
        ) => {
            let indicator = indicator_from_evidence(&proof[0])?;
            let report = report_from_evidence(&proof[0])?;
            let referenced_report_id = proof[1]
                .report_id
                .ok_or(UntracedReason::MissingNodeIdentity)?;
            if Some(referenced_report_id) != proof[0].report_id {
                return Err(UntracedReason::InconsistentProofEndpoints);
            }
            let cve = concept_node(TraceNodeKind::Cve, "cve", &relationship.target);
            (
                vec![start.clone(), indicator.clone(), report.clone(), cve.clone()],
                vec![
                    synthetic_edge(start, &indicator, TraceEdgeRelation::ArtifactHasIndicator),
                    proof_edge(
                        &indicator,
                        &report,
                        TraceEdgeRelation::IndicatorObservedInReport,
                        AssertionOrientation::Native,
                        0,
                    ),
                    proof_edge(
                        &report,
                        &cve,
                        TraceEdgeRelation::ReportReferencesCve,
                        AssertionOrientation::Native,
                        1,
                    ),
                ],
                TracePathState::Observed,
            )
        }
        (
            RelationshipKind::Cve,
            [EvidenceRelation::DetectsIndicator, EvidenceRelation::DetectionCoversCve],
        ) => {
            let indicator = indicator_from_evidence(&proof[0])?;
            let detection = detection_from_evidence(&proof[0])?;
            validate_detection_coverage_endpoint(&proof[0], &proof[1])?;
            let cve = concept_node(TraceNodeKind::Cve, "cve", &relationship.target);
            (
                vec![start.clone(), indicator.clone(), detection.clone(), cve.clone()],
                vec![
                    synthetic_edge(start, &indicator, TraceEdgeRelation::ArtifactHasIndicator),
                    proof_edge(
                        &indicator,
                        &detection,
                        TraceEdgeRelation::IndicatorMatchedByDetection,
                        AssertionOrientation::Reversed,
                        0,
                    ),
                    proof_edge(
                        &detection,
                        &cve,
                        TraceEdgeRelation::DetectionCoversCve,
                        AssertionOrientation::Native,
                        1,
                    ),
                ],
                TracePathState::Observed,
            )
        }
        (
            RelationshipKind::MalwareFamily,
            [EvidenceRelation::AttributedToMalwareFamily],
        ) => {
            let indicator = indicator_from_evidence(&proof[0])?;
            let family = concept_node(
                TraceNodeKind::MalwareFamily,
                "malware_family",
                &relationship.target,
            );
            (
                vec![start.clone(), indicator.clone(), family.clone()],
                vec![
                    synthetic_edge(start, &indicator, TraceEdgeRelation::ArtifactHasIndicator),
                    proof_edge(
                        &indicator,
                        &family,
                        TraceEdgeRelation::IndicatorAttributedToMalwareFamily,
                        AssertionOrientation::Native,
                        0,
                    ),
                ],
                TracePathState::Observed,
            )
        }
        (RelationshipKind::RiskBased, [EvidenceRelation::ContextualFilenameMatch]) => {
            let risk = concept_node(
                TraceNodeKind::RiskConcept,
                "risk",
                &relationship.target,
            );
            (
                vec![start.clone(), risk.clone()],
                vec![proof_edge(
                    start,
                    &risk,
                    TraceEdgeRelation::ContextualFilenameMatch,
                    AssertionOrientation::Synthetic,
                    0,
                )],
                TracePathState::Possible,
            )
        }
        _ => return Err(UntracedReason::UnsupportedRelationshipShape),
    };

    let weakest_source_confidence = proof
        .iter()
        .map(|hop| hop.confidence)
        .min()
        .ok_or(UntracedReason::EmptyProof)?;
    let rank = TracePathRank {
        relationship_strength: relationship.strength,
        weakest_source_confidence,
        hop_count: edges.len(),
    };
    let id = trace_path_id(
        start,
        relationship_index,
        relationship,
        state,
        &rank,
        &nodes,
        &edges,
        proof,
    );
    Ok(TracePath {
        id,
        relationship_index,
        target_kind: relationship.kind,
        target: relationship.target.clone(),
        state,
        rank,
        nodes,
        edges,
        supporting_proof: proof.to_vec(),
        supporting_evidence_partial: relationship.has_more_evidence,
    })
}

#[allow(clippy::too_many_arguments)]
fn trace_path_id(
    start: &TraceNode,
    relationship_index: usize,
    relationship: &ThreatRelationship,
    state: TracePathState,
    rank: &TracePathRank,
    nodes: &[TraceNode],
    edges: &[TraceEdge],
    proof: &[RelationshipEvidence],
) -> String {
    let mut digest = Sha256::new();
    hash_component(&mut digest, "orion-trace-path-v1");
    hash_component(&mut digest, &start.id);
    hash_component(&mut digest, &relationship_index.to_string());
    hash_component(&mut digest, relationship_kind_key(relationship.kind));
    hash_component(&mut digest, &relationship.target);
    hash_component(&mut digest, trace_path_state_key(state));
    hash_component(
        &mut digest,
        relationship_strength_key(rank.relationship_strength),
    );
    hash_component(&mut digest, &rank.weakest_source_confidence.to_string());
    hash_component(&mut digest, &rank.hop_count.to_string());
    hash_component(
        &mut digest,
        if relationship.has_more_evidence {
            "partial"
        } else {
            "complete"
        },
    );

    for node in nodes {
        hash_component(&mut digest, trace_node_kind_key(node.kind));
        hash_component(&mut digest, &node.id);
    }
    for edge in edges {
        hash_component(&mut digest, &edge.from);
        hash_component(&mut digest, &edge.to);
        hash_component(&mut digest, trace_edge_relation_key(edge.relation));
        hash_component(
            &mut digest,
            assertion_orientation_key(edge.assertion_orientation),
        );
        hash_optional_component(
            &mut digest,
            edge.proof_hop_index.map(|index| index.to_string()).as_deref(),
        );
    }
    for hop in proof {
        hash_component(&mut digest, evidence_relation_key(hop.relation));
        hash_component(&mut digest, &hop.source);
        hash_component(&mut digest, &hop.confidence.to_string());
        hash_optional_component(
            &mut digest,
            hop.report_id.map(|id| id.to_string()).as_deref(),
        );
        hash_optional_component(
            &mut digest,
            hop.indicator_kind.map(indicator_kind_key),
        );
        hash_optional_component(&mut digest, hop.indicator_value.as_deref());
        hash_optional_component(&mut digest, hop.detection_name.as_deref());
        hash_optional_component(&mut digest, hop.rule_fingerprint.as_deref());
        hash_component(&mut digest, evidence_timing_key(hop.timing));
    }

    format!("trace_path:{}", hex::encode(digest.finalize()))
}

fn hash_component(digest: &mut Sha256, value: &str) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value.as_bytes());
}

fn hash_optional_component(digest: &mut Sha256, value: Option<&str>) {
    match value {
        Some(value) => {
            hash_component(digest, "some");
            hash_component(digest, value);
        }
        None => hash_component(digest, "none"),
    }
}

fn relationship_kind_key(kind: RelationshipKind) -> &'static str {
    match kind {
        RelationshipKind::Ioc => "ioc",
        RelationshipKind::Detection => "detection",
        RelationshipKind::Cve => "cve",
        RelationshipKind::MalwareFamily => "malware_family",
        RelationshipKind::ThreatActor => "threat_actor",
        RelationshipKind::Campaign => "campaign",
        RelationshipKind::AttackTechnique => "attack_technique",
        RelationshipKind::RiskBased => "risk_based",
    }
}

fn relationship_strength_key(strength: RelationshipStrength) -> &'static str {
    match strength {
        RelationshipStrength::Weak => "weak",
        RelationshipStrength::Contextual => "contextual",
        RelationshipStrength::Strong => "strong",
        RelationshipStrength::Direct => "direct",
    }
}

fn trace_node_kind_key(kind: TraceNodeKind) -> &'static str {
    match kind {
        TraceNodeKind::Artifact => "artifact",
        TraceNodeKind::Indicator => "indicator",
        TraceNodeKind::Report => "report",
        TraceNodeKind::Detection => "detection",
        TraceNodeKind::Cve => "cve",
        TraceNodeKind::MalwareFamily => "malware_family",
        TraceNodeKind::RiskConcept => "risk_concept",
    }
}

fn trace_edge_relation_key(relation: TraceEdgeRelation) -> &'static str {
    match relation {
        TraceEdgeRelation::ArtifactHasIndicator => "artifact_has_indicator",
        TraceEdgeRelation::IndicatorObservedInReport => "indicator_observed_in_report",
        TraceEdgeRelation::ReportReferencesCve => "report_references_cve",
        TraceEdgeRelation::IndicatorMatchedByDetection => "indicator_matched_by_detection",
        TraceEdgeRelation::DetectionCoversCve => "detection_covers_cve",
        TraceEdgeRelation::IndicatorAttributedToMalwareFamily => {
            "indicator_attributed_to_malware_family"
        }
        TraceEdgeRelation::ContextualFilenameMatch => "contextual_filename_match",
    }
}

fn assertion_orientation_key(orientation: AssertionOrientation) -> &'static str {
    match orientation {
        AssertionOrientation::Native => "native",
        AssertionOrientation::Reversed => "reversed",
        AssertionOrientation::Synthetic => "synthetic",
    }
}

fn trace_path_state_key(state: TracePathState) -> &'static str {
    match state {
        TracePathState::Observed => "observed",
        TracePathState::Possible => "possible",
    }
}

fn evidence_relation_key(relation: EvidenceRelation) -> &'static str {
    match relation {
        EvidenceRelation::ObservedInReport => "observed_in_report",
        EvidenceRelation::ReportReferencesCve => "report_references_cve",
        EvidenceRelation::DetectsIndicator => "detects_indicator",
        EvidenceRelation::DetectionCoversCve => "detection_covers_cve",
        EvidenceRelation::AttributedToMalwareFamily => "attributed_to_malware_family",
        EvidenceRelation::ContextualFilenameMatch => "contextual_filename_match",
    }
}

fn evidence_timing_key(timing: EvidenceTiming) -> &'static str {
    match timing {
        EvidenceTiming::Observed => "observed",
        EvidenceTiming::ReceivedOnly => "received_only",
    }
}

fn artifact_node(sha256: &str, path: &str) -> TraceNode {
    TraceNode {
        // A file instance is content at a location. Hash-only identity would
        // collapse separate filesystem artifacts that happen to contain the
        // same bytes, destroying the path context Artemis hunts.
        id: stable_id("artifact", &[&sha256.to_lowercase(), path]),
        kind: TraceNodeKind::Artifact,
        label: path.to_string(),
    }
}

fn indicator_from_evidence(
    evidence: &RelationshipEvidence,
) -> Result<TraceNode, UntracedReason> {
    let kind = evidence
        .indicator_kind
        .ok_or(UntracedReason::MissingNodeIdentity)?;
    let value = evidence
        .indicator_value
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .ok_or(UntracedReason::MissingNodeIdentity)?;
    Ok(TraceNode {
        id: stable_id("indicator", &[indicator_kind_key(kind), value]),
        kind: TraceNodeKind::Indicator,
        label: value.to_string(),
    })
}

fn report_from_evidence(evidence: &RelationshipEvidence) -> Result<TraceNode, UntracedReason> {
    let report_id = evidence
        .report_id
        .ok_or(UntracedReason::MissingNodeIdentity)?;
    Ok(TraceNode {
        id: stable_id("report", &[&report_id.to_string()]),
        kind: TraceNodeKind::Report,
        label: evidence
            .report_title
            .clone()
            .unwrap_or_else(|| report_id.to_string()),
    })
}

fn detection_from_evidence(
    evidence: &RelationshipEvidence,
) -> Result<TraceNode, UntracedReason> {
    let name = evidence
        .detection_name
        .as_deref()
        .filter(|name| !name.trim().is_empty())
        .ok_or(UntracedReason::MissingNodeIdentity)?;
    // A Detection node represents the concrete rule that fired. Any-version
    // is valid only as the scope of a DetectionCoversCve assertion; it can
    // never stand in for a missing current observation fingerprint.
    let version = evidence
        .rule_fingerprint
        .as_deref()
        .filter(|version| !version.trim().is_empty())
        .ok_or(UntracedReason::MissingNodeIdentity)?;
    Ok(TraceNode {
        id: stable_id("detection_yara", &[name, version]),
        kind: TraceNodeKind::Detection,
        label: name.to_string(),
    })
}

fn validate_detection_coverage_endpoint(
    observation: &RelationshipEvidence,
    coverage: &RelationshipEvidence,
) -> Result<(), UntracedReason> {
    let observation_name = observation
        .detection_name
        .as_deref()
        .filter(|name| !name.trim().is_empty())
        .ok_or(UntracedReason::MissingNodeIdentity)?;
    let coverage_name = coverage
        .detection_name
        .as_deref()
        .filter(|name| !name.trim().is_empty())
        .ok_or(UntracedReason::MissingNodeIdentity)?;
    if coverage_name != observation_name {
        return Err(UntracedReason::InconsistentProofEndpoints);
    }

    let observation_version = observation
        .rule_fingerprint
        .as_deref()
        .filter(|version| !version.trim().is_empty())
        .ok_or(UntracedReason::MissingNodeIdentity)?;
    if let Some(coverage_version) = coverage.rule_fingerprint.as_deref() {
        if coverage_version.trim().is_empty() {
            return Err(UntracedReason::MissingNodeIdentity);
        }
        if coverage_version != observation_version {
            return Err(UntracedReason::InconsistentProofEndpoints);
        }
    }

    Ok(())
}

fn concept_node(kind: TraceNodeKind, namespace: &str, value: &str) -> TraceNode {
    TraceNode {
        id: stable_id(namespace, &[value]),
        kind,
        label: value.to_string(),
    }
}

fn stable_id(namespace: &str, components: &[&str]) -> String {
    let mut id = namespace.to_string();
    for component in components {
        id.push('|');
        id.push_str(&component.len().to_string());
        id.push(':');
        id.push_str(component);
    }
    id
}

fn indicator_kind_key(kind: IndicatorKind) -> &'static str {
    match kind {
        IndicatorKind::Sha256 => "sha256",
        IndicatorKind::Md5 => "md5",
        IndicatorKind::Sha1 => "sha1",
        IndicatorKind::Imphash => "imphash",
        IndicatorKind::Tlsh => "tlsh",
        IndicatorKind::Ssdeep => "ssdeep",
        IndicatorKind::Path => "path",
        IndicatorKind::Regkey => "regkey",
        IndicatorKind::Mutex => "mutex",
        IndicatorKind::Domain => "domain",
        IndicatorKind::Ip => "ip",
    }
}

fn synthetic_edge(from: &TraceNode, to: &TraceNode, relation: TraceEdgeRelation) -> TraceEdge {
    TraceEdge {
        from: from.id.clone(),
        to: to.id.clone(),
        relation,
        assertion_orientation: AssertionOrientation::Synthetic,
        proof_hop_index: None,
    }
}

fn proof_edge(
    from: &TraceNode,
    to: &TraceNode,
    relation: TraceEdgeRelation,
    assertion_orientation: AssertionOrientation,
    proof_hop_index: usize,
) -> TraceEdge {
    TraceEdge {
        from: from.id.clone(),
        to: to.id.clone(),
        relation,
        assertion_orientation,
        proof_hop_index: Some(proof_hop_index),
    }
}

fn untraced(
    relationship_index: usize,
    relationship: &ThreatRelationship,
    reason: UntracedReason,
) -> UntracedRelationship {
    UntracedRelationship {
        relationship_index,
        target_kind: relationship.kind,
        target: relationship.target.clone(),
        reason,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{EvidenceTiming, VerdictBounds};
    use chrono::{Duration, Utc};
    use uuid::Uuid;

    fn hop(relation: EvidenceRelation) -> RelationshipEvidence {
        let now = Utc::now();
        RelationshipEvidence {
            relation,
            source: "test-source".to_string(),
            confidence: 80,
            first_seen: now,
            last_seen: now,
            report_id: Some(Uuid::nil()),
            report_title: Some("Test report".to_string()),
            report_url: None,
            indicator_kind: Some(IndicatorKind::Sha256),
            indicator_value: Some("abc123".to_string()),
            detection_name: Some("test_rule".to_string()),
            rule_fingerprint: Some("rule-v1".to_string()),
            timing: EvidenceTiming::Observed,
        }
    }

    fn relationship(
        kind: RelationshipKind,
        strength: RelationshipStrength,
        target: &str,
        relations: &[EvidenceRelation],
    ) -> ThreatRelationship {
        ThreatRelationship {
            kind,
            strength,
            target: target.to_string(),
            explanation: "test".to_string(),
            evidence_paths: vec![relations.iter().copied().map(hop).collect()],
            has_more_evidence: false,
        }
    }

    fn verdict(relationships: Vec<ThreatRelationship>) -> Verdict {
        Verdict {
            path: "/tmp/sample.bin".to_string(),
            sha256: "abc123".to_string(),
            md5: "def456".to_string(),
            entries: Vec::new(),
            intel_freshness: Vec::new(),
            threat_relationships: relationships,
            bounds: VerdictBounds::default(),
        }
    }

    #[test]
    fn report_cve_trace_has_literal_endpoints_and_native_directions() {
        let trace = trace_verdict(&verdict(vec![relationship(
            RelationshipKind::Cve,
            RelationshipStrength::Contextual,
            "CVE-2026-0001",
            &[
                EvidenceRelation::ObservedInReport,
                EvidenceRelation::ReportReferencesCve,
            ],
        )]));

        let path = &trace.paths[0];
        assert_eq!(path.nodes.len(), 4);
        assert_eq!(path.nodes[0].kind, TraceNodeKind::Artifact);
        assert_eq!(path.nodes[1].kind, TraceNodeKind::Indicator);
        assert_eq!(path.nodes[2].kind, TraceNodeKind::Report);
        assert_eq!(path.nodes[3].kind, TraceNodeKind::Cve);
        assert_eq!(path.edges[1].assertion_orientation, AssertionOrientation::Native);
        assert_eq!(path.edges[2].proof_hop_index, Some(1));
        assert_eq!(path.supporting_proof.len(), 2);
    }

    #[test]
    fn path_identity_is_stable_across_observation_window_updates() {
        let relationship = relationship(
            RelationshipKind::Cve,
            RelationshipStrength::Contextual,
            "CVE-2026-0001",
            &[
                EvidenceRelation::ObservedInReport,
                EvidenceRelation::ReportReferencesCve,
            ],
        );
        let first = trace_verdict(&verdict(vec![relationship.clone()]));

        let mut observed_later = relationship;
        for hop in &mut observed_later.evidence_paths[0] {
            hop.first_seen += Duration::minutes(1);
            hop.last_seen += Duration::minutes(2);
            hop.report_title = Some("Renamed report title".to_string());
        }
        let second = trace_verdict(&verdict(vec![observed_later]));

        assert_eq!(first.paths[0].id, second.paths[0].id);
    }

    #[test]
    fn path_identity_changes_when_effective_detection_identity_changes() {
        let relationship = relationship(
            RelationshipKind::Detection,
            RelationshipStrength::Strong,
            "test_rule",
            &[EvidenceRelation::DetectsIndicator],
        );
        let first = trace_verdict(&verdict(vec![relationship.clone()]));

        let mut changed = relationship;
        changed.evidence_paths[0][0].rule_fingerprint = Some("rule-v2".to_string());
        let second = trace_verdict(&verdict(vec![changed]));

        assert_ne!(first.paths[0].id, second.paths[0].id);
    }

    #[test]
    fn path_identity_changes_when_supporting_evidence_becomes_partial() {
        let relationship = relationship(
            RelationshipKind::Detection,
            RelationshipStrength::Strong,
            "test_rule",
            &[EvidenceRelation::DetectsIndicator],
        );
        let complete = trace_verdict(&verdict(vec![relationship.clone()]));

        let mut partial_relationship = relationship;
        partial_relationship.has_more_evidence = true;
        let partial = trace_verdict(&verdict(vec![partial_relationship]));

        assert_ne!(complete.paths[0].id, partial.paths[0].id);
        assert!(!complete.paths[0].supporting_evidence_partial);
        assert!(partial.paths[0].supporting_evidence_partial);
        assert!(partial.bounds.input_evidence_truncated);
    }

    #[test]
    fn trace_discloses_relationship_and_evidence_input_partiality_separately() {
        let mut partial_relationship = relationship(
            RelationshipKind::Ioc,
            RelationshipStrength::Direct,
            "abc123",
            &[EvidenceRelation::ObservedInReport],
        );
        partial_relationship.has_more_evidence = true;
        let mut partial_verdict = verdict(vec![partial_relationship]);
        partial_verdict.bounds.relationships_truncated = true;

        let trace = trace_verdict(&partial_verdict);

        assert!(trace.bounds.input_relationships_truncated);
        assert!(trace.bounds.input_evidence_truncated);
        assert!(!trace.bounds.paths_truncated);
        assert_eq!(trace.bounds.omitted_paths, 0);
        assert!(trace.paths[0].supporting_evidence_partial);
    }

    #[test]
    fn detection_cve_trace_marks_the_hidden_reverse_explicitly() {
        let trace = trace_verdict(&verdict(vec![relationship(
            RelationshipKind::Cve,
            RelationshipStrength::Strong,
            "CVE-2026-0002",
            &[
                EvidenceRelation::DetectsIndicator,
                EvidenceRelation::DetectionCoversCve,
            ],
        )]));

        let path = &trace.paths[0];
        assert_eq!(path.nodes[2].kind, TraceNodeKind::Detection);
        assert_eq!(path.edges[1].relation, TraceEdgeRelation::IndicatorMatchedByDetection);
        assert_eq!(path.edges[1].assertion_orientation, AssertionOrientation::Reversed);
        assert_eq!(path.edges[2].assertion_orientation, AssertionOrientation::Native);
    }

    #[test]
    fn detection_cve_trace_accepts_explicit_any_version_coverage() {
        let mut cve = relationship(
            RelationshipKind::Cve,
            RelationshipStrength::Strong,
            "CVE-2026-0002",
            &[
                EvidenceRelation::DetectsIndicator,
                EvidenceRelation::DetectionCoversCve,
            ],
        );
        cve.evidence_paths[0][1].rule_fingerprint = None;

        let trace = trace_verdict(&verdict(vec![cve]));
        assert_eq!(trace.paths.len(), 1);
        assert!(trace.untraced_relationships.is_empty());
        assert!(trace.paths[0].nodes[2].id.contains("rule-v1"));
    }

    #[test]
    fn current_detection_identity_never_broadens_to_any_version() {
        for fingerprint in [None, Some(String::new()), Some("   ".to_string())] {
            let mut detection = relationship(
                RelationshipKind::Detection,
                RelationshipStrength::Strong,
                "test_rule",
                &[EvidenceRelation::DetectsIndicator],
            );
            detection.evidence_paths[0][0].rule_fingerprint = fingerprint;

            let trace = trace_verdict(&verdict(vec![detection]));
            assert!(trace.paths.is_empty());
            assert_eq!(trace.untraced_relationships.len(), 1);
            assert_eq!(
                trace.untraced_relationships[0].reason,
                UntracedReason::MissingNodeIdentity
            );
        }
    }

    #[test]
    fn contextual_filename_is_possible_not_observed() {
        let trace = trace_verdict(&verdict(vec![relationship(
            RelationshipKind::RiskBased,
            RelationshipStrength::Weak,
            "foo.exe",
            &[EvidenceRelation::ContextualFilenameMatch],
        )]));

        assert_eq!(trace.paths[0].state, TracePathState::Possible);
        assert_eq!(trace.paths[0].edges[0].assertion_orientation, AssertionOrientation::Synthetic);
    }

    #[test]
    fn ioc_detection_and_malware_family_shapes_are_directed() {
        let trace = trace_verdict(&verdict(vec![
            relationship(
                RelationshipKind::Ioc,
                RelationshipStrength::Direct,
                "abc123",
                &[EvidenceRelation::ObservedInReport],
            ),
            relationship(
                RelationshipKind::Detection,
                RelationshipStrength::Strong,
                "test_rule",
                &[EvidenceRelation::DetectsIndicator],
            ),
            relationship(
                RelationshipKind::MalwareFamily,
                RelationshipStrength::Strong,
                "TestFamily",
                &[EvidenceRelation::AttributedToMalwareFamily],
            ),
        ]));

        assert_eq!(trace.paths.len(), 3);
        let ioc = trace
            .paths
            .iter()
            .find(|path| path.target_kind == RelationshipKind::Ioc)
            .unwrap();
        assert_eq!(ioc.nodes.last().unwrap().kind, TraceNodeKind::Indicator);

        let detection = trace
            .paths
            .iter()
            .find(|path| path.target_kind == RelationshipKind::Detection)
            .unwrap();
        assert_eq!(detection.nodes.last().unwrap().kind, TraceNodeKind::Detection);
        assert_eq!(
            detection.edges.last().unwrap().assertion_orientation,
            AssertionOrientation::Reversed
        );

        let family = trace
            .paths
            .iter()
            .find(|path| path.target_kind == RelationshipKind::MalwareFamily)
            .unwrap();
        assert_eq!(family.nodes.last().unwrap().kind, TraceNodeKind::MalwareFamily);
        assert_eq!(
            family.edges.last().unwrap().assertion_orientation,
            AssertionOrientation::Native
        );
    }

    #[test]
    fn malformed_mixed_proof_is_disclosed_not_guessed() {
        let mut malformed = relationship(
            RelationshipKind::Cve,
            RelationshipStrength::Contextual,
            "CVE-2026-0003",
            &[
                EvidenceRelation::ObservedInReport,
                EvidenceRelation::ReportReferencesCve,
            ],
        );
        malformed.evidence_paths.push(vec![hop(EvidenceRelation::DetectsIndicator)]);

        let trace = trace_verdict(&verdict(vec![malformed]));
        assert!(trace.paths.is_empty());
        assert_eq!(
            trace.untraced_relationships[0].reason,
            UntracedReason::MixedProofShape
        );
    }

    #[test]
    fn missing_ioc_identity_is_not_synthesized_from_the_target() {
        let mut ioc = relationship(
            RelationshipKind::Ioc,
            RelationshipStrength::Direct,
            "abc123",
            &[EvidenceRelation::ObservedInReport],
        );
        ioc.evidence_paths[0][0].indicator_value = None;

        let trace = trace_verdict(&verdict(vec![ioc]));
        assert!(trace.paths.is_empty());
        assert_eq!(
            trace.untraced_relationships[0].reason,
            UntracedReason::MissingNodeIdentity
        );
    }

    #[test]
    fn relationship_targets_must_equal_their_proof_endpoints() {
        let ioc = relationship(
            RelationshipKind::Ioc,
            RelationshipStrength::Direct,
            "different-indicator",
            &[EvidenceRelation::ObservedInReport],
        );
        let detection = relationship(
            RelationshipKind::Detection,
            RelationshipStrength::Strong,
            "different-rule",
            &[EvidenceRelation::DetectsIndicator],
        );

        let trace = trace_verdict(&verdict(vec![ioc, detection]));
        assert!(trace.paths.is_empty());
        assert_eq!(trace.untraced_relationships.len(), 2);
        assert!(trace.untraced_relationships.iter().all(|untraced| {
            untraced.reason == UntracedReason::InconsistentProofEndpoints
        }));
    }

    #[test]
    fn shared_multi_hop_endpoints_fail_closed() {
        let mut missing_report = relationship(
            RelationshipKind::Cve,
            RelationshipStrength::Contextual,
            "CVE-2026-0010",
            &[
                EvidenceRelation::ObservedInReport,
                EvidenceRelation::ReportReferencesCve,
            ],
        );
        missing_report.evidence_paths[0][1].report_id = None;

        let mut wrong_detection = relationship(
            RelationshipKind::Cve,
            RelationshipStrength::Strong,
            "CVE-2026-0011",
            &[
                EvidenceRelation::DetectsIndicator,
                EvidenceRelation::DetectionCoversCve,
            ],
        );
        wrong_detection.evidence_paths[0][1].detection_name = Some("other_rule".to_string());

        let mut wrong_version = relationship(
            RelationshipKind::Cve,
            RelationshipStrength::Strong,
            "CVE-2026-0012",
            &[
                EvidenceRelation::DetectsIndicator,
                EvidenceRelation::DetectionCoversCve,
            ],
        );
        wrong_version.evidence_paths[0][1].rule_fingerprint = Some("rule-v2".to_string());

        let trace = trace_verdict(&verdict(vec![
            missing_report,
            wrong_detection,
            wrong_version,
        ]));
        assert!(trace.paths.is_empty());
        assert_eq!(trace.untraced_relationships.len(), 3);
        assert_eq!(
            trace.untraced_relationships[0].reason,
            UntracedReason::MissingNodeIdentity
        );
        assert_eq!(
            trace.untraced_relationships[1].reason,
            UntracedReason::InconsistentProofEndpoints
        );
        assert_eq!(
            trace.untraced_relationships[2].reason,
            UntracedReason::InconsistentProofEndpoints
        );
    }

    #[test]
    fn path_budget_gives_distinct_relationships_a_first_slot() {
        let mut noisy = relationship(
            RelationshipKind::Ioc,
            RelationshipStrength::Direct,
            "abc123",
            &[EvidenceRelation::ObservedInReport],
        );
        noisy.evidence_paths.push(vec![hop(EvidenceRelation::ObservedInReport)]);
        let second = relationship(
            RelationshipKind::RiskBased,
            RelationshipStrength::Weak,
            "foo.exe",
            &[EvidenceRelation::ContextualFilenameMatch],
        );

        let trace = trace_verdict_bounded(&verdict(vec![noisy, second]), 2);
        assert_eq!(trace.paths.len(), 2);
        assert!(trace.paths.iter().any(|path| path.relationship_index == 0));
        assert!(trace.paths.iter().any(|path| path.relationship_index == 1));
        assert!(trace.bounds.paths_truncated);
        assert_eq!(trace.bounds.omitted_paths, 1);
    }

    #[test]
    fn path_budget_selects_the_best_proof_inside_each_relationship() {
        let mut ioc = relationship(
            RelationshipKind::Ioc,
            RelationshipStrength::Direct,
            "abc123",
            &[EvidenceRelation::ObservedInReport],
        );
        ioc.evidence_paths[0][0].confidence = 10;
        let mut stronger_proof = hop(EvidenceRelation::ObservedInReport);
        stronger_proof.confidence = 95;
        ioc.evidence_paths.push(vec![stronger_proof]);

        let trace = trace_verdict_bounded(&verdict(vec![ioc]), 1);
        assert_eq!(trace.paths.len(), 1);
        assert_eq!(trace.paths[0].rank.weakest_source_confidence, 95);
        assert_eq!(trace.paths[0].supporting_proof[0].confidence, 95);
        assert!(trace.bounds.paths_truncated);
        assert_eq!(trace.bounds.omitted_paths, 1);
    }

    #[test]
    fn ranking_keeps_strength_and_confidence_as_separate_dimensions() {
        let weak = relationship(
            RelationshipKind::RiskBased,
            RelationshipStrength::Weak,
            "foo.exe",
            &[EvidenceRelation::ContextualFilenameMatch],
        );
        let mut direct = relationship(
            RelationshipKind::Ioc,
            RelationshipStrength::Direct,
            "abc123",
            &[EvidenceRelation::ObservedInReport],
        );
        direct.evidence_paths[0][0].confidence = 20;

        let trace = trace_verdict(&verdict(vec![weak, direct]));
        assert_eq!(trace.paths[0].rank.relationship_strength, RelationshipStrength::Direct);
        assert_eq!(trace.paths[0].rank.weakest_source_confidence, 20);
        assert_eq!(trace.paths[1].rank.relationship_strength, RelationshipStrength::Weak);
        assert_eq!(trace.paths[1].rank.weakest_source_confidence, 80);
    }
}
