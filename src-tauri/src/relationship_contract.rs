use anyhow::Result;
use serde::Serialize;
use sqlx::PgPool;
use std::path::Path;
use std::sync::Arc;

use crate::analysis_coverage::YaraCoverage;
use crate::bloom::{BloomState, IntelGate};
use crate::db::indicators::MAX_EVIDENCE_PER_RELATIONSHIP;
use crate::models::{
    EvidenceRelation, RelationshipKind, RelationshipStrength, ThreatRelationship, Verdict,
    VerdictTier,
};
use crate::yara_scan::YaraEngine;

// Keep the evidence resolver private behind this contract module. Round 11
// caught that the raw resolver was callable by any sibling Rust module, while
// relationship normalization and YARA coverage were only applied later at the
// Tauri command boundary. Orion/Execute are Rust-side consumers too, so the
// unsafe/raw shape must not be part of the crate-level API they can reach.
#[path = "verdict.rs"]
mod raw_verdict;

pub use raw_verdict::RecentYaraHits;

/// Authoritative RELATE-stage result for both UI and future Rust-side
/// consumers such as Orion/Execute.
///
/// `verdict` is already normalized to the stable relationship contract, and
/// `yara_coverage` travels with it so a failed ruleset can never be mistaken
/// for a healthy zero-hit scan merely because a caller bypassed Tauri IPC.
#[derive(Debug, Serialize)]
pub struct ResolvedVerdict {
    #[serde(flatten)]
    pub verdict: Verdict,
    pub yara_coverage: YaraCoverage,
    /// Orion's bounded, explicitly directed projection over the normalized
    /// RELATE result. Built here, at the authoritative Rust boundary, so the
    /// UI does not reinterpret proof direction or construct security graph
    /// semantics from prose.
    pub orion_trace: nsic_core::orion::OrionTrace,
}

/// Resolve one file into the authoritative RELATE contract.
///
/// This is intentionally the only crate-level resolver exposed outside this
/// module. The underlying evidence resolver remains private above, so a future
/// Orion implementation cannot accidentally consume assertion-shaped,
/// threshold-dependent relationships or omit runtime analysis coverage.
///
/// `RecentYaraHits` remains in `AppState` for compatibility with the frozen
/// PR #19 call shape, but persistence suppression is deliberately scoped to
/// one resolve call here. Every analyst-initiated live scan is a new observed
/// event and therefore gets a chance to advance durable `last_seen`; a
/// process-lifetime cache must not make Sustain/Retrohunt history stale.
#[allow(clippy::too_many_arguments)]
pub async fn resolve(
    pool: &PgPool,
    bloom: &BloomState,
    intel_gate: &IntelGate,
    yara: &Arc<YaraEngine>,
    yara_coverage: &YaraCoverage,
    _recent_yara_hits: &RecentYaraHits,
    path: &Path,
) -> Result<ResolvedVerdict> {
    let observation_scope = RecentYaraHits::new();
    let verdict = raw_verdict::resolve(
        pool,
        bloom,
        intel_gate,
        yara,
        &observation_scope,
        path,
    )
    .await?;

    Ok(finalize_resolved(verdict, yara_coverage))
}

fn finalize_resolved(verdict: Verdict, yara_coverage: &YaraCoverage) -> ResolvedVerdict {
    let verdict = finalize_verdict(verdict);
    let orion_trace = nsic_core::orion::trace_verdict(&verdict);
    ResolvedVerdict {
        verdict,
        yara_coverage: yara_coverage.clone(),
        orion_trace,
    }
}

/// Finalizes the stable RELATE relationship contract.
///
/// The lower-level relationship queries intentionally preserve assertion
/// provenance, and some have a concept-aware high-cardinality fallback. A
/// Round-10 review caught that returning those raw query objects directly
/// made the *meaning of one `ThreatRelationship`* change when cardinality
/// crossed the safety cap: below the cap an object represented one assertion,
/// while above it the fallback represented one concept with several evidence
/// paths. Orion/Execute cannot safely consume a threshold-dependent object.
///
/// The contract is therefore normalized here at every cardinality: one
/// `(kind, target, strength, evidence-proof shape)` object represents one
/// relationship concept reached by one evidence mechanism/strength class,
/// and every supporting assertion is carried as a separately inspectable
/// proof path (bounded separately). These are **supporting provenance chains**,
/// not directed Orion traversal paths: relation names retain the native
/// assertion direction of the underlying evidence graph, and TRACE will own
/// explicit traversal direction/endpoints. The proof shape remains part of
/// identity so materially different evidence mechanisms do not collapse.
pub fn finalize_verdict(mut verdict: Verdict) -> Verdict {
    let contextual_truncated = verdict
        .bounds
        .truncated_entry_tiers
        .contains(&VerdictTier::Contextual);

    // Contextual filename lookup is case-insensitive in Postgres, so its
    // concept identity must be case-insensitive here too. Preserve each
    // source's original spelling in the verdict provenance entries, but use a
    // canonical lowercase target for RELATE so `FOO.EXE` and `foo.exe` cannot
    // become separate concepts merely because different reports used
    // different casing. Canonicalize *before* coalescing/bounds propagation.
    for relationship in &mut verdict.threat_relationships {
        if is_contextual_filename_relationship(relationship) {
            relationship.target = relationship.target.to_lowercase();
        }
    }

    verdict.threat_relationships = coalesce_relationships(verdict.threat_relationships);

    // Contextual has a 20-row source cap and the relationship layer has a
    // separate 20-path cap. When row 21 exists, the raw derivation can still
    // hand exactly 20 paths to the coalescer; cardinality alone therefore
    // cannot tell the relationship it is partial. The verdict-level bound is
    // the authoritative fact that more contextual observations existed. Since
    // contextual identity is canonicalized above using the same
    // case-insensitive semantics as the producer, that partiality can now be
    // attached to the correct concept rather than to a casing-dependent row.
    if contextual_truncated {
        for relationship in &mut verdict.threat_relationships {
            if is_contextual_filename_relationship(relationship) {
                relationship.has_more_evidence = true;
            }
        }
    }

    verdict
}

fn is_contextual_filename_relationship(relationship: &ThreatRelationship) -> bool {
    relationship.kind == RelationshipKind::RiskBased
        && relationship.strength == RelationshipStrength::Weak
        && proof_shape(relationship) == Some(vec![EvidenceRelation::ContextualFilenameMatch])
}

pub fn coalesce_relationships(
    relationships: Vec<ThreatRelationship>,
) -> Vec<ThreatRelationship> {
    let evidence_limit = MAX_EVIDENCE_PER_RELATIONSHIP.max(0) as usize;
    let mut normalized: Vec<ThreatRelationship> = Vec::new();

    for mut relationship in relationships {
        if relationship.evidence_paths.len() > evidence_limit {
            relationship.evidence_paths.truncate(evidence_limit);
            relationship.has_more_evidence = true;
        }

        if let Some(existing) = normalized
            .iter_mut()
            .find(|candidate| same_semantic_relationship(candidate, &relationship))
        {
            let incoming_has_more = relationship.has_more_evidence;
            for path in relationship.evidence_paths {
                if existing.evidence_paths.len() < evidence_limit {
                    existing.evidence_paths.push(path);
                } else {
                    existing.has_more_evidence = true;
                }
            }
            existing.has_more_evidence |= incoming_has_more;

            // The normal detection->CVE query historically produced one
            // object per coverage assertion, whose explanation named that
            // one rule. Once those assertions are normalized into the stable
            // concept-level wire shape, the prose must not imply only the
            // first rule supports the relationship. The proof paths retain
            // the exact rule identities for inspection and future machine use.
            if existing.kind == RelationshipKind::Cve
                && existing.strength == RelationshipStrength::Strong
                && proof_shape(existing)
                    == Some(vec![
                        EvidenceRelation::DetectsIndicator,
                        EvidenceRelation::DetectionCoversCve,
                    ])
            {
                existing.explanation =
                    "One or more local detections that matched this exact file in the current scan are documented to cover this CVE -- inspect the supporting evidence paths for the rules, assess exposure, and hunt for exploitation evidence."
                        .to_string();
            }
        } else {
            normalized.push(relationship);
        }
    }

    normalized
}

fn same_semantic_relationship(left: &ThreatRelationship, right: &ThreatRelationship) -> bool {
    if left.kind != right.kind || left.target != right.target || left.strength != right.strength {
        return false;
    }

    // A malformed relationship whose paths do not all share one typed proof
    // shape must never coalesce merely because *another* malformed object also
    // returns `None`. Failing conservative preserves evidence rather than
    // silently merging structures Orion cannot safely interpret.
    match (proof_shape(left), proof_shape(right)) {
        (Some(left_shape), Some(right_shape)) => left_shape == right_shape,
        _ => false,
    }
}

/// The relation sequence of one complete supporting proof is the
/// relationship's evidence-mechanism identity. This function does **not**
/// describe directed Orion traversal: relations keep their native assertion
/// semantics (for example `DetectsIndicator` is Detection -> Indicator even
/// when it supports a file-to-Detection relationship). TRACE must construct
/// directed graph hops explicitly rather than infer hidden reversals here.
fn proof_shape(relationship: &ThreatRelationship) -> Option<Vec<EvidenceRelation>> {
    let first = relationship.evidence_paths.first()?;
    let shape: Vec<EvidenceRelation> = first.iter().map(|hop| hop.relation).collect();
    if relationship.evidence_paths.iter().all(|path| {
        path.len() == shape.len()
            && path
                .iter()
                .zip(shape.iter())
                .all(|(hop, relation)| hop.relation == *relation)
    }) {
        Some(shape)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    use crate::analysis_coverage::{YaraCoverage, YaraCoverageState};
    use crate::models::{EvidenceTiming, IndicatorKind, RelationshipEvidence, VerdictBounds};

    fn evidence(source: &str, relation: EvidenceRelation) -> Vec<RelationshipEvidence> {
        let now = Utc::now();
        vec![RelationshipEvidence {
            relation,
            source: source.to_string(),
            confidence: 70,
            first_seen: now,
            last_seen: now,
            report_id: None,
            report_title: None,
            report_url: None,
            indicator_kind: Some(IndicatorKind::Sha256),
            indicator_value: Some(format!("hash-{source}")),
            detection_name: None,
            rule_fingerprint: None,
            timing: EvidenceTiming::Observed,
        }]
    }

    fn relationship(
        target: &str,
        strength: RelationshipStrength,
        source: &str,
        relation: EvidenceRelation,
    ) -> ThreatRelationship {
        ThreatRelationship {
            kind: RelationshipKind::Cve,
            strength,
            target: target.to_string(),
            explanation: format!("assertion from {source}"),
            evidence_paths: vec![evidence(source, relation)],
            has_more_evidence: false,
        }
    }

    fn contextual_relationship(target: &str, source: &str) -> ThreatRelationship {
        ThreatRelationship {
            kind: RelationshipKind::RiskBased,
            strength: RelationshipStrength::Weak,
            target: target.to_string(),
            explanation: "contextual filename match".to_string(),
            evidence_paths: vec![evidence(source, EvidenceRelation::ContextualFilenameMatch)],
            has_more_evidence: false,
        }
    }

    fn empty_verdict(relationships: Vec<ThreatRelationship>, bounds: VerdictBounds) -> Verdict {
        Verdict {
            path: "/tmp/round-12".to_string(),
            sha256: "a".repeat(64),
            md5: "b".repeat(32),
            entries: vec![],
            intel_freshness: vec![],
            threat_relationships: relationships,
            bounds,
        }
    }

    #[test]
    fn normal_cardinality_assertions_emit_one_stable_concept_object() {
        let normalized = coalesce_relationships(vec![
            relationship(
                "CVE-2099-0001",
                RelationshipStrength::Contextual,
                "report-a",
                EvidenceRelation::ObservedInReport,
            ),
            relationship(
                "CVE-2099-0001",
                RelationshipStrength::Contextual,
                "report-b",
                EvidenceRelation::ObservedInReport,
            ),
        ]);

        assert_eq!(normalized.len(), 1);
        assert_eq!(normalized[0].target, "CVE-2099-0001");
        assert_eq!(normalized[0].evidence_paths.len(), 2);
        assert!(!normalized[0].has_more_evidence);
    }

    #[test]
    fn pregrouped_fallback_and_normal_path_have_the_same_object_semantics() {
        let mut grouped = relationship(
            "CVE-2099-0002",
            RelationshipStrength::Contextual,
            "report-a",
            EvidenceRelation::ObservedInReport,
        );
        grouped
            .evidence_paths
            .push(evidence("report-b", EvidenceRelation::ObservedInReport));

        let from_grouped = coalesce_relationships(vec![grouped]);
        let from_assertions = coalesce_relationships(vec![
            relationship(
                "CVE-2099-0002",
                RelationshipStrength::Contextual,
                "report-a",
                EvidenceRelation::ObservedInReport,
            ),
            relationship(
                "CVE-2099-0002",
                RelationshipStrength::Contextual,
                "report-b",
                EvidenceRelation::ObservedInReport,
            ),
        ]);

        assert_eq!(from_grouped.len(), 1);
        assert_eq!(from_assertions.len(), 1);
        assert_eq!(
            from_grouped[0].evidence_paths.len(),
            from_assertions[0].evidence_paths.len()
        );
        assert_eq!(from_grouped[0].target, from_assertions[0].target);
        assert_eq!(from_grouped[0].strength, from_assertions[0].strength);
    }

    #[test]
    fn evidence_budget_is_consistent_when_many_assertions_coalesce() {
        let limit = MAX_EVIDENCE_PER_RELATIONSHIP as usize;
        let relationships = (0..(limit + 3))
            .map(|n| {
                relationship(
                    "CVE-2099-0003",
                    RelationshipStrength::Contextual,
                    &format!("report-{n}"),
                    EvidenceRelation::ObservedInReport,
                )
            })
            .collect();

        let normalized = coalesce_relationships(relationships);
        assert_eq!(normalized.len(), 1);
        assert_eq!(normalized[0].evidence_paths.len(), limit);
        assert!(normalized[0].has_more_evidence);
    }

    #[test]
    fn materially_different_strength_routes_are_not_collapsed() {
        let normalized = coalesce_relationships(vec![
            relationship(
                "CVE-2099-0004",
                RelationshipStrength::Contextual,
                "report",
                EvidenceRelation::ObservedInReport,
            ),
            relationship(
                "CVE-2099-0004",
                RelationshipStrength::Strong,
                "detection",
                EvidenceRelation::DetectionCoversCve,
            ),
        ]);

        assert_eq!(normalized.len(), 2);
        assert!(normalized
            .iter()
            .any(|r| r.strength == RelationshipStrength::Contextual));
        assert!(normalized
            .iter()
            .any(|r| r.strength == RelationshipStrength::Strong));
    }

    #[test]
    fn different_evidence_mechanisms_with_same_strength_are_not_collapsed() {
        let normalized = coalesce_relationships(vec![
            relationship(
                "CVE-2099-0005",
                RelationshipStrength::Strong,
                "mechanism-a",
                EvidenceRelation::ObservedInReport,
            ),
            relationship(
                "CVE-2099-0005",
                RelationshipStrength::Strong,
                "mechanism-b",
                EvidenceRelation::DetectionCoversCve,
            ),
        ]);

        assert_eq!(normalized.len(), 2);
    }

    #[test]
    fn malformed_mixed_route_objects_fail_conservative_instead_of_coalescing() {
        let mut left = relationship(
            "CVE-2099-0006",
            RelationshipStrength::Strong,
            "left-a",
            EvidenceRelation::ObservedInReport,
        );
        left.evidence_paths
            .push(evidence("left-b", EvidenceRelation::DetectionCoversCve));

        let mut right = relationship(
            "CVE-2099-0006",
            RelationshipStrength::Strong,
            "right-a",
            EvidenceRelation::ObservedInReport,
        );
        right
            .evidence_paths
            .push(evidence("right-b", EvidenceRelation::DetectionCoversCve));

        assert_eq!(proof_shape(&left), None);
        assert_eq!(proof_shape(&right), None);

        let normalized = coalesce_relationships(vec![left, right]);
        assert_eq!(normalized.len(), 2);
    }

    #[test]
    fn contextual_row_truncation_marks_the_coalesced_relationship_partial() {
        let limit = MAX_EVIDENCE_PER_RELATIONSHIP as usize;
        let relationships = (0..limit)
            .map(|n| contextual_relationship("shared-sample-name.exe", &format!("report-{n}")))
            .collect();

        let verdict = empty_verdict(
            relationships,
            VerdictBounds {
                truncated_entry_tiers: vec![VerdictTier::Contextual],
                relationships_truncated: false,
            },
        );

        let finalized = finalize_verdict(verdict);
        assert_eq!(finalized.threat_relationships.len(), 1);
        assert_eq!(finalized.threat_relationships[0].evidence_paths.len(), limit);
        assert!(
            finalized.threat_relationships[0].has_more_evidence,
            "row 21 is known to exist from VerdictBounds, so the coalesced contextual relationship must not claim exhaustive evidence"
        );
    }

    #[test]
    fn mixed_case_contextual_targets_share_one_canonical_bounded_concept() {
        let limit = MAX_EVIDENCE_PER_RELATIONSHIP as usize;
        let mut relationships = Vec::with_capacity(limit);
        for n in 0..limit {
            let target = if n % 2 == 0 { "FOO.EXE" } else { "foo.exe" };
            relationships.push(contextual_relationship(target, &format!("report-{n}")));
        }

        let verdict = empty_verdict(
            relationships,
            VerdictBounds {
                truncated_entry_tiers: vec![VerdictTier::Contextual],
                relationships_truncated: false,
            },
        );

        let finalized = finalize_verdict(verdict);
        assert_eq!(finalized.threat_relationships.len(), 1);
        assert_eq!(finalized.threat_relationships[0].target, "foo.exe");
        assert_eq!(finalized.threat_relationships[0].evidence_paths.len(), limit);
        assert!(finalized.threat_relationships[0].has_more_evidence);
        assert!(!finalized.bounds.relationships_truncated);
    }

    #[test]
    fn authoritative_result_carries_relate_yara_and_orion_contracts_together() {
        let relationships = vec![
            relationship(
                "CVE-2099-0011",
                RelationshipStrength::Contextual,
                "report-a",
                EvidenceRelation::ObservedInReport,
            ),
            relationship(
                "CVE-2099-0011",
                RelationshipStrength::Contextual,
                "report-b",
                EvidenceRelation::ObservedInReport,
            ),
        ];
        let coverage = YaraCoverage {
            status: YaraCoverageState::Failed,
            rule_count: 0,
            failure_reason: Some("rejected ruleset".to_string()),
        };

        let resolved = finalize_resolved(
            empty_verdict(relationships, VerdictBounds::default()),
            &coverage,
        );

        assert_eq!(resolved.verdict.threat_relationships.len(), 1);
        assert_eq!(resolved.verdict.threat_relationships[0].evidence_paths.len(), 2);
        assert_eq!(resolved.yara_coverage, coverage);
        // This deliberately incomplete CVE proof shape is normalized by
        // RELATE but not safe to direct. Orion travels with the same result
        // and refuses to guess rather than silently dropping the concept.
        assert!(resolved.orion_trace.paths.is_empty());
        assert_eq!(resolved.orion_trace.untraced_relationships.len(), 1);
    }
}
