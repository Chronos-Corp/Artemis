use crate::db::indicators::MAX_EVIDENCE_PER_RELATIONSHIP;
use crate::models::{RelationshipKind, RelationshipStrength, ThreatRelationship, Verdict};

/// Finalizes the analyst-facing RELATE contract before it crosses Tauri IPC.
///
/// The lower-level relationship queries intentionally preserve assertion
/// provenance, and some have a concept-aware high-cardinality fallback. A
/// Round-10 review caught that returning those raw query objects directly
/// made the *meaning of one `ThreatRelationship`* change when cardinality
/// crossed the safety cap: below the cap an object represented one assertion,
/// while above it the fallback represented one concept with several evidence
/// paths. Orion/Execute cannot safely consume a threshold-dependent object.
///
/// The wire contract is therefore normalized here at every cardinality:
/// one `(kind, target, strength)` object represents one relationship concept
/// reached by one evidence mechanism/strength class, and every supporting
/// assertion is carried as an independently-walkable evidence path (bounded
/// separately). Strong and contextual routes to the same target remain
/// separate because they make materially different evidentiary claims.
pub fn finalize_verdict(mut verdict: Verdict) -> Verdict {
    verdict.threat_relationships = coalesce_relationships(verdict.threat_relationships);
    verdict
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

        if let Some(existing) = normalized.iter_mut().find(|candidate| {
            candidate.kind == relationship.kind
                && candidate.target == relationship.target
                && candidate.strength == relationship.strength
        }) {
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
            // first rule supports the relationship. The evidence paths retain
            // the exact rule identities for inspection and machine use.
            if existing.kind == RelationshipKind::Cve
                && existing.strength == RelationshipStrength::Strong
            {
                existing.explanation =
                    "One or more local detections that matched this exact file in the current scan are documented to cover this CVE -- inspect the evidence paths for the supporting rules, assess exposure, and hunt for exploitation evidence."
                        .to_string();
            }
        } else {
            normalized.push(relationship);
        }
    }

    normalized
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    use crate::models::{
        EvidenceRelation, EvidenceTiming, IndicatorKind, RelationshipEvidence,
    };

    fn evidence(source: &str) -> Vec<RelationshipEvidence> {
        let now = Utc::now();
        vec![RelationshipEvidence {
            relation: EvidenceRelation::ObservedInReport,
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
    ) -> ThreatRelationship {
        ThreatRelationship {
            kind: RelationshipKind::Cve,
            strength,
            target: target.to_string(),
            explanation: format!("assertion from {source}"),
            evidence_paths: vec![evidence(source)],
            has_more_evidence: false,
        }
    }

    #[test]
    fn normal_cardinality_assertions_emit_one_stable_concept_object() {
        let normalized = coalesce_relationships(vec![
            relationship("CVE-2099-0001", RelationshipStrength::Contextual, "report-a"),
            relationship("CVE-2099-0001", RelationshipStrength::Contextual, "report-b"),
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
        );
        grouped.evidence_paths.push(evidence("report-b"));

        let from_grouped = coalesce_relationships(vec![grouped]);
        let from_assertions = coalesce_relationships(vec![
            relationship("CVE-2099-0002", RelationshipStrength::Contextual, "report-a"),
            relationship("CVE-2099-0002", RelationshipStrength::Contextual, "report-b"),
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
            relationship("CVE-2099-0004", RelationshipStrength::Contextual, "report"),
            relationship("CVE-2099-0004", RelationshipStrength::Strong, "detection"),
        ]);

        assert_eq!(normalized.len(), 2);
        assert!(normalized
            .iter()
            .any(|r| r.strength == RelationshipStrength::Contextual));
        assert!(normalized
            .iter()
            .any(|r| r.strength == RelationshipStrength::Strong));
    }
}