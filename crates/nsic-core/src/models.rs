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
}

/// How current the local copy of one intel feed is, as of the moment a
/// verdict was resolved. `None` means this source has never completed a
/// sync -- `feed_sync_state` only gains a row for a source once
/// `ingest::run_all`'s per-feed sync function returns `Ok`, so a source
/// that has only ever failed (bad API key, network error, upstream schema
/// change) has no row at all, not a stale one. `last_successful_sync_at`
/// is deliberately named around "successful": a feed that has been
/// silently failing (an expired abuse.ch auth key returning 401 on every
/// attempt, say) must not read as freshly synced just because an attempt
/// was made -- see `ingest::mod::run_all`'s doc comment on why a failed
/// sync is reported as an error rather than swallowed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntelSourceFreshness {
    pub source: String,
    pub last_successful_sync_at: Option<DateTime<Utc>>,
}

/// The full verdict for a file: every piece of evidence found, sorted
/// strongest tier first. No boolean "bad"/"clean" collapse happens here.
///
/// `entries` being empty means no configured intel source or local rule
/// currently flags this file -- it does not mean the file is clean. Prior
/// to `intel_freshness`, that distinction only existed as hedging prose in
/// the UI; an empty `entries` produced against an intel corpus that hasn't
/// synced in 11 days looked byte-for-byte identical to one produced
/// against a corpus that synced 18 minutes ago. `intel_freshness` carries
/// one entry per known feed (see `IntelSourceFreshness`) so the UI can
/// show, not just say, what the absence of a match is actually backed by
/// -- the same problem `nsic_core`'s Phase 1 sensor-health work solved for
/// "no sightings from this host" vs. "this host never scanned."
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verdict {
    pub path: String,
    pub sha256: String,
    pub md5: String,
    pub entries: Vec<ProvenanceEntry>,
    pub intel_freshness: Vec<IntelSourceFreshness>,
    pub threat_relationships: Vec<ThreatRelationship>,
}

// ---------------------------------------------------------------------
// Threat Relationship Intelligence (Apollo Constitution §6)
// ---------------------------------------------------------------------

/// The category of security concept a file is related to. Deliberately
/// includes categories with no populated data path yet (`AttackTechnique`)
/// -- this is the same "declare the vocabulary, implement what has a real
/// source" precedent `DetectionKind::Sigma` already sets in this codebase
/// (no Sigma ingestion exists either, but the kind is real and complete).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationshipKind {
    Ioc,
    Cve,
    ThreatActor,
    Campaign,
    MalwareFamily,
    AttackTechnique,
    Detection,
    RiskBased,
}

/// Apollo Constitution §6, Open·3 ("Relationship strength"): an explicit
/// vocabulary for direct evidence, strong association, contextual support,
/// and weak association, so "related to" cannot flatten into an unbounded
/// graph of technically-true but operationally-useless connections.
///
/// Deliberately derived from the relationship's *evidence mechanism* --
/// which tier or edge established it, i.e. how directly it connects this
/// exact file to the target -- never from `confidence`. A first version of
/// this banded `strength` straight off `confidence`, which a review
/// correctly rejected: those are orthogonal. `confidence` is how much the
/// *sourcing feed* trusts its own data; `strength` is what *kind* of
/// evidence path connects file to concept. A 50%-confidence exact hash
/// match is still direct evidence (the match itself is unambiguous, only
/// the source's trust in its own data is middling); a 95%-confidence
/// filename-only match is still contextual (no amount of source confidence
/// turns "same filename" into "same file"). Every construction site below
/// sets `strength` as a literal for exactly this reason -- it is a
/// property of *which code path* produced the relationship, not a
/// computed function of any one field on it.
///
/// This is a first concrete implementation of Open·3, not a final answer
/// to it -- the Constitution marks the underlying question open, and this
/// ships something to test against rather than leaving the vocabulary
/// undefined.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationshipStrength {
    Weak,
    Contextual,
    Strong,
    Direct,
}

/// One hop of evidence supporting a `ThreatRelationship`. Postgres stores
/// provenance per *edge*, not per relationship -- a single-hop relationship
/// (`Ioc`, `Detection`, `RiskBased`, `MalwareFamily`) carries exactly one of
/// these, but a CVE relationship carries the full chain it was inferred
/// through (e.g. the `indicator_observed_in_report` hop *and* the
/// `report_references_cve` hop), each with its own source/confidence/
/// timestamps. A review caught an earlier version of this collapsing a
/// two-hop CVE inference down to a single flat source/confidence -- either
/// by copying the wrong edge's values entirely, or, once that was fixed, by
/// keeping only the last hop's values and silently discarding the first
/// hop's evidence. `target` and `explanation` on `ThreatRelationship` stay
/// single per relationship (there's still exactly one concept a file is
/// related to); `evidence` is what carries the possibly-multi-hop path that
/// established it, ordered from the file outward, so PR #20's Hunt engine
/// can walk the actual chain instead of parsing `explanation` prose to find
/// the supporting report or detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelationshipEvidence {
    /// What this hop's edge asserts, named after the edge table it comes
    /// from (`observed_in_report`, `report_references_cve`,
    /// `detects_indicator`, `detection_covers_cve`,
    /// `attributed_to_malware_family`, or `contextual_filename_match` for
    /// the one tier with no backing edge table) so a hop is traceable to
    /// its exact source, not just prose.
    pub relation: String,
    pub source: String,
    pub confidence: i16,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub report_id: Option<Uuid>,
    pub report_title: Option<String>,
    pub report_url: Option<String>,
    pub detection_name: Option<String>,
}

/// A single structured relationship between a file and a threat concept --
/// the RELATE-stage object the Apollo Constitution's §6 calls for, distinct
/// from `ProvenanceEntry`'s verdict-tier framing ("why did this file get
/// flagged"). `ThreatRelationship` answers a different question: "what
/// threat concept is this file connected to, how strongly, and what would
/// a hunt on it look for" -- `explanation` exists specifically to carry
/// that last part, since a relationship without a stated reason is exactly
/// the kind of technically-true-but-useless connection Open·3 warns about.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatRelationship {
    pub kind: RelationshipKind,
    pub strength: RelationshipStrength,
    /// The related concept itself: a malware family name, a CVE ID, an
    /// indicator value -- whatever `kind` identifies.
    pub target: String,
    pub explanation: String,
    /// See `RelationshipEvidence`'s doc comment -- one item for a
    /// single-hop relationship, the full chain for a multi-hop one. Never
    /// empty: every relationship exists because at least one edge asserted
    /// it.
    pub evidence: Vec<RelationshipEvidence>,
}

/// Derives the structured relationship view from a verdict's existing
/// provenance entries -- pure and DB-free, since every fact it needs
/// (tier, confidence, matched value, provenance) already lives on
/// `ProvenanceEntry`. Kept separate from `ThreatRelationship`s that come
/// from a dedicated relationship query (malware-family attribution, CVE
/// relationships -- both have their own edge tables with their own
/// provenance and are not derivable from provenance entries alone) --
/// callers combine both.
///
/// Each tier maps to relationship kinds by evidence *mechanism*, not
/// uniformly: a review caught a previous version of this function wrapping
/// every provenance entry in an IOC relationship regardless of tier, which
/// misrepresented a YARA rule firing (pattern-match evidence, not an
/// indicator-table lookup) and a filename-only contextual hit (never
/// touched the indicator table at all) as if they were known indicators.
/// `ExactHash`/`FuzzyHash`/`PathPattern` are genuine indicator-table
/// lookups (the Constitution's own IOC examples explicitly include path
/// indicators), so those three still produce an `Ioc` relationship;
/// `YaraHit` produces `Detection` only, and `Contextual` produces
/// `RiskBased` only. CVE relationships are never derived from a
/// `ProvenanceEntry` at all -- `ProvenanceEntry` no longer carries CVE IDs
/// in the first place (a review caught that field flattening the CVE
/// edge's own provenance into the parent indicator/detection edge's, and
/// the analyst UI rendering both, telling two conflicting stories about
/// the same CVE); see `db::indicators::cve_matches_via_report` /
/// `cve_matches_via_detection` for the dedicated, provenance-correct
/// source.
pub fn derive_relationships(entries: &[ProvenanceEntry]) -> Vec<ThreatRelationship> {
    let mut relationships = Vec::new();

    for entry in entries {
        let single_hop = |relation: &str| {
            vec![RelationshipEvidence {
                relation: relation.to_string(),
                source: entry.source.clone(),
                confidence: entry.confidence,
                first_seen: entry.first_seen,
                last_seen: entry.last_seen,
                report_id: entry.report_id,
                report_title: entry.report_title.clone(),
                report_url: entry.report_url.clone(),
                detection_name: entry.detection_name.clone(),
            }]
        };

        match entry.tier {
            VerdictTier::ExactHash => {
                relationships.push(ThreatRelationship {
                    kind: RelationshipKind::Ioc,
                    strength: RelationshipStrength::Direct,
                    target: entry.matched_value.clone(),
                    explanation:
                        "Exact hash match against a known indicator -- find other hosts or paths \
                         where this same indicator has been observed."
                            .to_string(),
                    evidence: single_hop("observed_in_report"),
                });
            }
            VerdictTier::FuzzyHash => {
                relationships.push(ThreatRelationship {
                    kind: RelationshipKind::Ioc,
                    strength: RelationshipStrength::Strong,
                    target: entry.matched_value.clone(),
                    explanation:
                        "Fuzzy hash similarity to a known indicator -- a close but non-exact \
                         match worth corroborating with other evidence."
                            .to_string(),
                    evidence: single_hop("observed_in_report"),
                });
            }
            VerdictTier::YaraHit => {
                if let Some(detection_name) = &entry.detection_name {
                    relationships.push(ThreatRelationship {
                        kind: RelationshipKind::Detection,
                        strength: RelationshipStrength::Direct,
                        target: detection_name.clone(),
                        explanation:
                            "A local YARA rule fired against this exact file -- run the rule or \
                             trace its logic to see exactly what it matched on."
                                .to_string(),
                        evidence: single_hop("detects_indicator"),
                    });
                }
            }
            VerdictTier::PathPattern => {
                relationships.push(ThreatRelationship {
                    kind: RelationshipKind::Ioc,
                    strength: RelationshipStrength::Contextual,
                    target: entry.matched_value.clone(),
                    explanation:
                        "Path or naming pattern matched a known indicator -- weaker than a \
                         content match, worth checking alongside other evidence."
                            .to_string(),
                    evidence: single_hop("observed_in_report"),
                });
                relationships.push(ThreatRelationship {
                    kind: RelationshipKind::RiskBased,
                    strength: RelationshipStrength::Contextual,
                    target: entry.matched_value.clone(),
                    explanation:
                        "Location or naming association only, not a content match -- expand the \
                         contextual hunt without treating this as direct compromise evidence."
                            .to_string(),
                    evidence: single_hop("observed_in_report"),
                });
            }
            VerdictTier::Contextual => {
                relationships.push(ThreatRelationship {
                    kind: RelationshipKind::RiskBased,
                    strength: RelationshipStrength::Weak,
                    target: entry.matched_value.clone(),
                    explanation:
                        "Filename matches a known sample name with no hash or rule match -- never \
                         passed through the indicator table, so this is not itself a known IOC. \
                         The weakest signal here; corroborate before treating this as meaningful."
                            .to_string(),
                    evidence: single_hop("contextual_filename_match"),
                });
            }
        }
    }

    relationships
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(tier: VerdictTier, confidence: i16) -> ProvenanceEntry {
        let now = Utc::now();
        ProvenanceEntry {
            tier,
            source: "test-source".to_string(),
            confidence,
            first_seen: now,
            last_seen: now,
            report_id: None,
            report_title: None,
            report_url: None,
            detection_name: Some("Test_Rule".to_string()),
            matched_value: "deadbeef".to_string(),
        }
    }

    #[test]
    fn strength_is_totally_ordered_weak_to_direct() {
        assert!(RelationshipStrength::Weak < RelationshipStrength::Contextual);
        assert!(RelationshipStrength::Contextual < RelationshipStrength::Strong);
        assert!(RelationshipStrength::Strong < RelationshipStrength::Direct);
    }

    // ---- derive_relationships ----
    //
    // A review's merge-blocking finding: a previous version of this
    // function wrapped every provenance entry in an IOC relationship
    // regardless of tier, which misrepresented a YARA rule firing (pattern
    // evidence, not an indicator-table lookup) and a filename-only
    // contextual hit (never touched the indicator table) as if they were
    // known indicators. The tests below specifically assert the *absence*
    // of an IOC relationship for those two tiers, not just the presence of
    // the right one, since that's the exact defect a passing-but-
    // insufficiently-specific test could hide again.

    #[test]
    fn exact_hash_entry_becomes_a_direct_ioc_relationship() {
        let entries = vec![entry(VerdictTier::ExactHash, 90)];
        let relationships = derive_relationships(&entries);
        assert_eq!(relationships.len(), 1);
        assert_eq!(relationships[0].kind, RelationshipKind::Ioc);
        assert_eq!(relationships[0].strength, RelationshipStrength::Direct);
        assert_eq!(relationships[0].target, "deadbeef");
    }

    #[test]
    fn fuzzy_hash_entry_becomes_a_strong_ioc_relationship() {
        let entries = vec![entry(VerdictTier::FuzzyHash, 70)];
        let relationships = derive_relationships(&entries);
        assert_eq!(relationships.len(), 1);
        assert_eq!(relationships[0].kind, RelationshipKind::Ioc);
        assert_eq!(relationships[0].strength, RelationshipStrength::Strong);
    }

    #[test]
    fn yara_hit_becomes_a_detection_relationship_only_not_an_ioc() {
        let entries = vec![entry(VerdictTier::YaraHit, 65)];
        let relationships = derive_relationships(&entries);
        assert_eq!(
            relationships.len(),
            1,
            "a YARA rule firing is pattern-match evidence, not an indicator-table lookup, and \
             must not also produce an IOC relationship: {relationships:?}"
        );
        assert_eq!(relationships[0].kind, RelationshipKind::Detection);
        assert_eq!(relationships[0].strength, RelationshipStrength::Direct);
        assert_eq!(relationships[0].target, "Test_Rule");
    }

    #[test]
    fn path_pattern_becomes_both_an_ioc_and_a_risk_based_relationship() {
        // Path indicators are a genuine indicator-table lookup (the
        // Constitution's own IOC examples explicitly include path
        // indicators), so PathPattern is the one tier that legitimately
        // produces both.
        let entries = vec![entry(VerdictTier::PathPattern, 50)];
        let relationships = derive_relationships(&entries);
        assert_eq!(relationships.len(), 2);
        let ioc = relationships
            .iter()
            .find(|r| r.kind == RelationshipKind::Ioc)
            .expect("expected an Ioc relationship for PathPattern");
        assert_eq!(ioc.strength, RelationshipStrength::Contextual);
        let risk = relationships
            .iter()
            .find(|r| r.kind == RelationshipKind::RiskBased)
            .expect("expected a RiskBased relationship for PathPattern");
        assert_eq!(risk.strength, RelationshipStrength::Contextual);
    }

    #[test]
    fn contextual_becomes_a_risk_based_relationship_only_not_an_ioc() {
        let entries = vec![entry(VerdictTier::Contextual, 25)];
        let relationships = derive_relationships(&entries);
        assert_eq!(
            relationships.len(),
            1,
            "a filename-only contextual match never touched the indicator table and must not \
             also produce an IOC relationship: {relationships:?}"
        );
        assert_eq!(relationships[0].kind, RelationshipKind::RiskBased);
        assert_eq!(relationships[0].strength, RelationshipStrength::Weak);
    }

    #[test]
    fn strength_does_not_track_confidence() {
        // The other merge-blocking finding: strength must come from the
        // evidence mechanism, not the source's confidence number. A
        // low-confidence exact match is still Direct; a high-confidence
        // contextual match is still Weak.
        let low_confidence_exact = vec![entry(VerdictTier::ExactHash, 10)];
        assert_eq!(
            derive_relationships(&low_confidence_exact)[0].strength,
            RelationshipStrength::Direct
        );

        let high_confidence_contextual = vec![entry(VerdictTier::Contextual, 99)];
        assert_eq!(
            derive_relationships(&high_confidence_contextual)[0].strength,
            RelationshipStrength::Weak
        );
    }

    #[test]
    fn single_hop_relationships_carry_exactly_one_evidence_item() {
        // A review's finding: a relationship's `evidence` chain must
        // preserve every hop that established it, not collapse to a flat
        // source/confidence -- single-hop tiers (everything derive_relationships
        // produces) still carry exactly one, named after the edge it came
        // from, and pure-derived relationships are entirely defined by
        // it, not a mix of stale flat fields.
        let entries = vec![entry(VerdictTier::ExactHash, 90)];
        let relationships = derive_relationships(&entries);
        assert_eq!(relationships[0].evidence.len(), 1);
        assert_eq!(relationships[0].evidence[0].relation, "observed_in_report");
        assert_eq!(relationships[0].evidence[0].source, "test-source");
        assert_eq!(relationships[0].evidence[0].confidence, 90);
    }

    #[test]
    fn no_entries_means_no_relationships() {
        assert!(derive_relationships(&[]).is_empty());
    }
}
