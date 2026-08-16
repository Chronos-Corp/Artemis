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
/// This is a first concrete implementation of that still-open question
/// (see `derive_strength`), not a final answer to it -- the Constitution
/// marks the underlying question open, and this ships something to test
/// against rather than leaving the vocabulary undefined.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationshipStrength {
    Weak,
    Contextual,
    Strong,
    Direct,
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
    pub source: String,
    pub confidence: i16,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub report_id: Option<Uuid>,
    pub report_title: Option<String>,
    pub report_url: Option<String>,
}

/// Maps a confidence score to a `RelationshipStrength` band. The exact
/// thresholds are drawn from confidence values already in real use across
/// this codebase, not arbitrary: MalwareBazaar's curated-feed confidence is
/// 90 (`ingest::malwarebazaar::CONFIDENCE`), a live local YARA hit is
/// recorded at 65 (`verdict::record_yara_hit`), and the weakest existing
/// tier -- filename-only contextual association -- is hardcoded at 25
/// (`db::indicators::contextual_matches`). The bands are drawn to keep each
/// of those three real values in the band its own tier already implies
/// (Direct/Strong/Weak respectively), with `Contextual` filling the gap
/// between "a real detection fired" and "genuinely weak association."
///
/// This is a HYPOTHESIS-level answer to Open·3, not a locked one: the
/// Constitution's own framing calls for testing analyst precision/recall
/// expectations against real use before treating any specific banding as
/// settled.
pub fn derive_strength(confidence: i16) -> RelationshipStrength {
    match confidence {
        85..=100 => RelationshipStrength::Direct,
        60..=84 => RelationshipStrength::Strong,
        35..=59 => RelationshipStrength::Contextual,
        _ => RelationshipStrength::Weak,
    }
}

/// Derives the structured relationship view from a verdict's existing
/// provenance entries -- pure and DB-free, since every fact it needs
/// (tier, confidence, matched value, CVE IDs, provenance) already lives on
/// `ProvenanceEntry`. Kept separate from `ThreatRelationship`s that come
/// from a dedicated relationship query (e.g. malware-family attribution,
/// which has its own table and isn't derivable from provenance alone) --
/// callers combine both.
///
/// One `ProvenanceEntry` can become more than one `ThreatRelationship`:
/// every entry is at least an IOC relationship (the indicator match
/// itself), a `YaraHit` is additionally a Detection relationship, a
/// `PathPattern`/`Contextual` entry is additionally a risk-based
/// relationship (the Constitution's risk-based category names "unusual
/// location" as an example), and any CVE IDs the entry carries become
/// their own CVE relationships.
pub fn derive_relationships(entries: &[ProvenanceEntry]) -> Vec<ThreatRelationship> {
    let mut relationships = Vec::new();

    for entry in entries {
        let strength = derive_strength(entry.confidence);

        let ioc_explanation = match entry.tier {
            VerdictTier::ExactHash => {
                "Exact hash match against a known indicator -- find other hosts or paths where \
                 this same indicator has been observed."
                    .to_string()
            }
            VerdictTier::FuzzyHash => {
                "Fuzzy hash similarity to a known indicator -- a close but non-exact match worth \
                 corroborating with other evidence."
                    .to_string()
            }
            VerdictTier::YaraHit => {
                "Matched a local detection rule -- see the Detection relationship for the rule \
                 itself."
                    .to_string()
            }
            VerdictTier::PathPattern => {
                "Path or naming pattern matched a known indicator -- weaker than a content match, \
                 worth checking alongside other evidence."
                    .to_string()
            }
            VerdictTier::Contextual => {
                "Filename matches a known sample name with no hash or rule match -- the weakest \
                 signal here; corroborate before treating this as meaningful."
                    .to_string()
            }
        };
        relationships.push(ThreatRelationship {
            kind: RelationshipKind::Ioc,
            strength,
            target: entry.matched_value.clone(),
            explanation: ioc_explanation,
            source: entry.source.clone(),
            confidence: entry.confidence,
            first_seen: entry.first_seen,
            last_seen: entry.last_seen,
            report_id: entry.report_id,
            report_title: entry.report_title.clone(),
            report_url: entry.report_url.clone(),
        });

        if entry.tier == VerdictTier::YaraHit {
            if let Some(detection_name) = &entry.detection_name {
                relationships.push(ThreatRelationship {
                    kind: RelationshipKind::Detection,
                    strength,
                    target: detection_name.clone(),
                    explanation:
                        "A local YARA rule fired against this exact file -- run the rule or trace \
                         its logic to see exactly what it matched on."
                            .to_string(),
                    source: entry.source.clone(),
                    confidence: entry.confidence,
                    first_seen: entry.first_seen,
                    last_seen: entry.last_seen,
                    report_id: entry.report_id,
                    report_title: entry.report_title.clone(),
                    report_url: entry.report_url.clone(),
                });
            }
        }

        if matches!(
            entry.tier,
            VerdictTier::PathPattern | VerdictTier::Contextual
        ) {
            relationships.push(ThreatRelationship {
                kind: RelationshipKind::RiskBased,
                strength,
                target: entry.matched_value.clone(),
                explanation:
                    "Location or naming association only, not a content or hash match -- expand \
                     the contextual hunt without treating this as direct compromise evidence."
                        .to_string(),
                source: entry.source.clone(),
                confidence: entry.confidence,
                first_seen: entry.first_seen,
                last_seen: entry.last_seen,
                report_id: entry.report_id,
                report_title: entry.report_title.clone(),
                report_url: entry.report_url.clone(),
            });
        }

        for cve_id in &entry.cve_ids {
            relationships.push(ThreatRelationship {
                kind: RelationshipKind::Cve,
                strength,
                target: cve_id.clone(),
                explanation:
                    "This file is linked to a CVE -- assess exposure and hunt for exploitation \
                     evidence, not just the vulnerable version's presence."
                        .to_string(),
                source: entry.source.clone(),
                confidence: entry.confidence,
                first_seen: entry.first_seen,
                last_seen: entry.last_seen,
                report_id: entry.report_id,
                report_title: entry.report_title.clone(),
                report_url: entry.report_url.clone(),
            });
        }
    }

    relationships
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(tier: VerdictTier, confidence: i16, cve_ids: Vec<String>) -> ProvenanceEntry {
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
            cve_ids,
        }
    }

    // ---- derive_strength ----
    //
    // Thresholds are drawn from real confidence values already in use
    // elsewhere in this codebase -- see derive_strength's doc comment.

    #[test]
    fn malwarebazaar_confidence_is_direct() {
        assert_eq!(derive_strength(90), RelationshipStrength::Direct);
    }

    #[test]
    fn yara_hit_confidence_is_strong() {
        assert_eq!(derive_strength(65), RelationshipStrength::Strong);
    }

    #[test]
    fn contextual_confidence_is_weak() {
        assert_eq!(derive_strength(25), RelationshipStrength::Weak);
    }

    #[test]
    fn strength_bands_are_ordered_and_exhaustive() {
        assert_eq!(derive_strength(0), RelationshipStrength::Weak);
        assert_eq!(derive_strength(34), RelationshipStrength::Weak);
        assert_eq!(derive_strength(35), RelationshipStrength::Contextual);
        assert_eq!(derive_strength(59), RelationshipStrength::Contextual);
        assert_eq!(derive_strength(60), RelationshipStrength::Strong);
        assert_eq!(derive_strength(84), RelationshipStrength::Strong);
        assert_eq!(derive_strength(85), RelationshipStrength::Direct);
        assert_eq!(derive_strength(100), RelationshipStrength::Direct);
    }

    #[test]
    fn strength_is_totally_ordered_weak_to_direct() {
        assert!(RelationshipStrength::Weak < RelationshipStrength::Contextual);
        assert!(RelationshipStrength::Contextual < RelationshipStrength::Strong);
        assert!(RelationshipStrength::Strong < RelationshipStrength::Direct);
    }

    // ---- derive_relationships ----

    #[test]
    fn exact_hash_entry_becomes_an_ioc_relationship() {
        let entries = vec![entry(VerdictTier::ExactHash, 90, vec![])];
        let relationships = derive_relationships(&entries);
        assert_eq!(relationships.len(), 1);
        assert_eq!(relationships[0].kind, RelationshipKind::Ioc);
        assert_eq!(relationships[0].strength, RelationshipStrength::Direct);
        assert_eq!(relationships[0].target, "deadbeef");
    }

    #[test]
    fn yara_hit_becomes_both_an_ioc_and_a_detection_relationship() {
        let entries = vec![entry(VerdictTier::YaraHit, 65, vec![])];
        let relationships = derive_relationships(&entries);
        assert_eq!(relationships.len(), 2);
        assert!(relationships
            .iter()
            .any(|r| r.kind == RelationshipKind::Ioc));
        let detection = relationships
            .iter()
            .find(|r| r.kind == RelationshipKind::Detection)
            .expect("expected a Detection relationship for a YARA hit");
        assert_eq!(detection.target, "Test_Rule");
        assert_eq!(detection.strength, RelationshipStrength::Strong);
    }

    #[test]
    fn path_pattern_becomes_both_an_ioc_and_a_risk_based_relationship() {
        let entries = vec![entry(VerdictTier::PathPattern, 50, vec![])];
        let relationships = derive_relationships(&entries);
        assert_eq!(relationships.len(), 2);
        assert!(relationships
            .iter()
            .any(|r| r.kind == RelationshipKind::Ioc));
        assert!(relationships
            .iter()
            .any(|r| r.kind == RelationshipKind::RiskBased));
    }

    #[test]
    fn contextual_becomes_both_an_ioc_and_a_risk_based_relationship() {
        let entries = vec![entry(VerdictTier::Contextual, 25, vec![])];
        let relationships = derive_relationships(&entries);
        assert_eq!(relationships.len(), 2);
        assert!(relationships
            .iter()
            .any(|r| r.kind == RelationshipKind::RiskBased
                && r.strength == RelationshipStrength::Weak));
    }

    #[test]
    fn cve_ids_become_their_own_relationships() {
        let entries = vec![entry(
            VerdictTier::ExactHash,
            90,
            vec!["CVE-2024-1234".to_string(), "CVE-2024-5678".to_string()],
        )];
        let relationships = derive_relationships(&entries);
        // 1 Ioc + 2 Cve
        assert_eq!(relationships.len(), 3);
        let cve_targets: Vec<&str> = relationships
            .iter()
            .filter(|r| r.kind == RelationshipKind::Cve)
            .map(|r| r.target.as_str())
            .collect();
        assert_eq!(cve_targets, vec!["CVE-2024-1234", "CVE-2024-5678"]);
    }

    #[test]
    fn no_entries_means_no_relationships() {
        assert!(derive_relationships(&[]).is_empty());
    }
}
