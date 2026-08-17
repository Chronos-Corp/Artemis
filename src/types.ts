export interface FileEntry {
  name: string;
  path: string;
  is_dir: boolean;
  size: number;
  modified: string | null;
}

export type VerdictTier =
  | "exact_hash"
  | "fuzzy_hash"
  | "yara_hit"
  | "path_pattern"
  | "contextual";

export const TIER_LABELS: Record<VerdictTier, string> = {
  exact_hash: "Exact hash match",
  fuzzy_hash: "Fuzzy match",
  yara_hit: "YARA rule hit",
  path_pattern: "Path or naming pattern",
  contextual: "Contextual association",
};

export const TIER_ORDER: VerdictTier[] = [
  "exact_hash",
  "fuzzy_hash",
  "yara_hit",
  "path_pattern",
  "contextual",
];

// Mirrors nsic_core::models::IndicatorKind's wire form -- that enum has no
// `#[serde(rename_all)]` of its own, unlike VerdictTier/RelationshipKind/
// RelationshipStrength/EvidenceRelation below, so it serializes as its
// Rust variant names (PascalCase), not snake_case.
export type IndicatorKind =
  | "Sha256"
  | "Md5"
  | "Sha1"
  | "Imphash"
  | "Tlsh"
  | "Ssdeep"
  | "Path"
  | "Regkey"
  | "Mutex"
  | "Domain"
  | "Ip";

export interface ProvenanceEntry {
  tier: VerdictTier;
  source: string;
  confidence: number;
  first_seen: string;
  last_seen: string;
  report_id: string | null;
  report_title: string | null;
  report_url: string | null;
  detection_name: string | null;
  matched_value: string;
  indicator_kind: IndicatorKind | null;
  ruleset_fingerprint: string | null;
}

export interface IntelSourceFreshness {
  source: string;
  last_successful_sync_at: string | null;
}

// ---------------------------------------------------------------------
// Threat Relationship Intelligence (Apollo Constitution §6) -- the
// RELATE-stage structured view, distinct from ProvenanceEntry's
// verdict-tier framing ("why did this file get flagged").
// ---------------------------------------------------------------------

export type RelationshipKind =
  | "ioc"
  | "cve"
  | "threat_actor"
  | "campaign"
  | "malware_family"
  | "attack_technique"
  | "detection"
  | "risk_based";

export const RELATIONSHIP_KIND_LABELS: Record<RelationshipKind, string> = {
  ioc: "IOC",
  cve: "CVE",
  threat_actor: "Threat actor",
  campaign: "Campaign",
  malware_family: "Malware family",
  attack_technique: "ATT&CK technique",
  detection: "Detection",
  risk_based: "Risk-based",
};

export type RelationshipStrength = "direct" | "strong" | "contextual" | "weak";

export const RELATIONSHIP_STRENGTH_LABELS: Record<RelationshipStrength, string> = {
  direct: "Direct",
  strong: "Strong",
  contextual: "Contextual",
  weak: "Weak",
};

// Strongest first, matching how the provenance list is already sorted.
export const RELATIONSHIP_STRENGTH_ORDER: RelationshipStrength[] = [
  "direct",
  "strong",
  "contextual",
  "weak",
];

// What a RelationshipEvidence hop asserts, named after the edge table it
// comes from -- a closed, typed vocabulary rather than free-form prose.
export type EvidenceRelation =
  | "observed_in_report"
  | "report_references_cve"
  | "detects_indicator"
  | "detection_covers_cve"
  | "attributed_to_malware_family"
  | "contextual_filename_match";

export const EVIDENCE_RELATION_LABELS: Record<EvidenceRelation, string> = {
  observed_in_report: "observed in report",
  report_references_cve: "report references CVE",
  detects_indicator: "detects indicator",
  detection_covers_cve: "detection covers CVE",
  attributed_to_malware_family: "attributed to malware family",
  contextual_filename_match: "contextual filename match",
};

// One hop of evidence supporting a ThreatRelationship. A single-hop
// relationship (ioc/detection/risk_based/malware_family) carries exactly
// one; a cve relationship carries the full multi-hop chain it was
// inferred through, each hop with its own source/confidence/timestamps --
// Postgres stores provenance per edge, not per relationship, so collapsing
// this to one flat value would either pick the wrong edge's provenance or
// silently discard a hop's evidence.
export interface RelationshipEvidence {
  relation: EvidenceRelation;
  source: string;
  confidence: number;
  first_seen: string;
  last_seen: string;
  report_id: string | null;
  report_title: string | null;
  report_url: string | null;
  indicator_kind: IndicatorKind | null;
  indicator_value: string | null;
  detection_name: string | null;
  ruleset_fingerprint: string | null;
}

export interface ThreatRelationship {
  kind: RelationshipKind;
  strength: RelationshipStrength;
  target: string;
  explanation: string;
  // Ordered from the file outward; never empty.
  evidence: RelationshipEvidence[];
}

export interface Verdict {
  path: string;
  sha256: string;
  md5: string;
  entries: ProvenanceEntry[];
  intel_freshness: IntelSourceFreshness[];
  threat_relationships: ThreatRelationship[];
}

export interface SyncSummary {
  source: string;
  indicators_added: number;
  indicators_updated: number;
  reports_added: number;
  synced_at: string;
}

export interface FeedSyncResult {
  source: string;
  ok: boolean;
  summary: SyncSummary | null;
  error: string | null;
}

export interface YaraStatus {
  rules_dir: string;
  rule_count: number;
}

// ---------------------------------------------------------------------
// File Intelligence Model (Apollo Constitution §5) -- the FILE/UNDERSTAND
// stages, independent of `Verdict`'s RELATE-stage threat-intel lookup.
// ---------------------------------------------------------------------

export interface FileIdentity {
  file_type: string;
  extension: string | null;
  is_hidden: boolean;
  is_executable: boolean;
  is_symlink: boolean;
  symlink_target: string | null;
  created: string | null;
  modified: string | null;
  accessed: string | null;
}

export type AuthenticityStatus = "verified" | "modified" | "unpackaged" | "unknown";

export interface FileAuthenticity {
  status: AuthenticityStatus;
  detail: string | null;
}

export interface ProductContext {
  package: string | null;
  version: string | null;
  vendor: string | null;
  description: string | null;
}

export type PurposeSource = "package_catalog" | "unknown";

export interface FilePurpose {
  summary: string;
  source: PurposeSource;
}

export type ExpectednessStatus = "expected" | "unexpected" | "unknown";

export interface FileExpectedness {
  status: ExpectednessStatus;
  reasons: string[];
}

export interface LocalContext {
  sibling_count: number;
  similarly_named_siblings: string[];
  available: boolean;
}

export interface FileIntelligence {
  identity: FileIdentity;
  authenticity: FileAuthenticity;
  product_context: ProductContext;
  purpose: FilePurpose;
  expectedness: FileExpectedness;
  local_context: LocalContext;
}

export interface DbStatus {
  connected: boolean;
}
