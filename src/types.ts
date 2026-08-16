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
  cve_ids: string[];
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

export interface ThreatRelationship {
  kind: RelationshipKind;
  strength: RelationshipStrength;
  target: string;
  explanation: string;
  source: string;
  confidence: number;
  first_seen: string;
  last_seen: string;
  report_id: string | null;
  report_title: string | null;
  report_url: string | null;
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
