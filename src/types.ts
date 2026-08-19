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

// Whether first_seen/last_seen below are a genuine observation window from
// a backing edge ("observed"), or only when Apollo itself received the
// underlying report ("received_only") -- see the matching Rust doc
// comment on EvidenceTiming. Only Contextual entries are "received_only";
// every other tier has real edge provenance to source a timestamp from.
export type EvidenceTiming = "observed" | "received_only";

export interface ProvenanceEntry {
  tier: VerdictTier;
  source: string;
  confidence: number;
  first_seen: string;
  last_seen: string;
  timing: EvidenceTiming;
  report_id: string | null;
  report_title: string | null;
  report_url: string | null;
  detection_name: string | null;
  matched_value: string;
  indicator_kind: IndicatorKind | null;
  rule_fingerprint: string | null;
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
  timing: EvidenceTiming;
  report_id: string | null;
  report_title: string | null;
  report_url: string | null;
  indicator_kind: IndicatorKind | null;
  indicator_value: string | null;
  detection_name: string | null;
  // The specific rule content's fingerprint (see the Rust
  // YaraEngine::rule_fingerprint doc comment) -- deliberately scoped per
  // rule, not the whole compiled ruleset, so an unrelated rule's edit
  // can't falsely invalidate this one's coverage. null is the edge's own
  // true "applies to any rule version" wildcard value, never fabricated
  // from whatever ruleset happens to be active during a later scan.
  rule_fingerprint: string | null;
}

export interface ThreatRelationship {
  kind: RelationshipKind;
  strength: RelationshipStrength;
  target: string;
  explanation: string;
  // Every distinct, independently-walkable evidence path from the file to
  // `target` -- each inner array is one complete, ordered chain (file
  // outward). Most relationships have exactly one path; a Cve relationship
  // derived from report co-occurrence can have more than one when the
  // report observed this file under more than one hash (or via more than
  // one source) before converging on the same CVE assertion -- a review
  // caught that flattening those into one array made a two-parents-one-
  // shared-tail shape look like a single linear chain. Never empty, and no
  // inner path is ever empty.
  evidence_paths: RelationshipEvidence[][];
  // True when this relationship has more supporting evidence paths than
  // `evidence_paths` carries, because the per-relationship evidence cap
  // fired. Distinct from VerdictBounds.relationships_truncated: "this CVE
  // has more supporting observations than shown" and "there are more CVEs
  // than shown" are different claims.
  has_more_evidence: boolean;
}

// Which parts of a verdict were bounded rather than exhaustive. Row caps
// keep one file from producing an unbounded payload, but a review caught
// that without this, a capped result was indistinguishable from a complete
// one -- so neither the analyst nor PR #20's hunt engine could tell that
// evidence had been withheld. A safe bound must not look like an
// exhaustive result.
export interface VerdictBounds {
  // Tiers whose entries hit the per-query row cap. Per-tier rather than one
  // flag because the tiers come from separate queries with separate caps.
  truncated_entry_tiers: VerdictTier[];
  // True when distinct related concepts exist that `threat_relationships`
  // does not list at all.
  relationships_truncated: boolean;
}

export interface Verdict {
  path: string;
  sha256: string;
  md5: string;
  entries: ProvenanceEntry[];
  intel_freshness: IntelSourceFreshness[];
  threat_relationships: ThreatRelationship[];
  bounds: VerdictBounds;
}

// ---------------------------------------------------------------------
// Orion TRACE -- an explicitly directed projection over the normalized
// RELATE contract. Proof direction is resolved in Rust, never inferred by
// the UI from EvidenceRelation names or explanation prose.
// ---------------------------------------------------------------------

export type TraceNodeKind =
  | "artifact"
  | "indicator"
  | "report"
  | "detection"
  | "cve"
  | "malware_family"
  | "risk_concept";

export interface TraceNode {
  id: string;
  kind: TraceNodeKind;
  label: string;
}

export type TraceEdgeRelation =
  | "artifact_has_indicator"
  | "indicator_observed_in_report"
  | "report_references_cve"
  | "indicator_matched_by_detection"
  | "detection_covers_cve"
  | "indicator_attributed_to_malware_family"
  | "contextual_filename_match";

export const TRACE_EDGE_LABELS: Record<TraceEdgeRelation, string> = {
  artifact_has_indicator: "has indicator",
  indicator_observed_in_report: "observed in report",
  report_references_cve: "references CVE",
  indicator_matched_by_detection: "matched by detection",
  detection_covers_cve: "covers CVE",
  indicator_attributed_to_malware_family: "attributed to family",
  contextual_filename_match: "possible filename association",
};

export type AssertionOrientation = "native" | "reversed" | "synthetic";
export type TracePathState = "observed" | "possible";

export interface TraceEdge {
  from: string;
  to: string;
  relation: TraceEdgeRelation;
  assertion_orientation: AssertionOrientation;
  proof_hop_index: number | null;
}

export interface TracePathRank {
  relationship_strength: RelationshipStrength;
  weakest_source_confidence: number;
  hop_count: number;
}

export interface TracePath {
  id: string;
  relationship_index: number;
  target_kind: RelationshipKind;
  target: string;
  state: TracePathState;
  rank: TracePathRank;
  nodes: TraceNode[];
  edges: TraceEdge[];
  supporting_proof: RelationshipEvidence[];
  supporting_evidence_partial: boolean;
}

export type UntracedReason =
  | "empty_proof"
  | "mixed_proof_shape"
  | "unsupported_relationship_shape"
  | "missing_node_identity"
  | "inconsistent_proof_endpoints";

export interface UntracedRelationship {
  relationship_index: number;
  target_kind: RelationshipKind;
  target: string;
  reason: UntracedReason;
}

export interface TraceBounds {
  input_relationships_truncated: boolean;
  input_evidence_truncated: boolean;
  paths_truncated: boolean;
  omitted_paths: number;
  max_paths: number;
}

export interface OrionTrace {
  start: TraceNode;
  paths: TracePath[];
  untraced_relationships: UntracedRelationship[];
  bounds: TraceBounds;
}

// ---------------------------------------------------------------------
// Artemis HUNT -- one authoritative Orion path applied to an explicit,
// bounded execution scope. The UI submits only selectors; Rust reconstructs
// the target and proof before scanning.
// ---------------------------------------------------------------------

export type HuntScopeKind = "subtree";

export interface HuntScope {
  kind: HuntScopeKind;
  root: string;
}

export interface HuntRequest {
  seed_path: string;
  expected_seed_sha256: string;
  trace_path_id: string;
  scope: HuntScope;
}

export interface HuntHypothesis {
  seed_artifact: TraceNode;
  selected_path: TracePath;
}

export type HuntEvidenceRole = "confirming" | "contradicting" | "contextual";

export interface HuntFinding {
  artifact_path: string;
  sha256: string;
  md5: string;
  role: HuntEvidenceRole;
  strength: RelationshipStrength;
  supporting_path: TracePath;
  additional_matching_paths: number;
}

export interface HuntScanError {
  path: string;
  error: string;
}

export interface HuntSummary {
  files_discovered: number;
  files_analyzed: number;
  files_inconclusive: number;
  confirming_findings: number;
  contradicting_findings: number;
  contextual_findings: number;
}

export interface HuntBounds {
  max_files: number;
  max_findings: number;
  max_errors: number;
  max_walk_entries: number;
  scope_truncated: boolean;
  findings_truncated: boolean;
  omitted_findings: number;
  errors_truncated: boolean;
  omitted_errors: number;
}

export interface HuntResult {
  hypothesis: HuntHypothesis;
  scope: HuntScope;
  findings: HuntFinding[];
  scan_errors: HuntScanError[];
  summary: HuntSummary;
  bounds: HuntBounds;
  limitations: string[];
  started_at: string;
  completed_at: string;
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
