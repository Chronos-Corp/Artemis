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

export interface Verdict {
  path: string;
  sha256: string;
  md5: string;
  entries: ProvenanceEntry[];
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

export interface DbStatus {
  connected: boolean;
}

export interface SyncState {
  source: string;
  last_synced_at: string | null;
}
