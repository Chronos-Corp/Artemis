import type { OrionTrace, Verdict, YaraStatus } from "./types";

export type YaraCoverageState = "loaded" | "empty" | "failed";

export interface YaraCoverage {
  status: YaraCoverageState;
  rule_count: number;
  failure_reason: string | null;
}

// Backend keeps the shared core Verdict intact and flattens runtime analysis
// coverage beside it at the Tauri command boundary.
export type VerdictWithCoverage = Verdict & {
  yara_coverage: YaraCoverage;
  orion_trace: OrionTrace;
};

export type YaraStatusWithCoverage = YaraStatus & YaraCoverage;
