export type CampaignStatus = "running" | "paused" | "completed" | "failed" | "cancelled" | string;
export type CampaignPhase = "baseline" | "attack" | "verify" | "patch" | "retest" | "held_out" | "report" | string;

export interface CampaignStatusResponse {
  campaign_id: string;
  status: CampaignStatus;
  phase: CampaignPhase;
  asr_before: number | null;
  asr_after: number | null;
  normal_acc_before: number | null;
  normal_acc_after: number | null;
  step_count: number;
  created_at: string;
  updated_at: string | null;
}

export interface CampaignPage {
  campaigns: CampaignStatusResponse[];
  page: number;
  limit: number;
  total: number;
}

export interface MetricsResponse {
  total_campaigns: number;
  completed_campaigns: number;
  average_asr_before: number;
  average_asr_after: number;
  total_regression_tests: number;
  total_patches_applied: number;
}

export interface ToolCall {
  name: string;
  args: Record<string, unknown>;
  result: Record<string, unknown> | null;
  timestamp: string;
  call_index: number;
  error: string | null;
}

export interface GateResult {
  gate: string;
  passed: boolean;
  evidence: Record<string, unknown>;
  attack_id: string | null;
}

export interface Trace {
  id: string;
  campaign_id: string;
  attack_id: string | null;
  phase: CampaignPhase;
  task: string;
  tool_calls: ToolCall[];
  final_response: string | null;
  gates_fired: GateResult[];
  created_at: string;
}

export interface FailureSummary {
  attack_family: string;
  gates_fired: string[];
  tool_violated: string;
  violation_type: string;
  injection_vector: string;
}

export interface CampaignReport {
  campaign_id: string;
  duration_seconds: number;
  asr_before: number;
  asr_after: number;
  asr_held_out_before: number;
  asr_held_out_after: number;
  normal_acc_before: number;
  normal_acc_after: number;
  patches_applied: number;
  human_interventions: number;
  regression_tests_added: number;
  total_steps: number;
  violations: FailureSummary[];
  patches: Array<{ id?: string; [key: string]: unknown }>;
  summary: string;
}

export interface CampaignReportResponse {
  report: CampaignReport;
  summary: string;
}

export interface CampaignCreateRequest {
  sut_descriptor: { type: "custom_sut"; tools: string[] };
  threat_model: { families: string[] };
  budget: { max_steps: number; max_tokens: number };
  human_policy: Record<string, never>;
}

export interface CampaignCreateResponse {
  campaign_id: string;
  status: string;
}

export interface LiveCampaignUpdate {
  phase?: CampaignPhase;
  asr_before?: number | null;
  asr_after?: number | null;
  step_count?: number;
  error?: string;
}

export interface HealthResponse {
  status: "healthy" | "unhealthy";
  version?: string;
  error?: string;
}
