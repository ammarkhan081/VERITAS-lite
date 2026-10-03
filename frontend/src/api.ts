import type {
  CampaignCreateRequest,
  CampaignCreateResponse,
  CampaignPage,
  CampaignReportResponse,
  CampaignStatusResponse,
  HealthResponse,
  MetricsResponse,
  Trace,
} from "./types";

const API_BASE = (import.meta.env.VITE_API_BASE_URL || "/api").replace(/\/$/, "");

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response;
  const headers = new Headers(init?.headers);
  headers.set("Accept", "application/json");
  if (init?.body) headers.set("Content-Type", "application/json");
  try {
    response = await fetch(`${API_BASE}${path}`, {
      ...init,
      headers,
    });
  } catch {
    throw new ApiError("Could not reach the VERITAS API. Check the API connection and try again.", 0);
  }

  if (!response.ok) {
    let message = `The API returned HTTP ${response.status}.`;
    try {
      const body = (await response.json()) as { detail?: unknown };
      if (typeof body.detail === "string") message = body.detail;
      else if (body.detail !== undefined) message = JSON.stringify(body.detail);
    } catch {
      // Keep the status-based message when an error body is not JSON.
    }
    throw new ApiError(message, response.status);
  }
  return (await response.json()) as T;
}

export const api = {
  health: (signal?: AbortSignal) => request<HealthResponse>("/health", { signal }),
  metrics: (signal?: AbortSignal) => request<MetricsResponse>("/metrics", { signal }),
  campaigns: (page = 1, limit = 20, signal?: AbortSignal) =>
    request<CampaignPage>(`/campaigns?page=${page}&limit=${limit}`, { signal }),
  campaign: (id: string, signal?: AbortSignal) =>
    request<CampaignStatusResponse>(`/campaigns/${encodeURIComponent(id)}`, { signal }),
  createCampaign: (body: CampaignCreateRequest) =>
    request<CampaignCreateResponse>("/campaigns", { method: "POST", body: JSON.stringify(body) }),
  cancelCampaign: (id: string) =>
    request<{ campaign_id: string; status: string }>(`/campaigns/${encodeURIComponent(id)}`, { method: "DELETE" }),
  deleteCampaignRecord: (id: string) =>
    request<{ campaign_id: string; deleted: boolean }>(`/campaigns/${encodeURIComponent(id)}/record`, { method: "DELETE" }),
  resumeCampaign: (id: string, approved: boolean) =>
    request<{ status: string; approved: boolean }>(`/campaigns/${encodeURIComponent(id)}/resume`, {
      method: "POST",
      body: JSON.stringify({ approved }),
    }),
  traces: (id: string, signal?: AbortSignal) =>
    request<{ campaign_id: string; traces: Trace[] }>(`/campaigns/${encodeURIComponent(id)}/traces`, { signal }),
  report: (id: string, signal?: AbortSignal) =>
    request<CampaignReportResponse>(`/campaigns/${encodeURIComponent(id)}/report`, { signal }),
};

export function campaignSocketUrl(id: string): string {
  const apiUrl = new URL(`${API_BASE}/campaigns/${encodeURIComponent(id)}/ws`, window.location.origin);
  apiUrl.protocol = apiUrl.protocol === "https:" ? "wss:" : "ws:";
  return apiUrl.toString();
}
