import type {
  AttackGraph,
  Briefing,
  Dashboard,
  Health,
  Incident,
  IncidentSummary,
  MitreResponse,
  ResponseAction,
  ResponseListing,
  SourceHealthResponse,
  Timeline,
} from './types';

// Baked in at build time so the browser reaches the host's published port
// rather than the compose-internal hostname.
const BASE = (import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:8080').replace(/\/$/, '');

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly code?: string,
  ) {
    super(message);
  }
}

async function get<T>(path: string): Promise<T> {
  const response = await fetch(`${BASE}/api/v1${path}`);

  if (!response.ok) {
    throw await toError(response);
  }
  return (await response.json()) as T;
}

async function post<T>(path: string, body: unknown): Promise<T> {
  const response = await fetch(`${BASE}/api/v1${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });

  if (!response.ok) {
    throw await toError(response);
  }
  return (await response.json()) as T;
}

/// Surfaces the API's own error message, which carries the reason a request was
/// refused (an approval gate, for instance) rather than a bare status code.
async function toError(response: Response): Promise<ApiError> {
  try {
    const body = (await response.json()) as { error?: string; message?: string };
    return new ApiError(
      body.message ?? `request failed with ${response.status}`,
      response.status,
      body.error,
    );
  } catch {
    return new ApiError(`request failed with ${response.status}`, response.status);
  }
}

export const api = {
  health: () => get<Health>('/health'),
  dashboard: () => get<Dashboard>('/dashboard'),
  incidents: () => get<{ total: number; incidents: IncidentSummary[] }>('/incidents'),
  incident: (id: string) => get<Incident>(`/incidents/${id}`),
  graph: (id: string) => get<AttackGraph>(`/incidents/${id}/graph`),
  timeline: (id: string) => get<Timeline>(`/incidents/${id}/timeline`),
  mitre: (id: string) => get<MitreResponse>(`/incidents/${id}/mitre`),
  briefing: (id: string) => get<Briefing>(`/incidents/${id}/ai`),
  responses: (id: string) => get<ResponseListing>(`/incidents/${id}/response`),
  sources: () => get<SourceHealthResponse>('/sources/health'),

  simulate: (id: string, actionId: string, approvedBy?: string) =>
    post<{ action: ResponseAction; narrative: string; approved_by: string | null }>(
      `/incidents/${id}/response/simulate`,
      { action_id: actionId, approved_by: approvedBy ?? null },
    ),
};

export { BASE as apiBaseUrl };
