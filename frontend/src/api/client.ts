/*
 * Client API unique. Toutes les URL sont relatives : en développement comme en
 * `vite preview`, le proxy Vite relaie /api et /ws vers le backend.
 */
import type {
  Alert,
  AssetChange,
  AssetDeclaration,
  AttackPath,
  BehaviorSummary,
  BlastRadius,
  Communication,
  Deviation,
  Exposure,
  Hypothesis,
  IncidentDetail,
  IncidentSummary,
  Inventory,
  InventoryDetail,
  LiveState,
  ObservedTechnique,
  Simulation,
  SimulationResult,
  SnapshotDetail,
  SnapshotSummary,
  Technique,
} from "./types";

export class ApiError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetch(path, {
      ...init,
      headers: { Accept: "application/json", ...(init?.body ? { "Content-Type": "application/json" } : {}), ...init?.headers },
    });
  } catch {
    throw new ApiError(0, "Backend injoignable : vérifiez que l'API tourne sur le port 8000.");
  }

  if (!response.ok) {
    let detail = `${response.status} ${response.statusText}`;
    try {
      const body = await response.json();
      if (typeof body?.detail === "string") detail = body.detail;
    } catch {
      // corps non JSON : on garde le statut HTTP
    }
    if (response.status === 401) detail = "Accès refusé : jeton d'API manquant ou invalide (CYBERMORPH_API_TOKEN).";
    throw new ApiError(response.status, detail);
  }
  return (await response.json()) as T;
}

const query = (params: Record<string, string | number | undefined>) => {
  const entries = Object.entries(params).filter(([, v]) => v !== undefined) as [string, string | number][];
  return entries.length ? `?${new URLSearchParams(entries.map(([k, v]) => [k, String(v)]))}` : "";
};

export const api = {
  liveState: () => request<LiveState>("/api/live/state"),
  exposure: (minScore = 25, maxLength = 4) =>
    request<Exposure>(`/api/exposure/${query({ min_score: minScore, max_length: maxLength })}`),
  blastRadius: (assetId: number) => request<BlastRadius>(`/api/exposure/blast-radius/${assetId}`),
  behavior: () => request<BehaviorSummary>("/api/behavior/"),
  communications: (params: { asset_id?: number; state?: string } = {}) =>
    request<Communication[]>(`/api/behavior/communications${query(params)}`),
  deviations: (params: { status?: string; asset_id?: number } = {}) =>
    request<Deviation[]>(`/api/behavior/deviations${query(params)}`),
  learnDeviation: (id: number) => request<Deviation>(`/api/behavior/deviations/${id}/learn`, { method: "POST" }),
  acknowledgeDeviation: (id: number) => request<Deviation>(`/api/behavior/deviations/${id}/acknowledge`, { method: "POST" }),
  inventory: () => request<Inventory>("/api/inventory/"),
  inventoryAsset: (assetId: number) => request<InventoryDetail>(`/api/inventory/${assetId}`),
  changes: (params: { limit?: number; asset_id?: number; min_severity?: string; include_acknowledged?: boolean } = {}) =>
    request<AssetChange[]>(`/api/changes/${query({ ...params, include_acknowledged: params.include_acknowledged === false ? "false" : undefined })}`),
  acknowledgeChange: (id: number) => request<AssetChange>(`/api/changes/${id}/acknowledge`, { method: "POST" }),
  declareAsset: (assetId: number, declaration: AssetDeclaration) =>
    request<unknown>(`/api/assets/${assetId}`, { method: "PATCH", body: JSON.stringify(declaration) }),
  alerts: (limit = 200) => request<Alert[]>(`/api/alerts/${query({ limit })}`),
  incidents: () => request<IncidentSummary[]>("/api/incidents/"),
  incident: (id: number) => request<IncidentDetail>(`/api/incidents/${id}`),
  attackPaths: (minScore = 0, maxLength = 4) =>
    request<{ count: number; paths: AttackPath[] }>(`/api/attack-paths/${query({ min_score: minScore, max_length: maxLength })}`),
  techniques: () => request<Technique[]>("/api/attack-techniques/"),
  observedTechniques: () => request<ObservedTechnique[]>("/api/attack-techniques/observed"),
  timeline: (limit = 288) => request<SnapshotSummary[]>(`/api/timeline/${query({ limit })}`),
  snapshot: (id: number) => request<SnapshotDetail>(`/api/timeline/${id}`),
  simulations: () => request<Simulation[]>("/api/simulations/"),
  hypothesisTypes: () => request<Record<string, string>>("/api/simulations/hypothesis-types"),
  createSimulation: (name: string, description?: string) =>
    request<Simulation>("/api/simulations/", { method: "POST", body: JSON.stringify({ name, description }) }),
  applyHypothesis: (id: number, hypothesis: Hypothesis) =>
    request<{ status: string }>(`/api/simulations/${id}/hypothesis`, { method: "POST", body: JSON.stringify(hypothesis) }),
  simulationResult: (id: number) =>
    request<{ simulation_id: number; name: string; hypothesis: Hypothesis; result: SimulationResult; completed_at: string }>(
      `/api/simulations/${id}/result`,
    ),
};

export function liveSocketUrl(): string {
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  return `${protocol}//${window.location.host}/ws/live`;
}
