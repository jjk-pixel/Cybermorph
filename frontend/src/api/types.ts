/*
 * Contrats de données du backend CYBERMORPH (FastAPI).
 * Les dates arrivent en ISO 8601 ; certaines colonnes historiques sont sans fuseau
 * et doivent être lues comme UTC (voir lib/format.ts → parseDate).
 */

export type RiskFactors = {
  risk_score: number;
  risk_level: string;
  factors: string[];
  breakdown: Record<string, number>;
};

export type LiveAsset = {
  id: number;
  ip: string;
  name: string;
  hostname: string | null;
  asset_type: string;
  risk_score: number | null;
  status: string;
  mac_address: string | null;
  vendor: string | null;
  os_detected: string | null;
  open_ports: string | null;
  services: string | null;
  zone: string | null;
  risk_factors: RiskFactors | null;
  last_seen: string | null;
};

export type EvidenceLevel = "voisinage_detecte" | "inferee" | "observee" | "alerte_ids";

export type AlertSummary = {
  message: string;
  priority: number | null;
  total_occurrences: number;
  alert_count: number;
  score_contribution: number;
};

export type LiveLink = {
  source: number;
  target: number;
  weight: number;
  connection_types: string[];
  evidence_level: EvidenceLevel;
  details: { protocol: string | null; port: number | null; connection_type: string | null }[];
  alert_summary: AlertSummary | null;
};

export type AttackPath = {
  source: number;
  target: number;
  nodes: number[];
  hops: number;
  score: number;
  risk: "low" | "moderate" | "high" | "critical";
  evidence_level: EvidenceLevel;
  connection_types: string[];
  alert_evidence?: AlertSummary[];
  // champs ajoutés par /api/attack-paths
  source_ip?: string | null;
  target_ip?: string | null;
  path_ips?: (string | null)[];
  // champ ajouté par les simulations
  score_before?: number;
};

export type IncidentStep = {
  id?: number;
  sequence: number;
  source_asset_id: number;
  destination_asset_id: number;
  status: "potential" | "confirmed" | string;
  confidence: number;
  technique_id: string | null;
  evidence_type?: string | null;
  detected_at?: string | null;
};

export type LiveIncident = {
  incident_id: number;
  status: string;
  source_asset_id: number | null;
  current_asset_id: number;
  target_asset_id: number | null;
  technique_id: string | null;
  confidence: number;
  current_step: number;
  total_steps: number;
  started_at: string | null;
  last_seen: string | null;
  trigger: string | null;
  steps: IncidentStep[];
};

export type Alert = {
  id: number;
  source_ip: string;
  destination_ip: string;
  source_asset_id?: number | null;
  destination_asset_id?: number | null;
  protocol: string | null;
  message: string;
  classification: string | null;
  priority: number | null;
  occurrence_count: number;
  first_seen: string | null;
  last_seen: string | null;
  technique_id?: string | null;
};

export type LiveStats = {
  assets: number;
  assets_up: number;
  assets_down: number;
  connections: number;
  alerts_total: number;
  alerts_24h: number;
  active_incidents: number;
  attack_paths: number;
  max_path_score: number;
  avg_risk: number;
  max_risk: number;
};

export type LiveState = {
  type: "state_update";
  generated_at: string;
  last_scan_at: string | null;
  assets: LiveAsset[];
  edges: { source: number; target: number; connection_type: string; protocol: string | null; port: number | null }[];
  links: LiveLink[];
  attack_paths: AttackPath[];
  active_incidents: LiveIncident[];
  recent_alerts: Alert[];
  stats: LiveStats;
};

export type IncidentSummary = {
  id: number;
  status: string;
  source_asset_id: number | null;
  current_asset_id: number | null;
  target_asset_id: number | null;
  technique_id: string | null;
  confidence: number;
  current_step: number;
  total_steps: number;
  started_at: string | null;
  last_seen: string | null;
};

export type IncidentDetail = IncidentSummary & { steps: IncidentStep[] };

export type Technique = {
  technique_id: string;
  name: string;
  tactic: string;
  description: string | null;
  platform: string | null;
};

export type ObservedTechnique = {
  technique_id: string;
  name: string;
  tactic: string;
  alerts: { alert_id: number; message: string; occurrence_count: number; confidence: number; matched_on: string | null }[];
};

export type SnapshotSummary = {
  id: number;
  captured_at: string;
  assets_count: number;
  connections_count: Record<string, number>;
  attack_paths_count: number;
  highest_path_score: number | null;
};

export type SnapshotDetail = {
  id: number;
  captured_at: string;
  assets_summary: { id: number; ip: string; asset_type: string; risk_score: number | null; status: string }[];
  connections_count: Record<string, number>;
  alerts_summary: { message: string; occurrence_count: number; priority: number | null }[];
  attack_paths_count: number;
  highest_path_score: number | null;
};

export type HypothesisType = "asset_compromised" | "new_service_exposed" | "connection_removed";

export type Hypothesis =
  | { type: "asset_compromised"; asset_id: number }
  | { type: "new_service_exposed"; asset_id: number }
  | { type: "connection_removed"; source_asset_id: number; destination_asset_id: number };

export type SimulationResult = {
  hypothesis: Hypothesis;
  paths_before_count: number;
  paths_after_count: number;
  new_paths_count: number;
  new_paths: AttackPath[];
  escalated_paths_count?: number;
  escalated_paths?: AttackPath[];
  paths_before: AttackPath[];
  paths_after: AttackPath[];
};

export type Simulation = {
  id: number;
  name: string;
  description: string | null;
  status: string;
  hypothesis: Hypothesis | null;
  result: SimulationResult | null;
  created_at: string;
  completed_at: string | null;
};
