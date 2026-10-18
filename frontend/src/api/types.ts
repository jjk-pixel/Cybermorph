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

export type CriticalityLevel = "low" | "medium" | "high" | "critical";

/* Criticité retenue : déclarée par l'opérateur (prime toujours) ou inférée de faits observés. */
export type Criticality = {
  level: CriticalityLevel;
  source: "declared" | "inferred";
  confidence: number;
  reasons: string[];
};

/* Classification automatique : chaque règle appliquée est une preuve, pour ou contre le type retenu. */
export type Classification = {
  type: string;
  confidence: number;
  reasons: { reason: string; source: string; supports: boolean }[];
  alternatives: { type: string; reasons: string[] }[];
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
  asset_type_source: "declared" | "inferred";
  classification: Classification | null;
  criticality: Criticality;
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
  choke_points: ChokePoint[];
  active_incidents: LiveIncident[];
  recent_alerts: Alert[];
  stats: LiveStats;
};

/* ---- Exposition (lot 1) ---- */

export type ChokePoint = {
  asset_id: number;
  paths: number;
  share: number;
  score_sum: number;
  max_score: number;
  targets: number[];
  sources: number[];
};

export type EntryKind = "incident" | "ids_alert_source" | "dangerous_service" | "assumed";
export type EntryFact = { kind: EntryKind; label: string; detail: string | null };

export type Recommendation = {
  kind: "edge" | "node";
  source_asset_id?: number;
  destination_asset_id?: number;
  asset_id?: number;
  action: string;
  rationale: string;
  paths_removed: number;
  paths_remaining: number;
  score_reduction: number;
  score_reduction_pct: number;
  max_score_after: number;
  targets_protected: number[];
};

export type ExposureTarget = {
  asset_id: number;
  criticality: Criticality;
  why_target: string;
  paths: number;
  max_score: number;
  qualified_entries: number[];
};

export type Exposure = {
  generated_at: string;
  parameters: { min_score: number; max_length: number };
  summary: {
    paths: number;
    total_score: number;
    max_score: number;
    targets: number;
    targets_reached: number;
    qualified_entry_points: number;
    paths_from_qualified_entries: number;
  };
  targets: ExposureTarget[];
  entry_points: { asset_id: number; facts: EntryFact[]; paths: number; max_score: number }[];
  choke_points: ChokePoint[];
  recommendations: Recommendation[];
  paths: (AttackPath & { entry: EntryFact[] })[];
  assumptions: string[];
};

export type BlastRadius = {
  asset_id: number;
  hypothesis: string;
  reachable: {
    asset_id: number;
    criticality: CriticalityLevel | null;
    critical: boolean;
    score: number;
    hops: number;
    nodes: number[];
    evidence_level: EvidenceLevel;
  }[];
  reachable_count: number;
  critical_reachable: number;
  unreachable: number[];
};

export type AssetDeclaration = {
  criticality?: CriticalityLevel | null;
  criticality_reason?: string | null;
  asset_type?: string | null;
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

