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
  authorization: "authorized" | "unauthorized" | null;
  is_scanner: boolean;
  open_deviations: number;
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
  details: { protocol: string | null; port: number | null; connection_type: string | null; source?: string | null; last_seen?: string | null }[];
  alert_summary: AlertSummary | null;
  /* provenance de la relation : plusieurs peuvent coexister sur une paire */
  provenance: { observed: boolean; inferred: boolean; declared: boolean; ids: boolean };
  observed_sources: string[];
  last_seen: string | null;
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
  unauthorized_assets: number;
  changes_24h: number;
  open_deviations: number;
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
  recent_changes: LiveChange[];
  open_deviations: LiveDeviation[];
  stats: LiveStats;
};

export type LiveDeviation = {
  id: number;
  kind: string;
  severity: ChangeSeverity;
  src_asset_id: number | null;
  dst_asset_id: number | null;
  src_ip: string | null;
  dst_ip: string | null;
  explanation: string;
  last_seen: string;
  occurrences: number;
};

export type LiveChange = {
  id: number;
  asset_id: number | null;
  ip: string | null;
  change_type: string;
  severity: ChangeSeverity;
  explanation: string;
  detected_at: string;
  acknowledged: boolean;
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
  authorization?: "authorized" | "unauthorized" | null;
  is_scanner?: boolean | null;
  scanner_reason?: string | null;
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

/* ---- Inventaire et identités (lot 2) ---- */

export type ChangeSeverity = "info" | "notice" | "warning";

export type Identifier = {
  attribute: "mac" | "vendor" | "os" | "hostname";
  value: string;
  sources: string[];
  first_seen: string;
  last_seen: string;
  current: boolean;
};

export type Identity = {
  confidence: number;
  reasons: string[];
  name: { value: string; sources: string[]; observed: boolean } | null;
  identifiers: Identifier[];
  open_conflicts: number;
};

export type InventoryEntry = {
  id: number;
  ip: string;
  name: string;
  asset_type: string;
  status: string;
  authorization: "authorized" | "unauthorized" | null;
  authorization_source: "learning" | "declared" | null;
  is_scanner: boolean;
  scanner_reason: string | null;
  first_seen: string | null;
  last_seen: string | null;
  identity: Identity;
  observation_count: number;
  changes_24h: number;
};

export type LearningWindow = { started_at: string; ends_at: string; hours: number; in_learning: boolean };

export type Inventory = {
  learning: LearningWindow;
  assets: InventoryEntry[];
  stats: { assets: number; unauthorized: number; pending: number; scanners: number; conflicts: number; new_24h: number; changes_24h: number };
};

export type AssetChange = {
  id: number;
  asset_id: number | null;
  ip: string | null;
  change_type: string;
  attribute: string | null;
  old_value: string | null;
  new_value: string | null;
  source: string | null;
  source_label: string | null;
  severity: ChangeSeverity;
  explanation: string;
  evidence: Record<string, unknown> | null;
  detected_at: string;
  acknowledged_at: string | null;
};

export type Observation = {
  id: number;
  source: string;
  source_label: string;
  attribute: string;
  value: string;
  first_seen: string;
  last_seen: string;
  seen_count: number;
  retired_at: string | null;
};

export type InventoryDetail = {
  asset_id: number;
  ip: string;
  identity: Identity;
  observations: Observation[];
  changes: AssetChange[];
};

/* ---- Comportement (lot 3) ---- */

export type BaselineState = "baseline" | "new" | "accepted";

export type Communication = {
  id: number;
  src_ip: string;
  dst_key: string;
  dst_scope: "local" | "routed" | "external" | "multicast" | "broadcast" | "link-local";
  src_asset_id: number | null;
  dst_asset_id: number | null;
  proto: string;
  dst_port: number | null;
  app_proto: string | null;
  first_seen: string;
  last_seen: string;
  flow_count: number;
  established_count: number;
  bytes_toserver: number;
  bytes_toclient: number;
  baseline_state: BaselineState;
  learned_via: string | null;
  details: { destinations?: string[]; sni?: string[]; flow_ids?: number[] };
};

export type Deviation = {
  id: number;
  kind: "new_communication" | "port_scan" | "host_sweep" | "unknown_host" | string;
  severity: ChangeSeverity;
  status: "open" | "acknowledged" | "learned";
  src_ip: string | null;
  dst_ip: string | null;
  src_asset_id: number | null;
  dst_asset_id: number | null;
  communication_id: number | null;
  explanation: string;
  reasons: string[];
  evidence: { alert_ids?: number[]; flow_ids?: number[]; similar_communication_id?: number; ports_sample?: number[]; distinct_ports?: number };
  first_seen: string;
  last_seen: string;
  occurrences: number;
  reviewed_at: string | null;
};

export type BehaviorSummary = {
  learning: LearningWindow;
  asset_learning_hours: number;
  sensor: {
    path: string;
    healthy: boolean;
    last_run: (Record<string, number | string | boolean> & { at: string; error?: string }) | null;
    thresholds: { port_scan_ports: number; host_sweep_hosts: number };
  };
  communications: Record<BaselineState, number>;
  deviations: Record<"open" | "acknowledged" | "learned", number>;
  method: string[];
};

