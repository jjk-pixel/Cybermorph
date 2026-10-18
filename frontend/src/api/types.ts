/*
 * Contrats de données du backend CYBERMORPH (FastAPI).
 * Les dates arrivent en ISO 8601 ; certaines colonnes historiques sont sans fuseau
 * et doivent être lues comme UTC (voir lib/format.ts → parseDate).
 */

export type RiskItem = { label: string; raw: number; justification: string; evidence: string[] };

export type RiskContributor = {
  criterion: string;
  label: string;
  max: number;
  raw: number;
  points: number;
  items: RiskItem[];
  note: string | null;
};

export type RiskFactors = {
  risk_score: number;
  risk_level: string;
  factors: string[];
  breakdown: Record<string, number>;
  /* modèle 2 : absents des scores calculés avant le lot D */
  model_version?: number;
  computed_at?: string;
  assessment?: "potential";
  disclaimer?: string;
  contributors?: RiskContributor[];
  missing_data?: string[];
  confidence?: { value: number; reasons: string[] };
  compromise_indicators?: { incident_id: number; step: number; label: string }[];
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
export type AssetRole = { role: string; label: string; confidence: number; reasons: string[]; source: string };

export type ServiceDetail = {
  port: number;
  proto?: string;
  name?: string | null;
  product?: string | null;
  version?: string | null;
  extrainfo?: string | null;
  cpe?: string | null;
  source?: string;
};

export type Classification = {
  type: string;
  confidence: number;
  reasons: { reason: string; source: string; supports: boolean; type?: string | null; weight?: number }[];
  alternatives: { type: string; reasons: string[]; score?: number }[];
  /* modèle 2 (lot A) : type, rôles et services distincts */
  model?: number;
  decision?: "assigned" | "insufficient" | "contradictory";
  scores?: Record<string, number>;
  roles?: AssetRole[];
  services?: ServiceDetail[];
  missing?: string[];
};

export type Freshness = "fresh" | "stale" | "obsolete" | "unknown";

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
  freshness?: Freshness;
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
  details: {
    protocol: string | null;
    port: number | null;
    connection_type: string | null;
    source?: string | null;
    last_seen?: string | null;
    relation_class?: RelationClass;
    origin?: string;
    confidence?: number;
    reason?: string;
    valid_until?: string | null;
  }[];
  alert_summary: AlertSummary | null;
  /* provenance de la relation : plusieurs peuvent coexister sur une paire */
  provenance: { observed: boolean; inferred: boolean; declared: boolean; ids: boolean };
  observed_sources: string[];
  last_seen: string | null;
  confidence?: number | null;
  relation_classes?: RelationClass[];
};

export type RelationClass = "observed" | "inferred" | "declared";

export type Precondition = {
  condition: string;
  status: "satisfied" | "unmet" | "unknown" | "not_observed" | "simulated";
  evidence: string;
  alert_ids?: number[];
};

export type PathStep = {
  source: number;
  target: number;
  weight: number;
  confidence?: number | null;
  relation_classes?: RelationClass[];
  services?: number[];
  preconditions?: Precondition[];
  uncertainties?: string[];
  exploit_evidence?: string[];
  observed_activity?: boolean;
};

export type PathLimits = {
  max_length: number;
  max_paths_per_pair: number;
  max_total_paths: number;
  truncated_pairs: [number, number][];
  total_limit_reached: boolean;
  excluded_transitions: { source: number; target: number; reason: string }[];
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
  // lot F : nature du chemin et explication de chaque saut
  nature?: "observed" | "hypothetical";
  confidence?: number;
  exploitation_demonstrated?: boolean;
  uncertainties?: string[];
  steps?: PathStep[];
  simulated?: boolean;
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

export type CollectionSummary = {
  interval_minutes: number;
  last_cycle_at: string | null;
  last_cycle_status: string | null;
  late: boolean;
  failing_steps: string[];
};

export type LiveState = {
  type: "state_update";
  generated_at: string;
  last_scan_at: string | null;
  collection?: CollectionSummary;
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

export type TechniqueStatus = "observed" | "inferred" | "unconfirmed";

export type TechniqueEvidence = {
  id: number;
  event_type: "alert" | "deviation";
  event_id: number;
  status: TechniqueStatus;
  status_label: string;
  source: string;
  confidence: number;
  reason: string | null;
  observations: number;
  first_seen: string | null;
  last_seen: string | null;
  event?: { message: string; source_ip: string | null; destination_ip: string | null; priority?: number | null; kind?: string };
};

export type ObservedTechnique = {
  technique_id: string;
  name: string;
  tactic: string;
  alerts: { alert_id: number; message: string; occurrence_count: number; confidence: number; matched_on: string | null; status?: TechniqueStatus }[];
  status?: TechniqueStatus;
  status_label?: string;
  observations?: number;
  first_seen?: string | null;
  last_seen?: string | null;
  sources?: string[];
  evidence?: TechniqueEvidence[];
  reference?: string;
  note?: string;
};

export type SnapshotSummary = {
  id: number;
  captured_at: string;
  assets_count: number;
  connections_count: Record<string, number>;
  attack_paths_count: number;
  highest_path_score: number | null;
  has_state?: boolean;
};

/* État complet d'un cycle (lot 4) : absent des snapshots antérieurs. */
export type SnapshotState = {
  version: number;
  relations: { source: number; target: number; connection_type: string; protocol: string | null; port: number | null; origin: string | null; last_seen: string | null }[];
  assets: { id: number; ip: string; open_ports: string | null; os: string | null; mac: string | null; authorization: string | null; criticality: CriticalityLevel; is_scanner: boolean }[];
  paths: { nodes: number[]; score: number }[];
};

export type SnapshotDetail = {
  id: number;
  captured_at: string;
  assets_summary: { id: number; ip: string; asset_type: string; risk_score: number | null; status: string }[];
  connections_count: Record<string, number>;
  alerts_summary: { message: string; occurrence_count: number; priority: number | null }[];
  attack_paths_count: number;
  highest_path_score: number | null;
  state?: SnapshotState | null;
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

/* ---- Mémoire et traçabilité (lot 4) ---- */

export type HistoryState = {
  at: string;
  snapshot: { id: number; captured_at: string; attack_paths_count: number; highest_path_score: number | null; state: SnapshotState | null };
  inventory: Record<string, { open_ports: (number | string)[]; mac: string[]; hostname: string[]; os: string[] }>;
  communications: { id: number; src_ip: string; dst_key: string; dst_scope: string; proto: string; dst_port: number | null; app_proto: string | null; baseline_state: BaselineState }[];
  open_deviations: { id: number; kind: string; severity: ChangeSeverity; explanation: string }[];
  changes_since_previous: AssetChange[];
  coverage: { topology: boolean; observations_since: string | null; communications_since: string | null; notes: string[] };
};

export type RawLine = { path: string; offset: number; line: string };

export type AlertTrace = {
  alert: Alert & { signature_id: string | null };
  sources: {
    fast_log_first: RawLine | null;
    fast_log_last: RawLine | null;
    eve_flow_ids: number[];
    eve_last: { timestamp: string; flow_id: number; src_port: number; dest_port: number; proto: string; app_proto: string | null } | null;
    note: string | null;
  };
  mitre: { technique_id: string; name: string; tactic: string; confidence: number; matched_on: string | null }[];
  communications: (Communication & { link: string })[];
  deviations: Deviation[];
  incidents: { id: number; status: string; technique_id: string | null; confidence: number; link: string }[];
  attack_paths: { nodes: number[]; score: number; evidence_level: EvidenceLevel }[];
};

export type IncidentTrace = {
  incident: { id: number; status: string; technique_id: string | null; confidence: number };
  trigger: AlertTrace | null;
  steps: { sequence: number; source_asset_id: number; destination_asset_id: number; status: string; confidence: number; evidence_type: string | null; detected_at: string | null }[];
};

/* ---- Renforcement du moteur (lots E, G, H) ---- */

export type FindingStatus = "probable" | "uncertain" | "confirmed" | "rejected" | "not_observed";

export type VulnerabilityFinding = {
  id: number;
  asset_id: number;
  port: number | null;
  cpe: string | null;
  product: string | null;
  version: string | null;
  cve_id: string;
  source: string;
  cvss_score: number | null;
  cvss_vector: string | null;
  severity: string | null;
  description: string | null;
  references: string[];
  status: FindingStatus;
  status_reason: string | null;
  last_checked_at: string;
  validated_note: string | null;
};

export type VulnerabilitySources = {
  configured: boolean;
  sources: { name: string; available: boolean }[];
  last_run: (Record<string, unknown> & { at: string; note?: string }) | null;
};

export type CorrelationEvent = { type: "alert" | "deviation" | "change"; id: number; at: string | null; summary: string };

export type Correlation = {
  id: number;
  kind: "port_probe" | "new_service_activity" | "profile_change" | "address_activity";
  asset_id: number | null;
  ip: string | null;
  window_start: string;
  window_end: string;
  events: CorrelationEvent[];
  event_count: number;
  reasoning: string;
  relation: "temporal" | "same_target" | "same_address";
  relation_label: string;
  confidence: number;
  techniques: string[];
};

export type StepHealth = {
  collector: string;
  label: string;
  last_run_at: string | null;
  last_status: string | null;
  last_error: string | null;
  last_duration_s: number | null;
  last_success_at: string | null;
  consecutive_failures: number;
};

export type SystemHealth = {
  generated_at: string;
  status: "ok" | "degraded" | "failing";
  cycle: {
    interval_minutes: number;
    last_cycle_at: string | null;
    last_cycle_status: string | null;
    last_cycle_duration_s: number | null;
    late: boolean;
    recent: { at: string; status: string; duration_s: number | null }[];
  };
  timer: { available: boolean; active_state?: string; last_trigger?: string | null };
  last_scan: { executed_at: string | null; status: string | null; succeeded_at: string | null };
  steps: StepHealth[];
  assets: { asset_id: number; ip: string; status: string; last_seen: string | null; age_s: number | null; freshness: Freshness }[];
  issues: { severity: "info" | "warning" | "critical"; message: string; collector?: string }[];
  refresh_note: string;
};

export type RiskHistoryPoint = { computed_at: string; score: number; level: string; confidence: number | null };
