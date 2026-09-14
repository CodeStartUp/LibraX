// Mirrors the JSON the API serves. Kept hand-written and narrow so a shape
// change surfaces as a type error rather than a blank panel.

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Exposure = 'confirmed' | 'reachable' | 'potential';
export type AssertionKind = 'fact' | 'inference' | 'unknown';

export interface Health {
  status: string;
  service: string;
  version: string;
  demo_mode: boolean;
  uptime_seconds: number;
  attack_dataset: string;
  detectors: number;
}

export interface Dashboard {
  hospitals: number;
  endpoints: number;
  assets: number;
  identities: number;
  events_received: number;
  events_rejected: number;
  events_unsupported: number;
  events_retained: number;
  events_per_minute: number;
  signals_total: number;
  signals_by_severity: Record<Severity, number>;
  incidents_total: number;
  incidents_critical: number;
  top_incident: { incident_id: string; title: string; overall_risk: number; severity: Severity } | null;
  reduction: {
    events: number;
    signals: number;
    incidents: number;
    critical_incidents: number;
    events_per_incident: number | null;
  };
  sources_total: number;
  sources_healthy: number;
  sources_warning: number;
  sources_blind_spot: number;
  edr_coverage_percent: number;
  demo_mode: boolean;
  last_ingest_at: string | null;
}

export interface IncidentSummary {
  incident_id: string;
  title: string;
  status: string;
  severity: Severity;
  overall_risk: number;
  threat_confidence: number;
  business_impact: number;
  blast_radius_level: Severity;
  signal_count: number;
  evidence_count: number;
  tactics: string[];
  first_seen: string;
  last_seen: string;
  duration_minutes: number;
}

export interface EntityRef {
  kind: string;
  id: string;
  name: string;
}

export interface RiskContribution {
  factor: string;
  points: number;
  detail: string;
}

export interface RiskScore {
  threat_confidence: number;
  business_impact: number;
  attack_progression: number;
  overall_risk: number;
  contributions: RiskContribution[];
}

export interface AffectedAsset {
  entity: EntityRef;
  exposure: Exposure;
  criticality: number;
  hospital: string | null;
  reason: string;
}

export interface BlastRadius {
  users: number;
  endpoints: number;
  servers: number;
  critical_databases: number;
  pacs_systems: number;
  potentially_reachable: number;
  level: Severity;
  assets: AffectedAsset[];
}

export interface Evidence {
  event_id: string;
  source_type: string;
  timestamp: string;
  severity: Severity;
  summary: string;
  cited_by: string[];
}

export interface Relationship {
  from: EntityRef;
  relation: string;
  to: EntityRef;
  confidence: number;
  first_seen: string;
  last_seen: string;
  evidence_event_ids: string[];
}

export interface MitreTechniqueRef {
  technique_id: string;
  name: string;
  tactic: string;
  confidence: number;
  rationale: string;
}

export interface Incident {
  incident_id: string;
  title: string;
  status: string;
  signals: string[];
  evidence: Evidence[];
  entities: EntityRef[];
  relationships: Relationship[];
  risk: RiskScore;
  blast_radius: BlastRadius;
  mitre_techniques: MitreTechniqueRef[];
  unknowns: string[];
  first_seen: string;
  last_seen: string;
  owner: string | null;
  notes: string[];
  // Added by the detail endpoint.
  correlation_reasons: string[];
  unmapped_techniques: string[];
  graph_node_count: number;
  graph_edge_count: number;
}

export interface GraphNode {
  id: string;
  kind: string;
  kind_label: string;
  label: string;
  exposure: Exposure;
  criticality: number | null;
  hospital: string | null;
  external: boolean;
  event_count: number;
  first_seen: string;
  last_seen: string;
}

export interface GraphEdge {
  id: string;
  from: string;
  to: string;
  relation: string;
  label: string;
  confidence: number;
  first_seen: string;
  last_seen: string;
  evidence_event_ids: string[];
  signal_ids: string[];
  structural: boolean;
}

export interface AttackGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface TimelineEntry {
  event_id: string;
  timestamp: string;
  time: string;
  source: string;
  severity: Severity;
  summary: string;
  cited_by: string[];
}

export interface Timeline {
  incident_id: string;
  first_seen: string;
  last_seen: string;
  duration_minutes: number;
  entries: TimelineEntry[];
}

export interface ProgressionStage {
  tactic: string;
  tactic_id: string;
  label: string;
  status: 'observed' | 'not_observed';
  techniques: MitreTechniqueRef[];
}

export interface MitreResponse {
  incident_id: string;
  attack_version: string;
  dataset: string;
  techniques: MitreTechniqueRef[];
  unmapped: string[];
  stages: ProgressionStage[];
  observed_stages: number;
  total_stages: number;
  furthest: string | null;
  score: number;
}

export interface Statement {
  assertion: AssertionKind;
  label: string;
  text: string;
  evidence_event_ids: string[];
}

export interface Briefing {
  incident_id: string;
  generator: string;
  summary: Statement[];
  risk_explanation: Statement[];
  evidence_explanation: Statement[];
  unknowns: Statement[];
  investigation_guidance: Statement[];
  response_suggestion: Statement[];
}

export interface ResponseAction {
  action_id: string;
  kind: string;
  target: EntityRef;
  incident_id: string;
  confidence: number;
  rationale: string;
  requires_approval: boolean;
  status: 'recommended' | 'awaiting_approval' | 'simulated' | 'declined';
  created_at: string;
  simulated_at: string | null;
  result: string | null;
}

export interface ResponseListing {
  incident_id: string;
  playbooks: string[];
  simulation_only: boolean;
  actions: ResponseAction[];
}

export interface SourceHealth {
  source_id: string;
  source_type: string;
  label: string;
  synthetic: boolean;
  last_event_at: string | null;
  events_per_minute: number;
  expected_rate: number;
  coverage_percent: number;
  assets_reporting: number;
  assets_expected: number;
  error_count: number;
  status: 'healthy' | 'warning' | 'blind_spot' | 'offline';
  status_label: string;
  events_observed: number;
}

export interface SourceHealthResponse {
  total: number;
  all_synthetic: boolean;
  sources: SourceHealth[];
}
