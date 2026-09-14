use axum::Json;
use axum::extract::{Path, State};
use librax_ai::Briefing;
use librax_graph::AttackGraph;
use librax_mitre::Progression;
use librax_response::ResponseError;
use librax_types::{
    BlastRadius, Evidence, Incident, MitreTechniqueRef, ResponseAction, RiskScore, Severity,
};
use serde::{Deserialize, Serialize};

use crate::error::{ApiError, ApiResult};
use crate::state::SharedState;


#[derive(Serialize)]
pub struct IncidentSummary {
    pub incident_id: String,
    pub title: String,
    pub status: String,
    pub severity: Severity,

    pub live: bool,
    pub overall_risk: f32,
    pub threat_confidence: f32,
    pub business_impact: f32,
    pub blast_radius_level: Severity,
    pub signal_count: usize,
    pub evidence_count: usize,
    pub tactics: Vec<String>,
    pub first_seen: chrono::DateTime<chrono::Utc>,
    pub last_seen: chrono::DateTime<chrono::Utc>,
    pub duration_minutes: i64,
}

fn summarise(incident: &Incident) -> IncidentSummary {
    IncidentSummary {
        incident_id: incident.incident_id.clone(),
        title: incident.title.clone(),
        status: incident.status.label().to_string(),
        severity: incident.severity(),
        live: incident.is_live(),
        overall_risk: incident.risk.overall_risk,
        threat_confidence: incident.risk.threat_confidence,
        business_impact: incident.risk.business_impact,
        blast_radius_level: incident.blast_radius.level,
        signal_count: incident.signals.len(),
        evidence_count: incident.evidence.len(),
        tactics: incident
            .tactics()
            .iter()
            .map(|t| t.label().to_string())
            .collect(),
        first_seen: incident.first_seen,
        last_seen: incident.last_seen,
        duration_minutes: incident.duration_minutes(),
    }
}

#[derive(Serialize)]
pub struct IncidentListResponse {
    pub total: usize,
    pub incidents: Vec<IncidentSummary>,
}


pub async fn list(State(state): State<SharedState>) -> Json<IncidentListResponse> {
    Json(state.read(|soc| {
        let mut incidents: Vec<IncidentSummary> = soc
            .incidents
            .iter()
            .map(|b| summarise(&b.incident))
            .collect();

        incidents.sort_by(|a, b| {
            b.overall_risk
                .partial_cmp(&a.overall_risk)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        IncidentListResponse {
            total: incidents.len(),
            incidents,
        }
    }))
}


fn with_incident<R>(
    state: &SharedState,
    id: &str,
    f: impl FnOnce(&librax_incidents::BuiltIncident) -> R,
) -> ApiResult<R> {
    state
        .read(|soc| {
            soc.incidents
                .iter()
                .find(|b| b.incident.incident_id.eq_ignore_ascii_case(id))
                .map(f)
        })
        .ok_or_else(|| ApiError::NotFound(format!("no incident `{id}`")))
}

#[derive(Serialize)]
pub struct IncidentDetail {
    #[serde(flatten)]
    pub incident: Incident,

    pub live: bool,

    pub severity: Severity,

    pub correlation_reasons: Vec<String>,

    pub unmapped_techniques: Vec<String>,
    pub graph_node_count: usize,
    pub graph_edge_count: usize,
}

pub async fn detail(
    State(state): State<SharedState>,
    Path(id): Path<String>,
) -> ApiResult<Json<IncidentDetail>> {
    with_incident(&state, &id, |built| {
        Json(IncidentDetail {
            live: built.incident.is_live(),
            severity: built.incident.severity(),
            incident: built.incident.clone(),
            correlation_reasons: built.correlation_reasons.clone(),
            unmapped_techniques: built.unmapped_techniques.clone(),
            graph_node_count: built.graph.node_count(),
            graph_edge_count: built.graph.edge_count(),
        })
    })
}

#[derive(Serialize)]
pub struct TimelineEntry {
    pub event_id: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub time: String,
    pub source: String,
    pub severity: Severity,
    pub summary: String,
    pub cited_by: Vec<String>,
}

#[derive(Serialize)]
pub struct TimelineResponse {
    pub incident_id: String,
    pub first_seen: chrono::DateTime<chrono::Utc>,
    pub last_seen: chrono::DateTime<chrono::Utc>,
    pub duration_minutes: i64,
    pub entries: Vec<TimelineEntry>,
}

pub async fn timeline(
    State(state): State<SharedState>,
    Path(id): Path<String>,
) -> ApiResult<Json<TimelineResponse>> {
    with_incident(&state, &id, |built| {
        let incident = &built.incident;
        Json(TimelineResponse {
            incident_id: incident.incident_id.clone(),
            first_seen: incident.first_seen,
            last_seen: incident.last_seen,
            duration_minutes: incident.duration_minutes(),
            entries: incident
                .evidence
                .iter()
                .map(|e| TimelineEntry {
                    event_id: e.event_id.clone(),
                    timestamp: e.timestamp,
                    time: e.timestamp.format("%H:%M").to_string(),
                    source: e.source_type.label().to_string(),
                    severity: e.severity,
                    summary: e.summary.clone(),
                    cited_by: e.cited_by.clone(),
                })
                .collect(),
        })
    })
}

pub async fn graph(
    State(state): State<SharedState>,
    Path(id): Path<String>,
) -> ApiResult<Json<AttackGraph>> {
    with_incident(&state, &id, |built| Json(built.graph.clone()))
}

#[derive(Serialize)]
pub struct MitreResponse {
    pub incident_id: String,
    pub attack_version: String,
    pub dataset: String,
    pub techniques: Vec<MitreTechniqueRef>,
    pub unmapped: Vec<String>,
    #[serde(flatten)]
    pub progression: Progression,
}

pub async fn mitre(
    State(state): State<SharedState>,
    Path(id): Path<String>,
) -> ApiResult<Json<MitreResponse>> {
    let attack_version = state.catalog().attack_version().to_string();
    let dataset = state.catalog().dataset_name().to_string();

    with_incident(&state, &id, |built| {
        Json(MitreResponse {
            incident_id: built.incident.incident_id.clone(),
            attack_version,
            dataset,
            techniques: built.incident.mitre_techniques.clone(),
            unmapped: built.unmapped_techniques.clone(),
            progression: built.progression.clone(),
        })
    })
}

pub async fn risk(
    State(state): State<SharedState>,
    Path(id): Path<String>,
) -> ApiResult<Json<RiskScore>> {
    with_incident(&state, &id, |built| Json(built.incident.risk.clone()))
}

pub async fn blast_radius(
    State(state): State<SharedState>,
    Path(id): Path<String>,
) -> ApiResult<Json<BlastRadius>> {
    with_incident(&state, &id, |built| {
        Json(built.incident.blast_radius.clone())
    })
}

#[derive(Serialize)]
pub struct EvidenceResponse {
    pub incident_id: String,
    pub evidence: Vec<Evidence>,
}

pub async fn evidence(
    State(state): State<SharedState>,
    Path(id): Path<String>,
) -> ApiResult<Json<EvidenceResponse>> {
    with_incident(&state, &id, |built| {
        Json(EvidenceResponse {
            incident_id: built.incident.incident_id.clone(),
            evidence: built.incident.evidence.clone(),
        })
    })
}

pub async fn briefing(
    State(state): State<SharedState>,
    Path(id): Path<String>,
) -> ApiResult<Json<Briefing>> {
    let built_briefing = with_incident(&state, &id, |built| state.briefing(built))?;
    Ok(Json(built_briefing))
}

#[derive(Serialize)]
pub struct ResponseListing {
    pub incident_id: String,
    pub playbooks: Vec<String>,

    pub simulation_only: bool,
    pub actions: Vec<ResponseAction>,
}

pub async fn responses(
    State(state): State<SharedState>,
    Path(id): Path<String>,
) -> ApiResult<Json<ResponseListing>> {
    let playbooks: Vec<String> = with_incident(&state, &id, |built| {
        state
            .response
            .matching_playbooks(&built.incident)
            .into_iter()
            .map(str::to_string)
            .collect()
    })?;

    Ok(Json(state.read(|soc| {
        let mut actions: Vec<ResponseAction> = soc
            .actions
            .values()
            .filter(|a| a.incident_id.eq_ignore_ascii_case(&id))
            .cloned()
            .collect();

        actions.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.action_id.cmp(&b.action_id))
        });

        ResponseListing {
            incident_id: id.clone(),
            playbooks,
            simulation_only: true,
            actions,
        }
    })))
}

#[derive(Debug, Deserialize)]
pub struct SimulateRequest {
    pub action_id: String,

    pub approved_by: Option<String>,
}

#[derive(Serialize)]
pub struct SimulateResponse {
    pub action: ResponseAction,
    pub narrative: String,
    pub approved_by: Option<String>,
    pub simulation_only: bool,
}


pub async fn simulate(
    State(state): State<SharedState>,
    Path(id): Path<String>,
    Json(request): Json<SimulateRequest>,
) -> ApiResult<Json<SimulateResponse>> {

    with_incident(&state, &id, |_| ())?;

    let outcome = state
        .with_action(&request.action_id, |action| {
            state
                .response
                .simulate(action, request.approved_by.as_deref())
        })
        .ok_or_else(|| ApiError::NotFound(format!("no action `{}`", request.action_id)))?;

    match outcome {
        Ok(outcome) => Ok(Json(SimulateResponse {
            action: outcome.action,
            narrative: outcome.narrative,
            approved_by: outcome.approved_by,
            simulation_only: true,
        })),
        Err(ResponseError::ApprovalRequired { action_id }) => {
            Err(ApiError::ApprovalRequired(format!(
                "`{action_id}` is destructive; resend with `approved_by` naming the approving analyst"
            )))
        }
        Err(error @ (ResponseError::AlreadySimulated { .. } | ResponseError::Declined { .. })) => {
            Err(ApiError::Conflict(error.to_string()))
        }
    }
}
