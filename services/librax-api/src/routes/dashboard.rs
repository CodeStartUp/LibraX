use axum::Json;
use axum::extract::State;
use chrono::Utc;
use librax_types::{Severity, SourceStatus};
use serde::Serialize;

use crate::state::SharedState;

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub service: &'static str,
    pub version: &'static str,
    pub demo_mode: bool,
    pub uptime_seconds: i64,
    pub attack_dataset: String,
    pub detectors: usize,
}

pub async fn health(State(state): State<SharedState>) -> Json<HealthResponse> {
    let uptime_seconds = state.read(|soc| {
        soc.stats
            .started_at
            .map(|start| (Utc::now() - start).num_seconds())
            .unwrap_or(0)
    });

    Json(HealthResponse {
        status: "ok",
        service: "librax-api",
        version: env!("CARGO_PKG_VERSION"),
        demo_mode: state.config.demo_mode,
        uptime_seconds,
        attack_dataset: format!(
            "{} v{}",
            state.catalog().dataset_name(),
            state.catalog().attack_version()
        ),
        detectors: state.detector_count(),
    })
}


#[derive(Serialize)]
pub struct DashboardResponse {
    pub hospitals: usize,
    pub endpoints: usize,
    pub assets: usize,
    pub identities: usize,

    pub events_received: u64,
    pub events_rejected: u64,
    pub events_unsupported: u64,
    pub events_retained: usize,
    pub events_per_minute: f64,

    pub signals_total: usize,
    pub signals_by_severity: SeverityBreakdown,

    pub incidents_total: usize,
    pub incidents_critical: usize,

    pub incidents_live: usize,
    pub top_incident: Option<TopIncident>,


    pub reduction: Reduction,

    pub sources_total: usize,
    pub sources_healthy: usize,
    pub sources_warning: usize,
    pub sources_blind_spot: usize,

    pub edr_coverage_percent: f32,
    pub demo_mode: bool,
    pub last_ingest_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Serialize, Default)]
pub struct SeverityBreakdown {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

#[derive(Serialize)]
pub struct TopIncident {
    pub incident_id: String,
    pub title: String,
    pub overall_risk: f32,
    pub severity: Severity,
    pub live: bool,
}

#[derive(Serialize)]
pub struct Reduction {
    pub events: u64,
    pub signals: usize,
    pub incidents: usize,
    pub critical_incidents: usize,

    pub events_per_incident: Option<u64>,
}

pub async fn dashboard(State(state): State<SharedState>) -> Json<DashboardResponse> {
    let inventory = state.inventory();
    let (covered, _expected, coverage_percent) = inventory.edr_coverage();
    let _ = covered;

    Json(state.read(|soc| {
        let mut by_severity = SeverityBreakdown::default();
        for signal in &soc.signals {
            match signal.severity {
                Severity::Critical => by_severity.critical += 1,
                Severity::High => by_severity.high += 1,
                Severity::Medium => by_severity.medium += 1,
                Severity::Low => by_severity.low += 1,
                Severity::Info => by_severity.info += 1,
            }
        }

        let critical = soc
            .incidents
            .iter()
            .filter(|b| b.incident.severity() == Severity::Critical)
            .count();

        let incidents_live = soc
            .incidents
            .iter()
            .filter(|b| b.incident.is_live())
            .count();

        let top = soc
            .incidents
            .iter()
            .max_by(|a, b| {
                a.incident
                    .risk
                    .overall_risk
                    .partial_cmp(&b.incident.risk.overall_risk)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|b| TopIncident {
                incident_id: b.incident.incident_id.clone(),
                title: b.incident.title.clone(),
                overall_risk: b.incident.risk.overall_risk,
                severity: b.incident.severity(),
                live: b.incident.is_live(),
            });


        let events_per_minute = soc
            .stats
            .started_at
            .map(|start| {
                let minutes = ((Utc::now() - start).num_seconds().max(1) as f64) / 60.0;
                soc.stats.events_received as f64 / minutes
            })
            .unwrap_or(0.0);

        let statuses = soc.source_health.values().map(|s| s.status);

        DashboardResponse {
            hospitals: inventory.hospitals.len(),
            endpoints: inventory.endpoint_count(),
            assets: inventory.assets.len(),
            identities: inventory.identities.len(),

            events_received: soc.stats.events_received,
            events_rejected: soc.stats.events_rejected,
            events_unsupported: soc.stats.events_unsupported,
            events_retained: soc.events.len(),
            events_per_minute,

            signals_total: soc.signals.len(),
            signals_by_severity: by_severity,

            incidents_total: soc.incidents.len(),
            incidents_critical: critical,
            incidents_live,
            top_incident: top,

            reduction: Reduction {
                events: soc.stats.events_received,
                signals: soc.signals.len(),
                incidents: soc.incidents.len(),
                critical_incidents: critical,
                events_per_incident: if soc.incidents.is_empty() {
                    None
                } else {
                    Some(soc.stats.events_received / soc.incidents.len() as u64)
                },
            },

            sources_total: soc.source_health.len(),
            sources_healthy: statuses
                .clone()
                .filter(|s| *s == SourceStatus::Healthy)
                .count(),
            sources_warning: statuses
                .clone()
                .filter(|s| *s == SourceStatus::Warning)
                .count(),
            sources_blind_spot: statuses
                .filter(|s| matches!(s, SourceStatus::BlindSpot | SourceStatus::Offline))
                .count(),

            edr_coverage_percent: coverage_percent,
            demo_mode: state.config.demo_mode,
            last_ingest_at: soc.stats.last_ingest_at,
        }
    }))
}
