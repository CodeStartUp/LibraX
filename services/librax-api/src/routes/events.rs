use axum::Json;
use axum::extract::{Query, State};
use librax_types::{RawEvent, SecuritySignal, Severity};
use serde::{Deserialize, Serialize};

use crate::error::{ApiError, ApiResult};
use crate::state::{IngestReport, SharedState};

#[derive(Debug, Deserialize)]
pub struct EventBatch {
    pub events: Vec<RawEvent>,
}

/// Accepts a batch of raw vendor events and runs the pipeline over them.
pub async fn ingest(
    State(state): State<SharedState>,
    Json(batch): Json<EventBatch>,
) -> ApiResult<Json<IngestReport>> {
    if batch.events.is_empty() {
        return Err(ApiError::BadRequest(
            "`events` was empty; send at least one raw event".to_string(),
        ));
    }

    Ok(Json(state.ingest(&batch.events)))
}

#[derive(Debug, Deserialize)]
pub struct SignalQuery {
    /// Lowest severity to include, e.g. `high`.
    pub min_severity: Option<String>,
    pub limit: Option<usize>,
}

#[derive(Serialize)]
pub struct SignalsResponse {
    pub total: usize,
    pub returned: usize,
    pub signals: Vec<SecuritySignal>,
}

/// Detections, newest first. This is the "before correlation" view.
pub async fn signals(
    State(state): State<SharedState>,
    Query(query): Query<SignalQuery>,
) -> ApiResult<Json<SignalsResponse>> {
    let floor = match query.min_severity.as_deref() {
        None => Severity::Info,
        Some(raw) => parse_severity(raw)?,
    };
    let limit = query.limit.unwrap_or(200).min(1_000);

    Ok(Json(state.read(|soc| {
        let matching: Vec<SecuritySignal> = soc
            .signals
            .iter()
            .filter(|s| s.severity >= floor)
            .rev()
            .take(limit)
            .cloned()
            .collect();

        SignalsResponse {
            total: soc.signals.len(),
            returned: matching.len(),
            signals: matching,
        }
    })))
}

fn parse_severity(raw: &str) -> ApiResult<Severity> {
    match raw.to_ascii_lowercase().as_str() {
        "info" => Ok(Severity::Info),
        "low" => Ok(Severity::Low),
        "medium" => Ok(Severity::Medium),
        "high" => Ok(Severity::High),
        "critical" => Ok(Severity::Critical),
        other => Err(ApiError::BadRequest(format!(
            "unknown severity `{other}`; expected info, low, medium, high or critical"
        ))),
    }
}
