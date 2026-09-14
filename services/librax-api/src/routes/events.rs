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

#[derive(Debug, Deserialize)]
pub struct EventSearchQuery {
    /// Free text, matched against the message, activity, entities and addresses.
    pub q: Option<String>,
    pub source_type: Option<String>,
    pub source_id: Option<String>,
    pub min_severity: Option<String>,
    pub host: Option<String>,
    pub user: Option<String>,
    pub process: Option<String>,
    pub hospital: Option<String>,
    /// Only events that ended up as evidence behind a detection.
    pub evidence_only: Option<bool>,
    pub limit: Option<usize>,
}

/// One row in the event search results.
#[derive(Serialize)]
pub struct EventRow {
    pub event_id: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub source_type: String,
    pub source_id: String,
    pub category: String,
    pub activity: String,
    pub severity: Severity,
    pub user: Option<String>,
    pub host: Option<String>,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub process: Option<String>,
    pub command_line: Option<String>,
    pub sha256: Option<String>,
    pub md5: Option<String>,
    pub hospital: Option<String>,
    pub message: String,
    /// Detections this event is evidence for, so a row can be pivoted from.
    pub signal_ids: Vec<String>,
}

#[derive(Serialize)]
pub struct EventSearchResponse {
    pub total_retained: usize,
    pub matched: usize,
    pub returned: usize,
    pub events: Vec<EventRow>,
}

/// Full-text and faceted search over retained telemetry.
///
/// This is the log view an analyst falls back to when the correlated story is not
/// enough, which is why it filters on the same facets the pipeline enriches with
/// rather than on raw vendor field names.
pub async fn search(
    State(state): State<SharedState>,
    Query(query): Query<EventSearchQuery>,
) -> ApiResult<Json<EventSearchResponse>> {
    let floor = match query.min_severity.as_deref() {
        None => Severity::Info,
        Some(raw) => parse_severity(raw)?,
    };
    let limit = query.limit.unwrap_or(200).min(2_000);

    let needle = query.q.as_deref().map(str::to_lowercase);
    let lower = |value: &Option<String>| value.as_deref().map(str::to_lowercase);
    let want_source_type = lower(&query.source_type);
    let want_source_id = lower(&query.source_id);
    let want_host = lower(&query.host);
    let want_user = lower(&query.user);
    let want_process = lower(&query.process);
    let want_hospital = lower(&query.hospital);
    let evidence_only = query.evidence_only.unwrap_or(false);

    Ok(Json(state.read(|soc| {
        let contains = |value: Option<&str>, want: &Option<String>| match want {
            None => true,
            Some(want) => value.is_some_and(|v| v.to_lowercase().contains(want)),
        };

        let mut rows: Vec<EventRow> = Vec::new();
        let mut matched = 0usize;

        // Newest first, and stop building rows once the page is full: the window
        // holds tens of thousands of events and the analyst asked for one page.
        for event in soc.events.iter().rev() {
            if event.severity < floor {
                continue;
            }

            let source_type = format!("{:?}", event.source_type).to_lowercase();
            if want_source_type.as_ref().is_some_and(|w| &source_type != w) {
                continue;
            }
            if !contains(Some(&event.source_id), &want_source_id)
                || !contains(event.host_name(), &want_host)
                || !contains(event.user(), &want_user)
                || !contains(event.process_name(), &want_process)
                || !contains(event.enrichment.hospital.as_deref(), &want_hospital)
            {
                continue;
            }

            if let Some(needle) = &needle {
                if !matches_text(event, needle) {
                    continue;
                }
            }

            let signal_ids: Vec<String> = soc
                .signals
                .iter()
                .filter(|s| s.evidence_event_ids.contains(&event.event_id))
                .map(|s| s.signal_id.clone())
                .collect();

            if evidence_only && signal_ids.is_empty() {
                continue;
            }

            matched += 1;
            if rows.len() < limit {
                rows.push(row(event, signal_ids));
            }
        }

        EventSearchResponse {
            total_retained: soc.events.len(),
            matched,
            returned: rows.len(),
            events: rows,
        }
    })))
}

fn row(event: &librax_types::CanonicalEvent, signal_ids: Vec<String>) -> EventRow {
    EventRow {
        event_id: event.event_id.clone(),
        timestamp: event.timestamp,
        source_type: format!("{:?}", event.source_type),
        source_id: event.source_id.clone(),
        category: format!("{:?}", event.category),
        activity: event.activity.clone(),
        severity: event.severity,
        user: event.user().map(str::to_string),
        host: event.host_name().map(str::to_string),
        src_ip: event.src_ip().map(str::to_string),
        dst_ip: event.dst_ip().map(str::to_string),
        process: event.process_name().map(str::to_string),
        command_line: event.process.as_ref().and_then(|p| p.command_line.clone()),
        sha256: event.process.as_ref().and_then(|p| p.hash_sha256.clone()),
        md5: event.process.as_ref().and_then(|p| p.hash_md5.clone()),
        hospital: event.enrichment.hospital.clone(),
        message: event.message.clone(),
        signal_ids,
    }
}

/// Free-text match across the fields an analyst would paste into a search box.
fn matches_text(event: &librax_types::CanonicalEvent, needle: &str) -> bool {
    let hit = |value: Option<&str>| value.is_some_and(|v| v.to_lowercase().contains(needle));

    if hit(Some(&event.message))
        || hit(Some(&event.activity))
        || hit(Some(&event.event_id))
        || hit(event.user())
        || hit(event.host_name())
        || hit(event.src_ip())
        || hit(event.dst_ip())
        || hit(event.process_name())
    {
        return true;
    }

    if let Some(process) = &event.process {
        if hit(process.command_line.as_deref())
            || hit(process.hash_sha256.as_deref())
            || hit(process.hash_md5.as_deref())
        {
            return true;
        }
    }

    if let Some(target) = &event.target {
        if hit(Some(&target.name)) {
            return true;
        }
    }

    // Falls through to the raw payload, so a search for a domain or an attachment
    // name works without the canonical model needing a field for each of them.
    event.attributes.values().any(|v| {
        v.as_str()
            .is_some_and(|s| s.to_lowercase().contains(needle))
    })
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
