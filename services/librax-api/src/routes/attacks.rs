//! Launching attacks against the synthetic estate.
//!
//! The analyst picks a playbook and watches it arrive. Events are delivered on a
//! timer at the playbook's own tempo (optionally accelerated), each stamped with
//! the moment it was delivered, so the incident builds up in front of them
//! instead of appearing fully formed. That is the difference between a demo and
//! a console.

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use chrono::Utc;
use librax_connectors::synthetic::attacks;
use librax_types::RawEvent;
use serde::{Deserialize, Serialize};

use crate::error::ApiError;
use crate::runs::{AttackRun, RunStatus};
use crate::state::SharedState;

/// Default playback multiplier.
///
/// A 31-minute intrusion at 20x arrives over about 90 seconds: long enough to
/// watch the graph grow, short enough that nobody is waiting.
const DEFAULT_SPEED: f64 = 20.0;

/// Longest we will sleep between two events, whatever the speed asks for.
const MAX_STEP_SECONDS: f64 = 45.0;

#[derive(Serialize)]
pub struct CatalogResponse {
    pub attacks: Vec<attacks::AttackKind>,
    pub note: String,
}

pub async fn catalog(State(state): State<SharedState>) -> Json<CatalogResponse> {
    let _ = &state;

    Json(CatalogResponse {
        attacks: attacks::catalog(),
        note: "Every playbook is synthetic telemetry describing an attack. No payload is built, \
               downloaded or executed, and nothing outside this process is touched."
            .to_string(),
    })
}

#[derive(Deserialize)]
pub struct LaunchRequest {
    pub attack_id: String,
    /// Playback multiplier; `0` delivers the whole attack immediately.
    #[serde(default)]
    pub speed: Option<f64>,
    /// Which campus to play it against. Rotates by default so repeated launches
    /// do not all land on the same site.
    #[serde(default)]
    pub campus_index: Option<usize>,
}

#[derive(Serialize)]
pub struct LaunchResponse {
    pub run: AttackRun,
    pub message: String,
}

pub async fn launch(
    State(state): State<SharedState>,
    Json(request): Json<LaunchRequest>,
) -> Result<Json<LaunchResponse>, ApiError> {
    let kind = attacks::kind(&request.attack_id).ok_or_else(|| {
        ApiError::NotFound(format!(
            "no attack playbook with id `{}`",
            request.attack_id
        ))
    })?;

    let speed = request.speed.unwrap_or(DEFAULT_SPEED).max(0.0);
    let run_index = state.read(|soc| soc.runs.len());
    let run_id = format!("RUN-{:04}", run_index + 1);

    let inventory = state.inventory_handle();
    let campus_index = request
        .campus_index
        .unwrap_or_else(|| attacks::rotate_campus(&inventory, run_index));
    // A run-specific tag keeps a relaunch distinct from the first run instead of
    // being discarded as duplicate events. The first play of the documented chain
    // keeps the documented ids so INC-0042 is reproducible.
    let tag = if request.attack_id == "multi_stage_ransomware" && run_index == 0 {
        "EVT".to_string()
    } else {
        format!("{run_id}-E")
    };

    let events = attacks::generate(
        &request.attack_id,
        &tag,
        Utc::now(),
        &inventory,
        campus_index,
    );

    if events.is_empty() {
        return Err(ApiError::BadRequest(format!(
            "playbook `{}` produced no events",
            request.attack_id
        )));
    }

    let mut run = AttackRun {
        run_id: run_id.clone(),
        attack_id: kind.id.clone(),
        name: kind.name.clone(),
        category: kind.category.clone(),
        // The documented chain is pinned to the documented site whatever campus was
        // requested, so the run record must not claim otherwise.
        campus: if request.attack_id == "multi_stage_ransomware" {
            librax_enrichment::demo::HOSPITAL.to_string()
        } else {
            attacks::campus_of(&inventory, campus_index)
        },
        severity_hint: kind.severity_hint,
        status: RunStatus::Running,
        status_label: RunStatus::Running.label().to_string(),
        launched_at: Utc::now(),
        completed_at: None,
        events_total: events.len(),
        events_delivered: 0,
        speed,
        signals_raised: Vec::new(),
        incident_ids: Vec::new(),
        event_ids: events.iter().map(|e| e.raw_id.clone()).collect(),
    };

    let message = if speed == 0.0 {
        format!("{} delivered at once against {}.", kind.name, run.campus)
    } else {
        let seconds = (kind.duration_seconds as f64 / speed).round() as i64;
        format!(
            "{} is now unfolding against {} over roughly {}s. Watch the incident queue.",
            kind.name, run.campus, seconds
        )
    };

    run = state.register_run(run);

    if speed == 0.0 {
        deliver_all(&state, &run_id, events);
    } else {
        tokio::spawn(play(Arc::clone(&state), run_id, events, speed));
    }

    Ok(Json(LaunchResponse { run, message }))
}

/// Delivers every event in one batch.
fn deliver_all(state: &SharedState, run_id: &str, mut events: Vec<RawEvent>) {
    let now = Utc::now();
    for event in &mut events {
        event.received_at = now;
    }

    let report = state.ingest(&events);
    state.with_run(run_id, |run| {
        run.events_delivered = report.accepted;
        run.mark(RunStatus::Complete);
    });
    state.attribute_run(run_id);

    tracing::info!(
        run = run_id,
        events = report.accepted,
        incidents = report.incidents,
        "attack delivered"
    );
}

/// Delivers events on a timer, preserving the gaps between them.
async fn play(state: SharedState, run_id: String, events: Vec<RawEvent>, speed: f64) {
    let mut previous = events[0].received_at;

    for (index, mut event) in events.into_iter().enumerate() {
        // The gap the playbook asked for, divided by the requested speed and
        // capped so an unhurried playbook cannot stall the console.
        let gap = (event.received_at - previous).num_milliseconds().max(0) as f64 / 1000.0;
        previous = event.received_at;

        let wait = (gap / speed).min(MAX_STEP_SECONDS);
        if index > 0 && wait > 0.0 {
            tokio::time::sleep(std::time::Duration::from_secs_f64(wait)).await;
        }

        // Stamped with the moment of delivery: the timeline should say when the
        // SOC actually saw it, not when the script imagined it.
        let raw_id = event.raw_id.clone();
        event.received_at = Utc::now();

        let report = state.ingest(std::slice::from_ref(&event));

        state.with_run(&run_id, |run| {
            run.events_delivered += report.accepted;
        });
        state.attribute_run(&run_id);

        tracing::debug!(
            run = %run_id,
            event = %raw_id,
            step = index + 1,
            "attack event delivered"
        );
    }

    state.with_run(&run_id, |run| run.mark(RunStatus::Complete));
    state.attribute_run(&run_id);

    tracing::info!(run = %run_id, "attack complete");
}

#[derive(Serialize)]
pub struct RunsResponse {
    pub total: usize,
    pub running: usize,
    pub runs: Vec<RunView>,
}

#[derive(Serialize)]
pub struct RunView {
    #[serde(flatten)]
    pub run: AttackRun,
    pub progress_percent: u8,
}

pub async fn runs(State(state): State<SharedState>) -> Json<RunsResponse> {
    state.read(|soc| {
        let running = soc
            .runs
            .iter()
            .filter(|r| r.status == RunStatus::Running)
            .count();

        Json(RunsResponse {
            total: soc.runs.len(),
            running,
            // Newest first: the analyst cares about what just happened.
            runs: soc
                .runs
                .iter()
                .rev()
                .map(|run| RunView {
                    progress_percent: run.progress_percent(),
                    run: run.clone(),
                })
                .collect(),
        })
    })
}

#[derive(Serialize)]
pub struct ResetResponse {
    pub cleared: bool,
    pub message: String,
}

/// Clears observed telemetry so the analyst can start from an empty console.
pub async fn reset(State(state): State<SharedState>) -> Json<ResetResponse> {
    state.clear_telemetry();

    tracing::info!("telemetry cleared on request");

    Json(ResetResponse {
        cleared: true,
        message: "Events, detections and incidents cleared. The estate and the indicator feed \
                  remain; launch an attack to populate the console."
            .to_string(),
    })
}
