//! The LibraX API service.

use std::sync::Arc;

use librax_config::Config;
use tracing_subscriber::EnvFilter;

mod error;
mod routes;
mod state;

use state::AppState;

#[tokio::main]
async fn main() {
    let config = Config::from_env();

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(&config.log_filter))
        .with_target(false)
        .init();

    tracing::info!(
        hospitals = config.hospitals,
        endpoints = config.endpoints,
        seed = config.seed,
        demo_mode = config.demo_mode,
        "starting librax-api"
    );

    let bind_addr = config.bind_addr;
    let demo_mode = config.demo_mode;
    let state = Arc::new(AppState::new(config));

    tracing::info!(
        assets = state.inventory().assets.len(),
        identities = state.inventory().identities.len(),
        detectors = state.detector_count(),
        "environment ready"
    );

    if demo_mode {
        seed_demo(&state);
    }

    let listener = tokio::net::TcpListener::bind(bind_addr)
        .await
        .unwrap_or_else(|e| panic!("could not bind {bind_addr}: {e}"));

    tracing::info!("listening on http://{bind_addr}");

    axum::serve(listener, routes::router(Arc::clone(&state)))
        .await
        .expect("server error");
}

/// Ingests the scripted intrusion plus background noise, so a judge sees a
/// populated SOC the moment the page loads rather than an empty queue.
fn seed_demo(state: &Arc<AppState>) {
    use chrono::{Duration, Utc};
    use librax_connectors::synthetic::TelemetryGenerator;

    let noise_count = state.config.demo_noise_events;
    let mut generator = TelemetryGenerator::new(state.inventory_handle(), state.config.seed);

    // Anchored in the recent past so the timeline reads as a shift that has just
    // happened rather than events dated in the future.
    let now = Utc::now();
    let noise_at = now - Duration::minutes(45);
    let intrusion_start = now - Duration::minutes(40);

    let noise = generator.noise_batch(noise_count, noise_at);
    let report = state.ingest(&noise);
    tracing::info!(
        events = report.accepted,
        signals = report.signals,
        "background telemetry ingested"
    );

    let intrusion = generator.attack_chain(intrusion_start);
    let report = state.ingest(&intrusion);
    tracing::info!(
        events = report.accepted,
        signals = report.signals,
        incidents = report.incidents,
        "scripted intrusion ingested"
    );

    // A second, unrelated incident, so the queue shows correlation keeping
    // separate things separate.
    let ddos = generator.ddos_burst(now - Duration::minutes(15));
    let report = state.ingest(&[ddos]);
    tracing::info!(
        events = report.accepted,
        incidents = report.incidents,
        "volumetric burst ingested"
    );

    state.read(|soc| {
        for built in &soc.incidents {
            tracing::info!(
                incident = %built.incident.incident_id,
                title = %built.incident.title,
                risk = built.incident.risk.overall_risk,
                signals = built.incident.signals.len(),
                "incident built"
            );
        }
    });
}
