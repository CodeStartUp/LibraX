//! The LibraX API service.

use std::sync::Arc;

use librax_config::Config;
use tracing_subscriber::EnvFilter;

mod error;
mod routes;
mod runs;
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
        seed_background(&state);
    }

    // Telemetry keeps arriving for as long as the service runs, so source health,
    // event rates and blind-spot detection reflect a live stream rather than one
    // batch frozen at startup.
    tokio::spawn(background_telemetry(Arc::clone(&state)));

    let listener = tokio::net::TcpListener::bind(bind_addr)
        .await
        .unwrap_or_else(|e| panic!("could not bind {bind_addr}: {e}"));

    tracing::info!("listening on http://{bind_addr}");

    axum::serve(listener, routes::router(Arc::clone(&state)))
        .await
        .expect("server error");
}

/// Fills the retained window with ordinary hospital traffic.
///
/// No attack is seeded. The console opens on a quiet estate with live sources and
/// an empty incident queue, and the analyst launches attacks from the console --
/// watching correlation happen is the demonstration, and it does not work if the
/// incident is already sitting there when the page loads.
fn seed_background(state: &Arc<AppState>) {
    use chrono::{Duration, Utc};
    use librax_connectors::synthetic::TelemetryGenerator;

    let mut generator = TelemetryGenerator::new(state.inventory_handle(), state.config.seed);

    // Anchored in the recent past, so the console shows the shift so far rather
    // than events dated in the future.
    let noise = generator.noise_batch(
        state.config.demo_noise_events,
        Utc::now() - Duration::minutes(45),
    );
    let report = state.ingest(&noise);

    tracing::info!(
        events = report.accepted,
        signals = report.signals,
        incidents = report.incidents,
        "background telemetry ingested; queue starts empty until an attack is launched"
    );
}

/// Interval between background telemetry batches.
const TELEMETRY_INTERVAL_SECS: u64 = 10;

/// Ordinary traffic, forever.
///
/// Without this the event rates on the source-health page decay to zero and every
/// source eventually reports a blind spot, which would be a lie about a system
/// that is running perfectly well.
async fn background_telemetry(state: Arc<AppState>) {
    use librax_connectors::synthetic::TelemetryGenerator;

    let mut generator =
        TelemetryGenerator::new(state.inventory_handle(), state.config.seed ^ 0x5EED);
    let per_batch = (state.config.demo_noise_events / 60).clamp(20, 400);
    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(TELEMETRY_INTERVAL_SECS));

    loop {
        ticker.tick().await;

        let batch = generator.noise_batch(per_batch, chrono::Utc::now());
        let report = state.ingest(&batch);

        tracing::debug!(
            events = report.accepted,
            retained = report.signals,
            "background telemetry batch"
        );
    }
}
