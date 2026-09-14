//! Pushes synthetic telemetry at the API so the SOC looks live.
//!
//! The API seeds its own demo corpus at startup, so a judge sees a populated
//! console even with this service stopped. What this adds is movement: a steady
//! trickle of background events so event rates, source health and the "quiet
//! source becomes a blind spot" behaviour are driven by real traffic rather than
//! a fixed snapshot.

use std::sync::Arc;
use std::time::Duration as StdDuration;

use chrono::Utc;
use librax_config::Config;
use librax_connectors::synthetic::TelemetryGenerator;
use librax_enrichment::{Inventory, InventorySpec};
use librax_types::RawEvent;
use tracing_subscriber::EnvFilter;

struct Settings {
    api_url: String,
    events_per_second: usize,
    /// Also send the scripted intrusion. Off by default, because the API seeds
    /// it; turning this on gives a second, later intrusion.
    inject_attack: bool,
    startup_delay: StdDuration,
}

fn settings() -> Settings {
    let read = |key: &str| std::env::var(key).ok().filter(|v| !v.trim().is_empty());

    Settings {
        api_url: read("LIBRAX_API_URL").unwrap_or_else(|| "http://api:8080".to_string()),
        events_per_second: read("LIBRAX_SIMULATOR_EPS")
            .and_then(|v| v.parse().ok())
            .unwrap_or(250),
        inject_attack: read("LIBRAX_SIMULATOR_INJECT_ATTACK")
            .and_then(|v| v.parse().ok())
            .unwrap_or(false),
        startup_delay: StdDuration::from_secs(
            read("LIBRAX_SIMULATOR_STARTUP_DELAY_SECS")
                .and_then(|v| v.parse().ok())
                .unwrap_or(10),
        ),
    }
}

#[tokio::main]
async fn main() {
    let config = Config::from_env();
    let settings = settings();

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(&config.log_filter))
        .with_target(false)
        .init();

    let inventory = Arc::new(Inventory::generate(InventorySpec {
        seed: config.seed,
        hospitals: config.hospitals as usize,
        endpoints: config.endpoints as usize,
    }));
    let mut generator = TelemetryGenerator::new(Arc::clone(&inventory), config.seed);

    let client = reqwest::Client::builder()
        .timeout(StdDuration::from_secs(30))
        .build()
        .expect("http client");

    let endpoint = format!("{}/api/v1/events", settings.api_url.trim_end_matches('/'));

    tracing::info!(
        api = %endpoint,
        eps = settings.events_per_second,
        "simulator starting"
    );

    // The API generates its own inventory and seed corpus; give it time to bind
    // before the first batch, rather than failing a race at startup.
    tokio::time::sleep(settings.startup_delay).await;
    wait_for_api(&client, &settings.api_url).await;

    if settings.inject_attack {
        let chain = generator.attack_chain(Utc::now());
        match send(&client, &endpoint, &chain).await {
            Ok(()) => tracing::info!(events = chain.len(), "injected scripted intrusion"),
            Err(e) => tracing::error!(error = %e, "could not inject intrusion"),
        }
    }

    let mut ticker = tokio::time::interval(StdDuration::from_secs(1));
    let mut sent: u64 = 0;
    let mut consecutive_failures: u32 = 0;

    loop {
        ticker.tick().await;

        let batch = generator.noise_batch(settings.events_per_second, Utc::now());

        match send(&client, &endpoint, &batch).await {
            Ok(()) => {
                sent += batch.len() as u64;
                consecutive_failures = 0;
                // One line a minute, not one a second.
                if sent % (settings.events_per_second as u64 * 60).max(1) == 0 {
                    tracing::info!(total_sent = sent, "telemetry flowing");
                }
            }
            Err(e) => {
                consecutive_failures += 1;
                // A restarting API should not take the simulator down with it.
                tracing::warn!(
                    error = %e,
                    consecutive_failures,
                    "could not deliver batch, will retry"
                );
                tokio::time::sleep(StdDuration::from_secs(
                    consecutive_failures.min(10) as u64
                ))
                .await;
            }
        }
    }
}

async fn send(
    client: &reqwest::Client,
    endpoint: &str,
    events: &[RawEvent],
) -> Result<(), String> {
    let response = client
        .post(endpoint)
        .json(&serde_json::json!({ "events": events }))
        .send()
        .await
        .map_err(|e| e.to_string())?;

    if response.status().is_success() {
        Ok(())
    } else {
        Err(format!("api returned {}", response.status()))
    }
}

/// Blocks until the API answers its health check.
async fn wait_for_api(client: &reqwest::Client, base: &str) {
    let health = format!("{}/api/v1/health", base.trim_end_matches('/'));

    for attempt in 1..=60 {
        match client.get(&health).send().await {
            Ok(response) if response.status().is_success() => {
                tracing::info!("api is ready");
                return;
            }
            _ => {
                if attempt % 10 == 0 {
                    tracing::info!(attempt, "waiting for api");
                }
                tokio::time::sleep(StdDuration::from_secs(2)).await;
            }
        }
    }

    tracing::warn!("api never became ready; sending anyway");
}
