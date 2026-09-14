//! Configuration, read from the environment with usable defaults.
//!
//! Every default here is chosen so that `docker compose up` produces a working
//! demo with no `.env` file present. A malformed value logs a warning and falls
//! back rather than aborting startup, because a demo that refuses to boot over a
//! typo is worse than one running on a default.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use serde::Serialize;

/// Endpoints in the synthetic estate, matching the scenario brief.
pub const DEFAULT_ENDPOINTS: u32 = 10_482;
pub const DEFAULT_HOSPITALS: u32 = 18;
/// The demo intrusion is documented as INC-0042, so numbering starts there.
pub const DEFAULT_INCIDENT_START: u64 = 42;

#[derive(Debug, Clone, Serialize)]
pub struct Config {
    pub bind_addr: SocketAddr,
    /// Seeds the environment and the simulator so runs are reproducible.
    pub seed: u64,
    pub hospitals: u32,
    pub endpoints: u32,
    pub incident_start_number: u64,
    /// Generates and ingests the scripted intrusion at startup.
    pub demo_mode: bool,
    /// How much background noise to generate alongside it.
    pub demo_noise_events: usize,
    pub correlation_window_minutes: i64,
    /// Upper bound on the retained event window, so a long run cannot grow
    /// without limit.
    pub event_window_limit: usize,
    /// Overrides the compiled-in ATT&CK dataset.
    pub mitre_dataset_path: Option<String>,
    /// Present for future persistence; the demo runs entirely in memory.
    pub database_url: Option<String>,
    pub redis_url: Option<String>,
    pub cors_allow_origin: String,
    pub log_filter: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8080),
            seed: 42,
            hospitals: DEFAULT_HOSPITALS,
            endpoints: DEFAULT_ENDPOINTS,
            incident_start_number: DEFAULT_INCIDENT_START,
            demo_mode: true,
            demo_noise_events: 20_000,
            correlation_window_minutes: 60,
            event_window_limit: 250_000,
            mitre_dataset_path: None,
            database_url: None,
            redis_url: None,
            cors_allow_origin: "*".to_string(),
            log_filter: "info,librax=debug".to_string(),
        }
    }
}

impl Config {
    pub fn from_env() -> Self {
        let defaults = Self::default();

        Self {
            bind_addr: parse_env("LIBRAX_BIND_ADDR", defaults.bind_addr),
            seed: parse_env("LIBRAX_SEED", defaults.seed),
            hospitals: parse_env("LIBRAX_HOSPITALS", defaults.hospitals),
            endpoints: parse_env("LIBRAX_ENDPOINTS", defaults.endpoints),
            incident_start_number: parse_env(
                "LIBRAX_INCIDENT_START",
                defaults.incident_start_number,
            ),
            demo_mode: parse_env("LIBRAX_DEMO_MODE", defaults.demo_mode),
            demo_noise_events: parse_env("LIBRAX_DEMO_NOISE_EVENTS", defaults.demo_noise_events),
            correlation_window_minutes: parse_env(
                "LIBRAX_CORRELATION_WINDOW_MINUTES",
                defaults.correlation_window_minutes,
            ),
            event_window_limit: parse_env(
                "LIBRAX_EVENT_WINDOW_LIMIT",
                defaults.event_window_limit,
            ),
            mitre_dataset_path: optional_env("LIBRAX_MITRE_DATASET"),
            database_url: optional_env("DATABASE_URL"),
            redis_url: optional_env("REDIS_URL"),
            cors_allow_origin: optional_env("LIBRAX_CORS_ALLOW_ORIGIN")
                .unwrap_or(defaults.cors_allow_origin),
            log_filter: optional_env("RUST_LOG").unwrap_or(defaults.log_filter),
        }
    }
}

fn optional_env(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

/// Reads and parses a variable, falling back to `default` on absence or garbage.
fn parse_env<T>(key: &str, default: T) -> T
where
    T: std::str::FromStr + std::fmt::Debug,
{
    match optional_env(key) {
        None => default,
        Some(raw) => match raw.parse::<T>() {
            Ok(value) => value,
            Err(_) => {
                tracing::warn!(
                    key,
                    value = %raw,
                    fallback = ?default,
                    "could not parse configuration value, using default"
                );
                default
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_describe_the_documented_environment() {
        let config = Config::default();
        assert_eq!(config.hospitals, 18);
        assert_eq!(config.endpoints, 10_482);
        assert_eq!(config.incident_start_number, 42);
        assert!(config.demo_mode, "the demo must work with no configuration");
    }

    #[test]
    fn unparseable_values_fall_back_instead_of_panicking() {
        assert_eq!(parse_env::<u32>("LIBRAX_TEST_NOT_A_NUMBER", 7), 7);
    }

    #[test]
    fn blank_values_are_treated_as_absent() {
        // Docker Compose passes empty strings for unset variables.
        unsafe { std::env::set_var("LIBRAX_TEST_BLANK", "   ") };
        assert_eq!(optional_env("LIBRAX_TEST_BLANK"), None);
        unsafe { std::env::remove_var("LIBRAX_TEST_BLANK") };
    }

    #[test]
    fn values_are_read_from_the_environment() {
        unsafe { std::env::set_var("LIBRAX_TEST_SEED", "1234") };
        assert_eq!(parse_env::<u64>("LIBRAX_TEST_SEED", 42), 1234);
        unsafe { std::env::remove_var("LIBRAX_TEST_SEED") };
    }
}
