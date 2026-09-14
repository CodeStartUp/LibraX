use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::event::SourceType;

/// Connector state. `BlindSpot` is the one that matters: a silent source looks
/// identical to a quiet network unless the SOC says otherwise out loud.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceStatus {
    #[default]
    Healthy,
    Warning,
    BlindSpot,
    Offline,
}

impl SourceStatus {
    pub fn label(self) -> &'static str {
        match self {
            SourceStatus::Healthy => "HEALTHY",
            SourceStatus::Warning => "WARNING",
            SourceStatus::BlindSpot => "BLIND SPOT",
            SourceStatus::Offline => "OFFLINE",
        }
    }
}

/// Seconds of silence before a source is treated as a blind spot rather than a
/// quiet one.
pub const DEFAULT_BLIND_SPOT_AFTER_SECS: i64 = 120;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceHealth {
    pub source_id: String,
    pub source_type: SourceType,
    /// Human-readable source name for the UI.
    pub label: String,
    /// True for simulator-backed sources. The UI must say so rather than imply a
    /// live integration exists.
    pub synthetic: bool,

    pub last_event_at: Option<DateTime<Utc>>,
    pub events_per_minute: f64,
    pub expected_rate: f64,
    /// Percentage of the fleet this source actually reports on.
    pub coverage_percent: f32,
    pub assets_reporting: u32,
    pub assets_expected: u32,
    pub error_count: u64,
    pub status: SourceStatus,

    /// Running totals behind `events_per_minute`.
    pub events_observed: u64,
    first_event_at: Option<DateTime<Utc>>,
}

impl SourceHealth {
    pub fn new(source_id: impl Into<String>, source_type: SourceType, synthetic: bool) -> Self {
        Self {
            source_id: source_id.into(),
            source_type,
            label: source_type.label().to_string(),
            synthetic,
            last_event_at: None,
            events_per_minute: 0.0,
            expected_rate: 0.0,
            coverage_percent: 100.0,
            assets_reporting: 0,
            assets_expected: 0,
            error_count: 0,
            status: SourceStatus::Offline,
            events_observed: 0,
            first_event_at: None,
        }
    }

    /// Records one received event.
    pub fn observe(&mut self, at: DateTime<Utc>) {
        self.events_observed += 1;
        self.first_event_at = Some(self.first_event_at.map_or(at, |first| first.min(at)));
        self.last_event_at = Some(self.last_event_at.map_or(at, |last| last.max(at)));
    }

    /// Recomputes the observed rate and the resulting status.
    pub fn evaluate(&mut self, now: DateTime<Utc>, blind_spot_after_secs: i64) {
        // Rate over the observed span, floored at one second so a single batch
        // does not report an absurd per-minute figure.
        if let Some(first) = self.first_event_at {
            let elapsed_secs = (now - first).num_seconds().max(1) as f64;
            self.events_per_minute = self.events_observed as f64 * 60.0 / elapsed_secs;
        }

        if self.assets_expected > 0 {
            self.coverage_percent =
                self.assets_reporting as f32 / self.assets_expected as f32 * 100.0;
        }

        let silent_for = self
            .last_event_at
            .map(|last| (now - last).num_seconds())
            .unwrap_or(i64::MAX);

        self.status = if self.last_event_at.is_none() {
            SourceStatus::Offline
        } else if silent_for >= blind_spot_after_secs {
            SourceStatus::BlindSpot
        } else if self.expected_rate > 0.0 && self.events_per_minute < self.expected_rate * 0.5 {
            SourceStatus::Warning
        } else if self.assets_expected > 0 && self.coverage_percent < 95.0 {
            // Reporting healthily, but not from everywhere it should.
            SourceStatus::Warning
        } else {
            SourceStatus::Healthy
        };
    }
}

#[cfg(test)]
mod tests {
    use chrono::Duration;

    use super::*;

    fn source() -> SourceHealth {
        SourceHealth::new("edr-campus-04", SourceType::Edr, true)
    }

    #[test]
    fn a_source_with_no_events_is_offline() {
        let mut health = source();
        health.evaluate(Utc::now(), DEFAULT_BLIND_SPOT_AFTER_SECS);
        assert_eq!(health.status, SourceStatus::Offline);
    }

    #[test]
    fn a_reporting_source_is_healthy() {
        let now = Utc::now();
        let mut health = source();
        for _ in 0..60 {
            health.observe(now);
        }
        health.evaluate(now, DEFAULT_BLIND_SPOT_AFTER_SECS);
        assert_eq!(health.status, SourceStatus::Healthy);
        assert!(health.events_per_minute > 0.0);
    }

    #[test]
    fn silence_becomes_a_blind_spot_not_a_quiet_network() {
        let now = Utc::now();
        let mut health = source();
        health.observe(now - Duration::minutes(10));
        health.evaluate(now, DEFAULT_BLIND_SPOT_AFTER_SECS);
        assert_eq!(health.status, SourceStatus::BlindSpot);
    }

    #[test]
    fn partial_fleet_coverage_is_a_warning() {
        let now = Utc::now();
        let mut health = source();
        health.observe(now);
        health.assets_reporting = 9_871;
        health.assets_expected = 10_482;

        health.evaluate(now, DEFAULT_BLIND_SPOT_AFTER_SECS);

        assert_eq!(health.status, SourceStatus::Warning);
        assert!((health.coverage_percent - 94.2).abs() < 0.1);
    }

    #[test]
    fn a_rate_far_below_expectation_is_a_warning() {
        let now = Utc::now();
        let mut health = source();
        health.observe(now);
        health.expected_rate = 10_000.0;

        health.evaluate(now, DEFAULT_BLIND_SPOT_AFTER_SECS);
        assert_eq!(health.status, SourceStatus::Warning);
    }

    #[test]
    fn synthetic_sources_are_flagged_as_such() {
        assert!(source().synthetic, "the UI must be able to say so");
    }
}
