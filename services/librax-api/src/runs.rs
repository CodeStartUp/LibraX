//! Records of attacks played against the synthetic estate.
//!
//! A run is how the console stops being a canned demo: the analyst launches an
//! attack, the events arrive over time at the tempo the playbook describes, and
//! this record tracks how far through it is. The run also carries the incidents
//! it produced, so the launcher can answer the only question that matters --
//! did correlation actually notice?

use chrono::{DateTime, Utc};
use librax_types::Severity;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    /// Events are still arriving.
    Running,
    /// Every event has been delivered.
    Complete,
}

impl RunStatus {
    pub fn label(self) -> &'static str {
        match self {
            RunStatus::Running => "IN PROGRESS",
            RunStatus::Complete => "DELIVERED",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct AttackRun {
    pub run_id: String,
    pub attack_id: String,
    pub name: String,
    pub category: String,
    pub campus: String,
    pub severity_hint: Severity,

    pub status: RunStatus,
    pub status_label: String,
    pub launched_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,

    pub events_total: usize,
    pub events_delivered: usize,
    /// Playback multiplier. `1` is the playbook's own tempo; `0` means the whole
    /// attack was delivered at once.
    pub speed: f64,

    /// Detections raised by the events this run delivered.
    pub signals_raised: Vec<String>,
    /// Incidents those detections were correlated into.
    pub incident_ids: Vec<String>,
    /// Event ids this run produced, so the run is traceable to its evidence.
    pub event_ids: Vec<String>,
}

impl AttackRun {
    pub fn progress_percent(&self) -> u8 {
        if self.events_total == 0 {
            return 100;
        }
        ((self.events_delivered * 100) / self.events_total) as u8
    }

    pub fn mark(&mut self, status: RunStatus) {
        self.status = status;
        self.status_label = status.label().to_string();
        if status == RunStatus::Complete {
            self.completed_at = Some(Utc::now());
        }
    }
}
