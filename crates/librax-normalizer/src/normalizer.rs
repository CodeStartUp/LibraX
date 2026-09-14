use std::collections::{HashMap, HashSet, VecDeque};

use chrono::{DateTime, Duration, Utc};
use librax_types::{CanonicalEvent, RawEvent};
use serde::Serialize;

use crate::parsers;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectReason {
    /// Already normalized. Sources re-deliver; incidents must not double-count.
    Duplicate,
    /// Implausible clock, which usually means a broken agent.
    TimestampOutOfRange,
    MissingIdentifier,
}

#[derive(Debug, Clone, Serialize)]
pub struct Rejection {
    pub raw_id: String,
    pub source_id: String,
    pub reason: RejectReason,
    pub detail: String,
}

#[derive(Debug, Default)]
pub struct NormalizeOutcome {
    pub events: Vec<CanonicalEvent>,
    pub rejections: Vec<Rejection>,
    /// Events parsed but not understood, kept rather than dropped.
    pub unsupported: usize,
}

/// Turns raw vendor payloads into canonical events.
///
/// A malformed event never stops the pipeline: it is counted against its source
/// and normalization continues, per the failure-handling rules.
pub struct Normalizer {
    seen: HashSet<String>,
    order: VecDeque<String>,
    dedup_capacity: usize,
    future_tolerance: Duration,
    past_tolerance: Duration,
    errors_by_source: HashMap<String, u64>,
}

impl Default for Normalizer {
    fn default() -> Self {
        Self::new()
    }
}

impl Normalizer {
    pub fn new() -> Self {
        Self {
            seen: HashSet::new(),
            order: VecDeque::new(),
            // Bounded so a long-running demo cannot grow the dedup set forever.
            dedup_capacity: 500_000,
            future_tolerance: Duration::hours(24),
            past_tolerance: Duration::days(30),
            errors_by_source: HashMap::new(),
        }
    }

    pub fn normalize(&mut self, raw: &RawEvent) -> Result<CanonicalEvent, Rejection> {
        self.normalize_at(raw, Utc::now())
    }

    fn normalize_at(
        &mut self,
        raw: &RawEvent,
        now: DateTime<Utc>,
    ) -> Result<CanonicalEvent, Rejection> {
        if raw.raw_id.trim().is_empty() {
            return Err(self.reject(raw, RejectReason::MissingIdentifier, "empty raw_id"));
        }

        if raw.received_at > now + self.future_tolerance
            || raw.received_at < now - self.past_tolerance
        {
            return Err(self.reject(
                raw,
                RejectReason::TimestampOutOfRange,
                format!("timestamp {} is implausible", raw.received_at),
            ));
        }

        if self.seen.contains(&raw.raw_id) {
            return Err(self.reject(raw, RejectReason::Duplicate, "already normalized"));
        }

        self.remember(raw.raw_id.clone());
        Ok(parsers::parse(raw))
    }

    pub fn normalize_batch(&mut self, raws: &[RawEvent]) -> NormalizeOutcome {
        let now = Utc::now();
        let mut outcome = NormalizeOutcome::default();

        for raw in raws {
            match self.normalize_at(raw, now) {
                Ok(event) => {
                    if event.attributes.contains_key("librax_unsupported") {
                        outcome.unsupported += 1;
                    }
                    outcome.events.push(event);
                }
                Err(rejection) => {
                    tracing::debug!(
                        raw_id = %rejection.raw_id,
                        source = %rejection.source_id,
                        reason = ?rejection.reason,
                        "event rejected during normalization"
                    );
                    outcome.rejections.push(rejection);
                }
            }
        }

        outcome
    }

    pub fn error_count(&self, source_id: &str) -> u64 {
        self.errors_by_source.get(source_id).copied().unwrap_or(0)
    }

    pub fn total_errors(&self) -> u64 {
        self.errors_by_source.values().sum()
    }

    fn reject(
        &mut self,
        raw: &RawEvent,
        reason: RejectReason,
        detail: impl Into<String>,
    ) -> Rejection {
        *self
            .errors_by_source
            .entry(raw.source_id.clone())
            .or_insert(0) += 1;

        Rejection {
            raw_id: raw.raw_id.clone(),
            source_id: raw.source_id.clone(),
            reason,
            detail: detail.into(),
        }
    }

    fn remember(&mut self, raw_id: String) {
        if self.order.len() >= self.dedup_capacity
            && let Some(oldest) = self.order.pop_front()
        {
            self.seen.remove(&oldest);
        }
        self.order.push_back(raw_id.clone());
        self.seen.insert(raw_id);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use librax_connectors::synthetic::{TelemetryGenerator, scenario};
    use librax_enrichment::{Inventory, InventorySpec, demo};
    use librax_types::{EventCategory, SourceType};
    use serde_json::json;

    use super::*;

    fn chain_events() -> Vec<CanonicalEvent> {
        let mut normalizer = Normalizer::new();
        let raws = scenario::attack_chain(Utc::now());
        let outcome = normalizer.normalize_batch(&raws);
        assert!(
            outcome.rejections.is_empty(),
            "scripted chain must normalize cleanly: {:?}",
            outcome.rejections
        );
        outcome.events
    }

    #[test]
    fn whole_attack_chain_normalizes() {
        let events = chain_events();
        assert_eq!(events.len(), 11);
        assert!(events.iter().all(|e| !e.event_id.is_empty()));
        // Evidence must stay traceable back to the raw record.
        assert!(events.iter().all(|e| e.raw_reference.is_some()));
    }

    #[test]
    fn chain_resolves_the_story_entities() {
        let events = chain_events();

        let powershell = events.iter().find(|e| e.event_id == "EVT-03").unwrap();
        assert_eq!(powershell.user(), Some(demo::USER));
        assert_eq!(powershell.host_name(), Some(demo::ENDPOINT));
        assert_eq!(powershell.process_name(), Some("powershell.exe"));
        assert_eq!(powershell.category, EventCategory::Process);

        let beacon = events.iter().find(|e| e.event_id == "EVT-04").unwrap();
        assert_eq!(beacon.src_ip(), Some(demo::ENDPOINT_IP));
        assert_eq!(beacon.dst_ip(), Some(demo::ATTACKER_IP));

        let db = events.iter().find(|e| e.event_id == "EVT-09").unwrap();
        assert_eq!(db.target_name(), Some(demo::PATIENT_DB));
        assert_eq!(db.attribute_f64("rows_returned"), Some(184_230.0));

        let pam = events.iter().find(|e| e.event_id == "EVT-08").unwrap();
        assert_eq!(pam.target_name(), Some(demo::PRIVILEGED_ACCOUNT));
        assert_eq!(pam.host_name(), Some(demo::DB_SERVER));
    }

    #[test]
    fn behavioural_attributes_survive_normalization() {
        let events = chain_events();
        let spray = events.iter().find(|e| e.event_id == "EVT-06").unwrap();
        assert_eq!(spray.attribute_f64("failure_count"), Some(14.0));
        assert_eq!(spray.activity, "logon_failure_burst");
    }

    #[test]
    fn duplicates_are_rejected_once_seen() {
        let mut normalizer = Normalizer::new();
        let raws = scenario::attack_chain(Utc::now());

        let first = normalizer.normalize_batch(&raws);
        assert_eq!(first.events.len(), 11);

        let second = normalizer.normalize_batch(&raws);
        assert!(second.events.is_empty());
        assert_eq!(second.rejections.len(), 11);
        assert!(
            second
                .rejections
                .iter()
                .all(|r| r.reason == RejectReason::Duplicate)
        );
    }

    #[test]
    fn implausible_timestamps_are_rejected_and_counted() {
        let mut normalizer = Normalizer::new();
        let mut raw = scenario::ddos_burst(Utc::now() + Duration::days(3));
        raw.source_id = "fw-broken-clock".to_string();

        let outcome = normalizer.normalize_batch(&[raw]);
        assert!(outcome.events.is_empty());
        assert_eq!(
            outcome.rejections[0].reason,
            RejectReason::TimestampOutOfRange
        );
        assert_eq!(normalizer.error_count("fw-broken-clock"), 1);
    }

    #[test]
    fn one_bad_event_does_not_stop_the_batch() {
        let mut normalizer = Normalizer::new();
        let mut raws = scenario::attack_chain(Utc::now());
        raws[4].raw_id = String::new();

        let outcome = normalizer.normalize_batch(&raws);
        assert_eq!(outcome.events.len(), 10, "the other ten must still land");
        assert_eq!(outcome.rejections.len(), 1);
    }

    #[test]
    fn unknown_source_is_kept_and_flagged_not_dropped() {
        let mut normalizer = Normalizer::new();
        let raw = RawEvent {
            raw_id: "WEIRD-1".into(),
            source_type: SourceType::Unknown,
            source_id: "mystery-appliance".into(),
            received_at: Utc::now(),
            payload: json!({ "something": "unparseable" }),
        };

        let outcome = normalizer.normalize_batch(&[raw]);
        assert_eq!(outcome.events.len(), 1);
        assert_eq!(outcome.unsupported, 1);
        assert_eq!(outcome.events[0].activity, "unsupported_event");
    }

    #[test]
    fn high_volume_noise_normalizes_without_rejections() {
        let inventory = Arc::new(Inventory::generate(InventorySpec {
            seed: 1,
            hospitals: 18,
            endpoints: 2_000,
        }));
        let mut generator = TelemetryGenerator::new(inventory, 4);
        let raws = generator.noise_batch(5_000, Utc::now());

        let mut normalizer = Normalizer::new();
        let outcome = normalizer.normalize_batch(&raws);

        assert_eq!(outcome.events.len(), raws.len());
        assert!(outcome.rejections.is_empty());
        assert_eq!(outcome.unsupported, 0);
    }
}
