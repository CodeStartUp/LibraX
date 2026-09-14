//! Deterministic synthetic telemetry for the demo environment.

pub mod attacks;
pub mod scenario;

use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use librax_enrichment::{Asset, AssetRole, Identity, Inventory};
use librax_types::{RawEvent, SourceType, SplitMix64};
use parking_lot::Mutex;
use serde_json::json;

use crate::connector::{Connector, ConnectorError, ConnectorHealth};

/// Benign domains the hospital fleet legitimately talks to.
const BENIGN_DOMAINS: &[&str] = &[
    "update.microsoft.com",
    "epic-emr.internal",
    "pacs-archive.internal",
    "outlook.office365.com",
    "pharmacy-api.partner.example",
];

/// Routine software on the fleet, taken from the indicator feed's own table.
///
/// Real hashes matter here: without them the file explorer shows the whole estate
/// as UNKNOWN, and an analyst cannot tell "nobody has assessed this" apart from
/// "the sensor did not report what it was".
use librax_enrichment::FLEET_SOFTWARE as BENIGN_PROCESSES;

/// Generates the background noise the SOC normally swims in, plus the scripted
/// intrusion. Reproducible: same seed, same events, every run.
pub struct TelemetryGenerator {
    inventory: Arc<Inventory>,
    rng: SplitMix64,
    sequence: u64,
    workstations: Vec<usize>,
    servers: Vec<usize>,
    databases: Vec<usize>,
    pacs: Vec<usize>,
}

impl TelemetryGenerator {
    pub fn new(inventory: Arc<Inventory>, seed: u64) -> Self {
        let index_of = |pred: fn(&Asset) -> bool| -> Vec<usize> {
            inventory
                .assets
                .iter()
                .enumerate()
                .filter(|(_, a)| pred(a))
                .map(|(i, _)| i)
                .collect()
        };

        Self {
            workstations: index_of(|a| a.role == AssetRole::Workstation),
            servers: index_of(|a| {
                matches!(
                    a.role,
                    AssetRole::Server | AssetRole::DomainController | AssetRole::CloudWorkload
                )
            }),
            databases: index_of(|a| a.role == AssetRole::Database),
            pacs: index_of(|a| a.role == AssetRole::Pacs),
            inventory,
            rng: SplitMix64::new(seed),
            sequence: 0,
        }
    }

    fn next_id(&mut self) -> String {
        self.sequence += 1;
        format!("NOISE-{:07}", self.sequence)
    }

    fn pick(&mut self, pool: &[usize]) -> Option<Asset> {
        if pool.is_empty() {
            return None;
        }
        let idx = self.rng.range_usize(0, pool.len());
        pool.get(idx)
            .and_then(|&i| self.inventory.assets.get(i))
            .cloned()
    }

    fn pick_workstation(&mut self) -> Option<Asset> {
        let pool = self.workstations.clone();
        self.pick(&pool)
    }

    fn pick_server(&mut self) -> Option<Asset> {
        let pool = self.servers.clone();
        self.pick(&pool)
    }

    fn pick_database(&mut self) -> Option<Asset> {
        let pool = self.databases.clone();
        self.pick(&pool)
    }

    fn pick_pacs(&mut self) -> Option<Asset> {
        let pool = self.pacs.clone();
        self.pick(&pool)
    }

    fn pick_identity(&mut self) -> Option<Identity> {
        if self.inventory.identities.is_empty() {
            return None;
        }
        let idx = self.rng.range_usize(0, self.inventory.identities.len());
        self.inventory.identities.get(idx).cloned()
    }

    fn choose_str(&mut self, options: &[&'static str]) -> &'static str {
        let idx = self.rng.range_usize(0, options.len());
        options[idx]
    }

    /// A routine process as (name, sha256, md5), dropping the signer the feed
    /// carries but the endpoint agent reports separately.
    fn choose_process(&mut self) -> (&'static str, &'static str, &'static str) {
        let idx = self.rng.range_usize(0, BENIGN_PROCESSES.len());
        let (name, sha256, md5, _signer) = BENIGN_PROCESSES[idx];
        (name, sha256, md5)
    }

    /// `count` benign events, timestamped around `at`.
    pub fn noise_batch(&mut self, count: usize, at: DateTime<Utc>) -> Vec<RawEvent> {
        (0..count).filter_map(|_| self.noise_event(at)).collect()
    }

    fn noise_event(&mut self, at: DateTime<Utc>) -> Option<RawEvent> {
        // Jitter within the second so events do not all share a timestamp.
        let jitter = chrono::Duration::milliseconds(self.rng.range(0, 1000) as i64);
        let at = at + jitter;
        let raw_id = self.next_id();

        // Weighted mix, roughly matching the relative chattiness of real sources.
        let roll = self.rng.range(0, 1000);
        let (source_type, source_id, payload) = match roll {
            0..=339 => {
                let host = self.pick_workstation()?;
                let identity = self.pick_identity()?;
                (
                    SourceType::Firewall,
                    format!("fw-edge-{}", campus_suffix(&host)),
                    json!({
                        "action": "allow",
                        "src": host.ip,
                        "dst": "104.18.32.7",
                        "dst_domain": self.choose_str(BENIGN_DOMAINS),
                        "dport": 443,
                        "proto": "tcp",
                        "bytes_out": self.rng.range(400, 90_000),
                        "bytes_in": self.rng.range(400, 900_000),
                        "rule": "OUTBOUND-WEB",
                        "connection_count": self.rng.range(1, 6),
                        "user_hint": identity.entity.name
                    }),
                )
            }
            340..=619 => {
                let host = self.pick_workstation()?;
                let identity = self.pick_identity()?;
                let (process, sha256, md5) = self.choose_process();
                (
                    SourceType::Edr,
                    format!("edr-{}", campus_suffix(&host)),
                    json!({
                        "event_type": "process_create",
                        "device_name": host.entity.name,
                        "user_name": identity.entity.name,
                        "process_name": process,
                        "parent_process": "explorer.exe",
                        "process_cmdline": "-- routine startup --",
                        "process_sha256": sha256,
                        "process_md5": md5,
                        "signed": true,
                        "pid": self.rng.range(1000, 40_000)
                    }),
                )
            }
            620..=779 => {
                let host = self.pick_workstation()?;
                let identity = self.pick_identity()?;
                (
                    SourceType::ActiveDirectory,
                    format!("ad-{}", campus_suffix(&host)),
                    json!({
                        "EventID": 4624,
                        "TargetUserName": identity.entity.name,
                        "WorkstationName": host.entity.name,
                        "IpAddress": host.ip,
                        "LogonType": 2,
                        "failure_count": 0
                    }),
                )
            }
            780..=849 => {
                let host = self.pick_workstation()?;
                (
                    SourceType::Dns,
                    format!("dns-{}", campus_suffix(&host)),
                    json!({
                        "query": self.choose_str(BENIGN_DOMAINS),
                        "qtype": "A",
                        "client": host.ip,
                        "answer": "104.18.32.7",
                        "response_code": "NOERROR"
                    }),
                )
            }
            850..=899 => {
                let server = self.pick_server()?;
                let identity = self.pick_identity()?;
                (
                    SourceType::Server,
                    format!("srv-{}", server.entity.name.to_lowercase()),
                    json!({
                        "host": server.entity.name,
                        "event": "service_logon",
                        "user": identity.entity.name,
                        "src_ip": "10.20.0.5",
                        "service": "Scheduled Task",
                        "logon_type": 5,
                        "first_time_for_user": false,
                        "source_is_workstation": false
                    }),
                )
            }
            900..=934 => {
                let db = self.pick_database()?;
                (
                    SourceType::Database,
                    "db-ops-01".to_string(),
                    json!({
                        "instance": db.entity.name,
                        "host": db.entity.name,
                        "principal": "app.reader",
                        "statement": "SELECT id, status FROM appointments WHERE day = CURRENT_DATE",
                        "rows_returned": self.rng.range(1, 900),
                        "baseline_rows_returned": 640,
                        "duration_ms": self.rng.range(3, 400),
                        "contains_phi": false
                    }),
                )
            }
            935..=959 => {
                let pacs = self.pick_pacs()?;
                let identity = self.pick_identity()?;
                (
                    SourceType::Pacs,
                    "pacs-gateway-01".to_string(),
                    json!({
                        "event": "study_accessed",
                        "device": pacs.entity.name,
                        "modality": "CT",
                        "user": identity.entity.name,
                        "study_count": self.rng.range(1, 5)
                    }),
                )
            }
            960..=979 => {
                let identity = self.pick_identity()?;
                (
                    SourceType::Vpn,
                    "vpn-core-01".to_string(),
                    json!({
                        "event": "session_start",
                        "user": identity.entity.name,
                        "client_ip": "203.0.113.12",
                        "client_country": "IN",
                        "previous_country": "IN",
                        "minutes_since_previous_session": self.rng.range(240, 4000),
                        "assigned_ip": "10.99.4.20",
                        "mfa_method": "push",
                        "mfa_prompts": 1,
                        "mfa_accepted_after": 1
                    }),
                )
            }
            // The remaining slice is low-grade nuisance: single failed logons and
            // blocked outbound attempts. These produce real but low-severity
            // signals, which is what the prioritisation engine has to survive.
            980..=991 => {
                let host = self.pick_workstation()?;
                let identity = self.pick_identity()?;
                (
                    SourceType::ActiveDirectory,
                    format!("ad-{}", campus_suffix(&host)),
                    json!({
                        "EventID": 4625,
                        "TargetUserName": identity.entity.name,
                        "WorkstationName": host.entity.name,
                        "IpAddress": host.ip,
                        "LogonType": 2,
                        "failure_count": 1,
                        "window_seconds": 60,
                        "distinct_accounts_targeted": 1,
                        "followed_by_success": true
                    }),
                )
            }
            _ => {
                let host = self.pick_workstation()?;
                (
                    SourceType::Firewall,
                    format!("fw-edge-{}", campus_suffix(&host)),
                    json!({
                        "action": "deny",
                        "src": host.ip,
                        "dst": "198.51.100.24",
                        "dport": 8443,
                        "proto": "tcp",
                        "bytes_out": 0,
                        "bytes_in": 0,
                        "rule": "DEFAULT-DENY",
                        "connection_count": 1
                    }),
                )
            }
        };

        Some(RawEvent {
            raw_id,
            source_type,
            source_id,
            received_at: at,
            payload,
        })
    }

    /// The scripted intrusion, plus an unrelated volumetric attack.
    pub fn attack_chain(&self, start: DateTime<Utc>) -> Vec<RawEvent> {
        scenario::attack_chain(start)
    }

    pub fn ddos_burst(&self, at: DateTime<Utc>) -> RawEvent {
        scenario::ddos_burst(at)
    }

    pub fn inventory(&self) -> &Inventory {
        &self.inventory
    }
}

fn campus_suffix(asset: &Asset) -> String {
    asset
        .hospital
        .rsplit('-')
        .next()
        .unwrap_or("01")
        .to_lowercase()
}

/// One synthetic source, exposed through the real [`Connector`] interface so the
/// SDK is genuinely exercised rather than described.
pub struct SyntheticSource {
    source_id: String,
    source_type: SourceType,
    generator: Arc<Mutex<TelemetryGenerator>>,
    events_per_collect: usize,
    state: Mutex<SourceState>,
    assets_expected: u32,
    assets_reporting: u32,
}

#[derive(Default)]
struct SourceState {
    collected: u64,
    errors: u64,
    last_event_at: Option<DateTime<Utc>>,
}

#[async_trait]
impl Connector for SyntheticSource {
    fn source_id(&self) -> &str {
        &self.source_id
    }

    fn source_type(&self) -> SourceType {
        self.source_type
    }

    fn is_synthetic(&self) -> bool {
        true
    }

    async fn health(&self) -> ConnectorHealth {
        let state = self.state.lock();
        ConnectorHealth {
            source_id: self.source_id.clone(),
            source_type: self.source_type,
            reachable: true,
            last_event_at: state.last_event_at,
            events_collected: state.collected,
            errors: state.errors,
            assets_reporting: self.assets_reporting,
            assets_expected: self.assets_expected,
            detail: Some("synthetic source".to_string()),
        }
    }

    async fn collect(&self) -> Result<Vec<RawEvent>, ConnectorError> {
        let now = Utc::now();
        let events: Vec<RawEvent> = {
            let mut generator = self.generator.lock();
            generator
                .noise_batch(self.events_per_collect * 3, now)
                .into_iter()
                .filter(|e| e.source_type == self.source_type)
                .take(self.events_per_collect)
                .collect()
        };

        let mut state = self.state.lock();
        state.collected += events.len() as u64;
        state.last_event_at = events.last().map(|e| e.received_at).or(state.last_event_at);
        Ok(events)
    }
}

/// Every synthetic source in the demo environment.
pub struct SyntheticFleet {
    sources: Vec<Arc<SyntheticSource>>,
    generator: Arc<Mutex<TelemetryGenerator>>,
}

impl SyntheticFleet {
    pub fn new(inventory: Arc<Inventory>, seed: u64) -> Self {
        let (covered, expected, _) = inventory.edr_coverage();
        let generator = Arc::new(Mutex::new(TelemetryGenerator::new(
            Arc::clone(&inventory),
            seed,
        )));

        let sources = SourceType::all()
            .iter()
            .map(|&source_type| {
                // EDR is the only source with a real coverage gap in the demo.
                let (reporting, total) = if source_type == SourceType::Edr {
                    (covered, expected)
                } else {
                    (expected, expected)
                };
                Arc::new(SyntheticSource {
                    source_id: format!(
                        "{}-synthetic",
                        source_type.label().to_lowercase().replace(' ', "-")
                    ),
                    source_type,
                    generator: Arc::clone(&generator),
                    events_per_collect: 25,
                    state: Mutex::new(SourceState::default()),
                    assets_expected: total,
                    assets_reporting: reporting,
                })
            })
            .collect();

        Self { sources, generator }
    }

    pub fn sources(&self) -> &[Arc<SyntheticSource>] {
        &self.sources
    }

    pub fn generator(&self) -> Arc<Mutex<TelemetryGenerator>> {
        Arc::clone(&self.generator)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use librax_enrichment::InventorySpec;

    use super::*;

    fn generator(seed: u64) -> TelemetryGenerator {
        let inventory = Arc::new(Inventory::generate(InventorySpec {
            seed: 7,
            hospitals: 18,
            endpoints: 2_000,
        }));
        TelemetryGenerator::new(inventory, seed)
    }

    #[test]
    fn noise_is_deterministic_for_a_seed() {
        let at = Utc::now();
        let a = generator(11).noise_batch(200, at);
        let b = generator(11).noise_batch(200, at);

        assert_eq!(a.len(), b.len());
        for (x, y) in a.iter().zip(b.iter()) {
            assert_eq!(x.raw_id, y.raw_id);
            assert_eq!(x.source_type, y.source_type);
            assert_eq!(x.payload, y.payload);
        }
    }

    #[test]
    fn noise_ids_never_collide() {
        let events = generator(3).noise_batch(5_000, Utc::now());
        let unique: HashSet<_> = events.iter().map(|e| e.raw_id.clone()).collect();
        assert_eq!(unique.len(), events.len());
    }

    #[test]
    fn noise_spreads_across_multiple_sources() {
        let events = generator(5).noise_batch(2_000, Utc::now());
        let sources: HashSet<_> = events.iter().map(|e| e.source_type).collect();
        assert!(
            sources.len() >= 6,
            "expected a heterogeneous stream, saw {sources:?}"
        );
    }

    #[test]
    fn noise_never_reuses_demo_attack_ids() {
        let events = generator(9).noise_batch(3_000, Utc::now());
        assert!(events.iter().all(|e| !e.raw_id.starts_with("EVT-")));
    }
}
