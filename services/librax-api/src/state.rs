use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use librax_ai::{AnalystEngine, Briefing, BriefingInput, DeterministicAnalyst};
use librax_config::Config;
use librax_correlation::{CorrelationConfig, Correlator};
use librax_detection::DetectionEngine;
use librax_enrichment::{Enricher, Inventory, InventorySpec, ThreatIntel};
use librax_entities::EntityResolver;
use librax_incidents::{BuiltIncident, IncidentBuilder, IncidentContext};
use librax_mitre::MitreCatalog;
use librax_normalizer::{NormalizeOutcome, Normalizer};
use librax_response::ResponseEngine;
use librax_types::{
    CanonicalEvent, DEFAULT_BLIND_SPOT_AFTER_SECS, RawEvent, ResponseAction, SecuritySignal,
    SourceHealth,
};
use parking_lot::RwLock;

use crate::runs::{AttackRun, RunStatus};

/// Counters the dashboard reports.
#[derive(Debug, Default, Clone)]
pub struct Stats {
    pub events_received: u64,
    pub events_rejected: u64,
    pub events_unsupported: u64,
    pub started_at: Option<DateTime<Utc>>,
    pub last_ingest_at: Option<DateTime<Utc>>,
}

/// Everything mutable, behind one lock.
///
/// A single writer lock is the right trade here: ingest is batched, so lock
/// contention is low, and it keeps the pipeline's ordering guarantees obvious.
pub struct SocState {
    pub normalizer: Normalizer,
    pub resolver: EntityResolver,
    pub events: Vec<CanonicalEvent>,
    pub signals: Vec<SecuritySignal>,
    pub incidents: Vec<BuiltIncident>,
    /// Kept across passes: it remembers which case number each story already has.
    pub incident_builder: IncidentBuilder,
    pub actions: HashMap<String, ResponseAction>,
    pub source_health: HashMap<String, SourceHealth>,
    pub stats: Stats,
    /// Attacks played against the estate, newest last.
    pub runs: Vec<AttackRun>,
}

pub struct AppState {
    inner: RwLock<SocState>,
    enricher: Enricher,
    catalog: Arc<MitreCatalog>,
    detection: DetectionEngine,
    correlator: Correlator,
    intel: ThreatIntel,
    pub response: ResponseEngine,
    pub config: Config,
}

pub type SharedState = Arc<AppState>;

impl AppState {
    pub fn new(config: Config) -> Self {
        let inventory = Inventory::generate(InventorySpec {
            seed: config.seed,
            hospitals: config.hospitals as usize,
            endpoints: config.endpoints as usize,
        });
        let resolver = EntityResolver::from_inventory(&inventory);
        let enricher = Enricher::new(inventory);

        let catalog = Arc::new(MitreCatalog::load(config.mitre_dataset_path.as_deref()));

        Self {
            inner: RwLock::new(SocState {
                normalizer: Normalizer::new(),
                resolver,
                events: Vec::new(),
                signals: Vec::new(),
                incidents: Vec::new(),
                incident_builder: IncidentBuilder::starting_at(config.incident_start_number),
                actions: HashMap::new(),
                source_health: HashMap::new(),
                stats: Stats {
                    started_at: Some(Utc::now()),
                    ..Default::default()
                },
                runs: Vec::new(),
            }),
            intel: ThreatIntel::demo(),
            detection: DetectionEngine::new(Arc::clone(&catalog)),
            correlator: Correlator::new(CorrelationConfig {
                window: Duration::minutes(config.correlation_window_minutes),
                ..Default::default()
            }),
            response: ResponseEngine::new(),
            catalog,
            enricher,
            config,
        }
    }

    pub fn inventory(&self) -> &Inventory {
        self.enricher.inventory()
    }

    /// Shared handle for components that need their own reference, such as the
    /// telemetry generator.
    pub fn inventory_handle(&self) -> Arc<Inventory> {
        self.enricher.inventory_handle()
    }

    pub fn catalog(&self) -> &MitreCatalog {
        &self.catalog
    }

    pub fn intel(&self) -> &ThreatIntel {
        &self.intel
    }

    /// Adds a run record and returns it, so the caller can answer the launch
    /// request before any events have been delivered.
    pub fn register_run(&self, run: AttackRun) -> AttackRun {
        let mut state = self.inner.write();
        state.runs.push(run.clone());
        run
    }

    pub fn with_run<R>(&self, run_id: &str, f: impl FnOnce(&mut AttackRun) -> R) -> Option<R> {
        let mut state = self.inner.write();
        state.runs.iter_mut().find(|r| r.run_id == run_id).map(f)
    }

    /// Records what a run's events actually turned into.
    ///
    /// Attribution is by event id rather than by timing: two attacks running at
    /// once must not claim each other's detections.
    pub fn attribute_run(&self, run_id: &str) {
        let mut state = self.inner.write();

        let Some(index) = state.runs.iter().position(|r| r.run_id == run_id) else {
            return;
        };
        let owned: Vec<String> = state.runs[index].event_ids.clone();

        let mut signals: Vec<String> = Vec::new();
        let mut incidents: Vec<String> = Vec::new();

        for signal in &state.signals {
            if signal
                .evidence_event_ids
                .iter()
                .any(|id| owned.contains(id))
            {
                if !signals.contains(&signal.detector_id) {
                    signals.push(signal.detector_id.clone());
                }

                if let Some(built) = state
                    .incidents
                    .iter()
                    .find(|b| b.incident.signals.contains(&signal.signal_id))
                {
                    let id = built.incident.incident_id.clone();
                    if !incidents.contains(&id) {
                        incidents.push(id);
                    }
                }
            }
        }

        signals.sort();
        incidents.sort();

        let run = &mut state.runs[index];
        run.signals_raised = signals;
        run.incident_ids = incidents;
    }

    /// Clears observed telemetry while keeping the estate and the feed.
    ///
    /// The inventory is the environment, not evidence, so it survives; runs are
    /// dropped because their events no longer exist to back them.
    pub fn clear_telemetry(&self) {
        let mut state = self.inner.write();

        state.events.clear();
        state.signals.clear();
        state.incidents.clear();
        state.actions.clear();
        state.source_health.clear();
        state.normalizer = Normalizer::new();
        // Numbering restarts too, so the next attack launched opens the documented
        // case number rather than continuing from a queue nobody can see any more.
        state.incident_builder.reset();
        state.runs.retain(|r| r.status == RunStatus::Running);
        state.stats = Stats {
            started_at: state.stats.started_at,
            ..Default::default()
        };
    }

    pub fn read<R>(&self, f: impl FnOnce(&SocState) -> R) -> R {
        f(&self.inner.read())
    }

    pub fn detector_count(&self) -> usize {
        self.detection.detector_count()
    }

    /// Runs the pipeline over a batch of raw events.
    ///
    /// Detection, correlation and incident assembly all re-run over the retained
    /// window rather than incrementally. That is deliberate: signal and incident
    /// ids are derived, so a full re-run is idempotent and cannot produce
    /// duplicates, and at demo volumes it costs milliseconds.
    pub fn ingest(&self, raws: &[RawEvent]) -> IngestReport {
        let mut state = self.inner.write();

        let outcome: NormalizeOutcome = state.normalizer.normalize_batch(raws);
        let accepted = outcome.events.len();
        let rejected = outcome.rejections.len();

        state.stats.events_received += accepted as u64;
        state.stats.events_rejected += rejected as u64;
        state.stats.events_unsupported += outcome.unsupported as u64;
        state.stats.last_ingest_at = Some(Utc::now());

        let mut events = outcome.events;
        self.enricher.enrich_all(&mut events);

        record_source_health(&mut state.source_health, raws, rejected);

        state.resolver.observe(&events);
        state.events.extend(events);

        // Keep the retained window bounded, oldest first.
        if state.events.len() > self.config.event_window_limit {
            let excess = state.events.len() - self.config.event_window_limit;
            state.events.drain(0..excess);
        }

        self.recompute(&mut state);

        IngestReport {
            accepted,
            rejected,
            unsupported: outcome.unsupported,
            signals: state.signals.len(),
            incidents: state.incidents.len(),
        }
    }

    /// Re-derives signals, clusters and incidents from the retained events.
    fn recompute(&self, state: &mut SocState) {
        state.signals = self.detection.run(&state.events);

        let clusters = self.correlator.cluster(&state.signals, &state.resolver);

        let ctx = IncidentContext {
            signals: &state.signals,
            events: &state.events,
            resolver: &state.resolver,
            inventory: self.enricher.inventory(),
            catalog: &self.catalog,
        };

        // The builder lives in state because it remembers which number each story
        // already carries. Rebuilding with a fresh one would renumber the queue on
        // every batch, and the case the analyst has open would become another case.
        let built = state.incident_builder.build_all(&ctx, &clusters);
        state.incidents = built;

        // Refresh recommendations, preserving any action an analyst already acted on.
        for built in &state.incidents {
            for action in self
                .response
                .recommend(&built.incident, &built.graph)
                .into_iter()
            {
                state
                    .actions
                    .entry(action.action_id.clone())
                    .or_insert(action);
            }
        }
    }

    /// The analyst briefing for an incident.
    pub fn briefing(&self, built: &BuiltIncident) -> Briefing {
        let playbooks = self.response.matching_playbooks(&built.incident);

        DeterministicAnalyst.brief(&BriefingInput {
            incident: &built.incident,
            graph: &built.graph,
            progression: &built.progression,
            correlation_reasons: &built.correlation_reasons,
            playbooks: &playbooks,
        })
    }

    /// Mutates a stored response action.
    pub fn with_action<R>(
        &self,
        action_id: &str,
        f: impl FnOnce(&mut ResponseAction) -> R,
    ) -> Option<R> {
        let mut state = self.inner.write();
        state.actions.get_mut(action_id).map(f)
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct IngestReport {
    pub accepted: usize,
    pub rejected: usize,
    pub unsupported: usize,
    pub signals: usize,
    pub incidents: usize,
}

/// Updates per-source health from what actually arrived.
fn record_source_health(
    health: &mut HashMap<String, SourceHealth>,
    raws: &[RawEvent],
    rejected: usize,
) {
    let now = Utc::now();

    for raw in raws {
        health
            .entry(raw.source_id.clone())
            .or_insert_with(|| {
                // Everything in this build is simulator-backed, and says so.
                SourceHealth::new(raw.source_id.clone(), raw.source_type, true)
            })
            .observe(now);
    }

    if rejected > 0 {
        // Attribute rejections to the sources present in this batch.
        let sources: Vec<String> = raws.iter().map(|r| r.source_id.clone()).collect();
        for source_id in sources.iter().take(rejected) {
            if let Some(entry) = health.get_mut(source_id) {
                entry.error_count += 1;
            }
        }
    }

    for entry in health.values_mut() {
        entry.evaluate(now, DEFAULT_BLIND_SPOT_AFTER_SECS);
    }
}
