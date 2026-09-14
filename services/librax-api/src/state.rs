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


#[derive(Debug, Default, Clone)]
pub struct Stats {
    pub events_received: u64,
    pub events_rejected: u64,
    pub events_unsupported: u64,
    pub started_at: Option<DateTime<Utc>>,
    pub last_ingest_at: Option<DateTime<Utc>>,
}


pub struct SocState {
    pub normalizer: Normalizer,
    pub resolver: EntityResolver,
    pub events: Vec<CanonicalEvent>,
    pub signals: Vec<SecuritySignal>,
    pub incidents: Vec<BuiltIncident>,

    pub incident_builder: IncidentBuilder,
    pub actions: HashMap<String, ResponseAction>,
    pub source_health: HashMap<String, SourceHealth>,
    pub stats: Stats,

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


    pub fn inventory_handle(&self) -> Arc<Inventory> {
        self.enricher.inventory_handle()
    }

    pub fn catalog(&self) -> &MitreCatalog {
        &self.catalog
    }

    pub fn intel(&self) -> &ThreatIntel {
        &self.intel
    }


    pub fn register_run(&self, run: AttackRun) -> AttackRun {
        let mut state = self.inner.write();
        state.runs.push(run.clone());
        run
    }

    pub fn with_run<R>(&self, run_id: &str, f: impl FnOnce(&mut AttackRun) -> R) -> Option<R> {
        let mut state = self.inner.write();
        state.runs.iter_mut().find(|r| r.run_id == run_id).map(f)
    }


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


    pub fn clear_telemetry(&self) {
        let mut state = self.inner.write();

        state.events.clear();
        state.signals.clear();
        state.incidents.clear();
        state.actions.clear();
        state.source_health.clear();
        state.normalizer = Normalizer::new();


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


        let built = state.incident_builder.build_all(&ctx, &clusters);
        state.incidents = built;


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

                SourceHealth::new(raw.source_id.clone(), raw.source_type, true)
            })
            .observe(now);
    }

    if rejected > 0 {

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
