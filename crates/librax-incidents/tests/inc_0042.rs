

use std::sync::Arc;

use chrono::{Duration, Utc};
use librax_connectors::synthetic::{TelemetryGenerator, scenario};
use librax_correlation::Correlator;
use librax_detection::DetectionEngine;
use librax_enrichment::{Enricher, Inventory, InventorySpec, demo};
use librax_entities::EntityResolver;
use librax_incidents::{BuiltIncident, IncidentBuilder, IncidentContext};
use librax_mitre::MitreCatalog;
use librax_normalizer::Normalizer;
use librax_types::{CanonicalEvent, Exposure, RawEvent, SecuritySignal, Severity, Tactic};

struct Run {
    incidents: Vec<BuiltIncident>,
    signals: Vec<SecuritySignal>,
    events: Vec<CanonicalEvent>,
}

fn pipeline(raws: &[RawEvent]) -> Run {
    let inventory = Inventory::generate(InventorySpec {
        seed: 42,
        hospitals: 18,
        endpoints: 10_482,
    });
    let enricher = Enricher::new(inventory);

    let mut normalizer = Normalizer::new();
    let mut outcome = normalizer.normalize_batch(raws);
    enricher.enrich_all(&mut outcome.events);
    let events = outcome.events;

    let mut resolver = EntityResolver::from_inventory(enricher.inventory());
    resolver.observe(&events);

    let catalog = Arc::new(MitreCatalog::embedded());
    let signals = DetectionEngine::new(Arc::clone(&catalog)).run(&events);
    let clusters = Correlator::default().cluster(&signals, &resolver);

    let ctx = IncidentContext {
        signals: &signals,
        events: &events,
        resolver: &resolver,
        inventory: enricher.inventory(),
        catalog: &catalog,
    };
    let incidents = IncidentBuilder::default().build_all(&ctx, &clusters);

    Run {
        incidents,
        signals,
        events,
    }
}


fn full_demo() -> Run {
    let now = Utc::now();
    let inventory = Arc::new(Inventory::generate(InventorySpec {
        seed: 42,
        hospitals: 18,
        endpoints: 10_482,
    }));
    let mut generator = TelemetryGenerator::new(inventory, 7);

    let mut raws = generator.noise_batch(20_000, now);
    raws.extend(scenario::attack_chain(now));
    raws.push(scenario::ddos_burst(now + Duration::minutes(90)));

    pipeline(&raws)
}

#[test]
fn twenty_thousand_events_reduce_to_one_critical_incident() {
    let run = full_demo();

    println!(
        "events={} signals={} incidents={}",
        run.events.len(),
        run.signals.len(),
        run.incidents.len()
    );

    assert!(run.events.len() > 20_000);

    let critical: Vec<&BuiltIncident> = run
        .incidents
        .iter()
        .filter(|i| i.incident.severity() == Severity::Critical)
        .collect();
    assert_eq!(
        critical.len(),
        1,
        "exactly one case should demand attention, got {}",
        critical.len()
    );


    assert!(
        run.incidents.len() <= 2,
        "{} incidents from {} signals is not prioritisation",
        run.incidents.len(),
        run.signals.len()
    );
    assert!(
        run.signals.len() > run.incidents.len() * 5,
        "the reduction from signals to incidents should be dramatic"
    );
}

#[test]
fn the_critical_incident_is_inc_0042() {
    let run = full_demo();
    let incident = &run.incidents[0].incident;

    assert_eq!(incident.incident_id, "INC-0042");
    assert_eq!(incident.title, "Multi-Stage Healthcare Intrusion");
    assert_eq!(incident.signals.len(), 11);
    assert_eq!(incident.duration_minutes(), 31);
}


#[test]
fn a_case_keeps_its_number_when_the_queue_changes() {
    let now = Utc::now();
    let inventory = Arc::new(Inventory::generate(InventorySpec {
        seed: 42,
        hospitals: 18,
        endpoints: 10_482,
    }));

    let chain = scenario::attack_chain(now);
    let flood = scenario::ddos_burst(now + Duration::minutes(4));

    let mut builder = IncidentBuilder::default();

    let first = build_with(&mut builder, &inventory, &chain);
    let intrusion = first
        .iter()
        .find(|i| i.incident.signals.len() > 5)
        .expect("the intrusion should be a case on its own");
    let original = intrusion.incident.incident_id.clone();
    assert_eq!(original, "INC-0042");

    let mut both = chain.clone();
    both.push(flood);
    let second = build_with(&mut builder, &inventory, &both);

    let intrusion_again = second
        .iter()
        .find(|i| i.incident.signals.len() > 5)
        .expect("the intrusion is still a case");
    assert_eq!(
        intrusion_again.incident.incident_id, original,
        "the intrusion changed case number when the flood arrived"
    );
    assert!(
        second
            .iter()
            .any(|i| i.incident.incident_id != original && i.incident.signals.len() == 1),
        "the flood should have opened a case of its own"
    );
}


fn build_with(
    builder: &mut IncidentBuilder,
    inventory: &Arc<Inventory>,
    raws: &[RawEvent],
) -> Vec<BuiltIncident> {
    let enricher = Enricher::shared(Arc::clone(inventory));
    let mut normalizer = Normalizer::new();
    let mut outcome = normalizer.normalize_batch(raws);
    enricher.enrich_all(&mut outcome.events);
    let events = outcome.events;

    let mut resolver = EntityResolver::from_inventory(enricher.inventory());
    resolver.observe(&events);

    let catalog = Arc::new(MitreCatalog::embedded());
    let signals = DetectionEngine::new(Arc::clone(&catalog)).run(&events);
    let clusters = Correlator::default().cluster(&signals, &resolver);

    builder.build_all(
        &IncidentContext {
            signals: &signals,
            events: &events,
            resolver: &resolver,
            inventory: enricher.inventory(),
            catalog: &catalog,
        },
        &clusters,
    )
}

#[test]
fn the_incident_carries_everything_the_console_needs() {
    let run = full_demo();
    let built = &run.incidents[0];
    let incident = &built.incident;

    assert!(!incident.evidence.is_empty(), "evidence panel");
    assert!(!incident.relationships.is_empty(), "graph relationships");
    assert!(!incident.mitre_techniques.is_empty(), "ATT&CK panel");
    assert!(!incident.risk.contributions.is_empty(), "risk breakdown");
    assert!(!incident.blast_radius.assets.is_empty(), "blast radius");
    assert!(!built.correlation_reasons.is_empty(), "why-connected panel");
    assert!(!incident.unknowns.is_empty(), "unknowns panel");

    assert!(built.graph.node_count() >= 10);
    assert!(built.graph.edge_count() >= 12);
    assert!(built.graph.unevidenced_edges().is_empty());
}

#[test]
fn the_timeline_runs_from_phishing_to_ransomware() {
    let run = full_demo();
    let evidence = &run.incidents[0].incident.evidence;

    assert_eq!(
        evidence.first().map(|e| e.event_id.as_str()),
        Some("EVT-01")
    );
    assert_eq!(evidence.last().map(|e| e.event_id.as_str()), Some("EVT-11"));

    for pair in evidence.windows(2) {
        assert!(pair[0].timestamp <= pair[1].timestamp);
    }

    assert!(evidence.iter().all(|e| !e.cited_by.is_empty()));
}

#[test]
fn attack_progression_spans_initial_access_to_impact() {
    let run = full_demo();
    let incident = &run.incidents[0].incident;

    let tactics = incident.tactics();
    assert_eq!(tactics.first(), Some(&Tactic::InitialAccess));
    assert_eq!(tactics.last(), Some(&Tactic::Impact));
    assert!(
        run.incidents[0].progression.observed_stages >= 7,
        "only {} stages observed",
        run.incidents[0].progression.observed_stages
    );
}

#[test]
fn the_unrelated_flood_is_its_own_incident() {
    let run = full_demo();

    let flood = run
        .incidents
        .iter()
        .find(|i| i.incident.signals.len() == 1)
        .expect("the volumetric attack should stand alone");

    assert_ne!(flood.incident.incident_id, "INC-0042");
    assert!(
        flood.incident.title.to_lowercase().contains("volumetric"),
        "got {:?}",
        flood.incident.title
    );
}

#[test]
fn the_incident_admits_what_it_has_not_proven() {
    let run = full_demo();
    let unknowns = run.incidents[0].incident.unknowns.join(" ");

    assert!(
        unknowns.contains("Exfiltration is unconfirmed"),
        "staging without transfer must be flagged: {unknowns}"
    );
    assert!(
        unknowns.to_lowercase().contains("encoded"),
        "the undecoded payload must be flagged: {unknowns}"
    );
    assert!(
        unknowns.contains("EDR covers"),
        "the coverage blind spot must be flagged: {unknowns}"
    );
}

#[test]
fn blast_radius_distinguishes_confirmed_from_reachable() {
    let run = full_demo();
    let blast = &run.incidents[0].incident.blast_radius;

    assert_eq!(blast.level, Severity::Critical);
    assert!(blast.critical_databases >= 1);
    assert!(blast.confirmed_count() >= 4);

    let confirmed = blast
        .assets
        .iter()
        .filter(|a| a.exposure == Exposure::Confirmed)
        .count();
    let other = blast.assets.len() - confirmed;
    assert!(
        other > 0,
        "reachable and potential assets must be shown separately"
    );


    let patient_db = blast
        .assets
        .iter()
        .find(|a| a.entity.name.eq_ignore_ascii_case(demo::PATIENT_DB))
        .expect("the patient database must be in the blast radius");
    assert_eq!(patient_db.exposure, Exposure::Confirmed);
}

#[test]
fn a_lone_low_grade_signal_never_becomes_an_incident() {
    let now = Utc::now();
    let inventory = Arc::new(Inventory::generate(InventorySpec {
        seed: 42,
        hospitals: 18,
        endpoints: 2_000,
    }));
    let mut generator = TelemetryGenerator::new(inventory, 3);


    let run = pipeline(&generator.noise_batch(20_000, now));

    assert!(
        !run.signals.is_empty(),
        "noise should still produce some signals"
    );
    assert!(
        run.incidents.is_empty(),
        "{} incident(s) manufactured from pure noise",
        run.incidents.len()
    );
}
