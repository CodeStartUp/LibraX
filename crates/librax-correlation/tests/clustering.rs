//! Correlation behaviour over the real detection output.

use std::sync::Arc;

use chrono::{Duration, Utc};
use librax_connectors::synthetic::{TelemetryGenerator, scenario};
use librax_correlation::{CorrelationConfig, Correlator};
use librax_detection::DetectionEngine;
use librax_enrichment::{Enricher, Inventory, InventorySpec, demo};
use librax_entities::EntityResolver;
use librax_mitre::MitreCatalog;
use librax_normalizer::Normalizer;
use librax_types::{RawEvent, SecuritySignal, Severity};

fn inventory() -> Inventory {
    Inventory::generate(InventorySpec {
        seed: 42,
        hospitals: 18,
        endpoints: 2_000,
    })
}

struct Pipeline {
    resolver: EntityResolver,
    signals: Vec<SecuritySignal>,
}

fn run(raws: &[RawEvent]) -> Pipeline {
    let inv = inventory();
    let enricher = Enricher::new(inv);
    let mut normalizer = Normalizer::new();
    let mut outcome = normalizer.normalize_batch(raws);
    enricher.enrich_all(&mut outcome.events);

    let mut resolver = EntityResolver::from_inventory(enricher.inventory());
    resolver.observe(&outcome.events);

    let signals = DetectionEngine::new(Arc::new(MitreCatalog::embedded())).run(&outcome.events);

    Pipeline { resolver, signals }
}

#[test]
fn the_whole_intrusion_becomes_exactly_one_cluster() {
    let pipeline = run(&scenario::attack_chain(Utc::now()));
    let clusters = Correlator::default().cluster(&pipeline.signals, &pipeline.resolver);

    assert_eq!(
        clusters.len(),
        1,
        "eleven signals must not become {} separate cases",
        clusters.len()
    );
    assert_eq!(clusters[0].len(), 11);
    assert_eq!(clusters[0].peak_severity, Severity::Critical);
    assert!(clusters[0].cohesion > 0.3);
}

#[test]
fn the_cluster_explains_why_it_was_grouped() {
    let pipeline = run(&scenario::attack_chain(Utc::now()));
    let clusters = Correlator::default().cluster(&pipeline.signals, &pipeline.resolver);
    let reasons = clusters[0].reasons.join(" | ");

    assert!(reasons.contains("Same identity"), "{reasons}");
    assert!(reasons.contains("Same host"), "{reasons}");
    assert!(reasons.contains("ATT&CK progression"), "{reasons}");

    // The named story entities must be among what ties it together.
    let names: Vec<String> = clusters[0]
        .shared_entities
        .iter()
        .map(|e| e.name.to_lowercase())
        .collect();
    assert!(names.iter().any(|n| n.as_str() == demo::USER));
    assert!(
        names
            .iter()
            .any(|n| n.as_str() == demo::ENDPOINT.to_lowercase())
    );
}

#[test]
fn an_unrelated_volumetric_attack_stays_its_own_case() {
    let now = Utc::now();
    let mut raws = scenario::attack_chain(now);
    raws.push(scenario::ddos_burst(now + Duration::minutes(10)));

    let pipeline = run(&raws);
    let clusters = Correlator::default().cluster(&pipeline.signals, &pipeline.resolver);

    assert_eq!(
        clusters.len(),
        2,
        "a gateway flood shares nothing with the intrusion and must not merge"
    );
    let sizes: Vec<usize> = clusters.iter().map(|c| c.len()).collect();
    assert!(sizes.contains(&11) && sizes.contains(&1), "{sizes:?}");
}

#[test]
fn proximity_in_time_alone_never_links() {
    let pipeline = run(&scenario::attack_chain(Utc::now()));
    let correlator = Correlator::default();

    let a = &pipeline.signals[0];
    let entities_a = pipeline.resolver.resolve_signal(a);

    // Same instant, entirely unrelated entities and no shared evidence.
    let mut b = a.clone();
    b.signal_id = "SIG-unrelated-1".into();
    b.entities = vec![librax_types::EntityRef::user("someone.else")];
    b.evidence_event_ids = vec!["EVT-UNRELATED".into()];
    let entities_b = pipeline.resolver.resolve_signal(&b);

    assert!(
        correlator.link(a, &entities_a, &b, &entities_b).is_none(),
        "coincidence is not correlation"
    );
}

#[test]
fn signals_outside_the_window_do_not_link() {
    let pipeline = run(&scenario::attack_chain(Utc::now()));
    let correlator = Correlator::new(CorrelationConfig {
        window: Duration::minutes(5),
        ..Default::default()
    });

    let clusters = correlator.cluster(&pipeline.signals, &pipeline.resolver);
    assert!(
        clusters.len() > 1,
        "a five-minute window cannot span a thirty-one-minute intrusion"
    );
}

#[test]
fn low_grade_noise_does_not_get_swept_into_the_intrusion() {
    let now = Utc::now();
    let inv = Arc::new(inventory());
    let mut generator = TelemetryGenerator::new(inv, 12);

    let mut raws = generator.noise_batch(4_000, now);
    raws.extend(scenario::attack_chain(now));

    let pipeline = run(&raws);
    let clusters = Correlator::default().cluster(&pipeline.signals, &pipeline.resolver);

    let intrusion = clusters
        .iter()
        .find(|c| c.len() >= 11)
        .expect("the intrusion cluster must survive the noise");

    assert_eq!(
        intrusion.len(),
        11,
        "noise leaked into the intrusion: {} signals",
        intrusion.len()
    );
}
