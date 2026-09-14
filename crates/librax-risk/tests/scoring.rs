//! Risk and blast radius over the real pipeline output.
//!
//! These tests deliberately assert *ranges and relationships* rather than exact
//! numbers. The demo target is roughly 94 / 99 / 97, but pinning the assertions
//! to those figures would just be hardcoding them one layer down.

use std::sync::Arc;

use chrono::Utc;
use librax_connectors::synthetic::scenario;
use librax_correlation::Correlator;
use librax_detection::DetectionEngine;
use librax_enrichment::{Enricher, Inventory, InventorySpec, demo};
use librax_entities::EntityResolver;
use librax_graph::AttackGraph;
use librax_mitre::{MitreCatalog, progression};
use librax_normalizer::Normalizer;
use librax_risk::{RiskInputs, assess_blast_radius, assess_risk};
use librax_types::{BlastRadius, CanonicalEvent, Exposure, RiskScore, SecuritySignal, Severity};

struct Assessed {
    risk: RiskScore,
    blast: BlastRadius,
    graph: AttackGraph,
    signals: Vec<SecuritySignal>,
    inventory: Inventory,
}

fn assess(events_from: fn() -> Vec<librax_types::RawEvent>) -> Assessed {
    let inventory = Inventory::generate(InventorySpec {
        seed: 42,
        hospitals: 18,
        endpoints: 2_000,
    });
    let enricher = Enricher::new(inventory);

    let mut normalizer = Normalizer::new();
    let mut outcome = normalizer.normalize_batch(&events_from());
    enricher.enrich_all(&mut outcome.events);
    let events: Vec<CanonicalEvent> = outcome.events;

    let mut resolver = EntityResolver::from_inventory(enricher.inventory());
    resolver.observe(&events);

    let catalog = Arc::new(MitreCatalog::embedded());
    let signals = DetectionEngine::new(Arc::clone(&catalog)).run(&events);

    let clusters = Correlator::default().cluster(&signals, &resolver);
    let cohesion = clusters.first().map(|c| c.cohesion).unwrap_or(0.0);

    let techniques: Vec<_> = signals.iter().flat_map(|s| s.mitre.clone()).collect();
    let (validated, _) = catalog.validate(techniques);
    let prog = progression::analyse(&validated);

    let graph = librax_graph::build(&events, &signals, &resolver, enricher.inventory());

    let risk = assess_risk(&RiskInputs {
        signals: &signals,
        events: &events,
        graph: &graph,
        progression_score: prog.score,
        correlation_cohesion: cohesion,
    });

    let blast = assess_blast_radius(&graph, enricher.inventory(), 2);

    Assessed {
        risk,
        blast,
        graph,
        signals,
        inventory: Inventory::generate(InventorySpec {
            seed: 42,
            hospitals: 18,
            endpoints: 2_000,
        }),
    }
}

fn intrusion() -> Assessed {
    assess(|| scenario::attack_chain(Utc::now()))
}

#[test]
fn the_intrusion_scores_as_a_critical_priority() {
    let assessed = intrusion();
    let risk = &assessed.risk;

    println!(
        "threat={:.1} impact={:.1} progression={:.1} overall={:.1}",
        risk.threat_confidence, risk.business_impact, risk.attack_progression, risk.overall_risk
    );

    assert!(
        risk.threat_confidence >= 85.0,
        "threat confidence was {:.1}",
        risk.threat_confidence
    );
    assert!(
        risk.business_impact >= 90.0,
        "business impact was {:.1}",
        risk.business_impact
    );
    assert!(
        risk.overall_risk >= 90.0,
        "overall risk was {:.1}",
        risk.overall_risk
    );
    assert_eq!(risk.severity(), Severity::Critical);
}

#[test]
fn the_breakdown_accounts_for_the_score() {
    let assessed = intrusion();

    assert!(
        assessed.risk.contributions.len() >= 6,
        "the UI needs a real breakdown, got {:?}",
        assessed.risk.contributions
    );
    assert!(
        assessed
            .risk
            .contributions
            .iter()
            .all(|c| !c.detail.is_empty()),
        "every contribution must say why"
    );

    let factors: Vec<&str> = assessed
        .risk
        .contributions
        .iter()
        .map(|c| c.factor.as_str())
        .collect();
    for expected in [
        "Detection strength",
        "Independent detectors",
        "Cross-source evidence",
        "Threat-intelligence match",
        "Most critical asset involved",
        "Regulated data exposed",
        "Attack progression",
    ] {
        assert!(
            factors.contains(&expected),
            "{expected} missing: {factors:?}"
        );
    }
}

#[test]
fn threat_confidence_and_business_impact_move_independently() {
    let assessed = intrusion();

    // The patient database drives impact far above what detection strength alone
    // would justify; if these were the same number the separation is fake.
    assert!(
        (assessed.risk.business_impact - assessed.risk.threat_confidence).abs() > 1.0,
        "impact {:.1} and confidence {:.1} are suspiciously identical",
        assessed.risk.business_impact,
        assessed.risk.threat_confidence
    );
}

#[test]
fn a_lone_low_grade_signal_is_not_a_crisis() {
    let assessed = intrusion();

    // Same machinery, one weak signal and nothing else.
    let single = vec![assessed.signals[0].clone()];
    let risk = assess_risk(&RiskInputs {
        signals: &single,
        events: &[],
        graph: &AttackGraph::default(),
        progression_score: 8.0,
        correlation_cohesion: 0.0,
    });

    assert!(
        risk.overall_risk < 40.0,
        "one signal on no known asset scored {:.1}",
        risk.overall_risk
    );
    assert_ne!(risk.severity(), Severity::Critical);
}

#[test]
fn no_signals_means_no_risk() {
    let risk = assess_risk(&RiskInputs {
        signals: &[],
        events: &[],
        graph: &AttackGraph::default(),
        progression_score: 0.0,
        correlation_cohesion: 0.0,
    });

    assert_eq!(risk.overall_risk, 0.0);
    assert!(risk.contributions.is_empty());
}

#[test]
fn blast_radius_reaches_the_patient_data_and_says_how_certain_it_is() {
    let assessed = intrusion();
    let blast = &assessed.blast;

    println!(
        "users={} endpoints={} servers={} dbs={} pacs={} reachable={} level={:?}",
        blast.users,
        blast.endpoints,
        blast.servers,
        blast.critical_databases,
        blast.pacs_systems,
        blast.potentially_reachable,
        blast.level
    );

    assert!(blast.users >= 2, "Alice and the service account at minimum");
    assert!(blast.servers >= 2, "app server and database server");
    assert!(blast.critical_databases >= 1, "the patient database");
    assert_eq!(blast.level, Severity::Critical);

    let confirmed = blast
        .assets
        .iter()
        .filter(|a| a.exposure == Exposure::Confirmed)
        .count();
    assert!(confirmed >= 4, "only {confirmed} assets confirmed");

    assert!(
        blast.assets.iter().all(|a| !a.reason.is_empty()),
        "every listed asset must explain why it is listed"
    );
}

#[test]
fn reachable_assets_are_never_reported_as_compromised() {
    let assessed = intrusion();

    let confirmed_names: Vec<String> = assessed
        .graph
        .nodes
        .iter()
        .filter(|n| n.exposure == Exposure::Confirmed)
        .map(|n| n.label.to_lowercase())
        .collect();

    for asset in &assessed.blast.assets {
        if asset.exposure != Exposure::Confirmed {
            assert!(
                !confirmed_names.contains(&asset.entity.name.to_lowercase()),
                "{} is listed as {:?} but was confirmed elsewhere",
                asset.entity.name,
                asset.exposure
            );
            assert!(
                asset.reason.contains("hop")
                    || asset.reason.contains("relationships")
                    || asset.reason.contains("no activity observed"),
                "{} gave reason {:?}",
                asset.entity.name,
                asset.reason
            );
        }
    }
}

#[test]
fn the_patient_database_is_the_impact_driver() {
    let assessed = intrusion();

    let driver = assessed
        .risk
        .contributions
        .iter()
        .find(|c| c.factor == "Most critical asset involved")
        .expect("impact must name its driver");

    assert!(
        driver
            .detail
            .to_lowercase()
            .contains(&demo::PATIENT_DB.to_lowercase()),
        "expected the patient database, got {:?}",
        driver.detail
    );
    assert!(driver.points > 40.0);

    // And the inventory agrees it is that critical.
    let asset = assessed
        .inventory
        .asset_by_name(demo::PATIENT_DB)
        .expect("patient database must exist in inventory");
    assert!(asset.criticality >= 95);
}
