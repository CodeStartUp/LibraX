//! End-to-end guard over normalize -> enrich -> detect.
//!
//! This is the test that keeps the simulator and the detectors honest with each
//! other: if a payload field is renamed on one side, the chain stops producing
//! eleven signals and this fails.

use std::collections::HashSet;
use std::sync::Arc;

use chrono::Utc;
use librax_connectors::synthetic::{TelemetryGenerator, scenario};
use librax_detection::DetectionEngine;
use librax_enrichment::{Enricher, Inventory, InventorySpec, demo};
use librax_mitre::MitreCatalog;
use librax_normalizer::Normalizer;
use librax_types::{RawEvent, SecuritySignal, Severity};

fn small_inventory() -> Inventory {
    Inventory::generate(InventorySpec {
        seed: 42,
        hospitals: 18,
        endpoints: 2_000,
    })
}

fn detect(raws: &[RawEvent]) -> Vec<SecuritySignal> {
    let enricher = Enricher::new(small_inventory());
    let mut normalizer = Normalizer::new();
    let mut outcome = normalizer.normalize_batch(raws);
    assert!(
        outcome.rejections.is_empty(),
        "unexpected rejections: {:?}",
        outcome.rejections
    );

    enricher.enrich_all(&mut outcome.events);
    DetectionEngine::new(Arc::new(MitreCatalog::embedded())).run(&outcome.events)
}

fn chain_signals() -> Vec<SecuritySignal> {
    detect(&scenario::attack_chain(Utc::now()))
}

#[test]
fn every_stage_of_the_intrusion_is_detected() {
    let signals = chain_signals();

    let detectors: HashSet<&str> = signals.iter().map(|s| s.detector_id.as_str()).collect();
    for expected in [
        "phishing_lure_delivered",
        "vpn_identity_anomaly",
        "powershell_encoded_command",
        "c2_connection",
        "network_discovery",
        "credential_abuse",
        "lateral_movement",
        "privileged_access_anomaly",
        "database_mass_access",
        "data_staging",
        "ransomware_indicator",
    ] {
        assert!(
            detectors.contains(expected),
            "{expected} did not fire; detectors that did: {detectors:?}"
        );
    }

    assert_eq!(
        signals.len(),
        11,
        "expected one signal per stage, got {}",
        signals.len()
    );
}

#[test]
fn signals_arrive_in_timeline_order() {
    let signals = chain_signals();
    for pair in signals.windows(2) {
        assert!(pair[0].timestamp <= pair[1].timestamp);
    }
}

#[test]
fn every_signal_explains_itself_and_cites_evidence() {
    for signal in chain_signals() {
        assert!(
            signal.explanation.len() > 40,
            "{} gave a threadbare explanation: {:?}",
            signal.detector_id,
            signal.explanation
        );
        assert!(
            !signal.evidence_event_ids.is_empty(),
            "{} cited no evidence",
            signal.detector_id
        );
        assert!(
            !signal.entities.is_empty(),
            "{} named no entities",
            signal.detector_id
        );
        assert!((0.0..=1.0).contains(&signal.confidence));
    }
}

#[test]
fn signal_ids_are_stable_across_runs() {
    let start = Utc::now();
    let first: Vec<String> = detect(&scenario::attack_chain(start))
        .into_iter()
        .map(|s| s.signal_id)
        .collect();
    let second: Vec<String> = detect(&scenario::attack_chain(start))
        .into_iter()
        .map(|s| s.signal_id)
        .collect();

    assert_eq!(first, second, "signal ids must be derivable, not random");
}

#[test]
fn techniques_are_mapped_only_where_behaviour_supports_them() {
    let signals = chain_signals();

    let powershell = signals
        .iter()
        .find(|s| s.detector_id == "powershell_encoded_command")
        .unwrap();
    assert!(
        powershell
            .mitre
            .iter()
            .any(|m| m.technique_id == "T1059.001"),
        "encoded PowerShell must map to T1059.001"
    );
    assert!(
        powershell.mitre.iter().all(|m| !m.rationale.is_empty()),
        "every mapping needs a rationale"
    );

    let ransomware = signals
        .iter()
        .find(|s| s.detector_id == "ransomware_indicator")
        .unwrap();
    assert!(ransomware.mitre.iter().any(|m| m.technique_id == "T1490"));
    assert_eq!(ransomware.severity, Severity::Critical);
}

#[test]
fn the_intrusion_reaches_the_patient_database() {
    let signals = chain_signals();
    let db = signals
        .iter()
        .find(|s| s.detector_id == "database_mass_access")
        .expect("bulk database access must be detected");

    assert_eq!(db.severity, Severity::Critical);
    assert!(
        db.entities
            .iter()
            .any(|e| e.name.eq_ignore_ascii_case(demo::PATIENT_DB)),
        "signal must name the patient database"
    );
    assert!(
        db.explanation.contains("184230") && db.explanation.contains("health information"),
        "{}",
        db.explanation
    );
}

#[test]
fn volumetric_attack_collapses_to_a_single_signal() {
    let signals = detect(&[scenario::ddos_burst(Utc::now())]);

    assert_eq!(signals.len(), 1, "1.8M connections must not become 1.8M alerts");
    assert_eq!(signals[0].detector_id, "network_volume_anomaly");
    assert!(signals[0].mitre.iter().any(|m| m.technique_id == "T1498"));
}

#[test]
fn background_noise_produces_no_serious_signals() {
    let inventory = Arc::new(small_inventory());
    let mut generator = TelemetryGenerator::new(inventory, 4);
    let noise = generator.noise_batch(20_000, Utc::now());

    let signals = detect(&noise);

    assert!(
        signals.iter().all(|s| s.severity <= Severity::Low),
        "noise must never manufacture a serious signal"
    );
    // The low-grade ones are the alert-fatigue baseline the engine has to filter.
    assert!(
        signals.len() < noise.len() / 20,
        "{} signals from {} events is too noisy",
        signals.len(),
        noise.len()
    );
}

#[test]
fn blocked_outbound_claims_no_technique() {
    let inventory = Arc::new(small_inventory());
    let mut generator = TelemetryGenerator::new(inventory, 8);
    let noise = generator.noise_batch(20_000, Utc::now());

    let signals = detect(&noise);
    let blocked: Vec<_> = signals
        .iter()
        .filter(|s| s.detector_id == "blocked_outbound_unproven_host")
        .collect();

    assert!(!blocked.is_empty(), "expected some low-grade noise signals");
    assert!(
        blocked.iter().all(|s| s.mitre.is_empty()),
        "a blocked connection is not evidence of a technique"
    );
}
