//! The graph must reconstruct the attack path and prove every edge.

use std::sync::Arc;

use chrono::Utc;
use librax_connectors::synthetic::scenario;
use librax_detection::DetectionEngine;
use librax_enrichment::{Enricher, Inventory, InventorySpec, demo};
use librax_entities::EntityResolver;
use librax_graph::{AttackGraph, build};
use librax_mitre::MitreCatalog;
use librax_normalizer::Normalizer;
use librax_types::{EntityKind, Exposure, RelationType};

fn graph_of_the_intrusion() -> AttackGraph {
    let inventory = Inventory::generate(InventorySpec {
        seed: 42,
        hospitals: 18,
        endpoints: 2_000,
    });
    let enricher = Enricher::new(inventory);

    let mut normalizer = Normalizer::new();
    let mut outcome = normalizer.normalize_batch(&scenario::attack_chain(Utc::now()));
    enricher.enrich_all(&mut outcome.events);

    let mut resolver = EntityResolver::from_inventory(enricher.inventory());
    resolver.observe(&outcome.events);

    let signals = DetectionEngine::new(Arc::new(MitreCatalog::embedded())).run(&outcome.events);

    build(&outcome.events, &signals, &resolver, enricher.inventory())
}

fn has_edge(graph: &AttackGraph, from: &str, relation: RelationType, to: &str) -> bool {
    graph.edges.iter().any(|e| {
        e.relation == relation
            && graph
                .node(&e.from)
                .is_some_and(|n| n.label.eq_ignore_ascii_case(from))
            && graph
                .node(&e.to)
                .is_some_and(|n| n.label.eq_ignore_ascii_case(to))
    })
}

#[test]
fn the_graph_reconstructs_the_attack_path() {
    let graph = graph_of_the_intrusion();

    assert!(
        has_edge(
            &graph,
            demo::PHISHING_DOMAIN,
            RelationType::Delivers,
            demo::USER
        ),
        "the lure must connect the sender domain to Alice"
    );
    assert!(
        has_edge(&graph, demo::USER, RelationType::Uses, demo::ENDPOINT),
        "Alice must be linked to her endpoint"
    );
    assert!(
        has_edge(
            &graph,
            demo::ENDPOINT,
            RelationType::Executes,
            "powershell.exe"
        ),
        "the endpoint must be shown executing PowerShell"
    );
    assert!(
        has_edge(
            &graph,
            demo::ENDPOINT,
            RelationType::ConnectsTo,
            demo::ATTACKER_IP
        ),
        "the beacon to attacker infrastructure must be an edge"
    );
    assert!(
        has_edge(
            &graph,
            demo::ENDPOINT,
            RelationType::LateralMovesTo,
            demo::APP_SERVER
        ),
        "lateral movement to the app server must be an edge"
    );
    assert!(
        has_edge(
            &graph,
            demo::PRIVILEGED_ACCOUNT,
            RelationType::PrivilegedAccess,
            demo::DB_SERVER
        ),
        "the privileged account must reach the database server"
    );
    assert!(
        has_edge(
            &graph,
            demo::PRIVILEGED_ACCOUNT,
            RelationType::Accesses,
            demo::PATIENT_DB
        ),
        "access to the patient database must be an edge"
    );
    assert!(
        has_edge(
            &graph,
            demo::PRIVILEGED_ACCOUNT,
            RelationType::Stages,
            demo::STAGED_FILE
        ),
        "the staged archive must be an edge"
    );
}

#[test]
fn every_derived_edge_cites_its_evidence() {
    let graph = graph_of_the_intrusion();

    let unproven = graph.unevidenced_edges();
    assert!(
        unproven.is_empty(),
        "edges without evidence: {:?}",
        unproven.iter().map(|e| &e.id).collect::<Vec<_>>()
    );

    // And the evidence must be real event ids from the chain.
    for edge in &graph.edges {
        for event_id in &edge.evidence_event_ids {
            assert!(
                event_id.starts_with("EVT-"),
                "edge {} cites {event_id}, which is not an event from this incident",
                edge.id
            );
        }
    }
}

#[test]
fn attacker_infrastructure_is_marked_external() {
    let graph = graph_of_the_intrusion();

    let attacker = graph
        .nodes
        .iter()
        .find(|n| n.label == demo::ATTACKER_IP)
        .expect("attacker address must be a node");
    assert!(attacker.external);
    assert_eq!(attacker.kind, EntityKind::Ip);

    let endpoint = graph
        .nodes
        .iter()
        .find(|n| n.label.eq_ignore_ascii_case(demo::ENDPOINT))
        .expect("the endpoint must be a node");
    assert!(!endpoint.external, "an owned asset is not external");
}

#[test]
fn critical_assets_carry_their_business_context() {
    let graph = graph_of_the_intrusion();

    let patient_db = graph
        .nodes
        .iter()
        .find(|n| n.label.eq_ignore_ascii_case(demo::PATIENT_DB))
        .expect("the patient database must be a node");

    assert!(
        patient_db.criticality.is_some_and(|c| c >= 95),
        "criticality was {:?}",
        patient_db.criticality
    );
    assert_eq!(patient_db.hospital.as_deref(), Some(demo::HOSPITAL));
}

#[test]
fn traversal_separates_confirmed_from_merely_reachable() {
    let graph = graph_of_the_intrusion();

    let confirmed = graph.confirmed_node_ids();
    assert!(!confirmed.is_empty(), "detections must confirm some nodes");

    let reach = graph.reach_from(&confirmed, 2);
    assert!(reach.iter().all(|r| r.hops <= 2));
    assert!(
        reach.iter().any(|r| r.exposure == Exposure::Confirmed),
        "origins are confirmed"
    );
    assert!(
        reach.len() >= confirmed.len(),
        "traversal cannot lose nodes"
    );
}

#[test]
fn the_graph_is_connected_enough_to_tell_a_story() {
    let graph = graph_of_the_intrusion();

    assert!(
        graph.node_count() >= 10,
        "expected the cast of the intrusion, got {} nodes",
        graph.node_count()
    );
    assert!(graph.edge_count() >= 12);

    // Starting from Alice, the whole path must be walkable to the patient data.
    let alice = graph
        .nodes
        .iter()
        .find(|n| n.label == demo::USER)
        .map(|n| n.id.clone())
        .expect("Alice must be a node");

    let reachable = graph.reach_from(&[alice], 8);
    let names: Vec<String> = reachable
        .iter()
        .filter_map(|r| graph.node(&r.node_id))
        .map(|n| n.label.to_lowercase())
        .collect();

    for expected in [
        demo::ENDPOINT,
        demo::APP_SERVER,
        demo::DB_SERVER,
        demo::PATIENT_DB,
        demo::STAGED_FILE,
    ] {
        assert!(
            names.contains(&expected.to_lowercase()),
            "{expected} is not reachable from Alice; reached {names:?}"
        );
    }
}
