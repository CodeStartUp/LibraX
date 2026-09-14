//! The briefing must be honest: facts cite evidence, guesses are labelled, and
//! nothing is invented.

use chrono::{Duration, Utc};
use librax_ai::{AnalystEngine, Assertion, Briefing, BriefingInput, DeterministicAnalyst};
use librax_graph::{AttackGraph, GraphNode};
use librax_mitre::{MitreCatalog, progression};
use librax_types::{
    BlastRadius, EntityKind, Evidence, Exposure, Incident, IncidentStatus, RelationType,
    Relationship, RiskContribution, RiskScore, Severity, SourceType,
};

fn node(kind: EntityKind, name: &str) -> GraphNode {
    let now = Utc::now();
    GraphNode {
        id: format!("{}:{}", kind.label().to_lowercase(), name.to_lowercase()),
        kind,
        kind_label: kind.label().to_string(),
        label: name.to_string(),
        exposure: Exposure::Confirmed,
        criticality: Some(98),
        hospital: Some("Campus-04".into()),
        platform: Some(librax_graph::Platform::Windows),
        platform_label: Some("Windows".into()),
        external: false,
        event_count: 1,
        first_seen: now,
        last_seen: now,
    }
}

fn incident() -> Incident {
    let start = Utc::now();

    Incident {
        incident_id: "INC-0042".into(),
        title: "Multi-Stage Healthcare Intrusion".into(),
        status: IncidentStatus::New,
        signals: (1..=11)
            .map(|n| format!("SIG-detector-EVT-{n:02}"))
            .collect(),
        evidence: (1..=11)
            .map(|n| Evidence {
                event_id: format!("EVT-{n:02}"),
                source_type: if n % 2 == 0 {
                    SourceType::Edr
                } else {
                    SourceType::Firewall
                },
                timestamp: start + Duration::minutes(n as i64 * 3),
                severity: Severity::High,
                summary: format!("event {n}"),
                cited_by: vec!["detector".into()],
            })
            .collect(),
        entities: Vec::new(),
        relationships: vec![Relationship {
            from: node(EntityKind::User, "alice.hr").entity(),
            relation: RelationType::Uses,
            to: node(EntityKind::Host, "HR-PC-23").entity(),
            confidence: 0.98,
            first_seen: start,
            last_seen: start,
            evidence_event_ids: vec!["EVT-03".into()],
        }],
        risk: RiskScore {
            threat_confidence: 92.2,
            business_impact: 95.6,
            attack_progression: 100.0,
            overall_risk: 95.4,
            contributions: vec![
                RiskContribution {
                    factor: "Most critical asset involved".into(),
                    points: 68.6,
                    detail: "PATIENT-DB at criticality 98/100".into(),
                },
                RiskContribution {
                    factor: "Detection strength".into(),
                    points: 36.4,
                    detail: "11 detections with mean confidence 91%".into(),
                },
            ],
        },
        blast_radius: BlastRadius::default(),
        mitre_techniques: Vec::new(),
        unknowns: vec![
            "Exfiltration is unconfirmed. An archive was staged, but no outbound transfer was \
             observed."
                .into(),
            "The encoded PowerShell payload has not been decoded.".into(),
            "EDR covers 9871 of 10482 endpoints (94.2%).".into(),
        ],
        first_seen: start,
        last_seen: start + Duration::minutes(31),
        owner: None,
        notes: Vec::new(),
    }
}

fn brief() -> Briefing {
    let incident = incident();
    let graph = AttackGraph {
        nodes: vec![
            node(EntityKind::User, "alice.hr"),
            node(EntityKind::Host, "HR-PC-23"),
            node(EntityKind::Server, "DB-SRV-02"),
            node(EntityKind::Database, "PATIENT-DB"),
        ],
        edges: Vec::new(),
    };

    let catalog = MitreCatalog::embedded();
    let techniques: Vec<_> = [
        "T1566.001",
        "T1059.001",
        "T1071.001",
        "T1110.003",
        "T1046",
        "T1021.006",
        "T1213",
        "T1490",
    ]
    .iter()
    .filter_map(|id| catalog.reference(id, 0.9, "test"))
    .collect();
    let prog = progression::analyse(&techniques);

    DeterministicAnalyst.brief(&BriefingInput {
        incident: &incident,
        graph: &graph,
        progression: &prog,
        correlation_reasons: &[
            "Same identity: both involve alice.hr".to_string(),
            "Same host: both touch HR-PC-23".to_string(),
        ],
        playbooks: &["Ransomware containment and escalation", "Standard triage"],
    })
}

#[test]
fn the_briefing_names_its_generator_rather_than_implying_a_model() {
    let briefing = brief();
    assert!(
        briefing.generator.contains("not a language model"),
        "got {:?}",
        briefing.generator
    );
}

#[test]
fn every_section_is_populated() {
    let briefing = brief();

    assert!(!briefing.summary.is_empty(), "what happened");
    assert!(!briefing.risk_explanation.is_empty(), "why this score");
    assert!(
        !briefing.evidence_explanation.is_empty(),
        "what supports it"
    );
    assert!(!briefing.unknowns.is_empty(), "what is not confirmed");
    assert!(!briefing.investigation_guidance.is_empty(), "what next");
    assert!(!briefing.response_suggestion.is_empty(), "which playbook");
}

#[test]
fn facts_cite_evidence_and_guesses_do_not_pretend_to() {
    let briefing = brief();

    for statement in briefing.summary.iter() {
        match statement.assertion {
            Assertion::Fact => assert!(
                !statement.evidence_event_ids.is_empty(),
                "a fact with no evidence: {:?}",
                statement.text
            ),
            Assertion::Inference | Assertion::Unknown => assert!(
                statement.evidence_event_ids.is_empty(),
                "an inference must not present evidence as proof: {:?}",
                statement.text
            ),
        }
    }
}

#[test]
fn unknowns_are_carried_through_verbatim_and_labelled() {
    let briefing = brief();
    let source = incident();

    assert_eq!(briefing.unknowns.len(), source.unknowns.len());
    for statement in &briefing.unknowns {
        assert_eq!(statement.assertion, Assertion::Unknown);
        assert_eq!(statement.label, "UNKNOWN");
        assert!(
            source.unknowns.contains(&statement.text),
            "unknowns must not be paraphrased: {:?}",
            statement.text
        );
    }
}

#[test]
fn the_interpretive_claim_is_marked_as_inference() {
    let briefing = brief();

    let interpretation = briefing
        .summary
        .iter()
        .find(|s| s.text.contains("one operator"))
        .expect("the single-operator reading should be stated");

    assert_eq!(interpretation.assertion, Assertion::Inference);
    assert!(
        interpretation.text.contains("does not observe intent"),
        "the limit of the claim must be stated: {:?}",
        interpretation.text
    );
}

#[test]
fn the_risk_explanation_shows_the_arithmetic_and_the_drivers() {
    let briefing = brief();
    let text: String = briefing
        .risk_explanation
        .iter()
        .map(|s| s.text.clone())
        .collect::<Vec<_>>()
        .join(" ");

    assert!(text.contains("95/100"), "{text}");
    assert!(
        text.contains("40%") && text.contains("35%") && text.contains("25%"),
        "{text}"
    );
    assert!(text.contains("PATIENT-DB"), "{text}");
    assert!(
        text.contains("scored separately"),
        "the separation of confidence and impact must be explained: {text}"
    );
}

#[test]
fn guidance_addresses_the_specific_gaps_recorded() {
    let briefing = brief();
    let text: String = briefing
        .investigation_guidance
        .iter()
        .map(|s| s.text.clone())
        .collect::<Vec<_>>()
        .join(" ");

    assert!(text.contains("egress netflow"), "exfiltration gap: {text}");
    assert!(text.contains("Decode the base64"), "payload gap: {text}");
    assert!(text.contains("blind spot"), "coverage gap: {text}");
    assert!(text.contains("alice.hr"), "user confirmation: {text}");

    // Guidance is advice, not established fact.
    assert!(
        briefing
            .investigation_guidance
            .iter()
            .all(|s| s.assertion == Assertion::Inference)
    );
}

#[test]
fn the_response_section_states_that_actions_are_simulated() {
    let briefing = brief();
    let text: String = briefing
        .response_suggestion
        .iter()
        .map(|s| s.text.clone())
        .collect::<Vec<_>>()
        .join(" ");

    assert!(text.contains("simulated"), "{text}");
    assert!(text.contains("named approver"), "{text}");
    assert!(text.contains("Ransomware containment"), "{text}");
}

#[test]
fn briefings_are_reproducible() {
    let first = brief();
    let second = brief();

    let flatten = |b: &Briefing| -> Vec<String> {
        b.all_statements()
            .map(|s| format!("{}:{}", s.label, s.text))
            .collect()
    };

    assert_eq!(flatten(&first), flatten(&second));
}

#[test]
fn a_thin_incident_makes_no_grand_claims() {
    let mut thin = incident();
    thin.signals = vec!["SIG-detector-EVT-01".into()];
    thin.unknowns = Vec::new();

    let catalog = MitreCatalog::embedded();
    let single: Vec<_> = catalog
        .reference("T1059.001", 0.6, "test")
        .into_iter()
        .collect();
    let prog = progression::analyse(&single);

    let briefing = DeterministicAnalyst.brief(&BriefingInput {
        incident: &thin,
        graph: &AttackGraph::default(),
        progression: &prog,
        correlation_reasons: &[],
        playbooks: &["Standard triage"],
    });

    assert!(
        !briefing
            .summary
            .iter()
            .any(|s| s.text.contains("one operator")),
        "a single detection is not a campaign"
    );
    assert!(briefing.unknowns.is_empty());
}
