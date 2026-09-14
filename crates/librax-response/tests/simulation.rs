//! Response simulation, and the guarantees around it.

use chrono::Utc;
use librax_graph::{AttackGraph, GraphNode};
use librax_response::{ResponseEngine, ResponseError};
use librax_types::{
    BlastRadius, EntityKind, Exposure, Incident, IncidentStatus, ResponseActionKind,
    ResponseStatus, RiskScore, Severity,
};

fn node(kind: EntityKind, name: &str, external: bool) -> GraphNode {
    let now = Utc::now();
    GraphNode {
        id: format!("{}:{}", kind.label().to_lowercase(), name.to_lowercase()),
        kind,
        kind_label: kind.label().to_string(),
        label: name.to_string(),
        exposure: Exposure::Confirmed,
        criticality: Some(90),
        hospital: Some("Campus-04".into()),
        platform: Some(librax_graph::Platform::Windows),
        platform_label: Some("Windows".into()),
        external,
        event_count: 1,
        first_seen: now,
        last_seen: now,
    }
}

/// An incident shaped like the demo intrusion: signal ids embed the detector,
/// which is how playbooks decide whether they apply.
fn intrusion() -> (Incident, AttackGraph) {
    let now = Utc::now();

    let incident = Incident {
        incident_id: "INC-0042".into(),
        title: "Multi-Stage Healthcare Intrusion".into(),
        status: IncidentStatus::New,
        signals: vec![
            "SIG-powershell_encoded_command-EVT-03".into(),
            "SIG-c2_connection-EVT-04".into(),
            "SIG-credential_abuse-EVT-06".into(),
            "SIG-vpn_identity_anomaly-EVT-02".into(),
            "SIG-ransomware_indicator-EVT-11".into(),
        ],
        evidence: Vec::new(),
        entities: Vec::new(),
        relationships: Vec::new(),
        risk: RiskScore {
            overall_risk: 95.0,
            ..Default::default()
        },
        blast_radius: BlastRadius::default(),
        mitre_techniques: Vec::new(),
        unknowns: vec!["Exfiltration is unconfirmed.".into()],
        first_seen: now,
        last_seen: now,
        owner: None,
        notes: Vec::new(),
    };

    let graph = AttackGraph {
        nodes: vec![
            node(EntityKind::Host, "HR-PC-23", false),
            node(EntityKind::Server, "DB-SRV-02", false),
            node(EntityKind::User, "alice.hr", false),
            node(EntityKind::Account, "svc.dbadmin", false),
            node(EntityKind::Process, "powershell.exe", false),
            node(EntityKind::File, "archive_patient_export.zip", false),
            node(EntityKind::Ip, "185.220.101.47", true),
            node(EntityKind::Domain, "cdn-sync-update.net", true),
        ],
        edges: Vec::new(),
    };

    (incident, graph)
}

#[test]
fn the_right_playbooks_fire_for_this_incident() {
    let (incident, _) = intrusion();
    let names = ResponseEngine::new().matching_playbooks(&incident);

    assert!(names.contains(&"Ransomware containment and escalation"));
    assert!(names.contains(&"Contain compromised endpoint"));
    assert!(names.contains(&"Contain compromised identity"));
    assert!(names.contains(&"Block attacker infrastructure"));
    assert!(names.contains(&"Standard triage"));
}

#[test]
fn recommendations_cover_containment_of_every_kind_of_target() {
    let (incident, graph) = intrusion();
    let actions = ResponseEngine::new().recommend(&incident, &graph);

    let kinds: Vec<ResponseActionKind> = actions.iter().map(|a| a.kind).collect();
    for expected in [
        ResponseActionKind::IsolateEndpoint,
        ResponseActionKind::DisableAccount,
        ResponseActionKind::BlockIp,
        ResponseActionKind::BlockDomain,
        ResponseActionKind::QuarantineFile,
        ResponseActionKind::Escalate,
        ResponseActionKind::CreateInvestigationTask,
    ] {
        assert!(
            kinds.contains(&expected),
            "{expected:?} was not recommended"
        );
    }

    // Sorted by confidence, and every one justified.
    for pair in actions.windows(2) {
        assert!(pair[0].confidence >= pair[1].confidence);
    }
    assert!(actions.iter().all(|a| a.rationale.len() > 30));
}

#[test]
fn recommendations_are_deterministic_and_free_of_duplicates() {
    let (incident, graph) = intrusion();
    let engine = ResponseEngine::new();

    let first: Vec<String> = engine
        .recommend(&incident, &graph)
        .into_iter()
        .map(|a| a.action_id)
        .collect();
    let second: Vec<String> = engine
        .recommend(&incident, &graph)
        .into_iter()
        .map(|a| a.action_id)
        .collect();

    assert_eq!(first, second, "action ids must be derivable, not random");

    let mut unique = first.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), first.len(), "duplicate actions offered");
}

#[test]
fn destructive_actions_refuse_to_run_without_an_approver() {
    let (incident, graph) = intrusion();
    let engine = ResponseEngine::new();
    let mut actions = engine.recommend(&incident, &graph);

    let action = actions
        .iter_mut()
        .find(|a| a.kind == ResponseActionKind::IsolateEndpoint)
        .expect("isolation must be offered");

    let error = engine.simulate(action, None).expect_err("must be refused");
    assert!(matches!(error, ResponseError::ApprovalRequired { .. }));
    assert_eq!(action.status, ResponseStatus::AwaitingApproval);
    assert!(action.result.is_none(), "nothing should have been recorded");
}

#[test]
fn an_approved_destructive_action_is_simulated_and_says_so() {
    let (incident, graph) = intrusion();
    let engine = ResponseEngine::new();
    let mut actions = engine.recommend(&incident, &graph);

    let action = actions
        .iter_mut()
        .find(|a| a.kind == ResponseActionKind::DisableAccount)
        .expect("account disable must be offered");

    let outcome = engine
        .simulate(action, Some("analyst.tier2"))
        .expect("approved action should simulate");

    assert_eq!(action.status, ResponseStatus::Simulated);
    assert!(action.simulated_at.is_some());
    assert_eq!(outcome.approved_by.as_deref(), Some("analyst.tier2"));

    let result = action.result.as_deref().unwrap();
    assert!(result.starts_with("SIMULATED."), "{result}");
    assert!(
        result.contains("No change was made to any system"),
        "{result}"
    );
}

#[test]
fn non_destructive_actions_need_no_approval() {
    let (incident, graph) = intrusion();
    let engine = ResponseEngine::new();
    let mut actions = engine.recommend(&incident, &graph);

    let action = actions
        .iter_mut()
        .find(|a| a.kind == ResponseActionKind::CreateInvestigationTask)
        .expect("triage task must be offered");

    assert!(!action.requires_approval);
    engine
        .simulate(action, None)
        .expect("opening a task is not destructive");
    assert_eq!(action.status, ResponseStatus::Simulated);
}

#[test]
fn every_destructive_action_is_gated() {
    let (incident, graph) = intrusion();
    let actions = ResponseEngine::new().recommend(&incident, &graph);

    for action in &actions {
        assert_eq!(
            action.requires_approval,
            action.kind.is_destructive(),
            "{:?} approval gate is wrong",
            action.kind
        );
    }
}

#[test]
fn simulating_twice_is_refused() {
    let (incident, graph) = intrusion();
    let engine = ResponseEngine::new();
    let mut actions = engine.recommend(&incident, &graph);

    let action = actions
        .iter_mut()
        .find(|a| a.kind == ResponseActionKind::Escalate)
        .unwrap();

    engine.simulate(action, Some("analyst.tier2")).unwrap();
    let error = engine
        .simulate(action, Some("analyst.tier2"))
        .expect_err("second run must be refused");
    assert!(matches!(error, ResponseError::AlreadySimulated { .. }));
}

#[test]
fn a_declined_action_cannot_then_be_simulated() {
    let (incident, graph) = intrusion();
    let engine = ResponseEngine::new();
    let mut actions = engine.recommend(&incident, &graph);

    let action = actions
        .iter_mut()
        .find(|a| a.kind == ResponseActionKind::IsolateEndpoint)
        .unwrap();

    engine.decline(action, "clinical system, needs change approval");
    assert_eq!(action.status, ResponseStatus::Declined);

    let error = engine
        .simulate(action, Some("analyst.tier2"))
        .expect_err("declined actions stay declined");
    assert!(matches!(error, ResponseError::Declined { .. }));
}

#[test]
fn destructive_recommendations_warn_about_their_own_side_effects() {
    let (incident, graph) = intrusion();
    let actions = ResponseEngine::new().recommend(&incident, &graph);

    let server_isolation = actions
        .iter()
        .find(|a| a.kind == ResponseActionKind::IsolateEndpoint && a.target.name == "DB-SRV-02")
        .expect("server isolation must be offered");
    assert!(
        server_isolation.rationale.contains("outage"),
        "isolating a server has consequences the analyst must see: {:?}",
        server_isolation.rationale
    );

    let disable = actions
        .iter()
        .find(|a| a.kind == ResponseActionKind::DisableAccount)
        .unwrap();
    assert!(
        disable.rationale.contains("legitimate"),
        "{:?}",
        disable.rationale
    );
}

#[test]
fn low_severity_incidents_get_no_tier_two_page() {
    let (mut incident, graph) = intrusion();
    incident.signals = vec!["SIG-blocked_outbound_unproven_host-NOISE-1".into()];
    incident.risk = RiskScore {
        overall_risk: 20.0,
        ..Default::default()
    };
    assert!(incident.severity() < Severity::High);

    let actions = ResponseEngine::new().recommend(&incident, &graph);
    assert!(
        !actions
            .iter()
            .any(|a| a.kind == ResponseActionKind::NotifyAnalyst),
        "a low-risk incident should not page tier 2"
    );
}
