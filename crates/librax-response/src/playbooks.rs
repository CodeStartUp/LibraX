use librax_graph::AttackGraph;
use librax_types::{EntityKind, EntityRef, Incident, ResponseAction, ResponseActionKind, Severity};


pub trait Playbook: Send + Sync {
    fn id(&self) -> &'static str;

    fn name(&self) -> &'static str;


    fn applies(&self, incident: &Incident) -> bool;

    fn actions(&self, incident: &Incident, graph: &AttackGraph) -> Vec<ResponseAction>;
}


fn confirmed<'a>(
    graph: &'a AttackGraph,
    kinds: &'a [EntityKind],
) -> impl Iterator<Item = EntityRef> + 'a {
    graph
        .nodes
        .iter()
        .filter(move |n| n.exposure == librax_types::Exposure::Confirmed && kinds.contains(&n.kind))
        .map(|n| n.entity())
}

fn fired(incident: &Incident, detector_hint: &str) -> bool {
    incident.signals.iter().any(|s| s.contains(detector_hint))
}

pub struct CompromisedEndpoint;

impl Playbook for CompromisedEndpoint {
    fn id(&self) -> &'static str {
        "compromised_endpoint"
    }

    fn name(&self) -> &'static str {
        "Contain compromised endpoint"
    }

    fn applies(&self, incident: &Incident) -> bool {
        fired(incident, "powershell_encoded_command") || fired(incident, "c2_connection")
    }

    fn actions(&self, incident: &Incident, graph: &AttackGraph) -> Vec<ResponseAction> {
        let mut actions = Vec::new();

        for host in confirmed(graph, &[EntityKind::Host]) {
            actions.push(ResponseAction::new(
                ResponseActionKind::IsolateEndpoint,
                host.clone(),
                &incident.incident_id,
                0.92,
                format!(
                    "{} executed an encoded command and reached external infrastructure. \
                     Network isolation stops the channel while preserving the host for forensics.",
                    host.name
                ),
            ));
        }

        for process in confirmed(graph, &[EntityKind::Process]) {
            if process.name.eq_ignore_ascii_case("powershell.exe") {
                actions.push(ResponseAction::new(
                    ResponseActionKind::KillProcess,
                    process.clone(),
                    &incident.incident_id,
                    0.70,
                    format!(
                        "Terminating {} ends the current execution, though it does not remove \
                         whatever established it.",
                        process.name
                    ),
                ));
            }
        }

        actions
    }
}

pub struct CompromisedIdentity;

impl Playbook for CompromisedIdentity {
    fn id(&self) -> &'static str {
        "compromised_identity"
    }

    fn name(&self) -> &'static str {
        "Contain compromised identity"
    }

    fn applies(&self, incident: &Incident) -> bool {
        fired(incident, "credential_abuse")
            || fired(incident, "vpn_identity_anomaly")
            || fired(incident, "privileged_access_anomaly")
    }

    fn actions(&self, incident: &Incident, graph: &AttackGraph) -> Vec<ResponseAction> {
        let mut actions = Vec::new();

        for identity in confirmed(graph, &[EntityKind::User, EntityKind::Account]) {
            actions.push(ResponseAction::new(
                ResponseActionKind::DisableAccount,
                identity.clone(),
                &incident.incident_id,
                0.88,
                format!(
                    "{} was used across several stages of this intrusion. Disabling it blocks \
                     further use, and will also interrupt any legitimate work under the same account.",
                    identity.name
                ),
            ));
            actions.push(ResponseAction::new(
                ResponseActionKind::ResetCredentials,
                identity.clone(),
                &incident.incident_id,
                0.80,
                format!(
                    "Rotating credentials for {} invalidates whatever the attacker obtained.",
                    identity.name
                ),
            ));
        }

        if fired(incident, "vpn_identity_anomaly") {
            for identity in confirmed(graph, &[EntityKind::User]) {
                actions.push(ResponseAction::new(
                    ResponseActionKind::RevokeSession,
                    identity.clone(),
                    &incident.incident_id,
                    0.85,
                    format!(
                        "The VPN session for {} began from an implausible location. Revoking it \
                         forces re-authentication.",
                        identity.name
                    ),
                ));
            }
        }

        actions
    }
}

pub struct MaliciousInfrastructure;

impl Playbook for MaliciousInfrastructure {
    fn id(&self) -> &'static str {
        "malicious_infrastructure"
    }

    fn name(&self) -> &'static str {
        "Block attacker infrastructure"
    }

    fn applies(&self, incident: &Incident) -> bool {
        fired(incident, "c2_connection") || fired(incident, "phishing_lure_delivered")
    }

    fn actions(&self, incident: &Incident, graph: &AttackGraph) -> Vec<ResponseAction> {
        let mut actions = Vec::new();

        for node in graph.nodes.iter().filter(|n| n.external) {
            let kind = match node.kind {
                EntityKind::Domain => ResponseActionKind::BlockDomain,
                EntityKind::Ip => ResponseActionKind::BlockIp,
                _ => continue,
            };

            actions.push(ResponseAction::new(
                kind,
                node.entity(),
                &incident.incident_id,
                0.90,
                format!(
                    "{} is external infrastructure involved in this incident. A perimeter block \
                     is low-risk and immediately reduces the attacker's options.",
                    node.label
                ),
            ));
        }

        actions
    }
}

pub struct RansomwareContainment;

impl Playbook for RansomwareContainment {
    fn id(&self) -> &'static str {
        "ransomware_containment"
    }

    fn name(&self) -> &'static str {
        "Ransomware containment and escalation"
    }

    fn applies(&self, incident: &Incident) -> bool {
        fired(incident, "ransomware_indicator")
    }

    fn actions(&self, incident: &Incident, graph: &AttackGraph) -> Vec<ResponseAction> {
        let mut actions = Vec::new();

        for server in confirmed(graph, &[EntityKind::Server]) {
            actions.push(ResponseAction::new(
                ResponseActionKind::IsolateEndpoint,
                server.clone(),
                &incident.incident_id,
                0.95,
                format!(
                    "Recovery was disabled on {} while files were being rewritten. Isolation is \
                     urgent, and on a server it will cause a service outage.",
                    server.name
                ),
            ));
        }

        for file in confirmed(graph, &[EntityKind::File]) {
            actions.push(ResponseAction::new(
                ResponseActionKind::QuarantineFile,
                file.clone(),
                &incident.incident_id,
                0.82,
                format!("{} is a staged archive of collected data.", file.name),
            ));
        }

        actions.push(ResponseAction::new(
            ResponseActionKind::Escalate,
            EntityRef::new(EntityKind::Application, "Incident Response Team"),
            &incident.incident_id,
            0.98,
            "Ransomware preparation against patient data warrants immediate escalation beyond \
             the SOC."
                .to_string(),
        ));

        actions
    }
}


pub struct StandardTriage;

impl Playbook for StandardTriage {
    fn id(&self) -> &'static str {
        "standard_triage"
    }

    fn name(&self) -> &'static str {
        "Standard triage"
    }

    fn applies(&self, _incident: &Incident) -> bool {
        true
    }

    fn actions(&self, incident: &Incident, _graph: &AttackGraph) -> Vec<ResponseAction> {
        let mut actions = vec![ResponseAction::new(
            ResponseActionKind::CreateInvestigationTask,
            EntityRef::new(EntityKind::Application, incident.incident_id.clone()),
            &incident.incident_id,
            1.0,
            format!(
                "Open a tracked investigation for {} covering the {} unresolved question(s) \
                 this incident records.",
                incident.incident_id,
                incident.unknowns.len()
            ),
        )];

        if incident.severity() >= Severity::High {
            actions.push(ResponseAction::new(
                ResponseActionKind::NotifyAnalyst,
                EntityRef::new(EntityKind::Application, "SOC Tier 2"),
                &incident.incident_id,
                1.0,
                format!(
                    "Overall risk is {:.0}/100, which is above the tier-2 notification threshold.",
                    incident.risk.overall_risk
                ),
            ));
        }

        actions
    }
}

pub fn all() -> Vec<Box<dyn Playbook>> {
    vec![
        Box::new(RansomwareContainment),
        Box::new(CompromisedEndpoint),
        Box::new(CompromisedIdentity),
        Box::new(MaliciousInfrastructure),
        Box::new(StandardTriage),
    ]
}
