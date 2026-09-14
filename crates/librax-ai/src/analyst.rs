use std::collections::HashSet;

use librax_graph::AttackGraph;
use librax_mitre::Progression;
use librax_types::{EntityKind, Exposure, Incident};
use serde::Serialize;


#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Assertion {

    Fact,

    Inference,

    Unknown,
}

impl Assertion {
    pub fn label(self) -> &'static str {
        match self {
            Assertion::Fact => "FACT",
            Assertion::Inference => "INFERENCE",
            Assertion::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Statement {
    pub assertion: Assertion,
    pub label: String,
    pub text: String,

    pub evidence_event_ids: Vec<String>,
}

impl Statement {
    pub fn fact(text: impl Into<String>, evidence: Vec<String>) -> Self {
        Self {
            assertion: Assertion::Fact,
            label: Assertion::Fact.label().to_string(),
            text: text.into(),
            evidence_event_ids: evidence,
        }
    }

    pub fn inference(text: impl Into<String>) -> Self {
        Self {
            assertion: Assertion::Inference,
            label: Assertion::Inference.label().to_string(),
            text: text.into(),
            evidence_event_ids: Vec::new(),
        }
    }

    pub fn unknown(text: impl Into<String>) -> Self {
        Self {
            assertion: Assertion::Unknown,
            label: Assertion::Unknown.label().to_string(),
            text: text.into(),
            evidence_event_ids: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Briefing {
    pub incident_id: String,

    pub generator: String,
    pub summary: Vec<Statement>,
    pub risk_explanation: Vec<Statement>,
    pub evidence_explanation: Vec<Statement>,
    pub unknowns: Vec<Statement>,
    pub investigation_guidance: Vec<Statement>,
    pub response_suggestion: Vec<Statement>,
}

impl Briefing {
    pub fn all_statements(&self) -> impl Iterator<Item = &Statement> {
        self.summary
            .iter()
            .chain(&self.risk_explanation)
            .chain(&self.evidence_explanation)
            .chain(&self.unknowns)
            .chain(&self.investigation_guidance)
            .chain(&self.response_suggestion)
    }
}

pub struct BriefingInput<'a> {
    pub incident: &'a Incident,
    pub graph: &'a AttackGraph,
    pub progression: &'a Progression,

    pub correlation_reasons: &'a [String],

    pub playbooks: &'a [&'static str],
}

pub trait AnalystEngine {
    fn name(&self) -> &'static str;

    fn brief(&self, input: &BriefingInput<'_>) -> Briefing;
}


pub struct DeterministicAnalyst;

impl AnalystEngine for DeterministicAnalyst {
    fn name(&self) -> &'static str {
        "deterministic rule-based generator (not a language model)"
    }

    fn brief(&self, input: &BriefingInput<'_>) -> Briefing {
        Briefing {
            incident_id: input.incident.incident_id.clone(),
            generator: self.name().to_string(),
            summary: summary(input),
            risk_explanation: risk_explanation(input),
            evidence_explanation: evidence_explanation(input),
            unknowns: input
                .incident
                .unknowns
                .iter()
                .map(Statement::unknown)
                .collect(),
            investigation_guidance: guidance(input),
            response_suggestion: response(input),
        }
    }
}

fn named(graph: &AttackGraph, kind: EntityKind) -> Vec<String> {
    graph
        .nodes
        .iter()
        .filter(|n| n.kind == kind && n.exposure == Exposure::Confirmed)
        .map(|n| n.label.clone())
        .collect()
}

fn all_evidence(incident: &Incident) -> Vec<String> {
    incident
        .evidence
        .iter()
        .map(|e| e.event_id.clone())
        .collect()
}

fn summary(input: &BriefingInput<'_>) -> Vec<Statement> {
    let incident = input.incident;
    let mut out = Vec::new();

    let sources: HashSet<_> = incident.evidence.iter().map(|e| e.source_type).collect();
    out.push(Statement::fact(
        format!(
            "{} detections fired between {} and {}, a window of {} minutes, corroborated across \
             {} telemetry sources.",
            incident.signals.len(),
            incident.first_seen.format("%H:%M"),
            incident.last_seen.format("%H:%M"),
            incident.duration_minutes(),
            sources.len()
        ),
        all_evidence(incident),
    ));


    let users = named(input.graph, EntityKind::User);
    let accounts = named(input.graph, EntityKind::Account);
    let hosts = named(input.graph, EntityKind::Host);
    let servers = named(input.graph, EntityKind::Server);
    let databases = named(input.graph, EntityKind::Database);

    if !users.is_empty() || !hosts.is_empty() {
        out.push(Statement::fact(
            format!(
                "Confirmed involvement: identities {}, endpoints {}, servers {}{}.",
                join_or(&[users, accounts].concat(), "none"),
                join_or(&hosts, "none"),
                join_or(&servers, "none"),
                if databases.is_empty() {
                    String::new()
                } else {
                    format!(", databases {}", join_or(&databases, "none"))
                }
            ),
            all_evidence(incident),
        ));
    }

    let tactics: Vec<String> = input
        .progression
        .observed_tactics()
        .iter()
        .map(|t| t.label().to_string())
        .collect();
    if !tactics.is_empty() {
        out.push(Statement::fact(
            format!(
                "Behaviour was observed at {} of {} kill-chain stages: {}.",
                input.progression.observed_stages,
                input.progression.total_stages,
                tactics.join(" -> ")
            ),
            all_evidence(incident),
        ));
    }


    if input.progression.observed_stages >= 4 {
        out.push(Statement::inference(
            "The ordering and shared entities are consistent with one operator progressing \
             through a single intrusion rather than unrelated activity coinciding. LibraX \
             correlates behaviour; it does not observe intent.",
        ));
    }

    out
}

fn risk_explanation(input: &BriefingInput<'_>) -> Vec<Statement> {
    let risk = &input.incident.risk;
    let mut out = vec![Statement::fact(
        format!(
            "Overall risk is {:.0}/100, combining threat confidence {:.0} at 40%, business \
             impact {:.0} at 35%, and attack progression {:.0} at 25%.",
            risk.overall_risk,
            risk.threat_confidence,
            risk.business_impact,
            risk.attack_progression
        ),
        Vec::new(),
    )];


    let mut contributions = risk.contributions.clone();
    contributions.sort_by(|a, b| {
        b.points
            .abs()
            .partial_cmp(&a.points.abs())
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    for contribution in contributions.iter().take(4) {
        out.push(Statement::fact(
            format!(
                "{} contributed {:+.1} points: {}.",
                contribution.factor, contribution.points, contribution.detail
            ),
            Vec::new(),
        ));
    }

    out.push(Statement::fact(
        format!(
            "Threat confidence and business impact are scored separately. Here they differ by \
             {:.0} points, so the priority reflects both how likely the activity is malicious \
             and how much the affected environment matters.",
            (risk.business_impact - risk.threat_confidence).abs()
        ),
        Vec::new(),
    ));

    out
}

fn evidence_explanation(input: &BriefingInput<'_>) -> Vec<Statement> {
    let incident = input.incident;
    let mut out = Vec::new();

    for reason in input.correlation_reasons {
        out.push(Statement::fact(
            format!("Signals were linked because: {reason}."),
            Vec::new(),
        ));
    }

    let evidenced = incident
        .relationships
        .iter()
        .filter(|r| !r.evidence_event_ids.is_empty())
        .count();
    out.push(Statement::fact(
        format!(
            "{} of {} relationships in the attack graph cite the specific events that establish \
             them, drawn from {} evidence records. Any relationship can be opened to inspect \
             its source events.",
            evidenced,
            incident.relationships.len(),
            incident.evidence.len()
        ),
        all_evidence(incident),
    ));

    out
}

fn guidance(input: &BriefingInput<'_>) -> Vec<Statement> {
    let incident = input.incident;
    let mut out: Vec<Statement> = Vec::new();


    for unknown in &incident.unknowns {
        let step = if unknown.contains("Exfiltration is unconfirmed") {
            Some(format!(
                "Pull egress netflow for the hour after {} to establish whether the staged \
                 archive left the network. This is the difference between an attempted and an \
                 actual data breach.",
                incident.last_seen.format("%H:%M")
            ))
        } else if unknown.contains("encoded PowerShell") {
            Some(
                "Decode the base64 command line from the PowerShell event to determine what was \
                 actually executed and whether persistence was established."
                    .to_string(),
            )
        } else if unknown.contains("EDR covers") {
            Some(
                "Check whether any endpoint without an EDR agent authenticated to the affected \
                 servers; those hosts are a blind spot in this timeline."
                    .to_string(),
            )
        } else if unknown.contains("No file has been confirmed encrypted") {
            Some(
                "Verify backup and shadow-copy state on the affected servers before isolating \
                 them, so recovery options are known before containment changes anything."
                    .to_string(),
            )
        } else {
            None
        };

        if let Some(step) = step {
            out.push(Statement::inference(step));
        }
    }

    if !named(input.graph, EntityKind::User).is_empty() {
        out.push(Statement::inference(format!(
            "Confirm with {} whether the attachment was opened. User confirmation is the \
             cheapest way to distinguish a successful lure from a blocked one.",
            join_or(&named(input.graph, EntityKind::User), "the affected user")
        )));
    }

    out
}

fn response(input: &BriefingInput<'_>) -> Vec<Statement> {
    let mut out: Vec<Statement> = input
        .playbooks
        .iter()
        .map(|name| Statement::inference(format!("Playbook `{name}` applies to this incident.")))
        .collect();

    out.push(Statement::fact(
        "Every containment action in this build is simulated. Destructive actions additionally \
         require a named approver before they will run."
            .to_string(),
        Vec::new(),
    ));

    out
}

fn join_or(items: &[String], fallback: &str) -> String {
    if items.is_empty() {
        fallback.to_string()
    } else {
        items.join(", ")
    }
}
