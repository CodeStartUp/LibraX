use std::collections::HashSet;

use chrono::Utc;
use librax_graph::AttackGraph;
use librax_types::{Incident, ResponseAction, ResponseActionKind, ResponseStatus};
use thiserror::Error;

use crate::playbooks::{self, Playbook};

#[derive(Debug, Error)]
pub enum ResponseError {
    #[error("`{action_id}` is destructive and cannot run without a named approver")]
    ApprovalRequired { action_id: String },

    #[error("`{action_id}` has already been simulated")]
    AlreadySimulated { action_id: String },

    #[error("`{action_id}` was declined by an analyst")]
    Declined { action_id: String },
}

#[derive(Debug, Clone)]
pub struct SimulationOutcome {
    pub action: ResponseAction,

    pub narrative: String,
    pub approved_by: Option<String>,
}

pub struct ResponseEngine {
    playbooks: Vec<Box<dyn Playbook>>,
}

impl Default for ResponseEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl ResponseEngine {
    pub fn new() -> Self {
        Self {
            playbooks: playbooks::all(),
        }
    }


    pub fn matching_playbooks(&self, incident: &Incident) -> Vec<&'static str> {
        self.playbooks
            .iter()
            .filter(|p| p.applies(incident))
            .map(|p| p.name())
            .collect()
    }


    pub fn recommend(&self, incident: &Incident, graph: &AttackGraph) -> Vec<ResponseAction> {
        let mut seen: HashSet<String> = HashSet::new();
        let mut actions: Vec<ResponseAction> = Vec::new();

        for playbook in self.playbooks.iter().filter(|p| p.applies(incident)) {
            for action in playbook.actions(incident, graph) {


                if seen.insert(action.action_id.clone()) {
                    actions.push(action);
                }
            }
        }

        actions.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.action_id.cmp(&b.action_id))
        });
        actions
    }


    pub fn simulate(
        &self,
        action: &mut ResponseAction,
        approved_by: Option<&str>,
    ) -> Result<SimulationOutcome, ResponseError> {
        match action.status {
            ResponseStatus::Simulated => {
                return Err(ResponseError::AlreadySimulated {
                    action_id: action.action_id.clone(),
                });
            }
            ResponseStatus::Declined => {
                return Err(ResponseError::Declined {
                    action_id: action.action_id.clone(),
                });
            }
            _ => {}
        }

        if action.requires_approval && approved_by.is_none() {
            action.status = ResponseStatus::AwaitingApproval;
            return Err(ResponseError::ApprovalRequired {
                action_id: action.action_id.clone(),
            });
        }

        let narrative = effect_of(action);
        let result = format!(
            "SIMULATED. {narrative} No change was made to any system; LibraX has no live \
             integration with the target."
        );

        action.status = ResponseStatus::Simulated;
        action.simulated_at = Some(Utc::now());
        action.result = Some(result);

        tracing::info!(
            action = %action.action_id,
            kind = ?action.kind,
            target = %action.target.name,
            approver = approved_by.unwrap_or("n/a"),
            "response simulated"
        );

        Ok(SimulationOutcome {
            action: action.clone(),
            narrative,
            approved_by: approved_by.map(str::to_string),
        })
    }

    pub fn decline(&self, action: &mut ResponseAction, reason: &str) {
        action.status = ResponseStatus::Declined;
        action.result = Some(format!("Declined by analyst: {reason}"));
    }
}


fn effect_of(action: &ResponseAction) -> String {
    let target = &action.target.name;

    match action.kind {
        ResponseActionKind::IsolateEndpoint => format!(
            "{target} would be cut off from the network at the agent, keeping the machine \
             running and available for forensics."
        ),
        ResponseActionKind::DisableAccount => format!(
            "{target} would be disabled in the directory, ending new authentication for that \
             account everywhere."
        ),
        ResponseActionKind::RevokeSession => format!(
            "Active sessions and refresh tokens for {target} would be invalidated, forcing \
             re-authentication."
        ),
        ResponseActionKind::BlockIp => {
            format!("{target} would be added to the perimeter deny list on every campus firewall.")
        }
        ResponseActionKind::BlockDomain => {
            format!("Resolution of {target} would be sinkholed at the internal DNS resolvers.")
        }
        ResponseActionKind::QuarantineFile => format!(
            "{target} would be moved to quarantine storage with its hash retained as evidence."
        ),
        ResponseActionKind::KillProcess => {
            format!("The running {target} process tree would be terminated.")
        }
        ResponseActionKind::ResetCredentials => format!(
            "A forced credential rotation would be issued for {target}, invalidating anything \
             the attacker captured."
        ),
        ResponseActionKind::CreateInvestigationTask => format!(
            "A tracked investigation task would be opened for {target} in the case management \
             system."
        ),
        ResponseActionKind::NotifyAnalyst => {
            format!("{target} would be paged with a link to this incident.")
        }
        ResponseActionKind::Escalate => {
            format!("{target} would be engaged out-of-hours under the ransomware escalation path.")
        }
    }
}
