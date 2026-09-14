use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::entity::EntityRef;


#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseActionKind {
    IsolateEndpoint,
    DisableAccount,
    RevokeSession,
    BlockIp,
    BlockDomain,
    QuarantineFile,
    KillProcess,
    ResetCredentials,
    CreateInvestigationTask,
    NotifyAnalyst,
    Escalate,
}

impl ResponseActionKind {
    pub fn label(self) -> &'static str {
        match self {
            ResponseActionKind::IsolateEndpoint => "Isolate Endpoint",
            ResponseActionKind::DisableAccount => "Disable Account",
            ResponseActionKind::RevokeSession => "Revoke Session",
            ResponseActionKind::BlockIp => "Block IP",
            ResponseActionKind::BlockDomain => "Block Domain",
            ResponseActionKind::QuarantineFile => "Quarantine File",
            ResponseActionKind::KillProcess => "Kill Process",
            ResponseActionKind::ResetCredentials => "Reset Credentials",
            ResponseActionKind::CreateInvestigationTask => "Create Investigation Task",
            ResponseActionKind::NotifyAnalyst => "Notify Analyst",
            ResponseActionKind::Escalate => "Escalate",
        }
    }


    pub fn is_destructive(self) -> bool {
        matches!(
            self,
            ResponseActionKind::IsolateEndpoint
                | ResponseActionKind::DisableAccount
                | ResponseActionKind::RevokeSession
                | ResponseActionKind::BlockIp
                | ResponseActionKind::BlockDomain
                | ResponseActionKind::QuarantineFile
                | ResponseActionKind::KillProcess
                | ResponseActionKind::ResetCredentials
        )
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseStatus {

    #[default]
    Recommended,
    AwaitingApproval,
    Simulated,
    Declined,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseAction {
    pub action_id: String,
    pub kind: ResponseActionKind,
    pub target: EntityRef,
    pub incident_id: String,


    pub confidence: f32,
    pub rationale: String,
    pub requires_approval: bool,
    pub status: ResponseStatus,

    pub created_at: DateTime<Utc>,
    pub simulated_at: Option<DateTime<Utc>>,

    pub result: Option<String>,
}

impl ResponseAction {
    pub fn new(
        kind: ResponseActionKind,
        target: EntityRef,
        incident_id: impl Into<String>,
        confidence: f32,
        rationale: impl Into<String>,
    ) -> Self {
        let incident_id = incident_id.into();

        Self {


            action_id: format!(
                "ACT-{}-{}-{}",
                incident_id,
                slug(kind.label()),
                slug(&target.name)
            ),
            kind,
            target,
            incident_id,
            confidence: confidence.clamp(0.0, 1.0),
            rationale: rationale.into(),
            requires_approval: kind.is_destructive(),
            status: ResponseStatus::Recommended,
            created_at: Utc::now(),
            simulated_at: None,
            result: None,
        }
    }
}


fn slug(value: &str) -> String {
    value
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect()
}
