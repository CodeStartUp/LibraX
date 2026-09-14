use serde::{Deserialize, Serialize};


#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tactic {
    Reconnaissance,
    ResourceDevelopment,
    InitialAccess,
    Execution,
    Persistence,
    PrivilegeEscalation,
    DefenseEvasion,
    CredentialAccess,
    Discovery,
    LateralMovement,
    Collection,
    CommandAndControl,
    Exfiltration,
    Impact,
}

impl Tactic {

    pub fn id(self) -> &'static str {
        match self {
            Tactic::Reconnaissance => "TA0043",
            Tactic::ResourceDevelopment => "TA0042",
            Tactic::InitialAccess => "TA0001",
            Tactic::Execution => "TA0002",
            Tactic::Persistence => "TA0003",
            Tactic::PrivilegeEscalation => "TA0004",
            Tactic::DefenseEvasion => "TA0005",
            Tactic::CredentialAccess => "TA0006",
            Tactic::Discovery => "TA0007",
            Tactic::LateralMovement => "TA0008",
            Tactic::Collection => "TA0009",
            Tactic::CommandAndControl => "TA0011",
            Tactic::Exfiltration => "TA0010",
            Tactic::Impact => "TA0040",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Tactic::Reconnaissance => "Reconnaissance",
            Tactic::ResourceDevelopment => "Resource Development",
            Tactic::InitialAccess => "Initial Access",
            Tactic::Execution => "Execution",
            Tactic::Persistence => "Persistence",
            Tactic::PrivilegeEscalation => "Privilege Escalation",
            Tactic::DefenseEvasion => "Defense Evasion",
            Tactic::CredentialAccess => "Credential Access",
            Tactic::Discovery => "Discovery",
            Tactic::LateralMovement => "Lateral Movement",
            Tactic::Collection => "Collection",
            Tactic::CommandAndControl => "Command and Control",
            Tactic::Exfiltration => "Exfiltration",
            Tactic::Impact => "Impact",
        }
    }


    pub fn stage_order(self) -> u8 {
        match self {
            Tactic::Reconnaissance => 0,
            Tactic::ResourceDevelopment => 1,
            Tactic::InitialAccess => 2,
            Tactic::Execution => 3,
            Tactic::Persistence => 4,
            Tactic::PrivilegeEscalation => 5,
            Tactic::DefenseEvasion => 6,
            Tactic::CredentialAccess => 7,
            Tactic::Discovery => 8,
            Tactic::LateralMovement => 9,
            Tactic::CommandAndControl => 10,
            Tactic::Collection => 11,
            Tactic::Exfiltration => 12,
            Tactic::Impact => 13,
        }
    }


    pub fn chain() -> &'static [Tactic] {
        &[
            Tactic::InitialAccess,
            Tactic::Execution,
            Tactic::CommandAndControl,
            Tactic::CredentialAccess,
            Tactic::Discovery,
            Tactic::LateralMovement,
            Tactic::Collection,
            Tactic::Impact,
        ]
    }
}


#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MitreTechniqueRef {

    pub technique_id: String,
    pub name: String,
    pub tactic: Tactic,
    pub confidence: f32,

    pub rationale: String,
}

impl MitreTechniqueRef {

    pub fn parent_id(&self) -> &str {
        match self.technique_id.split_once('.') {
            Some((parent, _)) => parent,
            None => &self.technique_id,
        }
    }
}
