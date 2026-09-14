use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::entity::EntityRef;


#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    #[default]
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {

    pub fn weight(self) -> f32 {
        match self {
            Severity::Info => 0.10,
            Severity::Low => 0.30,
            Severity::Medium => 0.55,
            Severity::High => 0.80,
            Severity::Critical => 1.00,
        }
    }


    pub fn from_score(score: f32) -> Self {
        match score {
            s if s >= 90.0 => Severity::Critical,
            s if s >= 70.0 => Severity::High,
            s if s >= 40.0 => Severity::Medium,
            s if s >= 20.0 => Severity::Low,
            _ => Severity::Info,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Severity::Info => "INFO",
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        }
    }
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceDomain {
    Identity,
    Endpoint,
    Network,
    Server,
    Database,
    Medical,
    Cloud,
    Other,
}


#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceType {
    ActiveDirectory,
    EntraId,
    Edr,
    Firewall,
    Vpn,
    Pam,
    Dns,
    Proxy,
    Email,
    Server,
    Database,
    Pacs,
    Cloud,
    #[default]
    Unknown,
}

impl SourceType {
    pub fn label(self) -> &'static str {
        match self {
            SourceType::ActiveDirectory => "Active Directory",
            SourceType::EntraId => "Entra ID",
            SourceType::Edr => "EDR",
            SourceType::Firewall => "Firewall",
            SourceType::Vpn => "VPN",
            SourceType::Pam => "PAM",
            SourceType::Dns => "DNS",
            SourceType::Proxy => "Proxy",
            SourceType::Email => "Email",
            SourceType::Server => "Server",
            SourceType::Database => "Database",
            SourceType::Pacs => "PACS",
            SourceType::Cloud => "Cloud",
            SourceType::Unknown => "Unknown",
        }
    }

    pub fn domain(self) -> SourceDomain {
        match self {
            SourceType::ActiveDirectory | SourceType::EntraId | SourceType::Pam => {
                SourceDomain::Identity
            }
            SourceType::Edr => SourceDomain::Endpoint,
            SourceType::Firewall | SourceType::Vpn | SourceType::Dns | SourceType::Proxy => {
                SourceDomain::Network
            }
            SourceType::Email | SourceType::Server => SourceDomain::Server,
            SourceType::Database => SourceDomain::Database,
            SourceType::Pacs => SourceDomain::Medical,
            SourceType::Cloud => SourceDomain::Cloud,
            SourceType::Unknown => SourceDomain::Other,
        }
    }


    pub fn all() -> &'static [SourceType] {
        &[
            SourceType::ActiveDirectory,
            SourceType::EntraId,
            SourceType::Edr,
            SourceType::Firewall,
            SourceType::Vpn,
            SourceType::Pam,
            SourceType::Dns,
            SourceType::Proxy,
            SourceType::Email,
            SourceType::Server,
            SourceType::Database,
            SourceType::Pacs,
            SourceType::Cloud,
        ]
    }
}


#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventCategory {
    Authentication,
    Identity,
    Process,
    Network,
    Dns,
    File,
    Database,
    Email,
    PrivilegeEscalation,
    Configuration,
    MedicalImaging,
    #[default]
    Unknown,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawEvent {
    pub raw_id: String,
    pub source_type: SourceType,

    pub source_id: String,
    pub received_at: DateTime<Utc>,
    pub payload: Value,
}


#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct NetworkEndpoint {
    pub ip: Option<String>,
    pub port: Option<u16>,
    pub hostname: Option<String>,
    pub domain: Option<String>,
    pub bytes: Option<u64>,
}

impl NetworkEndpoint {
    pub fn from_ip(ip: impl Into<String>) -> Self {
        Self {
            ip: Some(ip.into()),
            ..Default::default()
        }
    }
}


#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ProcessContext {
    pub name: String,
    pub pid: Option<u32>,
    pub command_line: Option<String>,
    pub parent_name: Option<String>,
    pub hash_sha256: Option<String>,
    pub hash_md5: Option<String>,


    pub signed: Option<bool>,
    pub signer: Option<String>,
}


#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatReputation {
    #[default]
    Unknown,
    Clean,
    Suspicious,
    Malicious,
}


#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Enrichment {
    pub department: Option<String>,
    pub hospital: Option<String>,
    pub asset_role: Option<String>,

    pub asset_criticality: Option<u8>,

    pub data_sensitivity: Option<u8>,
    pub privileged_account: bool,
    pub service_account: bool,
    pub source_reputation: ThreatReputation,
    pub destination_reputation: ThreatReputation,

    pub maintenance_window: bool,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanonicalEvent {
    pub event_id: String,
    pub timestamp: DateTime<Utc>,
    pub source_type: SourceType,
    pub source_id: String,
    pub category: EventCategory,

    pub activity: String,

    pub principal: Option<EntityRef>,
    pub source: Option<NetworkEndpoint>,
    pub destination: Option<NetworkEndpoint>,

    pub host: Option<EntityRef>,
    pub process: Option<ProcessContext>,
    pub target: Option<EntityRef>,

    pub severity: Severity,

    pub raw_reference: Option<String>,
    pub message: String,
    pub attributes: HashMap<String, Value>,
    pub enrichment: Enrichment,
}

impl CanonicalEvent {
    pub fn user(&self) -> Option<&str> {
        self.principal.as_ref().map(|e| e.name.as_str())
    }

    pub fn host_name(&self) -> Option<&str> {
        self.host.as_ref().map(|e| e.name.as_str())
    }

    pub fn src_ip(&self) -> Option<&str> {
        self.source.as_ref()?.ip.as_deref()
    }

    pub fn dst_ip(&self) -> Option<&str> {
        self.destination.as_ref()?.ip.as_deref()
    }

    pub fn process_name(&self) -> Option<&str> {
        self.process.as_ref().map(|p| p.name.as_str())
    }

    pub fn command_line(&self) -> Option<&str> {
        self.process.as_ref()?.command_line.as_deref()
    }

    pub fn target_name(&self) -> Option<&str> {
        self.target.as_ref().map(|e| e.name.as_str())
    }

    pub fn attribute_str(&self, key: &str) -> Option<&str> {
        self.attributes.get(key)?.as_str()
    }

    pub fn attribute_f64(&self, key: &str) -> Option<f64> {
        self.attributes.get(key)?.as_f64()
    }


    pub fn entities(&self) -> Vec<EntityRef> {
        let mut out = Vec::new();
        for slot in [&self.principal, &self.host, &self.target] {
            if let Some(entity) = slot {
                out.push(entity.clone());
            }
        }
        out
    }
}
