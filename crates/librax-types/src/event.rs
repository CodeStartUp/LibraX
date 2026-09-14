use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::entity::EntityRef;

/// Shared severity ladder. Ordered so `Critical` is always the maximum.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
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
    /// Normalised 0.0-1.0 weight used by the scoring code.
    pub fn weight(self) -> f32 {
        match self {
            Severity::Info => 0.10,
            Severity::Low => 0.30,
            Severity::Medium => 0.55,
            Severity::High => 0.80,
            Severity::Critical => 1.00,
        }
    }

    /// Maps a 0-100 risk score onto the ladder the UI colours by.
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

/// Coarse grouping used by the timeline source filters in the UI.
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

/// The telemetry system an event originated from.
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

    /// Every source LibraX ingests in the demo environment.
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

/// OCSF-inspired classification of what an event describes.
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

/// What a connector hands to the normalizer: an opaque vendor payload plus
/// enough envelope metadata to trace it back to its origin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawEvent {
    pub raw_id: String,
    pub source_type: SourceType,
    /// Connector instance identifier, e.g. `edr-campus-04`.
    pub source_id: String,
    pub received_at: DateTime<Utc>,
    pub payload: Value,
}

/// One side of a network conversation.
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

/// Process detail for endpoint telemetry.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ProcessContext {
    pub name: String,
    pub pid: Option<u32>,
    pub command_line: Option<String>,
    pub parent_name: Option<String>,
    pub hash_sha256: Option<String>,
}

/// Reputation verdict attached during enrichment.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatReputation {
    #[default]
    Unknown,
    Clean,
    Suspicious,
    Malicious,
}

/// Business and identity context added by `librax-enrichment`.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Enrichment {
    pub department: Option<String>,
    pub hospital: Option<String>,
    pub asset_role: Option<String>,
    /// 0-100. Drives the business-impact half of the risk score.
    pub asset_criticality: Option<u8>,
    /// 0-100. Patient data pushes this high.
    pub data_sensitivity: Option<u8>,
    pub privileged_account: bool,
    pub service_account: bool,
    pub source_reputation: ThreatReputation,
    pub destination_reputation: ThreatReputation,
    /// Suppresses risk when the activity coincides with planned maintenance.
    pub maintenance_window: bool,
}

/// The single event model every source converges on.
///
/// Convenience accessors below expose the flat projection
/// (`user`, `host_name`, `src_ip`, ...) that detectors and the API use, so no
/// second event model is ever needed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanonicalEvent {
    pub event_id: String,
    pub timestamp: DateTime<Utc>,
    pub source_type: SourceType,
    pub source_id: String,
    pub category: EventCategory,
    /// Short verb phrase, e.g. `process_created`, `logon_success`.
    pub activity: String,

    pub principal: Option<EntityRef>,
    pub source: Option<NetworkEndpoint>,
    pub destination: Option<NetworkEndpoint>,

    pub host: Option<EntityRef>,
    pub process: Option<ProcessContext>,
    pub target: Option<EntityRef>,

    pub severity: Severity,
    /// Points back at the originating `RawEvent` so evidence stays traceable.
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

    /// Every entity this event mentions, for entity resolution and correlation.
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
