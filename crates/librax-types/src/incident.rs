use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::entity::{EntityRef, Relationship};
use crate::event::{Severity, SourceType};
use crate::mitre::MitreTechniqueRef;


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub event_id: String,
    pub source_type: SourceType,
    pub timestamp: DateTime<Utc>,
    pub severity: Severity,
    pub summary: String,

    pub cited_by: Vec<String>,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Exposure {
    Confirmed,
    Reachable,
    Potential,
}

impl Exposure {
    pub fn label(self) -> &'static str {
        match self {
            Exposure::Confirmed => "CONFIRMED",
            Exposure::Reachable => "REACHABLE",
            Exposure::Potential => "POTENTIAL",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AffectedAsset {
    pub entity: EntityRef,
    pub exposure: Exposure,

    pub criticality: u8,
    pub hospital: Option<String>,

    pub reason: String,
}


#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct BlastRadius {
    pub users: u32,
    pub endpoints: u32,
    pub servers: u32,
    pub critical_databases: u32,
    pub pacs_systems: u32,
    pub potentially_reachable: u32,
    pub level: Severity,
    pub assets: Vec<AffectedAsset>,
}

impl BlastRadius {
    pub fn confirmed_count(&self) -> usize {
        self.assets
            .iter()
            .filter(|a| a.exposure == Exposure::Confirmed)
            .count()
    }
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskContribution {

    pub factor: String,

    pub points: f32,
    pub detail: String,
}


#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct RiskScore {

    pub threat_confidence: f32,

    pub business_impact: f32,

    pub attack_progression: f32,

    pub overall_risk: f32,
    pub contributions: Vec<RiskContribution>,
}

impl RiskScore {
    pub fn severity(&self) -> Severity {
        Severity::from_score(self.overall_risk)
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentStatus {
    #[default]
    New,
    Investigating,
    Contained,
    Resolved,
    FalsePositive,
}

impl IncidentStatus {
    pub fn label(self) -> &'static str {
        match self {
            IncidentStatus::New => "NEW",
            IncidentStatus::Investigating => "INVESTIGATING",
            IncidentStatus::Contained => "CONTAINED",
            IncidentStatus::Resolved => "RESOLVED",
            IncidentStatus::FalsePositive => "FALSE POSITIVE",
        }
    }
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Incident {
    pub incident_id: String,
    pub title: String,
    pub status: IncidentStatus,


    pub signals: Vec<String>,
    pub evidence: Vec<Evidence>,
    pub entities: Vec<EntityRef>,
    pub relationships: Vec<Relationship>,

    pub risk: RiskScore,
    pub blast_radius: BlastRadius,
    pub mitre_techniques: Vec<MitreTechniqueRef>,


    #[serde(default)]
    pub peak_signal_severity: Severity,


    pub unknowns: Vec<String>,

    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub owner: Option<String>,
    pub notes: Vec<String>,
}

impl Incident {
    pub fn severity(&self) -> Severity {
        self.risk.severity().max(self.peak_signal_severity)
    }


    pub fn is_live(&self) -> bool {
        self.signals.iter().any(|id| id.starts_with("SIG-ad_"))
    }

    pub fn duration_minutes(&self) -> i64 {
        (self.last_seen - self.first_seen).num_minutes()
    }


    pub fn tactics(&self) -> Vec<crate::mitre::Tactic> {
        let mut tactics: Vec<_> = self.mitre_techniques.iter().map(|t| t.tactic).collect();
        tactics.sort_by_key(|t| t.stage_order());
        tactics.dedup();
        tactics
    }
}
