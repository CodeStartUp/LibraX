use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::entity::{EntityRef, Relationship};
use crate::event::{Severity, SourceType};
use crate::mitre::MitreTechniqueRef;

/// A single citable event, denormalised for the evidence panel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub event_id: String,
    pub source_type: SourceType,
    pub timestamp: DateTime<Utc>,
    pub severity: Severity,
    pub summary: String,
    /// Which detector(s) cited this event.
    pub cited_by: Vec<String>,
}

/// How certain LibraX is that an asset is actually involved. Reachability is
/// not compromise, and the UI must not conflate the two.
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
    /// 0-100 business criticality carried over from enrichment.
    pub criticality: u8,
    pub hospital: Option<String>,
    /// Why this asset is in the blast radius.
    pub reason: String,
}

/// Graph-traversal estimate of what this intrusion can touch.
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

/// One line of the risk-explanation breakdown.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskContribution {
    /// Short label, e.g. `Critical asset`.
    pub factor: String,
    /// Signed points. Negative values reduce risk (e.g. maintenance context).
    pub points: f32,
    pub detail: String,
}

/// Threat confidence and business impact are deliberately kept apart: a noisy
/// detector on a critical database is a different problem from a confident
/// detector on a spare laptop.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct RiskScore {
    /// 0-100. How likely is this actually malicious?
    pub threat_confidence: f32,
    /// 0-100. How much does the affected environment matter?
    pub business_impact: f32,
    /// 0-100. How far along the kill chain is the intrusion?
    pub attack_progression: f32,
    /// 0-100 combined priority.
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

/// The one thing an analyst is asked to look at: many signals, one story.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Incident {
    pub incident_id: String,
    pub title: String,
    pub status: IncidentStatus,

    /// Signal ids, in the order they occurred.
    pub signals: Vec<String>,
    pub evidence: Vec<Evidence>,
    pub entities: Vec<EntityRef>,
    pub relationships: Vec<Relationship>,

    pub risk: RiskScore,
    pub blast_radius: BlastRadius,
    pub mitre_techniques: Vec<MitreTechniqueRef>,

    /// Facts LibraX has not established. Shown to the analyst verbatim.
    pub unknowns: Vec<String>,

    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub owner: Option<String>,
    pub notes: Vec<String>,
}

impl Incident {
    pub fn severity(&self) -> Severity {
        self.risk.severity()
    }

    pub fn duration_minutes(&self) -> i64 {
        (self.last_seen - self.first_seen).num_minutes()
    }

    /// Distinct ATT&CK tactics with evidence behind them, in kill-chain order.
    pub fn tactics(&self) -> Vec<crate::mitre::Tactic> {
        let mut tactics: Vec<_> = self.mitre_techniques.iter().map(|t| t.tactic).collect();
        tactics.sort_by_key(|t| t.stage_order());
        tactics.dedup();
        tactics
    }
}
