use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::entity::EntityRef;
use crate::event::Severity;
use crate::mitre::MitreTechniqueRef;

/// What a detector emits. Signals are the currency of correlation: never raw
/// events, never finished incidents.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecuritySignal {
    pub signal_id: String,
    /// Stable detector identity, e.g. `powershell_encoded_command`.
    pub detector_id: String,
    pub title: String,
    pub timestamp: DateTime<Utc>,

    pub severity: Severity,
    /// 0.0-1.0 detector confidence.
    pub confidence: f32,

    pub entities: Vec<EntityRef>,
    pub evidence_event_ids: Vec<String>,

    pub mitre: Vec<MitreTechniqueRef>,

    /// Human-readable justification. A detector that cannot explain itself has
    /// no business raising a signal.
    pub explanation: String,
}

impl SecuritySignal {
    /// The furthest-along tactic this signal implies, if any.
    pub fn primary_tactic(&self) -> Option<crate::mitre::Tactic> {
        self.mitre
            .iter()
            .map(|m| m.tactic)
            .max_by_key(|t| t.stage_order())
    }

    pub fn entity_ids(&self) -> Vec<&str> {
        self.entities.iter().map(|e| e.id.as_str()).collect()
    }

    pub fn mentions_entity(&self, entity_id: &str) -> bool {
        self.entities.iter().any(|e| e.id == entity_id)
    }
}
