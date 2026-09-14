use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::entity::EntityRef;
use crate::event::Severity;
use crate::mitre::MitreTechniqueRef;


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecuritySignal {
    pub signal_id: String,

    pub detector_id: String,
    pub title: String,
    pub timestamp: DateTime<Utc>,

    pub severity: Severity,

    pub confidence: f32,

    pub entities: Vec<EntityRef>,
    pub evidence_event_ids: Vec<String>,

    pub mitre: Vec<MitreTechniqueRef>,


    pub explanation: String,
}

impl SecuritySignal {

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
