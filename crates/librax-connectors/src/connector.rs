use async_trait::async_trait;
use chrono::{DateTime, Utc};
use librax_types::{RawEvent, SourceType};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConnectorError {
    #[error("connector `{source_id}` unreachable: {reason}")]
    Unreachable { source_id: String, reason: String },

    #[error("connector `{source_id}` returned an unreadable payload: {reason}")]
    BadPayload { source_id: String, reason: String },

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Json(#[from] serde_json::Error),
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorHealth {
    pub source_id: String,
    pub source_type: SourceType,
    pub reachable: bool,
    pub last_event_at: Option<DateTime<Utc>>,
    pub events_collected: u64,
    pub errors: u64,

    pub assets_reporting: u32,
    pub assets_expected: u32,
    pub detail: Option<String>,
}


#[async_trait]
pub trait Connector: Send + Sync {
    fn source_id(&self) -> &str;

    fn source_type(&self) -> SourceType;


    fn is_synthetic(&self) -> bool {
        true
    }

    async fn health(&self) -> ConnectorHealth;

    async fn collect(&self) -> Result<Vec<RawEvent>, ConnectorError>;
}
