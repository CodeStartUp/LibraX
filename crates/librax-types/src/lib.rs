//! Canonical shared types for LibraX.
//!
//! Every crate in the workspace converges on the models defined here, so no
//! detector, correlator or scorer ever sees a vendor-specific event shape.

pub mod entity;
pub mod event;
pub mod incident;
pub mod mitre;
pub mod response;
pub mod rng;
pub mod signal;
pub mod source;

pub use entity::{EntityKind, EntityRef, RelationType, Relationship};
pub use event::{
    CanonicalEvent, Enrichment, EventCategory, NetworkEndpoint, ProcessContext, RawEvent, Severity,
    SourceDomain, SourceType, ThreatReputation,
};
pub use incident::{
    AffectedAsset, BlastRadius, Evidence, Exposure, Incident, IncidentStatus, RiskContribution,
    RiskScore,
};
pub use mitre::{MitreTechniqueRef, Tactic};
pub use response::{ResponseAction, ResponseActionKind, ResponseStatus};
pub use rng::SplitMix64;
pub use signal::SecuritySignal;
pub use source::{DEFAULT_BLIND_SPOT_AFTER_SECS, SourceHealth, SourceStatus};
