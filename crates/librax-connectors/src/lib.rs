//! Connector SDK plus the synthetic telemetry source used by the demo.
//!
//! Real integrations would implement [`Connector`] against a vendor API. The
//! hackathon build ships exactly one implementation, [`synthetic::SyntheticFleet`],
//! and it reports `is_synthetic() == true` so the UI can label it honestly
//! rather than implying a live Active Directory is attached.

pub mod connector;
pub mod synthetic;

pub use connector::{Connector, ConnectorError, ConnectorHealth};
pub use synthetic::{SyntheticFleet, TelemetryGenerator, scenario};
