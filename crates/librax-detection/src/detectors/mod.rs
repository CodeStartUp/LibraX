//! The detector catalogue.
//!
//! Detectors are grouped by the telemetry domain they reason about, not by the
//! vendor that produced the events, because by this point every event looks the
//! same.

pub mod data;
pub mod email;
pub mod endpoint;
pub mod identity;
pub mod network;

use crate::engine::Detector;

/// Every detector the engine runs, in rough kill-chain order.
pub fn all() -> Vec<Box<dyn Detector>> {
    vec![
        Box::new(email::PhishingDetector),
        Box::new(identity::VpnAnomalyDetector),
        Box::new(endpoint::PowerShellDetector),
        Box::new(network::CommandAndControlDetector),
        Box::new(network::NetworkDiscoveryDetector),
        Box::new(identity::CredentialAbuseDetector),
        Box::new(data::LateralMovementDetector),
        Box::new(identity::PrivilegedAccessDetector),
        Box::new(data::DatabaseExfiltrationDetector),
        Box::new(endpoint::DataStagingDetector),
        Box::new(endpoint::RansomwareDetector),
        Box::new(network::VolumetricDetector),
        Box::new(network::BlockedOutboundDetector),
    ]
}
