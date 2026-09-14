

pub mod data;
pub mod directory;
pub mod email;
pub mod endpoint;
pub mod identity;
pub mod network;

use crate::engine::Detector;


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


        Box::new(directory::DirectorySprayDetector),
        Box::new(directory::KerberosAbuseDetector),
        Box::new(directory::SmbEnumerationDetector),
        Box::new(directory::DcSyncDetector),
    ]
}
