use std::collections::HashMap;

use librax_types::{EntityKind, EntityRef, SplitMix64};
use serde::{Deserialize, Serialize};

/// Fixed names used by the scripted demo intrusion. Detection, correlation and
/// the simulator all refer to these, so the story always resolves against real
/// inventory instead of invented entities.
pub mod demo {
    pub const HOSPITAL: &str = "Campus-04";
    pub const USER: &str = "alice.hr";
    pub const USER_DEPARTMENT: &str = "HR";
    pub const ENDPOINT: &str = "HR-PC-23";
    pub const ENDPOINT_IP: &str = "10.10.2.15";
    pub const ATTACKER_IP: &str = "185.220.101.47";
    pub const C2_DOMAIN: &str = "cdn-sync-update.net";
    /// Lookalike domain the spear-phishing lure is sent from.
    pub const PHISHING_DOMAIN: &str = "secure-doc-review.top";
    pub const APP_SERVER: &str = "APP-SRV-07";
    pub const APP_SERVER_IP: &str = "10.20.7.7";
    pub const DB_SERVER: &str = "DB-SRV-02";
    pub const DB_SERVER_IP: &str = "10.20.8.2";
    pub const PATIENT_DB: &str = "PATIENT-DB";
    pub const PACS: &str = "PACS-02";
    pub const PRIVILEGED_ACCOUNT: &str = "svc.dbadmin";
    pub const STAGED_FILE: &str = "archive_patient_export.zip";
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetRole {
    Workstation,
    Server,
    Database,
    Pacs,
    DomainController,
    Firewall,
    CloudWorkload,
}

impl AssetRole {
    pub fn label(self) -> &'static str {
        match self {
            AssetRole::Workstation => "Workstation",
            AssetRole::Server => "Server",
            AssetRole::Database => "Database",
            AssetRole::Pacs => "PACS Imaging",
            AssetRole::DomainController => "Domain Controller",
            AssetRole::Firewall => "Firewall",
            AssetRole::CloudWorkload => "Cloud Workload",
        }
    }

    pub fn entity_kind(self) -> EntityKind {
        match self {
            AssetRole::Workstation => EntityKind::Host,
            AssetRole::Database => EntityKind::Database,
            AssetRole::CloudWorkload => EntityKind::CloudResource,
            AssetRole::Pacs => EntityKind::Device,
            _ => EntityKind::Server,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hospital {
    pub id: String,
    pub name: String,
    pub region: String,
}

/// What an asset runs, which decides how the console draws it and what a
/// containment action would actually mean for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    Windows,
    Linux,
    /// Firewalls and switches: no agent, so no isolation action.
    NetworkAppliance,
    /// Imaging and clinical devices. Regulated, frequently unpatchable, and never
    /// something to isolate without clinical sign-off.
    MedicalDevice,
    Cloud,
}

impl Platform {
    pub fn label(self) -> &'static str {
        match self {
            Platform::Windows => "Windows",
            Platform::Linux => "Linux",
            Platform::NetworkAppliance => "Network appliance",
            Platform::MedicalDevice => "Medical device",
            Platform::Cloud => "Cloud workload",
        }
    }

    /// Whether an endpoint agent can plausibly isolate it.
    pub fn agent_capable(self) -> bool {
        matches!(self, Platform::Windows | Platform::Linux)
    }
}

impl AssetRole {
    /// The platform a role runs on.
    ///
    /// `index` breaks the tie for roles that are genuinely mixed in a hospital
    /// estate, so the fleet is not implausibly uniform.
    pub fn platform(self, index: usize) -> Platform {
        match self {
            AssetRole::Workstation => Platform::Windows,
            AssetRole::DomainController => Platform::Windows,
            AssetRole::Firewall => Platform::NetworkAppliance,
            AssetRole::Pacs => Platform::MedicalDevice,
            AssetRole::CloudWorkload => Platform::Cloud,
            AssetRole::Database => Platform::Linux,
            // Application servers are the genuinely mixed case.
            AssetRole::Server => {
                if index % 3 == 0 {
                    Platform::Linux
                } else {
                    Platform::Windows
                }
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Asset {
    pub entity: EntityRef,
    pub role: AssetRole,
    pub platform: Platform,
    pub hospital: String,
    pub ip: String,
    /// 0-100 business criticality.
    pub criticality: u8,
    /// 0-100 sensitivity of the data it holds.
    pub data_sensitivity: u8,
    /// Whether an EDR agent reports on this asset. Gaps create the coverage
    /// percentage the SOC dashboard shows.
    pub edr_covered: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    pub entity: EntityRef,
    pub department: String,
    pub hospital: String,
    pub privileged: bool,
    pub service_account: bool,
}

/// Knobs for the synthetic environment, driven by env vars in the demo.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InventorySpec {
    pub seed: u64,
    pub hospitals: usize,
    pub endpoints: usize,
}

impl Default for InventorySpec {
    fn default() -> Self {
        Self {
            seed: 42,
            hospitals: 18,
            endpoints: 10_482,
        }
    }
}

/// The synthetic hospital network, reproducible from a seed.
#[derive(Debug, Clone)]
pub struct Inventory {
    pub spec: InventorySpec,
    pub hospitals: Vec<Hospital>,
    pub assets: Vec<Asset>,
    pub identities: Vec<Identity>,

    by_name: HashMap<String, usize>,
    by_ip: HashMap<String, usize>,
    identity_by_name: HashMap<String, usize>,
}

const DEPARTMENTS: &[&str] = &[
    "HR",
    "Radiology",
    "Cardiology",
    "Emergency",
    "Pharmacy",
    "Finance",
    "IT",
    "Oncology",
    "Pathology",
    "Administration",
];

const REGIONS: &[&str] = &["North", "South", "East", "West", "Central", "Coastal"];

const FIRST_NAMES: &[&str] = &[
    "alice", "brian", "chen", "divya", "elena", "farid", "grace", "hugo", "imani", "jonas",
    "kavya", "liam", "mira", "noah", "omar", "priya", "quinn", "rosa", "samir", "tara",
];

const LAST_NAMES: &[&str] = &[
    "adams", "bose", "clark", "dutta", "evans", "ferro", "gupta", "hall", "iyer", "jain",
];

/// Short site code used in machine names: `campus-04` becomes `C04`.
fn campus_code(hospital_id: &str) -> String {
    let digits: String = hospital_id.chars().filter(|c| c.is_ascii_digit()).collect();
    format!(
        "C{}",
        if digits.is_empty() {
            "00".into()
        } else {
            digits
        }
    )
}

impl Inventory {
    pub fn generate(spec: InventorySpec) -> Self {
        let mut rng = SplitMix64::new(spec.seed);

        let hospitals: Vec<Hospital> = (1..=spec.hospitals)
            .map(|i| Hospital {
                id: format!("campus-{i:02}"),
                name: format!("Campus-{i:02}"),
                region: REGIONS[(i - 1) % REGIONS.len()].to_string(),
            })
            .collect();

        let mut assets = Vec::with_capacity(spec.endpoints + spec.hospitals * 8);
        let mut identities = Vec::new();

        // Workstations, spread evenly across campuses. One slot is left for the
        // demo endpoint installed below, so the fleet total matches `endpoints`.
        for i in 1..spec.endpoints {
            let hospital = &hospitals[i % hospitals.len()];
            let department = DEPARTMENTS[i % DEPARTMENTS.len()];
            let name = format!("{}-PC-{:05}", department.to_uppercase(), i);
            assets.push(Asset {
                entity: EntityRef::new(EntityKind::Host, &name),
                role: AssetRole::Workstation,
                platform: AssetRole::Workstation.platform(i),
                hospital: hospital.name.clone(),
                ip: format!("10.{}.{}.{}", 10 + i % 18, (i / 250) % 256, i % 250 + 2),
                criticality: rng.range_u8(20, 45),
                data_sensitivity: rng.range_u8(10, 40),
                // ~94% agent coverage, which is what creates the blind-spot story.
                edr_covered: rng.chance_permille(942),
            });
        }

        // Per-campus infrastructure.
        //
        // Names carry the campus code. A shared numbering scheme would eventually
        // collide with the documented demo servers, and a collision is worse than
        // ugly here: two hospitals appearing to share a database server makes
        // unrelated activity at both correlate on an entity they never shared.
        for (idx, hospital) in hospitals.iter().enumerate() {
            let code = campus_code(&hospital.id);
            let infra = [
                (
                    format!("{code}-DC-SRV-01"),
                    AssetRole::DomainController,
                    92u8,
                    70u8,
                ),
                (format!("{code}-APP-SRV-01"), AssetRole::Server, 74, 55),
                (format!("{code}-FILE-SRV-01"), AssetRole::Server, 68, 72),
                (format!("{code}-DB-SRV-01"), AssetRole::Database, 96, 97),
                (format!("{code}-PACS-01"), AssetRole::Pacs, 95, 98),
                (format!("{code}-FW-EDGE-01"), AssetRole::Firewall, 80, 20),
                (
                    format!("{code}-CLOUD-WL-01"),
                    AssetRole::CloudWorkload,
                    70,
                    60,
                ),
            ];

            for (slot, (name, role, criticality, sensitivity)) in infra.into_iter().enumerate() {
                assets.push(Asset {
                    entity: EntityRef::new(role.entity_kind(), &name),
                    role,
                    platform: role.platform(idx),
                    hospital: hospital.name.clone(),
                    // One address per machine: sharing an address across a campus
                    // would make entity resolution fold the whole rack into one host.
                    ip: format!("10.{}.{}.{}", 20 + idx, 1 + idx % 8, 2 + slot),
                    criticality,
                    data_sensitivity: sensitivity,
                    edr_covered: role != AssetRole::Pacs && role != AssetRole::Firewall,
                });
            }
        }

        // Staff identities.
        for i in 0..(spec.endpoints / 4) {
            let first = FIRST_NAMES[i % FIRST_NAMES.len()];
            let last = LAST_NAMES[(i / FIRST_NAMES.len()) % LAST_NAMES.len()];
            let department = DEPARTMENTS[i % DEPARTMENTS.len()];
            let hospital = &hospitals[i % hospitals.len()];
            let name = format!("{first}.{last}{i}");
            identities.push(Identity {
                entity: EntityRef::user(&name),
                department: department.to_string(),
                hospital: hospital.name.clone(),
                privileged: department == "IT" && i % 7 == 0,
                service_account: false,
            });
        }

        // Every campus administers its own databases. Without a local account per
        // site, campuses whose generated staff happen to include no privileged user
        // fall back to the one demo account, and unrelated activity at different
        // hospitals then correlates on an identity they do not actually share.
        for hospital in &hospitals {
            if hospital.name == demo::HOSPITAL {
                // install_demo_entities pins the documented account here.
                continue;
            }

            let name = format!("svc.dbadmin.{}", hospital.name.to_lowercase());
            identities.push(Identity {
                entity: EntityRef::new(EntityKind::Account, &name),
                department: "IT".to_string(),
                hospital: hospital.name.clone(),
                privileged: true,
                service_account: true,
            });
        }

        let mut inventory = Self {
            spec,
            hospitals,
            assets,
            identities,
            by_name: HashMap::new(),
            by_ip: HashMap::new(),
            identity_by_name: HashMap::new(),
        };

        inventory.install_demo_entities();
        inventory.reindex();
        inventory
    }

    /// Guarantees the scripted intrusion always has real inventory to point at.
    fn install_demo_entities(&mut self) {
        let fixed_assets = [
            (
                demo::ENDPOINT,
                AssetRole::Workstation,
                demo::ENDPOINT_IP,
                40u8,
                35u8,
                true,
            ),
            (
                demo::APP_SERVER,
                AssetRole::Server,
                demo::APP_SERVER_IP,
                78,
                60,
                true,
            ),
            (
                demo::DB_SERVER,
                AssetRole::Server,
                demo::DB_SERVER_IP,
                94,
                92,
                true,
            ),
            (
                demo::PATIENT_DB,
                AssetRole::Database,
                demo::DB_SERVER_IP,
                98,
                99,
                true,
            ),
            (demo::PACS, AssetRole::Pacs, "10.24.5.12", 95, 98, false),
        ];

        // Remove any generated collisions before inserting the canonical versions.
        self.assets.retain(|a| {
            !fixed_assets
                .iter()
                .any(|(name, ..)| a.entity.name.eq_ignore_ascii_case(name))
        });

        for (index, (name, role, ip, criticality, sensitivity, covered)) in
            fixed_assets.into_iter().enumerate()
        {
            self.assets.push(Asset {
                entity: EntityRef::new(role.entity_kind(), name),
                role,
                platform: role.platform(index),
                hospital: demo::HOSPITAL.to_string(),
                ip: ip.to_string(),
                criticality,
                data_sensitivity: sensitivity,
                edr_covered: covered,
            });
        }

        self.identities.retain(|i| {
            !i.entity.name.eq_ignore_ascii_case(demo::USER)
                && !i.entity.name.eq_ignore_ascii_case(demo::PRIVILEGED_ACCOUNT)
        });

        self.identities.push(Identity {
            entity: EntityRef::user(demo::USER),
            department: demo::USER_DEPARTMENT.to_string(),
            hospital: demo::HOSPITAL.to_string(),
            privileged: false,
            service_account: false,
        });
        self.identities.push(Identity {
            entity: EntityRef::new(EntityKind::Account, demo::PRIVILEGED_ACCOUNT),
            department: "IT".to_string(),
            hospital: demo::HOSPITAL.to_string(),
            privileged: true,
            service_account: true,
        });
    }

    fn reindex(&mut self) {
        self.by_name = self
            .assets
            .iter()
            .enumerate()
            .map(|(i, a)| (a.entity.name.to_lowercase(), i))
            .collect();
        self.by_ip = self
            .assets
            .iter()
            .enumerate()
            .map(|(i, a)| (a.ip.clone(), i))
            .collect();
        self.identity_by_name = self
            .identities
            .iter()
            .enumerate()
            .map(|(i, id)| (id.entity.name.to_lowercase(), i))
            .collect();
    }

    pub fn asset_by_name(&self, name: &str) -> Option<&Asset> {
        self.by_name
            .get(&name.to_lowercase())
            .map(|&i| &self.assets[i])
    }

    pub fn asset_by_ip(&self, ip: &str) -> Option<&Asset> {
        self.by_ip.get(ip).map(|&i| &self.assets[i])
    }

    pub fn identity_by_name(&self, name: &str) -> Option<&Identity> {
        self.identity_by_name
            .get(&name.to_lowercase())
            .map(|&i| &self.identities[i])
    }

    pub fn endpoint_count(&self) -> usize {
        self.assets
            .iter()
            .filter(|a| a.role == AssetRole::Workstation)
            .count()
    }

    pub fn server_count(&self) -> usize {
        self.assets
            .iter()
            .filter(|a| {
                matches!(
                    a.role,
                    AssetRole::Server | AssetRole::DomainController | AssetRole::Database
                )
            })
            .count()
    }

    /// EDR agent coverage across workstations, as a percentage.
    pub fn edr_coverage(&self) -> (u32, u32, f32) {
        let workstations: Vec<_> = self
            .assets
            .iter()
            .filter(|a| a.role == AssetRole::Workstation)
            .collect();
        let total = workstations.len() as u32;
        let covered = workstations.iter().filter(|a| a.edr_covered).count() as u32;
        let pct = if total == 0 {
            0.0
        } else {
            covered as f32 / total as f32 * 100.0
        };
        (covered, total, pct)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_is_deterministic() {
        let a = Inventory::generate(InventorySpec::default());
        let b = Inventory::generate(InventorySpec::default());
        assert_eq!(a.assets.len(), b.assets.len());
        assert_eq!(a.edr_coverage().0, b.edr_coverage().0);
    }

    #[test]
    fn demo_entities_always_resolve() {
        let inv = Inventory::generate(InventorySpec::default());
        assert!(inv.asset_by_name(demo::ENDPOINT).is_some());
        assert!(inv.asset_by_name(demo::PATIENT_DB).is_some());
        assert!(inv.asset_by_name(demo::PACS).is_some());
        assert!(inv.identity_by_name(demo::USER).is_some());

        let db = inv.asset_by_name(demo::PATIENT_DB).unwrap();
        assert!(db.criticality >= 95, "patient DB must be business critical");

        let account = inv.identity_by_name(demo::PRIVILEGED_ACCOUNT).unwrap();
        assert!(account.privileged);
    }

    /// A shared administrator name is a correlation trap: two unrelated attacks at
    /// two hospitals would link on an identity, and the analyst would be handed one
    /// incident spanning campuses that have nothing to do with each other.
    #[test]
    fn every_campus_has_its_own_privileged_account() {
        let inv = Inventory::generate(InventorySpec::default());

        for hospital in &inv.hospitals {
            let local: Vec<&Identity> = inv
                .identities
                .iter()
                .filter(|i| i.hospital == hospital.name && i.privileged)
                .collect();

            assert!(
                !local.is_empty(),
                "{} has no privileged account, so attacks there borrow another site's",
                hospital.name
            );

            for account in local {
                let elsewhere = inv.identities.iter().any(|other| {
                    other.entity.name == account.entity.name && other.hospital != account.hospital
                });
                assert!(
                    !elsewhere,
                    "{} is privileged at more than one campus",
                    account.entity.name
                );
            }
        }
    }

    #[test]
    fn endpoint_count_matches_spec() {
        let inv = Inventory::generate(InventorySpec::default());
        assert_eq!(inv.endpoint_count(), 10_482);
    }
}
