

use chrono::{DateTime, Duration, Utc};
use librax_enrichment::{Asset, AssetRole, Inventory, demo, hashes};
use librax_types::{RawEvent, Severity, SourceType};
use serde::Serialize;
use serde_json::json;

use super::scenario;


#[derive(Debug, Clone, Serialize)]
pub struct AttackKind {
    pub id: String,
    pub name: String,
    pub category: String,
    pub description: String,

    pub expected_detections: Vec<String>,
    pub expected_tactics: Vec<String>,
    pub event_count: usize,

    pub duration_seconds: i64,
    pub severity_hint: Severity,
}

pub fn catalog() -> Vec<AttackKind> {
    vec![
        AttackKind {
            id: "multi_stage_ransomware".into(),
            name: "Multi-stage healthcare intrusion".into(),
            category: "Ransomware".into(),
            description: "HR spear-phishing lure, VPN anomaly, encoded PowerShell, C2 beacon, \
                          internal discovery, credential spraying, lateral movement, privileged \
                          checkout, bulk patient-record read, staging, then ransomware \
                          preparation. The full chain."
                .into(),
            expected_detections: vec![
                "phishing_lure_delivered".into(),
                "vpn_identity_anomaly".into(),
                "powershell_encoded_command".into(),
                "c2_connection".into(),
                "network_discovery".into(),
                "credential_abuse".into(),
                "lateral_movement".into(),
                "privileged_access_anomaly".into(),
                "database_mass_access".into(),
                "data_staging".into(),
                "ransomware_indicator".into(),
            ],
            expected_tactics: vec![
                "Initial Access".into(),
                "Execution".into(),
                "Command and Control".into(),
                "Discovery".into(),
                "Credential Access".into(),
                "Lateral Movement".into(),
                "Collection".into(),
                "Impact".into(),
            ],
            event_count: 11,
            duration_seconds: 31 * 60,
            severity_hint: Severity::Critical,
        },
        AttackKind {
            id: "insider_exfiltration".into(),
            name: "Privileged insider data theft".into(),
            category: "Insider threat".into(),
            description: "No phishing and no malware. A trusted administrator checks out a \
                          privileged credential outside any change window, reads patient records \
                          far beyond their normal volume, and compresses the extract. Hard to \
                          catch precisely because every step is authorised."
                .into(),
            expected_detections: vec![
                "privileged_access_anomaly".into(),
                "database_mass_access".into(),
                "data_staging".into(),
                "lateral_movement".into(),
            ],
            expected_tactics: vec!["Lateral Movement".into(), "Collection".into()],
            event_count: 4,
            duration_seconds: 22 * 60,
            severity_hint: Severity::High,
        },
        AttackKind {
            id: "bec_account_takeover".into(),
            name: "Business email compromise".into(),
            category: "Account takeover".into(),
            description: "Credential phishing followed by a session from an implausible \
                          location, credential spraying against neighbouring accounts, and a \
                          first-ever remote logon. Stops short of encryption: the objective is \
                          the mailbox, not the estate."
                .into(),
            expected_detections: vec![
                "phishing_lure_delivered".into(),
                "vpn_identity_anomaly".into(),
                "credential_abuse".into(),
                "lateral_movement".into(),
            ],
            expected_tactics: vec![
                "Initial Access".into(),
                "Credential Access".into(),
                "Lateral Movement".into(),
            ],
            event_count: 4,
            duration_seconds: 18 * 60,
            severity_hint: Severity::High,
        },
        AttackKind {
            id: "credential_stuffing".into(),
            name: "Credential stuffing against the VPN".into(),
            category: "Brute force".into(),
            description: "A botnet replays breached credentials at the VPN portal, then pushes \
                          MFA prompts at the one account that matched. Thousands of failures \
                          that should surface as one finding, not thousands of alerts."
                .into(),
            expected_detections: vec!["credential_abuse".into(), "vpn_identity_anomaly".into()],
            expected_tactics: vec!["Credential Access".into()],
            event_count: 2,
            duration_seconds: 6 * 60,
            severity_hint: Severity::Medium,
        },
        AttackKind {
            id: "pacs_imaging_exfiltration".into(),
            name: "Medical imaging exfiltration".into(),
            category: "Medical device".into(),
            description: "An imaging system is used to sweep the network, beacon out, and pull \
                          studies in bulk before staging them. Targets the systems a hospital \
                          cannot simply switch off."
                .into(),
            expected_detections: vec![
                "network_discovery".into(),
                "c2_connection".into(),
                "database_mass_access".into(),
                "data_staging".into(),
            ],
            expected_tactics: vec![
                "Discovery".into(),
                "Command and Control".into(),
                "Collection".into(),
            ],
            event_count: 4,
            duration_seconds: 15 * 60,
            severity_hint: Severity::High,
        },
        AttackKind {
            id: "volumetric_ddos".into(),
            name: "Volumetric flood on a campus gateway".into(),
            category: "Availability".into(),
            description: "1.8 million connections a minute against one gateway from thousands \
                          of sources. Reported as a single finding rather than a per-packet \
                          flood, and deliberately unrelated to any intrusion."
                .into(),
            expected_detections: vec!["network_volume_anomaly".into()],
            expected_tactics: vec!["Impact".into()],
            event_count: 1,
            duration_seconds: 60,
            severity_hint: Severity::Medium,
        },
    ]
}

pub fn kind(id: &str) -> Option<AttackKind> {
    catalog().into_iter().find(|k| k.id == id)
}


struct Actors {
    user: String,
    endpoint: String,
    endpoint_ip: String,
    privileged: String,
    app_server: String,
    db_server: String,
    database: String,
    imaging: String,
    imaging_ip: String,
    gateway: String,
    gateway_ip: String,
    campus: String,
}

fn role_at<'a>(inventory: &'a Inventory, campus: &str, role: AssetRole) -> Option<&'a Asset> {
    inventory
        .assets
        .iter()
        .find(|a| a.hospital == campus && a.role == role)
}


fn actors(inventory: &Inventory, campus_index: usize) -> Actors {

    let campus = inventory
        .hospitals
        .get(campus_index % inventory.hospitals.len().max(1))
        .map(|h| h.name.clone())
        .unwrap_or_else(|| demo::HOSPITAL.to_string());

    let name_or = |role: AssetRole, fallback: &str| {
        role_at(inventory, &campus, role)
            .map(|a| a.entity.name.clone())
            .unwrap_or_else(|| fallback.to_string())
    };
    let ip_or = |role: AssetRole, fallback: &str| {
        role_at(inventory, &campus, role)
            .map(|a| a.ip.clone())
            .unwrap_or_else(|| fallback.to_string())
    };

    let workstation = role_at(inventory, &campus, AssetRole::Workstation);

    let user = inventory
        .identities
        .iter()
        .find(|i| i.hospital == campus && !i.privileged && !i.service_account)
        .map(|i| i.entity.name.clone())
        .unwrap_or_else(|| demo::USER.to_string());

    let privileged = inventory
        .identities
        .iter()
        .find(|i| i.hospital == campus && i.privileged)
        .map(|i| i.entity.name.clone())
        .unwrap_or_else(|| demo::PRIVILEGED_ACCOUNT.to_string());

    Actors {
        user,
        endpoint: workstation
            .map(|a| a.entity.name.clone())
            .unwrap_or_else(|| demo::ENDPOINT.to_string()),
        endpoint_ip: workstation
            .map(|a| a.ip.clone())
            .unwrap_or_else(|| demo::ENDPOINT_IP.to_string()),
        privileged,
        app_server: name_or(AssetRole::Server, demo::APP_SERVER),
        db_server: name_or(AssetRole::Database, demo::DB_SERVER),
        database: name_or(AssetRole::Database, demo::PATIENT_DB),
        imaging: name_or(AssetRole::Pacs, demo::PACS),
        imaging_ip: ip_or(AssetRole::Pacs, "10.24.5.12"),
        gateway: name_or(AssetRole::Firewall, "C04-FW-EDGE-01"),
        gateway_ip: ip_or(AssetRole::Firewall, "10.23.4.7"),
        campus,
    }
}

fn raw(
    id: String,
    source_type: SourceType,
    source_id: &str,
    at: DateTime<Utc>,
    payload: serde_json::Value,
) -> RawEvent {
    RawEvent {
        raw_id: id,
        source_type,
        source_id: source_id.to_string(),
        received_at: at,
        payload,
    }
}


pub fn generate(
    id: &str,
    tag: &str,
    start: DateTime<Utc>,
    inventory: &Inventory,
    campus_index: usize,
) -> Vec<RawEvent> {
    let a = actors(inventory, campus_index);
    let ev = |n: usize| format!("{tag}-{n:02}");
    let at = |minutes: i64| start + Duration::minutes(minutes);

    match id {

        "multi_stage_ransomware" => {
            let mut events = scenario::attack_chain(start);
            if tag != "EVT" {
                for (i, event) in events.iter_mut().enumerate() {
                    event.raw_id = ev(i + 1);
                }
            }
            events
        }

        "insider_exfiltration" => vec![
            raw(
                ev(1),
                SourceType::Server,
                "srv-app-07",
                at(0),
                json!({
                    "host": a.app_server,
                    "event": "remote_logon",
                    "user": a.privileged,
                    "src_ip": a.endpoint_ip,
                    "service": "RDP",
                    "logon_type": 10,
                    "first_time_for_user": true,
                    "source_is_workstation": true
                }),
            ),
            raw(
                ev(2),
                SourceType::Pam,
                "pam-core-01",
                at(6),
                json!({
                    "event": "session_checkout",
                    "requester": a.privileged,
                    "account": a.privileged,
                    "target_host": a.db_server,
                    "session_id": format!("PAM-{}", 300 + campus_index),
                    "approval": "auto",
                    "outside_change_window": true,
                    "requester_first_use_of_account": false
                }),
            ),
            raw(
                ev(3),
                SourceType::Database,
                "db-patient-01",
                at(14),
                json!({
                    "instance": a.database,
                    "host": a.db_server,
                    "principal": a.privileged,
                    "statement": "SELECT * FROM patient_records ORDER BY admitted_on DESC",
                    "rows_returned": 92_450,
                    "baseline_rows_returned": 380,
                    "duration_ms": 28_900,
                    "contains_phi": true
                }),
            ),
            raw(
                ev(4),
                SourceType::Edr,
                "edr-campus-04",
                at(22),
                json!({
                    "event_type": "file_create",
                    "device_name": a.db_server,
                    "user_name": a.privileged,
                    "file_name": "records_backup_q3.7z",
                    "file_path": "C:\\Users\\Public\\records_backup_q3.7z",
                    "file_size_bytes": 894_784_512i64,
                    "process_name": "7z.exe",
                    "process_sha256": hashes::SEVENZIP_SHA256,
                    "process_md5": hashes::SEVENZIP_MD5,
                    "is_archive": true,
                    "in_temp_directory": true,
                    "source_records": 92_450
                }),
            ),
        ],

        "bec_account_takeover" => vec![
            raw(
                ev(1),
                SourceType::Email,
                "email-gw-01",
                at(0),
                json!({
                    "event": "mail_delivered",
                    "recipient": a.user,
                    "sender": format!("payroll-notice@{}", demo::PHISHING_DOMAIN),
                    "sender_domain": demo::PHISHING_DOMAIN,
                    "subject": "Payroll correction requires your approval",
                    "attachment_name": "Payroll_Correction.docm",
                    "attachment_macro": true,
                    "attachment_sha256": hashes::LURE_SHA256,
                    "attachment_md5": hashes::LURE_MD5,
                    "embedded_url": format!("https://{}/payroll", demo::PHISHING_DOMAIN),
                    "spf": "fail",
                    "dkim": "fail",
                    "dmarc": "fail",
                    "lookalike_of": "payroll-notices.org",
                    "recipient_clicked": true
                }),
            ),
            raw(
                ev(2),
                SourceType::Vpn,
                "vpn-campus-04",
                at(5),
                json!({
                    "event": "session_start",
                    "user": a.user,
                    "client_ip": "203.0.113.77",
                    "client_country": "RO",
                    "previous_country": "IN",
                    "minutes_since_previous_session": 22,
                    "assigned_ip": a.endpoint_ip,
                    "mfa_method": "push",
                    "mfa_prompts": 9,
                    "mfa_accepted_after": 9
                }),
            ),
            raw(
                ev(3),
                SourceType::ActiveDirectory,
                "ad-campus-04",
                at(11),
                json!({
                    "EventID": 4625,
                    "TargetUserName": a.privileged,
                    "WorkstationName": a.endpoint,
                    "IpAddress": a.endpoint_ip,
                    "LogonType": 3,
                    "failure_count": 21,
                    "window_seconds": 180,
                    "distinct_accounts_targeted": 11,
                    "followed_by_success": true,
                    "success_event_id": 4624
                }),
            ),
            raw(
                ev(4),
                SourceType::Server,
                "srv-app-07",
                at(18),
                json!({
                    "host": a.app_server,
                    "event": "remote_logon",
                    "user": a.user,
                    "src_ip": a.endpoint_ip,
                    "service": "WinRM",
                    "logon_type": 3,
                    "first_time_for_user": true,
                    "source_is_workstation": true
                }),
            ),
        ],

        "credential_stuffing" => vec![
            raw(
                ev(1),
                SourceType::ActiveDirectory,
                "ad-campus-04",
                at(0),
                json!({
                    "EventID": 4625,
                    "TargetUserName": a.user,
                    "WorkstationName": "VPN-PORTAL",
                    "IpAddress": "45.133.1.90",
                    "LogonType": 3,
                    "failure_count": 3_184,
                    "window_seconds": 300,
                    "distinct_accounts_targeted": 742,
                    "followed_by_success": true,
                    "success_event_id": 4624
                }),
            ),
            raw(
                ev(2),
                SourceType::Vpn,
                "vpn-campus-04",
                at(5),
                json!({
                    "event": "session_start",
                    "user": a.user,
                    "client_ip": "45.133.1.90",
                    "client_country": "NL",
                    "previous_country": "IN",
                    "minutes_since_previous_session": 12,
                    "assigned_ip": a.endpoint_ip,
                    "mfa_method": "push",
                    "mfa_prompts": 14,
                    "mfa_accepted_after": 14
                }),
            ),
        ],

        "pacs_imaging_exfiltration" => vec![
            raw(
                ev(1),
                SourceType::Firewall,
                "fw-edge-04",
                at(0),
                json!({
                    "event": "flow_summary",


                    "src": a.imaging_ip,
                    "window_seconds": 120,
                    "distinct_destinations": 268,
                    "distinct_ports": 22,
                    "connections_denied": 241,
                    "connections_allowed": 27,
                    "baseline_distinct_destinations": 7
                }),
            ),
            raw(
                ev(2),
                SourceType::Firewall,
                "fw-edge-04",
                at(4),
                json!({
                    "action": "allow",
                    "src": a.imaging_ip,
                    "dst": demo::ATTACKER_IP,
                    "dst_domain": demo::C2_DOMAIN,
                    "dport": 443,
                    "proto": "tcp",
                    "bytes_out": 21_504,
                    "bytes_in": 3_180,
                    "rule": "OUTBOUND-WEB",
                    "connection_count": 41,
                    "interval_seconds_mean": 58.9,
                    "interval_seconds_stddev": 2.1,
                    "domain_age_days": 4
                }),
            ),
            raw(
                ev(3),
                SourceType::Pacs,
                "pacs-campus-04",
                at(9),
                json!({
                    "instance": a.imaging,
                    "host": a.imaging,
                    "principal": a.privileged,
                    "statement": "C-FIND STUDY * ; C-MOVE ALL",
                    "rows_returned": 41_820,
                    "baseline_rows_returned": 260,
                    "duration_ms": 96_400,
                    "contains_phi": true,
                    "modality": "CT"
                }),
            ),
            raw(
                ev(4),
                SourceType::Edr,
                "edr-campus-04",
                at(15),
                json!({
                    "event_type": "file_create",
                    "device_name": a.imaging,
                    "user_name": a.privileged,
                    "file_name": "studies_export.zip",
                    "file_path": "C:\\Windows\\Temp\\studies_export.zip",
                    "file_size_bytes": 6_442_450_944i64,
                    "process_name": "7z.exe",
                    "process_sha256": hashes::SEVENZIP_SHA256,
                    "is_archive": true,
                    "in_temp_directory": true,
                    "source_records": 41_820
                }),
            ),
        ],

        "volumetric_ddos" => vec![raw(
            ev(1),
            SourceType::Firewall,
            "fw-edge-11",
            at(0),
            json!({
                "event": "flow_summary",
                "dst": a.gateway_ip,
                "dst_hostname": a.gateway,
                "window_seconds": 60,
                "connections_per_minute": 1_800_000i64,
                "baseline_connections_per_minute": 12_000i64,
                "unique_sources": 4_231,
                "destination_concentration": 0.97,
                "connections_denied": 1_612_400i64
            }),
        )],

        _ => Vec::new(),
    }
}


pub fn campus_of(inventory: &Inventory, campus_index: usize) -> String {
    actors(inventory, campus_index).campus
}


pub fn rotate_campus(inventory: &Inventory, run_index: usize) -> usize {


    let available: Vec<usize> = (0..inventory.hospitals.len())
        .filter(|&i| inventory.hospitals[i].name != demo::HOSPITAL)
        .collect();

    if available.is_empty() {
        return 0;
    }

    available[run_index % available.len()]
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use librax_enrichment::InventorySpec;

    use super::*;

    fn inventory() -> Arc<Inventory> {
        Arc::new(Inventory::generate(InventorySpec {
            seed: 42,
            hospitals: 18,
            endpoints: 2_000,
        }))
    }

    #[test]
    fn every_catalogue_entry_generates_the_event_count_it_advertises() {
        let inv = inventory();

        for kind in catalog() {
            let events = generate(&kind.id, "ATK", Utc::now(), &inv, 3);
            assert_eq!(
                events.len(),
                kind.event_count,
                "{} advertises {} events but produced {}",
                kind.id,
                kind.event_count,
                events.len()
            );
        }
    }

    #[test]
    fn an_unknown_playbook_produces_nothing_rather_than_panicking() {
        assert!(generate("not_a_playbook", "ATK", Utc::now(), &inventory(), 0).is_empty());
    }

    #[test]
    fn the_documented_chain_keeps_its_documented_event_ids() {
        let events = generate("multi_stage_ransomware", "EVT", Utc::now(), &inventory(), 0);

        assert_eq!(events.len(), 11);
        assert_eq!(events[0].raw_id, "EVT-01");
        assert_eq!(events[10].raw_id, "EVT-11");
    }

    #[test]
    fn a_relaunch_produces_distinct_event_ids() {
        let inv = inventory();
        let first = generate("multi_stage_ransomware", "ATK-A", Utc::now(), &inv, 0);
        let second = generate("multi_stage_ransomware", "ATK-B", Utc::now(), &inv, 0);


        for (a, b) in first.iter().zip(&second) {
            assert_ne!(a.raw_id, b.raw_id);
        }
    }

    #[test]
    fn events_are_ordered_and_span_the_advertised_duration() {
        let inv = inventory();
        let start = Utc::now();

        for kind in catalog() {
            let events = generate(&kind.id, "ATK", start, &inv, 1);

            for pair in events.windows(2) {
                assert!(
                    pair[0].received_at <= pair[1].received_at,
                    "{} is out of order",
                    kind.id
                );
            }

            let span = events
                .last()
                .map(|e| (e.received_at - start).num_seconds())
                .unwrap_or(0);
            assert!(
                span <= kind.duration_seconds,
                "{} spans {span}s but advertises {}s",
                kind.id,
                kind.duration_seconds
            );
        }
    }

    #[test]
    fn consecutive_launches_land_on_different_campuses() {
        let inv = inventory();


        let sites: Vec<String> = (0..6)
            .map(|run| campus_of(&inv, rotate_campus(&inv, run)))
            .collect();

        for pair in sites.windows(2) {
            assert_ne!(pair[0], pair[1], "two launches in a row hit {}", pair[0]);
        }
        assert!(
            !sites.contains(&demo::HOSPITAL.to_string()),
            "the documented chain's campus should be left to it"
        );
    }

    #[test]
    fn different_campuses_give_different_casts() {
        let inv = inventory();

        let a = actors(&inv, 2);
        let b = actors(&inv, 9);

        assert_ne!(a.campus, b.campus);
        assert_ne!(
            a.endpoint, b.endpoint,
            "each campus should field its own machines"
        );
    }

    #[test]
    fn the_insider_playbook_involves_no_external_infrastructure() {
        let inv = inventory();
        let events = generate("insider_exfiltration", "ATK", Utc::now(), &inv, 4);


        let payloads = format!("{:?}", events);
        assert!(!payloads.contains(demo::ATTACKER_IP));
        assert!(!payloads.contains(demo::C2_DOMAIN));
        assert!(!payloads.contains(demo::PHISHING_DOMAIN));
    }
}
