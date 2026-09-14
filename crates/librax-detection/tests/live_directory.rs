

use std::sync::Arc;

use chrono::{Duration, Utc};
use librax_detection::DetectionEngine;
use librax_mitre::MitreCatalog;
use librax_normalizer::Normalizer;
use librax_types::{RawEvent, SecuritySignal, SourceType};
use serde_json::json;

fn raw(id: &str, secs: i64, payload: serde_json::Value) -> RawEvent {
    RawEvent {
        raw_id: id.to_string(),
        source_type: SourceType::ActiveDirectory,
        source_id: "dc-samba-01".to_string(),
        received_at: Utc::now() + Duration::seconds(secs),
        payload,
    }
}

fn auth(id: &str, secs: i64, account: &str, ip: &str, protocol: &str, success: bool) -> RawEvent {
    raw(
        id,
        secs,
        json!({
            "event_kind": "auth",
            "success": success,
            "status": if success { "NT_STATUS_OK" } else { "NT_STATUS_WRONG_PASSWORD" },
            "protocol": protocol,
            "TargetUserName": account,
            "IpAddress": ip,
            "WorkstationName": "attacker",
        }),
    )
}

fn detect(raws: &[RawEvent]) -> Vec<SecuritySignal> {
    let mut normalizer = Normalizer::new();
    let outcome = normalizer.normalize_batch(raws);
    assert!(
        outcome.rejections.is_empty(),
        "the shipper's shape must normalize cleanly: {:?}",
        outcome.rejections
    );
    DetectionEngine::new(Arc::new(MitreCatalog::embedded())).run(&outcome.events)
}

fn fired(signals: &[SecuritySignal], detector: &str) -> bool {
    signals.iter().any(|s| s.detector_id == detector)
}

#[test]
fn a_password_spray_from_one_source_becomes_one_finding() {
    let accounts = ["alice", "bob", "carol", "dave", "erin", "frank", "grace"];
    let mut events = Vec::new();
    for (i, account) in accounts.iter().cycle().take(30).enumerate() {
        events.push(auth(
            &format!("F-{i:03}"),
            i as i64,
            account,
            "10.10.0.66",
            "NTLMSSP",
            false,
        ));
    }

    let signals = detect(&events);
    let spray: Vec<_> = signals
        .iter()
        .filter(|s| s.detector_id == "ad_password_spray")
        .collect();

    assert_eq!(spray.len(), 1, "30 failures must collapse to one finding");
    assert!(
        spray[0].explanation.contains("distinct accounts"),
        "the finding should explain why it is a spray: {}",
        spray[0].explanation
    );
    assert!(
        spray[0].evidence_event_ids.len() >= 10,
        "the finding must cite the failures behind it"
    );
    assert!(
        spray[0].mitre.iter().any(|m| m.technique_id == "T1110.003"),
        "a spray maps to password spraying"
    );
}

#[test]
fn a_spray_that_gets_in_is_high_severity() {
    let mut events = Vec::new();
    for i in 0..12 {
        events.push(auth(
            &format!("F-{i:03}"),
            i,
            &format!("user{}", i % 6),
            "10.10.0.66",
            "NTLMSSP",
            false,
        ));
    }

    events.push(auth("S-1", 20, "user3", "10.10.0.66", "NTLMSSP", true));

    let signals = detect(&events);
    let spray = signals
        .iter()
        .find(|s| s.detector_id == "ad_password_spray")
        .expect("spray should fire");

    assert_eq!(spray.severity, librax_types::Severity::High);
    assert!(spray.explanation.contains("successful logon"));
}

#[test]
fn kerberos_enumeration_of_many_principals_is_flagged() {
    let mut events = Vec::new();
    for i in 0..12 {
        events.push(auth(
            &format!("K-{i:03}"),
            i,
            &format!("employee{i}"),
            "10.10.0.66",
            "Kerberos KDC",
            false,
        ));
    }

    events.push(auth("K-SVC", 13, "svc_sql", "10.10.0.66", "Kerberos KDC", true));

    let signals = detect(&events);
    let krb = signals
        .iter()
        .find(|s| s.detector_id == "ad_kerberos_abuse")
        .expect("kerberos abuse should fire");

    assert!(krb.mitre.iter().any(|m| m.technique_id == "T1087.002"));
    assert!(
        krb.mitre.iter().any(|m| m.technique_id == "T1558.003"),
        "a service account target should add Kerberoasting"
    );
}

#[test]
fn smb_share_sweep_is_flagged() {
    let shares = ["IPC$", "SYSVOL", "NETLOGON", "C$", "ADMIN$"];
    let events: Vec<RawEvent> = shares
        .iter()
        .enumerate()
        .map(|(i, share)| {
            raw(
                &format!("SMB-{i}"),
                i as i64,
                json!({
                    "event_kind": "smb",
                    "operation": "connect",
                    "success": true,
                    "status": "NT_STATUS_OK",
                    "protocol": "SMB2",
                    "TargetUserName": "attacker",
                    "IpAddress": "10.10.0.66",
                    "share": share,
                }),
            )
        })
        .collect();

    let signals = detect(&events);
    let smb = signals
        .iter()
        .find(|s| s.detector_id == "ad_smb_enum")
        .expect("smb enumeration should fire");
    assert!(smb.mitre.iter().any(|m| m.technique_id == "T1135"));
}

#[test]
fn a_replication_pull_is_a_dcsync_finding() {
    let events = vec![raw(
        "DRS-1",
        0,
        json!({
            "event_kind": "smb",
            "operation": "drsuapi",
            "success": true,
            "status": "NT_STATUS_OK",
            "protocol": "SMB2",
            "TargetUserName": "compromised.admin",
            "IpAddress": "10.10.0.66",
        }),
    )];

    let signals = detect(&events);
    let dcsync = signals
        .iter()
        .find(|s| s.detector_id == "ad_dcsync")
        .expect("dcsync should fire");
    assert_eq!(dcsync.severity, librax_types::Severity::Critical);
    assert!(dcsync.mitre.iter().any(|m| m.technique_id == "T1003.006"));
}


#[test]
fn the_live_detectors_stay_quiet_on_simulator_events() {
    let events = vec![raw(
        "SIM-1",
        0,
        json!({
            "EventID": 4625,
            "TargetUserName": "svc.dbadmin",
            "WorkstationName": "HR-PC-23",
            "IpAddress": "10.10.2.15",
            "failure_count": 3184,
            "window_seconds": 300,
            "distinct_accounts_targeted": 742,
            "followed_by_success": true,
        }),
    )];

    let signals = detect(&events);
    assert!(!fired(&signals, "ad_password_spray"));
    assert!(!fired(&signals, "ad_kerberos_abuse"));
}
