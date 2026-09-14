use std::collections::HashMap;

use librax_types::{
    CanonicalEvent, Enrichment, EntityKind, EntityRef, EventCategory, NetworkEndpoint,
    ProcessContext, RawEvent, Severity, SourceType,
};
use serde_json::Value;


fn base(
    raw: &RawEvent,
    category: EventCategory,
    activity: &str,
    severity: Severity,
) -> CanonicalEvent {
    let attributes: HashMap<String, Value> = raw
        .payload
        .as_object()
        .map(|obj| obj.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
        .unwrap_or_default();

    CanonicalEvent {
        event_id: raw.raw_id.clone(),
        timestamp: raw.received_at,
        source_type: raw.source_type,
        source_id: raw.source_id.clone(),
        category,
        activity: activity.to_string(),
        principal: None,
        source: None,
        destination: None,
        host: None,
        process: None,
        target: None,
        severity,
        raw_reference: Some(raw.raw_id.clone()),
        message: String::new(),
        attributes,
        enrichment: Enrichment::default(),
    }
}

fn str_field(raw: &RawEvent, key: &str) -> Option<String> {
    raw.payload.get(key)?.as_str().map(|s| s.to_string())
}

fn i64_field(raw: &RawEvent, key: &str) -> Option<i64> {
    raw.payload.get(key)?.as_i64()
}

fn bool_field(raw: &RawEvent, key: &str) -> bool {
    opt_bool_field(raw, key).unwrap_or(false)
}


fn opt_bool_field(raw: &RawEvent, key: &str) -> Option<bool> {
    raw.payload.get(key)?.as_bool()
}

fn endpoint(
    ip: Option<String>,
    port: Option<u16>,
    domain: Option<String>,
) -> Option<NetworkEndpoint> {
    if ip.is_none() && domain.is_none() {
        return None;
    }
    Some(NetworkEndpoint {
        ip,
        port,
        hostname: None,
        domain,
        bytes: None,
    })
}


pub fn parse(raw: &RawEvent) -> CanonicalEvent {
    match raw.source_type {
        SourceType::ActiveDirectory | SourceType::EntraId => directory(raw),
        SourceType::Edr => endpoint_agent(raw),
        SourceType::Firewall => firewall(raw),
        SourceType::Vpn => vpn(raw),
        SourceType::Pam => pam(raw),
        SourceType::Dns => dns(raw),
        SourceType::Server => server(raw),
        SourceType::Database => database(raw),
        SourceType::Pacs => pacs(raw),
        SourceType::Email => email(raw),
        SourceType::Cloud => cloud(raw),
        SourceType::Proxy => proxy(raw),
        SourceType::Unknown => unsupported(raw),
    }
}

fn directory(raw: &RawEvent) -> CanonicalEvent {


    if raw.payload.get("status").is_some() || raw.payload.get("event_kind").is_some() {
        return directory_live(raw);
    }

    let event_id = i64_field(raw, "EventID").unwrap_or_default();
    let failures = i64_field(raw, "failure_count").unwrap_or_default();

    let (activity, severity) = match event_id {
        4624 => ("logon_success", Severity::Info),
        4625 if failures >= 5 => ("logon_failure_burst", Severity::Medium),
        4625 => ("logon_failure", Severity::Low),
        4672 => ("special_privileges_assigned", Severity::Low),
        _ => ("directory_event", Severity::Info),
    };

    let mut event = base(raw, EventCategory::Authentication, activity, severity);
    event.principal = str_field(raw, "TargetUserName").map(EntityRef::user);
    event.host = str_field(raw, "WorkstationName").map(EntityRef::host);
    event.source = endpoint(str_field(raw, "IpAddress"), None, None);
    event.message = format!(
        "Windows event {event_id} for {} on {}",
        event.user().unwrap_or("unknown user"),
        event.host_name().unwrap_or("unknown host")
    );
    event
}


fn directory_live(raw: &RawEvent) -> CanonicalEvent {
    let kind = str_field(raw, "event_kind").unwrap_or_else(|| "auth".into());
    let status = str_field(raw, "status").unwrap_or_default();
    let success = opt_bool_field(raw, "success").unwrap_or(status == "NT_STATUS_OK");
    let protocol = str_field(raw, "protocol").unwrap_or_default();

    let (category, activity, severity) = match kind.as_str() {
        "smb" => {
            let op = str_field(raw, "operation").unwrap_or_default();


            if op.eq_ignore_ascii_case("drsuapi")
                || op.contains("GetNCChanges")
                || op.contains("DsGetNCChanges")
            {
                (EventCategory::Network, "directory_replication", Severity::High)
            } else if op.is_empty() || op == "connect" || op == "tree_connect" {
                (EventCategory::Network, "smb_tree_connect", Severity::Info)
            } else {
                (EventCategory::Network, "smb_operation", Severity::Info)
            }
        }
        _ => {
            if success {
                (EventCategory::Authentication, "logon_success", Severity::Info)
            } else {
                (EventCategory::Authentication, "logon_failure", Severity::Low)
            }
        }
    };

    let mut event = base(raw, category, activity, severity);
    event.principal = str_field(raw, "TargetUserName")
        .filter(|u| !u.is_empty() && u != "-")
        .map(EntityRef::user);
    event.host = str_field(raw, "WorkstationName")
        .filter(|w| !w.is_empty() && w != "-")
        .map(|w| EntityRef::host(w.trim_start_matches('\\')));
    event.source = endpoint(str_field(raw, "IpAddress"), None, None);
    if let Some(share) = str_field(raw, "share").filter(|s| !s.is_empty()) {
        event.target = Some(EntityRef::new(EntityKind::File, share));
    }

    event.message = match activity {
        "logon_success" => format!(
            "{} authenticated from {} via {}",
            event.user().unwrap_or("unknown account"),
            event.src_ip().unwrap_or("unknown address"),
            if protocol.is_empty() { "directory" } else { &protocol }
        ),
        "logon_failure" => format!(
            "Failed {} logon for {} from {} ({})",
            if protocol.is_empty() { "directory" } else { &protocol },
            event.user().unwrap_or("unknown account"),
            event.src_ip().unwrap_or("unknown address"),
            if status.is_empty() { "denied" } else { &status }
        ),
        "smb_tree_connect" => format!(
            "{} connected to {} on the domain controller",
            event.user().unwrap_or("unknown account"),
            event.target_name().unwrap_or("a share")
        ),
        "directory_replication" => format!(
            "Directory replication requested by {} from {}",
            event.user().unwrap_or("an unknown principal"),
            event.src_ip().unwrap_or("an unknown address")
        ),
        _ => format!(
            "{} on the domain controller by {}",
            activity,
            event.user().unwrap_or("unknown account")
        ),
    };
    event
}

fn endpoint_agent(raw: &RawEvent) -> CanonicalEvent {
    let kind = str_field(raw, "event_type").unwrap_or_default();

    let (category, activity) = match kind.as_str() {
        "process_create" => (EventCategory::Process, "process_create"),
        "file_create" => (EventCategory::File, "file_create"),
        "network_connect" => (EventCategory::Network, "network_connect"),
        _ => (EventCategory::Unknown, "endpoint_event"),
    };

    let mut event = base(raw, category, activity, Severity::Info);
    event.principal = str_field(raw, "user_name").map(EntityRef::user);
    event.host = str_field(raw, "device_name").map(EntityRef::host);

    if let Some(name) = str_field(raw, "process_name") {
        event.process = Some(ProcessContext {
            name,
            pid: i64_field(raw, "pid").and_then(|p| u32::try_from(p).ok()),
            command_line: str_field(raw, "process_cmdline"),
            parent_name: str_field(raw, "parent_process"),

            hash_sha256: str_field(raw, "process_sha256").or_else(|| str_field(raw, "sha256")),
            hash_md5: str_field(raw, "process_md5").or_else(|| str_field(raw, "md5")),
            signed: opt_bool_field(raw, "signed"),
            signer: str_field(raw, "signer"),
        });
    }

    if let Some(file) = str_field(raw, "file_name") {
        event.target = Some(EntityRef::new(EntityKind::File, file));
    }

    event.message = match (&event.process, &event.target) {
        (Some(p), _) => format!(
            "{} ran {} on {}",
            event.user().unwrap_or("unknown user"),
            p.name,
            event.host_name().unwrap_or("unknown host")
        ),
        (None, Some(t)) => format!(
            "{} created {} on {}",
            event.user().unwrap_or("unknown user"),
            t.name,
            event.host_name().unwrap_or("unknown host")
        ),
        _ => "Endpoint activity".to_string(),
    };
    event
}

fn firewall(raw: &RawEvent) -> CanonicalEvent {
    let is_summary = str_field(raw, "event").as_deref() == Some("flow_summary");
    let action = str_field(raw, "action").unwrap_or_else(|| "observed".to_string());

    let activity = if is_summary {
        "flow_summary"
    } else if action == "deny" {
        "connection_denied"
    } else {
        "connection_allowed"
    };

    let mut event = base(raw, EventCategory::Network, activity, Severity::Info);
    event.source = endpoint(str_field(raw, "src"), None, None);
    event.destination = endpoint(
        str_field(raw, "dst"),
        i64_field(raw, "dport").and_then(|p| u16::try_from(p).ok()),
        str_field(raw, "dst_domain"),
    );

    if let Some(dest) = event.destination.as_mut() {
        dest.bytes = i64_field(raw, "bytes_out").and_then(|b| u64::try_from(b).ok());
    }

    if let Some(host) = str_field(raw, "dst_hostname") {
        event.target = Some(EntityRef::host(host));
    }

    event.message = if is_summary {
        format!(
            "Flow summary from {}: {} distinct destinations",
            event.src_ip().unwrap_or("unknown"),
            i64_field(raw, "distinct_destinations").unwrap_or_default()
        )
    } else {
        format!(
            "Firewall {action} {} -> {}",
            event.src_ip().unwrap_or("unknown"),
            event.dst_ip().unwrap_or("unknown")
        )
    };
    event
}

fn vpn(raw: &RawEvent) -> CanonicalEvent {
    let mut event = base(
        raw,
        EventCategory::Authentication,
        "vpn_session_start",
        Severity::Info,
    );
    event.principal = str_field(raw, "user").map(EntityRef::user);
    event.source = endpoint(str_field(raw, "client_ip"), None, None);
    event.destination = endpoint(str_field(raw, "assigned_ip"), None, None);
    event.message = format!(
        "VPN session for {} from {}",
        event.user().unwrap_or("unknown user"),
        str_field(raw, "client_country").unwrap_or_else(|| "unknown country".into())
    );
    event
}

fn pam(raw: &RawEvent) -> CanonicalEvent {
    let mut event = base(
        raw,
        EventCategory::PrivilegeEscalation,
        "pam_session_checkout",
        Severity::Medium,
    );
    event.principal = str_field(raw, "requester").map(EntityRef::user);
    event.target = str_field(raw, "account").map(|a| EntityRef::new(EntityKind::Account, a));
    event.host = str_field(raw, "target_host").map(EntityRef::server);
    event.message = format!(
        "{} checked out {} for {}",
        event.user().unwrap_or("unknown requester"),
        event.target_name().unwrap_or("an account"),
        event.host_name().unwrap_or("an unknown host")
    );
    event
}

fn dns(raw: &RawEvent) -> CanonicalEvent {
    let mut event = base(raw, EventCategory::Dns, "dns_query", Severity::Info);
    event.source = endpoint(str_field(raw, "client"), None, None);
    event.destination = endpoint(str_field(raw, "answer"), None, str_field(raw, "query"));
    event.message = format!(
        "DNS query for {}",
        str_field(raw, "query").unwrap_or_else(|| "unknown".into())
    );
    event
}

fn server(raw: &RawEvent) -> CanonicalEvent {
    let activity = str_field(raw, "event").unwrap_or_else(|| "server_event".into());
    let mut event = base(
        raw,
        EventCategory::Authentication,
        &activity,
        Severity::Info,
    );
    event.principal = str_field(raw, "user").map(EntityRef::user);
    event.host = str_field(raw, "host").map(EntityRef::server);
    event.source = endpoint(str_field(raw, "src_ip"), None, None);
    event.message = format!(
        "{} {} on {} via {}",
        event.user().unwrap_or("unknown user"),
        activity,
        event.host_name().unwrap_or("unknown host"),
        str_field(raw, "service").unwrap_or_else(|| "unknown service".into())
    );
    event
}

fn database(raw: &RawEvent) -> CanonicalEvent {
    let mut event = base(
        raw,
        EventCategory::Database,
        "database_query",
        Severity::Info,
    );
    event.principal = str_field(raw, "principal").map(|p| EntityRef::new(EntityKind::Account, p));
    event.host = str_field(raw, "host").map(EntityRef::server);
    event.target = str_field(raw, "instance").map(EntityRef::database);
    event.message = format!(
        "{} queried {} returning {} rows",
        event.user().unwrap_or("unknown principal"),
        event.target_name().unwrap_or("unknown instance"),
        i64_field(raw, "rows_returned").unwrap_or_default()
    );
    event
}

fn pacs(raw: &RawEvent) -> CanonicalEvent {


    let studies = i64_field(raw, "rows_returned").or_else(|| i64_field(raw, "studies_returned"));
    let activity = if studies.is_some() {
        "pacs_study_retrieved"
    } else {
        "pacs_study_accessed"
    };

    let mut event = base(raw, EventCategory::MedicalImaging, activity, Severity::Info);


    event.principal = str_field(raw, "user")
        .or_else(|| str_field(raw, "principal"))
        .map(|p| EntityRef::user(p));
    event.host = str_field(raw, "device")
        .or_else(|| str_field(raw, "host"))
        .map(|d| EntityRef::new(EntityKind::Device, d));
    event.target = str_field(raw, "instance").map(|i| EntityRef::new(EntityKind::Device, i));

    event.message = match studies {
        Some(count) => format!(
            "{} retrieved {} imaging studies from {}",
            event.user().unwrap_or("unknown user"),
            count,
            event.host_name().unwrap_or("unknown device")
        ),
        None => format!(
            "{} accessed imaging on {}",
            event.user().unwrap_or("unknown user"),
            event.host_name().unwrap_or("unknown device")
        ),
    };
    event
}

fn email(raw: &RawEvent) -> CanonicalEvent {
    let severity = if bool_field(raw, "attachment_macro") {
        Severity::Low
    } else {
        Severity::Info
    };
    let mut event = base(raw, EventCategory::Email, "mail_delivered", severity);
    event.principal = str_field(raw, "recipient").map(EntityRef::user);
    event.destination = endpoint(None, None, str_field(raw, "sender_domain"));
    event.message = format!(
        "Mail to {} from {}",
        event.user().unwrap_or("unknown recipient"),
        str_field(raw, "sender").unwrap_or_else(|| "unknown sender".into())
    );
    event
}

fn cloud(raw: &RawEvent) -> CanonicalEvent {
    let activity = str_field(raw, "operation").unwrap_or_else(|| "cloud_operation".into());
    let mut event = base(raw, EventCategory::Configuration, &activity, Severity::Info);
    event.principal = str_field(raw, "principal").map(EntityRef::user);
    event.target = str_field(raw, "resource").map(|r| EntityRef::new(EntityKind::CloudResource, r));
    event.message = format!("Cloud operation {activity}");
    event
}

fn proxy(raw: &RawEvent) -> CanonicalEvent {
    let mut event = base(raw, EventCategory::Network, "proxy_request", Severity::Info);
    event.source = endpoint(str_field(raw, "client"), None, None);
    event.destination = endpoint(None, None, str_field(raw, "host"));
    event.message = "Proxy request".to_string();
    event
}

fn unsupported(raw: &RawEvent) -> CanonicalEvent {
    let mut event = base(
        raw,
        EventCategory::Unknown,
        "unsupported_event",
        Severity::Info,
    );
    event
        .attributes
        .insert("librax_unsupported".to_string(), Value::Bool(true));
    event.message = format!("Unsupported source `{}`", raw.source_id);
    event
}
