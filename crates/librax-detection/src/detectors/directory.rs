

use std::collections::{BTreeMap, BTreeSet};

use librax_types::{CanonicalEvent, EntityKind, EntityRef, SecuritySignal, Severity};

use crate::engine::{DetectionContext, Detector};
use crate::support::{attr_str, entities_of, signal};


const SPRAY_MIN_FAILURES: usize = 8;

const SPRAY_MIN_ACCOUNTS: usize = 5;

const KRB_MIN_ACCOUNTS: usize = 8;

const SMB_MIN_SHARES: usize = 3;

const EVIDENCE_CAP: usize = 40;


fn by_source<'a>(
    events: impl Iterator<Item = &'a CanonicalEvent>,
) -> BTreeMap<String, Vec<&'a CanonicalEvent>> {
    let mut grouped: BTreeMap<String, Vec<&CanonicalEvent>> = BTreeMap::new();
    for event in events {
        if let Some(ip) = event.src_ip() {
            grouped.entry(ip.to_string()).or_default().push(event);
        }
    }
    grouped
}


fn primary<'a>(group: &[&'a CanonicalEvent]) -> &'a CanonicalEvent {
    group.iter().copied().min_by_key(|e| e.timestamp).unwrap()
}

fn distinct_accounts(group: &[&CanonicalEvent]) -> BTreeSet<String> {
    group
        .iter()
        .filter_map(|e| e.user())
        .map(str::to_string)
        .collect()
}

fn evidence_ids(group: &[&CanonicalEvent]) -> Vec<String> {
    let mut ordered: Vec<&CanonicalEvent> = group.to_vec();
    ordered.sort_by_key(|e| e.timestamp);
    ordered
        .into_iter()
        .take(EVIDENCE_CAP)
        .map(|e| e.event_id.clone())
        .collect()
}


fn actors(primary: &CanonicalEvent, ip: &str, accounts: &BTreeSet<String>) -> Vec<EntityRef> {
    let mut entities = entities_of(primary);
    entities.push(EntityRef::ip(ip));
    for account in accounts {
        entities.push(EntityRef::user(account));
    }
    entities.sort();
    entities.dedup();
    entities
}


fn service_like(account: &str) -> bool {
    let lower = account.to_ascii_lowercase();
    lower.ends_with('$')
        || ["svc", "sql", "mssql", "http", "web", "backup", "sched", "service"]
            .iter()
            .any(|p| lower.starts_with(p) || lower.contains(&format!("{p}_")))
}


pub struct DirectorySprayDetector;

const SPRAY_ID: &str = "ad_password_spray";

impl Detector for DirectorySprayDetector {
    fn id(&self) -> &'static str {
        SPRAY_ID
    }

    fn title(&self) -> &'static str {
        "Password spray / brute force against Active Directory"
    }

    fn evaluate(&self, ctx: &DetectionContext<'_>) -> Vec<SecuritySignal> {
        let failures = by_source(ctx.matching(|e| e.activity == "logon_failure"));


        let successes: Vec<&CanonicalEvent> =
            ctx.matching(|e| e.activity == "logon_success").collect();

        failures
            .into_iter()
            .filter(|(_, group)| group.len() >= SPRAY_MIN_FAILURES)
            .map(|(ip, group)| {
                let accounts = distinct_accounts(&group);
                let is_spray = accounts.len() >= SPRAY_MIN_ACCOUNTS;

                let mut confidence = 0.50_f32;
                let mut reasons = vec![format!(
                    "{} failed logons from {ip}",
                    group.len()
                )];

                if is_spray {
                    confidence += 0.20;
                    reasons.push(format!(
                        "{} distinct accounts targeted, consistent with spraying",
                        accounts.len()
                    ));
                } else {
                    reasons.push("concentrated on a single account, consistent with brute force"
                        .to_string());
                }

                if group.len() >= 25 {
                    confidence += 0.10;
                }


                let breach = successes.iter().copied().find(|s| {
                    s.src_ip() == Some(ip.as_str())
                        && s.user().is_some_and(|u| accounts.contains(u))
                });
                if let Some(hit) = breach {
                    confidence += 0.25;
                    reasons.push(format!(
                        "followed by a successful logon as {}",
                        hit.user().unwrap_or("a targeted account")
                    ));
                }

                let severity = if breach.is_some() {
                    Severity::High
                } else {
                    Severity::Medium
                };

                let technique = if is_spray { "T1110.003" } else { "T1110.001" };
                let mitre = ctx
                    .catalog
                    .reference(
                        technique,
                        confidence,
                        "repeated authentication failures from a single source",
                    )
                    .into_iter()
                    .collect();

                let anchor = primary(&group);
                let mut evidence = evidence_ids(&group);
                if let Some(hit) = breach {
                    evidence.push(hit.event_id.clone());
                }

                signal(
                    SPRAY_ID,
                    "Password spray / brute force against Active Directory",
                    anchor,
                    severity,
                    confidence,
                    actors(anchor, &ip, &accounts),
                    evidence,
                    mitre,
                    format!("Directory authentication: {}.", reasons.join("; ")),
                )
            })
            .collect()
    }
}


pub struct KerberosAbuseDetector;

const KRB_ID: &str = "ad_kerberos_abuse";

impl Detector for KerberosAbuseDetector {
    fn id(&self) -> &'static str {
        KRB_ID
    }

    fn title(&self) -> &'static str {
        "Kerberos account enumeration or roasting"
    }

    fn evaluate(&self, ctx: &DetectionContext<'_>) -> Vec<SecuritySignal> {


        let kerberos = by_source(ctx.matching(|e| {
            matches!(e.activity.as_str(), "logon_failure" | "logon_success")
                && attr_str(e, "protocol")
                    .is_some_and(|p| p.to_ascii_lowercase().contains("kerberos"))
        }));

        kerberos
            .into_iter()
            .filter_map(|(ip, group)| {
                let accounts = distinct_accounts(&group);
                if accounts.len() < KRB_MIN_ACCOUNTS {
                    return None;
                }

                let service_targets: Vec<&String> =
                    accounts.iter().filter(|a| service_like(a)).collect();
                let roasting = !service_targets.is_empty();

                let mut confidence = 0.55_f32;
                let mut reasons = vec![format!(
                    "{} distinct principals requested Kerberos tickets from {ip}",
                    accounts.len()
                )];


                let mut mitre = Vec::new();
                if let Some(reference) = ctx.catalog.reference(
                    "T1087.002",
                    confidence,
                    "many domain principals enumerated via Kerberos from one source",
                ) {
                    mitre.push(reference);
                }
                if roasting {
                    confidence += 0.15;
                    reasons.push(format!(
                        "including service accounts ({}), consistent with Kerberoasting",
                        service_targets
                            .iter()
                            .take(4)
                            .map(|s| s.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ));
                    if let Some(reference) = ctx.catalog.reference(
                        "T1558.003",
                        confidence,
                        "service-principal tickets requested for offline cracking",
                    ) {
                        mitre.push(reference);
                    }
                }

                let anchor = primary(&group);
                Some(signal(
                    KRB_ID,
                    "Kerberos account enumeration or roasting",
                    anchor,
                    if roasting { Severity::High } else { Severity::Medium },
                    confidence,
                    actors(anchor, &ip, &accounts),
                    evidence_ids(&group),
                    mitre,
                    format!("Kerberos activity: {}.", reasons.join("; ")),
                ))
            })
            .collect()
    }
}


pub struct SmbEnumerationDetector;

const SMB_ID: &str = "ad_smb_enum";

impl Detector for SmbEnumerationDetector {
    fn id(&self) -> &'static str {
        SMB_ID
    }

    fn title(&self) -> &'static str {
        "SMB share enumeration"
    }

    fn evaluate(&self, ctx: &DetectionContext<'_>) -> Vec<SecuritySignal> {
        let connects = by_source(ctx.matching(|e| e.activity == "smb_tree_connect"));

        connects
            .into_iter()
            .filter_map(|(ip, group)| {
                let shares: BTreeSet<String> = group
                    .iter()
                    .filter_map(|e| e.target_name())
                    .map(str::to_string)
                    .collect();

                let hits_ipc = shares.iter().any(|s| s.to_uppercase().contains("IPC$"));
                if shares.len() < SMB_MIN_SHARES && !hits_ipc {
                    return None;
                }

                let mut confidence = 0.45_f32;
                let mut reasons = vec![format!(
                    "{} distinct shares/pipes connected from {ip}",
                    shares.len()
                )];
                if hits_ipc {
                    confidence += 0.15;
                    reasons.push("including the IPC$ pipe used for enumeration".to_string());
                }

                let mut mitre = Vec::new();
                for (id, why) in [
                    ("T1135", "shared folders and pipes enumerated over SMB"),
                    ("T1021.002", "administrative shares accessed with valid credentials"),
                ] {
                    if let Some(reference) = ctx.catalog.reference(id, confidence, why) {
                        mitre.push(reference);
                    }
                }

                let anchor = primary(&group);
                let accounts = distinct_accounts(&group);
                Some(signal(
                    SMB_ID,
                    "SMB share enumeration",
                    anchor,
                    Severity::Medium,
                    confidence,
                    actors(anchor, &ip, &accounts),
                    evidence_ids(&group),
                    mitre,
                    format!("SMB access: {}.", reasons.join("; ")),
                ))
            })
            .collect()
    }
}


pub struct DcSyncDetector;

const DCSYNC_ID: &str = "ad_dcsync";

impl Detector for DcSyncDetector {
    fn id(&self) -> &'static str {
        DCSYNC_ID
    }

    fn title(&self) -> &'static str {
        "Directory replication (DCSync) attempt"
    }

    fn evaluate(&self, ctx: &DetectionContext<'_>) -> Vec<SecuritySignal> {
        by_source(ctx.matching(|e| e.activity == "directory_replication"))
            .into_iter()
            .map(|(ip, group)| {
                let anchor = primary(&group);
                let accounts = distinct_accounts(&group);

                let mut entities = actors(anchor, &ip, &accounts);
                entities.push(EntityRef::new(EntityKind::Server, "domain-controller"));
                entities.sort();
                entities.dedup();

                let mitre = ctx
                    .catalog
                    .reference(
                        "T1003.006",
                        0.9,
                        "replication of directory secrets requested from a non-DC host",
                    )
                    .into_iter()
                    .collect();

                signal(
                    DCSYNC_ID,
                    "Directory replication (DCSync) attempt",
                    anchor,
                    Severity::Critical,
                    0.90,
                    entities,
                    evidence_ids(&group),
                    mitre,
                    format!(
                        "{} requested directory replication from {ip}; only domain controllers \
                         should replicate secrets.",
                        anchor.user().unwrap_or("An unexpected principal")
                    ),
                )
            })
            .collect()
    }
}
