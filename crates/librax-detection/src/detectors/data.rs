use librax_types::{EventCategory, SecuritySignal, Severity};

use crate::engine::{DetectionContext, Detector};
use crate::support::{attr_bool, attr_num, attr_str, entities_of, lower, ratio, signal};

/// A workstation authenticating into a server over a remote-execution service
/// for the first time.
pub struct LateralMovementDetector;

const LATERAL_ID: &str = "lateral_movement";

const REMOTE_SERVICES: &[&str] = &["winrm", "psexec", "rdp", "smb", "wmi"];

impl Detector for LateralMovementDetector {
    fn id(&self) -> &'static str {
        LATERAL_ID
    }

    fn title(&self) -> &'static str {
        "Lateral movement into a server"
    }

    fn evaluate(&self, ctx: &DetectionContext<'_>) -> Vec<SecuritySignal> {
        ctx.matching(|e| e.activity == "remote_logon")
            .filter_map(|event| {
                let service = lower(attr_str(event, "service"));
                if !REMOTE_SERVICES.iter().any(|s| service.contains(s)) {
                    return None;
                }

                // Server-to-server automation is normal; a workstation reaching
                // into a server over WinRM is not.
                if !attr_bool(event, "source_is_workstation") {
                    return None;
                }

                let mut confidence = 0.40_f32;
                let mut reasons = vec![format!(
                    "workstation at {} authenticated to {} over {}",
                    event.src_ip().unwrap_or("an unknown address"),
                    event.host_name().unwrap_or("a server"),
                    attr_str(event, "service").unwrap_or("a remote service")
                )];

                if attr_bool(event, "first_time_for_user") {
                    confidence += 0.25;
                    reasons.push("no prior history of this user on this host".to_string());
                }

                let technique = if service.contains("winrm") {
                    "T1021.006"
                } else {
                    "T1021"
                };
                let mitre = ctx
                    .catalog
                    .reference(
                        technique,
                        confidence,
                        "remote service used with valid credentials to reach another host",
                    )
                    .into_iter()
                    .collect();

                Some(signal(
                    LATERAL_ID,
                    "Lateral movement into a server",
                    event,
                    Severity::High,
                    confidence,
                    entities_of(event),
                    vec![event.event_id.clone()],
                    mitre,
                    format!(
                        "{}: {}.",
                        event.user().unwrap_or("An unknown user"),
                        reasons.join("; ")
                    ),
                ))
            })
            .collect()
    }
}

/// Bulk reads from a database, measured against that instance's own baseline.
pub struct DatabaseExfiltrationDetector;

const DB_ID: &str = "database_mass_access";

impl Detector for DatabaseExfiltrationDetector {
    fn id(&self) -> &'static str {
        DB_ID
    }

    fn title(&self) -> &'static str {
        "Abnormal bulk access to a clinical data store"
    }

    fn evaluate(&self, ctx: &DetectionContext<'_>) -> Vec<SecuritySignal> {
        // Imaging archives are data repositories too: a sweep of PACS is the same
        // behaviour as a sweep of the patient database, and both map to T1213.
        ctx.matching(|e| {
            matches!(
                e.category,
                EventCategory::Database | EventCategory::MedicalImaging
            )
        })
        .filter_map(|event| {
            let rows = attr_num(event, "rows_returned");
            let baseline = attr_num(event, "baseline_rows_returned");
            let multiple = ratio(rows, baseline);

            // Judged against the instance baseline, not an absolute number,
            // so a busy reporting database does not alert every minute.
            if multiple < 10.0 || rows < 1_000.0 {
                return None;
            }

            let unit = if event.category == EventCategory::MedicalImaging {
                "imaging studies"
            } else {
                "rows"
            };

            let mut confidence = 0.30_f32;
            let mut reasons = vec![format!(
                "{rows:.0} {unit} returned against a baseline of {baseline:.0} ({multiple:.0}x)"
            )];

            if attr_bool(event, "contains_phi") {
                confidence += 0.25;
                reasons.push("result set contains protected health information".to_string());
            }

            if multiple >= 100.0 {
                confidence += 0.25;
                reasons.push("volume is two orders of magnitude above normal".to_string());
            }

            if event.enrichment.privileged_account || event.enrichment.service_account {
                confidence += 0.15;
                reasons.push("executed under a privileged service account".to_string());
            }

            let severity = if attr_bool(event, "contains_phi") {
                Severity::Critical
            } else {
                Severity::High
            };

            let mitre = ctx
                .catalog
                .reference(
                    "T1213",
                    confidence,
                    "bulk retrieval from a business data repository",
                )
                .into_iter()
                .collect();

            Some(signal(
                DB_ID,
                self.title(),
                event,
                severity,
                confidence,
                entities_of(event),
                vec![event.event_id.clone()],
                mitre,
                format!(
                    "{} on {}: {}.",
                    event.user().unwrap_or("An unknown principal"),
                    event.target_name().unwrap_or("an unknown instance"),
                    reasons.join("; ")
                ),
            ))
        })
        .collect()
    }
}
