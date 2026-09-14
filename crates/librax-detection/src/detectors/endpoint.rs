use librax_types::{EventCategory, SecuritySignal, Severity, Tactic};

use crate::engine::{DetectionContext, Detector};
use crate::support::{attr_bool, attr_num, attr_str, entities_of, lower, signal};

/// Office applications that hatch PowerShell, and PowerShell that hides what it
/// is running.
///
/// Plain `powershell.exe` is a legitimate administration tool, so this detector
/// insists on either an encoded command or an Office parent process before it
/// says anything.
pub struct PowerShellDetector;

const PS_ID: &str = "powershell_encoded_command";

const OFFICE_PARENTS: &[&str] = &[
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "outlook.exe",
    "msaccess.exe",
];

impl Detector for PowerShellDetector {
    fn id(&self) -> &'static str {
        PS_ID
    }

    fn title(&self) -> &'static str {
        "Encoded PowerShell execution"
    }

    fn evaluate(&self, ctx: &DetectionContext<'_>) -> Vec<SecuritySignal> {
        ctx.matching(|e| {
            e.category == EventCategory::Process
                && lower(e.process_name()).contains("powershell")
        })
        .filter_map(|event| {
            let cmdline = lower(event.command_line());
            let parent = lower(event.process.as_ref().and_then(|p| p.parent_name.as_deref()));

            let encoded = ["-enc", "-encodedcommand", "-e "]
                .iter()
                .any(|flag| cmdline.contains(flag));
            let office_parent = OFFICE_PARENTS.iter().any(|p| parent == *p);

            // Neither condition present means this is ordinary administration.
            if !encoded && !office_parent {
                return None;
            }

            let mut confidence = 0.35_f32;
            let mut reasons: Vec<String> = Vec::new();

            if encoded {
                confidence += 0.25;
                reasons.push("command body is base64-encoded, hiding its contents".to_string());
            }
            if office_parent {
                confidence += 0.20;
                reasons.push(format!("spawned by {parent}, which indicates macro execution"));
            }
            if cmdline.contains("hidden") {
                confidence += 0.10;
                reasons.push("window style set to hidden".to_string());
            }
            if cmdline.contains("bypass") {
                confidence += 0.10;
                reasons.push("execution policy bypassed".to_string());
            }
            if cmdline.contains("-nop") || cmdline.contains("-noprofile") {
                confidence += 0.05;
                reasons.push("profile skipped to avoid logging hooks".to_string());
            }

            let mut mitre = Vec::new();
            if let Some(reference) = ctx.catalog.reference(
                "T1059.001",
                confidence,
                "PowerShell process created with attacker-style flags",
            ) {
                mitre.push(reference);
            }
            if encoded
                && let Some(reference) = ctx.catalog.reference(
                    "T1027",
                    confidence * 0.85,
                    "command line encoded to frustrate inspection",
                )
            {
                mitre.push(reference);
            }

            Some(signal(
                PS_ID,
                "Encoded PowerShell execution",
                event,
                Severity::High,
                confidence,
                entities_of(event),
                vec![event.event_id.clone()],
                mitre,
                format!(
                    "PowerShell on {} as {}: {}.",
                    event.host_name().unwrap_or("an unknown host"),
                    event.user().unwrap_or("an unknown user"),
                    reasons.join("; ")
                ),
            ))
        })
        .collect()
    }
}

/// Large archives assembled in temporary directories: collection before removal.
pub struct DataStagingDetector;

const STAGING_ID: &str = "data_staging";

impl Detector for DataStagingDetector {
    fn id(&self) -> &'static str {
        STAGING_ID
    }

    fn title(&self) -> &'static str {
        "Data staged for exfiltration"
    }

    fn evaluate(&self, ctx: &DetectionContext<'_>) -> Vec<SecuritySignal> {
        ctx.matching(|e| e.category == EventCategory::File)
            .filter_map(|event| {
                if !attr_bool(event, "is_archive") {
                    return None;
                }

                let size_bytes = attr_num(event, "file_size_bytes");
                let mut confidence = 0.40_f32;
                let mut reasons = vec![format!(
                    "archive {} created by {}",
                    event.target_name().unwrap_or("(unnamed)"),
                    attr_str(event, "process_name").unwrap_or("an unknown process")
                )];

                if attr_bool(event, "in_temp_directory") {
                    confidence += 0.20;
                    reasons.push("written to a temporary directory rather than a user share".to_string());
                }

                if size_bytes >= 100_000_000.0 {
                    confidence += 0.20;
                    reasons.push(format!(
                        "{:.1} GB of data in a single file",
                        size_bytes / 1_073_741_824.0
                    ));
                }

                let records = attr_num(event, "source_records");
                if records >= 1_000.0 {
                    confidence += 0.15;
                    reasons.push(format!("{records:.0} source records consolidated"));
                }

                if reasons.len() < 2 {
                    return None;
                }

                let mut mitre = Vec::new();
                for (id, note) in [
                    ("T1074.001", "collected data consolidated in one location"),
                    ("T1560.001", "archive utility used to compress the collection"),
                ] {
                    if let Some(reference) = ctx.catalog.reference(id, confidence, note) {
                        mitre.push(reference);
                    }
                }

                Some(signal(
                    STAGING_ID,
                    "Data staged for exfiltration",
                    event,
                    Severity::High,
                    confidence,
                    entities_of(event),
                    vec![event.event_id.clone()],
                    mitre,
                    format!(
                        "On {}: {}.",
                        event.host_name().unwrap_or("an unknown host"),
                        reasons.join("; ")
                    ),
                ))
            })
            .collect()
    }
}

/// Recovery being disabled and files changing en masse: ransomware staging.
pub struct RansomwareDetector;

const RANSOM_ID: &str = "ransomware_indicator";

impl Detector for RansomwareDetector {
    fn id(&self) -> &'static str {
        RANSOM_ID
    }

    fn title(&self) -> &'static str {
        "Ransomware preparation detected"
    }

    fn evaluate(&self, ctx: &DetectionContext<'_>) -> Vec<SecuritySignal> {
        ctx.matching(|e| e.category == EventCategory::Process)
            .filter_map(|event| {
                let shadow_deleted = attr_bool(event, "shadow_copy_deletion");
                let modify_rate = attr_num(event, "files_modified_per_minute");
                let new_extensions = event
                    .attributes
                    .get("new_extensions_observed")
                    .and_then(|v| v.as_array())
                    .map(|a| a.len())
                    .unwrap_or(0);

                // One of the two hard indicators is required.
                if !shadow_deleted && modify_rate < 500.0 {
                    return None;
                }

                let mut confidence = 0.25_f32;
                let mut reasons: Vec<String> = Vec::new();

                if shadow_deleted {
                    confidence += 0.40;
                    reasons.push(format!(
                        "shadow copies deleted via `{}`, removing the recovery path",
                        attr_str(event, "process_cmdline").unwrap_or("an unknown command")
                    ));
                }

                if modify_rate >= 500.0 {
                    confidence += 0.30;
                    reasons.push(format!(
                        "{modify_rate:.0} files modified per minute, far above interactive use"
                    ));
                }

                if new_extensions > 0 {
                    confidence += 0.20;
                    reasons.push(format!("{new_extensions} previously unseen file extension(s)"));
                }

                if attr_bool(event, "entropy_increase") {
                    confidence += 0.10;
                    reasons.push("file entropy rising, consistent with encryption".to_string());
                }

                let mut mitre = Vec::new();
                if shadow_deleted
                    && let Some(reference) = ctx.catalog.reference(
                        "T1490",
                        confidence,
                        "volume shadow copies destroyed",
                    )
                {
                    mitre.push(reference);
                }
                if (new_extensions > 0 || attr_bool(event, "entropy_increase"))
                    && let Some(reference) = ctx.catalog.reference_as(
                        "T1486",
                        Tactic::Impact,
                        confidence * 0.9,
                        "files rewritten with new extensions and rising entropy",
                    )
                {
                    mitre.push(reference);
                }

                Some(signal(
                    RANSOM_ID,
                    "Ransomware preparation detected",
                    event,
                    Severity::Critical,
                    confidence,
                    entities_of(event),
                    vec![event.event_id.clone()],
                    mitre,
                    format!(
                        "On {}: {}.",
                        event.host_name().unwrap_or("an unknown host"),
                        reasons.join("; ")
                    ),
                ))
            })
            .collect()
    }
}
