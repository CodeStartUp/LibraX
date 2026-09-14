use librax_types::{EventCategory, SecuritySignal, Severity, ThreatReputation};

use crate::engine::{DetectionContext, Detector};
use crate::support::{attr_bool, attr_str, entities_of, signal};


pub struct PhishingDetector;

const ID: &str = "phishing_lure_delivered";

impl Detector for PhishingDetector {
    fn id(&self) -> &'static str {
        ID
    }

    fn title(&self) -> &'static str {
        "Spear-phishing lure delivered"
    }

    fn evaluate(&self, ctx: &DetectionContext<'_>) -> Vec<SecuritySignal> {
        ctx.matching(|e| e.category == EventCategory::Email)
            .filter_map(|event| {
                let mut reasons: Vec<String> = Vec::new();
                let mut confidence = 0.25_f32;

                let failed_checks = ["spf", "dkim", "dmarc"]
                    .iter()
                    .filter(|key| attr_str(event, key) == Some("fail"))
                    .count();
                if failed_checks >= 2 {
                    confidence += 0.20;
                    reasons.push(format!(
                        "{failed_checks} of 3 sender-authentication checks failed"
                    ));
                }

                if attr_bool(event, "attachment_macro") {
                    confidence += 0.20;
                    reasons.push(format!(
                        "attachment {} carries a macro",
                        attr_str(event, "attachment_name").unwrap_or("(unnamed)")
                    ));
                }

                if event.enrichment.destination_reputation == ThreatReputation::Malicious {
                    confidence += 0.25;
                    reasons.push("sender domain matches known-bad infrastructure".to_string());
                }

                if let Some(imitated) = attr_str(event, "lookalike_of") {
                    confidence += 0.10;
                    reasons.push(format!("sender domain imitates {imitated}"));
                }

                if attr_bool(event, "recipient_clicked") {
                    confidence += 0.15;
                    reasons.push("recipient followed the embedded link".to_string());
                }


                if reasons.len() < 2 {
                    return None;
                }

                let severity =
                    if event.enrichment.destination_reputation == ThreatReputation::Malicious {
                        Severity::High
                    } else {
                        Severity::Medium
                    };

                let mut mitre = Vec::new();
                if let Some(reference) = ctx.catalog.reference(
                    "T1566.001",
                    confidence,
                    "malicious attachment delivered to a named recipient",
                ) {
                    mitre.push(reference);
                }
                if attr_bool(event, "recipient_clicked")
                    && let Some(reference) = ctx.catalog.reference(
                        "T1204.002",
                        confidence * 0.9,
                        "recipient interacted with the delivered file or link",
                    )
                {
                    mitre.push(reference);
                }

                Some(signal(
                    ID,
                    "Spear-phishing lure delivered",
                    event,
                    severity,
                    confidence,
                    entities_of(event),
                    vec![event.event_id.clone()],
                    mitre,
                    format!(
                        "Mail to {} from {}: {}.",
                        event.user().unwrap_or("an unknown recipient"),
                        attr_str(event, "sender").unwrap_or("an unknown sender"),
                        reasons.join("; ")
                    ),
                ))
            })
            .collect()
    }
}
