use librax_types::{SecuritySignal, Severity, Tactic};

use crate::engine::{DetectionContext, Detector};
use crate::support::{attr_bool, attr_num, attr_str, entities_of, signal};

/// Impossible travel and MFA fatigue on VPN authentication.
pub struct VpnAnomalyDetector;

const VPN_ID: &str = "vpn_identity_anomaly";

impl Detector for VpnAnomalyDetector {
    fn id(&self) -> &'static str {
        VPN_ID
    }

    fn title(&self) -> &'static str {
        "VPN identity anomaly"
    }

    fn evaluate(&self, ctx: &DetectionContext<'_>) -> Vec<SecuritySignal> {
        ctx.matching(|e| e.activity == "vpn_session_start")
            .filter_map(|event| {
                let mut reasons: Vec<String> = Vec::new();
                let mut confidence = 0.30_f32;

                let country = attr_str(event, "client_country").unwrap_or_default();
                let previous = attr_str(event, "previous_country").unwrap_or_default();
                let gap_minutes = attr_num(event, "minutes_since_previous_session");

                // Geography that cannot be reconciled with the previous session.
                if !country.is_empty()
                    && !previous.is_empty()
                    && country != previous
                    && gap_minutes > 0.0
                    && gap_minutes < 240.0
                {
                    confidence += 0.35;
                    reasons.push(format!(
                        "session from {country} only {gap_minutes:.0} minutes after a session from {previous}"
                    ));
                }

                let prompts = attr_num(event, "mfa_prompts");
                let accepted_after = attr_num(event, "mfa_accepted_after");
                if prompts >= 5.0 && accepted_after >= prompts {
                    confidence += 0.25;
                    reasons.push(format!(
                        "{prompts:.0} MFA prompts before approval, consistent with push fatigue"
                    ));
                }

                if reasons.is_empty() {
                    return None;
                }

                let severity = if reasons.len() >= 2 {
                    Severity::High
                } else {
                    Severity::Medium
                };

                let mitre = ctx
                    .catalog
                    .reference_as(
                        "T1078",
                        Tactic::InitialAccess,
                        confidence,
                        "valid credentials used from an implausible location",
                    )
                    .into_iter()
                    .collect();

                Some(signal(
                    VPN_ID,
                    "VPN identity anomaly",
                    event,
                    severity,
                    confidence,
                    entities_of(event),
                    vec![event.event_id.clone()],
                    mitre,
                    format!(
                        "VPN authentication for {}: {}.",
                        event.user().unwrap_or("an unknown user"),
                        reasons.join("; ")
                    ),
                ))
            })
            .collect()
    }
}

/// Password spraying and brute force that ends in a successful logon.
pub struct CredentialAbuseDetector;

const CRED_ID: &str = "credential_abuse";

impl Detector for CredentialAbuseDetector {
    fn id(&self) -> &'static str {
        CRED_ID
    }

    fn title(&self) -> &'static str {
        "Credential abuse against a privileged account"
    }

    fn evaluate(&self, ctx: &DetectionContext<'_>) -> Vec<SecuritySignal> {
        ctx.matching(|e| e.activity == "logon_failure_burst")
            .filter_map(|event| {
                let failures = attr_num(event, "failure_count");
                let window = attr_num(event, "window_seconds").max(1.0);
                let accounts = attr_num(event, "distinct_accounts_targeted");
                let succeeded = attr_bool(event, "followed_by_success");

                if failures < 5.0 {
                    return None;
                }

                let mut confidence = 0.45_f32;
                let mut reasons = vec![format!(
                    "{failures:.0} failed logons in {window:.0} seconds"
                )];

                if accounts >= 3.0 {
                    confidence += 0.20;
                    reasons.push(format!(
                        "{accounts:.0} distinct accounts targeted, consistent with spraying"
                    ));
                }

                if succeeded {
                    confidence += 0.25;
                    reasons.push("the burst was followed by a successful logon".to_string());
                }

                let severity = if succeeded {
                    Severity::High
                } else {
                    Severity::Medium
                };

                let mitre = ctx
                    .catalog
                    .reference(
                        "T1110.003",
                        confidence,
                        "repeated authentication failures across multiple accounts",
                    )
                    .into_iter()
                    .collect();

                Some(signal(
                    CRED_ID,
                    "Credential abuse against a privileged account",
                    event,
                    severity,
                    confidence,
                    entities_of(event),
                    vec![event.event_id.clone()],
                    mitre,
                    format!(
                        "Account {} on {}: {}.",
                        attr_str(event, "TargetUserName").unwrap_or("unknown"),
                        event.host_name().unwrap_or("an unknown host"),
                        reasons.join("; ")
                    ),
                ))
            })
            .collect()
    }
}

/// Privileged credential checkout that sidesteps normal change control.
pub struct PrivilegedAccessDetector;

const PAM_ID: &str = "privileged_access_anomaly";

impl Detector for PrivilegedAccessDetector {
    fn id(&self) -> &'static str {
        PAM_ID
    }

    fn title(&self) -> &'static str {
        "Privileged session outside change control"
    }

    fn evaluate(&self, ctx: &DetectionContext<'_>) -> Vec<SecuritySignal> {
        ctx.matching(|e| e.activity == "pam_session_checkout")
            .filter_map(|event| {
                let mut reasons: Vec<String> = Vec::new();
                let mut confidence = 0.35_f32;

                if attr_bool(event, "outside_change_window") {
                    confidence += 0.25;
                    reasons.push("checkout fell outside any approved change window".to_string());
                }

                if attr_bool(event, "requester_first_use_of_account") {
                    confidence += 0.20;
                    reasons.push("requester has never used this account before".to_string());
                }

                if attr_str(event, "approval") == Some("auto") {
                    confidence += 0.10;
                    reasons.push("granted by auto-approval with no human review".to_string());
                }

                if reasons.is_empty() {
                    return None;
                }

                let severity = if reasons.len() >= 2 {
                    Severity::High
                } else {
                    Severity::Medium
                };

                let mitre = ctx
                    .catalog
                    .reference_as(
                        "T1078",
                        Tactic::PrivilegeEscalation,
                        confidence,
                        "privileged account obtained through the credential vault",
                    )
                    .into_iter()
                    .collect();

                Some(signal(
                    PAM_ID,
                    "Privileged session outside change control",
                    event,
                    severity,
                    confidence,
                    entities_of(event),
                    vec![event.event_id.clone()],
                    mitre,
                    format!(
                        "{} checked out {} for {}: {}.",
                        event.user().unwrap_or("an unknown requester"),
                        event.target_name().unwrap_or("a privileged account"),
                        event.host_name().unwrap_or("an unknown host"),
                        reasons.join("; ")
                    ),
                ))
            })
            .collect()
    }
}
