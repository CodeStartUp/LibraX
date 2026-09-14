use std::collections::HashSet;

use librax_graph::AttackGraph;
use librax_types::{
    CanonicalEvent, RiskContribution, RiskScore, SecuritySignal, SourceType, ThreatReputation,
};

/// Everything the risk engine is allowed to look at.
pub struct RiskInputs<'a> {
    pub signals: &'a [SecuritySignal],
    /// The events the signals cite, used for cross-source and context factors.
    pub events: &'a [CanonicalEvent],
    pub graph: &'a AttackGraph,
    /// 0-100 from the ATT&CK progression analysis.
    pub progression_score: f32,
    /// 0.0-1.0 mean link strength from correlation.
    pub correlation_cohesion: f32,
}

/// Points available to each threat-confidence factor. They sum to 100, so the
/// breakdown the UI renders adds up to the score it sits beside.
mod threat_points {
    pub const DETECTION_STRENGTH: f32 = 40.0;
    pub const CORROBORATION: f32 = 20.0;
    pub const CROSS_SOURCE: f32 = 20.0;
    pub const THREAT_INTEL: f32 = 12.0;
    pub const COHESION: f32 = 8.0;
}

/// Impact is dominated by the single most critical thing the intrusion touched.
///
/// The remaining factors are escalators on top of that, not a division of it: an
/// attack focused on the patient database must not score below a diffuse attack
/// across a dozen unimportant assets.
mod impact_points {
    pub const PEAK_CRITICALITY: f32 = 70.0;
    pub const REGULATED_DATA: f32 = 15.0;
    pub const PRIVILEGED_IDENTITY: f32 = 8.0;
    pub const MULTIPLE_CRITICAL: f32 = 6.0;
    /// Awarded only for spread *beyond* one campus, so a single-site intrusion is
    /// not docked points for being contained.
    pub const MULTI_CAMPUS: f32 = 3.0;
}

/// How the three dimensions combine into one priority number.
mod overall_weights {
    pub const THREAT: f32 = 0.40;
    pub const IMPACT: f32 = 0.35;
    pub const PROGRESSION: f32 = 0.25;
}

fn contribution(factor: &str, points: f32, detail: impl Into<String>) -> RiskContribution {
    RiskContribution {
        factor: factor.to_string(),
        points,
        detail: detail.into(),
    }
}

pub fn assess_risk(inputs: &RiskInputs<'_>) -> RiskScore {
    if inputs.signals.is_empty() {
        return RiskScore::default();
    }

    let mut contributions: Vec<RiskContribution> = Vec::new();

    let threat_confidence = threat_confidence(inputs, &mut contributions);
    let business_impact = business_impact(inputs, &mut contributions);
    let attack_progression = inputs.progression_score.clamp(0.0, 100.0);

    contributions.push(contribution(
        "Attack progression",
        attack_progression * overall_weights::PROGRESSION,
        format!(
            "ATT&CK progression scored {attack_progression:.0}/100 and contributes {:.0}% of overall risk",
            overall_weights::PROGRESSION * 100.0
        ),
    ));

    let overall_risk = (threat_confidence * overall_weights::THREAT
        + business_impact * overall_weights::IMPACT
        + attack_progression * overall_weights::PROGRESSION)
        .clamp(0.0, 100.0);

    RiskScore {
        threat_confidence,
        business_impact,
        attack_progression,
        overall_risk,
        contributions,
    }
}

/// "How likely is this actually malicious?"
fn threat_confidence(inputs: &RiskInputs<'_>, out: &mut Vec<RiskContribution>) -> f32 {
    let signals = inputs.signals;

    let mean_confidence =
        signals.iter().map(|s| s.confidence).sum::<f32>() / signals.len() as f32;
    let detection = threat_points::DETECTION_STRENGTH * mean_confidence;
    out.push(contribution(
        "Detection strength",
        detection,
        format!(
            "{} detections with mean confidence {:.0}%",
            signals.len(),
            mean_confidence * 100.0
        ),
    ));

    let detectors: HashSet<&str> = signals.iter().map(|s| s.detector_id.as_str()).collect();
    // Eight independent detectors is treated as full corroboration; beyond that
    // the marginal evidence value is small.
    let corroboration =
        threat_points::CORROBORATION * (detectors.len().min(8) as f32 / 8.0);
    out.push(contribution(
        "Independent detectors",
        corroboration,
        format!(
            "{} different detectors fired on this activity",
            detectors.len()
        ),
    ));

    let sources: HashSet<SourceType> = inputs.events.iter().map(|e| e.source_type).collect();
    let cross_source = threat_points::CROSS_SOURCE * (sources.len().min(6) as f32 / 6.0);
    out.push(contribution(
        "Cross-source evidence",
        cross_source,
        format!(
            "corroborated across {} telemetry sources, which a single-source false positive cannot do",
            sources.len()
        ),
    ));

    let known_bad: Vec<&CanonicalEvent> = inputs
        .events
        .iter()
        .filter(|e| e.enrichment.destination_reputation == ThreatReputation::Malicious)
        .collect();
    let intel = if known_bad.is_empty() {
        0.0
    } else {
        threat_points::THREAT_INTEL
    };
    if intel > 0.0 {
        out.push(contribution(
            "Threat-intelligence match",
            intel,
            format!(
                "{} event(s) involve infrastructure already known to be malicious",
                known_bad.len()
            ),
        ));
    }

    let cohesion = threat_points::COHESION * inputs.correlation_cohesion.clamp(0.0, 1.0);
    out.push(contribution(
        "Correlation strength",
        cohesion,
        format!(
            "mean link strength {:.0}% across the correlated signals",
            inputs.correlation_cohesion * 100.0
        ),
    ));

    // Activity inside a declared maintenance window is more likely to be
    // legitimate administration, so it pulls confidence down.
    let in_maintenance = inputs.events.iter().any(|e| {
        e.attributes
            .get("maintenance_window")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    });
    let maintenance = if in_maintenance { -10.0 } else { 0.0 };
    if maintenance < 0.0 {
        out.push(contribution(
            "Maintenance context",
            maintenance,
            "part of this activity falls inside a declared maintenance window",
        ));
    }

    (detection + corroboration + cross_source + intel + cohesion + maintenance).clamp(0.0, 100.0)
}

/// "How much does the affected environment matter?"
fn business_impact(inputs: &RiskInputs<'_>, out: &mut Vec<RiskContribution>) -> f32 {
    let criticalities: Vec<u8> = inputs
        .graph
        .nodes
        .iter()
        .filter_map(|n| n.criticality)
        .collect();

    let peak = criticalities.iter().copied().max().unwrap_or(0);
    let peak_points = impact_points::PEAK_CRITICALITY * (peak as f32 / 100.0);
    let most_critical = inputs
        .graph
        .nodes
        .iter()
        .max_by_key(|n| n.criticality.unwrap_or(0));
    out.push(contribution(
        "Most critical asset involved",
        peak_points,
        match most_critical {
            Some(node) => format!("{} at criticality {peak}/100", node.label),
            None => "no rated asset identified".to_string(),
        },
    ));

    let critical_count = criticalities.iter().filter(|&&c| c >= 90).count();
    let multiple = impact_points::MULTIPLE_CRITICAL * (critical_count.min(3) as f32 / 3.0);
    out.push(contribution(
        "Critical asset count",
        multiple,
        format!("{critical_count} asset(s) rated 90 or above are involved"),
    ));

    let regulated = inputs.events.iter().any(|e| {
        e.attributes
            .get("contains_phi")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    });
    let regulated_points = if regulated {
        impact_points::REGULATED_DATA
    } else {
        0.0
    };
    if regulated {
        out.push(contribution(
            "Regulated data exposed",
            regulated_points,
            "protected health information was returned to the attacker's session",
        ));
    }

    let privileged: Vec<&str> = inputs
        .events
        .iter()
        .filter(|e| e.enrichment.privileged_account)
        .filter_map(|e| e.user())
        .collect();
    let privileged_points = if privileged.is_empty() {
        0.0
    } else {
        impact_points::PRIVILEGED_IDENTITY
    };
    if privileged_points > 0.0 {
        let unique: HashSet<&str> = privileged.into_iter().collect();
        out.push(contribution(
            "Privileged identity involved",
            privileged_points,
            format!(
                "privileged account(s) {} were used",
                unique.into_iter().collect::<Vec<_>>().join(", ")
            ),
        ));
    }

    let campuses: HashSet<&str> = inputs
        .graph
        .nodes
        .iter()
        .filter_map(|n| n.hospital.as_deref())
        .collect();
    let spread = campuses.len().saturating_sub(1).min(2) as f32 / 2.0;
    let campus_points = impact_points::MULTI_CAMPUS * spread;
    out.push(contribution(
        "Campus exposure",
        campus_points,
        match campuses.len() {
            0 => "no campus identified".to_string(),
            1 => format!(
                "contained to {}",
                campuses.iter().next().copied().unwrap_or("one campus")
            ),
            n => format!("spans {n} campuses"),
        },
    ));

    (peak_points + multiple + regulated_points + privileged_points + campus_points)
        .clamp(0.0, 100.0)
}
