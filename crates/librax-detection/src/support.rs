use librax_types::{CanonicalEvent, EntityRef, MitreTechniqueRef, SecuritySignal, Severity};

/// Assembles a signal with a stable, derivable id.
///
/// Deriving the id from `detector_id` + primary event means the same behaviour
/// seen twice produces the same signal, so overlapping detection windows are
/// idempotent rather than a source of duplicate incidents.
#[allow(clippy::too_many_arguments)]
pub fn signal(
    detector_id: &'static str,
    title: &'static str,
    primary: &CanonicalEvent,
    severity: Severity,
    confidence: f32,
    entities: Vec<EntityRef>,
    evidence_event_ids: Vec<String>,
    mitre: Vec<MitreTechniqueRef>,
    explanation: String,
) -> SecuritySignal {
    SecuritySignal {
        signal_id: format!("SIG-{detector_id}-{}", primary.event_id),
        detector_id: detector_id.to_string(),
        title: title.to_string(),
        timestamp: primary.timestamp,
        severity,
        confidence: confidence.clamp(0.0, 1.0),
        entities,
        evidence_event_ids,
        mitre,
        explanation,
    }
}

/// Every entity an event names, plus its network endpoints as IP entities.
pub fn entities_of(event: &CanonicalEvent) -> Vec<EntityRef> {
    let mut entities = event.entities();

    for ip in [event.src_ip(), event.dst_ip()].into_iter().flatten() {
        entities.push(EntityRef::ip(ip));
    }

    if let Some(process) = event.process_name() {
        entities.push(EntityRef::process(process));
    }

    entities.sort();
    entities.dedup();
    entities
}

pub fn lower(value: Option<&str>) -> String {
    value.unwrap_or_default().to_ascii_lowercase()
}

pub fn attr_bool(event: &CanonicalEvent, key: &str) -> bool {
    event
        .attributes
        .get(key)
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

pub fn attr_num(event: &CanonicalEvent, key: &str) -> f64 {
    event.attribute_f64(key).unwrap_or(0.0)
}

pub fn attr_str<'a>(event: &'a CanonicalEvent, key: &str) -> Option<&'a str> {
    event.attribute_str(key)
}

/// Ratio of `value` to `baseline`, guarding against a zero baseline.
pub fn ratio(value: f64, baseline: f64) -> f64 {
    if baseline <= 0.0 {
        if value > 0.0 { f64::INFINITY } else { 0.0 }
    } else {
        value / baseline
    }
}
