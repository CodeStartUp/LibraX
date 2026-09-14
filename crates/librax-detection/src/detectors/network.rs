use librax_types::{EventCategory, SecuritySignal, Severity, ThreatReputation};

use crate::engine::{DetectionContext, Detector};
use crate::support::{attr_num, attr_str, entities_of, ratio, signal};


pub struct CommandAndControlDetector;

const C2_ID: &str = "c2_connection";

impl Detector for CommandAndControlDetector {
    fn id(&self) -> &'static str {
        C2_ID
    }

    fn title(&self) -> &'static str {
        "Command-and-control channel"
    }

    fn evaluate(&self, ctx: &DetectionContext<'_>) -> Vec<SecuritySignal> {
        ctx.matching(|e| {
            matches!(e.category, EventCategory::Network | EventCategory::Dns)
                && e.activity != "flow_summary"
        })
        .filter_map(|event| {
            let known_bad =
                event.enrichment.destination_reputation == ThreatReputation::Malicious;

            let connections = attr_num(event, "connection_count");
            let mean = attr_num(event, "interval_seconds_mean");
            let stddev = attr_num(event, "interval_seconds_stddev");

            let regular = connections >= 10.0
                && mean > 0.0
                && stddev >= 0.0
                && (stddev / mean) < 0.15;

            if !known_bad && !regular {
                return None;
            }

            let mut confidence = 0.25_f32;
            let mut reasons: Vec<String> = Vec::new();

            if known_bad {
                confidence += 0.35;
                reasons.push(format!(
                    "destination {} matches known-bad infrastructure",
                    event
                        .destination
                        .as_ref()
                        .and_then(|d| d.domain.as_deref())
                        .or(event.dst_ip())
                        .unwrap_or("(unknown)")
                ));
            }

            if regular {
                confidence += 0.30;
                reasons.push(format!(
                    "{connections:.0} connections at {mean:.0}s intervals with only {stddev:.1}s variance"
                ));
            }

            let domain_age = attr_num(event, "domain_age_days");
            if domain_age > 0.0 && domain_age < 30.0 {
                confidence += 0.15;
                reasons.push(format!("destination domain registered {domain_age:.0} days ago"));
            }

            let mitre = ctx
                .catalog
                .reference(
                    "T1071.001",
                    confidence,
                    "outbound web traffic showing machine-timed beacon behaviour",
                )
                .into_iter()
                .collect();

            Some(signal(
                C2_ID,
                "Command-and-control channel",
                event,
                Severity::Critical,
                confidence,
                entities_of(event),
                vec![event.event_id.clone()],
                mitre,
                format!(
                    "Host at {}: {}.",
                    event.src_ip().unwrap_or("an unknown address"),
                    reasons.join("; ")
                ),
            ))
        })
        .collect()
    }
}


pub struct NetworkDiscoveryDetector;

const SCAN_ID: &str = "network_discovery";

impl Detector for NetworkDiscoveryDetector {
    fn id(&self) -> &'static str {
        SCAN_ID
    }

    fn title(&self) -> &'static str {
        "Internal network discovery"
    }

    fn evaluate(&self, ctx: &DetectionContext<'_>) -> Vec<SecuritySignal> {
        ctx.matching(|e| e.activity == "flow_summary")
            .filter_map(|event| {
                let destinations = attr_num(event, "distinct_destinations");
                let baseline = attr_num(event, "baseline_distinct_destinations");
                let multiple = ratio(destinations, baseline);

                if destinations < 50.0 || multiple < 5.0 {
                    return None;
                }

                let window = attr_num(event, "window_seconds").max(1.0);
                let mut confidence = 0.40_f32;
                let mut reasons = vec![format!(
                    "{destinations:.0} distinct destinations in {window:.0}s against a baseline of {baseline:.0}"
                )];

                let ports = attr_num(event, "distinct_ports");
                if ports >= 10.0 {
                    confidence += 0.15;
                    reasons.push(format!("{ports:.0} distinct ports probed"));
                }

                let denied = attr_num(event, "connections_denied");
                let allowed = attr_num(event, "connections_allowed");
                if denied > allowed * 3.0 && denied > 0.0 {
                    confidence += 0.20;
                    reasons.push(format!(
                        "{denied:.0} of {:.0} attempts were refused, consistent with sweeping rather than use",
                        denied + allowed
                    ));
                }

                let mut mitre = Vec::new();
                for (id, note) in [
                    ("T1046", "sweep across many hosts and ports in a short window"),
                    ("T1018", "enumeration of reachable internal systems"),
                ] {
                    if let Some(reference) = ctx.catalog.reference(id, confidence, note) {
                        mitre.push(reference);
                    }
                }

                Some(signal(
                    SCAN_ID,
                    "Internal network discovery",
                    event,
                    Severity::Medium,
                    confidence,
                    entities_of(event),
                    vec![event.event_id.clone()],
                    mitre,
                    format!(
                        "Source {}: {}.",
                        event.src_ip().unwrap_or("unknown"),
                        reasons.join("; ")
                    ),
                ))
            })
            .collect()
    }
}


pub struct VolumetricDetector;

const DDOS_ID: &str = "network_volume_anomaly";

impl Detector for VolumetricDetector {
    fn id(&self) -> &'static str {
        DDOS_ID
    }

    fn title(&self) -> &'static str {
        "Volumetric attack on a gateway"
    }

    fn evaluate(&self, ctx: &DetectionContext<'_>) -> Vec<SecuritySignal> {
        ctx.matching(|e| e.activity == "flow_summary")
            .filter_map(|event| {
                let rate = attr_num(event, "connections_per_minute");
                let baseline = attr_num(event, "baseline_connections_per_minute");
                let multiple = ratio(rate, baseline);
                let sources = attr_num(event, "unique_sources");
                let concentration = attr_num(event, "destination_concentration");

                if rate <= 0.0 || multiple < 10.0 || sources < 100.0 || concentration < 0.8 {
                    return None;
                }

                let confidence = (0.55 + (multiple / 1_000.0) as f32).clamp(0.0, 0.98);

                let mitre = ctx
                    .catalog
                    .reference(
                        "T1498",
                        confidence,
                        "connection volume far above baseline concentrated on one destination",
                    )
                    .into_iter()
                    .collect();

                Some(signal(
                    DDOS_ID,
                    "Volumetric attack on a gateway",
                    event,
                    Severity::High,
                    confidence,
                    entities_of(event),
                    vec![event.event_id.clone()],
                    mitre,
                    format!(
                        "Target {}: {rate:.0} connections/min against a baseline of {baseline:.0} ({multiple:.0}x) \
                         from {sources:.0} unique sources, {:.0}% aimed at one destination. \
                         Reported as one signal rather than {rate:.0} alerts.",
                        attr_str(event, "dst_hostname")
                            .or(event.dst_ip())
                            .unwrap_or("an unknown gateway"),
                        concentration * 100.0
                    ),
                ))
            })
            .collect()
    }
}


pub struct BlockedOutboundDetector;

const BLOCKED_ID: &str = "blocked_outbound_unproven_host";

impl Detector for BlockedOutboundDetector {
    fn id(&self) -> &'static str {
        BLOCKED_ID
    }

    fn title(&self) -> &'static str {
        "Blocked outbound connection"
    }

    fn evaluate(&self, ctx: &DetectionContext<'_>) -> Vec<SecuritySignal> {
        ctx.matching(|e| e.activity == "connection_denied")
            .filter_map(|event| {
                let destination = event.dst_ip()?;
                if destination.starts_with("10.") || destination.starts_with("192.168.") {
                    return None;
                }

                Some(signal(
                    BLOCKED_ID,
                    "Blocked outbound connection",
                    event,
                    Severity::Low,
                    0.30,
                    entities_of(event),
                    vec![event.event_id.clone()],


                    Vec::new(),
                    format!(
                        "Perimeter refused {} -> {destination}. No reputation data supports \
                         escalating this on its own.",
                        event.src_ip().unwrap_or("an internal host")
                    ),
                ))
            })
            .collect()
    }
}
