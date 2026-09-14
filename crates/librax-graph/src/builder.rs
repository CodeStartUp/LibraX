use std::collections::{HashMap, HashSet};

use librax_enrichment::Inventory;
use librax_entities::EntityResolver;
use librax_types::{
    CanonicalEvent, EntityKind, EntityRef, Exposure, RelationType, SecuritySignal,
};

use crate::graph::{AttackGraph, GraphEdge, GraphNode};

/// One derived relationship, before merging.
struct Derived {
    from: EntityRef,
    relation: RelationType,
    to: EntityRef,
    confidence: f32,
}

fn edge(from: EntityRef, relation: RelationType, to: EntityRef, confidence: f32) -> Derived {
    Derived {
        from,
        relation,
        to,
        confidence,
    }
}

/// Builds the graph for a set of events.
///
/// Callers pass the events an incident actually cites, so the result is that
/// incident's graph rather than a picture of the whole estate.
pub fn build(
    events: &[CanonicalEvent],
    signals: &[SecuritySignal],
    resolver: &EntityResolver,
    inventory: &Inventory,
) -> AttackGraph {
    // Entities named by a detection are confirmed; everything else the graph
    // touches is only adjacent to the intrusion.
    let confirmed: HashSet<String> = signals
        .iter()
        .flat_map(|s| resolver.resolve_signal(s))
        .map(|e| e.id)
        .collect();

    // Which detections cited which event.
    let mut signals_by_event: HashMap<&str, Vec<String>> = HashMap::new();
    for signal in signals {
        for event_id in &signal.evidence_event_ids {
            signals_by_event
                .entry(event_id.as_str())
                .or_default()
                .push(signal.signal_id.clone());
        }
    }

    let mut nodes: HashMap<String, GraphNode> = HashMap::new();
    let mut edges: HashMap<String, GraphEdge> = HashMap::new();

    for event in events {
        let cited_by = signals_by_event
            .get(event.event_id.as_str())
            .cloned()
            .unwrap_or_default();

        for derived in derive(event, resolver) {
            let from = touch_node(
                &mut nodes,
                derived.from,
                event,
                &confirmed,
                inventory,
            );
            let to = touch_node(&mut nodes, derived.to, event, &confirmed, inventory);

            if from == to {
                continue;
            }

            let key = format!("{from}|{}|{to}", derived.relation.label());
            let entry = edges.entry(key.clone()).or_insert_with(|| GraphEdge {
                id: key.clone(),
                from: from.clone(),
                to: to.clone(),
                relation: derived.relation,
                label: derived.relation.label().to_string(),
                confidence: derived.confidence,
                first_seen: event.timestamp,
                last_seen: event.timestamp,
                evidence_event_ids: Vec::new(),
                signal_ids: Vec::new(),
                structural: false,
            });

            entry.confidence = entry.confidence.max(derived.confidence);
            entry.first_seen = entry.first_seen.min(event.timestamp);
            entry.last_seen = entry.last_seen.max(event.timestamp);
            if !entry.evidence_event_ids.contains(&event.event_id) {
                entry.evidence_event_ids.push(event.event_id.clone());
            }
            for signal_id in &cited_by {
                if !entry.signal_ids.contains(signal_id) {
                    entry.signal_ids.push(signal_id.clone());
                }
            }
        }
    }

    // A detection can name an entity without establishing any relationship to
    // another one; a volumetric attack on a single gateway is the clearest case.
    // Those entities still belong in the graph, otherwise the asset the detection
    // was actually about is invisible to blast radius and impact scoring.
    for signal in signals {
        let anchor = signal
            .evidence_event_ids
            .iter()
            .find_map(|id| events.iter().find(|e| &e.event_id == id));

        let Some(event) = anchor else { continue };

        for entity in resolver.resolve_signal(signal) {
            if !nodes.contains_key(&entity.id) {
                touch_node(&mut nodes, entity, event, &confirmed, inventory);
            }
        }
    }

    let mut graph = AttackGraph {
        nodes: nodes.into_values().collect(),
        edges: edges.into_values().collect(),
    };

    graph.nodes.sort_by(|a, b| {
        a.first_seen
            .cmp(&b.first_seen)
            .then_with(|| a.id.cmp(&b.id))
    });
    graph.edges.sort_by(|a, b| {
        a.first_seen
            .cmp(&b.first_seen)
            .then_with(|| a.id.cmp(&b.id))
    });
    graph
}

fn touch_node(
    nodes: &mut HashMap<String, GraphNode>,
    entity: EntityRef,
    event: &CanonicalEvent,
    confirmed: &HashSet<String>,
    inventory: &Inventory,
) -> String {
    let id = entity.id.clone();
    let asset = inventory.asset_by_name(&entity.name);

    // Anything the inventory cannot place, and that resolution left as a bare
    // address or domain, is outside the estate.
    let external =
        asset.is_none() && matches!(entity.kind, EntityKind::Ip | EntityKind::Domain);

    let node = nodes.entry(id.clone()).or_insert_with(|| GraphNode {
        id: id.clone(),
        kind: entity.kind,
        kind_label: entity.kind.label().to_string(),
        label: entity.name.clone(),
        exposure: if confirmed.contains(&id) {
            Exposure::Confirmed
        } else {
            Exposure::Reachable
        },
        criticality: asset.map(|a| a.criticality),
        hospital: asset.map(|a| a.hospital.clone()).or_else(|| {
            // Internal entities the inventory does not list, such as a process,
            // sit at the site that observed them. External infrastructure sits
            // at no site: inheriting the observing host's campus would attribute
            // the attacker's server to a hospital.
            if external {
                None
            } else {
                event.enrichment.hospital.clone()
            }
        }),
        external,
        event_count: 0,
        first_seen: event.timestamp,
        last_seen: event.timestamp,
    });

    node.event_count += 1;
    node.first_seen = node.first_seen.min(event.timestamp);
    node.last_seen = node.last_seen.max(event.timestamp);
    id
}

/// Relationships implied by a single event.
fn derive(event: &CanonicalEvent, resolver: &EntityResolver) -> Vec<Derived> {
    let mut out: Vec<Derived> = Vec::new();

    let principal = event.principal.as_ref().map(|e| resolver.resolve(e));
    let host = event.host.as_ref().map(|e| resolver.resolve(e));
    let target = event.target.as_ref().map(|e| resolver.resolve(e));
    let src = event.src_ip().map(|ip| resolver.resolve(&EntityRef::ip(ip)));
    let dst = event.dst_ip().map(|ip| resolver.resolve(&EntityRef::ip(ip)));
    let domain = event
        .destination
        .as_ref()
        .and_then(|d| d.domain.as_deref())
        .map(|d| EntityRef::new(EntityKind::Domain, d));

    match event.activity.as_str() {
        // Mail arriving from outside, addressed to a named person.
        "mail_delivered" => {
            if let (Some(sender), Some(recipient)) = (domain.as_ref(), principal.as_ref()) {
                out.push(edge(
                    sender.clone(),
                    RelationType::Delivers,
                    recipient.clone(),
                    0.95,
                ));
            }
        }

        // A remote client authenticating in and being handed an internal address.
        "vpn_session_start" => {
            if let (Some(user), Some(assigned)) = (principal.as_ref(), dst.as_ref()) {
                out.push(edge(user.clone(), RelationType::Uses, assigned.clone(), 0.90));
            }
            if let (Some(client), Some(assigned)) = (src.as_ref(), dst.as_ref()) {
                out.push(edge(
                    client.clone(),
                    RelationType::ConnectsTo,
                    assigned.clone(),
                    0.88,
                ));
            }
        }

        // A workstation reaching into a server over a remote-execution service.
        "remote_logon" => {
            if let (Some(source), Some(server)) = (src.as_ref(), host.as_ref()) {
                out.push(edge(
                    source.clone(),
                    RelationType::LateralMovesTo,
                    server.clone(),
                    0.90,
                ));
            }
            if let (Some(user), Some(server)) = (principal.as_ref(), host.as_ref()) {
                out.push(edge(
                    user.clone(),
                    RelationType::AuthenticatesTo,
                    server.clone(),
                    0.95,
                ));
            }
        }

        "pam_session_checkout" => {
            if let (Some(requester), Some(account)) = (principal.as_ref(), target.as_ref()) {
                out.push(edge(
                    requester.clone(),
                    RelationType::PrivilegedAccess,
                    account.clone(),
                    0.97,
                ));
            }
            if let (Some(account), Some(server)) = (target.as_ref(), host.as_ref()) {
                out.push(edge(
                    account.clone(),
                    RelationType::PrivilegedAccess,
                    server.clone(),
                    0.92,
                ));
            }
        }

        "database_query" => {
            if let (Some(account), Some(instance)) = (principal.as_ref(), target.as_ref()) {
                out.push(edge(
                    account.clone(),
                    RelationType::Accesses,
                    instance.clone(),
                    0.96,
                ));
            }
            if let (Some(server), Some(instance)) = (host.as_ref(), target.as_ref()) {
                out.push(edge(
                    server.clone(),
                    RelationType::Owns,
                    instance.clone(),
                    1.0,
                ));
            }
        }

        "file_create" => {
            let archive = event
                .attributes
                .get("is_archive")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let relation = if archive {
                RelationType::Stages
            } else {
                RelationType::Creates
            };
            if let (Some(actor), Some(file)) = (principal.as_ref(), target.as_ref()) {
                out.push(edge(actor.clone(), relation, file.clone(), 0.94));
            }
            if let (Some(machine), Some(file)) = (host.as_ref(), target.as_ref()) {
                out.push(edge(machine.clone(), RelationType::Creates, file.clone(), 0.9));
            }
        }

        "dns_query" => {
            if let (Some(client), Some(name)) = (src.as_ref(), domain.as_ref()) {
                out.push(edge(
                    client.clone(),
                    RelationType::ResolvesTo,
                    name.clone(),
                    0.88,
                ));
            }
        }

        _ => {}
    }

    // Relationships that hold regardless of what the event was about.
    if let (Some(user), Some(machine)) = (principal.as_ref(), host.as_ref())
        && event.activity != "remote_logon"
        && event.activity != "pam_session_checkout"
        && event.activity != "database_query"
    {
        out.push(edge(
            user.clone(),
            RelationType::Uses,
            machine.clone(),
            0.98,
        ));
    }

    if let (Some(machine), Some(process)) = (host.as_ref(), event.process_name()) {
        out.push(edge(
            machine.clone(),
            RelationType::Executes,
            EntityRef::process(process),
            0.96,
        ));
    }

    // Outbound conversations, from whichever end we can identify.
    if event.activity == "connection_allowed" || event.activity == "connection_denied" {
        if let (Some(source), Some(destination)) = (src.as_ref(), dst.as_ref()) {
            out.push(edge(
                source.clone(),
                RelationType::ConnectsTo,
                destination.clone(),
                0.92,
            ));
        }
        if let (Some(destination), Some(name)) = (dst.as_ref(), domain.as_ref()) {
            out.push(edge(
                name.clone(),
                RelationType::ResolvesTo,
                destination.clone(),
                0.85,
            ));
        }
    }

    out
}
