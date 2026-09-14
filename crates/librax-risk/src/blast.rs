use std::collections::HashSet;

use librax_enrichment::{AssetRole, Inventory};
use librax_graph::AttackGraph;
use librax_types::{AffectedAsset, BlastRadius, EntityKind, EntityRef, Exposure, Severity};

/// Assets beyond the incident graph that we are willing to call *potentially*
/// reachable. Kept small so the panel stays useful rather than alarming.
const MAX_POTENTIAL_ASSETS: usize = 12;
/// Only high-value neighbours are worth surfacing as potential exposure.
const POTENTIAL_CRITICALITY_FLOOR: u8 = 80;

/// Walks the graph outward from the confirmed nodes, then considers high-value
/// neighbours on the same campus.
///
/// The three exposure levels are kept strictly apart. A reachable database is
/// not a breached database, and this function never promotes one to the other.
pub fn assess_blast_radius(
    graph: &AttackGraph,
    inventory: &Inventory,
    max_hops: usize,
) -> BlastRadius {
    let confirmed_ids = graph.confirmed_node_ids();
    let reach = graph.reach_from(&confirmed_ids, max_hops);

    let mut assets: Vec<AffectedAsset> = Vec::new();
    let mut accounted: HashSet<String> = HashSet::new();

    for hop in &reach {
        let Some(node) = graph.node(&hop.node_id) else {
            continue;
        };

        // Processes, files and bare domains are evidence, not assets to count.
        if matches!(
            node.kind,
            EntityKind::Process | EntityKind::File | EntityKind::Domain | EntityKind::Session
        ) {
            continue;
        }

        accounted.insert(node.id.clone());
        assets.push(AffectedAsset {
            entity: node.entity(),
            exposure: hop.exposure,
            criticality: node.criticality.unwrap_or(0),
            hospital: node.hospital.clone(),
            reason: match hop.exposure {
                Exposure::Confirmed => {
                    "named directly by a detection with supporting evidence".to_string()
                }
                Exposure::Reachable => format!(
                    "one relationship away from a confirmed entity ({} hop)",
                    hop.hops
                ),
                Exposure::Potential => format!(
                    "{} relationships from the nearest confirmed entity",
                    hop.hops
                ),
            },
        });
    }

    // High-value neighbours sharing a campus with something confirmed. These are
    // inventory adjacency rather than observed activity, so they can never be
    // more than Potential.
    let compromised_campuses: HashSet<String> = assets
        .iter()
        .filter(|a| a.exposure == Exposure::Confirmed)
        .filter_map(|a| a.hospital.clone())
        .collect();

    let mut potential_added = 0;
    for asset in &inventory.assets {
        if potential_added >= MAX_POTENTIAL_ASSETS {
            break;
        }
        if asset.criticality < POTENTIAL_CRITICALITY_FLOOR
            || accounted.contains(&asset.entity.id)
            || !compromised_campuses.contains(&asset.hospital)
        {
            continue;
        }

        accounted.insert(asset.entity.id.clone());
        potential_added += 1;
        assets.push(AffectedAsset {
            entity: asset.entity.clone(),
            exposure: Exposure::Potential,
            criticality: asset.criticality,
            hospital: Some(asset.hospital.clone()),
            reason: format!(
                "criticality {} and shares {} with a confirmed asset; no activity observed on it",
                asset.criticality, asset.hospital
            ),
        });
    }

    let role_of = |entity: &EntityRef| -> Option<AssetRole> {
        inventory.asset_by_name(&entity.name).map(|a| a.role)
    };

    let users = assets
        .iter()
        .filter(|a| matches!(a.entity.kind, EntityKind::User | EntityKind::Account))
        .count() as u32;

    let endpoints = assets
        .iter()
        .filter(|a| role_of(&a.entity) == Some(AssetRole::Workstation))
        .count() as u32;

    let servers = assets
        .iter()
        .filter(|a| {
            matches!(
                role_of(&a.entity),
                Some(
                    AssetRole::Server
                        | AssetRole::DomainController
                        | AssetRole::CloudWorkload
                        | AssetRole::Firewall
                )
            )
        })
        .count() as u32;

    let critical_databases = assets
        .iter()
        .filter(|a| role_of(&a.entity) == Some(AssetRole::Database) && a.criticality >= 90)
        .count() as u32;

    let pacs_systems = assets
        .iter()
        .filter(|a| role_of(&a.entity) == Some(AssetRole::Pacs))
        .count() as u32;

    let potentially_reachable = assets
        .iter()
        .filter(|a| a.exposure != Exposure::Confirmed)
        .count() as u32;

    // Most severe first, so the panel leads with what matters.
    assets.sort_by(|a, b| {
        a.exposure
            .label()
            .cmp(b.exposure.label())
            .then_with(|| b.criticality.cmp(&a.criticality))
    });

    BlastRadius {
        users,
        endpoints,
        servers,
        critical_databases,
        pacs_systems,
        potentially_reachable,
        level: level(critical_databases, pacs_systems, servers, endpoints),
        assets,
    }
}

fn level(critical_databases: u32, pacs: u32, servers: u32, endpoints: u32) -> Severity {
    if critical_databases >= 1 && (pacs >= 1 || servers >= 2) {
        Severity::Critical
    } else if critical_databases >= 1 || servers >= 3 {
        Severity::High
    } else if servers >= 1 || endpoints >= 3 {
        Severity::Medium
    } else if endpoints >= 1 {
        Severity::Low
    } else {
        Severity::Info
    }
}
