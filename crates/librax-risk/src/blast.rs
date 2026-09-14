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

    let is_user =
        |a: &AffectedAsset| matches!(a.entity.kind, EntityKind::User | EntityKind::Account);
    let is_endpoint = |a: &AffectedAsset| role_of(&a.entity) == Some(AssetRole::Workstation);
    let is_server = |a: &AffectedAsset| {
        matches!(
            role_of(&a.entity),
            Some(
                AssetRole::Server
                    | AssetRole::DomainController
                    | AssetRole::CloudWorkload
                    | AssetRole::Firewall
            )
        )
    };
    let is_critical_db =
        |a: &AffectedAsset| role_of(&a.entity) == Some(AssetRole::Database) && a.criticality >= 90;
    let is_pacs = |a: &AffectedAsset| role_of(&a.entity) == Some(AssetRole::Pacs);

    let count = |f: &dyn Fn(&AffectedAsset) -> bool| assets.iter().filter(|a| f(a)).count() as u32;
    let count_confirmed = |f: &dyn Fn(&AffectedAsset) -> bool| {
        assets
            .iter()
            .filter(|a| a.exposure == Exposure::Confirmed && f(a))
            .count() as u32
    };

    let users = count(&is_user);
    let endpoints = count(&is_endpoint);
    let servers = count(&is_server);
    let critical_databases = count(&is_critical_db);
    let pacs_systems = count(&is_pacs);

    let potentially_reachable = assets
        .iter()
        .filter(|a| a.exposure != Exposure::Confirmed)
        .count() as u32;

    // The severity of the blast radius is driven by what is actually compromised.
    // Counting merely-reachable assets here would let campus co-location alone
    // report a critical blast radius for an incident that breached nothing.
    let confirmed = ConfirmedCounts {
        users: count_confirmed(&is_user),
        endpoints: count_confirmed(&is_endpoint),
        servers: count_confirmed(&is_server),
        critical_databases: count_confirmed(&is_critical_db),
        pacs_systems: count_confirmed(&is_pacs),
    };
    let high_value_reachable = assets
        .iter()
        .filter(|a| {
            a.exposure != Exposure::Confirmed && a.criticality >= POTENTIAL_CRITICALITY_FLOOR
        })
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
        level: level(&confirmed, high_value_reachable),
        assets,
    }
}

/// Counts restricted to assets the evidence places inside the intrusion.
struct ConfirmedCounts {
    users: u32,
    endpoints: u32,
    servers: u32,
    critical_databases: u32,
    pacs_systems: u32,
}

fn level(confirmed: &ConfirmedCounts, high_value_reachable: u32) -> Severity {
    let base = if confirmed.critical_databases >= 1
        && (confirmed.pacs_systems >= 1 || confirmed.servers >= 2)
    {
        Severity::Critical
    } else if confirmed.critical_databases >= 1 || confirmed.servers >= 3 {
        Severity::High
    } else if confirmed.servers >= 1 || confirmed.endpoints >= 3 {
        Severity::Medium
    } else if confirmed.endpoints >= 1 || confirmed.users >= 1 {
        Severity::Low
    } else {
        Severity::Info
    };

    // High-value neighbours raise the floor to Medium, and no further. They are
    // adjacent, not breached, and campus co-location is weak evidence of reach.
    if high_value_reachable >= 2 && base < Severity::Medium {
        Severity::Medium
    } else {
        base
    }
}

#[cfg(test)]
mod level_tests {
    use super::*;

    fn counts() -> ConfirmedCounts {
        ConfirmedCounts {
            users: 0,
            endpoints: 0,
            servers: 0,
            critical_databases: 0,
            pacs_systems: 0,
        }
    }

    #[test]
    fn a_breached_patient_database_beside_other_servers_is_critical() {
        let confirmed = ConfirmedCounts {
            critical_databases: 1,
            servers: 2,
            ..counts()
        };
        assert_eq!(level(&confirmed, 4), Severity::Critical);
    }

    #[test]
    fn reachable_neighbours_alone_never_reach_critical() {
        // A gateway flood: one server confirmed, high-value assets merely nearby.
        let confirmed = ConfirmedCounts {
            servers: 1,
            ..counts()
        };
        assert_eq!(level(&confirmed, 8), Severity::Medium);
    }

    #[test]
    fn nothing_confirmed_and_nothing_nearby_is_info() {
        assert_eq!(level(&counts(), 0), Severity::Info);
    }

    #[test]
    fn high_value_neighbours_lift_a_bare_incident_to_medium() {
        let confirmed = ConfirmedCounts {
            users: 1,
            ..counts()
        };
        assert_eq!(level(&confirmed, 0), Severity::Low);
        assert_eq!(level(&confirmed, 3), Severity::Medium);
    }
}
