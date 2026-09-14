use std::collections::HashMap;

use chrono::{DateTime, Utc};
use librax_enrichment::{AssetRole, Inventory};
use librax_types::{
    CanonicalEvent, EntityKind, EntityRef, RelationType, Relationship, SecuritySignal,
};
use serde::Serialize;


#[derive(Debug, Clone, Serialize)]
pub struct ResolvedEntity {
    pub entity: EntityRef,

    pub aliases: Vec<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub event_count: u64,
    pub hospital: Option<String>,
    pub criticality: Option<u8>,
}


pub struct EntityResolver {

    aliases: HashMap<String, String>,
    entities: HashMap<String, ResolvedEntity>,

    ip_bindings: Vec<(String, EntityRef)>,


    by_asset_name: HashMap<String, EntityRef>,


    by_identity_name: HashMap<String, EntityRef>,
}

impl EntityResolver {


    pub fn from_inventory(inventory: &Inventory) -> Self {
        let mut resolver = Self {
            aliases: HashMap::new(),
            entities: HashMap::new(),
            ip_bindings: Vec::new(),
            by_asset_name: HashMap::new(),
            by_identity_name: HashMap::new(),
        };

        for identity in &inventory.identities {
            resolver
                .by_identity_name
                .insert(identity.entity.name.to_lowercase(), identity.entity.clone());
        }

        for asset in &inventory.assets {
            let canonical = asset.entity.id.clone();

            resolver
                .by_asset_name
                .insert(asset.entity.name.to_lowercase(), asset.entity.clone());


            if asset.role != AssetRole::Database {
                resolver
                    .aliases
                    .insert(format!("ip:{}", asset.ip), canonical.clone());
                resolver
                    .ip_bindings
                    .push((asset.ip.clone(), asset.entity.clone()));
            }

            resolver.aliases.insert(canonical.clone(), canonical);
        }

        resolver
    }


    pub fn resolve(&self, entity: &EntityRef) -> EntityRef {
        match entity.kind {
            EntityKind::User | EntityKind::Account => {
                return self
                    .by_identity_name
                    .get(&entity.name.to_lowercase())
                    .cloned()
                    .unwrap_or_else(|| entity.clone());
            }
            EntityKind::Host
            | EntityKind::Server
            | EntityKind::Database
            | EntityKind::Device
            | EntityKind::CloudResource
            | EntityKind::Application => {
                return self
                    .by_asset_name
                    .get(&entity.name.to_lowercase())
                    .cloned()
                    .unwrap_or_else(|| entity.clone());
            }
            EntityKind::Ip => {}
            _ => return entity.clone(),
        }

        match self.aliases.get(&entity.id) {
            Some(canonical_id) => self
                .entities
                .get(canonical_id)
                .map(|resolved| resolved.entity.clone())
                .or_else(|| {
                    self.ip_bindings
                        .iter()
                        .find(|(_, asset)| &asset.id == canonical_id)
                        .map(|(_, asset)| asset.clone())
                })
                .unwrap_or_else(|| entity.clone()),
            None => entity.clone(),
        }
    }

    pub fn resolve_all(&self, entities: &[EntityRef]) -> Vec<EntityRef> {
        let mut resolved: Vec<EntityRef> = entities.iter().map(|e| self.resolve(e)).collect();
        resolved.sort();
        resolved.dedup();
        resolved
    }


    pub fn observe(&mut self, events: &[CanonicalEvent]) {
        for event in events {
            let named = event.entities();
            for entity in &named {
                self.touch(entity, event);
            }


            if host_owns_source_address(event)
                && let (Some(host), Some(ip)) = (event.host.as_ref(), event.src_ip())
            {
                self.aliases.insert(format!("ip:{ip}"), host.id.clone());
                if let Some(resolved) = self.entities.get_mut(&host.id) {
                    let alias = format!("ip:{ip}");
                    if !resolved.aliases.contains(&alias) {
                        resolved.aliases.push(alias);
                    }
                }
            }
        }
    }

    fn touch(&mut self, entity: &EntityRef, event: &CanonicalEvent) {
        let record = self
            .entities
            .entry(entity.id.clone())
            .or_insert_with(|| ResolvedEntity {
                entity: entity.clone(),
                aliases: vec![entity.id.clone()],
                first_seen: event.timestamp,
                last_seen: event.timestamp,
                event_count: 0,
                hospital: None,
                criticality: None,
            });

        record.event_count += 1;
        record.first_seen = record.first_seen.min(event.timestamp);
        record.last_seen = record.last_seen.max(event.timestamp);

        if record.hospital.is_none() {
            record.hospital = event.enrichment.hospital.clone();
        }
        if record.criticality.is_none() {
            record.criticality = event.enrichment.asset_criticality;
        }
    }


    pub fn resolve_signal(&self, signal: &SecuritySignal) -> Vec<EntityRef> {
        self.resolve_all(&signal.entities)
    }

    pub fn known(&self, entity_id: &str) -> Option<&ResolvedEntity> {
        self.entities.get(entity_id)
    }

    pub fn len(&self) -> usize {
        self.entities.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entities.is_empty()
    }


    pub fn address_relationships(&self, at: DateTime<Utc>) -> Vec<Relationship> {
        self.entities
            .values()
            .flat_map(|record| {
                record
                    .aliases
                    .iter()
                    .filter(|alias| alias.starts_with("ip:"))
                    .map(|alias| {
                        let address = alias.trim_start_matches("ip:").to_string();
                        Relationship {
                            from: record.entity.clone(),
                            relation: RelationType::HasIp,
                            to: EntityRef::ip(address),
                            confidence: 1.0,
                            first_seen: record.first_seen,
                            last_seen: at,
                            evidence_event_ids: Vec::new(),
                        }
                    })
                    .collect::<Vec<_>>()
            })
            .collect()
    }
}


fn host_owns_source_address(event: &CanonicalEvent) -> bool {
    use librax_types::SourceType;

    if event.activity == "remote_logon"
        || event
            .attributes
            .get("source_is_workstation")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    {
        return false;
    }

    matches!(
        event.source_type,
        SourceType::ActiveDirectory | SourceType::EntraId | SourceType::Edr
    )
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use librax_connectors::synthetic::scenario;
    use librax_enrichment::{Enricher, InventorySpec, demo};
    use librax_normalizer::Normalizer;

    use super::*;

    fn inventory() -> Inventory {
        Inventory::generate(InventorySpec {
            seed: 42,
            hospitals: 18,
            endpoints: 2_000,
        })
    }

    fn chain_events() -> Vec<CanonicalEvent> {
        let enricher = Enricher::new(inventory());
        let mut normalizer = Normalizer::new();
        let mut outcome = normalizer.normalize_batch(&scenario::attack_chain(Utc::now()));
        enricher.enrich_all(&mut outcome.events);
        outcome.events
    }

    #[test]
    fn endpoint_address_resolves_to_its_host() {
        let resolver = EntityResolver::from_inventory(&inventory());
        let resolved = resolver.resolve(&EntityRef::ip(demo::ENDPOINT_IP));

        assert_eq!(resolved.kind, EntityKind::Host);
        assert!(resolved.name.eq_ignore_ascii_case(demo::ENDPOINT));
    }

    #[test]
    fn unknown_address_is_left_as_an_ip_not_guessed() {
        let resolver = EntityResolver::from_inventory(&inventory());
        let attacker = resolver.resolve(&EntityRef::ip(demo::ATTACKER_IP));

        assert_eq!(
            attacker.kind,
            EntityKind::Ip,
            "external infrastructure must not be bound to an internal asset"
        );
        assert_eq!(attacker.name, demo::ATTACKER_IP);
    }

    #[test]
    fn observing_the_chain_collapses_sources_onto_shared_entities() {
        let inventory = inventory();
        let mut resolver = EntityResolver::from_inventory(&inventory);
        let events = chain_events();
        resolver.observe(&events);


        let from_firewall = resolver.resolve(&EntityRef::ip(demo::ENDPOINT_IP));
        let from_edr = resolver.resolve(&EntityRef::host(demo::ENDPOINT));
        assert_eq!(from_firewall.id, from_edr.id);

        assert!(resolver.known(&EntityRef::user(demo::USER).id).is_some());
        assert!(resolver.len() > 5);
    }

    #[test]
    fn the_same_machine_named_by_two_sources_is_one_entity() {
        let resolver = EntityResolver::from_inventory(&inventory());


        let from_edr = resolver.resolve(&EntityRef::host(demo::DB_SERVER));
        let from_pam = resolver.resolve(&EntityRef::server(demo::DB_SERVER));
        assert_eq!(from_edr.id, from_pam.id);
    }

    #[test]
    fn the_same_identity_named_by_two_sources_is_one_entity() {
        let resolver = EntityResolver::from_inventory(&inventory());


        let from_directory = resolver.resolve(&EntityRef::user(demo::PRIVILEGED_ACCOUNT));
        let from_vault = resolver.resolve(&EntityRef::new(
            EntityKind::Account,
            demo::PRIVILEGED_ACCOUNT,
        ));
        assert_eq!(from_directory.id, from_vault.id);
        assert_eq!(from_directory.kind, EntityKind::Account);
    }

    #[test]
    fn resolution_deduplicates_mixed_references() {
        let inventory = inventory();
        let resolver = EntityResolver::from_inventory(&inventory);

        let mixed = vec![
            EntityRef::ip(demo::ENDPOINT_IP),
            EntityRef::host(demo::ENDPOINT),
            EntityRef::user(demo::USER),
        ];

        let resolved = resolver.resolve_all(&mixed);
        assert_eq!(
            resolved.len(),
            2,
            "address and hostname must collapse: {resolved:?}"
        );
    }
}
