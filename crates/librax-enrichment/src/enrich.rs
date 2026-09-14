use std::sync::Arc;

use librax_types::{CanonicalEvent, Enrichment, ThreatReputation};

use crate::inventory::{Inventory, demo};

/// Known-bad indicators for the demo. In enterprise mode this is where a real
/// threat-intel feed would plug in; the local demo must not need one.
const MALICIOUS_IPS: &[&str] = &[demo::ATTACKER_IP, "91.219.236.18", "45.133.1.90"];
const MALICIOUS_DOMAINS: &[&str] = &[demo::C2_DOMAIN, demo::PHISHING_DOMAIN];

/// Attaches identity, asset and reputation context to canonical events.
///
/// Enrichment never invents entities: if an asset or identity is unknown, the
/// fields stay empty and downstream scoring treats the gap as uncertainty.
pub struct Enricher {
    inventory: Arc<Inventory>,
}

impl Enricher {
    pub fn new(inventory: Inventory) -> Self {
        Self::shared(Arc::new(inventory))
    }

    /// Shares one inventory with other components, such as the simulator, rather
    /// than duplicating ten thousand assets per consumer.
    pub fn shared(inventory: Arc<Inventory>) -> Self {
        Self { inventory }
    }

    pub fn inventory(&self) -> &Inventory {
        &self.inventory
    }

    pub fn inventory_handle(&self) -> Arc<Inventory> {
        Arc::clone(&self.inventory)
    }

    pub fn enrich(&self, event: &mut CanonicalEvent) {
        let mut enrichment = Enrichment::default();

        // Identity context.
        if let Some(user) = event.user()
            && let Some(identity) = self.inventory.identity_by_name(user)
        {
            enrichment.department = Some(identity.department.clone());
            enrichment.hospital = Some(identity.hospital.clone());
            enrichment.privileged_account = identity.privileged;
            enrichment.service_account = identity.service_account;
        }

        // Asset context, preferring the host and falling back to the target.
        let asset = event
            .host_name()
            .and_then(|h| self.inventory.asset_by_name(h))
            .or_else(|| {
                event
                    .target_name()
                    .and_then(|t| self.inventory.asset_by_name(t))
            })
            .or_else(|| event.src_ip().and_then(|ip| self.inventory.asset_by_ip(ip)));

        if let Some(asset) = asset {
            enrichment.asset_role = Some(asset.role.label().to_string());
            enrichment.asset_criticality = Some(asset.criticality);
            enrichment.data_sensitivity = Some(asset.data_sensitivity);
            enrichment.hospital = Some(asset.hospital.clone());
        }

        enrichment.source_reputation = reputation(event.src_ip(), None);
        enrichment.destination_reputation = reputation(
            event.dst_ip(),
            event.destination.as_ref().and_then(|d| d.domain.as_deref()),
        );

        // Preserve a maintenance flag the source may have declared.
        enrichment.maintenance_window = event
            .attributes
            .get("maintenance_window")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        event.enrichment = enrichment;
    }

    pub fn enrich_all(&self, events: &mut [CanonicalEvent]) {
        for event in events {
            self.enrich(event);
        }
    }
}

fn reputation(ip: Option<&str>, domain: Option<&str>) -> ThreatReputation {
    if ip.is_some_and(|v| MALICIOUS_IPS.contains(&v))
        || domain.is_some_and(|d| MALICIOUS_DOMAINS.iter().any(|m| d.ends_with(m)))
    {
        return ThreatReputation::Malicious;
    }
    // Private ranges are treated as internal-clean; anything else is unproven.
    match ip {
        Some(v) if v.starts_with("10.") || v.starts_with("192.168.") => ThreatReputation::Clean,
        Some(_) => ThreatReputation::Suspicious,
        None => ThreatReputation::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use librax_types::{
        CanonicalEvent, EntityRef, EventCategory, NetworkEndpoint, Severity, SourceType,
    };

    use super::*;
    use crate::inventory::InventorySpec;

    fn event() -> CanonicalEvent {
        CanonicalEvent {
            event_id: "EVT-1".into(),
            timestamp: Utc::now(),
            source_type: SourceType::Edr,
            source_id: "edr-1".into(),
            category: EventCategory::Process,
            activity: "process_created".into(),
            principal: Some(EntityRef::user(demo::USER)),
            source: Some(NetworkEndpoint::from_ip(demo::ENDPOINT_IP)),
            destination: Some(NetworkEndpoint::from_ip(demo::ATTACKER_IP)),
            host: Some(EntityRef::host(demo::ENDPOINT)),
            process: None,
            target: None,
            severity: Severity::Medium,
            raw_reference: None,
            message: String::new(),
            attributes: Default::default(),
            enrichment: Enrichment::default(),
        }
    }

    fn enricher() -> Enricher {
        Enricher::new(Inventory::generate(InventorySpec::default()))
    }

    #[test]
    fn resolves_identity_and_asset_context() {
        let mut e = event();
        enricher().enrich(&mut e);

        assert_eq!(
            e.enrichment.department.as_deref(),
            Some(demo::USER_DEPARTMENT)
        );
        assert_eq!(e.enrichment.hospital.as_deref(), Some(demo::HOSPITAL));
        assert!(e.enrichment.asset_criticality.is_some());
    }

    #[test]
    fn flags_known_bad_destination() {
        let mut e = event();
        enricher().enrich(&mut e);

        assert_eq!(e.enrichment.source_reputation, ThreatReputation::Clean);
        assert_eq!(
            e.enrichment.destination_reputation,
            ThreatReputation::Malicious
        );
    }

    #[test]
    fn unknown_user_is_left_empty_not_invented() {
        let mut e = event();
        e.principal = Some(EntityRef::user("does.not.exist"));
        enricher().enrich(&mut e);

        assert!(e.enrichment.department.is_none());
        assert!(!e.enrichment.privileged_account);
    }
}
