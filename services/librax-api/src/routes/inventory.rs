use axum::Json;
use axum::extract::{Query, State};
use serde::{Deserialize, Serialize};

use crate::state::SharedState;

#[derive(Debug, Deserialize)]
pub struct AssetQuery {
    pub hospital: Option<String>,
    /// Only assets at or above this criticality.
    pub min_criticality: Option<u8>,
    pub limit: Option<usize>,
}

#[derive(Serialize)]
pub struct AssetView {
    pub entity_id: String,
    pub name: String,
    pub kind: String,
    pub role: String,
    pub hospital: String,
    pub ip: String,
    pub criticality: u8,
    /// Drives the regulated-data contribution to business impact.
    pub data_sensitivity: u8,
    pub edr_covered: bool,
}

#[derive(Serialize)]
pub struct AssetsResponse {
    pub total: usize,
    pub returned: usize,
    pub assets: Vec<AssetView>,
}

/// The asset inventory, most critical first.
pub async fn assets(
    State(state): State<SharedState>,
    Query(query): Query<AssetQuery>,
) -> Json<AssetsResponse> {
    let inventory = state.inventory();
    let limit = query.limit.unwrap_or(100).min(1_000);
    let floor = query.min_criticality.unwrap_or(0);

    let mut matching: Vec<&librax_enrichment::Asset> = inventory
        .assets
        .iter()
        .filter(|asset| asset.criticality >= floor)
        .filter(|asset| {
            query
                .hospital
                .as_ref()
                .is_none_or(|h| asset.hospital.eq_ignore_ascii_case(h))
        })
        .collect();

    matching.sort_by(|a, b| {
        b.criticality
            .cmp(&a.criticality)
            .then_with(|| a.entity.name.cmp(&b.entity.name))
    });

    let total = matching.len();
    let assets: Vec<AssetView> = matching
        .into_iter()
        .take(limit)
        .map(|asset| AssetView {
            entity_id: asset.entity.id.clone(),
            name: asset.entity.name.clone(),
            kind: asset.entity.kind.label().to_string(),
            role: asset.role.label().to_string(),
            hospital: asset.hospital.clone(),
            ip: asset.ip.clone(),
            criticality: asset.criticality,
            data_sensitivity: asset.data_sensitivity,
            edr_covered: asset.edr_covered,
        })
        .collect();

    Json(AssetsResponse {
        total,
        returned: assets.len(),
        assets,
    })
}

#[derive(Debug, Deserialize)]
pub struct IdentityQuery {
    pub privileged_only: Option<bool>,
    pub limit: Option<usize>,
}

#[derive(Serialize)]
pub struct IdentityView {
    pub entity_id: String,
    pub name: String,
    pub department: String,
    pub hospital: String,
    pub privileged: bool,
    pub service_account: bool,
}

#[derive(Serialize)]
pub struct IdentitiesResponse {
    pub total: usize,
    pub returned: usize,
    pub identities: Vec<IdentityView>,
}

pub async fn identities(
    State(state): State<SharedState>,
    Query(query): Query<IdentityQuery>,
) -> Json<IdentitiesResponse> {
    let inventory = state.inventory();
    let limit = query.limit.unwrap_or(100).min(1_000);
    let privileged_only = query.privileged_only.unwrap_or(false);

    let matching: Vec<&librax_enrichment::Identity> = inventory
        .identities
        .iter()
        .filter(|identity| !privileged_only || identity.privileged)
        .collect();

    let total = matching.len();
    let identities: Vec<IdentityView> = matching
        .into_iter()
        .take(limit)
        .map(|identity| IdentityView {
            entity_id: identity.entity.id.clone(),
            name: identity.entity.name.clone(),
            department: identity.department.clone(),
            hospital: identity.hospital.clone(),
            privileged: identity.privileged,
            service_account: identity.service_account,
        })
        .collect();

    Json(IdentitiesResponse {
        total,
        returned: identities.len(),
        identities,
    })
}

#[derive(Serialize)]
pub struct HospitalView {
    pub id: String,
    pub name: String,
    pub region: String,
    pub asset_count: usize,
    pub endpoint_count: usize,
    pub critical_asset_count: usize,
}

#[derive(Serialize)]
pub struct HospitalsResponse {
    pub total: usize,
    pub endpoints: usize,
    pub servers: usize,
    pub hospitals: Vec<HospitalView>,
}

pub async fn hospitals(State(state): State<SharedState>) -> Json<HospitalsResponse> {
    let inventory = state.inventory();

    Json(HospitalsResponse {
        total: inventory.hospitals.len(),
        endpoints: inventory.endpoint_count(),
        servers: inventory.server_count(),
        hospitals: inventory
            .hospitals
            .iter()
            .map(|hospital| {
                // Assets record the hospital by name, not by id.
                let at_site = || {
                    inventory
                        .assets
                        .iter()
                        .filter(|a| a.hospital == hospital.name)
                };

                HospitalView {
                    id: hospital.id.clone(),
                    name: hospital.name.clone(),
                    region: hospital.region.clone(),
                    asset_count: at_site().count(),
                    endpoint_count: at_site()
                        .filter(|a| a.entity.kind == librax_types::EntityKind::Host)
                        .count(),
                    critical_asset_count: at_site().filter(|a| a.criticality >= 80).count(),
                }
            })
            .collect(),
    })
}
