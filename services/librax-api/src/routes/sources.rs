use axum::Json;
use axum::extract::State;
use librax_types::SourceHealth;
use serde::Serialize;

use crate::state::SharedState;

#[derive(Serialize)]
pub struct SourceHealthEntry {
    #[serde(flatten)]
    pub health: SourceHealth,
    pub status_label: String,
}

#[derive(Serialize)]
pub struct SourceHealthResponse {
    pub total: usize,
    /// True when every source in this build is simulator-backed, which it is.
    pub all_synthetic: bool,
    pub sources: Vec<SourceHealthEntry>,
}

/// Per-connector health, including blind spots.
pub async fn health(State(state): State<SharedState>) -> Json<SourceHealthResponse> {
    let (reporting, expected, _) = state.inventory().edr_coverage();

    Json(state.read(|soc| {
        let mut sources: Vec<SourceHealthEntry> = soc
            .source_health
            .values()
            .cloned()
            .map(|mut health| {
                // EDR is the one source with a real fleet-coverage gap in this
                // environment; the rest see everything they are meant to.
                if health.source_type == librax_types::SourceType::Edr {
                    health.assets_reporting = reporting;
                    health.assets_expected = expected;
                    health.coverage_percent = reporting as f32 / expected.max(1) as f32 * 100.0;
                }

                SourceHealthEntry {
                    status_label: health.status.label().to_string(),
                    health,
                }
            })
            .collect();

        sources.sort_by(|a, b| a.health.source_id.cmp(&b.health.source_id));

        SourceHealthResponse {
            total: sources.len(),
            all_synthetic: sources.iter().all(|s| s.health.synthetic),
            sources,
        }
    }))
}
