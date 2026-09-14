use axum::Router;
use axum::routing::{get, post};
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;

use crate::state::SharedState;

pub mod attacks;
pub mod dashboard;
pub mod events;
pub mod incidents;
pub mod intel;
pub mod inventory;
pub mod sources;

pub fn router(state: SharedState) -> Router {
    // The frontend is served from a different origin in development, so CORS is
    // permissive by default and narrowed by configuration in deployment.
    let cors = if state.config.cors_allow_origin == "*" {
        CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(Any)
            .allow_headers(Any)
    } else {
        CorsLayer::new()
            .allow_origin(
                state
                    .config
                    .cors_allow_origin
                    .parse::<axum::http::HeaderValue>()
                    .expect("LIBRAX_CORS_ALLOW_ORIGIN must be a valid origin"),
            )
            .allow_methods(Any)
            .allow_headers(Any)
    };

    Router::new()
        .route("/api/v1/health", get(dashboard::health))
        .route("/api/v1/dashboard", get(dashboard::dashboard))
        .route("/api/v1/events", post(events::ingest))
        .route("/api/v1/signals", get(events::signals))
        .route("/api/v1/events/search", get(events::search))
        .route("/api/v1/attacks", get(attacks::catalog))
        .route("/api/v1/attacks/launch", post(attacks::launch))
        .route("/api/v1/attacks/runs", get(attacks::runs))
        .route("/api/v1/reset", post(attacks::reset))
        .route("/api/v1/intel/indicators", get(intel::feed))
        .route("/api/v1/intel/lookup", get(intel::lookup))
        .route("/api/v1/intel/lookup/{value}", get(intel::lookup_path))
        .route("/api/v1/files", get(intel::files))
        .route("/api/v1/incidents", get(incidents::list))
        .route("/api/v1/incidents/{id}", get(incidents::detail))
        .route("/api/v1/incidents/{id}/timeline", get(incidents::timeline))
        .route("/api/v1/incidents/{id}/graph", get(incidents::graph))
        .route("/api/v1/incidents/{id}/mitre", get(incidents::mitre))
        .route("/api/v1/incidents/{id}/risk", get(incidents::risk))
        .route(
            "/api/v1/incidents/{id}/blast-radius",
            get(incidents::blast_radius),
        )
        .route("/api/v1/incidents/{id}/evidence", get(incidents::evidence))
        .route("/api/v1/incidents/{id}/ai", get(incidents::briefing))
        .route("/api/v1/incidents/{id}/response", get(incidents::responses))
        .route(
            "/api/v1/incidents/{id}/response/simulate",
            post(incidents::simulate),
        )
        .route("/api/v1/assets", get(inventory::assets))
        .route("/api/v1/identities", get(inventory::identities))
        .route("/api/v1/hospitals", get(inventory::hospitals))
        .route("/api/v1/sources/health", get(sources::health))
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
