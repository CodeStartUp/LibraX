use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

/// A single error shape for the whole API, so the frontend never has to guess.
#[derive(Debug)]
pub enum ApiError {
    NotFound(String),
    BadRequest(String),
    /// A destructive action was requested without an approver.
    ApprovalRequired(String),
    Conflict(String),
}

#[derive(Serialize)]
struct ErrorBody {
    error: &'static str,
    message: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, error, message) = match self {
            ApiError::NotFound(message) => (StatusCode::NOT_FOUND, "not_found", message),
            ApiError::BadRequest(message) => (StatusCode::BAD_REQUEST, "bad_request", message),
            ApiError::ApprovalRequired(message) => {
                (StatusCode::FORBIDDEN, "approval_required", message)
            }
            ApiError::Conflict(message) => (StatusCode::CONFLICT, "conflict", message),
        };

        (status, Json(ErrorBody { error, message })).into_response()
    }
}

pub type ApiResult<T> = Result<T, ApiError>;
