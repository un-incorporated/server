//! Error envelope for `/api/v1/chain/*`.
//!
//! Every non-2xx response carries a `{ "error": { "code", "message" } }` body
//! so customer backends have a stable contract to parse.

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use chain_store::StorageError;
use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ApiError {
    #[error("unauthorized: {0}")]
    Unauthorized(String),

    #[error("forbidden: {0}")]
    Forbidden(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("internal: {0}")]
    Internal(String),

    /// Dependency temporarily unreachable (e.g., chain-engine unresponsive
    /// during an erasure tombstone write). 503 → safe to retry.
    #[error("unavailable: {0}")]
    Unavailable(String),
}

impl From<StorageError> for ApiError {
    fn from(e: StorageError) -> Self {
        match e {
            StorageError::ChainNotFound(h) => {
                ApiError::NotFound(format!("no chain for user hash {h}"))
            }
            other => ApiError::Internal(other.to_string()),
        }
    }
}

#[derive(Serialize)]
struct ErrorBody {
    error: ErrorDetail,
}

#[derive(Serialize)]
struct ErrorDetail {
    code: &'static str,
    message: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code) = match &self {
            ApiError::Unauthorized(_) => (StatusCode::UNAUTHORIZED, "unauthorized"),
            ApiError::Forbidden(_) => (StatusCode::FORBIDDEN, "forbidden"),
            ApiError::NotFound(_) => (StatusCode::NOT_FOUND, "not_found"),
            ApiError::BadRequest(_) => (StatusCode::BAD_REQUEST, "bad_request"),
            ApiError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal"),
            ApiError::Unavailable(_) => (StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
        };
        let body = ErrorBody {
            error: ErrorDetail {
                code,
                message: self.to_string(),
            },
        };
        (status, Json(body)).into_response()
    }
}
