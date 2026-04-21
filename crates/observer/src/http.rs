//! Internal HTTP endpoint for the verification task to read observer
//! chain state. Runs on `:2026`. Access-controlled via a shared secret
//! (`read_secret` in `ObserverConfig`) that only the proxy VM and any
//! out-of-band control plane should hold. The endpoint is NOT exposed
//! to the public internet — operators must restrict inbound to the
//! proxy VM (e.g. GCE service-account tag, AWS security group, etc.).
//!
//! Endpoints:
//!
//!   - `GET /health`                              — liveness
//!   - `GET /observer/chain/{chain_id}/head`      — current head hash.
//!                                                  Liveness + reachability
//!                                                  probe for `/health/
//!                                                  detailed`; NOT used
//!                                                  as a verification
//!                                                  check — the two
//!                                                  chains have
//!                                                  independent lineage
//!                                                  so byte-equality
//!                                                  of heads isn't
//!                                                  meaningful per §5.5.
//!   - `GET /observer/chain/{chain_id}/entries`   — paged entries. This
//!                                                  is the read path
//!                                                  the verification
//!                                                  task uses to fold
//!                                                  the observer's
//!                                                  unverified window
//!                                                  into the §5.5
//!                                                  running-hash
//!                                                  comparison against
//!                                                  the proxy's
//!                                                  projected
//!                                                  DeploymentEvent
//!                                                  payloads.
//!
//! The verification task in `server/crates/verification/src/task.rs`
//! calls these endpoints on every scheduled run (periodic 4h timer
//! and on every admin-session-end).

use crate::chain::ObserverChain;
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use chain_store::ChainEntry;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{info, warn};

pub struct HttpState {
    pub chain: Arc<ObserverChain>,
    pub read_secret: String,
}

pub fn router(state: Arc<HttpState>) -> Router {
    // Axum 0.8 requires `{capture}` path syntax; `:capture` panics at
    // router build time.
    Router::new()
        .route("/health", get(health))
        .route("/observer/chain/{chain_id}/head", get(head))
        .route("/observer/chain/{chain_id}/entries", get(entries))
        .with_state(state)
}

async fn health() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok", "component": "observer" }))
}

#[derive(Debug, Serialize)]
struct HeadResponse {
    chain_id: String,
    head_hash: Option<String>,
}

async fn head(
    State(state): State<Arc<HttpState>>,
    Path(chain_id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if !check_auth(&headers, &state.read_secret) {
        warn!(chain_id = chain_id.as_str(), "observer head read rejected — bad auth");
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "unauthorized" })),
        )
            .into_response();
    }

    match state.chain.read_head(&chain_id).await {
        Ok(opt) => {
            let resp = HeadResponse {
                chain_id: chain_id.clone(),
                head_hash: opt.map(hex::encode),
            };
            (StatusCode::OK, Json(serde_json::to_value(resp).unwrap())).into_response()
        }
        Err(e) => {
            warn!(chain_id = chain_id.as_str(), error = %e, "observer head read failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": format!("{e}") })),
            )
                .into_response()
        }
    }
}

/// Query params for `/entries`. `cursor` is the starting entry index
/// (0-based); `limit` bounds the page size. The defaults let the
/// verification task call `/entries` with no query string for an
/// initial small-page fetch during a fresh run.
#[derive(Debug, Deserialize)]
struct EntriesQuery {
    #[serde(default)]
    cursor: Option<u64>,
    #[serde(default = "default_limit")]
    limit: usize,
}

fn default_limit() -> usize {
    100
}

/// Response shape matches the proxy's chain-API `EntriesResponse`
/// (`crates/proxy/src/chain_api/mod.rs`) so verification code and any
/// future client can treat the two surfaces symmetrically.
#[derive(Debug, Serialize)]
struct EntriesResponse {
    chain_id: String,
    entries: Vec<ChainEntry>,
    /// Next cursor — opaque u64 offset. `None` when the caller has
    /// reached the tail of the chain.
    next_cursor: Option<u64>,
    /// Head hash (hex) for the entries returned. The verification
    /// task uses this to detect chain-growth races (observer committed
    /// new entries between `/head` and `/entries` calls).
    head_hash: String,
    /// Total entry count reported by meta.json. Matches spec §7.1.1
    /// `total_entries`; callers check for truncation attacks by
    /// comparing to the count from the previous run.
    total_entries: u64,
}

async fn entries(
    State(state): State<Arc<HttpState>>,
    Path(chain_id): Path<String>,
    Query(q): Query<EntriesQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if !check_auth(&headers, &state.read_secret) {
        warn!(chain_id = chain_id.as_str(), "observer entries read rejected — bad auth");
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "unauthorized" })),
        )
            .into_response();
    }
    // Bound the page size to match the proxy's chain API. Prevents a
    // caller from asking for 10M entries in a single response.
    if q.limit == 0 || q.limit > 500 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "limit must be 1..=500" })),
        )
            .into_response();
    }

    let start = q.cursor.unwrap_or(0);

    let total = match state.chain.entry_count(&chain_id).await {
        Ok(n) => n,
        Err(e) => {
            warn!(chain_id = chain_id.as_str(), error = %e, "observer entry_count failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": format!("{e}") })),
            )
                .into_response();
        }
    };

    let page = match state.chain.read_entries(&chain_id, start, q.limit).await {
        Ok(v) => v,
        Err(e) => {
            warn!(chain_id = chain_id.as_str(), error = %e, "observer entries read failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": format!("{e}") })),
            )
                .into_response();
        }
    };

    let returned = page.len() as u64;
    let next_cursor = if start + returned < total {
        Some(start + returned)
    } else {
        None
    };

    let head_hash = match state.chain.read_head(&chain_id).await {
        Ok(opt) => opt.map(hex::encode).unwrap_or_default(),
        Err(_) => String::new(),
    };

    let resp = EntriesResponse {
        chain_id,
        entries: page,
        next_cursor,
        head_hash,
        total_entries: total,
    };
    (StatusCode::OK, Json(serde_json::to_value(resp).unwrap())).into_response()
}

fn check_auth(headers: &HeaderMap, expected: &str) -> bool {
    let Some(value) = headers.get("x-uninc-read-secret") else {
        return false;
    };
    let Ok(value_str) = value.to_str() else {
        return false;
    };
    // Constant-time comparison. The shared secret is 32+ bytes so a
    // byte-by-byte compare is practically fine, but doing it this way
    // keeps the habit.
    constant_time_eq(value_str.as_bytes(), expected.as_bytes())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

pub async fn serve(state: Arc<HttpState>, port: u16) -> anyhow::Result<()> {
    let app = router(state);
    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], port));
    info!(port, "observer http endpoint listening");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode as HttpStatus};
    use tempfile::TempDir;
    use tower::ServiceExt;
    use uninc_common::ActionType;

    /// Build a fresh ObserverChain on a tempdir + its HTTP router
    /// wrapped in an axum `Router` ready for `oneshot`.
    async fn fixture(
        entries: usize,
    ) -> (Arc<HttpState>, axum::Router, TempDir) {
        let tmp = TempDir::new().unwrap();
        let chain = Arc::new(ObserverChain::new(tmp.path(), "test-salt"));
        // Seed N entries into the `_deployment` chain so pagination
        // has something to page over.
        for i in 0..entries {
            chain
                .append(
                    "_deployment",
                    format!("actor-{i}"),
                    ActionType::Write,
                    format!("resource-{i}"),
                    format!("scope-{i}"),
                    [i as u8; 32],
                    None,
                )
                .await
                .unwrap();
        }
        let state = Arc::new(HttpState {
            chain,
            read_secret: "shared-secret".to_string(),
        });
        let app = router(Arc::clone(&state));
        (state, app, tmp)
    }

    #[tokio::test]
    async fn entries_requires_auth() {
        let (_state, app, _tmp) = fixture(3).await;
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/observer/chain/_deployment/entries")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), HttpStatus::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn entries_returns_all_when_within_limit() {
        let (_state, app, _tmp) = fixture(3).await;
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/observer/chain/_deployment/entries?limit=100")
                    .header("x-uninc-read-secret", "shared-secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), HttpStatus::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["entries"].as_array().unwrap().len(), 3);
        assert_eq!(json["total_entries"].as_u64().unwrap(), 3);
        assert!(json["next_cursor"].is_null(), "no more pages expected");
        assert!(json["head_hash"].as_str().unwrap().len() >= 64);
    }

    #[tokio::test]
    async fn entries_pages_correctly() {
        let (_state, app, _tmp) = fixture(5).await;
        // First page: limit=2 returns entries 0..2 with next_cursor=2.
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/observer/chain/_deployment/entries?limit=2")
                    .header("x-uninc-read-secret", "shared-secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), HttpStatus::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["entries"].as_array().unwrap().len(), 2);
        assert_eq!(json["next_cursor"].as_u64().unwrap(), 2);
        // Second page: cursor=2, limit=2 returns entries 2..4 with next_cursor=4.
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/observer/chain/_deployment/entries?cursor=2&limit=2")
                    .header("x-uninc-read-secret", "shared-secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["entries"].as_array().unwrap().len(), 2);
        assert_eq!(json["next_cursor"].as_u64().unwrap(), 4);
        // Third page: cursor=4, limit=2 returns entry 4 with next_cursor=null.
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/observer/chain/_deployment/entries?cursor=4&limit=2")
                    .header("x-uninc-read-secret", "shared-secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["entries"].as_array().unwrap().len(), 1);
        assert!(json["next_cursor"].is_null());
    }

    #[tokio::test]
    async fn entries_rejects_zero_and_oversized_limit() {
        let (_state, app, _tmp) = fixture(1).await;
        for bad in ["limit=0", "limit=501", "limit=10000"] {
            let resp = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(format!("/observer/chain/_deployment/entries?{bad}"))
                        .header("x-uninc-read-secret", "shared-secret")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                resp.status(),
                HttpStatus::BAD_REQUEST,
                "limit={bad} should be rejected"
            );
        }
    }

    #[tokio::test]
    async fn entries_for_nonexistent_chain_returns_empty() {
        let (_state, app, _tmp) = fixture(0).await;
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/observer/chain/nonexistent_chain_id/entries?limit=10")
                    .header("x-uninc-read-secret", "shared-secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), HttpStatus::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["entries"].as_array().unwrap().len(), 0);
        assert_eq!(json["total_entries"].as_u64().unwrap(), 0);
        assert!(json["next_cursor"].is_null());
    }
}
