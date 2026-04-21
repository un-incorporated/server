//! Client for the observer VM's read-only HTTP endpoint.
//!
//! The observer (`server/crates/observer/`) exposes
//! `GET /observer/chain/:chain_id/head` on `:2026` with the response
//! shape `{ "chain_id": "...", "head_hash": "<hex>|null }`. The
//! scheduled verification task fetches the observer's deployment-chain
//! head once per run and byte-compares it to the proxy's own head —
//! UAT §3.3 requires that any mismatch emit a `verification_failure`
//! DeploymentEvent on the deployment chain.
//!
//! This module provides the `ObserverHeadReader` trait and the
//! production HTTP implementation. The trait lets the scheduled task
//! swap in a stub for tests without spinning up an axum server.
//!
//! Error surface:
//! - `ObserverError::Unauthorized` — observer rejected the shared secret
//! - `ObserverError::Http(StatusCode)` — non-2xx response (incl. 404)
//! - `ObserverError::Timeout` — request exceeded the configured timeout
//! - `ObserverError::Transport(String)` — connection refused, DNS, etc.
//! - `ObserverError::InvalidResponse(String)` — 200 body didn't decode
//!
//! The scheduled task's retry policy distinguishes these: transient
//! errors (timeout / transport) are worth a single retry; 401 / invalid
//! response are not. See `task::run_scheduled_verification` for the
//! wiring.

use async_trait::async_trait;
use chain_store::ChainEntry;
use reqwest::StatusCode;
use serde::Deserialize;
use std::time::Duration;
use thiserror::Error;

/// Default HTTP timeout for the observer head-read call. Tight because
/// the endpoint serves a single 32-byte hash from local disk — if it
/// isn't responding within this window something is wrong and we want
/// to surface it, not wait.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Error)]
pub enum ObserverError {
    #[error("observer rejected auth (401)")]
    Unauthorized,

    #[error("observer returned non-success status {0}")]
    Http(StatusCode),

    #[error("observer request timed out")]
    Timeout,

    #[error("transport error: {0}")]
    Transport(String),

    #[error("invalid response: {0}")]
    InvalidResponse(String),
}

impl ObserverError {
    /// Whether the scheduled task's retry policy should try again on
    /// this error class. True for transient network / server failures,
    /// false for auth or invalid-response errors where retrying can't
    /// possibly change the outcome.
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Timeout | Self::Transport(_) => true,
            Self::Http(status) => status.is_server_error(),
            Self::Unauthorized | Self::InvalidResponse(_) => false,
        }
    }
}

#[async_trait]
pub trait ObserverHeadReader: Send + Sync {
    /// Fetch the observer's current head for `chain_id` (typically
    /// `"_deployment"`).
    ///
    /// Returns `Ok(None)` when the observer's chain is empty — matches
    /// the UAT §5.1 V7 convention that an empty chain's head is 32 zero
    /// octets. Callers that need the 32-byte form can translate
    /// `None` → `[0u8; 32]` at the comparison site.
    async fn read_head(&self, chain_id: &str) -> Result<Option<[u8; 32]>, ObserverError>;

    /// Fetch a paginated range of observer chain entries. Used by
    /// Process 2 of Scheduled Verification (UAT §5.5.2) to advance the
    /// `cursor_obs` cursor entry-by-entry. `cursor` is 0-based; `limit`
    /// bounds the page size (observer enforces 1..=500). `head_hash` is
    /// the observer's current head at read time, returned for drift
    /// detection across paginated requests.
    async fn read_entries(
        &self,
        chain_id: &str,
        cursor: u64,
        limit: usize,
    ) -> Result<EntriesPage, ObserverError>;
}

/// Paginated response from `read_entries`. Mirrors the observer's HTTP
/// `/entries` endpoint response shape so the verification loop can
/// iterate without re-defining JSON structure.
#[derive(Debug, Clone)]
pub struct EntriesPage {
    pub chain_id: String,
    pub entries: Vec<ChainEntry>,
    /// Next cursor — opaque u64 offset. `None` when the caller has
    /// reached the tail.
    pub next_cursor: Option<u64>,
    /// Current head hash at read time (hex). Empty string when the
    /// chain is empty.
    pub head_hash: String,
    /// Total entries reported by observer meta.json at read time.
    pub total_entries: u64,
}

/// Production implementation that talks to the observer VM over HTTP.
pub struct HttpObserverClient {
    base_url: String,
    read_secret: String,
    http: reqwest::Client,
}

impl HttpObserverClient {
    /// Build a new client. `base_url` should be the observer VM's
    /// external address without a trailing slash, e.g.
    /// `"http://10.0.3.5:2026"`. `read_secret` is the shared secret the
    /// observer expects in the `x-uninc-read-secret` header; it must
    /// match the observer's `ObserverConfig.read_secret` value.
    pub fn new(base_url: impl Into<String>, read_secret: impl Into<String>) -> Self {
        Self::with_timeout(base_url, read_secret, DEFAULT_TIMEOUT)
    }

    pub fn with_timeout(
        base_url: impl Into<String>,
        read_secret: impl Into<String>,
        timeout: Duration,
    ) -> Self {
        let http = reqwest::Client::builder()
            .timeout(timeout)
            // No connection pool reuse benefit — the scheduled task
            // fires once per run and makes a single request. Default
            // pool config is fine.
            .build()
            .expect("reqwest client builder never fails with these settings");
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            read_secret: read_secret.into(),
            http,
        }
    }
}

#[derive(Deserialize)]
struct HeadResponse {
    #[allow(dead_code)] // Present for parse-validation; not otherwise used.
    chain_id: String,
    head_hash: Option<String>,
}

#[derive(Deserialize)]
struct EntriesResponse {
    chain_id: String,
    entries: Vec<ChainEntry>,
    next_cursor: Option<u64>,
    head_hash: String,
    total_entries: u64,
}

#[async_trait]
impl ObserverHeadReader for HttpObserverClient {
    async fn read_head(&self, chain_id: &str) -> Result<Option<[u8; 32]>, ObserverError> {
        let url = format!("{}/observer/chain/{}/head", self.base_url, chain_id);
        let resp = self
            .http
            .get(&url)
            .header("x-uninc-read-secret", &self.read_secret)
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    ObserverError::Timeout
                } else {
                    ObserverError::Transport(e.to_string())
                }
            })?;

        let status = resp.status();
        if status == StatusCode::UNAUTHORIZED {
            return Err(ObserverError::Unauthorized);
        }
        if !status.is_success() {
            return Err(ObserverError::Http(status));
        }

        let body: HeadResponse = resp
            .json()
            .await
            .map_err(|e| ObserverError::InvalidResponse(format!("json decode: {e}")))?;

        match body.head_hash {
            None => Ok(None),
            Some(hex_str) => {
                let bytes = hex::decode(&hex_str).map_err(|e| {
                    ObserverError::InvalidResponse(format!("head_hash not hex: {e}"))
                })?;
                if bytes.len() != 32 {
                    return Err(ObserverError::InvalidResponse(format!(
                        "head_hash must be 32 octets, got {}",
                        bytes.len()
                    )));
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                Ok(Some(arr))
            }
        }
    }

    async fn read_entries(
        &self,
        chain_id: &str,
        cursor: u64,
        limit: usize,
    ) -> Result<EntriesPage, ObserverError> {
        let url = format!(
            "{}/observer/chain/{}/entries?cursor={}&limit={}",
            self.base_url, chain_id, cursor, limit,
        );
        let resp = self
            .http
            .get(&url)
            .header("x-uninc-read-secret", &self.read_secret)
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    ObserverError::Timeout
                } else {
                    ObserverError::Transport(e.to_string())
                }
            })?;

        let status = resp.status();
        if status == StatusCode::UNAUTHORIZED {
            return Err(ObserverError::Unauthorized);
        }
        if !status.is_success() {
            return Err(ObserverError::Http(status));
        }

        let body: EntriesResponse = resp
            .json()
            .await
            .map_err(|e| ObserverError::InvalidResponse(format!("entries json decode: {e}")))?;

        Ok(EntriesPage {
            chain_id: body.chain_id,
            entries: body.entries,
            next_cursor: body.next_cursor,
            head_hash: body.head_hash,
            total_entries: body.total_entries,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        extract::{Path, State},
        http::{HeaderMap, StatusCode as AxumStatus},
        response::IntoResponse,
        routing::get,
        Json, Router,
    };
    use std::net::SocketAddr;
    use std::sync::Arc;
    use tokio::net::TcpListener;

    struct TestState {
        expected_secret: String,
        head_hash: Option<String>,
        status_override: Option<AxumStatus>,
    }

    async fn test_head(
        State(state): State<Arc<TestState>>,
        Path(chain_id): Path<String>,
        headers: HeaderMap,
    ) -> impl IntoResponse {
        if let Some(s) = state.status_override {
            return (s, Json(serde_json::json!({ "error": "stubbed" }))).into_response();
        }
        let ok_auth = headers
            .get("x-uninc-read-secret")
            .and_then(|v| v.to_str().ok())
            .map(|v| v == state.expected_secret)
            .unwrap_or(false);
        if !ok_auth {
            return (
                AxumStatus::UNAUTHORIZED,
                Json(serde_json::json!({ "error": "unauthorized" })),
            )
                .into_response();
        }
        (
            AxumStatus::OK,
            Json(serde_json::json!({
                "chain_id": chain_id,
                "head_hash": state.head_hash,
            })),
        )
            .into_response()
    }

    /// Spin up an axum server on a random port, return (addr, handle).
    async fn spawn_server(state: Arc<TestState>) -> SocketAddr {
        // Axum 0.8 uses `{capture}` path syntax; this mirrors the
        // observer's own route (server/crates/observer/src/http.rs).
        let app = Router::new()
            .route("/observer/chain/{chain_id}/head", get(test_head))
            .with_state(state);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        addr
    }

    #[tokio::test]
    async fn read_head_returns_hex_decoded_bytes() {
        let state = Arc::new(TestState {
            expected_secret: "s3cret".into(),
            head_hash: Some("abcd".repeat(16)),
            status_override: None,
        });
        let addr = spawn_server(state).await;
        let client = HttpObserverClient::new(format!("http://{addr}"), "s3cret");
        let head = client.read_head("_deployment").await.unwrap();
        assert_eq!(head, Some([0xab, 0xcd].repeat(16).try_into().unwrap()));
    }

    #[tokio::test]
    async fn read_head_null_returns_none_for_empty_chain() {
        let state = Arc::new(TestState {
            expected_secret: "s3cret".into(),
            head_hash: None,
            status_override: None,
        });
        let addr = spawn_server(state).await;
        let client = HttpObserverClient::new(format!("http://{addr}"), "s3cret");
        let head = client.read_head("_deployment").await.unwrap();
        assert_eq!(head, None);
    }

    #[tokio::test]
    async fn read_head_wrong_secret_returns_unauthorized() {
        let state = Arc::new(TestState {
            expected_secret: "correct".into(),
            head_hash: Some("00".repeat(32)),
            status_override: None,
        });
        let addr = spawn_server(state).await;
        let client = HttpObserverClient::new(format!("http://{addr}"), "wrong");
        let err = client.read_head("_deployment").await.unwrap_err();
        assert!(matches!(err, ObserverError::Unauthorized));
        assert!(
            !err.is_retryable(),
            "unauthorized must not retry — auth is configuration, not transient"
        );
    }

    #[tokio::test]
    async fn read_head_5xx_reports_http_error_and_is_retryable() {
        let state = Arc::new(TestState {
            expected_secret: "s3cret".into(),
            head_hash: None,
            status_override: Some(AxumStatus::INTERNAL_SERVER_ERROR),
        });
        let addr = spawn_server(state).await;
        let client = HttpObserverClient::new(format!("http://{addr}"), "s3cret");
        let err = client.read_head("_deployment").await.unwrap_err();
        match &err {
            ObserverError::Http(s) => assert_eq!(*s, StatusCode::INTERNAL_SERVER_ERROR),
            other => panic!("expected Http(500), got {other:?}"),
        }
        assert!(err.is_retryable(), "5xx should be retryable");
    }

    #[tokio::test]
    async fn read_head_invalid_hex_is_not_retryable() {
        // Server returns malformed head_hash — we should reject cleanly
        // rather than crash, and the scheduled task shouldn't retry
        // because retrying can't possibly fix bad server output.
        let state = Arc::new(TestState {
            expected_secret: "s3cret".into(),
            head_hash: Some("not-hex".into()),
            status_override: None,
        });
        let addr = spawn_server(state).await;
        let client = HttpObserverClient::new(format!("http://{addr}"), "s3cret");
        let err = client.read_head("_deployment").await.unwrap_err();
        assert!(matches!(err, ObserverError::InvalidResponse(_)));
        assert!(!err.is_retryable());
    }

    #[tokio::test]
    async fn read_head_wrong_length_hex_is_rejected() {
        let state = Arc::new(TestState {
            expected_secret: "s3cret".into(),
            head_hash: Some("ab".repeat(10)), // 10 bytes, not 32
            status_override: None,
        });
        let addr = spawn_server(state).await;
        let client = HttpObserverClient::new(format!("http://{addr}"), "s3cret");
        let err = client.read_head("_deployment").await.unwrap_err();
        assert!(matches!(err, ObserverError::InvalidResponse(_)));
    }

    #[tokio::test]
    async fn read_head_connection_refused_is_retryable() {
        // Port 1 is almost never open. Exercise the transport-error
        // branch of the client, assert the error classifies as
        // retryable so the scheduled task will attempt the second try.
        let client = HttpObserverClient::with_timeout(
            "http://127.0.0.1:1",
            "s3cret",
            Duration::from_millis(500),
        );
        let err = client.read_head("_deployment").await.unwrap_err();
        assert!(
            matches!(err, ObserverError::Transport(_) | ObserverError::Timeout),
            "expected transport/timeout, got {err:?}"
        );
        assert!(err.is_retryable());
    }
}
