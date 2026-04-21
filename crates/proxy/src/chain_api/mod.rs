//! Transparency chain read API, served on `:9091` (separate listener from
//! `:9090/health`). JWT-gated via `auth::JwtClaims`, reads per-user chains
//! from disk via the shared `chain-store` crate. See `server/docs/chain-api.md`
//! for the customer-facing spec.
//!
//! The proxy binary is the ONLY process that serves these routes — chain-engine
//! is write-only. Read-only mount of `/data/chains` on the proxy container
//! enforces that at the filesystem layer.

use axum::{
    Router,
    extract::{Path as AxPath, Query, State},
    response::Json,
    routing::{delete, get},
};
use chain_store::{ChainEntry, ChainStore};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use uninc_common::crypto::hash_user_id;
use uninc_common::tombstone::{TombstoneError, TombstoneWriter};
use uninc_common::types::ErasureRequest;

pub mod auth;
pub mod errors;

use crate::jwt_replay::JtiDenyList;
use auth::{AUD_ADMIN, JwtClaims};
use errors::ApiError;

/// Runtime state for the chain API listener. Loaded once at startup from env
/// and passed to every handler. Wrapped in `Arc` so axum's built-in `Clone`
/// blanket `FromRef` impl satisfies the state-extraction bound without any
/// manual trait wiring.
#[derive(Clone)]
pub struct ChainApiState {
    /// Root directory for per-user chain storage. Mirrors chain-engine's
    /// `CHAIN_STORAGE_PATH` — both sides MUST read the same value or the
    /// reader will 404 everything the writer produced.
    pub data_dir: PathBuf,

    /// Per-deployment salt used by `uninc_common::crypto::hash_user_id` to
    /// derive the directory name from a user id. Mirrors chain-engine's
    /// `CHAIN_SERVER_SALT`. Must match.
    pub server_salt: String,

    /// HS256 secret for JWT validation. Mirrors the customer backend's copy
    /// (typically provisioned per-deployment via a secret manager, or via
    /// `.env` for single-host deployments).
    pub jwt_secret: Vec<u8>,

    /// Shared `jti` replay deny-list. Enforces §10.5 of the protocol spec:
    /// any JWT whose `jti` is already in the deny-list inside its `exp`
    /// window is rejected as a replay. Shared with the `/health/detailed`
    /// endpoint so a token presented to one JWT-gated route cannot be
    /// replayed on another.
    pub jti_deny: Arc<JtiDenyList>,

    /// Writer used by DELETE /api/v1/chain/u/{user_id} to commit a
    /// `UserErasureRequested` tombstone to the deployment chain before
    /// replying (§7.3.1). In production this is the shared `NatsClient`,
    /// which round-trips the request to chain-engine via core NATS
    /// request/reply. In unit tests it's `InMemoryTombstoneWriter`.
    pub tombstone_writer: Arc<dyn TombstoneWriter>,
}

pub fn router(state: Arc<ChainApiState>) -> Router {
    Router::new()
        .route(
            "/api/v1/chain/u/{user_id}/entries",
            get(get_user_entries),
        )
        .route("/api/v1/chain/u/{user_id}/head", get(get_user_head))
        .route("/api/v1/chain/u/{user_id}", delete(erase_user_chain))
        .route("/api/v1/chain/deployment/entries", get(get_deployment_entries))
        .route("/api/v1/chain/deployment/summary", get(get_deployment_summary))
        .with_state(state)
}

// ---------------------------------------------------------------------------
// GET /api/v1/chain/u/{user_id}/entries
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct EntriesQuery {
    #[serde(default)]
    cursor: Option<u64>,
    #[serde(default = "default_limit")]
    limit: usize,
}

fn default_limit() -> usize {
    100
}

#[derive(Serialize)]
struct EntriesResponse {
    /// Hex-encoded `HMAC-SHA-256(deployment_salt, user_id)` per spec §3.2.
    /// Callers MAY use this to correlate with the chain directory name
    /// without re-deriving the hash themselves.
    chain_id: String,
    entries: Vec<ChainEntry>,
    /// Next cursor — opaque u64 offset. `None` when the caller has reached
    /// the tail of the chain.
    next_cursor: Option<u64>,
    /// Head hash (hex). Clients pass this to the WASM verifier alongside
    /// the entries array to check integrity client-side.
    head_hash: String,
    /// Total entry count reported by meta.json. Matches spec §7.1.1
    /// `total_entries`; used by verifiers to detect truncation attacks.
    total_entries: u64,
}

async fn get_user_entries(
    State(state): State<Arc<ChainApiState>>,
    claims: JwtClaims,
    AxPath(user_id): AxPath<String>,
    Query(q): Query<EntriesQuery>,
) -> Result<Json<EntriesResponse>, ApiError> {
    // Subject-binding check: the JWT's `sub` must equal the URL's `user_id`.
    // Without this, any customer backend holding a valid JWT could swap the
    // path segment and read any user's audit trail.
    if claims.aud != auth::AUD_USER {
        return Err(ApiError::Forbidden(
            "token audience must be chain-api-user for user-scoped endpoints".into(),
        ));
    }
    if claims.sub != user_id {
        return Err(ApiError::Forbidden(
            "jwt sub must match path user_id".into(),
        ));
    }
    if q.limit == 0 || q.limit > 500 {
        return Err(ApiError::BadRequest("limit must be 1..=500".into()));
    }

    let user_hash = hash_user_id(&user_id, &state.server_salt);
    let store = ChainStore::open_by_hash(&state.data_dir, &user_hash)?;

    let total = store.entry_count()?;
    let start = q.cursor.unwrap_or(0);
    let entries = store.read_range(start, q.limit)?;
    let returned = entries.len() as u64;
    let next_cursor = if start + returned < total {
        Some(start + returned)
    } else {
        None
    };

    let head_hash = store
        .read_head_hash()?
        .map(hex::encode)
        .unwrap_or_default();

    Ok(Json(EntriesResponse {
        chain_id: user_hash,
        entries,
        next_cursor,
        head_hash,
        total_entries: total,
    }))
}

// ---------------------------------------------------------------------------
// GET /api/v1/chain/u/{user_id}/head
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct HeadResponse {
    /// Hex-encoded `HMAC-SHA-256(deployment_salt, user_id)` per spec §3.2.
    chain_id: String,
    head_hash: String,
    /// Matches spec §7.1.2 `total_entries`.
    total_entries: u64,
    /// Unix seconds (spec §4.4) when the tail entry was appended. `0`
    /// for empty chains. Spec §7.1.2 `last_updated_at`.
    last_updated_at: i64,
}

async fn get_user_head(
    State(state): State<Arc<ChainApiState>>,
    claims: JwtClaims,
    AxPath(user_id): AxPath<String>,
) -> Result<Json<HeadResponse>, ApiError> {
    if claims.aud != auth::AUD_USER {
        return Err(ApiError::Forbidden(
            "token audience must be chain-api-user for user-scoped endpoints".into(),
        ));
    }
    if claims.sub != user_id {
        return Err(ApiError::Forbidden(
            "jwt sub must match path user_id".into(),
        ));
    }

    let user_hash = hash_user_id(&user_id, &state.server_salt);
    let store = ChainStore::open_by_hash(&state.data_dir, &user_hash)?;

    let head_hash = store
        .read_head_hash()?
        .map(hex::encode)
        .unwrap_or_default();
    let total_entries = store.entry_count()?;

    // last_updated_at comes from the tail entry's `timestamp` (Unix
    // seconds, §4.4). Empty chains report 0.
    let last_updated_at = if total_entries > 0 {
        store
            .read_entry(total_entries - 1)
            .map(|e| e.timestamp)
            .unwrap_or(0)
    } else {
        0
    };

    Ok(Json(HeadResponse {
        chain_id: user_hash,
        head_hash,
        total_entries,
        last_updated_at,
    }))
}

// ---------------------------------------------------------------------------
// DELETE /api/v1/chain/u/{user_id}  (user-initiated erasure per spec §7.3.1 / §8.1)
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct EraseResponse {
    tombstone_entry_id: String,
    tombstone_deployment_chain_index: u64,
}

async fn erase_user_chain(
    State(state): State<Arc<ChainApiState>>,
    claims: JwtClaims,
    AxPath(user_id): AxPath<String>,
    headers: axum::http::HeaderMap,
) -> Result<Json<EraseResponse>, ApiError> {
    // §6.3 — the JWT subject MUST match the url user_id, raw strings, no
    // hashing or transformation. The erasure privilege is scoped to the
    // data subject themselves. Admin-initiated erasure is out of scope in
    // v1 per the 2026-04-20 S3 decision; revisit in v1.1.
    if claims.aud != auth::AUD_USER {
        return Err(ApiError::Forbidden(
            "token audience must be chain-api-user for erasure requests".into(),
        ));
    }
    if claims.sub != user_id {
        return Err(ApiError::Forbidden(
            "jwt sub must match path user_id".into(),
        ));
    }

    let user_hash = hash_user_id(&user_id, &state.server_salt);

    // Fail fast with 404 if the user has no chain: we don't want to emit a
    // tombstone for a user who had nothing to erase. That would pollute
    // the deployment chain with noise from bored DELETE spammers AND
    // produce a misleading audit trail (a tombstone implies "something
    // was deleted" — nothing was). `open_by_hash` returns `ChainNotFound`
    // which `ApiError::from` maps to 404.
    //
    // We don't hold the `ChainStore` handle across the dispatch. The
    // physical delete lives in chain-engine now (§8.1 step 2, per the
    // 2026-04-20 G13 rewrite) so the proxy's /data/chains mount can be
    // read-only as documented at the top of this module.
    let _ = ChainStore::open_by_hash(&state.data_dir, &user_hash)?;

    // Dispatch the erasure to chain-engine. Chain-engine commits the
    // tombstone AND performs the physical delete (local fs + durable
    // replicas) in one atomic-from-the-proxy's-POV operation. The three
    // response shapes we might decode:
    //
    //   Ok(receipt)                     → 200, receipt body
    //   Err(Transport)                  → 503, tombstone NOT committed, retry safe
    //   Err(Refused)                    → 500, chain-engine rejected
    //   Err(PartialErasure)             → 503, tombstone committed but
    //                                      delete failed; body carries the
    //                                      tombstone id so an operator can
    //                                      finish the durable-tier cleanup
    //                                      without double-tombstoning.
    let request = ErasureRequest {
        user_id_hash: user_hash.clone(),
        source_ip: extract_source_ip(&headers),
        session_id: None,
        requested_at: chrono::Utc::now().timestamp(),
    };
    let receipt = state
        .tombstone_writer
        .write_erasure_tombstone(request)
        .await
        .map_err(|e| match e {
            TombstoneError::Transport(msg) => ApiError::Unavailable(format!(
                "tombstone write failed, disk untouched: {msg}"
            )),
            TombstoneError::Refused(msg) => {
                ApiError::Internal(format!("chain-engine refused tombstone: {msg}"))
            }
            TombstoneError::PartialErasure { receipt, message } => {
                ApiError::Unavailable(format!(
                    "partial erasure: tombstone_entry_id={} tombstone_deployment_chain_index={} \
                     committed, but physical chain delete failed: {message}. \
                     Contact the operator with these tombstone fields to complete the \
                     durable-tier cleanup; do NOT retry DELETE (would double-tombstone).",
                    receipt.tombstone_entry_id, receipt.tombstone_deployment_chain_index
                ))
            }
        })?;

    Ok(Json(EraseResponse {
        tombstone_entry_id: receipt.tombstone_entry_id,
        tombstone_deployment_chain_index: receipt.tombstone_deployment_chain_index,
    }))
}

/// Best-effort source-IP extraction. Prefers `X-Forwarded-For` (first hop)
/// so the recorded IP is the original client rather than an upstream
/// load balancer. Falls back to `X-Real-IP`, then to the literal string
/// `"unknown"`. The tombstone field is not security-critical — it's a
/// forensic hint — so "unknown" is acceptable when no header is present.
fn extract_source_ip(headers: &axum::http::HeaderMap) -> String {
    if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        if let Some(first) = xff.split(',').next() {
            let trimmed = first.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
    }
    if let Some(real) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
        let trimmed = real.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    "unknown".to_string()
}

// ---------------------------------------------------------------------------
// GET /api/v1/chain/deployment/entries  (operator-only, spec §7.2.1)
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct OrgEntriesResponse {
    entries: Vec<ChainEntry>,
    next_cursor: Option<u64>,
    head_hash: String,
    total_entries: u64,
}

async fn get_deployment_entries(
    State(state): State<Arc<ChainApiState>>,
    claims: JwtClaims,
    Query(q): Query<EntriesQuery>,
) -> Result<Json<OrgEntriesResponse>, ApiError> {
    if claims.aud != AUD_ADMIN {
        return Err(ApiError::Forbidden(
            "operator-scoped token required (aud=chain-api-admin)".into(),
        ));
    }
    if q.limit == 0 || q.limit > 500 {
        return Err(ApiError::BadRequest("limit must be 1..=500".into()));
    }

    // The deployment chain is stored under the fixed `_deployment/`
    // directory name. Its on-disk layout is identical to per-user chains
    // — spec §3.1 does not distinguish storage mechanics — so the same
    // ChainStore open-by-hash path works.
    let store = ChainStore::open_by_hash(&state.data_dir, "_deployment")?;

    let total = store.entry_count()?;
    let start = q.cursor.unwrap_or(0);
    let entries = store.read_range(start, q.limit)?;
    let returned = entries.len() as u64;
    let next_cursor = if start + returned < total {
        Some(start + returned)
    } else {
        None
    };
    let head_hash = store
        .read_head_hash()?
        .map(hex::encode)
        .unwrap_or_default();

    Ok(Json(OrgEntriesResponse {
        entries,
        next_cursor,
        head_hash,
        total_entries: total,
    }))
}

// ---------------------------------------------------------------------------
// GET /api/v1/chain/deployment/summary  (operator-only, spec §7.2.2)
// ---------------------------------------------------------------------------

/// Breakdown of DeploymentEvent entries by `category` on the deployment chain.
/// Covers every `DeploymentCategory` defined in spec §4.11.
#[derive(Default, Serialize)]
struct CategoryCounts {
    admin_access: u64,
    admin_lifecycle: u64,
    config: u64,
    deploy: u64,
    schema: u64,
    system: u64,
    approved_access: u64,
    egress: u64,
    user_erasure_requested: u64,
    retention_sweep: u64,
    verification_failure: u64,
    nightly_verification: u64,
    replica_reshuffle: u64,
}

#[derive(Serialize)]
struct OrgSummary {
    head_hash: String,
    total_entries: u64,
    category_counts: CategoryCounts,
}

async fn get_deployment_summary(
    State(state): State<Arc<ChainApiState>>,
    claims: JwtClaims,
) -> Result<Json<OrgSummary>, ApiError> {
    if claims.aud != AUD_ADMIN {
        return Err(ApiError::Forbidden(
            "operator-scoped token required (aud=chain-api-admin)".into(),
        ));
    }

    // An uninitialized deployment chain (n = 0) is a valid state per
    // §5.2.1 V7 — head hash is 32 zero octets. Return that rather than
    // 404 so operator tooling can poll this endpoint at boot without
    // special-casing "not yet initialized."
    let Ok(store) = ChainStore::open_by_hash(&state.data_dir, "_deployment") else {
        return Ok(Json(OrgSummary {
            head_hash: hex::encode([0u8; 32]),
            total_entries: 0,
            category_counts: CategoryCounts::default(),
        }));
    };

    let total_entries = store.entry_count()?;
    let head_hash = store
        .read_head_hash()?
        .map(hex::encode)
        .unwrap_or_else(|| hex::encode([0u8; 32]));

    // Walk the chain to count per-category. Adequate at v1 scale
    // (thousands of entries); a sidecar counter is the right answer
    // once volume warrants it.
    let mut counts = CategoryCounts::default();
    if total_entries > 0 {
        for entry in store.read_all()?.iter() {
            if let chain_store::EventPayload::Deployment(org) = &entry.payload {
                match org.category {
                    chain_store::DeploymentCategory::AdminAccess => counts.admin_access += 1,
                    chain_store::DeploymentCategory::AdminLifecycle => counts.admin_lifecycle += 1,
                    chain_store::DeploymentCategory::Config => counts.config += 1,
                    chain_store::DeploymentCategory::Deploy => counts.deploy += 1,
                    chain_store::DeploymentCategory::Schema => counts.schema += 1,
                    chain_store::DeploymentCategory::System => counts.system += 1,
                    chain_store::DeploymentCategory::ApprovedAccess => counts.approved_access += 1,
                    chain_store::DeploymentCategory::Egress => counts.egress += 1,
                    chain_store::DeploymentCategory::UserErasureRequested => {
                        counts.user_erasure_requested += 1
                    }
                    chain_store::DeploymentCategory::RetentionSweep => counts.retention_sweep += 1,
                    chain_store::DeploymentCategory::VerificationFailure => {
                        counts.verification_failure += 1
                    }
                    chain_store::DeploymentCategory::NightlyVerification => {
                        counts.nightly_verification += 1
                    }
                    chain_store::DeploymentCategory::ReplicaReshuffle => counts.replica_reshuffle += 1,
                }
            }
        }
    }

    Ok(Json(OrgSummary {
        head_hash,
        total_entries,
        category_counts: counts,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use chain_store::{
        AccessAction, AccessActorType, AccessEvent, AccessScope, ChainEntry, Protocol,
    };
    use jsonwebtoken::{EncodingKey, Header, encode};
    use tower::ServiceExt;

    fn make_state(tmp: &std::path::Path) -> Arc<ChainApiState> {
        make_state_with_writer(tmp, Arc::new(uninc_common::InMemoryTombstoneWriter::new()))
    }

    fn make_state_with_writer(
        tmp: &std::path::Path,
        writer: Arc<dyn TombstoneWriter>,
    ) -> Arc<ChainApiState> {
        Arc::new(ChainApiState {
            data_dir: tmp.to_path_buf(),
            server_salt: "test-salt".into(),
            jwt_secret: b"test-secret-test-secret-test-secret".to_vec(),
            jti_deny: Arc::new(JtiDenyList::new(1024)),
            tombstone_writer: writer,
        })
    }

    fn sign_token(secret: &[u8], sub: &str, aud: &str) -> String {
        sign_token_with_jti(secret, sub, aud, &uuid::Uuid::new_v4().to_string())
    }

    fn sign_token_with_jti(secret: &[u8], sub: &str, aud: &str, jti: &str) -> String {
        #[derive(Serialize)]
        struct Claims<'a> {
            sub: &'a str,
            aud: &'a str,
            exp: usize,
            iat: usize,
            iss: &'a str,
            jti: &'a str,
        }
        let now = chrono::Utc::now().timestamp() as usize;
        encode(
            &Header::new(jsonwebtoken::Algorithm::HS256),
            &Claims {
                sub,
                aud,
                exp: now + 300,
                iat: now,
                iss: "test",
                jti,
            },
            &EncodingKey::from_secret(secret),
        )
        .unwrap()
    }

    fn sample_access_event() -> AccessEvent {
        AccessEvent {
            actor_id: "admin".into(),
            actor_type: AccessActorType::Admin,
            actor_label: "admin".into(),
            protocol: Protocol::Postgres,
            action: AccessAction::Read,
            resource: "users".into(),
            affected_user_ids: vec![],
            query_fingerprint: hex::encode([0u8; 32]),
            query_shape: None,
            scope: AccessScope::default(),
            source_ip: "127.0.0.1".into(),
            session_id: "00000000-0000-0000-0000-000000000000".into(),
            correlation_id: None,
        }
    }

    fn seed_chain(data_dir: &std::path::Path, user_id: &str, salt: &str, count: u64) {
        let store = ChainStore::open(data_dir, user_id, salt).unwrap();
        let mut prev = [0u8; 32];
        for i in 0..count {
            let entry =
                ChainEntry::access(i, prev, 1_000 + i as i64, sample_access_event()).unwrap();
            prev = entry.entry_hash;
            store.append(&entry).unwrap();
        }
    }

    #[tokio::test]
    async fn entries_happy_path() {
        let tmp = tempfile::tempdir().unwrap();
        seed_chain(tmp.path(), "user42", "test-salt", 3);
        let state = make_state(tmp.path());
        let app = router(state.clone());

        let token = sign_token(&state.jwt_secret, "user42", "chain-api-user");
        let req = Request::builder()
            .uri("/api/v1/chain/u/user42/entries")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["entries"].as_array().unwrap().len(), 3);
        assert_eq!(parsed["total_entries"], 3);
        assert_eq!(
            parsed["chain_id"].as_str().unwrap().len(),
            64,
            "chain_id must be 64-char hex per spec §3.2"
        );
        assert!(parsed["head_hash"].as_str().unwrap().len() == 64);
    }

    #[tokio::test]
    async fn missing_bearer_returns_401() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());
        let app = router(state);

        let req = Request::builder()
            .uri("/api/v1/chain/u/user42/entries")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn sub_mismatch_returns_403() {
        let tmp = tempfile::tempdir().unwrap();
        seed_chain(tmp.path(), "user42", "test-salt", 1);
        let state = make_state(tmp.path());
        let app = router(state.clone());

        let token = sign_token(&state.jwt_secret, "someone_else", "chain-api-user");
        let req = Request::builder()
            .uri("/api/v1/chain/u/user42/entries")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn unknown_user_returns_404() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_state(tmp.path());
        let app = router(state.clone());

        let token = sign_token(&state.jwt_secret, "ghost", "chain-api-user");
        let req = Request::builder()
            .uri("/api/v1/chain/u/ghost/entries")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn limit_out_of_range_returns_400() {
        let tmp = tempfile::tempdir().unwrap();
        seed_chain(tmp.path(), "user42", "test-salt", 1);
        let state = make_state(tmp.path());
        let app = router(state.clone());

        let token = sign_token(&state.jwt_secret, "user42", "chain-api-user");
        let req = Request::builder()
            .uri("/api/v1/chain/u/user42/entries?limit=501")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn org_summary_requires_admin_aud() {
        let tmp = tempfile::tempdir().unwrap();
        seed_chain(tmp.path(), "user42", "test-salt", 2);
        let state = make_state(tmp.path());
        let app = router(state.clone());

        // User-scoped token cannot reach admin endpoint.
        let user_token = sign_token(&state.jwt_secret, "user42", "chain-api-user");
        let req = Request::builder()
            .uri("/api/v1/chain/deployment/summary")
            .header("authorization", format!("Bearer {user_token}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        // Admin token works.
        let admin_token = sign_token(&state.jwt_secret, "operator", "chain-api-admin");
        let req = Request::builder()
            .uri("/api/v1/chain/deployment/summary")
            .header("authorization", format!("Bearer {admin_token}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn erase_user_chain_dispatches_tombstone_request() {
        // §7.3.1 — a JWT-authenticated DELETE on /api/v1/chain/u/{user_id}
        // MUST dispatch an erasure request whose ultimate effect is (a) a
        // `UserErasureRequested` tombstone on the deployment chain, (b)
        // removal of the per-user chain from BOTH local fs and durable
        // replicas, and (c) the real tombstone identity in the response body.
        //
        // Since the 2026-04-20 G13 rewrite, (a) and (b) both live in
        // chain-engine's `erasure_handler`; the proxy here only dispatches
        // the request and returns the receipt. This test uses an
        // `InMemoryTombstoneWriter` so the proxy-side path runs without a
        // live chain-engine. The end-to-end delete path is covered by
        // `tests/erasure_roundtrip.rs` (real NATS + real DeploymentChainManager
        // + real ChainManager).
        let tmp = tempfile::tempdir().unwrap();
        seed_chain(tmp.path(), "user42", "test-salt", 3);
        let writer = Arc::new(uninc_common::InMemoryTombstoneWriter::new());
        let state = make_state_with_writer(tmp.path(), writer.clone());
        let app = router(state.clone());

        // Confirm the chain directory exists before erasure — the proxy
        // short-circuits with 404 if the chain doesn't exist on /data/chains.
        let user_hash = hash_user_id("user42", &state.server_salt);
        assert!(tmp.path().join(&user_hash).exists());

        let token = sign_token(&state.jwt_secret, "user42", "chain-api-user");
        let req = Request::builder()
            .method("DELETE")
            .uri("/api/v1/chain/u/user42")
            .header("authorization", format!("Bearer {token}"))
            .header("x-forwarded-for", "203.0.113.7, 10.0.0.1")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // The response body carries a REAL tombstone id — not the sentinel
        // the pre-tombstone implementation used to return.
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let tombstone_id = parsed["tombstone_entry_id"].as_str().unwrap();
        assert_eq!(
            tombstone_id.len(),
            64,
            "tombstone_entry_id must be hex-encoded SHA-256 (64 chars)"
        );
        assert_ne!(
            tombstone_id, user_hash,
            "tombstone_entry_id must NOT be the user hash — that was the \
             sentinel from the stubbed implementation"
        );
        assert_eq!(parsed["tombstone_deployment_chain_index"], 0);

        // The tombstone writer saw the request with the right shape — proof
        // the proxy dispatched the request chain-engine is responsible for
        // fulfilling. Physical delete is NOT asserted here because the
        // in-memory writer doesn't run chain-engine's delete path; see
        // `tests/erasure_roundtrip.rs` for the end-to-end delete assertion.
        let received = writer.received();
        assert_eq!(received.len(), 1);
        assert_eq!(received[0].user_id_hash, user_hash);
        assert_eq!(
            received[0].source_ip, "203.0.113.7",
            "source_ip MUST be the first XFF hop, not the intermediary"
        );
    }

    #[tokio::test]
    async fn erase_preserves_disk_when_tombstone_fails() {
        // Tombstone-first ordering invariant: if the tombstone write fails,
        // the on-disk chain MUST stay intact so the caller can retry
        // without having silently destroyed data.
        use async_trait::async_trait;
        use uninc_common::tombstone::{TombstoneError, TombstoneWriter};
        use uninc_common::types::{ErasureReceipt, ErasureRequest};

        struct FailingWriter;
        #[async_trait]
        impl TombstoneWriter for FailingWriter {
            async fn write_erasure_tombstone(
                &self,
                _req: ErasureRequest,
            ) -> Result<ErasureReceipt, TombstoneError> {
                Err(TombstoneError::Transport("simulated outage".into()))
            }
        }

        let tmp = tempfile::tempdir().unwrap();
        seed_chain(tmp.path(), "user42", "test-salt", 2);
        let state = make_state_with_writer(tmp.path(), Arc::new(FailingWriter));
        let app = router(state.clone());

        let user_hash = hash_user_id("user42", &state.server_salt);
        assert!(tmp.path().join(&user_hash).exists());

        let token = sign_token(&state.jwt_secret, "user42", "chain-api-user");
        let req = Request::builder()
            .method("DELETE")
            .uri("/api/v1/chain/u/user42")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);

        // Disk untouched — safe to retry.
        assert!(tmp.path().join(&user_hash).exists());
    }

    #[tokio::test]
    async fn erase_on_nonexistent_user_returns_404_without_writing_tombstone() {
        // A DELETE for a user with no chain MUST return 404 WITHOUT first
        // emitting a tombstone. Otherwise a bored attacker could spam
        // DELETE against random user ids and pollute the deployment chain
        // with meaningless "erasure" records for users who never had data.
        let tmp = tempfile::tempdir().unwrap();
        let writer = Arc::new(uninc_common::InMemoryTombstoneWriter::new());
        let state = make_state_with_writer(tmp.path(), writer.clone());
        let app = router(state.clone());

        let token = sign_token(&state.jwt_secret, "ghost", "chain-api-user");
        let req = Request::builder()
            .method("DELETE")
            .uri("/api/v1/chain/u/ghost")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            writer.received().len(),
            0,
            "no tombstone must be written for a missing user chain"
        );
    }

    #[tokio::test]
    async fn erase_rejects_mismatched_sub() {
        let tmp = tempfile::tempdir().unwrap();
        seed_chain(tmp.path(), "victim", "test-salt", 1);
        let state = make_state(tmp.path());
        let app = router(state.clone());

        // Attacker JWT (sub != path) must be refused.
        let token = sign_token(&state.jwt_secret, "attacker", "chain-api-user");
        let req = Request::builder()
            .method("DELETE")
            .uri("/api/v1/chain/u/victim")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn replayed_jti_is_rejected() {
        // §10.5: a token presented twice MUST be rejected on the second
        // presentation, regardless of signature / exp / aud validity.
        let tmp = tempfile::tempdir().unwrap();
        seed_chain(tmp.path(), "user42", "test-salt", 1);
        let state = make_state(tmp.path());
        let app = router(state.clone());

        let token = sign_token_with_jti(
            &state.jwt_secret,
            "user42",
            "chain-api-user",
            "fixed-jti-for-replay-test",
        );

        let make_req = || {
            Request::builder()
                .uri("/api/v1/chain/u/user42/entries")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap()
        };

        let first = app.clone().oneshot(make_req()).await.unwrap();
        assert_eq!(first.status(), StatusCode::OK);

        let replay = app.oneshot(make_req()).await.unwrap();
        assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn missing_jti_is_rejected() {
        // §6.1 makes `jti` required. A token without one (or with an empty
        // one) must never be admitted.
        let tmp = tempfile::tempdir().unwrap();
        seed_chain(tmp.path(), "user42", "test-salt", 1);
        let state = make_state(tmp.path());
        let app = router(state.clone());

        #[derive(Serialize)]
        struct NoJtiClaims<'a> {
            sub: &'a str,
            aud: &'a str,
            exp: usize,
            iat: usize,
            iss: &'a str,
        }
        let now = chrono::Utc::now().timestamp() as usize;
        let token = encode(
            &Header::new(jsonwebtoken::Algorithm::HS256),
            &NoJtiClaims {
                sub: "user42",
                aud: "chain-api-user",
                exp: now + 300,
                iat: now,
                iss: "test",
            },
            &EncodingKey::from_secret(&state.jwt_secret),
        )
        .unwrap();

        let req = Request::builder()
            .uri("/api/v1/chain/u/user42/entries")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn token_without_iat_is_accepted() {
        // §6.1: v1 does not use `iat`. A token omitting the claim must be
        // accepted as long as the other required claims are present.
        let tmp = tempfile::tempdir().unwrap();
        seed_chain(tmp.path(), "user42", "test-salt", 1);
        let state = make_state(tmp.path());
        let app = router(state.clone());

        #[derive(Serialize)]
        struct NoIatClaims<'a> {
            sub: &'a str,
            aud: &'a str,
            exp: usize,
            iss: &'a str,
            jti: &'a str,
        }
        let now = chrono::Utc::now().timestamp() as usize;
        let token = encode(
            &Header::new(jsonwebtoken::Algorithm::HS256),
            &NoIatClaims {
                sub: "user42",
                aud: "chain-api-user",
                exp: now + 300,
                iss: "test",
                jti: &uuid::Uuid::new_v4().to_string(),
            },
            &EncodingKey::from_secret(&state.jwt_secret),
        )
        .unwrap();

        let req = Request::builder()
            .uri("/api/v1/chain/u/user42/entries")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
