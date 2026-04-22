//! `/health` endpoints on the proxy.
//!
//! Three routes, split by information sensitivity:
//!
//! - `GET /health` — **open**, returns `200` with `{"status":"ok"}` plus an
//!   `observer` block when the deployment has one configured. The observer
//!   block carries the result of an active probe of the observer's
//!   `/observer/chain/deployment/head` endpoint (run inside the VPC so the
//!   mothership, which can't reach the private-subnet observer directly,
//!   still gets a real reachability signal). Probe results are cached
//!   for 15 s so LB polls don't amplify into observer load. The endpoint
//!   always returns 200 — a broken observer surfaces as
//!   `{"observer": {"reachable": false, "error": "..."}}` in the body,
//!   not as a non-200 status (keeps the LB contract stable).
//!
//! - `GET /health/ready` — **open**, returns `200 {"status":"ready"}` if
//!   the process can serve traffic (NATS connected, recent publish ok), or
//!   `503 {"status":"not_ready"}` otherwise. Used by GCP LB readiness
//!   probes. Body is minimal — no state leak.
//!
//! - `GET /health/detailed` — **JWT-gated** (audience `health-detailed`),
//!   returns the full rich body: NATS publish timestamps, per-listener pool
//!   utilization, uptime, rollup status. This is the endpoint operators
//!   poll from a control-plane UI. A scanner without the JWT secret
//!   can't fingerprint the deployment or measure saturation remotely.
//!
//! See ARCHITECTURE.md §"Capacity & overload protection" Layer 1.
//!
//! The shared state is assembled in `main.rs` and queried by the handler on
//! each request. No background task — state is pulled lazily so the endpoint
//! reflects real-time conditions.

use std::sync::Arc;
use std::time::Instant;

use axum::Json;
use axum::extract::{FromRequestParts, State};
use axum::http::{StatusCode, header::AUTHORIZATION, request::Parts};
use axum::response::{IntoResponse, Response};
use jsonwebtoken::{DecodingKey, Validation, decode};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uninc_common::health::{SubsystemHealth, now_ms};
use uninc_common::nats_client::NatsClient;

use crate::jwt_replay::{JtiAdmit, JtiDenyList};
use crate::pool::ConnectionCap;

/// JWT audience required on tokens presented to `/health/detailed`. Kept
/// distinct from the chain-api audiences (`chain-api`, `chain-api-admin`)
/// so that a chain-read token can't be replayed against the health endpoint
/// and vice versa.
pub const AUD_HEALTH_DETAILED: &str = "health-detailed";

/// Shared state read by the `/health` handlers. Constructed once in `main.rs`
/// and handed to the axum router via `with_state`.
#[derive(Clone)]
pub struct HealthState {
    inner: Arc<HealthStateInner>,
}

struct HealthStateInner {
    /// Monotonic start time, used to compute uptime.
    started_at: Instant,

    /// Postgres listener's connection cap (clone — shares the underlying
    /// semaphore + counter). `None` if the postgres listener is disabled.
    postgres_cap: Option<ConnectionCap>,

    /// MongoDB listener's connection cap. `None` if disabled.
    mongodb_cap: Option<ConnectionCap>,

    /// S3 listener's connection cap. `None` if disabled.
    s3_cap: Option<ConnectionCap>,

    /// NATS client reference — used for liveness probe.
    nats: Option<Arc<NatsClient>>,

    /// Observer base URL + read-secret. When both are populated the `/health`
    /// handler includes an `observer` block in its response, carrying the
    /// result of an active probe of `${observer_url}/observer/chain/deployment/head`.
    /// `None` in single-host / Playground topologies with no observer; the
    /// block is omitted in that case.
    observer_url: Option<String>,
    observer_read_secret: Option<String>,

    /// Cached observer-probe result. Short TTL (15s) keeps LB poll cost
    /// bounded while still reflecting a broken observer within seconds.
    observer_probe_cache: tokio::sync::Mutex<Option<ObserverProbe>>,

    /// Per-subsystem liveness stamps. Each entry is shared via `Arc` so
    /// subsystems running in other parts of the proxy (listeners, the
    /// verification task, NATS ops subscribers relaying signals from
    /// chain-engine, etc.) can stamp their state without locking. Reads
    /// from `/health/detailed` are lock-free on the atomics and take a
    /// single uncontended mutex for `last_err_reason`.
    ///
    /// Keys are stable string IDs surfaced in the JSON response:
    /// - `"nats"`           — NATS publish from any listener
    /// - `"chain_commit"`   — chain-engine deployment/per-user append outcome
    /// - `"observer_head"`  — scheduled verification task's observer HTTP read
    ///
    /// Additional subsystems can be added without changing the response
    /// schema — the handler enumerates the map.
    subsystems: std::collections::BTreeMap<&'static str, Arc<SubsystemHealth>>,

    /// HS256 secret for `/health/detailed` JWT validation. Shared with the
    /// frontend and the chain API — same `JWT_SECRET` env var, loaded once
    /// in `main.rs`. `None` means the detailed endpoint will refuse every
    /// request (fail-closed).
    jwt_secret: Option<Vec<u8>>,

    /// Shared `jti` replay deny-list, same `Arc` that `ChainApiState`
    /// holds. Enforces §10.5 of the protocol spec across every JWT-gated
    /// endpoint on the proxy, so a token swipe cannot be replayed from
    /// one surface to another.
    jti_deny: Option<Arc<JtiDenyList>>,
}

impl HealthState {
    pub fn new(nats: Option<Arc<NatsClient>>) -> Self {
        // Pre-register every subsystem the detailed handler is expected
        // to report on. Each starts in the "idle" state — no ok_ms yet,
        // no err_ms yet. Subsystems that are not configured (e.g. the
        // observer head fetch in single-host deployments) will report
        // `"not_configured"` at rollup time based on the `configured`
        // flag passed to `status()`.
        let mut subsystems = std::collections::BTreeMap::new();
        subsystems.insert("nats", Arc::new(SubsystemHealth::new()));
        subsystems.insert("chain_commit", Arc::new(SubsystemHealth::new()));
        subsystems.insert("observer_head", Arc::new(SubsystemHealth::new()));

        Self {
            inner: Arc::new(HealthStateInner {
                started_at: Instant::now(),
                postgres_cap: None,
                mongodb_cap: None,
                s3_cap: None,
                nats,
                subsystems,
                jwt_secret: None,
                jti_deny: None,
                observer_url: None,
                observer_read_secret: None,
                observer_probe_cache: tokio::sync::Mutex::new(None),
            }),
        }
    }

    /// Builder — attach the observer base URL and its read-secret so the
    /// `/health/observer` endpoint can perform an active reachability probe.
    /// Both must be present; if either is `None`, the probe reports
    /// `configured: false` (not an error — it's how single-host deployments
    /// are distinguished from a misconfiguration).
    pub fn with_observer(mut self, url: Option<String>, secret: Option<String>) -> Self {
        let inner = Arc::get_mut(&mut self.inner)
            .expect("HealthState::with_* called after clone");
        inner.observer_url = url;
        inner.observer_read_secret = secret;
        self
    }

    /// Builder — attach the shared HS256 secret used to validate JWTs on
    /// `/health/detailed`. Must be set before the endpoint will accept any
    /// requests; if left unset, the handler always returns 503.
    pub fn with_jwt_secret(mut self, secret: Vec<u8>) -> Self {
        Arc::get_mut(&mut self.inner)
            .expect("HealthState::with_* called after clone")
            .jwt_secret = Some(secret);
        self
    }

    /// Builder — attach the shared `jti` replay deny-list. Same `Arc`
    /// that `ChainApiState` holds. If unset, `/health/detailed` returns
    /// 401 for every request (fail-closed on replay enforcement).
    pub fn with_jti_deny(mut self, deny: Arc<JtiDenyList>) -> Self {
        Arc::get_mut(&mut self.inner)
            .expect("HealthState::with_* called after clone")
            .jti_deny = Some(deny);
        self
    }

    /// Builder — attach the Postgres listener's connection cap.
    pub fn with_postgres_cap(mut self, cap: ConnectionCap) -> Self {
        Arc::get_mut(&mut self.inner)
            .expect("HealthState::with_* called after clone")
            .postgres_cap = Some(cap);
        self
    }

    pub fn with_mongodb_cap(mut self, cap: ConnectionCap) -> Self {
        Arc::get_mut(&mut self.inner)
            .expect("HealthState::with_* called after clone")
            .mongodb_cap = Some(cap);
        self
    }

    pub fn with_s3_cap(mut self, cap: ConnectionCap) -> Self {
        Arc::get_mut(&mut self.inner)
            .expect("HealthState::with_* called after clone")
            .s3_cap = Some(cap);
        self
    }

    /// Hand out an `Arc` to the named subsystem's health cell. Callers
    /// stamp `.stamp_ok()` / `.stamp_err(reason)` on the return value.
    /// Returns `None` for an unknown name — all legitimate names are
    /// pre-registered in `new()`, so a `None` indicates a typo at the
    /// call site (tests catch this).
    pub fn subsystem(&self, name: &str) -> Option<Arc<SubsystemHealth>> {
        self.inner.subsystems.get(name).cloned()
    }

    /// Convenience accessor for the NATS-publish subsystem — the name
    /// every listener needs and the one that existed before the
    /// per-subsystem generalization. Preserved so the listener call
    /// sites remain a one-liner.
    pub fn nats_publish(&self) -> Arc<SubsystemHealth> {
        self.inner
            .subsystems
            .get("nats")
            .cloned()
            .expect("nats subsystem is pre-registered in HealthState::new")
    }

    /// Convenience accessor for the chain-commit subsystem. The proxy
    /// itself does not produce chain appends — chain-engine runs in a
    /// separate process. A NATS ops subscriber on the proxy turns
    /// `uninc.ops.chain_commit.*` messages into `stamp_ok/err` calls
    /// on this cell, which is how the `/health/detailed` endpoint sees
    /// chain-engine's state without a direct RPC.
    pub fn chain_commit(&self) -> Arc<SubsystemHealth> {
        self.inner
            .subsystems
            .get("chain_commit")
            .cloned()
            .expect("chain_commit subsystem is pre-registered in HealthState::new")
    }

    /// Convenience accessor for the observer-head subsystem — stamped
    /// by the scheduled verification task on each observer HTTP read
    /// attempt. `"not_configured"` when the deployment has no observer.
    pub fn observer_head(&self) -> Arc<SubsystemHealth> {
        self.inner
            .subsystems
            .get("observer_head")
            .cloned()
            .expect("observer_head subsystem is pre-registered in HealthState::new")
    }
}

/// Minimal-body JWT claims expected on `/health/detailed`. Same HS256 secret
/// the frontend (and chain API) already uses — the frontend signs a token
/// with `aud: "health-detailed"`, a short `exp`, and a unique `jti` and the
/// proxy decodes it here. No service-account plumbing.
///
/// `jti` is REQUIRED per §6.1 / §10.5 of protocol/draft-wang-data-access-transparency-00.md —
/// the health endpoint enforces the same replay deny-list as the chain API,
/// so a token sniffed off one endpoint cannot be replayed against the other.
#[derive(Debug, Deserialize, Serialize)]
struct HealthJwtClaims {
    #[serde(default)]
    sub: String,
    aud: String,
    exp: usize,
    jti: String,
}

/// Extractor — pulls `Authorization: Bearer <token>`, validates against
/// `HealthState::jwt_secret` with audience `health-detailed`. Any failure
/// (missing secret, missing header, bad token, wrong audience, expired)
/// collapses to a single `401 Unauthorized` response so the endpoint
/// can't be used to distinguish failure modes.
pub struct HealthJwt;

impl FromRequestParts<HealthState> for HealthJwt {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &HealthState,
    ) -> Result<Self, Self::Rejection> {
        let unauth = || (StatusCode::UNAUTHORIZED, "unauthorized").into_response();

        let secret = state
            .inner
            .jwt_secret
            .as_ref()
            .ok_or_else(unauth)?;
        // Replay deny-list must be wired in main.rs alongside the secret.
        // Missing deny-list collapses to 401 — refuse rather than serve
        // replay-vulnerable responses.
        let deny = state
            .inner
            .jti_deny
            .as_ref()
            .ok_or_else(unauth)?;

        let token = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .and_then(|h| h.strip_prefix("Bearer "))
            .ok_or_else(unauth)?;

        let mut validation = Validation::new(jsonwebtoken::Algorithm::HS256);
        validation.set_audience(&[AUD_HEALTH_DETAILED]);
        validation.set_required_spec_claims(&["exp", "aud", "sub"]);
        validation.validate_exp = true;
        validation.leeway = 5;

        let claims = decode::<HealthJwtClaims>(
            token,
            &DecodingKey::from_secret(secret),
            &validation,
        )
        .map_err(|_| unauth())?
        .claims;

        if claims.jti.trim().is_empty() {
            return Err(unauth());
        }

        match deny.admit(&claims.jti, claims.exp as u64) {
            JtiAdmit::Fresh => Ok(HealthJwt),
            JtiAdmit::Replayed | JtiAdmit::Expired => Err(unauth()),
        }
    }
}

/// `GET /health` — open, stable for LB / uptime checks. Returns
/// `{"status":"ok"}` plus an `observer` block when the deployment has an
/// observer configured (single-host / Playground topologies omit it
/// entirely). Status is always 200 — the observer's state is reported in
/// the body, never via a non-200 status, so an LB that only looks at HTTP
/// status still treats a reachable proxy as healthy even when the observer
/// is offline. The probe is cached for 15 s.
///
/// Leak analysis: the head hash and index are already recoverable via
/// `/api/v1/chain/deployment/head`. The `reachable` boolean and the error
/// string are coarse operational data (HTTP status / timeout reason), not
/// observer internals. Nothing that wasn't already derivable is exposed.
pub async fn handle_health_basic(State(state): State<HealthState>) -> Json<Value> {
    if state.inner.observer_url.is_none() {
        return Json(json!({ "status": "ok" }));
    }
    let observer = probe_observer(&state).await;
    Json(json!({ "status": "ok", "observer": observer }))
}

/// `GET /health/ready` — open, readiness probe. Returns 200 if the process
/// is ready to accept traffic, 503 otherwise. "Ready" means:
///
/// - NATS is configured AND (has recently published OK, or we're still in
///   the startup grace window of 30s), OR
/// - NATS is not configured at all (single-mode local dev, always ready).
///
/// No detail is included in the body — just `{"status":"ready"}` or
/// `{"status":"not_ready"}`. Matches the same "no fingerprinting" rule as
/// `/health`: an external scanner can learn "process is up" from /health
/// and "process is serving" from /health/ready, but nothing else.
pub async fn handle_health_ready(State(state): State<HealthState>) -> Response {
    let now = now_ms();
    let uptime_secs = state.inner.started_at.elapsed().as_secs();
    let nats_configured = state.inner.nats.is_some();
    let nats_status = state
        .nats_publish()
        .status(now, nats_configured, uptime_secs);

    // Readiness is NATS-gated only: the other subsystems (chain_commit,
    // observer_head) can be legitimately idle without making the process
    // unable to serve traffic — a chain-commit stall should degrade the
    // detailed status but not pull the process out of the LB rotation.
    // If we start marking the proxy unready on chain_commit errors, we
    // create a feedback loop where a chain-engine hiccup evicts the
    // proxy and causes admin writes to 503, which is worse than serving
    // with a degraded chain path.
    let ready = !nats_configured
        || matches!(nats_status, "ok" | "stale");

    if ready {
        (StatusCode::OK, Json(json!({ "status": "ready" }))).into_response()
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "status": "not_ready" })),
        )
            .into_response()
    }
}

/// `GET /health/detailed` — JWT-gated. Returns the full rich JSON body with
/// NATS publish timestamps, per-listener pool utilization, uptime, rollup
/// status. This is what operators poll from a control-plane UI.
///
/// Status rollup:
///
/// - `unhealthy` — NATS publish has failed in the last 30s AND no success
///   has been recorded since, OR any connection cap is fully exhausted.
/// - `degraded` — any cap is >80% utilized, OR NATS has not published
///   successfully in the last 60s despite being connected.
/// - `ok` — everything within budget.
pub async fn handle_health_detailed(
    State(state): State<HealthState>,
    _jwt: HealthJwt,
) -> Json<Value> {
    let now = now_ms();
    let uptime_secs = state.inner.started_at.elapsed().as_secs();

    // Which subsystems are actually expected to produce stamps in this
    // deployment. Subsystems without a configured peer (no observer, no
    // NATS) report "not_configured" and do not count toward the rollup.
    let nats_configured = state.inner.nats.is_some();
    let chain_commit_configured = nats_configured; // chain-engine stamps arrive via NATS ops
    let observer_head_configured = state
        .observer_head()
        .last_ok_ms()
        .max(state.observer_head().last_err_ms())
        > 0; // first stamp from the scheduled task flips it on

    let subsystem_json: serde_json::Map<String, Value> = state
        .inner
        .subsystems
        .iter()
        .map(|(name, cell)| {
            let configured = match *name {
                "nats" => nats_configured,
                "chain_commit" => chain_commit_configured,
                "observer_head" => observer_head_configured,
                _ => true,
            };
            (name.to_string(), cell.to_json(now, configured, uptime_secs))
        })
        .collect();

    fn cap_json(cap: &Option<ConnectionCap>) -> Value {
        match cap {
            None => json!({ "enabled": false }),
            Some(c) => {
                let in_use = c.in_use();
                let max = c.max() as u64;
                let utilization_pct = if max == 0 {
                    0.0
                } else {
                    (in_use as f64 / max as f64) * 100.0
                };
                let status = if in_use >= max {
                    "exhausted"
                } else if utilization_pct >= 80.0 {
                    "degraded"
                } else {
                    "ok"
                };
                json!({
                    "enabled": true,
                    "in_use": in_use,
                    "max": max,
                    "utilization_pct": format!("{utilization_pct:.1}"),
                    "status": status,
                })
            }
        }
    }

    let postgres = cap_json(&state.inner.postgres_cap);
    let mongodb = cap_json(&state.inner.mongodb_cap);
    let s3 = cap_json(&state.inner.s3_cap);

    let any_exhausted = [&postgres, &mongodb, &s3].iter().any(|v| {
        v.get("status").and_then(|s| s.as_str()) == Some("exhausted")
    });
    let any_degraded = [&postgres, &mongodb, &s3].iter().any(|v| {
        v.get("status").and_then(|s| s.as_str()) == Some("degraded")
    });

    // Subsystem-level rollup. "down" in any subsystem → unhealthy;
    // "stale" or "idle" → degraded. `not_configured` does not
    // contribute either way — an absent observer is not a fault.
    let subsystem_down = subsystem_json
        .values()
        .any(|v| v.get("status").and_then(|s| s.as_str()) == Some("down"));
    let subsystem_soft = subsystem_json.values().any(|v| {
        matches!(
            v.get("status").and_then(|s| s.as_str()),
            Some("stale") | Some("idle")
        )
    });

    let overall = if subsystem_down || any_exhausted {
        "unhealthy"
    } else if subsystem_soft || any_degraded {
        "degraded"
    } else {
        "ok"
    };

    Json(json!({
        "status": overall,
        "uptime_secs": uptime_secs,
        "now_ms": now,
        "checks": {
            "subsystems": subsystem_json,
            "listeners": {
                "postgres": postgres,
                "mongodb": mongodb,
                "s3": s3,
            },
        }
    }))
}

/// Cached result of an observer reachability probe. Short TTL keeps LB
/// health polls cheap while still reflecting a broken observer within
/// seconds.
const OBSERVER_PROBE_TTL_SECS: u64 = 15;

#[derive(Clone)]
struct ObserverProbe {
    checked_at: Instant,
    body: Value,
}

/// Actively probe the observer's `/observer/chain/deployment/head` endpoint
/// from inside the VPC. Cached via `state.inner.observer_probe_cache` for
/// `OBSERVER_PROBE_TTL_SECS`, so an idle LB hitting `/health` 10×/sec does
/// not amplify into observer load.
async fn probe_observer(state: &HealthState) -> Value {
    let (url, secret) = match (
        state.inner.observer_url.as_ref(),
        state.inner.observer_read_secret.as_ref(),
    ) {
        (Some(url), Some(secret)) => (url.clone(), secret.clone()),
        _ => return json!({ "configured": false }),
    };

    // Fast path: serve from cache when fresh.
    {
        let cache = state.inner.observer_probe_cache.lock().await;
        if let Some(cached) = cache.as_ref() {
            if cached.checked_at.elapsed().as_secs() < OBSERVER_PROBE_TTL_SECS {
                return cached.body.clone();
            }
        }
    }

    let probe_url = format!(
        "{}/observer/chain/deployment/head",
        url.trim_end_matches('/')
    );
    let body = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()
    {
        Err(e) => json!({
            "configured": true,
            "reachable": false,
            "error": format!("http client init failed: {e}"),
        }),
        Ok(client) => {
            let res = client
                .get(&probe_url)
                .header("x-uninc-read-secret", secret)
                .send()
                .await;
            match res {
                Ok(resp) if resp.status().is_success() => match resp.json::<Value>().await {
                    Ok(body) => json!({
                        "configured": true,
                        "reachable": true,
                        "head_hash": body.get("head_hash").cloned().unwrap_or(Value::Null),
                    }),
                    Err(e) => json!({
                        "configured": true,
                        "reachable": false,
                        "error": format!("observer response not json: {e}"),
                    }),
                },
                Ok(resp) => json!({
                    "configured": true,
                    "reachable": false,
                    "error": format!("observer returned {}", resp.status()),
                }),
                Err(e) => json!({
                    "configured": true,
                    "reachable": false,
                    "error": format!("observer probe failed: {e}"),
                }),
            }
        }
    };

    let mut cache = state.inner.observer_probe_cache.lock().await;
    *cache = Some(ObserverProbe { checked_at: Instant::now(), body: body.clone() });
    body
}

#[cfg(test)]
mod tests {
    use super::*;
    use uninc_common::config::PoolConfig;

    #[test]
    fn health_state_with_caps_reports_ok_initially() {
        let pg = ConnectionCap::from_config(&PoolConfig::default(), "postgres");
        let state = HealthState::new(None).with_postgres_cap(pg);

        assert!(state.inner.postgres_cap.is_some());
        assert!(state.inner.mongodb_cap.is_none());
        assert_eq!(state.nats_publish().last_ok_ms(), 0);
        assert_eq!(state.chain_commit().last_ok_ms(), 0);
        assert_eq!(state.observer_head().last_ok_ms(), 0);
    }

    #[test]
    fn health_state_subsystem_lookup_returns_none_for_unknown() {
        let state = HealthState::new(None);
        assert!(state.subsystem("nats").is_some());
        assert!(state.subsystem("chain_commit").is_some());
        assert!(state.subsystem("observer_head").is_some());
        assert!(state.subsystem("bogus_subsystem").is_none());
    }
}
