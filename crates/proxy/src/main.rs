use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;
use uninc_common::config::{
    PROXY_CHAIN_API_PORT, PROXY_HEALTH_PORT, PoolConfig, RateLimitConfig, UnincConfig,
};
use uninc_common::nats_client::NatsClient;
use uninc_proxy::chain_api::{self, ChainApiState};
use uninc_proxy::health::{
    HealthState, handle_health_basic, handle_health_detailed, handle_health_ready,
};
use uninc_proxy::jwt_replay::{DEFAULT_JTI_CAPACITY, JtiDenyList};
use uninc_proxy::pool::ConnectionCap;
use uninc_proxy::rate_limit::RateLimiter;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::from_default_env().add_directive("uninc_proxy=info".parse()?),
        )
        .json()
        .init();

    info!("uninc-proxy starting");

    // Load configuration
    let config_path = std::env::var("UNINC_CONFIG").unwrap_or_else(|_| "uninc.yml".into());
    let config = UnincConfig::load(Path::new(&config_path))?;

    // Connect to NATS
    let nats = NatsClient::connect(&config.proxy.nats.url, &config.proxy.nats.subject_prefix)
        .await?;
    nats.ensure_stream().await?;
    let nats = Arc::new(nats);

    // JWT_SECRET is loaded once here and shared by both the /health/detailed
    // endpoint (on :9090) and the chain read API (on :9091). Same HS256 secret
    // the frontend uses — there's no service account; customers sign their own
    // short-lived tokens with this secret.
    let jwt_secret = std::env::var("JWT_SECRET")
        .context("JWT_SECRET must be set on the proxy — used by both the chain API and /health/detailed")?
        .into_bytes();

    // Shared `jti` replay deny-list (protocol spec §10.5). Every JWT-gated
    // surface on the proxy — the chain API on :9091 and /health/detailed on
    // :9090 — shares this instance, so a token sniffed from one surface
    // cannot be replayed against the other. Capacity overridable via
    // UNINC_JTI_CAPACITY; default is 100k entries.
    let jti_capacity = std::env::var("UNINC_JTI_CAPACITY")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(DEFAULT_JTI_CAPACITY);
    let jti_deny = Arc::new(JtiDenyList::new(jti_capacity));
    info!(capacity = jti_capacity, "jwt jti replay deny-list initialized");

    // Construct HealthState before the verification engine — the engine's
    // scheduled task needs an `Arc<SubsystemHealth>` for the observer-head
    // subsystem, stamped on each observer HTTP read attempt. Constructing
    // health here keeps the observer-head cell alive for the full lifetime
    // of the task.
    // Observer details are read from the verification block so that a single
    // `uninc.yml` drives both the scheduled-verification observer reads and
    // the `/health` endpoint's reachability probe. When no observer is
    // configured (single-host / Playground), both fields are None and
    // `/health` omits the `observer` block entirely.
    let (observer_url, observer_read_secret) = match &config.verification {
        Some(v) => (v.observer_url.clone(), v.observer_read_secret.clone()),
        None => (None, None),
    };
    // Pre-register per-replica health cells from the chain-durability
    // config. chain-engine stamps these cells over NATS after each
    // fan-out write — see chain_engine::multi_replica_storage. Empty when
    // running single-host (no durability section).
    let replica_ids: Vec<String> = config
        .chain
        .durability
        .as_ref()
        .map(|d| d.replicas.iter().map(|r| r.replica_id.clone()).collect())
        .unwrap_or_default();
    let mut health = HealthState::new(Some(nats.clone()))
        .with_jwt_secret(jwt_secret.clone())
        .with_jti_deny(Arc::clone(&jti_deny))
        .with_observer(observer_url, observer_read_secret)
        .with_replicas(&replica_ids);
    if !replica_ids.is_empty() {
        info!(
            replica_count = replica_ids.len(),
            replicas = ?replica_ids,
            "registered per-replica health cells on /health/detailed"
        );
    }

    // Wire the NATS client's internal publish-stamping to the `nats`
    // subsystem cell on `HealthState`. Every publish through this client
    // will now mark the cell ok or err automatically — no listener call
    // site needs to import the health crate to participate.
    nats.set_health_cell(health.nats_publish());

    // Cross-process subsystem-health relay: chain-engine (and any other
    // process that shares the NATS server) publishes
    // `uninc.ops.subsystem_health.{name}` pings; this subscriber stamps
    // the matching cell on `HealthState`. Without this, the
    // `chain_commit` subsystem on `/health/detailed` would stay idle
    // forever because the proxy never directly sees chain-engine's
    // successes or failures.
    let ops_prefix = uninc_common::ops_health::ops_prefix_from_access(
        &config.proxy.nats.subject_prefix,
    );
    {
        let health_for_sub = health.clone();
        let ops_prefix = ops_prefix.clone();
        let raw_client = nats.core_client().clone();
        uninc_common::ops_health::spawn_subsystem_health_subscriber(
            raw_client,
            ops_prefix,
            move |name| health_for_sub.subsystem(name),
        );
    }

    // Cross-process `FailureEvent` relay: chain-engine publishes
    // `uninc.ops.failure_event.*` pings once its consecutive-quorum-
    // failure counter crosses `QUORUM_ALERT_THRESHOLD`. This subscriber
    // translates each ping into a `FailureEvent` and dispatches it
    // through a local `FailureHandlerChain`, giving chain-engine the
    // same alert → deny-list → lockdown escalation the scheduled
    // verification task uses when it detects divergence.
    //
    // FOLLOWUP: the `CredentialDenyList` and `ReadOnlyLockdown`
    // constructed here are independent from the ones used by the
    // scheduled verification task. For full cross-process enforcement
    // they should be shared (and wired into the proxy's query path);
    // today neither consumer of those handles is plumbed yet, so
    // separate instances are behaviorally equivalent to one.
    if let Some(ref verify_config) = config.verification {
        if verify_config.enabled {
            let failure_chain_for_ops = Arc::new(verification::failure::build_default_chain(
                &verify_config.on_failure,
                Arc::clone(&nats),
                verification::failure::CredentialDenyList::default(),
                verification::failure::ReadOnlyLockdown::default(),
                None,
            ));
            let replica_count = verify_config.replica_count as usize;
            let raw_client = nats.core_client().clone();
            uninc_common::ops_failure::spawn_failure_event_subscriber(
                raw_client,
                ops_prefix.clone(),
                move |ping| {
                    let chain = Arc::clone(&failure_chain_for_ops);
                    async move {
                        let Some(event) =
                            verification::failure::ping_to_failure_event(ping, replica_count)
                        else {
                            return;
                        };
                        let outcomes = chain.handle(event).await;
                        info!(
                            handler_outcomes = outcomes.len(),
                            "cross-process failure_event dispatched"
                        );
                    }
                },
            );
        }
    }

    // Phase 3 — instantiate the verification engine (multi-VM topology only).
    // Spawns periodic and nightly verification tasks.
    // All verification triggers publish results to the deployment chain via NATS
    // (actor_id: "uninc-verifier", category: System).
    let verification_engine: Option<Arc<verification::VerificationEngine>> =
        if let Some(ref verify_config) = config.verification {
            if verify_config.enabled {
                // Build the per-DB verifier registry. Postgres + MongoDB
                // are real; S3 is a scaffold. See verification/src/verifiers/.
                let registry = verification::verifiers::VerifierRegistry::new()
                    .with_postgres(
                        verification::verifiers::postgres::PostgresVerifier::new(
                            vec![],
                        ),
                    )
                    .with_mongodb(
                        verification::verifiers::mongodb::MongoVerifier::new(),
                    )
                    .with_s3(verification::verifiers::s3::S3Verifier::new());

                let engine = Arc::new(
                    verification::VerificationEngine::new(
                        verify_config.clone(),
                        Some(nats.clone()),
                    )
                    .with_verifiers(registry),
                );

                // T3 nightly cross-replica verification — the only
                // trigger in v1. Runs in the background, once per day at
                // jittered 02:00–04:00 UTC. See verification/src/task.rs.
                // T1 (per-session), T2 (periodic), and T4 (reshuffle)
                // are deferred — see FOLLOWUPS.md §"trigger expansion".
                //
                // The `observer_head` subsystem cell is passed in so the
                // task can stamp `/health/detailed` on every observer
                // HTTP read attempt — operators see a red subsystem
                // within seconds of the observer VM going offline rather
                // than waiting for the next scheduled summary to miss.
                {
                    let engine_clone = Arc::clone(&engine);
                    let nats_clone = nats.clone();
                    let observer_head_cell = health.observer_head();
                    // Process 2 (§5.5.2) prerequisites: a local chain
                    // reader and the deployment salt, both of which
                    // are already loaded for the chain-API below.
                    let proxy_chain: Option<
                        Arc<dyn verification::task::ProxyChainReader>,
                    > = Some(Arc::new(
                        verification::task::LocalDiskProxyChainReader::new(
                            std::env::var("CHAIN_STORAGE_PATH")
                                .unwrap_or_else(|_| "/data/chains".into()),
                        ),
                    ));
                    let deployment_salt = std::env::var("CHAIN_SERVER_SALT")
                        .unwrap_or_else(|_| String::new());
                    tokio::spawn(async move {
                        verification::triggers::start_scheduled_verification_task(
                            engine_clone,
                            nats_clone,
                            Some(observer_head_cell),
                            proxy_chain,
                            deployment_salt,
                        )
                        .await;
                    });
                }

                info!(
                    replica_count = verify_config.replica_count,
                    "verification engine started with nightly (T3) background task"
                );
                Some(engine)
            } else {
                None
            }
        } else {
            None
        };

    // Spawn protocol listeners based on config
    let mut handles = Vec::new();

    // S3 HTTP proxy
    if let Some(ref s3_config) = config.proxy.s3 {
        if s3_config.enabled {
            let s3_cfg = s3_config.clone();
            let identity_cfg = config.proxy.identity.clone();
            let nats_clone = Some(nats.clone());
            // S3 doesn't have a `pool` / `rate_limit` field in S3Config (the
            // struct predates round-1 overload protection). Use the Postgres
            // listener's config as the shared capacity + rate-limit knob if
            // present, else default.
            let s3_pool_cfg: PoolConfig = config
                .proxy
                .postgres
                .as_ref()
                .map(|p| p.pool.clone())
                .unwrap_or_default();
            let s3_rate_cfg: RateLimitConfig = config
                .proxy
                .postgres
                .as_ref()
                .map(|p| p.rate_limit.clone())
                .unwrap_or_default();
            let s3_cap = ConnectionCap::from_config(&s3_pool_cfg, "s3");
            let s3_rl = Arc::new(RateLimiter::new(s3_rate_cfg));
            health = health.with_s3_cap(s3_cap.clone());
            let handle = tokio::spawn(async move {
                info!(
                    port = uninc_common::config::PROXY_S3_PORT,
                    "starting S3 proxy"
                );
                if let Err(e) = uninc_proxy::s3::server::start(
                    s3_cfg,
                    identity_cfg,
                    nats_clone,
                    s3_cap,
                    s3_rl,
                )
                .await
                {
                    error!(error = %e, "S3 proxy failed");
                }
            });
            handles.push(handle);
        }
    }

    // PostgreSQL proxy
    #[cfg(feature = "postgres")]
    if let Some(ref pg_config) = config.proxy.postgres {
        if pg_config.enabled {
            let pg_cfg = pg_config.clone();
            let identity_cfg = config.proxy.identity.clone();
            let schema_cfg = config.proxy.schema.clone();
            let nats_clone = Some(nats.clone());
            let pg_cap = ConnectionCap::from_config(&pg_cfg.pool, "postgres");
            let pg_rl = Arc::new(RateLimiter::new(pg_cfg.rate_limit.clone()));
            health = health.with_postgres_cap(pg_cap.clone());
            let ve_clone = verification_engine.clone();
            // Sidechannel actor-marker (spec §5.5 byte-identity
            // support). Writes one row to `uninc_audit_marker` before
            // each forwarded admin query so the observer's WAL reader
            // can recover the actor id. Failure is non-fatal — the
            // proxy still serves traffic; observer attribution falls
            // back to a placeholder that won't byte-match.
            let pg_marker: Option<
                Arc<dyn uninc_proxy::postgres::actor_marker::ActorMarkerEmitter>,
            > = match uninc_proxy::postgres::actor_marker::PgActorMarker::connect(
                &pg_cfg.upstream,
            )
            .await
            {
                Ok(m) => {
                    info!("postgres actor-marker sidechannel connected");
                    Some(Arc::new(m) as Arc<_>)
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "postgres actor-marker sidechannel unavailable — observer attribution \
                         will fall back to placeholder (see server/SPEC-DELTA.md)"
                    );
                    None
                }
            };
            let handle = tokio::spawn(async move {
                info!(
                    port = uninc_common::config::PROXY_POSTGRES_PORT,
                    "starting PostgreSQL proxy"
                );
                if let Err(e) = uninc_proxy::postgres::listener::start_listener(
                    &pg_cfg.upstream,
                    identity_cfg,
                    schema_cfg,
                    nats_clone,
                    pg_cap,
                    pg_cfg.timeouts.clone(),
                    pg_rl,
                    ve_clone,
                    pg_marker,
                )
                .await
                {
                    error!(error = %e, "PostgreSQL proxy failed");
                }
            });
            handles.push(handle);
        }
    }

    // MongoDB proxy
    #[cfg(feature = "mongodb")]
    if let Some(ref mongo_config) = config.proxy.mongodb {
        if mongo_config.enabled {
            let mongo_cap = ConnectionCap::from_config(&mongo_config.pool, "mongodb");
            let mongo_rl = Arc::new(RateLimiter::new(mongo_config.rate_limit.clone()));
            health = health.with_mongodb_cap(mongo_cap.clone());
            // Sidechannel client for actor-marker emission (spec §5.5
            // byte-identity support). Construction failure is WARN
            // rather than fatal so playground/single-VM topologies
            // without an observer still boot; in production the marker
            // client MUST connect or observer attribution degrades
            // silently.
            let marker: Option<Arc<dyn uninc_proxy::mongodb::actor_marker::ActorMarkerEmitter>> =
                match uninc_proxy::mongodb::actor_marker::MongoActorMarker::connect(
                    &mongo_config.upstream,
                )
                .await
                {
                    Ok(m) => {
                        info!("mongo actor-marker sidechannel connected");
                        Some(Arc::new(m) as Arc<_>)
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            "mongo actor-marker sidechannel unavailable — observer attribution \
                             will fall back to placeholder actor_id_hash (see server/SPEC-DELTA.md)"
                        );
                        None
                    }
                };
            let state = Arc::new(uninc_proxy::mongodb::listener::MongoListenerState {
                listener_config: mongo_config.clone(),
                identity_config: config.proxy.identity.clone(),
                schema_config: config.proxy.schema.clone(),
                nats: nats.clone(),
                cap: mongo_cap,
                rate_limiter: mongo_rl,
                marker,
            });
            let handle = tokio::spawn(async move {
                info!("starting MongoDB proxy");
                if let Err(e) = uninc_proxy::mongodb::listener::start(state).await {
                    error!(error = %e, "MongoDB proxy failed");
                }
            });
            handles.push(handle);
        }
    }

    if handles.is_empty() {
        error!("no protocol listeners enabled — check uninc.yml");
        return Ok(());
    }

    info!(listeners = handles.len(), "all protocol listeners started");

    // Item E — /health endpoints. Three routes, split by information
    // sensitivity (see health.rs docs):
    //
    //   /health          — open, minimal {"status":"ok"} for LB liveness
    //   /health/ready    — open, 200/503 readiness probe, minimal body
    //   /health/detailed — JWT-gated (aud: "health-detailed"), rich body
    //                      with NATS state, pool utilization, rollup
    //
    // The open routes leak nothing beyond "process is up / serving." The
    // rich body moves behind the same HS256 secret the chain API uses.
    let health_state = health;
    let health_handle = tokio::spawn(async move {
        let app = axum::Router::new()
            .route("/health", axum::routing::get(handle_health_basic))
            .route("/health/ready", axum::routing::get(handle_health_ready))
            .route(
                "/health/detailed",
                axum::routing::get(handle_health_detailed),
            )
            .with_state(health_state);
        let bind = format!("0.0.0.0:{PROXY_HEALTH_PORT}");
        let listener = tokio::net::TcpListener::bind(&bind).await.unwrap();
        info!(port = PROXY_HEALTH_PORT, "health check endpoint ready");
        axum::serve(listener, app).await.unwrap();
    });
    handles.push(health_handle);

    // Transparency chain read API — a SECOND Axum listener on :9091, separate
    // from :9090/health. JWT-gated via `chain_api::auth`. Reads per-user chain
    // files from /data/chains (same path chain-engine writes to) via the
    // shared `chain-store` crate. See server/docs/chain-api.md.
    //
    // Env vars are REQUIRED — fail fast rather than silently drift from the
    // chain-engine writer.
    let chain_data_dir = PathBuf::from(
        std::env::var("CHAIN_STORAGE_PATH").unwrap_or_else(|_| "/data/chains".into()),
    );
    let chain_server_salt = std::env::var("CHAIN_SERVER_SALT").context(
        "CHAIN_SERVER_SALT must be set on the proxy — it MUST match chain-engine's \
         value or the reader will 404 every user's chain",
    )?;
    let chain_state = Arc::new(ChainApiState {
        data_dir: chain_data_dir.clone(),
        server_salt: chain_server_salt,
        jwt_secret: jwt_secret.clone(),
        jti_deny: Arc::clone(&jti_deny),
        // In production the NatsClient doubles as the TombstoneWriter —
        // its `request_erasure_tombstone` round-trips to chain-engine via
        // core NATS request/reply. See uninc-common/src/nats_client.rs.
        tombstone_writer: nats.clone(),
    });
    let chain_handle = tokio::spawn(async move {
        let app = chain_api::router(chain_state);
        let bind = format!("0.0.0.0:{PROXY_CHAIN_API_PORT}");
        let listener = match tokio::net::TcpListener::bind(&bind).await {
            Ok(l) => l,
            Err(e) => {
                error!(error = %e, port = PROXY_CHAIN_API_PORT, "chain api bind failed");
                return;
            }
        };
        info!(
            port = PROXY_CHAIN_API_PORT,
            data_dir = %chain_data_dir.display(),
            "chain api endpoint ready"
        );
        if let Err(e) = axum::serve(listener, app).await {
            error!(error = %e, "chain api listener failed");
        }
    });
    handles.push(chain_handle);

    // Wait for any listener to exit (shouldn't under normal operation)
    let (result, _index, _remaining) = futures::future::select_all(handles).await;
    if let Err(e) = result {
        error!(error = %e, "a listener task panicked");
    }

    info!("uninc-proxy shutting down");
    Ok(())
}
