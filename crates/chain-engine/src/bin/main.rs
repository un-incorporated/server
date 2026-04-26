use anyhow::{Context, Result};
use chain_engine::chain::ChainManager;
use chain_engine::consumer;
use chain_engine::deployment_chain::DeploymentChainManager;
use chain_engine::erasure_handler;
use chain_engine::multi_replica_storage::{MultiReplicaStorage, ReplicaHealthRelay};
use chain_engine::reaper::{self, ReaperConfig};
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;
use uninc_common::config::UnincConfig;
use uninc_common::nats_client::NatsClient;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::from_default_env().add_directive("chain_engine=info".parse()?),
        )
        .json()
        .init();

    info!("chain-engine starting");

    let nats_url = std::env::var("NATS_URL").unwrap_or_else(|_| "nats://localhost:4222".into());
    let subject_prefix =
        std::env::var("NATS_SUBJECT_PREFIX").unwrap_or_else(|_| "uninc.access".into());
    let storage_path =
        std::env::var("CHAIN_STORAGE_PATH").unwrap_or_else(|_| "/data/chains".into());
    // Spec §10.3: the per-deployment salt MUST be CSPRNG-generated. A
    // silent fallback to a literal string violates that requirement on
    // its face AND — if only one of {proxy, chain-engine, CLI} falls back
    // — produces a silent mismatch where chain_id_user hashes disagree
    // across processes and nothing works for reasons no error message
    // explains. Hard-fail on missing env var, same pattern the proxy uses.
    let salt = std::env::var("CHAIN_SERVER_SALT").context(
        "CHAIN_SERVER_SALT must be set — §10.3 requires a CSPRNG-generated \
         per-deployment secret (e.g. `openssl rand -hex 32`) shared between \
         proxy and chain-engine",
    )?;

    let storage = std::path::Path::new(&storage_path);

    // Optional: load the full UnincConfig for the durability tier.
    // If UNINC_CONFIG isn't set, we run in single-disk mode (single-host
    // topology). If it is set AND has a `chain.durability` section, we
    // build a MultiReplicaStorage and attach it to both managers.
    let durable_storage = load_durable_storage().await;

    let mut chain_manager = ChainManager::new(storage, &salt);
    let mut deployment_chain_manager =
        DeploymentChainManager::new(storage).expect("failed to initialize deployment chain manager");

    if let Some(storage_arc) = durable_storage.clone() {
        info!(
            replica_count = storage_arc.replica_count(),
            quorum = storage_arc.quorum(),
            bucket = storage_arc.bucket(),
            "attached MultiReplicaStorage durable tier to chain managers"
        );
        // Wire the per-replica health relay. Best-effort: if NATS isn't
        // reachable here, per-replica `/health/detailed` cells stay idle
        // until the next chain-engine restart, but writes keep working.
        // Same fail-soft pattern the reaper uses below for its own NATS
        // dependency.
        match async_nats::connect(&nats_url).await {
            Ok(core_client) => {
                let ops_prefix =
                    uninc_common::ops_health::ops_prefix_from_access(&subject_prefix);
                storage_arc.set_health_relay(Arc::new(ReplicaHealthRelay {
                    core_client,
                    ops_prefix,
                }));
                info!(
                    replicas = ?storage_arc.replica_ids(),
                    "wired per-replica health relay onto MultiReplicaStorage"
                );
            }
            Err(e) => {
                warn!(
                    error = %e,
                    "failed to connect NATS for replica-health relay; \
                     /health/detailed per-replica cells will stay idle"
                );
            }
        }
        chain_manager = chain_manager.with_durable(Arc::clone(&storage_arc));
        deployment_chain_manager = deployment_chain_manager.with_durable(storage_arc);
    } else {
        info!("no durable tier configured — running in single-disk mode");
    }

    let chain_manager = Arc::new(chain_manager);
    let deployment_chain_manager = Arc::new(deployment_chain_manager);

    info!("deployment chain storage at {storage_path}/_deployment");

    // Spawn the retention reaper. Runs daily, deletes chains older than
    // chain.retention_days through `ChainManager::delete_chain_by_hash`
    // (so both local fs and durable replicas get cleaned), and publishes
    // a §8.2 RetentionSweep tombstone per reaped chain to the deployment
    // chain.
    {
        let reaper_cfg = ReaperConfig {
            storage_root: PathBuf::from(&storage_path),
            retention_days: 365,
            run_interval: std::time::Duration::from_secs(24 * 60 * 60),
        };
        let reaper_cm = Arc::clone(&chain_manager);
        match NatsClient::connect(&nats_url, &subject_prefix).await {
            Ok(nats) => {
                let nats = Arc::new(nats);
                tokio::spawn(async move {
                    reaper::run_reaper(reaper_cfg, nats, reaper_cm).await;
                });
                info!("retention reaper spawned");
            }
            Err(e) => {
                warn!(error = %e, "failed to connect reaper NATS client; reaper disabled");
            }
        }
    }

    // Erasure request handler — core NATS request/reply on
    // `uninc.control.erasure`. Serves the proxy's DELETE
    // /api/v1/chain/u/{user_id} path per spec §7.3.1 + §8.1:
    //   1. commit UserErasureRequested tombstone → receipt
    //   2. delete per-user chain (local fs + durable replicas, quorum)
    //   3. reply receipt (or partial_failure envelope on step 2 failure)
    // Runs concurrently with the JetStream consumer.
    {
        let dcm = Arc::clone(&deployment_chain_manager);
        let cm = Arc::clone(&chain_manager);
        let nats_url_clone = nats_url.clone();
        tokio::spawn(async move {
            if let Err(e) =
                erasure_handler::run_erasure_handler(&nats_url_clone, dcm, cm).await
            {
                warn!(error = %e, "erasure handler exited");
            }
        });
        info!("erasure handler spawned");
    }

    consumer::run_consumer(&nats_url, &subject_prefix, chain_manager, deployment_chain_manager)
        .await?;

    info!("chain-engine shutting down");
    Ok(())
}

/// Build a [`MultiReplicaStorage`] from the `UNINC_CONFIG` YAML if it
/// declares `chain.durability` with at least one replica.
async fn load_durable_storage() -> Option<Arc<MultiReplicaStorage>> {
    let config_path = std::env::var("UNINC_CONFIG").ok()?;
    let config = match UnincConfig::load(std::path::Path::new(&config_path)) {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "failed to load UNINC_CONFIG for durability setup");
            return None;
        }
    };
    let durability = config.chain.durability?;
    if durability.replicas.is_empty() {
        return None;
    }
    match MultiReplicaStorage::from_config(&durability) {
        Ok(storage) => Some(Arc::new(storage)),
        Err(e) => {
            warn!(error = %e, "failed to build MultiReplicaStorage");
            None
        }
    }
}
