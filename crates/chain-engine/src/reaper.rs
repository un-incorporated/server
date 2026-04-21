//! Chain retention reaper.
//!
//! Runs as a tokio task inside chain-engine, sleeping between runs. On each
//! tick it walks the chain storage root, reads `meta.json` for each chain,
//! and deletes entries older than `chain.retention_days` (default 365 days).
//!
//! Each reaped batch publishes a `RetentionSweep` tombstone to the
//! deployment chain via NATS. The tombstone is quorum-replicated across
//! replica MinIOs (multi-VM topology) or persisted on the single
//! proxy-local MinIO (single-host topology), so the retention action is
//! itself tamper-evident.
//!
//! GDPR Article 17 (right-to-erasure) deletion is a separate path — see
//! the `DELETE /api/v1/chain/u/:user_id_hash` handler in the proxy chain
//! API. That path also emits a tombstone (category: UserErasureRequested)
//! before removing the target chain directory.

use crate::chain::ChainManager;
use futures::future::FutureExt;
use std::panic::AssertUnwindSafe;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::fs;
use tracing::{debug, error, info, warn};
use uninc_common::nats_client::NatsClient;
use uninc_common::types::{ActionType, ActorType, DeploymentCategory, DeploymentEvent};

/// The deployment chain lives at `<storage_root>/_deployment` and is NOT
/// a per-user chain — it MUST NOT be reaped. Every other directory under
/// the storage root is a per-user chain keyed by `user_id_hash`.
const DEPLOYMENT_CHAIN_DIR: &str = "_deployment";

/// Maximum wall-clock time a single reaper run may take before we give
/// up and wait for the next interval. A stuck NATS publish or a pathological
/// directory walk can't stall the task forever.
const REAPER_MAX_DURATION: Duration = Duration::from_secs(30 * 60);

/// Floor on the run interval so a misconfigured `run_interval = 0`
/// never causes a hot loop.
const REAPER_MIN_INTERVAL: Duration = Duration::from_secs(60);

/// Sleep between unrecoverable scheduler errors.
const REAPER_ERROR_BACKOFF: Duration = Duration::from_secs(5 * 60);

#[derive(Debug, Clone)]
pub struct ReaperConfig {
    /// Root of chain storage, e.g. `/data/chains`.
    pub storage_root: PathBuf,
    /// Keep entries at most this old. Default 365 days.
    pub retention_days: u32,
    /// How often to run the reaper. Default 24 hours.
    pub run_interval: Duration,
}

impl Default for ReaperConfig {
    fn default() -> Self {
        Self {
            storage_root: PathBuf::from("/data/chains"),
            retention_days: 365,
            run_interval: Duration::from_secs(24 * 60 * 60),
        }
    }
}

/// Run the retention reaper as a tokio task. Never returns — call via
/// `tokio::spawn`. The loop is error-tolerant at three layers:
///
///   1. `run_once` returns a `Result` that we match on — errors log
///      at warn level and the loop continues with the next sleep.
///   2. `tokio::time::timeout` bounds each run so a stuck NATS publish
///      or a pathological directory walk can't stall the task forever.
///   3. `AssertUnwindSafe + catch_unwind` catches panics from inside
///      `run_once` so one corrupt `meta.json` or a bug in the reaper
///      never kills the task for the rest of the process lifetime.
pub async fn run_reaper(
    cfg: ReaperConfig,
    nats: Arc<NatsClient>,
    chain_manager: Arc<ChainManager>,
) {
    info!(
        storage_root = %cfg.storage_root.display(),
        retention_days = cfg.retention_days,
        "chain retention reaper started"
    );

    let interval = cfg.run_interval.max(REAPER_MIN_INTERVAL);

    loop {
        let run_future = run_once(&cfg, &nats, &chain_manager);
        let outcome = tokio::time::timeout(
            REAPER_MAX_DURATION,
            AssertUnwindSafe(run_future).catch_unwind(),
        )
        .await;

        match outcome {
            Ok(Ok(Ok(()))) => {
                // run_once succeeded; fall through to the normal interval sleep.
            }
            Ok(Ok(Err(e))) => {
                warn!(error = %e, "reaper run failed — continuing");
            }
            Ok(Err(panic)) => {
                let msg = panic_message(&panic);
                error!(%msg, "reaper run PANICKED — loop continuing");
                tokio::time::sleep(REAPER_ERROR_BACKOFF).await;
            }
            Err(_elapsed) => {
                error!(
                    timeout_secs = REAPER_MAX_DURATION.as_secs(),
                    "reaper run TIMED OUT — loop continuing"
                );
                tokio::time::sleep(REAPER_ERROR_BACKOFF).await;
            }
        }

        tokio::time::sleep(interval).await;
    }
}

fn panic_message(boxed: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = boxed.downcast_ref::<&'static str>() {
        (*s).to_string()
    } else if let Some(s) = boxed.downcast_ref::<String>() {
        s.clone()
    } else {
        "<non-string panic payload>".to_string()
    }
}

async fn run_once(
    cfg: &ReaperConfig,
    nats: &NatsClient,
    chain_manager: &ChainManager,
) -> std::io::Result<()> {
    let cutoff_secs = (cfg.retention_days as u64) * 24 * 60 * 60;
    let cutoff = std::time::SystemTime::now()
        .checked_sub(Duration::from_secs(cutoff_secs))
        .unwrap_or(std::time::UNIX_EPOCH);

    let mut reaped_chains = 0usize;
    let mut reaped_entries = 0usize;

    // The chain storage layout is:
    //   <storage_root>/_deployment/...
    //   <storage_root>/<user_id_hash>/...
    //
    // For each directory directly under storage_root, check its meta.json
    // created time. If older than cutoff, delete the chain via
    // `ChainManager::delete_chain_by_hash` so both local fs and the
    // durable replica tier get cleaned. If newer, skip (this is a
    // coarse-grained reap — finer-grained per-entry reap would require
    // parsing the JSON-lines format, which is more expensive and only
    // matters once individual chains start living longer than the
    // retention window — see ROADMAP.md v1.1 "Per-entry retention sweeps").
    let mut entries = match fs::read_dir(&cfg.storage_root).await {
        Ok(d) => d,
        Err(e) => {
            warn!(error = %e, "reaper: cannot read storage root, skipping run");
            return Ok(());
        }
    };

    while let Ok(Some(entry)) = entries.next_entry().await {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }

        let dir_name = match path.file_name().and_then(|n| n.to_str()) {
            Some(s) => s.to_string(),
            None => continue,
        };

        // The deployment chain is not a per-user chain and retention does
        // not apply to it — skip.
        if dir_name == DEPLOYMENT_CHAIN_DIR {
            continue;
        }

        let meta_path = path.join("meta.json");
        let Ok(meta_bytes) = fs::read(&meta_path).await else {
            debug!(path = %path.display(), "reaper: skipping (no meta.json)");
            continue;
        };
        let Ok(meta) = serde_json::from_slice::<serde_json::Value>(&meta_bytes) else {
            debug!(path = %path.display(), "reaper: skipping (meta.json unreadable)");
            continue;
        };

        // `created_at` is Unix seconds as written by
        // `chain_store::storage::ChainStore::update_meta_count`. A prior
        // version of this reaper read `created_at_ms` with an
        // `unwrap_or(0)` fallback, which silently treated every chain as
        // UNIX_EPOCH and reaped everything on the first run. Skip (do NOT
        // default to 0) if the field is missing or non-numeric; the next
        // append will stamp a fresh `created_at` and the chain becomes
        // reapable on a later run.
        let Some(created_secs) = meta.get("created_at").and_then(|v| v.as_i64()) else {
            debug!(
                path = %path.display(),
                "reaper: skipping (meta.json missing created_at)"
            );
            continue;
        };
        if created_secs < 0 {
            debug!(
                path = %path.display(),
                created_secs,
                "reaper: skipping (meta.json created_at is negative)"
            );
            continue;
        }
        let created =
            std::time::UNIX_EPOCH + Duration::from_secs(created_secs as u64);
        if created >= cutoff {
            continue;
        }

        let entry_count = meta.get("entry_count").and_then(|v| v.as_u64()).unwrap_or(0);

        // Route through ChainManager so both local fs and durable replicas
        // are deleted under the same code path the GDPR erasure handler uses.
        // If quorum fails on the durable tier, surface as a warn! and DO NOT
        // emit a RetentionSweep tombstone — a tombstone implies "this chain
        // is gone," and if the durable replicas still hold it, the tombstone
        // would be a lie.
        if let Err(e) = chain_manager.delete_chain_by_hash(&dir_name).await {
            warn!(
                chain = %dir_name,
                error = %e,
                "reaper: delete_chain_by_hash failed (local or durable) — tombstone not emitted"
            );
            continue;
        }

        reaped_chains += 1;
        reaped_entries += entry_count as usize;

        info!(
            chain = %dir_name,
            entry_count,
            "reaper: deleted chain older than retention cutoff"
        );

        // Publish a RetentionSweep tombstone to the deployment chain per §8.2.
        // Field names and units match the spec: `created_at` in Unix seconds,
        // not `created_at_ms` in milliseconds.
        let mut details = std::collections::HashMap::new();
        details.insert("chain_id".into(), dir_name.clone());
        details.insert("entry_count".into(), entry_count.to_string());
        details.insert("created_at".into(), created_secs.to_string());
        details.insert("retention_days".into(), cfg.retention_days.to_string());

        let event = DeploymentEvent {
            actor_id: "system:retention-reaper".into(),
            actor_type: ActorType::System,
            category: DeploymentCategory::RetentionSweep,
            action: ActionType::Delete,
            resource: "chain".into(),
            scope: format!("retention sweep removed chain {dir_name}"),
            details: Some(details),
            artifact_hash: None,
            timestamp: chrono::Utc::now().timestamp(),
            session_id: None,
            source_ip: None,
        };

        if let Err(e) = nats.publish_system_deployment_event(&event).await {
            warn!(error = %e, "reaper: failed to publish RetentionSweep tombstone");
        }
    }

    if reaped_chains > 0 {
        info!(
            reaped_chains,
            reaped_entries, "reaper: run complete"
        );
    }

    Ok(())
}
