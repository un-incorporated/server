//! NATS JetStream consumer: deserialize events, route to per-user or deployment chain.
//!
//! Handles two subject families:
//! - `uninc.access.{target}` — admin database operations (AccessEvent)
//! - `uninc.system._deployment` — system-level events like verification results (DeploymentEvent)

use crate::chain::{ChainError, ChainManager};
use crate::deployment_chain::{DeploymentChainError, DeploymentChainManager};
use anyhow::Result;
use async_nats::jetstream;
use dashmap::DashMap;
use futures::StreamExt;
use std::sync::Arc;
use tracing::{error, info, warn};
use uninc_common::ops_failure::{publish_failure_event, ChainFailurePing};
use uninc_common::ops_health::{publish_subsystem_health, SubsystemHealthPing};
use uninc_common::{AccessEvent, DeploymentEvent};

/// Consecutive chain-commit failures per chain id before chain-engine
/// escalates from "log ERROR" to "publish `FailureEvent` via ops relay".
/// Three picked as the floor where a single transient blip (e.g. one
/// replica VM restarting) doesn't fire an alert, but a sustained outage
/// (network partition, chain-MinIO sidecar crashed) does.
pub const QUORUM_ALERT_THRESHOLD: u32 = 3;

/// Wall-clock duration a chain must be failing before the stuck-consumer
/// detector upgrades its signal from threshold-based to duration-based.
/// Chosen so that one stuck chain pins `/health/detailed` to `down`
/// within a small multiple of the natural JetStream redelivery interval
/// (`AckWait`, default ~30s). Higher than 2–3 redeliveries so transient
/// hiccups don't page anyone; lower than the marketing-claim "tamper
/// detection within 4 hours" so we still beat the outer SLO.
pub const STUCK_CONSUMER_ALERT_SECS: u64 = 300;

/// Per-chain failure record: consecutive count AND the wall-clock time
/// the current failure streak started. The timestamp lets the stuck-
/// consumer detector report "stuck for N seconds" in logs and failure
/// pings, and lets the converter on the proxy side escalate severity
/// by duration (not just count).
#[derive(Debug, Clone, Copy)]
pub struct FailureRecord {
    pub count: u32,
    /// Unix millis at which `count` went 0 → 1.
    pub first_failure_ms: i64,
}

/// Tracks consecutive chain-commit failures keyed by chain id. Reset to
/// zero on the next successful commit for that chain. Concurrency via
/// `DashMap` so per-chain write paths don't contend on a single lock.
#[derive(Default)]
pub struct QuorumFailureTracker {
    records: DashMap<String, FailureRecord>,
}

impl QuorumFailureTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Increment and return the updated record for `chain_id`. On the
    /// transition 0 → 1, `first_failure_ms` is set to now; subsequent
    /// failures preserve it.
    pub fn record_failure(&self, chain_id: &str) -> FailureRecord {
        let now = uninc_common::health::now_ms();
        let mut entry = self
            .records
            .entry(chain_id.to_string())
            .or_insert(FailureRecord {
                count: 0,
                first_failure_ms: now,
            });
        entry.count += 1;
        *entry
    }

    /// Reset the counter on success. Returns the previous record (if any)
    /// so the caller can decide whether to emit a "recovered" log line.
    pub fn record_success(&self, chain_id: &str) -> Option<FailureRecord> {
        self.records.remove(chain_id).map(|(_, v)| v)
    }

    /// Snapshot of every currently-failing chain. Used by the stuck-
    /// consumer detector task to walk the tracker without holding a
    /// `DashMap` guard across an await.
    pub fn snapshot(&self) -> Vec<(String, FailureRecord)> {
        self.records
            .iter()
            .map(|r| (r.key().clone(), *r.value()))
            .collect()
    }

    #[cfg(test)]
    pub fn current_count(&self, chain_id: &str) -> u32 {
        self.records.get(chain_id).map(|r| r.count).unwrap_or(0)
    }
}

/// Launch the stuck-consumer detector. Every `tick_secs`, walks the
/// tracker and for each chain that has been failing for longer than
/// `STUCK_CONSUMER_ALERT_SECS`:
/// - logs CRITICAL with the chain id, consecutive count, and duration,
/// - stamps `uninc.ops.subsystem_health.chain_commit = err(stuck for Ns)`
///   so `/health/detailed` shows the chain as down within a tick
///   regardless of whether a fresh per-message failure has arrived.
///
/// Returns the task handle; the caller can `.abort()` at shutdown.
/// Failing to publish the ops stamp on a tick is best-effort (warn log)
/// — the next tick will try again.
pub fn spawn_stuck_consumer_detector(
    tracker: Arc<QuorumFailureTracker>,
    core_client: async_nats::Client,
    ops_prefix: String,
    tick: std::time::Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tick);
        // First tick fires immediately; skip it so we let the consumer
        // accumulate at least a few seconds of operation before we
        // start walking the tracker.
        interval.tick().await;
        loop {
            interval.tick().await;
            let now = uninc_common::health::now_ms();
            for (chain_id, record) in tracker.snapshot() {
                let stuck_ms = now - record.first_failure_ms;
                if stuck_ms < (STUCK_CONSUMER_ALERT_SECS as i64) * 1000 {
                    continue;
                }
                let stuck_secs = stuck_ms / 1000;
                error!(
                    chain_id,
                    consecutive_failures = record.count,
                    stuck_secs,
                    "🚨 CRITICAL: chain consumer stuck — no successful commit for {stuck_secs}s"
                );
                let reason = format!(
                    "consumer stuck on {chain_id} for {stuck_secs}s ({} consecutive failures)",
                    record.count
                );
                if let Err(e) = publish_subsystem_health(
                    &core_client,
                    &ops_prefix,
                    "chain_commit",
                    &SubsystemHealthPing::err(reason),
                )
                .await
                {
                    warn!(error = %e, "stuck-consumer detector: failed to publish err stamp");
                }
            }
        }
    })
}

/// Ops-relay handles used by the consumer to stamp subsystem health and
/// publish failure events. Held by value in the consumer loop so each
/// error path can reach them without plumbing three extra arguments.
pub struct OpsRelay {
    pub core_client: async_nats::Client,
    pub ops_prefix: String,
}

/// Start the NATS consumer loop.
///
/// Consumes events from the UNINC_ACCESS stream and routes them:
/// - `uninc.access._deployment` → deployment chain via `DeploymentChainManager::append_from_access_event`
/// - `uninc.access.{user_id}` → per-user chain via `ChainManager::append_event`
/// - `uninc.system._deployment` → deployment chain via `DeploymentChainManager::append_deployment_event`
///
/// Every commit outcome stamps `uninc.ops.subsystem_health.chain_commit`
/// on core NATS so the proxy's `/health/detailed` endpoint reflects
/// chain-engine liveness. Persistent quorum failures (>= `QUORUM_ALERT_THRESHOLD`
/// consecutive) additionally publish a `ChainCommitFailed` ping on
/// `uninc.ops.failure_event.*` that the proxy dispatches through the
/// verification crate's `FailureHandlerChain`.
pub async fn run_consumer(
    nats_url: &str,
    subject_prefix: &str,
    chain_manager: Arc<ChainManager>,
    deployment_chain_manager: Arc<DeploymentChainManager>,
) -> Result<()> {
    let client = async_nats::connect(nats_url).await?;
    let jetstream = jetstream::new(client.clone());

    // Derive ops prefix from the access prefix and stash a core NATS
    // client for the ops relay. Failing to build the relay is logged
    // but not fatal — the consumer must still run; losing only the
    // health/failure stamps is a downgrade, not a show-stopper.
    let ops_relay = OpsRelay {
        core_client: client.clone(),
        ops_prefix: uninc_common::ops_health::ops_prefix_from_access(subject_prefix),
    };
    let tracker = Arc::new(QuorumFailureTracker::new());

    // Wire 3: stuck-consumer detector. Runs as a separate task so the
    // duration-based alert fires even if no new message arrives to
    // trip the count-based Wire 1 path. Tick every 30s — a full tick
    // period longer than the JetStream AckWait default so a chain
    // that's currently being retried has its counter up before the
    // detector checks it.
    spawn_stuck_consumer_detector(
        Arc::clone(&tracker),
        client,
        ops_relay.ops_prefix.clone(),
        std::time::Duration::from_secs(30),
    );

    // Derive system prefix: uninc.access → uninc.system
    let system_prefix = subject_prefix
        .rsplit_once('.')
        .map(|(base, _)| format!("{base}.system"))
        .unwrap_or_else(|| format!("{subject_prefix}.system"));

    // Get or create the stream
    let stream = jetstream
        .get_or_create_stream(jetstream::stream::Config {
            name: "UNINC_ACCESS".to_string(),
            subjects: vec![
                format!("{subject_prefix}.>"),
                format!("{system_prefix}.>"),
            ],
            retention: jetstream::stream::RetentionPolicy::WorkQueue,
            max_age: std::time::Duration::from_secs(7 * 24 * 3600),
            storage: jetstream::stream::StorageType::File,
            ..Default::default()
        })
        .await?;

    // Create a durable pull consumer
    let consumer = stream
        .get_or_create_consumer(
            "chain-engine",
            jetstream::consumer::pull::Config {
                durable_name: Some("chain-engine".to_string()),
                ack_policy: jetstream::consumer::AckPolicy::Explicit,
                ..Default::default()
            },
        )
        .await?;

    info!("NATS consumer started, waiting for events...");

    // Pull messages continuously
    let mut messages = consumer.messages().await?;

    while let Some(msg_result) = messages.next().await {
        let msg = match msg_result {
            Ok(m) => m,
            Err(e) => {
                error!(error = %e, "failed to receive message");
                continue;
            }
        };

        let subject = msg.subject.as_str();

        // Route by subject family: uninc.system.* or uninc.access.*
        if subject.starts_with(&system_prefix) {
            // System event → deployment chain directly
            let event: DeploymentEvent = match serde_json::from_slice(&msg.payload) {
                Ok(e) => e,
                Err(e) => {
                    error!(error = %e, subject, "failed to deserialize DeploymentEvent, acking to skip");
                    let _ = msg.ack().await;
                    continue;
                }
            };

            match deployment_chain_manager
                .append_deployment_event(
                    &event.actor_id,
                    event.actor_type,
                    event.category,
                    event.action,
                    &event.resource,
                    &event.scope,
                    event.details,
                    event.artifact_hash,
                    event.session_id,
                    event.source_ip.as_deref(),
                )
                .await
            {
                Ok(_) => {
                    on_commit_success(&tracker, &ops_relay, "_deployment").await;
                    let _ = msg.ack().await;
                }
                Err(e) => {
                    on_commit_failure_deployment(&tracker, &ops_relay, "_deployment", &e).await;
                }
            }
        } else {
            // Access event → deployment chain or per-user chain
            let event: AccessEvent = match serde_json::from_slice(&msg.payload) {
                Ok(e) => e,
                Err(e) => {
                    error!(error = %e, subject, "failed to deserialize AccessEvent, acking to skip");
                    let _ = msg.ack().await;
                    continue;
                }
            };

            let target = subject
                .strip_prefix(&format!("{subject_prefix}."))
                .unwrap_or("unknown");

            if target == "_deployment" {
                match deployment_chain_manager.append_from_access_event(&event).await {
                    Ok(()) => {
                        on_commit_success(&tracker, &ops_relay, "_deployment").await;
                        let _ = msg.ack().await;
                    }
                    Err(e) => {
                        on_commit_failure_deployment(&tracker, &ops_relay, "_deployment", &e).await;
                    }
                }
            } else {
                match chain_manager.append_event(target, &event).await {
                    Ok(()) => {
                        on_commit_success(&tracker, &ops_relay, target).await;
                        let _ = msg.ack().await;
                    }
                    Err(e) => {
                        on_commit_failure_user(
                            &tracker,
                            &ops_relay,
                            target,
                            &e,
                            deployment_chain_manager.as_ref(),
                        )
                        .await;
                    }
                }
            }
        }
    }

    warn!("NATS consumer stream ended");
    Ok(())
}

/// Record a successful commit. Resets the failure counter for this
/// chain, logs a recovery line if the counter was non-zero, and stamps
/// `subsystem_health.chain_commit = ok` on the ops relay.
async fn on_commit_success(
    tracker: &QuorumFailureTracker,
    relay: &OpsRelay,
    chain_id: &str,
) {
    let prev_count = tracker
        .record_success(chain_id)
        .map(|r| r.count)
        .unwrap_or(0);
    if prev_count > 0 {
        info!(
            chain_id,
            prior_failures = prev_count,
            "chain commit recovered after {prev_count} consecutive failures"
        );
    }
    if let Err(e) = publish_subsystem_health(
        &relay.core_client,
        &relay.ops_prefix,
        "chain_commit",
        &SubsystemHealthPing::ok(),
    )
    .await
    {
        // Best-effort channel; a NATS hiccup publishing the ok ping is
        // not worth raising — the next successful commit republishes.
        warn!(error = %e, "failed to publish chain_commit ok stamp");
    }
}

/// Classify a deployment-chain commit error, stamp ops_health, and
/// escalate via `publish_failure_event` once the consecutive-failure
/// threshold is crossed.
async fn on_commit_failure_deployment(
    tracker: &QuorumFailureTracker,
    relay: &OpsRelay,
    chain_id: &str,
    err: &DeploymentChainError,
) {
    let is_quorum = matches!(err, DeploymentChainError::QuorumFailed(_));
    let reason = err.to_string();
    on_commit_failure_common(tracker, relay, chain_id, is_quorum, &reason, None).await;
}

async fn on_commit_failure_user(
    tracker: &QuorumFailureTracker,
    relay: &OpsRelay,
    chain_id: &str,
    err: &ChainError,
    deployment_chain_manager: &DeploymentChainManager,
) {
    let is_quorum = matches!(err, ChainError::QuorumFailed(_));
    let reason = err.to_string();
    on_commit_failure_common(
        tracker,
        relay,
        chain_id,
        is_quorum,
        &reason,
        // Pass the deployment chain manager so common can attempt a
        // best-effort DeploymentEvent write. We deliberately do NOT pass it
        // in the deployment-chain failure path above — the deployment
        // chain IS the thing that's failing, so reentrant writes would
        // just stack the same problem.
        Some(deployment_chain_manager),
    )
    .await;
}

async fn on_commit_failure_common(
    tracker: &QuorumFailureTracker,
    relay: &OpsRelay,
    chain_id: &str,
    is_quorum: bool,
    reason: &str,
    best_effort_deployment: Option<&DeploymentChainManager>,
) {
    let record = tracker.record_failure(chain_id);
    let count = record.count;
    // Severity of the log line tracks the severity of the condition:
    // every transient failure is ERROR; crossing the threshold is
    // CRITICAL, logged once and accompanied by a `ChainCommitFailed`
    // ping that the proxy turns into a `FailureEvent`.
    if count == QUORUM_ALERT_THRESHOLD && is_quorum {
        error!(
            chain_id,
            consecutive_failures = count,
            reason,
            "🚨 CRITICAL: chain commit has failed {count} times in a row — escalating via \
             ops.failure_event relay"
        );
    } else {
        error!(
            chain_id,
            consecutive_failures = count,
            reason,
            "chain commit failed — will retry on redelivery"
        );
    }

    // Always stamp the subsystem health err, regardless of the threshold.
    // Operators see the last reason on `/health/detailed` within seconds
    // of the first failure, not only after the threshold crosses.
    if let Err(e) = publish_subsystem_health(
        &relay.core_client,
        &relay.ops_prefix,
        "chain_commit",
        &SubsystemHealthPing::err(reason.to_string()),
    )
    .await
    {
        warn!(error = %e, "failed to publish chain_commit err stamp");
    }

    // Escalate on threshold crossing (only for quorum failures — a
    // serialization bug or a malformed event shouldn't page anyone).
    if is_quorum && count >= QUORUM_ALERT_THRESHOLD {
        let ping = ChainFailurePing::ChainCommitFailed {
            chain_id: chain_id.to_string(),
            consecutive_failures: count,
            last_reason: reason.to_string(),
        };
        if let Err(e) = publish_failure_event(&relay.core_client, &relay.ops_prefix, &ping).await {
            warn!(
                error = %e,
                "failed to publish failure_event — handler chain will not be invoked for this \
                 quorum failure"
            );
        }

        // Wire 2: best-effort "quorum_failed" DeploymentEvent on the
        // deployment chain, local-hot-only. Emitted ONCE on threshold
        // crossing so we don't spam the chain with thousands of
        // repetitions if the outage is long. A future reconciliation
        // pass re-publishes the locally-held entry to the durable
        // tier once quorum returns.
        //
        // Safe to skip entirely when the chain that's failing IS the
        // deployment chain — `best_effort_deployment` is None in that
        // case so we avoid reentrant storms.
        if count == QUORUM_ALERT_THRESHOLD {
            if let Some(dcm) = best_effort_deployment {
                let mut details = std::collections::HashMap::new();
                details.insert("chain_id".into(), chain_id.to_string());
                details.insert("consecutive_failures".into(), count.to_string());
                details.insert("reason".into(), reason.to_string());
                match dcm
                    .append_deployment_event_best_effort(
                        "chain-engine",
                        uninc_common::ActorType::System,
                        uninc_common::DeploymentCategory::System,
                        uninc_common::ActionType::Write,
                        "chain-engine",
                        "quorum_failed",
                        Some(details),
                        None,
                        None,
                        None,
                    )
                    .await
                {
                    Ok(outcome) => {
                        info!(
                            chain_id,
                            signal_index = outcome.index,
                            durable = outcome.durable,
                            "emitted quorum_failed DeploymentEvent on deployment chain \
                             (durable={} — reconciliation pending if false)",
                            outcome.durable
                        );
                    }
                    Err(e) => {
                        warn!(
                            chain_id,
                            error = %e,
                            "failed to emit quorum_failed DeploymentEvent best-effort — \
                             signal lost for this outage"
                        );
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tracker_increments_and_resets_per_chain() {
        let t = QuorumFailureTracker::new();
        assert_eq!(t.record_failure("a").count, 1);
        assert_eq!(t.record_failure("a").count, 2);
        assert_eq!(t.record_failure("b").count, 1);
        assert_eq!(t.current_count("a"), 2);
        assert_eq!(t.current_count("b"), 1);

        assert_eq!(t.record_success("a").map(|r| r.count), Some(2));
        assert_eq!(t.current_count("a"), 0);
        // success on a chain that never failed returns None
        assert_eq!(t.record_success("c").map(|r| r.count), None);
    }

    #[test]
    fn tracker_is_chain_scoped() {
        // Failures on chain A must not affect the counter on chain B.
        // This is the invariant the alert threshold depends on: one
        // stuck per-user chain can't trigger cross-chain alerts.
        let t = QuorumFailureTracker::new();
        for _ in 0..5 {
            t.record_failure("chain-a");
        }
        assert_eq!(t.current_count("chain-a"), 5);
        assert_eq!(t.current_count("chain-b"), 0);
        t.record_success("chain-b");
        assert_eq!(t.current_count("chain-a"), 5);
    }

    #[test]
    fn tracker_preserves_first_failure_ms_across_increments() {
        // The stuck-consumer detector's duration signal depends on
        // first_failure_ms being pinned at the 0→1 transition and NOT
        // updated on subsequent failures. Guard against an accidental
        // rewrite that would reset the clock every tick.
        let t = QuorumFailureTracker::new();
        let r1 = t.record_failure("x");
        std::thread::sleep(std::time::Duration::from_millis(10));
        let r2 = t.record_failure("x");
        assert_eq!(r1.first_failure_ms, r2.first_failure_ms);
        assert_eq!(r2.count, 2);
    }

    #[test]
    fn tracker_snapshot_returns_all_failing_chains() {
        let t = QuorumFailureTracker::new();
        t.record_failure("alpha");
        t.record_failure("alpha");
        t.record_failure("beta");
        let mut snap = t.snapshot();
        snap.sort_by_key(|(k, _)| k.clone());
        assert_eq!(snap.len(), 2);
        assert_eq!(snap[0].0, "alpha");
        assert_eq!(snap[0].1.count, 2);
        assert_eq!(snap[1].0, "beta");
        assert_eq!(snap[1].1.count, 1);
    }
}
