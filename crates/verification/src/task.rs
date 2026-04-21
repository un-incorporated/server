//! Scheduled Verification task — runs once per **Tick** (UAT §5.5).
//!
//! Terminology aligned with UAT §5.5:
//!
//! - A **Tick** is the moment a Scheduled Verification is triggered. Two
//!   trigger sources race through a `tokio::select!`:
//!     - **Periodic timer** (default 4h via `SCHEDULED_PERIOD`): upper
//!       bound on how long the system can go without running a pass.
//!     - **Session-end trigger** (`VerificationEngine::session_end_notify`):
//!       fires whenever an admin session closes; `notify_one`-coalesced.
//!
//! - **Scheduled Verification** is the work that runs on each Tick.
//!   Per UAT §5.5 it runs TWO processes:
//!
//!     **Process 1 — Per-user chain cross-replica verification**
//!     (UAT §5.5.1). For each chain in `{deployment} ∪ {active
//!     per-user chains}`, read `(entry_count, head_hash)` from every
//!     replica, compare to a baseline replica, and fire the failure
//!     handler on any divergence. Head-hash equality under identical
//!     `entry_count` is the invariant.
//!
//!     **Process 2 — Deployment chain observer-proxy verification**
//!     (UAT §5.5.2). Walk the proxy's deployment-chain
//!     `ObservedDeploymentEvent`-projectable entries and the
//!     observation chain's `ObservedDeploymentEvent` entries in
//!     lockstep from their persisted cursors. On byte-matching
//!     canonicalized payloads advance both cursors; on first mismatch
//!     emit a `VerificationFailure` DeploymentEvent carrying both
//!     payloads and stop. The un-compared tail (longer side's
//!     suffix) stays unverified until the slower side catches up —
//!     no time-based alarm.
//!
//! What this task does each Tick, in order:
//!
//!   1. Drand round for entropy provenance (best-effort).
//!   2. Count active / ended sessions for the summary.
//!   3. **Process 1**: cross-replica head-hash check on the deployment
//!      chain. (Per-user chains covered when engine exposes the chain-
//!      list iterator — currently gapped; see server/SPEC-DELTA.md.)
//!   4. **Process 2**: observer-proxy entry walk on the deployment
//!      chain.
//!   5. Publish a `NightlyVerification` DeploymentEvent summary (spec-
//!      locked category name; Rust identifiers decoupled from cadence).
//!   6. Fire the failure handler on any Process 1 or Process 2
//!      divergence.

use crate::engine::VerificationEngine;
use crate::failure::{
    build_default_chain, CredentialDenyList, FailureEvent, FailureHandlerChain,
    ReadOnlyLockdown, Severity,
};
use crate::observer_client::{EntriesPage, HttpObserverClient, ObserverError, ObserverHeadReader};
use crate::verifiers::VerifierRegistry;
use chain_store::{canonicalize_payload, ChainEntry, EventPayload};
use chain_engine::observed_projection::project_to_observed;
use futures::future::FutureExt;
use std::collections::HashMap;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{error, info, warn};
use uninc_common::nats_client::NatsClient;
use uninc_common::types::{ActionType, ActorType, DeploymentCategory, DeploymentEvent};

/// Maximum wall-clock time a single scheduled run may take before we give
/// up on it and schedule the next. A stuck replica or a slow network
/// path can't stall the scheduler forever.
const SCHEDULED_RUN_MAX_DURATION: Duration = Duration::from_secs(30 * 60);

/// Periodic tick — upper bound on how long the system goes without
/// running a verification pass. 4h matches the longest expected admin
/// session; session-end triggers will typically fire sooner than this.
const SCHEDULED_PERIOD: Duration = Duration::from_secs(4 * 60 * 60);

/// Debounce between consecutive runs, whether triggered by timer or
/// session-end. A burst of session-ends in the same second shouldn't
/// queue multiple runs; the first run dispatches, subsequent notifies
/// are coalesced into the NEXT select iteration.
const SCHEDULED_RUN_MIN_INTERVAL: Duration = Duration::from_secs(60);

/// Sleep between unrecoverable scheduler errors. If the pipeline itself
/// panics or times out, we need to back off before retrying.
const SCHEDULER_ERROR_BACKOFF: Duration = Duration::from_secs(5 * 60);

/// Backoff between the first observer HTTP attempt and the retry.
/// Short enough to stay inside the scheduled-run wall clock, long
/// enough to let a transient blip (observer restart, brief network
/// hiccup) clear.
const OBSERVER_RETRY_BACKOFF: Duration = Duration::from_secs(2);

/// Synthetic replica ID used to represent the observer in
/// `FailureEvent::VerificationDivergence::replicas_disagreed`. Chosen
/// as a distinct string so handlers can tell observer-vs-proxy divergence
/// (emitted from Process 2's per-payload byte comparison) apart from
/// replica-to-replica divergence (Process 1's cross-replica head
/// comparison, which tags divergences as `{chain_id}@{replica_id}`)
/// without needing a new enum variant. Used by Process 2's
/// `verification_failure` dispatch below.
const OBSERVER_SENTINEL_ID: &str = "observer";

pub struct ScheduledVerificationConfig {
    /// Which chain to head-compare across replicas. Usually `"_deployment"`.
    pub deployment_chain_id: String,
    /// How old a session must be to be included in the run's window.
    /// Default: 24 hours.
    pub window: chrono::Duration,
}

impl Default for ScheduledVerificationConfig {
    fn default() -> Self {
        Self {
            deployment_chain_id: "_deployment".to_string(),
            window: chrono::Duration::hours(24),
        }
    }
}

pub struct ScheduledVerificationReport {
    pub sessions_checked: usize,
    /// Process 1 (§5.5.1): number of (replica, chain) pairs whose head
    /// disagreed with the baseline replica for the same chain.
    pub head_divergences: usize,
    /// Process 1 (§5.5.1): number of per-user chains the iteration
    /// walked through this Tick (independent of the deployment chain).
    pub per_user_chains_checked: usize,
    /// Process 1 (§5.5.1): number of per-user chains that had at
    /// least one replica disagreeing with the baseline.
    pub per_user_chains_divergent: usize,
    pub session_divergences: usize,
    pub clean: bool,
    /// Process 2 (§5.5.2): whether the observer-proxy entry walk
    /// actually ran this tick. False when no observer is configured or
    /// the observer was unreachable even after retry.
    pub observer_compared: bool,
    /// Process 2 (§5.5.2): true when the entry walk found a byte-
    /// mismatching pair (proxy projection ≠ observer payload).
    pub observer_divergent: bool,
    /// Process 2 (§5.5.2): number of entry pairs the walk advanced
    /// through on this tick (i.e., how many observation-chain entries
    /// were verified against their proxy counterpart).
    pub observer_entries_verified: u64,
    /// Process 2 (§5.5.2): current depth of the unverified tail on
    /// the longer side after the walk stops. `0` when both cursors are
    /// fully caught up.
    pub observer_tail_depth: u64,
}

/// State Process 2 persists across Ticks: the cursor pair for each
/// chain being walked. `cursor_prx` is the index into the proxy's
/// deployment chain (counting every entry, not just projectable
/// ones); `cursor_obs` is the index into the observation chain.
///
/// See UAT §5.5.2: both cursors advance monotonically; they are NOT
/// advanced when a byte-mismatch is detected, so the next Tick
/// re-observes the same mismatch unless the divergent entry has been
/// redressed.
#[derive(Debug, Clone, Default)]
pub struct Process2Cursors {
    pub cursor_prx: u64,
    pub cursor_obs: u64,
}

#[allow(clippy::too_many_arguments)]
pub async fn run_scheduled_verification(
    engine: Arc<VerificationEngine>,
    verifiers: Arc<VerifierRegistry>,
    failure_chain: Arc<FailureHandlerChain>,
    nats: Arc<NatsClient>,
    cfg: &ScheduledVerificationConfig,
    last_head_per_replica: &RwLock<HashMap<String, [u8; 32]>>,
    observer: Option<Arc<dyn ObserverHeadReader>>,
    // Stamped on each observer HTTP read attempt so `/health/detailed`
    // reflects observer reachability without waiting for the next
    // scheduled summary. `None` when the deployment has no observer,
    // or when health is not plumbed (test harnesses).
    observer_health: Option<Arc<uninc_common::SubsystemHealth>>,
    // Process 2 (§5.5.2) state: the cursor pair for the deployment
    // chain's observer-proxy walk. Persisted across Ticks. Takes a
    // RwLock so concurrent health-endpoint reads can inspect the
    // cursor without blocking the task.
    cursors: &RwLock<Process2Cursors>,
    // Process 2 (§5.5.2) proxy-side chain reader — used to pull the
    // proxy's deployment chain entries for projection. `None` disables
    // Process 2 (legacy test harnesses / Playground with no local
    // chain store).
    proxy_chain: Option<Arc<dyn ProxyChainReader>>,
    // Deployment salt — HMAC key used by `project_to_observed` to
    // derive `actor_id_hash`. Must match the proxy's
    // `chain.server_salt` and the observer's `deployment_salt`.
    deployment_salt: &str,
) -> ScheduledVerificationReport {
    info!("🗓️  scheduled verification starting");

    let config = engine.config();
    let replicas = &config.replicas;

    // 1. Fetch drand round (best-effort; fall back to Utc::now() marker).
    let drand = crate::entropy::DrandClient::new();
    let drand_round = match drand.latest_round().await {
        Ok(r) => Some(r),
        Err(e) => {
            warn!(error = %e, "scheduled verification: drand fetch failed, proceeding without proof");
            None
        }
    };

    // 2. Freeze session window (session iteration is done inside the
    //    engine today; we just count active+total for the summary).
    let total_sessions = engine.total_session_count().await;
    let active_sessions = engine.active_session_count().await;
    let sessions_checked = total_sessions.saturating_sub(active_sessions);

    // 3. Process 1 — per-user chain cross-replica verification (UAT
    //    §5.5.1). For each chain in {deployment} ∪ {per-user chains},
    //    pick one replica's head as baseline and verify every other
    //    replica matches it. Any divergence goes into
    //    `head_divergences` with a "(chain_id, replica_id)" pair so
    //    the summary event records exactly which replica + chain
    //    disagreed.
    //
    //    Chain enumeration: the deployment chain is hard-coded; per-
    //    user chain IDs come from the proxy's local chain-store via
    //    `proxy_chain.list_chain_ids()`. If no proxy reader is wired
    //    (Playground / tests), Process 1 runs against the deployment
    //    chain only and logs that per-user iteration was skipped.
    //
    //    Scope note (v0.1-pre): today Process 1 verifies EVERY chain
    //    on the proxy's disk, not just "active since last Tick."
    //    Active-since-last-Tick filtering is a scale optimization
    //    tracked in server/SPEC-DELTA.md; at small-customer scale
    //    (thousands of chains) the full scan fits comfortably inside
    //    the SCHEDULED_RUN_MAX_DURATION budget.
    let mut head_divergences: Vec<String> = vec![];
    let mut per_user_chains_checked: usize = 0;
    let mut per_user_chains_divergent: usize = 0;
    {
        let verifier = verifiers
            .get(uninc_common::types::Protocol::Postgres)
            .or_else(|| verifiers.get(uninc_common::types::Protocol::S3));
        if let Some(verifier) = verifier {
            // First — the deployment chain. Process 2 no longer uses
            // the baseline head (entry-walk comparison supersedes the
            // head-byte check), so the baseline is only needed inside
            // the helper to detect cross-replica drift.
            let deployment_outcome = verify_chain_cross_replica(
                verifier.as_ref(),
                replicas,
                &cfg.deployment_chain_id,
            )
            .await;
            if !deployment_outcome.divergent_replicas.is_empty() {
                for replica_id in &deployment_outcome.divergent_replicas {
                    head_divergences.push(format!(
                        "{}@{}",
                        cfg.deployment_chain_id, replica_id
                    ));
                }
            }
            *last_head_per_replica.write().await = deployment_outcome.per_replica_head;

            // Then — every per-user chain the proxy holds. Enumerate
            // via the proxy reader; run the same per-chain helper.
            if let Some(chain_reader) = proxy_chain.as_ref() {
                match chain_reader.list_chain_ids().await {
                    Ok(chain_ids) => {
                        for chain_id in &chain_ids {
                            per_user_chains_checked += 1;
                            let outcome = verify_chain_cross_replica(
                                verifier.as_ref(),
                                replicas,
                                chain_id,
                            )
                            .await;
                            if !outcome.divergent_replicas.is_empty() {
                                per_user_chains_divergent += 1;
                                for replica_id in &outcome.divergent_replicas {
                                    head_divergences
                                        .push(format!("{}@{}", chain_id, replica_id));
                                }
                            }
                        }
                        info!(
                            per_user_chains_checked,
                            per_user_chains_divergent,
                            "process 1: per-user chain iteration complete"
                        );
                    }
                    Err(e) => {
                        warn!(
                            error = %e,
                            "process 1: failed to enumerate per-user chain ids — \
                             deployment chain was still checked"
                        );
                    }
                }
            } else {
                info!(
                    "process 1: no proxy chain reader — per-user chain iteration skipped \
                     (deployment chain was still checked)"
                );
            }
        } else {
            warn!("no registered verifier can read chain heads — skipping Process 1");
        }
    }

    // 4. Process 2 — deployment-chain observer-proxy entry walk
    //    (UAT §5.5.2). Walk the proxy's deployment chain and the
    //    observation chain from their persisted cursors in lockstep;
    //    advance both cursors on each byte-match; stop on first
    //    mismatch and fire the failure handler.
    //
    //    Skips when:
    //      - no observer is configured (single-host / Playground), OR
    //      - no proxy-chain reader was passed (legacy test harness).
    //
    //    The tail on whichever side is longer stays unverified —
    //    §5.5.2 "by construction" rule — so legitimate replication lag
    //    does not trigger verification_failure. A persistent tail
    //    surfaces through `observer_tail_depth` on the summary event;
    //    no automatic alarm, no Δ_lag.
    let mut proc2 = Process2Outcome::default();
    let mut proc2_failure: Option<Process2Failure> = None;
    if let (Some(reader), Some(chain_reader)) = (observer.as_ref(), proxy_chain.as_ref()) {
        let (cursor_prx, cursor_obs) = {
            let guard = cursors.read().await;
            (guard.cursor_prx, guard.cursor_obs)
        };
        match run_process_2(
            reader.as_ref(),
            chain_reader.as_ref(),
            &cfg.deployment_chain_id,
            cursor_prx,
            cursor_obs,
            deployment_salt,
            observer_health.as_deref(),
        )
        .await
        {
            Ok(outcome) => {
                // Advance cursors regardless of whether a byte
                // mismatch occurred — the task.rs convention is "stop
                // AT the mismatch; do not consume it." `run_process_2`
                // returns cursors pointing at the first unverified
                // entry (past the last verified pair), which is what
                // we persist. On byte mismatch the cursors point AT
                // the mismatching pair — the next Tick re-reads and
                // re-fails on the same entries unless the divergence
                // was redressed, which is the spec's "cursors NOT
                // advanced on rejection" behaviour (see §5.5.2
                // step 5).
                let mut guard = cursors.write().await;
                guard.cursor_prx = outcome.cursor_prx;
                guard.cursor_obs = outcome.cursor_obs;
                drop(guard);
                proc2 = outcome;
                if let Some(f) = proc2.failure.take() {
                    proc2_failure = Some(f);
                }
            }
            Err(e) => {
                warn!(
                    error = %e,
                    "process 2: observer entry read failed after retry — \
                     treating as infrastructure failure, not tampering"
                );
                proc2.compared = false;
                proc2.unreachable_reason = Some(e.to_string());
            }
        }
    } else if observer.is_none() {
        info!("no observer configured — skipping Process 2");
    } else {
        info!("no proxy chain reader — skipping Process 2 (Playground / test)");
    }
    let observer_compared = proc2.compared;
    let observer_divergent = proc2.divergent;
    let observer_unreachable_reason = proc2.unreachable_reason.clone();

    // 5. Session-level verification (placeholder: engine doesn't yet expose
    //    a "list recently-ended sessions" iterator, so we rely on T1's
    //    per-session dispatch. The scheduled run remains head-check + summary.)

    // 6. Publish summary to deployment chain.
    let mut details = HashMap::new();
    details.insert("trigger".into(), "T3".into());
    details.insert("sessions_checked".into(), sessions_checked.to_string());
    details.insert("head_divergences".into(), head_divergences.len().to_string());
    details.insert(
        "per_user_chains_checked".into(),
        per_user_chains_checked.to_string(),
    );
    details.insert(
        "per_user_chains_divergent".into(),
        per_user_chains_divergent.to_string(),
    );
    details.insert("observer_compared".into(), observer_compared.to_string());
    details.insert("observer_divergent".into(), observer_divergent.to_string());
    details.insert(
        "observer_entries_verified".into(),
        proc2.entries_verified.to_string(),
    );
    details.insert(
        "observer_tail_depth".into(),
        proc2.tail_depth.to_string(),
    );
    if let Some(ref r) = drand_round {
        details.insert("drand_round".into(), r.round.to_string());
        details.insert("drand_chain".into(), drand.chain_hash().to_string());
    }

    let summary_scope = if head_divergences.is_empty() {
        "scheduled verification passed".to_string()
    } else {
        format!(
            "scheduled verification failed: {} divergent party/parties",
            head_divergences.len()
        )
    };

    let org_event = DeploymentEvent {
        actor_id: "uninc-verifier".to_string(),
        actor_type: ActorType::System,
        // §4.11 / Appendix A.1 CC7.2: the scheduled cross-replica head
        // check is recorded under the spec-locked `nightly_verification`
        // category name. The Rust identifier carries a cadence hint from
        // when the task only ran nightly; the category string is part of
        // the wire format and is not renamed here. See the module doc
        // comment for the naming rationale.
        category: DeploymentCategory::NightlyVerification,
        action: ActionType::Read,
        resource: "chain-heads".to_string(),
        scope: summary_scope,
        details: Some(details),
        artifact_hash: None,
        timestamp: chrono::Utc::now().timestamp(),
        session_id: None,
        source_ip: None,
    };
    if let Err(e) = nats.publish_system_deployment_event(&org_event).await {
        error!(error = %e, "scheduled verification: deployment chain publish failed");
    }

    // 6b. Observer-unreachable DeploymentEvent. Distinct from the
    // VerificationFailure / NightlyVerification events above so
    // auditors can tell "infrastructure is broken, check unknown"
    // apart from "check ran and disagreed."
    if let Some(reason) = observer_unreachable_reason {
        let mut infra_details = HashMap::new();
        infra_details.insert("component".into(), "observer".into());
        infra_details.insert("reason".into(), reason);
        let infra_event = DeploymentEvent {
            actor_id: "uninc-verifier".to_string(),
            actor_type: ActorType::System,
            category: DeploymentCategory::System,
            action: ActionType::Read,
            resource: "observer-head".to_string(),
            scope: "observer head unreachable after retry".to_string(),
            details: Some(infra_details),
            artifact_hash: None,
            timestamp: chrono::Utc::now().timestamp(),
            session_id: None,
            source_ip: None,
        };
        if let Err(e) = nats.publish_system_deployment_event(&infra_event).await {
            error!(error = %e, "scheduled verification: observer-unreachable publish failed");
        }
    }

    // 7. Fire failure handler on Process 1 divergence. `head_divergences`
    //    carries `{chain_id}@{replica_id}` tuples from Process 1's
    //    cross-replica head comparison. Observer-vs-proxy payload
    //    mismatches are reported separately below by Process 2's own
    //    failure dispatch (see the `proc2_failure` block), which tags
    //    `replicas_disagreed` with `OBSERVER_SENTINEL_ID` so downstream
    //    handlers can distinguish replica divergence from observer
    //    divergence without a new enum variant. `observer_divergent`
    //    here reflects step 4's best-effort head-byte probe, which is
    //    log-only pending emitter alignment — it does not contribute to
    //    `head_divergences`.
    if !head_divergences.is_empty() {
        let reason = "scheduled verification: replica head divergence".to_string();
        let event = FailureEvent::VerificationDivergence {
            severity: Severity::Critical,
            session_id: None,
            admin_id: None,
            replicas_disagreed: head_divergences.clone(),
            reason,
        };
        failure_chain.handle(event).await;
    }

    let clean = head_divergences.is_empty();
    info!(
        clean,
        observer_compared,
        observer_divergent,
        "🗓️  scheduled verification complete"
    );
    // Fire Process 2 failure handler if the entry walk found a byte
    // mismatch. Distinct from the Process 1 `head_divergences` above
    // — they share the same handler chain so one divergence path
    // triggers lockdown / credential-deny / alert either way, but
    // the failure event carries the specific Process 2 payload
    // pointers in `details` so operators can jump straight to the
    // offending entries.
    if let Some(f) = &proc2_failure {
        let mut details = HashMap::new();
        details.insert("process".into(), "2".into());
        details.insert("chain_id".into(), cfg.deployment_chain_id.clone());
        details.insert("cursor_prx".into(), f.cursor_prx.to_string());
        details.insert("cursor_obs".into(), f.cursor_obs.to_string());
        details.insert("proxy_payload".into(), hex::encode(&f.proxy_payload));
        details.insert("observed_payload".into(), hex::encode(&f.observed_payload));
        if let Some(side) = f.canon_error_side {
            // Distinguishes canon-failure from a byte-level mismatch so
            // operators can jump straight to the poisoned entry rather
            // than chasing a non-existent payload disagreement.
            details.insert("canon_error_side".into(), side.into());
        }
        let event = DeploymentEvent {
            actor_id: "uninc-verifier".to_string(),
            actor_type: ActorType::System,
            category: DeploymentCategory::VerificationFailure,
            action: ActionType::Read,
            resource: cfg.deployment_chain_id.clone(),
            scope: "process 2: observer-proxy payload byte mismatch".to_string(),
            details: Some(details),
            artifact_hash: None,
            timestamp: chrono::Utc::now().timestamp(),
            session_id: None,
            source_ip: None,
        };
        if let Err(e) = nats.publish_system_deployment_event(&event).await {
            error!(error = %e, "process 2: failed to publish verification_failure event");
        }
        let fire = FailureEvent::VerificationDivergence {
            severity: Severity::Critical,
            session_id: None,
            admin_id: None,
            replicas_disagreed: vec![OBSERVER_SENTINEL_ID.to_string()],
            reason: format!(
                "process 2: observer-proxy payload mismatch at cursor_prx={}, cursor_obs={}",
                f.cursor_prx, f.cursor_obs,
            ),
        };
        failure_chain.handle(fire).await;
    }

    ScheduledVerificationReport {
        sessions_checked,
        head_divergences: head_divergences.len(),
        per_user_chains_checked,
        per_user_chains_divergent,
        session_divergences: 0,
        clean: clean && proc2_failure.is_none(),
        observer_compared,
        observer_divergent,
        observer_entries_verified: proc2.entries_verified,
        observer_tail_depth: proc2.tail_depth,
    }
}

/// Fetch the observer's head for `chain_id`, retrying once on transient
/// errors (timeout / 5xx / transport). Returns the observer's reported
/// head (or `None` for empty chain) on success; the last error on
/// failure.
#[allow(dead_code)] // Retained as a liveness probe helper; Process 2
                    // does the real verification via `read_entries`.
async fn fetch_observer_head_with_retry(
    observer: &dyn ObserverHeadReader,
    chain_id: &str,
) -> Result<Option<[u8; 32]>, crate::observer_client::ObserverError> {
    match observer.read_head(chain_id).await {
        Ok(head) => Ok(head),
        Err(first_err) if first_err.is_retryable() => {
            warn!(
                error = %first_err,
                backoff_ms = OBSERVER_RETRY_BACKOFF.as_millis() as u64,
                "observer head read failed — retrying once"
            );
            tokio::time::sleep(OBSERVER_RETRY_BACKOFF).await;
            observer.read_head(chain_id).await
        }
        Err(fatal) => Err(fatal),
    }
}

// ─── Process 1 (UAT §5.5.1) ────────────────────────────────────────────

/// Outcome of one chain's cross-replica head-hash comparison. Used by
/// Process 1 to iterate over `{deployment} ∪ {per-user chains}` and
/// collect divergences for the summary event.
struct ChainCrossReplicaOutcome {
    /// Every replica whose head disagreed with the baseline.
    divergent_replicas: Vec<String>,
    /// Per-replica head record. Read by the caller to populate
    /// `last_head_per_replica` for the scheduler's "did the head
    /// change at all" heuristic.
    per_replica_head: HashMap<String, [u8; 32]>,
}

/// Verify one chain's head-hash consistency across every replica.
///
/// Picks the first replica's view as the baseline and compares every
/// other replica to it. Read errors on individual replicas are logged
/// and do NOT count as divergences (infrastructure failure, not
/// tampering). Applies to both the deployment chain and every per-
/// user chain; called once per chain per Tick by Process 1.
async fn verify_chain_cross_replica(
    verifier: &dyn crate::verifiers::ReplicaStateVerifier,
    replicas: &[uninc_common::config::ReplicaConfig],
    chain_id: &str,
) -> ChainCrossReplicaOutcome {
    let mut baseline: Option<[u8; 32]> = None;
    let mut divergent_replicas: Vec<String> = vec![];
    let mut per_replica_head: HashMap<String, [u8; 32]> = HashMap::new();

    for replica in replicas {
        match verifier
            .verify_chain_head(replica, chain_id, &baseline.unwrap_or([0u8; 32]))
            .await
        {
            Ok(crate::verifiers::HeadMatch::Same) if baseline.is_some() => {
                if let Some(b) = baseline {
                    per_replica_head.insert(replica.id.clone(), b);
                }
            }
            Ok(crate::verifiers::HeadMatch::Different { observed }) => {
                if baseline.is_none() {
                    baseline = Some(observed);
                    per_replica_head.insert(replica.id.clone(), observed);
                } else {
                    divergent_replicas.push(replica.id.clone());
                    per_replica_head.insert(replica.id.clone(), observed);
                }
            }
            Ok(crate::verifiers::HeadMatch::Same) => {
                // No baseline yet; wait for next replica.
            }
            Err(e) => {
                warn!(
                    replica = replica.id.as_str(),
                    chain_id,
                    error = %e,
                    "process 1: replica head read failed"
                );
            }
        }
    }

    let _ = baseline; // baseline no longer consumed by callers; kept
                      // for the duration of the loop above to drive
                      // the match-vs-diverge decision.
    ChainCrossReplicaOutcome {
        divergent_replicas,
        per_replica_head,
    }
}

// ─── Process 2 (UAT §5.5.2) ────────────────────────────────────────────

/// Trait exposed by the proxy to Processes 1 and 2 so the verification
/// task can read the proxy's own chain state from disk (the local
/// hot-tier cache that `chain-api` on :9091 reads from). Kept as a
/// trait so tests can inject an in-memory impl.
#[async_trait::async_trait]
pub trait ProxyChainReader: Send + Sync {
    /// Return `entry_count` for the chain. Used by Process 2 to bound
    /// the walk and compute `tail_depth`.
    async fn entry_count(&self, chain_id: &str) -> Result<u64, String>;

    /// Return a paginated range of entries from the proxy's local
    /// chain copy. `cursor` is the starting 0-based entry index;
    /// `limit` bounds the page size. Matches the observer `/entries`
    /// semantics so Process 2 can walk both sides with the same loop
    /// structure.
    async fn read_entries(
        &self,
        chain_id: &str,
        cursor: u64,
        limit: usize,
    ) -> Result<Vec<ChainEntry>, String>;

    /// Enumerate per-user chain IDs held on the proxy. Used by Process
    /// 1 (UAT §5.5.1) to iterate every per-user chain for cross-
    /// replica head-hash verification. Returns the 64-hex-character
    /// `chain_id_user(user_id)` strings that name on-disk chain
    /// directories; the deployment chain (`_deployment`) is
    /// deliberately excluded — callers verify it separately.
    async fn list_chain_ids(&self) -> Result<Vec<String>, String>;
}

/// Concrete `ProxyChainReader` that reads from a local on-disk
/// `chain-store`. Used in production where the verification task
/// runs in the same process as `chain-api` and therefore has direct
/// access to the chain-store directory.
pub struct LocalDiskProxyChainReader {
    data_dir: std::path::PathBuf,
}

impl LocalDiskProxyChainReader {
    pub fn new(data_dir: impl Into<std::path::PathBuf>) -> Self {
        Self {
            data_dir: data_dir.into(),
        }
    }
}

#[async_trait::async_trait]
impl ProxyChainReader for LocalDiskProxyChainReader {
    async fn entry_count(&self, chain_id: &str) -> Result<u64, String> {
        let data_dir = self.data_dir.clone();
        let chain_id = chain_id.to_string();
        tokio::task::spawn_blocking(move || {
            let store = chain_store::ChainStore::open_by_hash(&data_dir, &chain_id)
                .map_err(|e| format!("open_by_hash: {e}"))?;
            store.entry_count().map_err(|e| format!("entry_count: {e}"))
        })
        .await
        .map_err(|e| format!("join error: {e}"))?
    }

    async fn read_entries(
        &self,
        chain_id: &str,
        cursor: u64,
        limit: usize,
    ) -> Result<Vec<ChainEntry>, String> {
        let data_dir = self.data_dir.clone();
        let chain_id = chain_id.to_string();
        tokio::task::spawn_blocking(move || {
            let store = chain_store::ChainStore::open_by_hash(&data_dir, &chain_id)
                .map_err(|e| format!("open_by_hash: {e}"))?;
            store
                .read_range(cursor, limit)
                .map_err(|e| format!("read_range: {e}"))
        })
        .await
        .map_err(|e| format!("join error: {e}"))?
    }

    async fn list_chain_ids(&self) -> Result<Vec<String>, String> {
        let data_dir = self.data_dir.clone();
        tokio::task::spawn_blocking(move || {
            chain_store::list_chain_dirs(&data_dir)
                .map_err(|e| format!("list_chain_dirs: {e}"))
        })
        .await
        .map_err(|e| format!("join error: {e}"))?
    }
}

/// Outcome of a single Tick's Process 2 run.
#[derive(Debug, Default, Clone)]
struct Process2Outcome {
    /// Whether Process 2 executed (observer reachable + proxy chain
    /// readable). `false` when the observer was unreachable after
    /// retry or when no proxy chain reader was configured.
    compared: bool,
    /// Whether the entry walk found a byte-mismatching pair.
    divergent: bool,
    /// Populated when `divergent` is true: carries the specific
    /// entries that disagreed so the caller can emit a forensic
    /// failure event without re-fetching the chains.
    failure: Option<Process2Failure>,
    /// Number of entry pairs the walk advanced through this Tick.
    entries_verified: u64,
    /// Depth of the unverified tail on the longer side after the
    /// walk stopped. `0` when both cursors are fully caught up.
    tail_depth: u64,
    /// Present when the observer was unreachable — caller emits the
    /// System-category observation-chain-unreachable event.
    unreachable_reason: Option<String>,
    /// Cursor values after the walk. On clean advance these point
    /// past the last verified pair. On mismatch these point AT the
    /// mismatching pair (the cursors are NOT advanced past a mismatch
    /// per UAT §5.5.2 step 5).
    cursor_prx: u64,
    cursor_obs: u64,
}

/// Details of a Process 2 divergence — stored on the report so the
/// caller can emit a forensic `verification_failure` DeploymentEvent.
///
/// Two kinds of divergence land here:
///
/// 1. Byte-mismatch (§5.5.2 step 5): both sides canonicalized OK but
///    their payload bytes disagree. `proxy_payload` and
///    `observed_payload` hold the two canonical forms.
/// 2. Canon-failure: one side's entry could not be canonicalized
///    (e.g., a payload containing `null` at depth — forbidden by §4.9
///    rule 5 — or a disk-corrupted entry that fails deserialization).
///    `canon_error_side` identifies which side failed; the non-failing
///    side's canonical payload is still recorded for comparison.
///    Treating canon-failure as a mismatch prevents the silent stall
///    where a poisoned entry causes Process 2 to warn-log every Tick
///    forever with no operator-visible alert.
#[derive(Debug, Clone)]
struct Process2Failure {
    cursor_prx: u64,
    cursor_obs: u64,
    proxy_payload: Vec<u8>,
    observed_payload: Vec<u8>,
    /// `None` for byte-mismatch; `Some("proxy")` or `Some("observer")`
    /// for canon-failure on that side.
    canon_error_side: Option<&'static str>,
}

/// Page size for both the proxy and observer read paths. 500 matches
/// the observer endpoint's hard cap; the walk will issue multiple
/// paginated requests if the tail exceeds this.
const PROCESS2_PAGE_LIMIT: usize = 500;

/// Walk the proxy's deployment chain and the observation chain from
/// their cursors in lockstep (per UAT §5.5.2). Returns an outcome
/// describing the Tick's result; errors are transport failures on the
/// observer side (which the caller interprets as infrastructure, not
/// tampering).
async fn run_process_2(
    observer: &dyn ObserverHeadReader,
    proxy: &dyn ProxyChainReader,
    chain_id: &str,
    initial_cursor_prx: u64,
    initial_cursor_obs: u64,
    deployment_salt: &str,
    observer_health: Option<&uninc_common::SubsystemHealth>,
) -> Result<Process2Outcome, ObserverError> {
    let mut cursor_prx = initial_cursor_prx;
    let mut cursor_obs = initial_cursor_obs;
    let mut entries_verified: u64 = 0;

    // Read one page from each side. If either side has zero new
    // entries we're done for this Tick; tail_depth accounts for what
    // remains unverified on the longer side.
    let observer_page = match read_observer_entries_with_retry(
        observer,
        chain_id,
        cursor_obs,
        PROCESS2_PAGE_LIMIT,
    )
    .await
    {
        Ok(p) => {
            if let Some(cell) = observer_health {
                cell.stamp_ok();
            }
            p
        }
        Err(e) => {
            if let Some(cell) = observer_health {
                cell.stamp_err(e.to_string());
            }
            return Err(e);
        }
    };
    let observer_total = observer_page.total_entries;

    // Read proxy entries starting at cursor_prx. We read eagerly up to
    // the page limit; non-projectable entries get skipped (cursor_prx
    // advances past them without consuming an observer counterpart
    // per UAT §5.5.2 step 1).
    let proxy_entries = proxy
        .read_entries(chain_id, cursor_prx, PROCESS2_PAGE_LIMIT)
        .await
        .map_err(|e| ObserverError::Transport(format!("proxy chain read: {e}")))?;
    let proxy_total = proxy
        .entry_count(chain_id)
        .await
        .map_err(|e| ObserverError::Transport(format!("proxy chain count: {e}")))?;

    // Filter proxy entries to the projectable subset. Non-projectable
    // entries (DeploymentEvent entries in Config/System/Deploy/etc)
    // consume a cursor_prx increment but no observer counterpart.
    let mut proxy_iter = proxy_entries.into_iter();
    let mut observer_iter = observer_page.entries.into_iter();

    let mut failure: Option<Process2Failure> = None;

    loop {
        // Try to find the next projectable proxy entry, advancing
        // cursor_prx past any non-projectable entries in the process.
        let proxy_next = loop {
            let Some(e) = proxy_iter.next() else {
                break None;
            };
            cursor_prx = e.index + 1;
            if let Some(projected) = project_to_observed(&e, deployment_salt) {
                break Some((e.index, projected));
            }
            // Non-projectable entry — skip without consuming observer side.
        };

        let Some((prx_idx, projected)) = proxy_next else {
            break;
        };

        let Some(obs_entry) = observer_iter.next() else {
            // Proxy has a projectable entry but observer hasn't
            // caught up. Rewind cursor_prx so the next Tick reads
            // this same entry again.
            cursor_prx = prx_idx;
            break;
        };

        // Canonicalize both payloads and byte-compare. Both sides MUST
        // produce identical bytes for the same operation per UAT
        // §5.5.2 payload-byte-equality invariant. A canon failure on
        // either side is surfaced as a divergence (not a silent stall)
        // so the failure chain fires and operators see the alert —
        // otherwise a poisoned entry (e.g., a null-bearing payload that
        // a non-conformant producer sneaked past rule 5) would warn-log
        // every Tick forever.
        let proxy_canon_result = canonicalize_payload(&EventPayload::Observed(projected));
        let observer_canon_result = canonicalize_payload(&obs_entry.payload);

        let (proxy_canon, observer_canon) = match (proxy_canon_result, observer_canon_result) {
            (Ok(p), Ok(o)) => (p, o),
            (Err(e), Ok(o)) => {
                warn!(error = ?e, proxy_index = prx_idx,
                      "process 2: proxy canon failed — recording as divergence");
                cursor_prx = prx_idx;
                cursor_obs = obs_entry.index;
                failure = Some(Process2Failure {
                    cursor_prx: prx_idx,
                    cursor_obs: obs_entry.index,
                    proxy_payload: format!("canon error: {e}").into_bytes(),
                    observed_payload: o,
                    canon_error_side: Some("proxy"),
                });
                break;
            }
            (Ok(p), Err(e)) => {
                warn!(error = ?e, observer_index = obs_entry.index,
                      "process 2: observer canon failed — recording as divergence");
                cursor_prx = prx_idx;
                cursor_obs = obs_entry.index;
                failure = Some(Process2Failure {
                    cursor_prx: prx_idx,
                    cursor_obs: obs_entry.index,
                    proxy_payload: p,
                    observed_payload: format!("canon error: {e}").into_bytes(),
                    canon_error_side: Some("observer"),
                });
                break;
            }
            (Err(pe), Err(oe)) => {
                warn!(proxy_error = ?pe, observer_error = ?oe,
                      proxy_index = prx_idx, observer_index = obs_entry.index,
                      "process 2: both sides canon failed — recording as divergence");
                cursor_prx = prx_idx;
                cursor_obs = obs_entry.index;
                failure = Some(Process2Failure {
                    cursor_prx: prx_idx,
                    cursor_obs: obs_entry.index,
                    proxy_payload: format!("canon error: {pe}").into_bytes(),
                    observed_payload: format!("canon error: {oe}").into_bytes(),
                    canon_error_side: Some("both"),
                });
                break;
            }
        };

        if proxy_canon == observer_canon {
            // Match — advance observer cursor past this entry.
            // cursor_prx already advanced when we pulled from the
            // iterator above.
            cursor_obs = obs_entry.index + 1;
            entries_verified += 1;
        } else {
            // Mismatch — §5.5.2 step 5. Record both payloads, rewind
            // cursors to POINT AT the mismatching pair (not past it),
            // stop the walk.
            cursor_prx = prx_idx;
            cursor_obs = obs_entry.index;
            failure = Some(Process2Failure {
                cursor_prx: prx_idx,
                cursor_obs: obs_entry.index,
                proxy_payload: proxy_canon,
                observed_payload: observer_canon,
                canon_error_side: None,
            });
            break;
        }
    }

    // Compute tail_depth: how many entries on each side have NOT yet
    // been verified. The larger of the two is the tail.
    let proxy_tail = proxy_total.saturating_sub(cursor_prx);
    let observer_tail = observer_total.saturating_sub(cursor_obs);
    let tail_depth = proxy_tail.max(observer_tail);

    let divergent = failure.is_some();
    Ok(Process2Outcome {
        compared: true,
        divergent,
        failure,
        entries_verified,
        tail_depth,
        unreachable_reason: None,
        cursor_prx,
        cursor_obs,
    })
}

/// Fetch one page of observer entries with a single-retry policy,
/// matching `fetch_observer_head_with_retry` for consistency.
async fn read_observer_entries_with_retry(
    observer: &dyn ObserverHeadReader,
    chain_id: &str,
    cursor: u64,
    limit: usize,
) -> Result<EntriesPage, ObserverError> {
    match observer.read_entries(chain_id, cursor, limit).await {
        Ok(page) => Ok(page),
        Err(first_err) if first_err.is_retryable() => {
            warn!(
                error = %first_err,
                backoff_ms = OBSERVER_RETRY_BACKOFF.as_millis() as u64,
                "observer entries read failed — retrying once"
            );
            tokio::time::sleep(OBSERVER_RETRY_BACKOFF).await;
            observer.read_entries(chain_id, cursor, limit).await
        }
        Err(fatal) => Err(fatal),
    }
}

// ─── Scheduler ─────────────────────────────────────────────────────────

/// The only verification task in v1. Spawn this once at proxy startup.
/// It loops forever, racing two triggers:
///
/// - **Periodic**: sleeps for `SCHEDULED_PERIOD` (4h) between runs. Floor
///   on staleness even on a fully idle deployment.
/// - **Session-end**: `VerificationEngine::session_end_notify()` fires on
///   every admin session close; the scheduler picks up the notify and
///   runs a pass. `notify_one` is coalescing, so a burst of session-ends
///   inside one run results in exactly one follow-up run.
///
/// After each run the scheduler sleeps at least `SCHEDULED_RUN_MIN_INTERVAL`
/// (1 min) regardless of trigger, to prevent a pathological back-to-back
/// session-end loop.
///
/// The task is fully background: no caller waits on it, no request path
/// blocks on it, and a failure in one run only logs — the next trigger
/// or timer tick tries again.
#[allow(clippy::too_many_arguments)]
pub async fn start_scheduled_verification_task(
    engine: Arc<VerificationEngine>,
    nats: Arc<NatsClient>,
    observer_health: Option<Arc<uninc_common::SubsystemHealth>>,
    // Process 2 (§5.5.2) proxy-side chain reader. `None` disables
    // Process 2 (Playground / tests without a local chain-store).
    proxy_chain: Option<Arc<dyn ProxyChainReader>>,
    // Deployment salt for `project_to_observed`. Must match the
    // observer's `deployment_salt` and the proxy's `chain.server_salt`.
    // Empty string is accepted for test harnesses that don't exercise
    // Process 2.
    deployment_salt: String,
) {
    let session_end_notify = engine.session_end_notify();
    info!(
        period_secs = SCHEDULED_PERIOD.as_secs(),
        "🗓️  scheduled verification task started (session-end trigger + periodic backstop)"
    );

    // Build the failure handler chain once. Reused across runs.
    let failure_chain = Arc::new(build_default_chain(
        &engine.config().on_failure,
        Arc::clone(&nats),
        CredentialDenyList::default(),
        ReadOnlyLockdown::default(),
        None, // webhook URL not plumbed through engine config yet
    ));

    // v1 (2026-04-15 redesign): role assignments are now per-session, not
    // process-wide. The startup assignment step from the old three-role
    // model is gone — the verification task just walks the configured
    // replica list directly for head comparison.
    if engine.config().replicas.is_empty() {
        warn!("no replicas configured — scheduled verification task will idle");
    }

    // Build the observer client if the deployment is configured with
    // an observer URL + secret. Both fields must be set; having just
    // one is a config error, not a silent skip — warn so operators see
    // it rather than wondering why observer comparison never runs.
    let observer: Option<Arc<dyn ObserverHeadReader>> = {
        let cfg = engine.config();
        match (&cfg.observer_url, &cfg.observer_read_secret) {
            (Some(url), Some(secret)) => {
                info!(
                    base_url = url.as_str(),
                    "observer-vs-proxy head comparison enabled"
                );
                Some(Arc::new(HttpObserverClient::new(url.clone(), secret.clone()))
                    as Arc<dyn ObserverHeadReader>)
            }
            (Some(_), None) => {
                warn!(
                    "verification.observer_url set without observer_read_secret — \
                     observer comparison disabled (both fields required)"
                );
                None
            }
            (None, Some(_)) => {
                warn!(
                    "verification.observer_read_secret set without observer_url — \
                     observer comparison disabled (both fields required)"
                );
                None
            }
            (None, None) => {
                info!("no observer configured — scheduled runs will not compare observer head");
                None
            }
        }
    };

    // In-memory head cache passed into each run. Lets consecutive runs
    // detect "the head didn't change at all" and log that as a soft
    // anomaly (legitimate quiet deployments look the same as a stuck
    // consumer, so it's worth knowing).
    let last_head_per_replica: RwLock<HashMap<String, [u8; 32]>> = RwLock::new(HashMap::new());
    // Process 2 cursors — one pair for the deployment chain. This is
    // the persistent state spec §5.5.2 refers to: cursor_prx and
    // cursor_obs advance monotonically as entries are verified.
    let process2_cursors: RwLock<Process2Cursors> = RwLock::new(Process2Cursors::default());
    let cfg = ScheduledVerificationConfig::default();

    // Main scheduling loop. Anything that can throw or panic inside the
    // loop body is caught so one bad run never kills the task for the
    // rest of the process lifetime.
    loop {
        // Race the periodic timer against the session-end notify.
        // Whichever fires first triggers the run. `notify_one` is
        // coalescing: if several session-ends fire during a run, at
        // most ONE follow-up run is queued, not N.
        let trigger = tokio::select! {
            _ = tokio::time::sleep(SCHEDULED_PERIOD) => "periodic",
            _ = session_end_notify.notified()       => "session_end",
        };
        info!(
            trigger,
            "🗓️  scheduled verification triggered"
        );

        let verifiers = engine.verifiers();

        // Two layers of protection:
        //   1. tokio::time::timeout bounds the wall-clock duration of a
        //      single run (SCHEDULED_RUN_MAX_DURATION). A stuck replica
        //      response can't hold the task forever.
        //   2. AssertUnwindSafe + FutureExt::catch_unwind catches panics
        //      from inside run_scheduled_verification so the loop keeps
        //      running even if the pipeline has a bug or a replica
        //      serializer crashes.
        let pipeline = run_scheduled_verification(
            Arc::clone(&engine),
            verifiers,
            Arc::clone(&failure_chain),
            Arc::clone(&nats),
            &cfg,
            &last_head_per_replica,
            observer.clone(),
            observer_health.clone(),
            &process2_cursors,
            proxy_chain.clone(),
            &deployment_salt,
        );
        let outcome = tokio::time::timeout(
            SCHEDULED_RUN_MAX_DURATION,
            AssertUnwindSafe(pipeline).catch_unwind(),
        )
        .await;

        match outcome {
            Ok(Ok(report)) => {
                info!(
                    clean = report.clean,
                    sessions_checked = report.sessions_checked,
                    head_divergences = report.head_divergences,
                    "🗓️  scheduled verification run summary"
                );
            }
            Ok(Err(panic)) => {
                let msg = panic_message(&panic);
                error!(%msg, "🗓️  scheduled verification run PANICKED — loop continuing");
                tokio::time::sleep(SCHEDULER_ERROR_BACKOFF).await;
            }
            Err(_elapsed) => {
                error!(
                    timeout_secs = SCHEDULED_RUN_MAX_DURATION.as_secs(),
                    "🗓️  scheduled verification run TIMED OUT — loop continuing"
                );
                tokio::time::sleep(SCHEDULER_ERROR_BACKOFF).await;
            }
        }

        // Debounce. If the previous run succeeded quickly AND a
        // session-end notify is already queued, the next iteration's
        // select will fire immediately on `notified()`. Without this
        // floor the scheduler could run back-to-back under a burst of
        // admin session closes. 1 minute is long enough to absorb a
        // burst but short enough not to delay legitimate follow-up
        // runs meaningfully.
        tokio::time::sleep(SCHEDULED_RUN_MIN_INTERVAL).await;
    }
}

/// Extract a human-readable message from a boxed panic payload.
fn panic_message(boxed: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = boxed.downcast_ref::<&'static str>() {
        (*s).to_string()
    } else if let Some(s) = boxed.downcast_ref::<String>() {
        s.clone()
    } else {
        "<non-string panic payload>".to_string()
    }
}


#[cfg(test)]
mod tests {
    //! Tests covering the observer-comparison retry policy
    //! (`fetch_observer_head_with_retry`). Full task-level end-to-end
    //! tests are covered by the manual run described in the plan's
    //! Verification section — they require live NATS + a configured
    //! VerificationEngine, which is heavier than a unit-test harness
    //! should carry.
    use super::*;
    use crate::observer_client::{ObserverError, ObserverHeadReader};
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Stub observer that returns a preconfigured sequence of results.
    /// Each `read_head` call advances through the sequence; if the
    /// sequence is exhausted the stub panics (tests must preconfigure
    /// enough entries).
    struct SequenceStub {
        sequence: Vec<Result<Option<[u8; 32]>, ObserverError>>,
        cursor: AtomicUsize,
    }

    impl SequenceStub {
        fn new(sequence: Vec<Result<Option<[u8; 32]>, ObserverError>>) -> Self {
            Self {
                sequence,
                cursor: AtomicUsize::new(0),
            }
        }

        fn calls(&self) -> usize {
            self.cursor.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl ObserverHeadReader for SequenceStub {
        async fn read_head(
            &self,
            _chain_id: &str,
        ) -> Result<Option<[u8; 32]>, ObserverError> {
            let i = self.cursor.fetch_add(1, Ordering::SeqCst);
            self.sequence
                .get(i)
                .cloned()
                .expect("SequenceStub: test requested more calls than the sequence has")
        }

        async fn read_entries(
            &self,
            _chain_id: &str,
            _cursor: u64,
            _limit: usize,
        ) -> Result<crate::observer_client::EntriesPage, ObserverError> {
            // This stub only exercises the head-read retry policy. Tests
            // that need `/entries` behaviour build a dedicated stub.
            unimplemented!(
                "SequenceStub.read_entries: tests that need /entries should use a different stub"
            )
        }
    }

    // `ObserverError` isn't Clone by default; for the stub's needs
    // above we re-build sequence entries manually at test-site.
    impl Clone for ObserverError {
        fn clone(&self) -> Self {
            match self {
                Self::Unauthorized => Self::Unauthorized,
                Self::Http(s) => Self::Http(*s),
                Self::Timeout => Self::Timeout,
                Self::Transport(s) => Self::Transport(s.clone()),
                Self::InvalidResponse(s) => Self::InvalidResponse(s.clone()),
            }
        }
    }

    #[tokio::test]
    async fn retry_policy_succeeds_on_first_try() {
        let stub = SequenceStub::new(vec![Ok(Some([0x42; 32]))]);
        let got = fetch_observer_head_with_retry(&stub, "_deployment")
            .await
            .unwrap();
        assert_eq!(got, Some([0x42; 32]));
        assert_eq!(stub.calls(), 1, "must not retry on success");
    }

    #[tokio::test]
    async fn retry_policy_recovers_from_transient_error() {
        let stub = SequenceStub::new(vec![Err(ObserverError::Timeout), Ok(Some([0xaa; 32]))]);
        let got = fetch_observer_head_with_retry(&stub, "_deployment")
            .await
            .unwrap();
        assert_eq!(got, Some([0xaa; 32]));
        assert_eq!(stub.calls(), 2, "must retry once on transient error");
    }

    #[tokio::test]
    async fn retry_policy_fails_fast_on_non_retryable() {
        let stub = SequenceStub::new(vec![Err(ObserverError::Unauthorized)]);
        let err = fetch_observer_head_with_retry(&stub, "_deployment")
            .await
            .unwrap_err();
        assert!(matches!(err, ObserverError::Unauthorized));
        assert_eq!(
            stub.calls(),
            1,
            "auth failure must not retry — config, not transient"
        );
    }

    #[tokio::test]
    async fn retry_policy_surfaces_second_failure_when_retry_also_fails() {
        let stub = SequenceStub::new(vec![
            Err(ObserverError::Timeout),
            Err(ObserverError::Transport("still broken".into())),
        ]);
        let err = fetch_observer_head_with_retry(&stub, "_deployment")
            .await
            .unwrap_err();
        match err {
            ObserverError::Transport(msg) => assert!(msg.contains("still broken")),
            other => panic!("expected second error to surface, got {other:?}"),
        }
        assert_eq!(stub.calls(), 2);
    }

    #[tokio::test]
    async fn retry_policy_empty_chain_null_passes_through() {
        let stub = SequenceStub::new(vec![Ok(None)]);
        let got = fetch_observer_head_with_retry(&stub, "_deployment")
            .await
            .unwrap();
        assert_eq!(got, None);
    }
}

// build_startup_assignment removed in the 2026-04-15 redesign. Per-session
// role assignments live on `AdminSession` (see engine.rs start_session).
//
// Phase 4 cross-chain verification + state spot-check logic is tracked in
// FOLLOWUPS.md and ROADMAP.md; disk volume constraints during the Phase 3
// crate split mean the state_checker module is inlined into `verification`
// as a follow-up edit once space is reclaimed. The observer chain read
// path uses `OBSERVER_URL` + `OBSERVER_READ_SECRET` env vars exposed by
// the provisioning worker.
