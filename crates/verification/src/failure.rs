//! Failure handler chain for verification divergences.
//!
//! When the cross-replica verifier detects a divergence (chain head mismatch across
//! replicas, session-level checksum disagreement, chain corruption, or a
//! replica becoming unreachable), the `FailureHandlerChain` runs its
//! registered handlers in order of escalation:
//!
//!   1. DeploymentChainFailureHandler   — append a tamper-evident record of the
//!                                  divergence to the deployment chain.
//!                                  This is the permanent audit trail.
//!   2. NatsAlertFailureHandler  — publish on uninc.alerts.verification.*
//!                                  so www can surface a red banner and
//!                                  email the operator.
//!   3. WebhookFailureHandler    — POST to customer-configured webhook
//!                                  (Slack / PagerDuty / email gateway).
//!   4. CredentialRevokeHandler  — add the implicated admin credential to
//!                                  the proxy's in-memory deny list so the
//!                                  attacker can't finish what they started.
//!   5. ReadOnlyLockdownHandler  — on severity = Critical, flip the proxy
//!                                  into read-only mode until a human
//!                                  clears it.
//!
//! Handlers are composable and independently testable. The chain itself
//! never panics — handler errors are logged and the next handler runs.
//!
//! Dev logs are colorized via tracing's ansi feature; prod logs are
//! structured JSON via tracing-subscriber's json layer (configured at
//! proxy startup, not here).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::RwLock;
use tracing::{error, info, warn};
use uninc_common::config::FailureResponseConfig;
use uninc_common::nats_client::NatsClient;
use uninc_common::types::{ActionType, ActorType, DeploymentCategory, DeploymentEvent};
use uuid::Uuid;

/// What kind of failure is being handled. Different events carry different
/// context, which handlers use to decide how aggressive to be.
#[derive(Debug, Clone)]
pub enum FailureEvent {
    /// Head hash disagreement across replicas, or session-level checksum
    /// divergence. Includes which replicas disagreed and what the
    /// divergence was.
    VerificationDivergence {
        severity: Severity,
        session_id: Option<Uuid>,
        admin_id: Option<String>,
        replicas_disagreed: Vec<String>,
        reason: String,
    },

    /// A chain file on disk is corrupted (hash doesn't match, index is
    /// gapped, file truncated). Usually means the proxy VM was attacked
    /// or had a hardware fault. Severity is always Critical.
    ChainCorruption {
        chain_id: String,
        detail: String,
    },

    /// A replica is unreachable for longer than a threshold. Becomes
    /// Critical if quorum is lost (fewer than ⌊N/2⌋+1 replicas available).
    ReplicaUnreachable {
        replica_id: String,
        duration: Duration,
        quorum_still_holds: bool,
    },

    /// Chain-engine's durable fan-out has failed `consecutive_failures`
    /// times in a row for `chain_id`. Escalation path for a persistent
    /// quorum failure that the existing `VerificationDivergence` and
    /// `ChainCorruption` variants don't cover — those describe detected
    /// tampering or on-disk corruption, whereas this one describes an
    /// infrastructure fault (replica VMs offline, chain-MinIO sidecar
    /// crashed, network partition).
    ///
    /// Emitted by chain-engine via the `ops_failure` NATS relay once the
    /// consecutive-failure count crosses the alert threshold (default 3).
    /// Severity is `Error` below quorum-loss and `Critical` once quorum
    /// is lost — determined by the handler at dispatch time using the
    /// configured replica count.
    ChainCommitFailed {
        severity: Severity,
        chain_id: String,
        consecutive_failures: u32,
        last_reason: String,
    },
}

/// Severity ladder used by handlers to decide escalation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Warning,
    Error,
    Critical,
}

impl FailureEvent {
    pub fn severity(&self) -> Severity {
        match self {
            FailureEvent::VerificationDivergence { severity, .. } => *severity,
            FailureEvent::ChainCorruption { .. } => Severity::Critical,
            FailureEvent::ReplicaUnreachable {
                quorum_still_holds: false,
                ..
            } => Severity::Critical,
            FailureEvent::ReplicaUnreachable { .. } => Severity::Warning,
            FailureEvent::ChainCommitFailed { severity, .. } => *severity,
        }
    }

    pub fn short_label(&self) -> &'static str {
        match self {
            FailureEvent::VerificationDivergence { .. } => "verification-divergence",
            FailureEvent::ChainCorruption { .. } => "chain-corruption",
            FailureEvent::ReplicaUnreachable { .. } => "replica-unreachable",
            FailureEvent::ChainCommitFailed { .. } => "chain-commit-failed",
        }
    }
}

/// Outcome of a single handler invocation. Kept separate from errors so
/// a "skipped because below severity threshold" looks different from
/// a real failure.
#[derive(Debug, Clone)]
pub enum HandlerOutcome {
    Ran { detail: String },
    Skipped { reason: String },
    Failed { error: String },
}

/// All handlers implement this trait. Each handler decides for itself
/// whether it cares about a given event (usually via severity threshold).
pub trait Handler: Send + Sync {
    fn name(&self) -> &'static str;

    fn handle<'a>(
        &'a self,
        event: &'a FailureEvent,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = HandlerOutcome> + Send + 'a>>;
}

/// A composed chain of handlers. Run in order, collecting outcomes.
/// A failing handler does not stop the chain — other handlers still run.
pub struct FailureHandlerChain {
    handlers: Vec<Arc<dyn Handler>>,
}

impl FailureHandlerChain {
    pub fn new() -> Self {
        Self {
            handlers: Vec::new(),
        }
    }

    pub fn with_handler(mut self, handler: Arc<dyn Handler>) -> Self {
        self.handlers.push(handler);
        self
    }

    pub fn push(&mut self, handler: Arc<dyn Handler>) {
        self.handlers.push(handler);
    }

    pub async fn handle(&self, event: FailureEvent) -> Vec<(&'static str, HandlerOutcome)> {
        // Colorized header line for dev visibility. In prod (JSON logs)
        // the tracing event is structured and the emoji is just a string.
        error!(
            event_type = event.short_label(),
            severity = ?event.severity(),
            "🚨 verification failure dispatched to handler chain"
        );

        let mut outcomes = Vec::with_capacity(self.handlers.len());
        for handler in &self.handlers {
            let outcome = handler.handle(&event).await;
            match &outcome {
                HandlerOutcome::Ran { detail } => {
                    info!(handler = handler.name(), detail, "✅ handler ran");
                }
                HandlerOutcome::Skipped { reason } => {
                    info!(handler = handler.name(), reason, "⏭  handler skipped");
                }
                HandlerOutcome::Failed { error } => {
                    error!(handler = handler.name(), error, "❌ handler failed");
                }
            }
            outcomes.push((handler.name(), outcome));
        }
        outcomes
    }
}

impl Default for FailureHandlerChain {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Handler 1: write to deployment chain ───────────────────────────────────────

/// Publishes a tamper-evident record of the failure to the deployment chain.
/// This handler runs for every event regardless of severity, because an
/// unauthenticated event is as forensically important as an authenticated one.
pub struct DeploymentChainFailureHandler {
    nats: Arc<NatsClient>,
}

impl DeploymentChainFailureHandler {
    pub fn new(nats: Arc<NatsClient>) -> Self {
        Self { nats }
    }
}

impl Handler for DeploymentChainFailureHandler {
    fn name(&self) -> &'static str {
        "deployment_chain_write"
    }

    fn handle<'a>(
        &'a self,
        event: &'a FailureEvent,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = HandlerOutcome> + Send + 'a>> {
        Box::pin(async move {
            let mut details = HashMap::new();
            details.insert("event_type".into(), event.short_label().into());
            details.insert("severity".into(), format!("{:?}", event.severity()));

            // Branch category + action per FailureEvent variant so the
            // deployment chain distinguishes tampering signals from infra
            // faults (spec §3.3, §4.11, Appendix A.1 CC7.3).
            //
            // VerificationDivergence / ChainCorruption are tampering-class
            // events: they indicate that the chain state disagrees with
            // itself or with an observer, which is the exact signal the
            // protocol exists to surface. Both use
            // `category = verification_failure`.
            //
            // ReplicaUnreachable is an infra fault: the replica couldn't
            // be reached, which is noise rather than evidence of tamper.
            // Keep it on `category = system`.
            let (scope, session_id, category) = match event {
                FailureEvent::VerificationDivergence {
                    session_id,
                    admin_id,
                    replicas_disagreed,
                    reason,
                    ..
                } => {
                    if let Some(admin) = admin_id {
                        details.insert("admin_id".into(), admin.clone());
                    }
                    details.insert(
                        "replicas_disagreed".into(),
                        replicas_disagreed.join(","),
                    );
                    details.insert("reason".into(), reason.clone());
                    (
                        format!("verification divergence: {}", reason),
                        *session_id,
                        DeploymentCategory::VerificationFailure,
                    )
                }
                FailureEvent::ChainCorruption { chain_id, detail } => {
                    details.insert("chain_id".into(), chain_id.clone());
                    details.insert("detail".into(), detail.clone());
                    (
                        format!("chain corruption on {chain_id}: {detail}"),
                        None,
                        DeploymentCategory::VerificationFailure,
                    )
                }
                FailureEvent::ReplicaUnreachable {
                    replica_id,
                    duration,
                    quorum_still_holds,
                } => {
                    details.insert("replica_id".into(), replica_id.clone());
                    details.insert("duration_secs".into(), duration.as_secs().to_string());
                    details.insert(
                        "quorum_still_holds".into(),
                        quorum_still_holds.to_string(),
                    );
                    (
                        format!(
                            "replica {replica_id} unreachable for {}s",
                            duration.as_secs()
                        ),
                        None,
                        DeploymentCategory::System,
                    )
                }
                FailureEvent::ChainCommitFailed {
                    chain_id,
                    consecutive_failures,
                    last_reason,
                    ..
                } => {
                    details.insert("chain_id".into(), chain_id.clone());
                    details.insert(
                        "consecutive_failures".into(),
                        consecutive_failures.to_string(),
                    );
                    details.insert("last_reason".into(), last_reason.clone());
                    (
                        format!(
                            "chain commit failed on {chain_id}: {consecutive_failures} \
                             consecutive failures; last reason: {last_reason}"
                        ),
                        None,
                        // Not `VerificationFailure` — quorum loss is an
                        // infrastructure fault, not tamper evidence.
                        DeploymentCategory::System,
                    )
                }
            };

            let org_event = DeploymentEvent {
                actor_id: "uninc-verifier".into(),
                actor_type: ActorType::System,
                category,
                // The verifier observed a state it couldn't reconcile — the
                // deployment-chain entry records the observation, not a
                // mutation, so the action is Read.
                action: ActionType::Read,
                resource: "verification".into(),
                scope,
                details: Some(details),
                artifact_hash: None,
                timestamp: chrono::Utc::now().timestamp(),
                session_id,
                source_ip: None,
            };

            match self.nats.publish_system_deployment_event(&org_event).await {
                Ok(_) => HandlerOutcome::Ran {
                    detail: "deployment chain entry published".into(),
                },
                Err(e) => HandlerOutcome::Failed {
                    error: format!("deployment chain publish failed: {e}"),
                },
            }
        })
    }
}

// ─── Handler 2: NATS alert for www to consume ────────────────────────────

/// Publishes to a dedicated alerts subject for the www backend to consume.
/// Separate from the deployment chain so alerts can be processed by ephemeral
/// subscribers without being permanently recorded.
pub struct NatsAlertFailureHandler {
    nats: Arc<NatsClient>,
}

impl NatsAlertFailureHandler {
    pub fn new(nats: Arc<NatsClient>) -> Self {
        Self { nats }
    }
}

impl Handler for NatsAlertFailureHandler {
    fn name(&self) -> &'static str {
        "nats_alert"
    }

    fn handle<'a>(
        &'a self,
        event: &'a FailureEvent,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = HandlerOutcome> + Send + 'a>> {
        Box::pin(async move {
            let subject = format!("uninc.alerts.verification.{}", event.short_label());
            let payload = match serde_json::to_vec(&serde_json::json!({
                "event_type": event.short_label(),
                "severity": format!("{:?}", event.severity()),
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "summary": summarize(event),
            })) {
                Ok(p) => p,
                Err(e) => {
                    return HandlerOutcome::Failed {
                        error: format!("alert payload serialize failed: {e}"),
                    };
                }
            };
            // Use jetstream directly — alerts live outside the UNINC_ACCESS
            // stream, so we publish to core NATS (no durability). If nobody's
            // listening the message is dropped; that's fine — the deployment chain
            // entry (handler 1) is the durable record.
            match self
                .nats
                .jetstream()
                .publish(subject.clone(), payload.into())
                .await
            {
                Ok(fut) => match fut.await {
                    Ok(_) => HandlerOutcome::Ran {
                        detail: format!("alert published to {subject}"),
                    },
                    Err(e) => HandlerOutcome::Failed {
                        error: format!("nats ack failed: {e}"),
                    },
                },
                Err(e) => HandlerOutcome::Failed {
                    error: format!("nats publish failed: {e}"),
                },
            }
        })
    }
}

// ─── Handler 3: customer webhook ─────────────────────────────────────────

/// POSTs a JSON payload to a customer-configured webhook URL (Slack, PagerDuty,
/// email gateway, etc.). Disabled if no URL is configured.
pub struct WebhookFailureHandler {
    url: Option<String>,
    client: reqwest::Client,
    min_severity: Severity,
}

impl WebhookFailureHandler {
    pub fn new(url: Option<String>, min_severity: Severity) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self {
            url,
            client,
            min_severity,
        }
    }
}

impl Handler for WebhookFailureHandler {
    fn name(&self) -> &'static str {
        "webhook"
    }

    fn handle<'a>(
        &'a self,
        event: &'a FailureEvent,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = HandlerOutcome> + Send + 'a>> {
        Box::pin(async move {
            let Some(url) = self.url.as_ref() else {
                return HandlerOutcome::Skipped {
                    reason: "no webhook URL configured".into(),
                };
            };
            if event.severity() < self.min_severity {
                return HandlerOutcome::Skipped {
                    reason: format!(
                        "severity {:?} below threshold {:?}",
                        event.severity(),
                        self.min_severity
                    ),
                };
            }

            let payload = serde_json::json!({
                "event_type": event.short_label(),
                "severity": format!("{:?}", event.severity()),
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "summary": summarize(event),
            });

            match self.client.post(url).json(&payload).send().await {
                Ok(resp) if resp.status().is_success() => HandlerOutcome::Ran {
                    detail: format!("webhook {} -> {}", url, resp.status()),
                },
                Ok(resp) => HandlerOutcome::Failed {
                    error: format!("webhook {} -> {}", url, resp.status()),
                },
                Err(e) => HandlerOutcome::Failed {
                    error: format!("webhook request failed: {e}"),
                },
            }
        })
    }
}

fn summarize(event: &FailureEvent) -> String {
    match event {
        FailureEvent::ChainCommitFailed {
            chain_id,
            consecutive_failures,
            last_reason,
            ..
        } => format!(
            "chain-commit stuck: {chain_id} failed {consecutive_failures} consecutive \
             attempts; last reason: {last_reason}"
        ),
        FailureEvent::VerificationDivergence {
            admin_id, reason, ..
        } => {
            format!(
                "Verification divergence{}: {}",
                admin_id
                    .as_ref()
                    .map(|a| format!(" (admin: {a})"))
                    .unwrap_or_default(),
                reason
            )
        }
        FailureEvent::ChainCorruption { chain_id, detail } => {
            format!("Chain corruption on {chain_id}: {detail}")
        }
        FailureEvent::ReplicaUnreachable {
            replica_id,
            duration,
            ..
        } => format!(
            "Replica {replica_id} unreachable for {}s",
            duration.as_secs()
        ),
    }
}

// ─── Handler 4: credential revocation (proxy-local deny list) ────────────

/// In-memory deny list the proxy checks at admin-connection classify time.
/// A credential added here cannot establish a new admin session until
/// manually cleared.
#[derive(Clone, Default)]
pub struct CredentialDenyList {
    inner: Arc<RwLock<Vec<String>>>,
}

impl CredentialDenyList {
    pub async fn add(&self, credential: String) {
        let mut guard = self.inner.write().await;
        if !guard.contains(&credential) {
            guard.push(credential);
        }
    }

    pub async fn contains(&self, credential: &str) -> bool {
        self.inner.read().await.iter().any(|c| c == credential)
    }

    pub async fn clear(&self) {
        self.inner.write().await.clear();
    }
}

/// Adds the implicated admin credential to an in-memory deny list.
/// Only fires for `VerificationDivergence` events that name an admin.
pub struct CredentialRevokeHandler {
    deny_list: CredentialDenyList,
}

impl CredentialRevokeHandler {
    pub fn new(deny_list: CredentialDenyList) -> Self {
        Self { deny_list }
    }
}

impl Handler for CredentialRevokeHandler {
    fn name(&self) -> &'static str {
        "credential_revoke"
    }

    fn handle<'a>(
        &'a self,
        event: &'a FailureEvent,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = HandlerOutcome> + Send + 'a>> {
        Box::pin(async move {
            match event {
                FailureEvent::VerificationDivergence {
                    admin_id: Some(admin),
                    ..
                } => {
                    self.deny_list.add(admin.clone()).await;
                    HandlerOutcome::Ran {
                        detail: format!("credential '{admin}' added to deny list"),
                    }
                }
                _ => HandlerOutcome::Skipped {
                    reason: "no admin credential in event".into(),
                },
            }
        })
    }
}

// ─── Handler 5: read-only lockdown ───────────────────────────────────────

/// Proxy-wide read-only flag. When set, the proxy rejects any write
/// operation with an "emergency read-only" error until manually cleared.
#[derive(Clone, Default)]
pub struct ReadOnlyLockdown {
    inner: Arc<RwLock<Option<String>>>,
}

impl ReadOnlyLockdown {
    pub async fn engage(&self, reason: String) {
        let mut guard = self.inner.write().await;
        *guard = Some(reason);
    }

    pub async fn is_engaged(&self) -> Option<String> {
        self.inner.read().await.clone()
    }

    pub async fn clear(&self) {
        *self.inner.write().await = None;
    }
}

pub struct ReadOnlyLockdownHandler {
    lockdown: ReadOnlyLockdown,
}

impl ReadOnlyLockdownHandler {
    pub fn new(lockdown: ReadOnlyLockdown) -> Self {
        Self { lockdown }
    }
}

impl Handler for ReadOnlyLockdownHandler {
    fn name(&self) -> &'static str {
        "read_only_lockdown"
    }

    fn handle<'a>(
        &'a self,
        event: &'a FailureEvent,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = HandlerOutcome> + Send + 'a>> {
        Box::pin(async move {
            if event.severity() < Severity::Critical {
                return HandlerOutcome::Skipped {
                    reason: format!("severity {:?} not critical", event.severity()),
                };
            }
            let reason = format!("{:?} at {}", event, chrono::Utc::now().to_rfc3339());
            self.lockdown.engage(reason.clone()).await;
            warn!(
                reason = reason.as_str(),
                "🛑 proxy flipped to read-only lockdown"
            );
            HandlerOutcome::Ran {
                detail: "proxy locked to read-only".into(),
            }
        })
    }
}

// ─── Legacy shim for existing callsites in engine.rs / triggers.rs ──────

/// Thin wrapper that accepts only `FailureResponseConfig` and provides the
/// old `handle_failure(session_id, reason)` API. Internally it holds a
/// `FailureHandlerChain` with only the non-NATS handlers, since the legacy
/// constructor doesn't have a NatsClient. Callsites that want the full
/// handler chain (including deployment-chain writes + NATS alerts) should use
/// `build_default_chain` directly.
pub struct FailureHandler {
    chain: FailureHandlerChain,
    config: FailureResponseConfig,
}

impl FailureHandler {
    /// Legacy constructor: builds a chain with only the handlers that
    /// don't need external dependencies (credential revoke + lockdown).
    /// The richer construction is `build_default_chain`.
    pub fn new(config: FailureResponseConfig) -> Self {
        let mut chain = FailureHandlerChain::new();
        if config.lock_admin {
            chain.push(Arc::new(CredentialRevokeHandler::new(
                CredentialDenyList::default(),
            )));
        }
        if config.auto_rollback || config.quarantine_replica {
            chain.push(Arc::new(ReadOnlyLockdownHandler::new(
                ReadOnlyLockdown::default(),
            )));
        }
        Self { chain, config }
    }

    /// Dispatch a legacy `(session_id, reason)` pair as a
    /// `FailureEvent::VerificationDivergence` with severity derived from
    /// the config flags. The session_id is optional at the type level
    /// (`Uuid::nil()` in old code means "unknown session").
    pub async fn handle_failure(&self, session_id: &Uuid, reason: &str) {
        if self.config.alert {
            warn!(
                %session_id,
                reason,
                "⚠️  legacy failure handler: verification failure detected"
            );
        }
        let event = FailureEvent::VerificationDivergence {
            severity: if self.config.quarantine_replica || self.config.auto_rollback {
                Severity::Critical
            } else {
                Severity::Error
            },
            session_id: if session_id.is_nil() {
                None
            } else {
                Some(*session_id)
            },
            admin_id: None,
            replicas_disagreed: vec![],
            reason: reason.to_string(),
        };
        let _ = self.chain.handle(event).await;
    }
}

// ─── Builder helper that honors legacy FailureResponseConfig flags ──────

/// Build the default handler chain from existing config + the NATS client.
/// Individual handlers can still be attached after construction.
/// Translate a cross-process `ChainFailurePing` (delivered via NATS ops
/// relay from chain-engine) into a `FailureEvent` the handler chain can
/// dispatch. Severity derivation is intentionally local to this layer:
/// chain-engine doesn't know the quorum threshold at emit time, so we
/// encode "persistent but quorum-partial" as `Error` and escalate to
/// `Critical` if the configured replica count implies quorum loss.
pub fn ping_to_failure_event(
    ping: uninc_common::ops_failure::ChainFailurePing,
    replica_count: usize,
) -> Option<FailureEvent> {
    use uninc_common::ops_failure::ChainFailurePing;
    match ping {
        ChainFailurePing::ChainCommitFailed {
            chain_id,
            consecutive_failures,
            last_reason,
        } => {
            // Heuristic: if the reason string mentions fewer acks than
            // the quorum threshold (⌊N/2⌋+1), we're below quorum —
            // escalate to Critical. We can't parse N-of-M reliably from
            // the free-form reason string, so fall back on
            // "consecutive_failures ≥ 10 is definitely critical".
            let quorum = (replica_count / 2) + 1;
            let below_quorum = last_reason.contains(&format!("0/{replica_count}"))
                || (1..quorum).any(|n| last_reason.contains(&format!("{n}/{replica_count}")));
            let severity = if below_quorum || consecutive_failures >= 10 {
                Severity::Critical
            } else {
                Severity::Error
            };
            Some(FailureEvent::ChainCommitFailed {
                severity,
                chain_id,
                consecutive_failures,
                last_reason,
            })
        }
        ChainFailurePing::ObserverMismatch {
            chain_id,
            proxy_head_hex,
            observer_head_hex,
        } => Some(FailureEvent::VerificationDivergence {
            severity: Severity::Critical,
            session_id: None,
            admin_id: None,
            replicas_disagreed: vec!["observer".into()],
            reason: format!(
                "observer-vs-proxy head mismatch on {chain_id}: proxy={proxy_head_hex} \
                 observer={observer_head_hex}"
            ),
        }),
    }
}

pub fn build_default_chain(
    cfg: &FailureResponseConfig,
    nats: Arc<NatsClient>,
    deny_list: CredentialDenyList,
    lockdown: ReadOnlyLockdown,
    webhook_url: Option<String>,
) -> FailureHandlerChain {
    let mut chain = FailureHandlerChain::new();

    // Handler 1: always on — deployment chain is the forensic record.
    chain.push(Arc::new(DeploymentChainFailureHandler::new(Arc::clone(&nats))));

    // Handler 2: always on — NATS alert for www consumption.
    if cfg.alert {
        chain.push(Arc::new(NatsAlertFailureHandler::new(nats)));
    }

    // Handler 3: customer webhook (opt-in via config).
    if webhook_url.is_some() {
        chain.push(Arc::new(WebhookFailureHandler::new(
            webhook_url,
            Severity::Warning,
        )));
    }

    // Handler 4: credential revoke.
    if cfg.lock_admin {
        chain.push(Arc::new(CredentialRevokeHandler::new(deny_list)));
    }

    // Handler 5: read-only lockdown (maps to the old auto_rollback flag,
    // since "rollback" as originally conceived was unsafe; lockdown is
    // the correct interpretation of "stop taking writes until human").
    if cfg.auto_rollback || cfg.quarantine_replica {
        chain.push(Arc::new(ReadOnlyLockdownHandler::new(lockdown)));
    }

    chain
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn credential_deny_list_add_and_contains() {
        let list = CredentialDenyList::default();
        assert!(!list.contains("admin@x.co").await);
        list.add("admin@x.co".into()).await;
        assert!(list.contains("admin@x.co").await);
    }

    #[tokio::test]
    async fn read_only_lockdown_engage_and_clear() {
        let lockdown = ReadOnlyLockdown::default();
        assert!(lockdown.is_engaged().await.is_none());
        lockdown.engage("test".into()).await;
        assert!(lockdown.is_engaged().await.is_some());
        lockdown.clear().await;
        assert!(lockdown.is_engaged().await.is_none());
    }

    #[tokio::test]
    async fn lockdown_handler_only_fires_on_critical() {
        let lockdown = ReadOnlyLockdown::default();
        let handler = ReadOnlyLockdownHandler::new(lockdown.clone());
        let low_event = FailureEvent::ReplicaUnreachable {
            replica_id: "r0".into(),
            duration: Duration::from_secs(10),
            quorum_still_holds: true,
        };
        let outcome = handler.handle(&low_event).await;
        assert!(matches!(outcome, HandlerOutcome::Skipped { .. }));
        assert!(lockdown.is_engaged().await.is_none());

        let crit_event = FailureEvent::ChainCorruption {
            chain_id: "c1".into(),
            detail: "hash mismatch".into(),
        };
        let outcome = handler.handle(&crit_event).await;
        assert!(matches!(outcome, HandlerOutcome::Ran { .. }));
        assert!(lockdown.is_engaged().await.is_some());
    }

    #[tokio::test]
    async fn credential_revoke_fires_only_with_admin_id() {
        let deny = CredentialDenyList::default();
        let handler = CredentialRevokeHandler::new(deny.clone());

        let with_admin = FailureEvent::VerificationDivergence {
            severity: Severity::Error,
            session_id: None,
            admin_id: Some("dba@co".into()),
            replicas_disagreed: vec!["r0".into(), "r1".into()],
            reason: "checksum mismatch".into(),
        };
        let outcome = handler.handle(&with_admin).await;
        assert!(matches!(outcome, HandlerOutcome::Ran { .. }));
        assert!(deny.contains("dba@co").await);

        let without_admin = FailureEvent::ChainCorruption {
            chain_id: "c1".into(),
            detail: "x".into(),
        };
        let outcome = handler.handle(&without_admin).await;
        assert!(matches!(outcome, HandlerOutcome::Skipped { .. }));
    }
}
