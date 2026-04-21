use crate::error::UnincError;
use crate::health::SubsystemHealth;
use crate::tombstone::{TombstoneError, TombstoneWriter};
use crate::types::{
    AccessEvent, DeploymentEvent, ERASURE_NATS_SUBJECT, ErasureReceipt, ErasureRequest,
};
use async_nats::jetstream;
use async_trait::async_trait;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tracing::{error, info};

/// NATS client for the proxy + chain-engine.
///
/// Holds a JetStream context for the durable access-event pipeline AND a
/// core `async_nats::Client` for synchronous request/reply patterns like
/// the erasure tombstone (§7.3.1). The core client is cheap to clone — it
/// wraps an `Arc` internally — so this doesn't open a second connection.
///
/// Optionally holds a `SubsystemHealth` cell (`health_cell`): if set,
/// every publish through this client stamps ok on success or err on
/// failure. The proxy's `/health/detailed` endpoint reads this cell to
/// surface NATS liveness without the listener call sites needing to
/// import the health crate.
pub struct NatsClient {
    jetstream: jetstream::Context,
    core: async_nats::Client,
    subject_prefix: String,
    /// Outer `RwLock` so `with_health_cell` can be called after a
    /// read-only `Arc<NatsClient>` has been shared out — this is the
    /// bootstrap order in the proxy's `main.rs`, which constructs the
    /// NATS client before the `HealthState`. Reads on the publish path
    /// take the read-lock (contention-free in practice) and are cheap.
    health_cell: RwLock<Option<Arc<SubsystemHealth>>>,
}

impl NatsClient {
    /// Connect to NATS and create the JetStream context.
    pub async fn connect(url: &str, subject_prefix: &str) -> Result<Self, UnincError> {
        let client = async_nats::connect(url)
            .await
            .map_err(|e| UnincError::Nats(format!("failed to connect to {url}: {e}")))?;

        let jetstream = jetstream::new(client.clone());

        info!(url, "connected to NATS");

        Ok(Self {
            jetstream,
            core: client,
            subject_prefix: subject_prefix.to_string(),
            health_cell: RwLock::new(None),
        })
    }

    /// Install a `SubsystemHealth` cell to be stamped on every publish.
    /// Idempotent; the last caller wins. Intended to be called once from
    /// `main.rs` after `HealthState` is constructed.
    pub fn set_health_cell(&self, cell: Arc<SubsystemHealth>) {
        match self.health_cell.write() {
            Ok(mut g) => *g = Some(cell),
            Err(poisoned) => {
                let mut g = poisoned.into_inner();
                *g = Some(cell);
            }
        }
    }

    fn stamp_ok(&self) {
        if let Ok(g) = self.health_cell.read() {
            if let Some(cell) = g.as_ref() {
                cell.stamp_ok();
            }
        }
    }

    fn stamp_err(&self, reason: impl Into<String>) {
        if let Ok(g) = self.health_cell.read() {
            if let Some(cell) = g.as_ref() {
                cell.stamp_err(reason.into());
            }
        }
    }

    /// Ensure the JetStream stream exists for access and system events.
    ///
    /// Stream name: `UNINC_ACCESS`
    /// Subjects: `uninc.access.>`, `uninc.system.>`
    pub async fn ensure_stream(&self) -> Result<(), UnincError> {
        // Derive the system prefix from the access prefix.
        // uninc.access → uninc.system
        let system_prefix = self
            .subject_prefix
            .rsplit_once('.')
            .map(|(base, _)| format!("{base}.system"))
            .unwrap_or_else(|| format!("{}.system", self.subject_prefix));

        let stream_config = jetstream::stream::Config {
            name: "UNINC_ACCESS".to_string(),
            subjects: vec![
                format!("{}.>", self.subject_prefix),
                format!("{system_prefix}.>"),
            ],
            retention: jetstream::stream::RetentionPolicy::WorkQueue,
            max_age: std::time::Duration::from_secs(7 * 24 * 3600), // 7 days
            storage: jetstream::stream::StorageType::File,
            ..Default::default()
        };

        self.jetstream
            .get_or_create_stream(stream_config)
            .await
            .map_err(|e| UnincError::Nats(format!("failed to create stream: {e}")))?;

        info!("UNINC_ACCESS stream ready");
        Ok(())
    }

    /// Publish an access event for a specific user.
    ///
    /// Subject: `{prefix}.{user_id}` (e.g., `uninc.access.user_42`)
    /// NATS JetStream guarantees per-subject ordering.
    pub async fn publish_event(
        &self,
        user_id: &str,
        event: &AccessEvent,
    ) -> Result<(), UnincError> {
        let subject = format!("{}.{}", self.subject_prefix, user_id);
        let payload = serde_json::to_vec(event).map_err(|e| {
            let err = UnincError::Serialization(e.to_string());
            self.stamp_err(err.to_string());
            err
        })?;

        let outcome: Result<(), UnincError> = async {
            self.jetstream
                .publish(subject.clone(), payload.into())
                .await
                .map_err(|e| UnincError::Nats(format!("publish to {subject} failed: {e}")))?
                .await
                .map_err(|e| UnincError::Nats(format!("publish ack for {subject} failed: {e}")))?;
            Ok(())
        }
        .await;

        match &outcome {
            Ok(()) => self.stamp_ok(),
            Err(e) => self.stamp_err(e.to_string()),
        }
        outcome
    }

    /// Publish an access event to the deployment chain.
    ///
    /// Subject: `{prefix}._deployment` (e.g., `uninc.access._deployment`)
    /// The deployment chain receives EVERY admin operation, regardless of whether
    /// affected users were identified. This is the complete admin activity log.
    pub async fn publish_deployment_event(&self, event: &AccessEvent) -> Result<(), UnincError> {
        self.publish_event("_deployment", event).await
    }

    /// Publish an access event to the deployment chain AND all affected user chains.
    ///
    /// Always publishes to `_deployment` first (deployment chain gets every admin event).
    /// Then publishes to each affected user's chain (if any users identified).
    pub async fn publish_for_affected_users(&self, event: &AccessEvent) -> Result<(), UnincError> {
        // Deployment chain always gets the event — even with empty affected_users.
        self.publish_deployment_event(event).await?;

        // Per-user chains only for identified users.
        for user_id in &event.affected_users {
            if let Err(e) = self.publish_event(user_id, event).await {
                error!(user_id, error = %e, "failed to publish event for user");
                return Err(e);
            }
        }
        Ok(())
    }

    /// Publish a system-level org event (verification results, restarts, etc.).
    ///
    /// Subject: `uninc.system._deployment`
    /// Consumed by chain-engine and routed to `DeploymentChainManager.append_deployment_event()`.
    pub async fn publish_system_deployment_event(&self, event: &DeploymentEvent) -> Result<(), UnincError> {
        let system_prefix = self
            .subject_prefix
            .rsplit_once('.')
            .map(|(base, _)| format!("{base}.system"))
            .unwrap_or_else(|| format!("{}.system", self.subject_prefix));

        let subject = format!("{system_prefix}._deployment");
        let payload = match serde_json::to_vec(event) {
            Ok(p) => p,
            Err(e) => {
                let err = UnincError::Serialization(e.to_string());
                self.stamp_err(err.to_string());
                return Err(err);
            }
        };

        let outcome: Result<(), UnincError> = async {
            self.jetstream
                .publish(subject.clone(), payload.into())
                .await
                .map_err(|e| UnincError::Nats(format!("publish to {subject} failed: {e}")))?
                .await
                .map_err(|e| UnincError::Nats(format!("publish ack for {subject} failed: {e}")))?;
            Ok(())
        }
        .await;

        match &outcome {
            Ok(()) => self.stamp_ok(),
            Err(e) => self.stamp_err(e.to_string()),
        }
        outcome
    }

    /// Get the JetStream context for creating consumers.
    pub fn jetstream(&self) -> &jetstream::Context {
        &self.jetstream
    }

    /// Get the subject prefix.
    pub fn subject_prefix(&self) -> &str {
        &self.subject_prefix
    }

    /// Borrow the core `async_nats::Client` for pub/sub on subjects
    /// outside the JetStream pipeline — used by the subsystem-health
    /// relay (`uninc.ops.*`) which is ephemeral and does not need the
    /// durability guarantees of a JetStream stream.
    pub fn core_client(&self) -> &async_nats::Client {
        &self.core
    }

    /// Core-NATS request for an erasure tombstone commit. Spec §7.3.1
    /// requires the HTTP reply to carry the real `(index, entry_hash)` of
    /// the tombstone, so this uses request/reply (synchronous) instead of
    /// JetStream fire-and-forget.
    ///
    /// Timeout chosen as 5s: a deployment-chain append is a single local
    /// disk write plus a best-effort MinIO fan-out. Normal latency is
    /// milliseconds; 5s comfortably covers a GC pause or a slow replica
    /// ack without leaving the HTTP caller hanging.
    pub async fn request_erasure_tombstone(
        &self,
        request: &ErasureRequest,
    ) -> Result<ErasureReceipt, TombstoneError> {
        let payload = serde_json::to_vec(request)
            .map_err(|e| TombstoneError::Transport(format!("serialize request: {e}")))?;

        let reply = tokio::time::timeout(
            Duration::from_secs(5),
            self.core.request(ERASURE_NATS_SUBJECT, payload.into()),
        )
        .await
        .map_err(|_| {
            TombstoneError::Transport(
                "erasure request timed out after 5s — chain-engine unreachable or overloaded"
                    .into(),
            )
        })?
        .map_err(|e| TombstoneError::Transport(format!("nats request failed: {e}")))?;

        // Chain-engine encodes one of three shapes in the reply:
        //   1. ErasureReceipt JSON              → Ok(receipt)
        //   2. {"error": "..."}                 → Err(Refused(msg))
        //   3. {"receipt": ..., "partial_failure": "..."}  → Err(PartialErasure)
        //
        // (3) is the "tombstone committed but local/durable delete failed"
        // case per §8.1. The caller MUST surface the receipt so an operator
        // can run the durable-tier cleanup by hand.
        if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&reply.payload) {
            if let Some(err) = v.get("error").and_then(|x| x.as_str()) {
                return Err(TombstoneError::Refused(err.to_string()));
            }
            if let Some(msg) = v.get("partial_failure").and_then(|x| x.as_str()) {
                if let Some(receipt_json) = v.get("receipt") {
                    if let Ok(receipt) = serde_json::from_value::<ErasureReceipt>(
                        receipt_json.clone(),
                    ) {
                        return Err(TombstoneError::PartialErasure {
                            receipt,
                            message: msg.to_string(),
                        });
                    }
                }
                return Err(TombstoneError::Transport(format!(
                    "partial_failure reply missing valid receipt: {msg}"
                )));
            }
        }

        serde_json::from_slice(&reply.payload).map_err(|e| {
            TombstoneError::Transport(format!("decode erasure receipt: {e}"))
        })
    }
}

#[async_trait]
impl TombstoneWriter for NatsClient {
    async fn write_erasure_tombstone(
        &self,
        req: ErasureRequest,
    ) -> Result<ErasureReceipt, TombstoneError> {
        self.request_erasure_tombstone(&req).await
    }
}
