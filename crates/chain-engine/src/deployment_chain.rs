//! High-level DeploymentChainManager: append, read, verify, head operations
//! for the single deployment-wide chain.
//!
//! Per v1 spec §3.1, the deployment chain is an ordered sequence of
//! `DeploymentEvent` payloads inside the standard binary envelope (§4.1). Its
//! directory on disk is `_deployment/` — this is an implementation
//! detail, not part of the protocol. The HTTP surface uses
//! `/api/v1/chain/deployment/*` per §7.2.
//!
//! ## Durable tier
//!
//! After each successful local disk append, the manager fans out the
//! same entry to an optional [`MultiReplicaStorage`] holding N replica
//! MinIO clients. A quorum (⌊N/2⌋+1) must ack before the write is
//! considered durable.

use crate::deployment_entry::{self, DeploymentChainEntry};
use crate::deployment_storage::{DeploymentChainStore, DeploymentStorageError};
use crate::multi_replica_storage::MultiReplicaStorage;
use crate::verification_status::{record_durable_range, DurabilityTracker};
use chain_store::EntryError;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::Mutex;
use tracing::{error, info, warn};
use uninc_common::{AccessEvent, ActionType, ActorType, DeploymentCategory};
use uuid::Uuid;

pub const DEPLOYMENT_CHAIN_ID: &str = "_deployment";

#[derive(Debug, Error)]
pub enum DeploymentChainError {
    #[error("storage error: {0}")]
    Storage(#[from] DeploymentStorageError),
    #[error("entry serialization error: {0}")]
    Entry(#[from] EntryError),
    #[error("quorum not reached for durable write: {0}")]
    QuorumFailed(String),
}

/// Manages the single deployment-wide org chain.
pub struct DeploymentChainManager {
    store: DeploymentChainStore,
    /// Single write lock — the deployment chain is not sharded.
    write_lock: Mutex<()>,
    /// Durable tier: N replica MinIOs with quorum writes. None in single-host topologies.
    durable: Option<Arc<MultiReplicaStorage>>,
    durability: Arc<DurabilityTracker>,
    storage_root: std::path::PathBuf,
}

impl DeploymentChainManager {
    pub fn new(base_path: &Path) -> Result<Self, DeploymentChainError> {
        let store = DeploymentChainStore::open(base_path)?;
        Ok(Self {
            store,
            write_lock: Mutex::new(()),
            durable: None,
            durability: Arc::new(DurabilityTracker::default()),
            storage_root: base_path.to_path_buf(),
        })
    }

    pub fn with_durable(mut self, storage: Arc<MultiReplicaStorage>) -> Self {
        self.durable = Some(storage);
        self
    }

    async fn durable_commit(&self, index: u64, bytes: &[u8]) -> Result<(), DeploymentChainError> {
        let Some(durable) = self.durable.as_ref() else {
            return Ok(());
        };
        match durable
            .put_entry("_deployment", DEPLOYMENT_CHAIN_ID, index, bytes)
            .await
        {
            Ok(ack) => {
                info!(
                    index,
                    acked = ack.acked,
                    total = ack.total,
                    "deployment chain entry durably committed"
                );
                let sidecar = self
                    .storage_root
                    .join(DEPLOYMENT_CHAIN_ID)
                    .join("durable_ranges.json");
                if let Err(e) = record_durable_range(&sidecar, index, index + 1).await {
                    warn!(error = %e, "failed to write durable_ranges sidecar");
                }
                self.durability.mark_durable(DEPLOYMENT_CHAIN_ID, index).await;
                Ok(())
            }
            Err(e) => {
                error!(index, error = %e, "deployment chain durable commit failed (quorum)");
                Err(DeploymentChainError::QuorumFailed(e.to_string()))
            }
        }
    }

    /// Append an entry converted from an AccessEvent. Strips row-level
    /// detail and user IDs per §4.11.
    pub async fn append_from_access_event(
        &self,
        event: &AccessEvent,
    ) -> Result<(), DeploymentChainError> {
        let _guard = self.write_lock.lock().await;

        let prev_hash = self.store.read_head_hash()?.unwrap_or([0u8; 32]);
        let index = self.store.entry_count()?;

        let entry = deployment_entry::from_access_event(index, prev_hash, event)?;
        self.store.append(&entry)?;
        if let Ok(bytes) = serde_json::to_vec(&entry) {
            self.durable_commit(index, &bytes).await?;
        }
        Ok(())
    }

    /// Append a generic org event (config changes, deploys, system events, etc.).
    ///
    /// Returns the `(index, entry_hash)` of the appended entry so callers that
    /// need to reply with the tombstone identity (user-erasure, in particular —
    /// spec §7.3.1) can surface the real values instead of guessing.
    #[allow(clippy::too_many_arguments)]
    pub async fn append_deployment_event(
        &self,
        actor_id: &str,
        actor: ActorType,
        cat: DeploymentCategory,
        action: ActionType,
        resource: &str,
        scope: &str,
        details: Option<HashMap<String, String>>,
        artifact_hash: Option<[u8; 32]>,
        session_id: Option<Uuid>,
        source_ip: Option<&str>,
    ) -> Result<(u64, [u8; 32]), DeploymentChainError> {
        let _guard = self.write_lock.lock().await;

        let now_seconds = chrono::Utc::now().timestamp();
        let prev_hash = self.store.read_head_hash()?.unwrap_or([0u8; 32]);
        let index = self.store.entry_count()?;

        let payload = deployment_entry::build_deployment_event(
            actor_id,
            actor,
            cat,
            action,
            resource,
            scope,
            details,
            artifact_hash,
            session_id,
            source_ip,
        );
        let entry = DeploymentChainEntry::deployment(index, prev_hash, now_seconds, payload)?;
        let entry_hash = entry.entry_hash;
        // Ordering: DURABLE-first, LOCAL-second. Mirrors `ChainManager::append_event`;
        // closes the bifurcation hazard described in SPEC-DELTA.md
        // §"Durability consistency". Serialization and QuorumFailed both bubble
        // up before local advances; the NATS redelivery then rebuilds at the
        // SAME index with a fresh timestamp and durable's idempotent put either
        // overwrites or rejects as-already-present. No gap, no fork.
        let bytes = serde_json::to_vec(&entry).map_err(EntryError::Canonicalization)?;
        self.durable_commit(index, &bytes).await?;
        self.store.append(&entry)?;
        Ok((index, entry_hash))
    }

    /// Append a deployment event to the LOCAL hot tier only, tolerating
    /// durable-tier failure. Returns `Ok` as long as the local write
    /// succeeds, regardless of whether quorum ack was reached.
    ///
    /// Intended for the narrow case where the deployment chain needs to
    /// record a failure-signal entry (e.g. `quorum_failed`) while the
    /// durable tier is itself what's failing. A strict
    /// `append_deployment_event` call in that state would return
    /// `QuorumFailed` and the failure record would never reach the
    /// chain — the ironic "the system that records failures can't
    /// record its own failure" problem.
    ///
    /// The returned `local_only` flag lets the caller surface the
    /// durability downgrade; a later reconciliation step (future work)
    /// can re-attempt durable publication of the local-only entry once
    /// quorum returns.
    pub async fn append_deployment_event_best_effort(
        &self,
        actor_id: &str,
        actor: ActorType,
        cat: DeploymentCategory,
        action: ActionType,
        resource: &str,
        scope: &str,
        details: Option<HashMap<String, String>>,
        artifact_hash: Option<[u8; 32]>,
        session_id: Option<Uuid>,
        source_ip: Option<&str>,
    ) -> Result<BestEffortAppendOutcome, DeploymentChainError> {
        let _guard = self.write_lock.lock().await;

        let now_seconds = chrono::Utc::now().timestamp();
        let prev_hash = self.store.read_head_hash()?.unwrap_or([0u8; 32]);
        let index = self.store.entry_count()?;

        let payload = deployment_entry::build_deployment_event(
            actor_id,
            actor,
            cat,
            action,
            resource,
            scope,
            details,
            artifact_hash,
            session_id,
            source_ip,
        );
        let entry = DeploymentChainEntry::deployment(index, prev_hash, now_seconds, payload)?;
        let entry_hash = entry.entry_hash;
        self.store.append(&entry)?;

        let durable = if let Ok(bytes) = serde_json::to_vec(&entry) {
            match self.durable_commit(index, &bytes).await {
                Ok(()) => true,
                Err(e) => {
                    warn!(
                        index,
                        error = %e,
                        "best-effort deployment append: durable tier unreachable, entry \
                         persisted locally only"
                    );
                    false
                }
            }
        } else {
            false
        };

        Ok(BestEffortAppendOutcome {
            index,
            entry_hash,
            durable,
        })
    }

    pub fn read_range(
        &self,
        start: u64,
        limit: usize,
    ) -> Result<Vec<DeploymentChainEntry>, DeploymentChainError> {
        Ok(self.store.read_range(start, limit)?)
    }

    pub fn read_all(&self) -> Result<Vec<DeploymentChainEntry>, DeploymentChainError> {
        Ok(self.store.read_all()?)
    }

    pub fn head_hash(&self) -> Result<Option<[u8; 32]>, DeploymentChainError> {
        Ok(self.store.read_head_hash()?)
    }

    pub fn entry_count(&self) -> Result<u64, DeploymentChainError> {
        Ok(self.store.entry_count()?)
    }

    pub fn summary(&self) -> Result<DeploymentChainSummary, DeploymentChainError> {
        Ok(DeploymentChainSummary {
            entry_count: self.store.entry_count()?,
            head_hash: self.store.read_head_hash()?,
        })
    }
}

/// Outcome of [`DeploymentChainManager::append_deployment_event_best_effort`].
#[derive(Debug, Clone, Copy)]
pub struct BestEffortAppendOutcome {
    pub index: u64,
    pub entry_hash: [u8; 32],
    /// `true` if the durable-tier fan-out acked quorum; `false` if the
    /// entry is only in the local hot tier. `false` implies reconciliation
    /// is needed once quorum returns.
    pub durable: bool,
}

#[derive(Debug, Clone)]
pub struct DeploymentChainSummary {
    pub entry_count: u64,
    pub head_hash: Option<[u8; 32]>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deployment_entry::as_deployment;
    use tempfile::TempDir;
    use uninc_common::{AccessEvent, Protocol};

    fn make_access_event(admin: &str, resource: &str, users: Vec<&str>) -> AccessEvent {
        AccessEvent {
            protocol: Protocol::Postgres,
            admin_id: admin.into(),
            action: ActionType::Read,
            resource: resource.into(),
            scope: "test".into(),
            query_fingerprint: [0u8; 32],
            affected_users: users.into_iter().map(String::from).collect(),
            timestamp: chrono::Utc::now().timestamp_millis(),
            session_id: Uuid::new_v4(),
            metadata: HashMap::new(),
        }
    }

    #[tokio::test]
    async fn append_from_access_event_starts_at_zero() {
        let tmp = TempDir::new().unwrap();
        let mgr = DeploymentChainManager::new(tmp.path()).unwrap();

        let event = make_access_event("admin@co.com", "users", vec!["user_42"]);
        mgr.append_from_access_event(&event).await.unwrap();

        assert_eq!(mgr.entry_count().unwrap(), 1);
        let entries = mgr.read_all().unwrap();
        let org = as_deployment(&entries[0]).unwrap();
        assert_eq!(org.category, chain_store::DeploymentCategory::AdminAccess);
        assert_eq!(org.actor_id, "admin@co.com");
        assert_eq!(entries[0].prev_hash, [0u8; 32]);
        assert!(entries[0].verify_hash());
    }

    #[tokio::test]
    async fn append_event_with_no_users() {
        let tmp = TempDir::new().unwrap();
        let mgr = DeploymentChainManager::new(tmp.path()).unwrap();

        let event = make_access_event("dba", "(utility)", vec![]);
        mgr.append_from_access_event(&event).await.unwrap();

        let entries = mgr.read_all().unwrap();
        assert_eq!(entries.len(), 1);
        let org = as_deployment(&entries[0]).unwrap();
        assert_eq!(
            org.details.as_object().unwrap().get("affected_user_count"),
            Some(&serde_json::Value::Number(0.into()))
        );
    }

    #[tokio::test]
    async fn append_deployment_event_for_system_action() {
        let tmp = TempDir::new().unwrap();
        let mgr = DeploymentChainManager::new(tmp.path()).unwrap();

        mgr.append_deployment_event(
            "SYSTEM",
            ActorType::System,
            DeploymentCategory::System,
            ActionType::SchemaChange,
            "chain_engine",
            "chain engine restarted",
            Some(HashMap::from([("version".into(), "0.1.0".into())])),
            None,
            None,
            None,
        )
        .await
        .unwrap();

        let entries = mgr.read_all().unwrap();
        assert_eq!(entries.len(), 1);
        let org = as_deployment(&entries[0]).unwrap();
        assert_eq!(org.category, chain_store::DeploymentCategory::System);
    }

    #[tokio::test]
    async fn summary_reflects_state() {
        let tmp = TempDir::new().unwrap();
        let mgr = DeploymentChainManager::new(tmp.path()).unwrap();

        let summary = mgr.summary().unwrap();
        assert_eq!(summary.entry_count, 0);
        assert!(summary.head_hash.is_none());

        let event = make_access_event("admin", "t", vec![]);
        mgr.append_from_access_event(&event).await.unwrap();

        let summary = mgr.summary().unwrap();
        assert_eq!(summary.entry_count, 1);
        assert!(summary.head_hash.is_some());
    }
}
