//! High-level ChainManager: append, read, verify, head operations for
//! per-user chains per Uninc Access Transparency v1.
//!
//! The v1 spec permits empty chains (§5.2.1 V7 — an empty chain has
//! `chain_head_hash = 0x00^32` and is valid). We therefore do NOT write
//! a genesis entry on chain creation; the first real `AccessEvent`
//! lands at `index = 0`.
//!
//! ## Durable tier
//!
//! After each successful local disk append, the manager fans the same
//! entry out to an optional [`MultiReplicaStorage`] holding N replica
//! MinIO clients. A quorum (⌊N/2⌋+1) must ack before the write is
//! considered durable. The durable_ranges sidecar records the ack so
//! the LRU cache knows the entry is safe to evict. On quorum failure
//! the write is logged at error level and the failure handler chain
//! fires from the proxy-level wiring.
//!
//! In single-host topologies there are no replicas, so the manager is
//! constructed with `durable = None` and only the local disk write runs.

use crate::entry::ChainEntry;
use crate::locks::ChainLocks;
use crate::multi_replica_storage::MultiReplicaStorage;
use crate::payload_from::{ms_to_seconds, to_access_payload};
use crate::storage::ChainStore;
use crate::verification_status::{record_durable_range, DurabilityTracker};
use crate::verify::{self, VerificationError};
use chain_store::EntryError;
use std::path::Path;
use std::sync::Arc;
use thiserror::Error;
use tracing::{error, info, warn};
use uninc_common::crypto::hash_user_id;
use uninc_common::AccessEvent;

#[derive(Debug, Error)]
pub enum ChainError {
    #[error("storage error: {0}")]
    Storage(#[from] crate::storage::StorageError),
    #[error("verification error: {0}")]
    Verification(#[from] VerificationError),
    #[error("entry serialization error: {0}")]
    Entry(#[from] EntryError),
    #[error("quorum not reached for durable write: {0}")]
    QuorumFailed(String),
}

/// Manages all users' chains.
pub struct ChainManager {
    base_path: Arc<Path>,
    salt: String,
    locks: ChainLocks,
    /// Durable tier: N replica MinIOs with quorum writes. None in single-host topologies.
    durable: Option<Arc<MultiReplicaStorage>>,
    /// Tracks which (chain, index) pairs are quorum-durable.
    durability: Arc<DurabilityTracker>,
}

impl ChainManager {
    pub fn new(base_path: &Path, salt: &str) -> Self {
        Self {
            base_path: Arc::from(base_path),
            salt: salt.to_string(),
            locks: ChainLocks::new(),
            durable: None,
            durability: Arc::new(DurabilityTracker::default()),
        }
    }

    /// Attach a multi-replica durable tier. Call once at startup.
    pub fn with_durable(mut self, storage: Arc<MultiReplicaStorage>) -> Self {
        self.durable = Some(storage);
        self
    }

    /// Quorum-commit a serialized entry to all replica MinIOs.
    /// Returns Ok immediately in single-host topologies (no replicas).
    async fn durable_commit(
        &self,
        chain_id: &str,
        index: u64,
        bytes: &[u8],
    ) -> Result<(), ChainError> {
        let Some(durable) = self.durable.as_ref() else {
            return Ok(());
        };
        match durable.put_entry("user", chain_id, index, bytes).await {
            Ok(ack) => {
                info!(
                    chain_id,
                    index,
                    acked = ack.acked,
                    total = ack.total,
                    "chain entry durably committed"
                );
                let sidecar = self.base_path.join(chain_id).join("durable_ranges.json");
                if let Err(e) = record_durable_range(&sidecar, index, index + 1).await {
                    warn!(error = %e, "failed to write durable_ranges sidecar");
                }
                self.durability.mark_durable(chain_id, index).await;
                Ok(())
            }
            Err(e) => {
                error!(chain_id, index, error = %e, "chain durable commit failed (quorum)");
                Err(ChainError::QuorumFailed(e.to_string()))
            }
        }
    }

    /// Ensure a user's chain directory exists. v1 chains are valid when
    /// empty (§5.2.1 V7), so no genesis entry is written.
    pub async fn create_chain(&self, user_id: &str) -> Result<(), ChainError> {
        let lock = self.locks.get(user_id);
        let _guard = lock.lock().await;
        ChainStore::open(&self.base_path, user_id, &self.salt)?;
        info!(user_id, "chain directory created (empty chain is valid per §5.2.1 V7)");
        Ok(())
    }

    /// Append an access event to a user's chain.
    ///
    /// Ordering: DURABLE-first, LOCAL-second. Closes the bifurcation hazard
    /// documented in SPEC-DELTA.md §"Durability consistency": if we wrote
    /// local first and durable failed with `QuorumFailed`, a NATS redelivery
    /// would read the advanced local count, build a fresh entry at N+1, and
    /// leave local with N_orig that durable never saw. Reversing this so
    /// durable sees the bytes first means a quorum failure leaves the local
    /// count untouched — the retry rebuilds at the SAME index N (with a new
    /// envelope timestamp, new hash), and durable's idempotent `put_entry`
    /// either overwrites the prior attempt at that key or rejects it as
    /// already-present. Either way, local and durable stay index-aligned.
    pub async fn append_event(
        &self,
        user_id: &str,
        event: &AccessEvent,
    ) -> Result<(), ChainError> {
        let lock = self.locks.get(user_id);
        let _guard = lock.lock().await;

        let store = ChainStore::open(&self.base_path, user_id, &self.salt)?;

        let prev_hash = store.read_head_hash()?.unwrap_or([0u8; 32]);
        let index = store.entry_count()?;

        let payload = to_access_payload(event, &self.salt);
        let timestamp = ms_to_seconds(event.timestamp);
        let entry = ChainEntry::access(index, prev_hash, timestamp, payload)?;

        let chain_id = hash_user_id(user_id, &self.salt);
        // Durable first. Any serialization failure (theoretically unreachable
        // for a typed `ChainEntry`, but we do not trust silent skips) and any
        // QuorumFailed bubble up; local never advances.
        let bytes = serde_json::to_vec(&entry).map_err(EntryError::Canonicalization)?;
        self.durable_commit(&chain_id, index, &bytes).await?;
        // Local after durable acked. If this local append fails, durable has
        // an entry the local tier doesn't know about. `ChainStore::open` does
        // NOT currently backfill from durable on restart — the `durable_ranges.json`
        // sidecar is written but not yet read back. A failure here leaves a
        // gap that only a future backfill-on-open implementation will close;
        // tracked as a v1.1 server ROADMAP item. For now the NATS redelivery
        // path is the only recovery: the redelivered event re-enters at the
        // SAME index (local never advanced), durable's idempotent put absorbs
        // the duplicate, and local gets its second-chance append.
        store.append(&entry)?;
        Ok(())
    }

    /// Read all entries for a user's chain.
    pub fn read_chain(&self, user_id: &str) -> Result<Vec<ChainEntry>, ChainError> {
        let store = ChainStore::open(&self.base_path, user_id, &self.salt)?;
        Ok(store.read_all()?)
    }

    /// Read paginated entries.
    pub fn read_entries(
        &self,
        user_id: &str,
        page: u64,
        limit: usize,
    ) -> Result<Vec<ChainEntry>, ChainError> {
        let store = ChainStore::open(&self.base_path, user_id, &self.salt)?;
        Ok(store.read_range(page * limit as u64, limit)?)
    }

    /// Verify a user's full chain.
    pub fn verify_chain(&self, user_id: &str) -> Result<(), ChainError> {
        let entries = self.read_chain(user_id)?;
        if entries.is_empty() {
            return Ok(());
        }
        verify::verify_chain(&entries)?;
        Ok(())
    }

    /// Get chain summary (entry count, head hash).
    pub fn chain_summary(&self, user_id: &str) -> Result<Option<ChainSummary>, ChainError> {
        let store = ChainStore::open(&self.base_path, user_id, &self.salt)?;
        if !store.exists() {
            return Ok(None);
        }
        let meta = store.read_meta()?;
        let head = store.read_head_hash()?;
        Ok(Some(ChainSummary {
            entry_count: meta.map(|m| m.entry_count).unwrap_or(0),
            head_hash: head,
        }))
    }

    /// Delete a user's chain (GDPR right-to-erasure per spec §8.1 + §7.3.1).
    ///
    /// Order: local disk first, then durable replicas. Local fs is the
    /// authoritative reader source; removing it first closes the hot-tier
    /// read surface immediately. Durable delete follows under quorum; if
    /// quorum fails, the local disk is already gone but the replicas
    /// retain data that the spec requires removed — the caller MUST
    /// surface the partial failure (typically as 503) so an operator
    /// can re-run the durable sweep by hand.
    pub async fn delete_chain(&self, user_id: &str) -> Result<(), ChainError> {
        let lock = self.locks.get(user_id);
        let _guard = lock.lock().await;

        let store = ChainStore::open(&self.base_path, user_id, &self.salt)?;
        store.delete()?;

        if let Some(durable) = self.durable.as_ref() {
            let chain_id = hash_user_id(user_id, &self.salt);
            durable
                .delete_prefix("user", &chain_id)
                .await
                .map_err(|e| ChainError::QuorumFailed(e.to_string()))?;
        }

        self.locks.remove(user_id);
        warn!(user_id, "chain deleted (local + durable)");
        Ok(())
    }

    /// Delete a per-user chain by its already-hashed chain id (no plaintext
    /// user_id required). Used by:
    ///   - the retention reaper, which walks the storage root and only has
    ///     the directory name (= chain_id hex);
    ///   - the erasure handler, which receives the hash from the proxy
    ///     tombstone request (plaintext user_id never leaves the proxy).
    ///
    /// Same ordering as `delete_chain`: local fs first, then durable replicas.
    ///
    /// Idempotent on a missing local dir: a concurrent reaper or an earlier
    /// partial run may have already removed the local copy. The durable
    /// replicas still get a delete sweep. The function only returns
    /// `QuorumFailed` if the durable-tier delete fails under quorum — that
    /// is the case callers must surface (the replicas retain data that
    /// §8.1 MUSTs require removed).
    pub async fn delete_chain_by_hash(&self, chain_id: &str) -> Result<(), ChainError> {
        // Lock under the hash — the reaper has no plaintext user_id to key
        // the locks map with. Reaper runs on chains that are already past
        // their retention cutoff, so concurrent writes to the same chain
        // would violate the retention contract anyway; the lock here is
        // defense-in-depth against a racing append.
        let lock = self.locks.get(chain_id);
        let _guard = lock.lock().await;

        match ChainStore::open_by_hash(&self.base_path, chain_id) {
            Ok(store) => {
                store.delete()?;
            }
            Err(crate::storage::StorageError::ChainNotFound(_)) => {
                // Already gone locally — fall through to durable delete.
                info!(chain_id, "local chain directory already absent; only durable delete will run");
            }
            Err(e) => return Err(e.into()),
        }

        if let Some(durable) = self.durable.as_ref() {
            durable
                .delete_prefix("user", chain_id)
                .await
                .map_err(|e| ChainError::QuorumFailed(e.to_string()))?;
        }

        self.locks.remove(chain_id);
        warn!(chain_id, "chain deleted by hash (local + durable)");
        Ok(())
    }
}

/// Summary of a user's chain state.
#[derive(Debug, Clone)]
pub struct ChainSummary {
    pub entry_count: u64,
    pub head_hash: Option<[u8; 32]>,
}
