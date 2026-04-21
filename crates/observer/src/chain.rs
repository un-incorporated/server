//! Observer chain storage — wraps `chain-store` so the observer produces
//! on-disk chains in the exact same format the proxy uses.
//!
//! Observer and proxy both hash through `chain_store::compute_hash`
//! (spec v1 §5.1). For the same sequence of `ObservedDeploymentEvent`
//! payloads, both sides produce byte-identical payload bytes — which is
//! the comparison unit §5.5 requires.
//!
//! The observer only appends to the `_deployment` chain. Per-user chain
//! resolution requires schema config (which tables map to which user
//! IDs), and the observer's job is to independently verify what the
//! *database* did — not to replicate the proxy's user-resolution logic.
//!
//! # Payload type
//!
//! Observer entries carry payload type `0x03` (`ObservedDeploymentEvent`,
//! spec §4.12). That's a strict structural subset of `DeploymentEvent`
//! (`0x02`) — only fields both the proxy and the replication stream can
//! honestly derive (action, resource, actor_id_hash, user_id_hashes,
//! query_fingerprint). Rich proxy-side metadata (source_ip, session_id,
//! free-form details) lives in proxy-side sidecar metadata per §6.4,
//! never on the observer chain.

use chain_store::{
    ChainEntry, ChainStore, ObservedAction, ObservedDeploymentEvent,
};
use dashmap::DashMap;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tracing::{debug, warn};

type HmacSha256 = Hmac<Sha256>;

/// Observer-owned chain writer. Wraps `chain_store::ChainStore` for the
/// actual disk I/O and maintains an in-memory cache of per-chain head
/// hashes to avoid re-reading head.hash on every append.
pub struct ObserverChain {
    base_path: PathBuf,
    /// Deployment salt — HMAC key used to derive the `actor_id_hash`
    /// field of `ObservedDeploymentEvent`. MUST match the proxy's
    /// `deployment_salt` so the observer's and proxy's hashes for the
    /// same pre-hash actor identifier agree byte-for-byte.
    deployment_salt: String,
    /// chain_id → (next_index, current_head_hash).
    heads: DashMap<String, (u64, [u8; 32])>,
}

impl ObserverChain {
    pub fn new(base_path: impl Into<PathBuf>, deployment_salt: impl Into<String>) -> Self {
        Self {
            base_path: base_path.into(),
            deployment_salt: deployment_salt.into(),
            heads: DashMap::new(),
        }
    }

    /// Append a new entry to the named chain as an `ObservedDeploymentEvent`
    /// payload (spec §4.12, payload type `0x03`). `chain_id` is typically
    /// `"_deployment"`.
    ///
    /// `actor_pre_hash` is the actor identifier as it appears in the
    /// replication stream — e.g. the Postgres `application_name` marker
    /// or the S3 object metadata `x-amz-meta-uninc-actor` attribute. It
    /// is HMAC'd with the deployment salt to produce `actor_id_hash`.
    /// When marker injection isn't yet wired for a primitive (e.g., the
    /// current MinIO subscriber hardcodes a placeholder), the resulting
    /// hash is still well-formed — it just won't byte-match the proxy's
    /// entry until both emitters agree on the pre-hash value.
    ///
    /// The `_scope` and `_metadata` parameters are accepted for
    /// subscriber compatibility but no longer hashed — §4.12 doesn't
    /// carry a free-form details field (sidecar metadata, §6.4, is
    /// served alongside the entry by the proxy's chain API, not by the
    /// observer). Subscribers may migrate off them at their convenience.
    pub async fn append(
        &self,
        chain_id: &str,
        actor_pre_hash: String,
        action: uninc_common::ActionType,
        resource: String,
        _scope: String,
        query_fingerprint: [u8; 32],
        _metadata: Option<HashMap<String, String>>,
    ) -> anyhow::Result<()> {
        let observer_dir = self.chain_dir(chain_id);
        std::fs::create_dir_all(&observer_dir)?;

        // Map the broader ActionType enum to the four replication-
        // observable verbs §4.12 defines. ActionType variants without a
        // replication counterpart (Export, AccountCreated, ChainRecovery)
        // cannot honestly appear on the observer chain — an observer
        // that sees them is by definition mislabelling WAL/oplog events.
        let observed_action = match action {
            uninc_common::ActionType::Read => ObservedAction::Read,
            uninc_common::ActionType::Write => ObservedAction::Write,
            uninc_common::ActionType::Delete => ObservedAction::Delete,
            uninc_common::ActionType::SchemaChange => ObservedAction::SchemaChange,
            uninc_common::ActionType::Export
            | uninc_common::ActionType::AccountCreated
            | uninc_common::ActionType::ChainRecovery => {
                warn!(
                    ?action,
                    "observer dropping non-replication-observable action \
                     (spec §4.12 enumerates only read/write/delete/schema_change)"
                );
                return Ok(());
            }
        };

        let (index, prev_hash) = {
            let entry = self
                .heads
                .entry(chain_id.to_string())
                .or_try_insert_with(|| self.load_head_state(chain_id))?;
            let pair = *entry.value();
            drop(entry);
            pair
        };

        let timestamp_seconds = chrono::Utc::now().timestamp();

        let actor_id_hash = hmac_hex(&self.deployment_salt, &actor_pre_hash);

        let payload = ObservedDeploymentEvent {
            action: observed_action,
            resource,
            actor_id_hash,
            query_fingerprint: hex::encode(query_fingerprint),
        };

        let entry = ChainEntry::observed(index, prev_hash, timestamp_seconds, payload)?;

        let store = ChainStore::open_by_hash(
            observer_dir.parent().unwrap_or(&self.base_path),
            &chain_id_to_dir_name(chain_id),
        )?;
        store.append(&entry)?;

        self.heads
            .insert(chain_id.to_string(), (index + 1, entry.entry_hash));

        debug!(
            chain_id,
            index,
            entry_hash = hex::encode(entry.entry_hash),
            "observer chain entry appended"
        );

        Ok(())
    }

    /// Read a paginated range of chain entries, starting at
    /// `start_index` (0-based) and returning up to `limit` entries.
    /// Returns an empty vector when the caller has read past the tail.
    ///
    /// The verification task uses this to fetch observer entries since
    /// its last-verified cursor, project them into `running_hash`
    /// inputs, and compare the result against the proxy's projection
    /// of its own `DeploymentEvent` entries over the same window
    /// (spec §5.5 byte-level payload comparison).
    pub async fn read_entries(
        &self,
        chain_id: &str,
        start_index: u64,
        limit: usize,
    ) -> anyhow::Result<Vec<ChainEntry>> {
        let observer_dir = self.chain_dir(chain_id);
        if !observer_dir.exists() {
            return Ok(Vec::new());
        }
        let store = ChainStore::open_by_hash(
            observer_dir.parent().unwrap_or(&self.base_path),
            &chain_id_to_dir_name(chain_id),
        )?;
        Ok(store.read_range(start_index, limit)?)
    }

    /// Total entry count on the given chain (reads from meta.json).
    /// Callers use this to compute `next_cursor` pagination and to
    /// detect truncation attacks (observer chain that shrank between
    /// two reads).
    pub async fn entry_count(&self, chain_id: &str) -> anyhow::Result<u64> {
        let observer_dir = self.chain_dir(chain_id);
        if !observer_dir.exists() {
            return Ok(0);
        }
        let store = ChainStore::open_by_hash(
            observer_dir.parent().unwrap_or(&self.base_path),
            &chain_id_to_dir_name(chain_id),
        )?;
        Ok(store.entry_count()?)
    }

    /// Read the current head hash for a chain. `None` if the chain
    /// doesn't exist yet.
    pub async fn read_head(&self, chain_id: &str) -> anyhow::Result<Option<[u8; 32]>> {
        if let Some(entry) = self.heads.get(chain_id) {
            let (idx, hash) = entry.value();
            if *idx > 0 {
                return Ok(Some(*hash));
            }
        }

        let head_path = self.chain_dir(chain_id).join("head.hash");
        if !head_path.exists() {
            return Ok(None);
        }
        let bytes = std::fs::read(&head_path)?;
        if bytes.len() != 32 {
            anyhow::bail!(
                "observer chain head.hash at {:?} has wrong size: {}",
                head_path,
                bytes.len()
            );
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(Some(out))
    }

    /// Load the current (next_index, head_hash) from disk for a chain.
    /// Returns `(0, [0; 32])` for a chain that has not been written yet.
    fn load_head_state(&self, chain_id: &str) -> anyhow::Result<(u64, [u8; 32])> {
        let dir = self.chain_dir(chain_id);
        let meta_path = dir.join("meta.json");
        let head_path = dir.join("head.hash");

        if !meta_path.exists() || !head_path.exists() {
            return Ok((0, [0u8; 32]));
        }

        let meta_raw = std::fs::read_to_string(&meta_path)?;
        let meta: serde_json::Value = serde_json::from_str(&meta_raw)?;
        let count = meta
            .get("entry_count")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        let bytes = std::fs::read(&head_path)?;
        if bytes.len() != 32 {
            warn!(chain_id, "corrupt head.hash, starting fresh");
            return Ok((0, [0u8; 32]));
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&bytes);

        Ok((count, hash))
    }

    fn chain_dir(&self, chain_id: &str) -> PathBuf {
        self.base_path.join("observer").join(chain_id)
    }

    pub fn base_path(&self) -> &Path {
        &self.base_path
    }
}

fn chain_id_to_dir_name(chain_id: &str) -> String {
    chain_id.to_string()
}

/// Hex-encoded `HMAC-SHA-256(deployment_salt, actor_pre_hash)`.
/// Spec §3.2 convention — lower-case hex, no separators. Proxy-side code
/// uses the same formula in `uninc_common::crypto::hash_user_id`; they
/// MUST produce identical output for identical inputs so §5.5 byte
/// comparison holds.
fn hmac_hex(salt: &str, value: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(salt.as_bytes())
        .expect("HMAC-SHA256 accepts any key length");
    mac.update(value.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}
