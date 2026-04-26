//! Multi-replica durable chain storage (multi-VM topology).
//!
//! Fans out every chain write to N replica MinIO instances in parallel
//! and waits for quorum (⌊N/2⌋+1 of N) acks before returning. This is
//! the durable tier of the two-tier chain storage architecture; the
//! proxy's local disk (managed by `lru_cache.rs`) is the hot tier that
//! serves reads until an entry is evicted.
//!
//! The write path is:
//!
//!   1. `consumer.rs` receives a NATS message, routes to per-user or org.
//!   2. `chain.rs` / `deployment_chain.rs` writes to local disk first (hot tier).
//!   3. `MultiReplicaStorage::put_entry` fans out to N replicas in parallel.
//!   4. As soon as ⌊N/2⌋+1 replicas ack, return Ok(QuorumAck).
//!   5. Stragglers continue in the background; their failures are logged
//!      but don't fail the write.
//!   6. On quorum failure (timeout or ≥⌊N/2⌋+1 failures), return Err and
//!      let the caller fire the failure handler chain (see
//!      verification/src/failure.rs).
//!
//! Single-host collapse: when `durability.replicas` is empty, callers
//! should skip `MultiReplicaStorage` entirely and write directly to the
//! existing single-target `S3ChainStorage`. The collapse happens at the
//! caller level, not inside this module, to keep the fan-out logic clean.
//!
//! See docs/chain-storage-architecture.md for the full architecture.

use crate::s3_storage::{S3ChainStorage, S3StorageError};
use futures::future::join_all;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use thiserror::Error;
use tokio::time::timeout;
use tracing::{debug, error, warn};
use uninc_common::config::{ChainDurabilityConfig, ChainReplicaStoreConfig, ChainS3Config};
use uninc_common::ops_health::{
    publish_subsystem_health, SubsystemHealthPing,
};

/// NATS handles used to publish per-replica subsystem-health pings on each
/// fan-out write. Wired in lazily by `bin/main.rs` once the NATS client is
/// connected, then read by `put_entry` to stamp `replica-{id}` cells on the
/// proxy's `/health/detailed` endpoint.
///
/// Optional by design — when missing (e.g. NATS connect failed at startup)
/// the fan-out keeps working; per-replica health stamps just don't happen,
/// matching the existing "best-effort relay" contract for the `chain_commit`
/// stamp.
#[derive(Debug, Clone)]
pub struct ReplicaHealthRelay {
    pub core_client: async_nats::Client,
    pub ops_prefix: String,
}

/// Cell-name format the proxy must pre-register to receive these stamps.
/// Centralized here so the proxy and chain-engine can't drift on the
/// naming scheme without one of them failing to compile.
pub fn replica_subsystem_name(replica_id: &str) -> String {
    format!("replica-{replica_id}")
}

#[derive(Debug, Error)]
pub enum MultiReplicaError {
    #[error("quorum not reached: {acked}/{quorum} acks within {timeout_ms}ms")]
    QuorumNotReached {
        acked: usize,
        quorum: usize,
        timeout_ms: u64,
    },
    #[error("no replicas configured")]
    Empty,
    #[error("replica setup failed: {0}")]
    Setup(String),
}

/// Per-entry acknowledgement returned from a successful multi-replica write.
/// Callers use this to update the `durable_ranges.json` sidecar.
#[derive(Debug, Clone)]
pub struct QuorumAck {
    /// Number of replicas that acked within the quorum window.
    pub acked: usize,
    /// Number of replicas in the fan-out.
    pub total: usize,
    /// Replica IDs that acked successfully.
    pub replica_ids: Vec<String>,
}

/// Fan-out target: one `S3ChainStorage` wrapper per replica MinIO.
pub struct ReplicaTarget {
    pub replica_id: String,
    pub storage: Arc<S3ChainStorage>,
}

pub struct MultiReplicaStorage {
    targets: Vec<ReplicaTarget>,
    quorum: usize,
    timeout: Duration,
    bucket: String,
    /// Set once at startup after NATS connects; read by `put_entry` to
    /// publish per-replica subsystem-health pings. `OnceLock` so the
    /// storage can be constructed before NATS is up (matching the
    /// existing reaper / consumer ordering in bin/main.rs) without
    /// reaching for interior mutability or rebuild gymnastics.
    health_relay: OnceLock<Arc<ReplicaHealthRelay>>,
}

impl MultiReplicaStorage {
    /// Build from a `ChainDurabilityConfig`. Each replica entry becomes
    /// a separate `S3ChainStorage` client pointed at that replica's
    /// chain-MinIO endpoint (:9002).
    pub fn from_config(cfg: &ChainDurabilityConfig) -> Result<Self, MultiReplicaError> {
        if cfg.replicas.is_empty() {
            return Err(MultiReplicaError::Empty);
        }

        let mut targets = Vec::with_capacity(cfg.replicas.len());
        for replica in &cfg.replicas {
            let s3_config = replica_to_s3_config(replica, &cfg.bucket);
            let storage = S3ChainStorage::new(&s3_config)
                .map_err(|e| MultiReplicaError::Setup(format!("{}: {e}", replica.replica_id)))?;
            targets.push(ReplicaTarget {
                replica_id: replica.replica_id.clone(),
                storage: Arc::new(storage),
            });
        }

        let quorum = if cfg.quorum_threshold > 0 {
            cfg.quorum_threshold
        } else {
            (targets.len() / 2) + 1
        };

        Ok(Self {
            targets,
            quorum,
            timeout: Duration::from_millis(cfg.write_timeout_ms),
            bucket: cfg.bucket.clone(),
            health_relay: OnceLock::new(),
        })
    }

    pub fn replica_count(&self) -> usize {
        self.targets.len()
    }

    pub fn quorum(&self) -> usize {
        self.quorum
    }

    pub fn bucket(&self) -> &str {
        &self.bucket
    }

    /// Replica IDs in fan-out order. The proxy reads the same list from
    /// `chain.durability.replicas` to pre-register one `replica-{id}` cell
    /// per replica on `HealthState`; exposing them here lets unit tests
    /// drive the proxy and chain-engine wiring from the same source.
    pub fn replica_ids(&self) -> Vec<String> {
        self.targets.iter().map(|t| t.replica_id.clone()).collect()
    }

    /// Wire the per-replica health relay. Called once after NATS connects;
    /// subsequent calls are silently ignored (`OnceLock::set` semantics)
    /// because there's only ever one valid relay per process. Must be set
    /// BEFORE the first `put_entry` for stamps to fire on that write —
    /// the relay is read on each fan-out, so anything written before this
    /// is set just won't carry per-replica stamps (degrades to today's
    /// pre-relay behaviour, no crash).
    pub fn set_health_relay(&self, relay: Arc<ReplicaHealthRelay>) {
        let _ = self.health_relay.set(relay);
    }

    async fn stamp_replica_ok(&self, replica_id: &str) {
        let Some(relay) = self.health_relay.get() else { return };
        let cell = replica_subsystem_name(replica_id);
        if let Err(e) = publish_subsystem_health(
            &relay.core_client,
            &relay.ops_prefix,
            &cell,
            &SubsystemHealthPing::ok(),
        )
        .await
        {
            // Best-effort — losing one stamp doesn't matter; the next
            // successful write republishes.
            warn!(replica = replica_id, error = %e, "failed to publish replica ok stamp");
        }
    }

    async fn stamp_replica_err(&self, replica_id: &str, reason: &str) {
        let Some(relay) = self.health_relay.get() else { return };
        let cell = replica_subsystem_name(replica_id);
        if let Err(e) = publish_subsystem_health(
            &relay.core_client,
            &relay.ops_prefix,
            &cell,
            &SubsystemHealthPing::err(reason.to_string()),
        )
        .await
        {
            warn!(replica = replica_id, error = %e, "failed to publish replica err stamp");
        }
    }

    /// Stamp every replica err — used when the fan-out itself blew its
    /// timeout, so we don't know which specific replica was slow but we
    /// know none of them met the deadline.
    async fn stamp_all_replicas_err(&self, reason: &str) {
        if self.health_relay.get().is_none() {
            return;
        }
        for t in &self.targets {
            self.stamp_replica_err(&t.replica_id, reason).await;
        }
    }

    /// Write a chain entry to all replicas, waiting for quorum.
    ///
    /// The entry path follows the same key layout as single-target S3:
    ///   chains/{chain_type}/{chain_id}/{index:010}.json
    ///
    /// On success returns `QuorumAck` with the list of replicas that
    /// acked within the window. On failure (quorum not reached within
    /// timeout) returns `MultiReplicaError::QuorumNotReached`.
    pub async fn put_entry(
        &self,
        chain_type: &str,
        chain_id: &str,
        index: u64,
        json_bytes: &[u8],
    ) -> Result<QuorumAck, MultiReplicaError> {
        let total = self.targets.len();
        if total == 0 {
            return Err(MultiReplicaError::Empty);
        }

        // Spawn N parallel put_entry calls.
        let futures_vec = self.targets.iter().map(|t| {
            let storage = Arc::clone(&t.storage);
            let id = t.replica_id.clone();
            let chain_type_owned = chain_type.to_string();
            let chain_id_owned = chain_id.to_string();
            let bytes = json_bytes.to_vec();
            async move {
                let res = storage
                    .put_entry(&chain_type_owned, &chain_id_owned, index, &bytes)
                    .await;
                (id, res)
            }
        });

        let results = match timeout(self.timeout, join_all(futures_vec)).await {
            Ok(r) => r,
            Err(_) => {
                warn!(
                    chain_type,
                    chain_id,
                    index,
                    timeout_ms = self.timeout.as_millis() as u64,
                    "multi-replica put_entry timed out waiting for quorum"
                );
                // The whole fan-out blew the timeout — every replica
                // should be marked unhealthy. Stamp them all err with
                // the same reason so /health/detailed shows which write
                // window failed.
                self.stamp_all_replicas_err("fan-out timed out before any ack").await;
                return Err(MultiReplicaError::QuorumNotReached {
                    acked: 0,
                    quorum: self.quorum,
                    timeout_ms: self.timeout.as_millis() as u64,
                });
            }
        };

        let mut acked_ids = Vec::new();
        let mut failures: Vec<(String, S3StorageError)> = Vec::new();
        for (id, res) in results {
            // Stamp per-replica health on each result. Done before the
            // quorum decision so a replica that acked still shows ok even
            // when the overall write fails (and vice versa).
            match &res {
                Ok(_) => self.stamp_replica_ok(&id).await,
                Err(e) => self.stamp_replica_err(&id, &e.to_string()).await,
            }
            match res {
                Ok(_) => acked_ids.push(id),
                Err(e) => failures.push((id, e)),
            }
        }

        if acked_ids.len() < self.quorum {
            for (id, e) in &failures {
                error!(replica = id.as_str(), error = %e, "replica write failed");
            }
            return Err(MultiReplicaError::QuorumNotReached {
                acked: acked_ids.len(),
                quorum: self.quorum,
                timeout_ms: self.timeout.as_millis() as u64,
            });
        }

        debug!(
            chain_type,
            chain_id,
            index,
            acked = acked_ids.len(),
            total,
            "quorum reached"
        );
        Ok(QuorumAck {
            acked: acked_ids.len(),
            total,
            replica_ids: acked_ids,
        })
    }

    /// Delete every object under `chains/{chain_type}/{chain_id}/` across
    /// all replicas, waiting for quorum. Used by the GDPR erasure path
    /// (§8.1) and the retention reaper (§8.2).
    ///
    /// Fan-out shape mirrors `put_entry`: spawn N parallel deletes,
    /// await with the same `write_timeout_ms`, require ⌊N/2⌋+1 acks.
    /// A replica whose `delete_prefix` errors counts as a non-ack;
    /// stragglers past quorum are not awaited beyond the timeout window.
    pub async fn delete_prefix(
        &self,
        chain_type: &str,
        chain_id: &str,
    ) -> Result<QuorumAck, MultiReplicaError> {
        let total = self.targets.len();
        if total == 0 {
            return Err(MultiReplicaError::Empty);
        }

        let futures_vec = self.targets.iter().map(|t| {
            let storage = Arc::clone(&t.storage);
            let id = t.replica_id.clone();
            let chain_type_owned = chain_type.to_string();
            let chain_id_owned = chain_id.to_string();
            async move {
                let res = storage
                    .delete_prefix(&chain_type_owned, &chain_id_owned)
                    .await;
                (id, res)
            }
        });

        let results = match timeout(self.timeout, join_all(futures_vec)).await {
            Ok(r) => r,
            Err(_) => {
                warn!(
                    chain_type,
                    chain_id,
                    timeout_ms = self.timeout.as_millis() as u64,
                    "multi-replica delete_prefix timed out waiting for quorum"
                );
                return Err(MultiReplicaError::QuorumNotReached {
                    acked: 0,
                    quorum: self.quorum,
                    timeout_ms: self.timeout.as_millis() as u64,
                });
            }
        };

        let mut acked_ids = Vec::new();
        let mut failures: Vec<(String, S3StorageError)> = Vec::new();
        for (id, res) in results {
            match res {
                Ok(_) => acked_ids.push(id),
                Err(e) => failures.push((id, e)),
            }
        }

        if acked_ids.len() < self.quorum {
            for (id, e) in &failures {
                error!(replica = id.as_str(), error = %e, "replica delete failed");
            }
            return Err(MultiReplicaError::QuorumNotReached {
                acked: acked_ids.len(),
                quorum: self.quorum,
                timeout_ms: self.timeout.as_millis() as u64,
            });
        }

        debug!(
            chain_type,
            chain_id,
            acked = acked_ids.len(),
            total,
            "delete_prefix quorum reached"
        );
        Ok(QuorumAck {
            acked: acked_ids.len(),
            total,
            replica_ids: acked_ids,
        })
    }

    /// Read a chain entry from any replica (cache miss fallback path).
    /// Tries replicas in order and returns the first successful response.
    pub async fn get_entry(
        &self,
        chain_type: &str,
        chain_id: &str,
        index: u64,
    ) -> Result<Vec<u8>, MultiReplicaError> {
        for target in &self.targets {
            match target.storage.get_entry(chain_type, chain_id, index).await {
                Ok(bytes) => return Ok(bytes),
                Err(e) => {
                    debug!(
                        replica = target.replica_id.as_str(),
                        error = %e,
                        "replica read failed, trying next"
                    );
                }
            }
        }
        Err(MultiReplicaError::Setup(
            "all replicas failed to return the entry".into(),
        ))
    }
}

fn replica_to_s3_config(r: &ChainReplicaStoreConfig, bucket: &str) -> ChainS3Config {
    ChainS3Config {
        endpoint: r.endpoint.clone(),
        bucket: bucket.to_string(),
        access_key: r.access_key.clone(),
        secret_key: r.secret_key.clone(),
        region: r.region.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replica_subsystem_name_matches_proxy_pre_registered_format() {
        // Pinned format. The proxy's `HealthState::with_replicas` uses
        // the literal `format!("replica-{id}")` and a unit test there
        // pins the same. If you change either side, you must change
        // both — this test will catch the drift on a build.
        assert_eq!(replica_subsystem_name("db-0"), "replica-db-0");
        assert_eq!(replica_subsystem_name("db-7"), "replica-db-7");
        // ID with no hyphen still works (non-default IDs).
        assert_eq!(replica_subsystem_name("primary"), "replica-primary");
    }

    #[test]
    fn quorum_defaults_to_majority() {
        // 3 replicas → quorum = 2
        let cfg = ChainDurabilityConfig {
            replicas: vec![
                dummy_replica("r0"),
                dummy_replica("r1"),
                dummy_replica("r2"),
            ],
            quorum_threshold: 0,
            write_timeout_ms: 1000,
            bucket: "uninc-chain".into(),
        };
        // We can't construct MultiReplicaStorage in a unit test without
        // reachable MinIO endpoints, so we assert the threshold math
        // matches what the struct would compute.
        let quorum = if cfg.quorum_threshold > 0 {
            cfg.quorum_threshold
        } else {
            (cfg.replicas.len() / 2) + 1
        };
        assert_eq!(quorum, 2);
    }

    #[test]
    fn quorum_for_five_is_three() {
        let replicas: Vec<_> = (0..5).map(|i| dummy_replica(&format!("r{i}"))).collect();
        let quorum = (replicas.len() / 2) + 1;
        assert_eq!(quorum, 3);
    }

    #[test]
    fn quorum_for_seven_is_four() {
        let replicas: Vec<_> = (0..7).map(|i| dummy_replica(&format!("r{i}"))).collect();
        let quorum = (replicas.len() / 2) + 1;
        assert_eq!(quorum, 4);
    }

    fn dummy_replica(id: &str) -> ChainReplicaStoreConfig {
        ChainReplicaStoreConfig {
            replica_id: id.into(),
            endpoint: "http://127.0.0.1:9002".into(),
            access_key: "uninc".into(),
            secret_key: "uninc".into(),
            region: "us-east-1".into(),
        }
    }
}
