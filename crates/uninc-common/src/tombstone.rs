//! User-erasure tombstone writer abstraction — §7.3.1 / §8.1 of the protocol spec.
//!
//! The proxy's DELETE /api/v1/chain/u/{user_id} handler MUST commit a
//! `UserErasureRequested` entry to the deployment chain before (or as part
//! of) replying to the caller. The handler can't do that write itself —
//! chain-engine owns the deployment-chain file, not the proxy — so the
//! handler goes through this trait.
//!
//! Production wiring: `NatsTombstoneWriter` publishes a core-NATS request
//! on `ERASURE_NATS_SUBJECT`; chain-engine's subscriber calls into
//! `DeploymentChainManager::append_deployment_event` and replies with the
//! resulting `(index, entry_hash)`.
//!
//! Test wiring: `InMemoryTombstoneWriter` returns canned receipts and
//! records every request for assertion — no NATS cluster required.

use crate::types::{ErasureReceipt, ErasureRequest};
use async_trait::async_trait;
use std::sync::Mutex;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TombstoneError {
    /// NATS publish or reply-wait failed. Network, timeout, or reply decode.
    /// The tombstone is NOT committed; retry is safe.
    #[error("tombstone transport failure: {0}")]
    Transport(String),
    /// Chain-engine returned an explicit error instead of a receipt.
    /// The tombstone is NOT committed; retry is safe.
    #[error("chain-engine refused tombstone: {0}")]
    Refused(String),
    /// Tombstone IS committed on the deployment chain, but the subsequent
    /// physical chain delete (local fs + durable replicas per §8.1) failed.
    /// The caller MUST surface the receipt so an operator can run the
    /// durable-tier cleanup by hand; automatic retry of the DELETE would
    /// double-tombstone.
    #[error("partial erasure: tombstone index={} committed, delete failed: {message}", .receipt.tombstone_deployment_chain_index)]
    PartialErasure {
        receipt: crate::types::ErasureReceipt,
        message: String,
    },
}

#[async_trait]
pub trait TombstoneWriter: Send + Sync {
    async fn write_erasure_tombstone(
        &self,
        req: ErasureRequest,
    ) -> Result<ErasureReceipt, TombstoneError>;
}

/// In-memory tombstone writer for unit tests. Returns a synthetic receipt
/// (`index = <recorded count>`, `entry_id = sha256("test-tombstone:<hash>")`)
/// and records every request so the test can assert.
pub struct InMemoryTombstoneWriter {
    received: Mutex<Vec<ErasureRequest>>,
}

impl InMemoryTombstoneWriter {
    pub fn new() -> Self {
        Self {
            received: Mutex::new(Vec::new()),
        }
    }

    pub fn received(&self) -> Vec<ErasureRequest> {
        self.received.lock().unwrap().clone()
    }
}

impl Default for InMemoryTombstoneWriter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl TombstoneWriter for InMemoryTombstoneWriter {
    async fn write_erasure_tombstone(
        &self,
        req: ErasureRequest,
    ) -> Result<ErasureReceipt, TombstoneError> {
        let mut received = self.received.lock().unwrap();
        let index = received.len() as u64;
        let entry_id = {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(b"test-tombstone:");
            h.update(req.user_id_hash.as_bytes());
            h.update(index.to_be_bytes());
            hex::encode(h.finalize())
        };
        received.push(req);
        Ok(ErasureReceipt {
            tombstone_entry_id: entry_id,
            tombstone_deployment_chain_index: index,
        })
    }
}
