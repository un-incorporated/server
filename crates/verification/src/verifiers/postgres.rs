//! Postgres-specific verifier for the data access transparency log.
//!
//! Uses the existing `replica_client::ReplicaClient` (Postgres md5 +
//! SHA-256 table checksums) to compare the Primary and Verifier replicas
//! after a session ends. Session-level verification computes a
//! full-state checksum on both and compares them; divergence means the
//! chain's claim about what happened does not match the actual replica
//! state.
//!
//! Chain-head verification is a separate code path: it reads the chain
//! head file out of each replica's chain-MinIO (via `MultiReplicaStorage`)
//! and compares the 32-byte values directly. No Postgres involvement.

use super::ReplicaStateVerifier;
use super::shared::{Divergence, HeadMatch, VerificationReport, VerifierError};
use crate::assignment::RoleAssignment;
use crate::replica_client::ReplicaClient;
use crate::session::AdminSession;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, warn};
use uninc_common::config::ReplicaConfig;
use uninc_common::types::Protocol;

pub struct PostgresVerifier {
    /// Schema tables to checksum during verification. Configured at proxy
    /// startup from `uninc.yml` (`schema.tables`). If empty, we fall back
    /// to `pg_catalog.pg_tables` as a trivial health-check baseline.
    pub tables: Vec<String>,

    /// A shared chain-store reader so we can fetch head hashes for the
    /// chain-head path. None means chain-head verification is unavailable
    /// (e.g. single-host topology without replica MinIOs).
    pub head_reader: Option<Arc<dyn ChainHeadReader>>,
}

/// Abstraction over "get me the head hash for this chain from this replica."
/// Implemented by the multi-replica storage layer. Kept as a trait so the
/// verifier crate doesn't hard-depend on chain-engine's storage types.
pub trait ChainHeadReader: Send + Sync {
    fn read_head<'a>(
        &'a self,
        replica: &'a ReplicaConfig,
        chain_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<[u8; 32], VerifierError>> + Send + 'a>>;
}

impl PostgresVerifier {
    pub fn new(tables: Vec<String>) -> Self {
        Self {
            tables: if tables.is_empty() {
                vec!["pg_catalog.pg_tables".to_string()]
            } else {
                tables
            },
            head_reader: None,
        }
    }

    pub fn with_head_reader(mut self, reader: Arc<dyn ChainHeadReader>) -> Self {
        self.head_reader = Some(reader);
        self
    }
}

impl ReplicaStateVerifier for PostgresVerifier {
    fn protocol(&self) -> Protocol {
        Protocol::Postgres
    }

    fn verify_session<'a>(
        &'a self,
        session: &'a AdminSession,
        assignment: &'a RoleAssignment,
    ) -> Pin<Box<dyn Future<Output = Result<VerificationReport, VerifierError>> + Send + 'a>> {
        Box::pin(async move {
            let mut report = VerificationReport::new(session.session_id, "postgres");

            if session.operations.is_empty() {
                report
                    .notes
                    .push("session had no operations, trivially verified".into());
                return Ok(report);
            }

            let primary_client = ReplicaClient::connect(&assignment.primary)
                .await
                .map_err(|e| VerifierError::Connection(e.to_string()))?;
            let primary_state = primary_client
                .full_state_checksum(&self.tables)
                .await
                .map_err(|e| VerifierError::Checksum(e.to_string()))?;

            let verifier_client = ReplicaClient::connect(&assignment.verifier)
                .await
                .map_err(|e| VerifierError::Connection(e.to_string()))?;
            let verifier_state = verifier_client
                .full_state_checksum(&self.tables)
                .await
                .map_err(|e| VerifierError::Checksum(e.to_string()))?;

            if primary_state != verifier_state {
                report.divergences.push(Divergence {
                    replica_a: assignment.primary.id.clone(),
                    replica_b: assignment.verifier.id.clone(),
                    detail: format!(
                        "state checksum mismatch: primary={} verifier={}",
                        hex::encode(primary_state),
                        hex::encode(verifier_state)
                    ),
                    first_diverging_index: None,
                });
            } else {
                debug!(
                    replica = assignment.verifier.id.as_str(),
                    "verifier replica matches primary state"
                );
            }

            Ok(report)
        })
    }

    fn verify_chain_head<'a>(
        &'a self,
        replica: &'a ReplicaConfig,
        chain_id: &'a str,
        expected_head: &'a [u8; 32],
    ) -> Pin<Box<dyn Future<Output = Result<HeadMatch, VerifierError>> + Send + 'a>> {
        Box::pin(async move {
            let Some(reader) = &self.head_reader else {
                return Err(VerifierError::Storage(
                    "PostgresVerifier has no chain head reader configured".into(),
                ));
            };
            let observed = reader.read_head(replica, chain_id).await?;
            if &observed == expected_head {
                Ok(HeadMatch::Same)
            } else {
                warn!(
                    replica = replica.id.as_str(),
                    expected = hex::encode(expected_head).as_str(),
                    observed = hex::encode(observed).as_str(),
                    "chain head divergence"
                );
                Ok(HeadMatch::Different { observed })
            }
        })
    }

    fn bisect_divergence<'a>(
        &'a self,
        _replica_a: &'a ReplicaConfig,
        _replica_b: &'a ReplicaConfig,
        _chain_id: &'a str,
        _lo: u64,
        _hi: u64,
    ) -> Pin<Box<dyn Future<Output = Result<Option<u64>, VerifierError>> + Send + 'a>> {
        Box::pin(async move {
            // Bisection reads arbitrary chain entries by index from each
            // replica's MinIO. The ChainHeadReader trait covers head-only
            // reads; entry-by-index reads are handled by a separate
            // `ChainEntryReader` trait that the multi-replica storage
            // module will provide. For v1 we return None (unknown
            // divergence point) and let the engine fall back to a full
            // replay of the session's operations.
            Ok(None)
        })
    }
}

// Keep the unused imports happy during development.
#[allow(dead_code)]
struct _KeepImports<'a>(&'a RwLock<()>);
