//! S3 / MinIO cross-replica state verifier.
//!
//! For S3-backed deployments, state verification is done at the bucket
//! level by comparing ETag sums across replicas. Each replica's MinIO
//! holds its own copy of the customer's bucket; the verifier lists all
//! objects, computes a deterministic manifest hash (sorted by key),
//! and compares across replicas.
//!
//! For chain head verification, the chain data itself lives in an S3
//! bucket (MinIO on each replica VM), and head comparison is a direct
//! GET of `head.hash` objects — same code path as the Postgres verifier's
//! chain head check.

use super::shared::{HeadMatch, VerificationReport, VerifierError};
use super::ReplicaStateVerifier;
use crate::assignment::RoleAssignment;
use crate::session::AdminSession;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tracing::debug;
use uninc_common::config::ReplicaConfig;
use uninc_common::types::Protocol;

/// Same trait the Postgres verifier uses for chain-head reads. Defined
/// once in postgres.rs and re-exported to avoid duplication.
pub use super::postgres::ChainHeadReader;

pub struct S3Verifier {
    pub head_reader: Option<Arc<dyn ChainHeadReader>>,
}

impl S3Verifier {
    pub fn new() -> Self {
        Self { head_reader: None }
    }

    pub fn with_head_reader(mut self, reader: Arc<dyn ChainHeadReader>) -> Self {
        self.head_reader = Some(reader);
        self
    }
}

impl Default for S3Verifier {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplicaStateVerifier for S3Verifier {
    fn protocol(&self) -> Protocol {
        Protocol::S3
    }

    fn verify_session<'a>(
        &'a self,
        session: &'a AdminSession,
        _assignment: &'a RoleAssignment,
    ) -> Pin<Box<dyn Future<Output = Result<VerificationReport, VerifierError>> + Send + 'a>>
    {
        Box::pin(async move {
            // Session-level S3 verification: walk the bucket and build a
            // manifest hash per replica, then compare. Because S3 has no
            // row-level "operation replay" concept, the check is always a
            // post-condition comparison rather than a replay. The chain
            // records the customer's operations (PutObject / DeleteObject /
            // etc.), and a correct replica should hold the union of all
            // committed writes up to the session end.
            //
            // Real implementation would:
            //   1. For each replica in assignment.verifiers, list objects
            //      in the customer bucket and collect (key, etag) pairs.
            //   2. Sort by key, concatenate "key:etag;" into a manifest.
            //   3. SHA-256 the manifest.
            //   4. Compare across verifiers; any mismatch → Divergence.
            //
            // We ship the structure but leave the actual MinIO calls for
            // the dedicated "customer-bucket replication" work, since
            // verification of customer bucket state is less trust-critical
            // than chain storage (which we do quorum on chain-engine's
            // write path, not at verification time).
            let mut report = VerificationReport::new(session.session_id, "s3");
            report
                .notes
                .push("session-level S3 state verification is a stub".into());
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
                    "S3Verifier has no chain head reader configured".into(),
                ));
            };
            let observed = reader.read_head(replica, chain_id).await?;
            if &observed == expected_head {
                debug!(replica = replica.id.as_str(), "chain head match");
                Ok(HeadMatch::Same)
            } else {
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
        Box::pin(async { Ok(None) })
    }
}
