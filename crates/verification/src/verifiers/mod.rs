//! Per-primitive cross-replica state verifier trait and implementations.
//!
//! v1 is **cross-replica detection**, not Byzantine fault tolerance — no
//! quorum vote, no 2f+1 threshold, just "do Primary and Verifier replicas
//! fingerprint the same state?". Real BFT (multi-observer quorum, signed
//! votes) is v2 — see `server/ROADMAP.md`.
//!
//! Each primitive (Postgres, MongoDB, S3) exposes a different introspection
//! surface via its client protocol, so we abstract them behind the
//! `ReplicaStateVerifier` trait and dispatch by `Protocol` in the engine.
//!
//!   - postgres.rs  — client-side SHA-256 over sorted-by-PK rows
//!   - mongodb.rs   — dbHash admin command (server-computed MD5 per collection)
//!   - s3.rs        — manifest hash over (key, ETag) pairs sorted by key
//!   - shared.rs    — common report/divergence/error types

pub mod mongodb;
pub mod postgres;
pub mod s3;
pub mod shared;

pub use shared::{Divergence, HeadMatch, VerificationReport, VerifierError};

use crate::assignment::RoleAssignment;
use crate::session::AdminSession;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use uninc_common::config::ReplicaConfig;
use uninc_common::types::Protocol;

/// A cross-replica state verifier for one primitive. The engine holds a
/// `HashMap<Protocol, Arc<dyn ReplicaStateVerifier>>` and dispatches per
/// session. The name describes what it checks (replica state agreement),
/// not how — v1 is a simple pairwise compare, not a Byzantine protocol.
pub trait ReplicaStateVerifier: Send + Sync {
    fn protocol(&self) -> Protocol;

    /// Run the primitive-specific cross-replica check for one admin
    /// session's operations against its assigned Primary + Verifier
    /// replicas. Fingerprints both, compares, reports divergence.
    fn verify_session<'a>(
        &'a self,
        session: &'a AdminSession,
        assignment: &'a RoleAssignment,
    ) -> Pin<Box<dyn Future<Output = Result<VerificationReport, VerifierError>> + Send + 'a>>;

    /// Compare this replica's view of a given chain head against an expected
    /// value. Used by the nightly trigger for O(1) cross-replica consistency.
    fn verify_chain_head<'a>(
        &'a self,
        replica: &'a ReplicaConfig,
        chain_id: &'a str,
        expected_head: &'a [u8; 32],
    ) -> Pin<Box<dyn Future<Output = Result<HeadMatch, VerifierError>> + Send + 'a>>;

    /// Bisect the chain index range [lo, hi) to find the first index where
    /// two replicas disagree. Used when a head mismatch is detected.
    /// Default implementation does binary search via the trait's
    /// `entry_hash_at` method; overrides are allowed for primitives that
    /// can answer the question more cheaply.
    fn bisect_divergence<'a>(
        &'a self,
        replica_a: &'a ReplicaConfig,
        replica_b: &'a ReplicaConfig,
        chain_id: &'a str,
        lo: u64,
        hi: u64,
    ) -> Pin<Box<dyn Future<Output = Result<Option<u64>, VerifierError>> + Send + 'a>>;
}

/// Thin registry the engine owns. Indexed by Protocol, keeps Arc'd verifiers.
#[derive(Default, Clone)]
pub struct VerifierRegistry {
    postgres: Option<Arc<postgres::PostgresVerifier>>,
    mongodb: Option<Arc<mongodb::MongoVerifier>>,
    s3: Option<Arc<s3::S3Verifier>>,
}

impl VerifierRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_postgres(mut self, v: postgres::PostgresVerifier) -> Self {
        self.postgres = Some(Arc::new(v));
        self
    }

    pub fn with_mongodb(mut self, v: mongodb::MongoVerifier) -> Self {
        self.mongodb = Some(Arc::new(v));
        self
    }

    pub fn with_s3(mut self, v: s3::S3Verifier) -> Self {
        self.s3 = Some(Arc::new(v));
        self
    }

    pub fn get(&self, protocol: Protocol) -> Option<Arc<dyn ReplicaStateVerifier>> {
        match protocol {
            Protocol::Postgres => self
                .postgres
                .as_ref()
                .map(|p| Arc::clone(p) as Arc<dyn ReplicaStateVerifier>),
            Protocol::MongoDB => self
                .mongodb
                .as_ref()
                .map(|m| Arc::clone(m) as Arc<dyn ReplicaStateVerifier>),
            Protocol::S3 => self
                .s3
                .as_ref()
                .map(|s| Arc::clone(s) as Arc<dyn ReplicaStateVerifier>),
        }
    }
}
