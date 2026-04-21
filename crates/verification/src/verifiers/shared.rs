//! Shared types used by every `ReplicaStateVerifier` implementation.

use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum VerifierError {
    #[error("not implemented for this primitive yet")]
    NotImplemented,

    #[error("replica connection failed: {0}")]
    Connection(String),

    #[error("query failed: {0}")]
    Query(String),

    #[error("checksum computation failed: {0}")]
    Checksum(String),

    #[error("storage backend error: {0}")]
    Storage(String),
}

/// Outcome of comparing two replicas' view of a chain head.
#[derive(Debug, Clone)]
pub enum HeadMatch {
    /// Both replicas agree on the head hash.
    Same,
    /// Replicas disagree. `observed` is what the queried replica reported.
    Different { observed: [u8; 32] },
}

#[derive(Debug, Clone)]
pub struct VerificationReport {
    pub session_id: Uuid,
    pub protocol_label: &'static str,
    pub divergences: Vec<Divergence>,
    pub notes: Vec<String>,
}

impl VerificationReport {
    pub fn is_clean(&self) -> bool {
        self.divergences.is_empty()
    }

    pub fn new(session_id: Uuid, protocol_label: &'static str) -> Self {
        Self {
            session_id,
            protocol_label,
            divergences: vec![],
            notes: vec![],
        }
    }
}

/// A single observed disagreement. Verifiers return zero-or-more of these
/// per session.
#[derive(Debug, Clone)]
pub struct Divergence {
    pub replica_a: String,
    pub replica_b: String,
    pub detail: String,
    /// If the verifier could narrow the divergence down to a specific chain
    /// index via bisection, it's recorded here. None means "we saw a
    /// mismatch but didn't or couldn't bisect."
    pub first_diverging_index: Option<u64>,
}
