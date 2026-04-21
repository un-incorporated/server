//! Data access transparency log — per-session verification engine.
//!
//! 2026-04-15 redesign: collapsed from the three-role model (Access /
//! Witness / Verifier) to a two-role model (Primary + Verifier) with
//! per-session drand-seeded role assignment. Primary is pinned to the
//! DB primary (replicas[0]); Verifier rotates per session via
//! Fisher-Yates shuffle over the non-primary replicas. The `Witness`
//! slot from the earlier design had zero runtime behavior and was
//! removed entirely.
//!
//! The verification pipeline runs on a TTL schedule (1h–4h) and
//! cross-checks the proxy chain against an independent observer chain
//! (see `server/crates/observer`) plus spot-checks against the
//! Verifier replica's state. Cross-chain comparison is the real defense
//! against a compromised proxy — see ROADMAP.md and
//! session-2026_04_15.md for the design reasoning.

pub mod assignment;
pub mod batch;
pub mod comparator;
pub mod engine;
pub mod entropy;
pub mod failure;
pub mod observer_client;
pub mod task;
pub mod replica_client;
pub mod session;
pub mod triggers;
pub mod verifiers;

pub use assignment::{assign_replicas, assign_replicas_with_drand, RoleAssignment};
pub use engine::{VerificationEngine, VerificationResult};
pub use entropy::{DrandClient, DrandRound, EntropySource};
pub use observer_client::{HttpObserverClient, ObserverError, ObserverHeadReader};
pub use session::{AdminSession, SessionOperation};
pub use verifiers::{ReplicaStateVerifier, VerifierRegistry};
