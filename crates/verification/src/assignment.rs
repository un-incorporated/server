//! Per-session role assignment: shuffle seeded from external entropy (drand).
//!
//! Two-role model: **Primary** (pinned to the first replica in the config,
//! conventionally the DB primary) and **Verifier** (rotated per session via
//! drand-seeded Fisher-Yates shuffle over the non-primary replicas).
//!
//! The earlier three-role model (Access / Witness / Verifier) dropped Witness
//! entirely in the 2026-04-15 redesign. Witness had zero runtime behavior —
//! the slot was populated by Fisher-Yates and then unused everywhere in the
//! codebase. The useful role at verification time is Verifier (the replica
//! whose state we read to cross-check the chain), and Primary is always
//! whichever replica the DB cluster considers primary — rotating it would
//! require per-session DB failover, which is operationally prohibitive and
//! adds no trust benefit.
//!
//! Rotating the Verifier is cheap because Verifiers are read-only observers;
//! rotating them just means "which replica do I read state from this session."
//! The drand-seeded shuffle is what makes the choice unpredictable to an
//! attacker who has compromised one specific replica and is trying to sit in
//! the Verifier slot to sign off on bad state.
//!
//! Two seed paths are supported:
//!   - **drand** (default in v1): seed is a hash of a drand public
//!     randomness beacon round + session inputs. The drand round number
//!     and BLS signature are stored in the assignment record as an
//!     auditable proof. An auditor who wants to re-derive the assignment
//!     needs only the session_id, the drand round, and the replica list.
//!     BLS verification of each fetched round is implemented in
//!     [`crate::entropy::verify_drand_bls`] and runs inline on every
//!     `DrandClient::latest_round` / `::round` call.
//!   - **fallback**: if every configured drand relay is unreachable or a
//!     returned round fails BLS verification, we fall back to a hash of
//!     session_id + timestamp + OS random bytes, flagged as
//!     `EntropySource::Fallback { reason }` where `reason` names the
//!     relay failure. This path is not externally auditable and is
//!     logged at `warn!` so an operator can see it.
//!
//! Opt-out. `UNINC_DISABLE_DRAND` disables the drand path entirely,
//! short-circuiting straight to the OS-random fallback. Intended for
//! local development where reaching drand relays is impractical; MUST
//! NOT be set in production.

use crate::entropy::{DrandClient, DrandRound, EntropySource};
use sha2::{Digest, Sha256};
use std::time::{Duration, SystemTime};
use tracing::warn;
use uninc_common::config::ReplicaConfig;
use uuid::Uuid;

/// Verifier TTL window: per-session verification triggers fire at an
/// expiry chosen deterministically from the drand seed so auditors can
/// re-derive it given the same inputs. v1 uses 1h–4h per the 2026-04-15
/// redesign (bumped from the earlier 30m–4h — 30m was noisy without
/// meaningfully improving the detection story).
pub const MIN_TTL_SECONDS: u64 = 60 * 60; // 1 hour
pub const MAX_TTL_SECONDS: u64 = 4 * 60 * 60; // 4 hours

/// The role assignment for a single admin session.
///
/// v1 redesign: Primary is pinned (always the first replica in the config,
/// which the DB cluster treats as primary), and a single Verifier is
/// selected per session via drand-seeded Fisher-Yates shuffle over the
/// non-primary replicas. The Witness slot from the earlier three-role
/// model is gone.
#[derive(Debug, Clone)]
pub struct RoleAssignment {
    /// The replica the admin's queries actually execute against. Pinned
    /// to the DB primary — does NOT rotate per session.
    pub primary: ReplicaConfig,
    /// The replica whose state will be read at verification time to
    /// cross-check the chain. Rotated per session via drand shuffle.
    pub verifier: ReplicaConfig,
    /// The seed used to derive this assignment (for audit re-derivation).
    pub seed: [u8; 32],
    /// Which entropy source produced the seed.
    pub entropy: EntropySource,
    /// When this assignment was made.
    pub assigned_at: SystemTime,
    /// When this assignment expires. Derived deterministically from the
    /// seed, in [MIN_TTL_SECONDS, MAX_TTL_SECONDS].
    pub expires_at: SystemTime,
}

/// Synchronous fallback path that seeds purely from OS random.
///
/// v1's production call path is `assign_replicas_with_drand`, which
/// seeds from a BLS-verified drand round by default. This function
/// exists for callers that do not have an `async` context or a
/// `DrandClient` to hand (a narrow case) and for unit tests. Seeds
/// produced here are NOT externally auditable — they're tagged
/// `EntropySource::Fallback { reason: "caller used sync os_random path" }`
/// — but are still unpredictable to an attacker who hasn't compromised
/// the proxy VM.
///
/// # Panics
///
/// Panics if `replicas.len() < 2` — you need at least a primary and one
/// non-primary replica to have something to assign as Verifier.
pub fn assign_replicas(
    session_id: &Uuid,
    timestamp: i64,
    replicas: &[ReplicaConfig],
    deployment_chain_head: Option<&[u8; 32]>,
) -> RoleAssignment {
    assert!(
        replicas.len() >= 2,
        "need at least 2 replicas for primary + verifier, got {}",
        replicas.len()
    );

    let chain_head = deployment_chain_head.unwrap_or(&[0u8; 32]);
    let system_random: [u8; 32] = rand::random();
    let seed = compute_seed(session_id, timestamp, chain_head, &system_random);

    let (primary, verifier) = apply_fisher_yates(replicas, &seed);

    let now = SystemTime::now();
    let ttl_secs = deterministic_ttl_from_seed(&seed);

    RoleAssignment {
        primary,
        verifier,
        seed,
        entropy: EntropySource::Fallback {
            reason: "caller used sync os_random path (no drand client available)".into(),
        },
        assigned_at: now,
        expires_at: now + Duration::from_secs(ttl_secs),
    }
}

/// Production assignment path: seeds from a BLS-verified drand round by
/// default, falling back to OS random only when every configured relay is
/// unreachable or a returned round fails BLS verification.
///
/// The drand path is default-on. Operators who explicitly need the OS-random
/// fallback (for example, local development without drand egress) can set
/// `UNINC_DISABLE_DRAND=1`. `UNINC_DISABLE_DRAND` MUST NOT be set in
/// production — it disables the externally-auditable seed and weakens the
/// trust story documented in ROADMAP.md.
///
/// BLS verification of each fetched round happens inline in
/// [`crate::entropy::DrandClient::latest_round`] via
/// [`crate::entropy::verify_drand_bls`], against the hardcoded League of
/// Entropy G1 public key. A forged round from a compromised relay fails
/// verification and the client tries the next relay.
pub async fn assign_replicas_with_drand(
    drand: &DrandClient,
    session_id: &Uuid,
    timestamp: i64,
    replicas: &[ReplicaConfig],
    deployment_chain_head: Option<&[u8; 32]>,
) -> RoleAssignment {
    assert!(
        replicas.len() >= 2,
        "need at least 2 replicas for primary + verifier, got {}",
        replicas.len()
    );

    let (seed, entropy) = if std::env::var("UNINC_DISABLE_DRAND").is_ok() {
        // Explicit opt-out — the operator has chosen to skip drand and use
        // OS random. Log at warn! so this is visible in the deployment log.
        warn!(
            "UNINC_DISABLE_DRAND is set — seeding from OS random only; \
             this disables the externally-auditable seed"
        );
        let chain_head = deployment_chain_head.unwrap_or(&[0u8; 32]);
        let system_random: [u8; 32] = rand::random();
        let seed = compute_seed(session_id, timestamp, chain_head, &system_random);
        let entropy = EntropySource::Fallback {
            reason: "UNINC_DISABLE_DRAND set by operator".into(),
        };
        (seed, entropy)
    } else {
        match drand.latest_round().await {
            Ok(round) => {
                let seed = compute_seed_drand(session_id, timestamp, &round);
                let entropy = EntropySource::Drand {
                    round: round.round,
                    signature_hex: round.signature_hex.clone(),
                };
                (seed, entropy)
            }
            Err(e) => {
                warn!(error = %e, "all drand relays failed; falling back to OS random");
                let chain_head = deployment_chain_head.unwrap_or(&[0u8; 32]);
                let system_random: [u8; 32] = rand::random();
                let seed = compute_seed(session_id, timestamp, chain_head, &system_random);
                let entropy = EntropySource::Fallback {
                    reason: format!("drand unreachable: {e}"),
                };
                (seed, entropy)
            }
        }
    };

    let (primary, verifier) = apply_fisher_yates(replicas, &seed);

    let now = SystemTime::now();
    let ttl_secs = deterministic_ttl_from_seed(&seed);

    RoleAssignment {
        primary,
        verifier,
        seed,
        entropy,
        assigned_at: now,
        expires_at: now + Duration::from_secs(ttl_secs),
    }
}

/// Deterministic TTL from a seed, in [MIN_TTL_SECONDS, MAX_TTL_SECONDS].
/// An auditor with the seed can re-derive the expected expiry.
pub fn deterministic_ttl_from_seed(seed: &[u8; 32]) -> u64 {
    let top = u64::from_be_bytes(seed[24..32].try_into().unwrap());
    let range = MAX_TTL_SECONDS - MIN_TTL_SECONDS;
    MIN_TTL_SECONDS + (top % range)
}

/// Pin Primary to `replicas[0]` (the DB primary), then shuffle the rest
/// via Fisher-Yates and pick the first one as Verifier.
///
/// Pinning Primary means admin queries always route to the same replica
/// across sessions — no per-session DB failover. Shuffling the rest means
/// the Verifier is unpredictable to an attacker who knows which replica
/// they've compromised.
fn apply_fisher_yates(
    replicas: &[ReplicaConfig],
    seed: &[u8; 32],
) -> (ReplicaConfig, ReplicaConfig) {
    let primary = replicas[0].clone();

    // Shuffle the non-primary replicas deterministically from the seed.
    let non_primary: Vec<usize> = (1..replicas.len()).collect();
    let mut indices: Vec<usize> = non_primary;
    let mut rng_state = *seed;
    for i in (1..indices.len()).rev() {
        let j = (u64::from_be_bytes(rng_state[..8].try_into().unwrap()) as usize) % (i + 1);
        indices.swap(i, j);
        rng_state = Sha256::digest(rng_state).into();
    }

    let verifier = replicas[indices[0]].clone();
    (primary, verifier)
}

/// Domain tag prefixed to every seed-derivation hash so the drand and
/// fallback paths can never produce the same 32-byte output from a
/// colliding input concatenation. HKDF-style hygiene — cheap, and
/// eliminates a theoretical preimage concern where a crafted drand
/// round could match the byte layout of the fallback input.
const SEED_DOMAIN_DRAND: &[u8] = b"uninc/v1/seed/drand\0";
const SEED_DOMAIN_FALLBACK: &[u8] = b"uninc/v1/seed/fallback\0";

/// Drand-seeded seed derivation: SHA-256 of domain-tag || drand randomness
/// || round || session_id || timestamp. Auditable: given the same drand
/// round + session inputs, the result is bit-identical.
fn compute_seed_drand(session_id: &Uuid, timestamp: i64, round: &DrandRound) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SEED_DOMAIN_DRAND);
    hasher.update(round.randomness);
    hasher.update(round.round.to_be_bytes());
    hasher.update(session_id.as_bytes());
    hasher.update(timestamp.to_be_bytes());
    hasher.finalize().into()
}

/// Compute the deterministic seed from all entropy inputs.
fn compute_seed(
    session_id: &Uuid,
    timestamp: i64,
    chain_head: &[u8; 32],
    system_random: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SEED_DOMAIN_FALLBACK);
    hasher.update(session_id.as_bytes());
    hasher.update(timestamp.to_be_bytes());
    hasher.update(chain_head);
    hasher.update(system_random);
    hasher.finalize().into()
}

/// Re-derive a verifier selection from known inputs (for audit verification).
/// Returns the index of the chosen verifier in the `replicas` slice.
pub fn verify_assignment(seed: &[u8; 32], replica_count: usize) -> usize {
    let mut indices: Vec<usize> = (1..replica_count).collect();
    let mut rng_state = *seed;
    for i in (1..indices.len()).rev() {
        let j = (u64::from_be_bytes(rng_state[..8].try_into().unwrap()) as usize) % (i + 1);
        indices.swap(i, j);
        rng_state = Sha256::digest(rng_state).into();
    }
    indices[0]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_replicas(n: usize) -> Vec<ReplicaConfig> {
        (0..n)
            .map(|i| ReplicaConfig {
                id: format!("replica-{i}"),
                host: format!("10.0.2.{}", 10 + i),
                port: 5432,
                user: "uninc".into(),
                password: "test".into(),
                database: "testdb".into(),
            })
            .collect()
    }

    #[test]
    fn assignment_with_3_replicas() {
        let replicas = make_replicas(3);
        let assignment = assign_replicas(&Uuid::new_v4(), 1712592000000, &replicas, None);
        // Primary is always replica-0
        assert_eq!(assignment.primary.id, "replica-0");
        // Verifier must be one of the non-primary replicas
        assert!(
            assignment.verifier.id == "replica-1" || assignment.verifier.id == "replica-2"
        );
        // Primary and verifier are distinct
        assert_ne!(assignment.primary.id, assignment.verifier.id);
    }

    #[test]
    fn assignment_with_5_replicas() {
        let replicas = make_replicas(5);
        let assignment = assign_replicas(&Uuid::new_v4(), 1712592000000, &replicas, None);
        assert_eq!(assignment.primary.id, "replica-0");
        assert_ne!(assignment.verifier.id, "replica-0");
    }

    #[test]
    fn deterministic_given_same_seed() {
        let seed = [0xab; 32];
        let idx1 = verify_assignment(&seed, 5);
        let idx2 = verify_assignment(&seed, 5);
        assert_eq!(idx1, idx2);
    }

    #[test]
    fn different_sessions_get_different_assignments() {
        let replicas = make_replicas(5);
        let a1 = assign_replicas(&Uuid::new_v4(), 1000, &replicas, None);
        let a2 = assign_replicas(&Uuid::new_v4(), 1000, &replicas, None);
        // Extremely unlikely to be the same (OS random per call).
        assert_ne!(a1.seed, a2.seed);
    }

    #[test]
    #[should_panic(expected = "need at least 2 replicas")]
    fn panics_with_one_replica() {
        let replicas = make_replicas(1);
        assign_replicas(&Uuid::new_v4(), 1000, &replicas, None);
    }

    #[test]
    fn ttl_is_within_range() {
        let seed = [0x42; 32];
        let ttl = deterministic_ttl_from_seed(&seed);
        assert!(ttl >= MIN_TTL_SECONDS);
        assert!(ttl < MAX_TTL_SECONDS);
    }

    #[test]
    fn seed_paths_are_domain_separated() {
        // Regression guard: the drand and fallback seed derivations must
        // produce different outputs even if an attacker can line up the
        // variable inputs so the raw concatenations would collide. The
        // SEED_DOMAIN_DRAND / SEED_DOMAIN_FALLBACK prefixes guarantee the
        // SHA-256 inputs differ at byte 0. Without the prefixes a crafted
        // drand round carrying (randomness || round) = (session_id_bytes
        // || timestamp) could, in principle, produce a colliding seed
        // across paths; the domain tag eliminates that concern.
        let sid = Uuid::nil();
        let ts = 0i64;

        // Build a drand round whose bytes, if concatenated without a
        // domain tag, would partly mirror the fallback input shape.
        let round = DrandRound {
            round: 0,
            randomness: [0u8; 32],
            signature_hex: String::new(),
            previous_signature_hex: None,
            fetched_at: std::time::SystemTime::UNIX_EPOCH,
        };
        let drand_seed = compute_seed_drand(&sid, ts, &round);

        // Fallback path with zeroed chain_head + system_random.
        let fallback_seed = compute_seed(&sid, ts, &[0u8; 32], &[0u8; 32]);

        assert_ne!(
            drand_seed, fallback_seed,
            "seed domain separation broken — drand and fallback paths produced identical output"
        );
    }
}
