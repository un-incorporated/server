//! Chain verification: full O(n) walk and head-only O(1) check.
//!
//! Implements the verification predicate of Uninc Access Transparency v1
//! §5.2.1 (`protocol/draft-wang-data-access-transparency-00.md`).

use crate::entry::ChainEntry;
use chain_store::{PAYLOAD_TYPE_ACCESS_EVENT, PAYLOAD_TYPE_DEPLOYMENT_EVENT};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum VerificationError {
    #[error("unsupported version at index {at_index}: {version}")]
    UnsupportedVersion { at_index: usize, version: u8 },

    #[error("index gap at entry {at_index}: expected {expected}, got {got}")]
    IndexGap {
        at_index: usize,
        expected: u64,
        got: u64,
    },

    #[error("unknown payload_type at index {at_index}: 0x{payload_type:02X} (V3)")]
    UnknownPayloadType { at_index: usize, payload_type: u8 },

    #[error("invalid first entry: prev_hash is not all zeros")]
    InvalidFirst,

    #[error("broken chain at index {at_index}: prev_hash does not match prior entry_hash")]
    BrokenChain { at_index: usize },

    #[error("tampered entry at index {at_index}: recomputed hash does not match entry_hash")]
    TamperedEntry { at_index: usize },

    /// Retained for API compatibility and callers that explicitly want to
    /// distinguish "chain has zero entries" from a successful verification.
    /// Per §5.2.1 V7 a chain with `n = 0` IS valid with head hash `0^32`;
    /// `verify_chain` returns `Ok(())` on the empty input. Callers that
    /// care about the empty case can test `entries.is_empty()` explicitly.
    #[error("empty chain")]
    EmptyChain,
}

/// Verify a full chain per §5.2.1 conditions V1, V2, V3, V5, V6, V7, V8.
///
/// 1. `e_i.version = 0x01`                              (V1)
/// 2. `e_i.index = i`                                   (V2)
/// 3. `e_i.payload_type ∈ {0x01, 0x02}`                 (V3)
/// 4. `e_0.prev_hash = 0x00^32` when n ≥ 1              (V5)
/// 5. `e_i.prev_hash = e_{i-1}.entry_hash` for i ≥ 1    (V6)
/// 6. `n = 0` ⇒ head = `0x00^32`                        (V7 — empty chain OK)
/// 7. `e_i.entry_hash = SHA-256(serialize(e_i))`        (V8, hash recomputation)
///
/// V4 (`payload_length ≤ 2^20`) is transitively enforced via
/// `MAX_PAYLOAD_LEN` in `chain_store::entry::serialize`, which
/// `verify_hash` drives — an oversize payload fails hash recomputation
/// before V8 can succeed. See N1 in docs/v1-spec-code-gaps.md.
///
/// Performance: O(n) in entry count.
pub fn verify_chain(entries: &[ChainEntry]) -> Result<(), VerificationError> {
    // V7: empty chain is a §5.2.1 success (head_hash = 0^32). A prior
    // version of this function returned `EmptyChain` here, which broke
    // conformance with verifiers that start from "no entries yet,
    // expected_head = 0^32" — the exact case a freshly-created per-user
    // chain presents.
    if entries.is_empty() {
        return Ok(());
    }

    for (i, entry) in entries.iter().enumerate() {
        if entry.version != 0x01 {
            return Err(VerificationError::UnsupportedVersion {
                at_index: i,
                version: entry.version,
            });
        }
        if entry.index != i as u64 {
            return Err(VerificationError::IndexGap {
                at_index: i,
                expected: i as u64,
                got: entry.index,
            });
        }
        // V3: payload_type MUST be one of the two defined by this
        // specification. Serialize transitively rejects unknown types via
        // error propagation, but a typed V3 failure here gives auditors a
        // clearer signal than a generic hash mismatch would.
        if entry.payload_type != PAYLOAD_TYPE_ACCESS_EVENT
            && entry.payload_type != PAYLOAD_TYPE_DEPLOYMENT_EVENT
        {
            return Err(VerificationError::UnknownPayloadType {
                at_index: i,
                payload_type: entry.payload_type,
            });
        }

        if i == 0 {
            if entry.prev_hash != [0u8; 32] {
                return Err(VerificationError::InvalidFirst);
            }
        } else if entry.prev_hash != entries[i - 1].entry_hash {
            return Err(VerificationError::BrokenChain { at_index: i });
        }

        if !entry.verify_hash() {
            return Err(VerificationError::TamperedEntry { at_index: i });
        }
    }

    Ok(())
}

/// Fast head-only verification: just check the last entry's hash.
///
/// Doesn't verify the full chain — only that the head entry
/// hasn't been tampered with. Full verification runs nightly.
pub fn verify_head(entries: &[ChainEntry]) -> Result<(), VerificationError> {
    let last = entries.last().ok_or(VerificationError::EmptyChain)?;
    if !last.verify_hash() {
        return Err(VerificationError::TamperedEntry {
            at_index: last.index as usize,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chain_store::{AccessAction, AccessActorType, AccessEvent, AccessScope, Protocol};

    fn sample_event() -> AccessEvent {
        AccessEvent {
            actor_id: "admin".into(),
            actor_type: AccessActorType::Admin,
            actor_label: "test".into(),
            protocol: Protocol::Postgres,
            action: AccessAction::Read,
            resource: "users".into(),
            affected_user_ids: vec![],
            query_fingerprint: hex::encode([0u8; 32]),
            query_shape: None,
            scope: AccessScope::default(),
            source_ip: "127.0.0.1".into(),
            session_id: "00000000-0000-0000-0000-000000000000".into(),
            correlation_id: None,
        }
    }

    fn build_chain(n: usize) -> Vec<ChainEntry> {
        let mut entries = Vec::with_capacity(n);
        let mut prev = [0u8; 32];
        for i in 0..n {
            let e = ChainEntry::access(i as u64, prev, 1_000 + (i as i64) * 100, sample_event())
                .unwrap();
            prev = e.entry_hash;
            entries.push(e);
        }
        entries
    }

    #[test]
    fn valid_chain_passes() {
        let chain = build_chain(100);
        assert!(verify_chain(&chain).is_ok());
    }

    #[test]
    fn empty_chain_is_v7_success() {
        // §5.2.1 V7: `n = 0` is a valid chain whose head hash is 0^32.
        // `verify_chain` MUST return Ok(()), not an error.
        assert!(verify_chain(&[]).is_ok());
    }

    #[test]
    fn unknown_payload_type_rejected() {
        // V3 (§5.2.1): payload_type MUST be 0x01 (AccessEvent) or
        // 0x02 (DeploymentEvent). Tamper the byte directly and assert the
        // typed V3 error surfaces before the hash-check path.
        let mut chain = build_chain(3);
        chain[1].payload_type = 0x03;
        match verify_chain(&chain) {
            Err(VerificationError::UnknownPayloadType { at_index, payload_type }) => {
                assert_eq!(at_index, 1);
                assert_eq!(payload_type, 0x03);
            }
            other => panic!("expected UnknownPayloadType, got {other:?}"),
        }
    }

    #[test]
    fn tampered_entry_detected() {
        let mut chain = build_chain(10);
        if let chain_store::EventPayload::Access(ref mut ev) = chain[5].payload {
            ev.actor_id = "ATTACKER".into();
        }
        assert!(matches!(
            verify_chain(&chain),
            Err(VerificationError::TamperedEntry { at_index: 5 })
        ));
    }

    #[test]
    fn broken_linkage_detected() {
        let mut chain = build_chain(10);
        chain[5] =
            ChainEntry::access(5, [0xff; 32], chain[5].timestamp, sample_event()).unwrap();
        assert!(matches!(
            verify_chain(&chain),
            Err(VerificationError::BrokenChain { at_index: 5 })
        ));
    }

    #[test]
    fn head_verification_passes() {
        let chain = build_chain(50);
        assert!(verify_head(&chain).is_ok());
    }

    #[test]
    fn head_verification_catches_tamper() {
        let mut chain = build_chain(50);
        let last = chain.last_mut().unwrap();
        if let chain_store::EventPayload::Access(ref mut ev) = last.payload {
            ev.resource = "hacked".into();
        }
        assert!(verify_head(&chain).is_err());
    }

    #[test]
    fn large_chain_verifies_quickly() {
        let chain = build_chain(1000);
        let start = std::time::Instant::now();
        verify_chain(&chain).unwrap();
        let elapsed = start.elapsed();
        assert!(elapsed.as_millis() < 500, "took {}ms", elapsed.as_millis());
    }

    // ───────────────────────────────────────────────────────────────────
    // Cross-verifier conformance
    //
    // The server-side native verifier (this crate) and the browser-side
    // WASM verifier (chain-verifier-wasm) must agree on every input. If
    // they diverge on a malformed chain, one side can accept what the
    // other rejects — breaking the "the server cannot forge a passing
    // result" guarantee in either direction. This test runs a shared
    // matrix of valid and tampered chains through both verifiers and
    // asserts their pass/fail verdicts match byte-for-byte.
    //
    // The two contracts aren't literally identical — the native verifier
    // returns typed Result<(), VerificationError>, the WASM verifier
    // returns VerifyResult { verified, reason, ... } and also takes an
    // expected_head parameter. The matrix maps each case to the outcome
    // each API is supposed to produce and asserts both.
    // ───────────────────────────────────────────────────────────────────

    use chain_verifier_wasm::verify_chain_native as wasm_verify;

    /// Outcome expected from a cross-verifier case.
    #[derive(Debug)]
    enum Expect {
        BothPass,
        BothFail,
    }

    fn assert_cross_consistent(case: &str, entries: &[ChainEntry], expect: Expect) {
        let native = verify_chain(entries);
        let head_hex = match entries.last() {
            Some(e) => hex::encode(e.entry_hash),
            None => hex::encode([0u8; 32]),
        };
        let wasm = wasm_verify(entries, &head_hex);

        match expect {
            Expect::BothPass => {
                assert!(native.is_ok(), "{case}: native rejected a valid chain: {native:?}");
                assert!(
                    wasm.verified,
                    "{case}: wasm rejected a valid chain: {:?}",
                    wasm.reason
                );
            }
            Expect::BothFail => {
                assert!(
                    native.is_err(),
                    "{case}: native accepted a malformed chain it should have rejected"
                );
                assert!(
                    !wasm.verified,
                    "{case}: wasm accepted a malformed chain it should have rejected"
                );
            }
        }
    }

    #[test]
    fn cross_verifier_empty_chain() {
        assert_cross_consistent("empty", &[], Expect::BothPass);
    }

    #[test]
    fn cross_verifier_single_entry() {
        assert_cross_consistent("single", &build_chain(1), Expect::BothPass);
    }

    #[test]
    fn cross_verifier_three_entries() {
        assert_cross_consistent("three", &build_chain(3), Expect::BothPass);
    }

    #[test]
    fn cross_verifier_prev_hash_tamper() {
        let mut chain = build_chain(3);
        chain[2].prev_hash = [0xff; 32];
        assert_cross_consistent("prev-tamper", &chain, Expect::BothFail);
    }

    #[test]
    fn cross_verifier_entry_hash_tamper() {
        let mut chain = build_chain(3);
        chain[1].entry_hash = [0xaa; 32];
        assert_cross_consistent("hash-tamper", &chain, Expect::BothFail);
    }

    #[test]
    fn cross_verifier_payload_tamper() {
        let mut chain = build_chain(3);
        if let chain_store::EventPayload::Access(ref mut ev) = chain[1].payload {
            ev.actor_id = "ATTACKER".into();
        }
        assert_cross_consistent("payload-tamper", &chain, Expect::BothFail);
    }

    #[test]
    fn cross_verifier_unknown_payload_type() {
        let mut chain = build_chain(3);
        chain[1].payload_type = 0x03;
        assert_cross_consistent("unknown-type", &chain, Expect::BothFail);
    }

    #[test]
    fn cross_verifier_index_gap() {
        let mut chain = build_chain(3);
        chain[1].index = 99;
        assert_cross_consistent("index-gap", &chain, Expect::BothFail);
    }

    #[test]
    fn cross_verifier_oversize_payload() {
        // V4 transitive enforcement: serialize() rejects >MAX_PAYLOAD_LEN,
        // both verifiers must surface that as verification failure.
        let mut chain = build_chain(2);
        if let chain_store::EventPayload::Access(ref mut ev) = chain[0].payload {
            ev.actor_id = "a".repeat(chain_store::MAX_PAYLOAD_LEN + 1);
        }
        assert_cross_consistent("oversize", &chain, Expect::BothFail);
    }
}
