//! Client-side chain verifier — compiled to WASM and served to the
//! end user's browser. Implements the verification procedure of
//! Uninc Access Transparency v1 §5.2 (`protocol/draft-wang-data-access-transparency-00.md`).
//!
//! The customer's frontend fetches a list of `ChainEntry` records from
//! the proxy's `/api/v1/chain/u/:id/entries` endpoint (directly or via
//! their own backend), then calls `verify_chain` to confirm integrity.
//! Because verifier code is served from a different origin than the
//! one that issued the entries, the customer's server cannot forge a
//! passing result.
//!
//! **Zero-drift guarantee**: this crate calls `chain_store::compute_hash`
//! directly. The writer (`chain-engine`), the reader (proxy `chain_api`),
//! and the observer all share the same function. One source of truth.

use chain_store::{ChainEntry, compute_hash};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

/// Input to `verify_chain`. `expected_head` is the hex-encoded head hash
/// returned by `/api/v1/chain/u/:id/head` — the verifier confirms that
/// replaying `entries` from the zero hash reaches this exact value.
#[derive(Deserialize)]
struct Input {
    entries: Vec<ChainEntry>,
    expected_head: String,
}

#[derive(Serialize)]
pub struct VerifyResult {
    pub verified: bool,
    pub reason: Option<String>,
    pub entry_count: usize,
}

impl VerifyResult {
    fn ok(count: usize) -> Self {
        Self {
            verified: true,
            reason: None,
            entry_count: count,
        }
    }

    fn fail(count: usize, reason: impl Into<String>) -> Self {
        Self {
            verified: false,
            reason: Some(reason.into()),
            entry_count: count,
        }
    }
}

/// Implements the verification procedure of §5.2.2.
///
/// For each entry `e_i` the verifier checks:
/// - `e_i.version = 0x01`                       (V1)
/// - `e_i.index = i`                            (V2)
/// - `e_i.payload_type ∈ { 0x01, 0x02, 0x03 }`    (V3)
/// - `e_i.prev_hash = running_prev`              (V5, V6)
/// - entry_hash = H(serialize(e_i))              (V8 hash recomputation)
///
/// After the loop, the verifier confirms `running_prev = expected_head`.
///
/// V4 (`payload_length ≤ 2^20`) is NOT checked directly on the
/// deserialized `ChainEntry` because the struct drops the wire-format
/// `payload_length` field after parsing. V4 is enforced transitively:
/// `compute_hash` calls the same serialize routine the chain-engine
/// producer uses, which rejects payloads exceeding `MAX_PAYLOAD_LEN`
/// (1 MiB). An oversize payload therefore fails V8 with a hash mismatch
/// before it could ever bypass the check — the outcome (verification
/// fails) is identical. See N1 in docs/v1-spec-code-gaps.md for the
/// full rationale.
pub fn verify_chain_native(entries: &[ChainEntry], expected_head_hex: &str) -> VerifyResult {
    let expected_head = match hex::decode(expected_head_hex) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        _ => {
            return VerifyResult::fail(
                0,
                format!("expected_head must be 64 hex chars, got {expected_head_hex:?}"),
            );
        }
    };

    let mut running_prev = [0u8; 32];
    for (i, entry) in entries.iter().enumerate() {
        if entry.version != 0x01 {
            return VerifyResult::fail(
                i,
                format!("unsupported version at index {}: {}", entry.index, entry.version),
            );
        }
        if entry.index as usize != i {
            return VerifyResult::fail(
                i,
                format!("index gap at position {i}: entry.index = {}", entry.index),
            );
        }
        if entry.payload_type != 0x01 && entry.payload_type != 0x02 && entry.payload_type != 0x03
        {
            return VerifyResult::fail(
                i,
                format!(
                    "unknown payload_type at index {}: 0x{:02x}",
                    entry.index, entry.payload_type
                ),
            );
        }
        if entry.prev_hash != running_prev {
            return VerifyResult::fail(
                i,
                format!("prev_hash mismatch at index {}", entry.index),
            );
        }
        let computed = match compute_hash(entry) {
            Ok(h) => h,
            Err(e) => {
                return VerifyResult::fail(
                    i,
                    format!("serialization error at index {}: {}", entry.index, e),
                );
            }
        };
        if computed != entry.entry_hash {
            return VerifyResult::fail(
                i,
                format!("entry_hash mismatch at index {}", entry.index),
            );
        }
        running_prev = computed;
    }

    if entries.is_empty() {
        if running_prev != expected_head {
            return VerifyResult::fail(0, "head divergence: empty chain expected zero head");
        }
    } else if running_prev != expected_head {
        return VerifyResult::fail(
            entries.len(),
            "head divergence: walked chain does not match expected_head",
        );
    }

    VerifyResult::ok(entries.len())
}

/// WASM entrypoint. Deserializes the JS input, runs the native verifier,
/// and serializes the result back to a JsValue. On malformed input,
/// returns a `verified: false` result rather than panicking.
#[wasm_bindgen]
pub fn verify_chain(payload: JsValue) -> JsValue {
    let input: Input = match serde_wasm_bindgen::from_value(payload) {
        Ok(v) => v,
        Err(e) => {
            return serde_wasm_bindgen::to_value(&VerifyResult::fail(
                0,
                format!("payload parse error: {e}"),
            ))
            .unwrap_or(JsValue::NULL);
        }
    };
    let result = verify_chain_native(&input.entries, &input.expected_head);
    serde_wasm_bindgen::to_value(&result).unwrap_or(JsValue::NULL)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chain_store::{
        AccessAction, AccessActorType, AccessEvent, AccessScope, EventPayload, MAX_PAYLOAD_LEN,
        Protocol,
    };

    fn sample_event(i: u64) -> AccessEvent {
        AccessEvent {
            actor_id: "admin".into(),
            actor_type: AccessActorType::Admin,
            actor_label: "test".into(),
            protocol: Protocol::Postgres,
            action: AccessAction::Read,
            resource: "users".into(),
            affected_user_ids: vec![],
            query_fingerprint: hex::encode([i as u8; 32]),
            query_shape: None,
            scope: AccessScope::default(),
            source_ip: "127.0.0.1".into(),
            session_id: "00000000-0000-0000-0000-000000000000".into(),
            correlation_id: None,
        }
    }

    fn build_chain(count: u64) -> (Vec<ChainEntry>, String) {
        let mut entries = Vec::new();
        let mut prev = [0u8; 32];
        for i in 0..count {
            let e = ChainEntry::access(i, prev, 1_000 + i as i64, sample_event(i)).unwrap();
            prev = e.entry_hash;
            entries.push(e);
        }
        (entries, hex::encode(prev))
    }

    #[test]
    fn empty_chain_with_zero_head_verifies() {
        let result = verify_chain_native(&[], &hex::encode([0u8; 32]));
        assert!(result.verified);
        assert_eq!(result.entry_count, 0);
    }

    #[test]
    fn single_entry_verifies() {
        let (entries, head) = build_chain(1);
        let result = verify_chain_native(&entries, &head);
        assert!(result.verified);
    }

    #[test]
    fn three_entry_chain_verifies() {
        let (entries, head) = build_chain(3);
        let result = verify_chain_native(&entries, &head);
        assert!(result.verified, "reason={:?}", result.reason);
    }

    #[test]
    fn index_gap_detected() {
        let (mut entries, head) = build_chain(3);
        entries[1].index = 99;
        let result = verify_chain_native(&entries, &head);
        assert!(!result.verified);
        assert!(result.reason.as_ref().unwrap().contains("index gap"));
    }

    #[test]
    fn prev_hash_tamper_detected() {
        let (mut entries, head) = build_chain(3);
        entries[2].prev_hash = [0xff; 32];
        let result = verify_chain_native(&entries, &head);
        assert!(!result.verified);
        assert!(result.reason.as_ref().unwrap().contains("prev_hash mismatch"));
    }

    #[test]
    fn entry_hash_tamper_detected() {
        let (mut entries, head) = build_chain(3);
        entries[1].entry_hash = [0xaa; 32];
        let result = verify_chain_native(&entries, &head);
        assert!(!result.verified);
        assert!(result.reason.as_ref().unwrap().contains("entry_hash mismatch"));
    }

    #[test]
    fn head_divergence_detected() {
        let (entries, _real) = build_chain(3);
        let wrong = hex::encode([0xbb; 32]);
        let result = verify_chain_native(&entries, &wrong);
        assert!(!result.verified);
        assert!(result.reason.as_ref().unwrap().contains("head divergence"));
    }

    #[test]
    fn malformed_expected_head_rejected() {
        let (entries, _) = build_chain(1);
        let result = verify_chain_native(&entries, "not-hex");
        assert!(!result.verified);
        assert!(result.reason.as_ref().unwrap().contains("64 hex chars"));
    }

    #[test]
    fn observed_payload_type_accepted() {
        // Spec §4.6 + §4.12: payload type 0x03 is a defined value and
        // the v1 verifier MUST accept it. The earlier V3 check was
        // `payload_type ∈ {0x01, 0x02}`; the §4.12 extension added
        // 0x03 as a defined value. This test constructs a valid chain
        // with a 0x03 entry and asserts the verifier walks it cleanly.
        use chain_store::{ObservedAction, ObservedDeploymentEvent};
        let observed = ObservedDeploymentEvent {
            action: ObservedAction::Write,
            resource: "users".into(),
            actor_id_hash: hex::encode([0x11; 32]),
            query_fingerprint: hex::encode([0xab; 32]),
        };
        let e0 = ChainEntry::observed(0, [0u8; 32], 1_712_592_000, observed).unwrap();
        let head = hex::encode(e0.entry_hash);
        let result = verify_chain_native(&[e0], &head);
        assert!(
            result.verified,
            "payload type 0x03 should be accepted: {:?}",
            result.reason
        );
    }

    #[test]
    fn unknown_payload_type_still_rejected_after_0x03() {
        // Adding 0x03 to the allow-list must not relax V3 for
        // higher payload types. Forge an entry with payload_type = 0x04
        // (after serialization) and confirm the verifier rejects.
        let (entries, head) = build_chain(1);
        let mut forged = entries[0].clone();
        forged.payload_type = 0x04;
        // The hash still matches only if we recompute against the
        // forged byte sequence; without that the test degenerates into
        // a hash-mismatch assertion rather than a V3 rejection. We
        // don't bother — the point is that the V3 check fires first.
        let result = verify_chain_native(&[forged], &head);
        assert!(!result.verified);
        let reason = result.reason.unwrap_or_default();
        assert!(
            reason.contains("unknown payload_type") || reason.contains("0x04"),
            "expected V3 rejection for payload_type 0x04, got: {reason}"
        );
    }

    #[test]
    fn oversize_payload_rejected_transitively() {
        // V4 (§5.2.1): payload_length ≤ 2^20. The WASM verifier drops the
        // wire-format payload_length field after parsing (see the comment
        // on verify_chain_native), which was flagged as a coverage gap by
        // an external audit: the claim that V4 is "enforced transitively"
        // via serialize() → MAX_PAYLOAD_LEN rejection had no test exercising
        // the path. This closes that gap.
        //
        // Mutate a valid entry to carry a >1 MiB actor_id so canonicalize_payload
        // produces output >MAX_PAYLOAD_LEN. Verifier's compute_hash call will
        // surface this as a serialization error before any hash comparison
        // could bypass V4. Outcome: verified=false with a V4-traceable reason.
        let (mut entries, head) = build_chain(2);
        match entries[0].payload {
            EventPayload::Access(ref mut ev) => {
                ev.actor_id = "a".repeat(MAX_PAYLOAD_LEN + 1);
            }
            _ => panic!("build_chain produced a non-Access entry"),
        }
        let result = verify_chain_native(&entries, &head);
        assert!(!result.verified, "oversize payload should not verify");
        let reason = result.reason.unwrap_or_default();
        assert!(
            reason.contains("serialization error"),
            "expected V4 transitive failure surfaced as a serialization error, \
             got: {reason}"
        );
    }
}
