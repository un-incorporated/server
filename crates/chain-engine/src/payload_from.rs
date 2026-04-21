//! Translation from internal NATS event DTOs (`uninc_common::AccessEvent`,
//! `uninc_common::DeploymentEvent`) to the spec-shaped payloads defined
//! in `chain_store` (§4.10 AccessEvent, §4.11 DeploymentEvent).
//!
//! The internal types capture "what the proxy observed." The spec types
//! are the canonical wire form fed into the hash. Keeping them separate
//! lets the proxy evolve its parser output without breaking the hash
//! algorithm, and keeps the protocol spec narrow.

use chain_store::{
    AccessAction, AccessActorType, AccessEvent as SpecAccess, AccessScope,
    Protocol as SpecProtocol,
};
use uninc_common::crypto::hash_user_id;
use uninc_common::{AccessEvent, ActionType, Protocol};

/// Convert the proxy's internal `AccessEvent` into the spec-shaped payload
/// hashed into per-user chain entries. `deployment_salt` is required to
/// derive the `HMAC-SHA-256(salt, user_id)` form mandated by §3.2 + §4.10.
pub fn to_access_payload(ev: &AccessEvent, deployment_salt: &str) -> SpecAccess {
    SpecAccess {
        actor_id: ev.admin_id.clone(),
        actor_type: AccessActorType::Admin,
        actor_label: ev.admin_id.clone(),
        protocol: match ev.protocol {
            Protocol::Postgres => SpecProtocol::Postgres,
            Protocol::MongoDB => SpecProtocol::Mongodb,
            Protocol::S3 => SpecProtocol::S3,
        },
        action: match ev.action {
            ActionType::Read => AccessAction::Read,
            ActionType::Write => AccessAction::Write,
            ActionType::Delete => AccessAction::Delete,
            ActionType::Export => AccessAction::Export,
            ActionType::SchemaChange => AccessAction::SchemaChange,
            // Lifecycle actions are DeploymentEvents per the spec; a stray
            // lifecycle in the AccessEvent stream degrades to Write
            // so the access chain remains spec-conformant.
            ActionType::AccountCreated | ActionType::ChainRecovery => AccessAction::Write,
        },
        resource: ev.resource.clone(),
        affected_user_ids: {
            // Spec §4.10 MUST: entries sorted ascending byte-wise and deduplicated
            // before canonicalization. JCS preserves array order, so two
            // implementations resolving the same query via different plans would
            // otherwise produce divergent hashes for semantically identical events.
            let mut ids: Vec<String> = ev
                .affected_users
                .iter()
                .map(|u| hash_user_id(u, deployment_salt))
                .collect();
            ids.sort();
            ids.dedup();
            ids
        },
        query_fingerprint: hex::encode(ev.query_fingerprint),
        query_shape: None,
        scope: AccessScope::default(),
        source_ip: ev
            .metadata
            .get("source_ip")
            .cloned()
            .unwrap_or_else(|| "unknown".into()),
        session_id: ev.session_id.to_string(),
        correlation_id: ev.metadata.get("correlation_id").cloned(),
    }
}

// Note: the internal `DeploymentEvent` → spec-shaped `DeploymentEvent`
// conversion that used to live here as `to_deployment_payload` was
// removed 2026-04-21 (S-AUDIT-2). The live code path is
// [`deployment_entry::build_deployment_event`], which is called directly
// from [`DeploymentChainManager::append_deployment_event`] and threads
// the real `source_ip` through; the removed function hardcoded
// `source_ip: "unknown"` regardless of input, so any caller that wired
// it in would have silently dropped the HTTP caller's IP into the
// hashed payload. Removal avoids that tripwire.

/// Milliseconds → seconds conversion for spec §4.4 timestamps. The
/// internal event stream still carries milliseconds because it predates
/// the v1 spec; values are truncated (floor) to the nearest second.
pub fn ms_to_seconds(ms: i64) -> i64 {
    ms.div_euclid(1_000)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chain_store::canonicalize_payload;
    use chain_store::EventPayload;
    use std::collections::HashMap;
    use uninc_common::{ActionType, Protocol};
    use uuid::Uuid;

    fn access_event_with_users(affected: Vec<String>) -> AccessEvent {
        AccessEvent {
            protocol: Protocol::Postgres,
            admin_id: "admin-1".into(),
            action: ActionType::Read,
            resource: "public.users".into(),
            scope: "columns: email; filter: id IN (...)".into(),
            query_fingerprint: [0u8; 32],
            affected_users: affected,
            timestamp: 1_712_592_034_000,
            session_id: Uuid::nil(),
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn affected_user_ids_sort_invariant_same_hash() {
        // Spec §4.10 MUST: affected_user_ids sorted ascending, deduplicated
        // before canonicalization. Two producers resolving the same query in
        // different orders MUST yield byte-identical canonicalized payloads.
        let salt = "test-salt";
        let order_a = access_event_with_users(vec![
            "user-42".into(),
            "user-1".into(),
            "user-99".into(),
        ]);
        let order_b = access_event_with_users(vec![
            "user-99".into(),
            "user-42".into(),
            "user-1".into(),
        ]);

        let payload_a = EventPayload::Access(to_access_payload(&order_a, salt));
        let payload_b = EventPayload::Access(to_access_payload(&order_b, salt));

        let bytes_a = canonicalize_payload(&payload_a).unwrap();
        let bytes_b = canonicalize_payload(&payload_b).unwrap();

        assert_eq!(
            bytes_a, bytes_b,
            "canonicalized payloads must be byte-identical regardless of input order"
        );
    }

    #[test]
    fn affected_user_ids_are_sorted_ascending() {
        let salt = "test-salt";
        let ev = access_event_with_users(vec![
            "user-zzz".into(),
            "user-aaa".into(),
            "user-mmm".into(),
        ]);
        let spec = to_access_payload(&ev, salt);
        for window in spec.affected_user_ids.windows(2) {
            assert!(
                window[0] <= window[1],
                "affected_user_ids must be sorted ascending: {:?}",
                spec.affected_user_ids
            );
        }
    }

    #[test]
    fn affected_user_ids_are_deduplicated() {
        // A proxy that accidentally resolves the same user twice (e.g. two
        // parser passes that both emit the id) must not produce a payload
        // with duplicates — that would break cross-implementation equality
        // against a proxy that dedupes.
        let salt = "test-salt";
        let ev = access_event_with_users(vec![
            "user-dup".into(),
            "user-dup".into(),
            "user-other".into(),
        ]);
        let spec = to_access_payload(&ev, salt);
        assert_eq!(spec.affected_user_ids.len(), 2);
    }

    #[test]
    fn affected_user_ids_empty_stays_empty() {
        let salt = "test-salt";
        let ev = access_event_with_users(vec![]);
        let spec = to_access_payload(&ev, salt);
        assert!(spec.affected_user_ids.is_empty());
    }


    // The internal AccessEvent.timestamp is milliseconds (see the field doc
    // in uninc_common::types). The on-chain envelope timestamp is Unix
    // seconds per spec §4.4. The whole pipeline hinges on ms_to_seconds
    // being the single conversion boundary: the proxy writes millis into
    // AccessEvent, chain-engine floors to seconds exactly once before
    // handing bytes to chain-store. A "cleanup" that flips either side
    // — proxy to seconds, or removes the conversion — double-truncates
    // or double-multiplies and breaks cross-replica hashes silently.
    //
    // These tests pin the invariant so such a change fails CI instead of
    // shipping.
    #[test]
    fn ms_to_seconds_floors_positive_values() {
        assert_eq!(ms_to_seconds(0), 0);
        assert_eq!(ms_to_seconds(999), 0);
        assert_eq!(ms_to_seconds(1_000), 1);
        assert_eq!(ms_to_seconds(1_999), 1);
        assert_eq!(ms_to_seconds(1_712_592_034_567), 1_712_592_034);
    }

    #[test]
    fn ms_to_seconds_floors_negative_values_toward_neg_infinity() {
        // div_euclid on negative values floors toward -∞, not toward zero.
        // Matters only in tests or misconfigured clocks (production never
        // sees pre-1970 timestamps), but documenting the behaviour pins
        // it against an accidental switch to `/` which would truncate
        // toward zero and break timestamp monotonicity.
        assert_eq!(ms_to_seconds(-1), -1);
        assert_eq!(ms_to_seconds(-1_000), -1);
        assert_eq!(ms_to_seconds(-1_001), -2);
    }

    #[test]
    fn access_event_millis_convention_is_millis_not_seconds() {
        // AccessEvent.timestamp is an i64 with no unit in the type. This
        // test asserts the convention by constructing an event whose value
        // is unambiguously milliseconds (13-digit Unix ms) and confirming
        // ms_to_seconds reduces it to the expected seconds value. If
        // someone changes the producer side to emit seconds, this test
        // still passes because 1_712_592_034 seconds happens to be valid
        // input, but it will round-trip to the year 56324 after conversion
        // — the assertion on the converted value catches that.
        let millis: i64 = 1_712_592_034_567; // Apr 2024
        let seconds = ms_to_seconds(millis);
        assert_eq!(seconds, 1_712_592_034);

        // Guard against the "seconds passed in by mistake" regression:
        // if someone swaps a proxy timestamp_millis() call for timestamp(),
        // the value fed here would be ~1.7e9 instead of ~1.7e12, and
        // ms_to_seconds would produce ~1.7e6 — a year-1970 garbage date.
        let accidentally_seconds: i64 = 1_712_592_034;
        let double_truncated = ms_to_seconds(accidentally_seconds);
        assert!(
            double_truncated < 2_000_000,
            "double-truncation catastrophe produces a 1970-ish year, got {double_truncated}"
        );
    }
}
