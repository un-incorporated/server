//! Verification-time projection: `DeploymentEvent` → `ObservedDeploymentEvent`.
//!
//! Per spec §5.5, the comparison between the observer chain and the
//! proxy's deployment chain is byte-level equality of canonicalized
//! `ObservedDeploymentEvent` payloads. The proxy's write path does NOT
//! emit `ObservedDeploymentEvent` entries directly — every deployment
//! chain entry is a `DeploymentEvent` (payload type `0x02`). At
//! verification time, the verification task reads the entries since
//! the last-verified cursor and projects the subset that corresponds
//! to replication-observable operations into the `ObservedDeploymentEvent`
//! shape the observer emits (payload type `0x03`, §4.12).
//!
//! The projection is lossy on purpose: proxy-only fields (`source_ip`,
//! `session_id`, free-form `details`, full `scope` object) are stripped,
//! and non-observable actions (e.g. SELECT) or non-observable categories
//! (config, deploy, system) yield `None`. Only the projection's output
//! participates in the running-hash comparison with the observer chain.
//!
//! Byte-identity invariant: for every DB-observable operation the
//! observer subscribes to, `canonicalize(project(DeploymentEvent_i))`
//! equals `canonicalize(ObservedDeploymentEvent_observer_i)` — assuming
//! both sides agree on the pre-hash actor identifier (see `Actor
//! alignment` below).
//!
//! # Actor alignment
//!
//! `ObservedDeploymentEvent.actor_id_hash` is `HMAC-SHA-256(salt,
//! actor_id)`. For the proxy's projection this uses
//! `DeploymentEvent.actor_id`; for the observer this uses whatever
//! identifier the subscriber recovered from the replication stream.
//! Byte-identity therefore requires the two sides to agree on the
//! pre-hash value. That is NOT guaranteed today: the MinIO subscriber
//! hardcodes `"observer:minio"`, the Postgres subscriber reads the
//! `application_name` session variable (only populated when the proxy
//! injects `SET application_name = 'uninc:<admin_id>'` — a write-path
//! change tracked separately). Until that marker injection lands,
//! byte-identity holds only for operations where the observer can
//! honestly recover the same pre-hash string the proxy used.

use chain_store::{
    canonicalize_payload, ChainEntry, DeploymentCategory, EventPayload, ObservedAction,
    ObservedDeploymentEvent,
};
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Project a deployment-chain entry to the observer-chain shape, or
/// return `None` if the entry has no cleanly-matchable observer
/// counterpart. The "take both out when uncertain" rule: if there's
/// any ambiguity in category-or-action mapping, project to `None` so
/// neither side appears in the §5.5 comparison set. False positives
/// (proxy emits X, observer emits nominally-matching-but-different-
/// resource Y, compare fails, fires verification_failure) are worse
/// than coverage gaps.
///
/// Returns `None` when:
///
/// - The payload is not a `DeploymentEvent` (`AccessEvent` entries and
///   already-`ObservedDeploymentEvent` entries aren't projected).
/// - The category is not `is_observer_witnessable()`. v1 narrows this
///   to `AdminAccess` and `Schema` — `AdminLifecycle` and
///   `UserErasureRequested` are DB-observable in principle, but the
///   proxy-layer vs replication-layer resource-name mismatch (e.g.
///   `CREATE USER` vs writes-to-`pg_auth_members`) breaks byte-
///   identity. Both those categories are v1.1 scope.
/// - The action verb doesn't cleanly map: `read` (no replication
///   trace), or anything outside `{write, delete, schema_change}`.
pub fn project_to_observed(entry: &ChainEntry, salt: &str) -> Option<ObservedDeploymentEvent> {
    let ev = match &entry.payload {
        EventPayload::Deployment(d) => d,
        _ => return None,
    };

    if !ev.category.is_observer_witnessable() {
        return None;
    }

    let action = match ev.action.as_str() {
        "write" => ObservedAction::Write,
        "delete" => ObservedAction::Delete,
        "schema_change" => ObservedAction::SchemaChange,
        // "read" has no replication trace; anything else is unmapped.
        _ => return None,
    };

    // Tighten the category × action combination: `Schema` entries
    // should only project for `schema_change`, `AdminAccess` for
    // write/delete. Any off-diagonal pair (e.g., `Schema` with
    // `write`) implies a producer bug on the proxy side and should be
    // dropped rather than projected to a guess.
    let coherent = matches!(
        (ev.category, action),
        (DeploymentCategory::AdminAccess, ObservedAction::Write)
            | (DeploymentCategory::AdminAccess, ObservedAction::Delete)
            | (DeploymentCategory::Schema, ObservedAction::SchemaChange)
    );
    if !coherent {
        return None;
    }

    // §5.5.2 "drop both sides when uncertain": if the proxy DeploymentEvent
    // lacks a query_fingerprint in details, the projection is unknowable
    // in the byte-equality sense — returning `None` keeps the entry out of
    // the comparison set instead of synthesizing an empty string and
    // generating a false-positive `verification_failure` against an observer
    // that honestly populated the field.
    let query_fingerprint = ev
        .details
        .get("query_fingerprint")
        .and_then(|v| v.as_str())?
        .to_string();

    Some(ObservedDeploymentEvent {
        action,
        resource: ev.resource.clone(),
        actor_id_hash: hmac_hex(salt, &ev.actor_id),
        query_fingerprint,
    })
}

/// Running hash over the canonicalized bytes of an ordered sequence of
/// `ObservedDeploymentEvent` payloads. Used by the verification task to
/// fold the projection output into a single 32-byte head that's
/// compared against the observer's running hash over its own unverified
/// entries (spec §5.5).
///
/// `SHA-256(H_0 || canon(p_0) || H_1 || canon(p_1) || ...)` is NOT the
/// scheme — it's a simple sequential hash:
///
/// ```text
/// state_0 = SHA-256(canon(p_0))
/// state_i = SHA-256(state_{i-1} || canon(p_i))
/// ```
///
/// Equivalent to HKDF-chain-hashing the canonicalized payloads. Empty
/// sequence produces 32 octets of `0x00` (matching the §5.1 V7
/// empty-chain convention).
pub fn running_hash(
    events: impl IntoIterator<Item = ObservedDeploymentEvent>,
) -> Result<[u8; 32], chain_store::EntryError> {
    use sha2::Digest;
    let mut state = [0u8; 32];
    for ev in events {
        let canon = canonicalize_payload(&EventPayload::Observed(ev))?;
        let mut hasher = Sha256::new();
        hasher.update(state);
        hasher.update(&canon);
        state = hasher.finalize().into();
    }
    Ok(state)
}

fn hmac_hex(salt: &str, value: &str) -> String {
    let mut mac =
        HmacSha256::new_from_slice(salt.as_bytes()).expect("HMAC-SHA256 accepts any key length");
    mac.update(value.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chain_store::{DeploymentActorType, DeploymentEvent};
    use uninc_common::DeploymentCategory as UCat;

    fn admin_access_write_event(actor: &str, resource: &str, qfp: &str) -> DeploymentEvent {
        DeploymentEvent {
            actor_id: actor.into(),
            actor_type: DeploymentActorType::Admin,
            category: UCat::AdminAccess.into(),
            action: "write".into(),
            resource: resource.into(),
            scope: serde_json::json!({}),
            details: serde_json::json!({ "query_fingerprint": qfp }),
            source_ip: "10.0.0.1".into(),
            session_id: Some("abc".into()),
        }
    }

    #[test]
    fn projection_yields_byte_identical_payload_to_direct_observer_emission() {
        // Simulate the exact scenario §5.5 cares about: proxy emits a
        // DeploymentEvent for an admin_access write; observer
        // (independently) emits an ObservedDeploymentEvent for the
        // same replication event. Projection of the proxy entry MUST
        // canonicalize to the same bytes as the observer's direct
        // emission.
        let salt = "deployment-salt";
        let actor = "admin@example.com";
        let resource = "users";
        let qfp = hex::encode([0xAB; 32]);

        let dep = admin_access_write_event(actor, resource, &qfp);
        let entry =
            ChainEntry::deployment(0, [0u8; 32], 1_712_592_000, dep).unwrap();
        let projected = project_to_observed(&entry, salt).unwrap();

        let observer_direct = ObservedDeploymentEvent {
            action: ObservedAction::Write,
            resource: resource.into(),
            actor_id_hash: hmac_hex(salt, actor),
            query_fingerprint: qfp,
        };

        let canon_projected =
            canonicalize_payload(&EventPayload::Observed(projected)).unwrap();
        let canon_observer =
            canonicalize_payload(&EventPayload::Observed(observer_direct)).unwrap();

        assert_eq!(
            canon_projected, canon_observer,
            "projection and observer emission MUST produce byte-identical canonicalized payloads"
        );
    }

    #[test]
    fn reads_project_to_none() {
        // SELECT operations don't show up in replication; the
        // projection must drop them so they don't appear in the
        // comparison set (otherwise the observer-absent entry would
        // look like a missing entry and fire verification_failure).
        let mut dep = admin_access_write_event("a", "users", "");
        dep.action = "read".into();
        let entry = ChainEntry::deployment(0, [0u8; 32], 0, dep).unwrap();
        assert!(project_to_observed(&entry, "salt").is_none());
    }

    #[test]
    fn missing_query_fingerprint_projects_to_none() {
        // §5.5.2 "drop both sides when uncertain": an entry that lacks a
        // query_fingerprint in details is unprojectable — don't synthesize
        // an empty string and generate a false-positive verification_failure
        // against an observer that honestly populated the field. Guards
        // against an earlier `.unwrap_or("")` default that fell through
        // silently when the proxy-side producer omitted the key.
        let mut dep = admin_access_write_event("a", "users", "");
        dep.details = serde_json::json!({}); // no query_fingerprint key
        let entry = ChainEntry::deployment(0, [0u8; 32], 0, dep).unwrap();
        assert!(project_to_observed(&entry, "salt").is_none());
    }

    #[test]
    fn proxy_only_categories_project_to_none() {
        // Config, Deploy, System, etc. have no replication counterpart
        // — they MUST NOT appear in the comparison set.
        for cat in [
            UCat::Config,
            UCat::Deploy,
            UCat::System,
            UCat::ApprovedAccess,
            UCat::Egress,
            UCat::RetentionSweep,
            UCat::ReplicaReshuffle,
            UCat::VerificationFailure,
            UCat::NightlyVerification,
        ] {
            let dep = DeploymentEvent {
                actor_id: "a".into(),
                actor_type: DeploymentActorType::System,
                category: cat.into(),
                action: "write".into(),
                resource: "r".into(),
                scope: serde_json::json!({}),
                details: serde_json::json!({}),
                source_ip: "".into(),
                session_id: None,
            };
            let entry = ChainEntry::deployment(0, [0u8; 32], 0, dep).unwrap();
            assert!(
                project_to_observed(&entry, "salt").is_none(),
                "{cat:?} MUST NOT project",
            );
        }
    }

    #[test]
    fn running_hash_stable_across_runs() {
        // Two identical sequences produce identical running heads —
        // the whole point of the §5.5 comparison.
        let events = (0..3)
            .map(|i| ObservedDeploymentEvent {
                action: ObservedAction::Write,
                resource: format!("t{i}"),
                actor_id_hash: hex::encode([i as u8; 32]),
                query_fingerprint: hex::encode([i as u8; 32]),
            })
            .collect::<Vec<_>>();
        let a = running_hash(events.clone()).unwrap();
        let b = running_hash(events).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn running_hash_empty_sequence_is_zero() {
        let h = running_hash(std::iter::empty()).unwrap();
        assert_eq!(h, [0u8; 32]);
    }

    #[test]
    fn running_hash_order_sensitive() {
        let a = ObservedDeploymentEvent {
            action: ObservedAction::Write,
            resource: "a".into(),
            actor_id_hash: "".into(),
            query_fingerprint: "".into(),
        };
        let b = ObservedDeploymentEvent {
            action: ObservedAction::Delete,
            resource: "b".into(),
            actor_id_hash: "".into(),
            query_fingerprint: "".into(),
        };
        let ab = running_hash([a.clone(), b.clone()]).unwrap();
        let ba = running_hash([b, a]).unwrap();
        assert_ne!(ab, ba, "reordering must produce a different head");
    }
}
