//! Deployment chain entry construction helpers.
//!
//! Per Uninc Access Transparency v1 §3.1 and §4.11, deployment-chain
//! entries carry `DeploymentEvent` payloads inside the same binary envelope
//! (§4.1) used for per-user chains. A `DeploymentChainEntry` is therefore
//! just a `chain_store::ChainEntry` whose payload type is `0x02`.
//!
//! **GDPR design**: DeploymentEvent payloads MUST NOT carry row-level scope or
//! `affected_user_ids` values (§4.11). Per-user detail belongs only in
//! per-user chains, which are GDPR-erasable per §8.1.

use chain_store::{ChainEntry, DeploymentEvent, EntryError, EventPayload};
use std::collections::HashMap;
use uninc_common::{ActionType, ActorType, DeploymentCategory};
use uuid::Uuid;

/// Type alias — a deployment chain entry is a [`ChainEntry`] whose
/// `payload_type` is `0x02` (DeploymentEvent, §4.6).
pub type DeploymentChainEntry = ChainEntry;

/// Build an `DeploymentEvent` payload from a broad set of fields produced by
/// internal code paths. `details` and `artifact_hash` are merged into the
/// JSON `details` member. `source_ip` is the caller IP where one exists
/// (HTTP-triggered flows like erasure, proxy-forwarded AccessEvent pass-through);
/// `None` for events with no human caller (retention sweeps, scheduled
/// verification summaries, observer-unreachable notices, quorum-failed
/// best-effort records) and serializes to the literal string `"unknown"` at
/// the chain boundary per spec §4.11 (the field is REQUIRED but the value is
/// unconstrained).
#[allow(clippy::too_many_arguments)]
pub fn build_deployment_event(
    actor_id: &str,
    actor: ActorType,
    cat: DeploymentCategory,
    action: ActionType,
    resource: &str,
    scope: &str,
    details: Option<HashMap<String, String>>,
    artifact_hash: Option<[u8; 32]>,
    session_id: Option<Uuid>,
    source_ip: Option<&str>,
) -> DeploymentEvent {
    let mut details_map = serde_json::Map::new();
    if let Some(d) = details {
        for (k, v) in d {
            details_map.insert(k, serde_json::Value::String(v));
        }
    }
    if let Some(h) = artifact_hash {
        details_map.insert(
            "artifact_hash".into(),
            serde_json::Value::String(hex::encode(h)),
        );
    }

    DeploymentEvent {
        actor_id: actor_id.to_string(),
        actor_type: actor.into(),
        category: cat.into(),
        action: action.to_string(),
        resource: resource.to_string(),
        scope: serde_json::json!({ "description": scope }),
        details: serde_json::Value::Object(details_map),
        source_ip: source_ip.unwrap_or("unknown").to_string(),
        session_id: session_id.map(|u| u.to_string()),
    }
}

/// Construct a deployment-chain entry from an internal `AccessEvent`.
/// Strips all user-identifying fields per §4.11 (deployment chain is
/// table-level; row-level detail lives only in per-user chains).
pub fn from_access_event(
    index: u64,
    prev_hash: [u8; 32],
    event: &uninc_common::AccessEvent,
) -> Result<DeploymentChainEntry, EntryError> {
    let mut details_map = serde_json::Map::new();
    details_map.insert(
        "affected_user_count".into(),
        serde_json::Value::Number(event.affected_users.len().into()),
    );
    details_map.insert(
        "query_fingerprint".into(),
        serde_json::Value::String(hex::encode(event.query_fingerprint)),
    );

    let org_event = DeploymentEvent {
        actor_id: event.admin_id.clone(),
        actor_type: chain_store::DeploymentActorType::Admin,
        category: chain_store::DeploymentCategory::AdminAccess,
        action: event.action.to_string(),
        resource: event.resource.clone(),
        scope: serde_json::json!({}),
        details: serde_json::Value::Object(details_map),
        source_ip: event
            .metadata
            .get("source_ip")
            .cloned()
            .unwrap_or_else(|| "unknown".into()),
        session_id: Some(event.session_id.to_string()),
    };

    let timestamp_seconds = event.timestamp.div_euclid(1_000);
    ChainEntry::deployment(index, prev_hash, timestamp_seconds, org_event)
}

/// Extract the DeploymentEvent payload from an entry, if it is one.
pub fn as_deployment(entry: &ChainEntry) -> Option<&DeploymentEvent> {
    match &entry.payload {
        EventPayload::Deployment(ev) => Some(ev),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_access_event_strips_user_ids() {
        let event = uninc_common::AccessEvent {
            protocol: uninc_common::Protocol::Postgres,
            admin_id: "admin@co.com".into(),
            action: ActionType::Read,
            resource: "users".into(),
            scope: "row-level detail".into(),
            query_fingerprint: [0xaa; 32],
            affected_users: vec!["u1".into(), "u2".into(), "u3".into()],
            timestamp: 1_712_592_000_000,
            session_id: Uuid::nil(),
            metadata: HashMap::new(),
        };

        let entry = from_access_event(0, [0u8; 32], &event).unwrap();
        let org = as_deployment(&entry).unwrap();

        assert_eq!(org.category, chain_store::DeploymentCategory::AdminAccess);
        assert_eq!(org.actor_id, "admin@co.com");
        // §4.11 — no affected_user_ids, no row-level scope.
        assert!(org.scope.as_object().unwrap().is_empty());
        assert_eq!(
            org.details.as_object().unwrap().get("affected_user_count"),
            Some(&serde_json::Value::Number(3.into()))
        );
        assert!(entry.verify_hash());
    }
}
