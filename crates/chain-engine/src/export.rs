//! JSON/CSV serialization of chain entries for user export.

use crate::entry::ChainEntry;
use chain_store::EventPayload;

/// Export chain entries as pretty-printed JSON.
pub fn to_json(entries: &[ChainEntry]) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(entries)
}

/// Export chain entries as CSV. Per-user chains always carry
/// `AccessEvent` payloads; DeploymentEvent entries get blanks for access-specific
/// columns so the schema is stable across mixed input.
pub fn to_csv(entries: &[ChainEntry]) -> String {
    let mut csv =
        String::from("index,timestamp,actor_id,action,resource,query_fingerprint,entry_hash\n");
    for e in entries {
        let (actor, action, resource, qf) = match &e.payload {
            EventPayload::Access(ev) => (
                ev.actor_id.as_str(),
                format!("{:?}", ev.action).to_lowercase(),
                ev.resource.as_str(),
                ev.query_fingerprint.as_str(),
            ),
            EventPayload::Deployment(ev) => (
                ev.actor_id.as_str(),
                ev.action.clone(),
                ev.resource.as_str(),
                "",
            ),
            EventPayload::Observed(ev) => (
                // ObservedDeploymentEvent carries `actor_id_hash`, not a
                // plaintext actor_id; exporting the hash is fine for CSV
                // round-trip (deployment-chain entries are admin-scoped,
                // not user-scoped, so the hex hash is the useful value
                // for downstream consumers too).
                ev.actor_id_hash.as_str(),
                format!("{:?}", ev.action).to_lowercase(),
                ev.resource.as_str(),
                ev.query_fingerprint.as_str(),
            ),
        };
        csv.push_str(&format!(
            "{},{},{},{},{},{},{}\n",
            e.index,
            e.timestamp,
            actor,
            action,
            resource,
            qf,
            hex::encode(e.entry_hash),
        ));
    }
    csv
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

    #[test]
    fn json_export() {
        let entries =
            vec![ChainEntry::access(0, [0u8; 32], 1_000, sample_event()).unwrap()];
        let json = to_json(&entries).unwrap();
        assert!(json.contains("\"index\": 0"));
        assert!(json.contains("admin"));
    }

    #[test]
    fn csv_export() {
        let entries =
            vec![ChainEntry::access(0, [0u8; 32], 1_000, sample_event()).unwrap()];
        let csv = to_csv(&entries);
        assert!(csv.starts_with(
            "index,timestamp,actor_id,action,resource,query_fingerprint,entry_hash\n"
        ));
        assert!(csv.contains("0,1000,admin,"));
    }
}
