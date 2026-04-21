//! Corruption detection, truncate-at-last-valid, re-process from NATS.

use crate::entry::ChainEntry;
use tracing::{info, warn};

/// Scan a chain and find the length of the valid prefix (in entries).
pub fn find_last_valid(entries: &[ChainEntry]) -> usize {
    if entries.is_empty() {
        return 0;
    }

    for (i, entry) in entries.iter().enumerate() {
        if entry.version != 0x01 {
            warn!(at_index = i, got = entry.version, "unsupported version");
            return i;
        }
        if entry.index != i as u64 {
            warn!(
                expected = i,
                got = entry.index,
                "index gap detected at position {i}"
            );
            return i;
        }

        if i == 0 {
            if entry.prev_hash != [0u8; 32] || !entry.verify_hash() {
                warn!("invalid first entry");
                return 0;
            }
        } else if entry.prev_hash != entries[i - 1].entry_hash || !entry.verify_hash() {
            warn!(
                at_index = i,
                "corruption detected: broken linkage or tampered hash"
            );
            return i;
        }
    }

    entries.len()
}

pub fn needs_recovery(entries: &[ChainEntry]) -> bool {
    find_last_valid(entries) < entries.len()
}

pub fn truncate_to_valid(entries: &[ChainEntry]) -> Vec<ChainEntry> {
    let valid_count = find_last_valid(entries);
    if valid_count == entries.len() {
        return entries.to_vec();
    }
    info!(
        original_len = entries.len(),
        valid_count, "truncating chain to last valid entry"
    );
    entries[..valid_count].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chain_store::{AccessAction, AccessActorType, AccessEvent, AccessScope, EventPayload, Protocol};

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

    fn tamper_actor(entry: &mut ChainEntry, name: &str) {
        if let EventPayload::Access(ref mut ev) = entry.payload {
            ev.actor_id = name.into();
        }
    }

    #[test]
    fn valid_chain_fully_valid() {
        let chain = build_chain(10);
        assert_eq!(find_last_valid(&chain), 10);
        assert!(!needs_recovery(&chain));
    }

    #[test]
    fn empty_chain() {
        assert_eq!(find_last_valid(&[]), 0);
    }

    #[test]
    fn corruption_at_index_5() {
        let mut chain = build_chain(10);
        tamper_actor(&mut chain[5], "ATTACKER");
        assert_eq!(find_last_valid(&chain), 5);
        assert!(needs_recovery(&chain));
    }

    #[test]
    fn truncate_removes_corrupt_tail() {
        let mut chain = build_chain(10);
        tamper_actor(&mut chain[7], "ATTACKER");
        let valid = truncate_to_valid(&chain);
        assert_eq!(valid.len(), 7);
    }

    #[test]
    fn invalid_first() {
        let mut chain = build_chain(5);
        tamper_actor(&mut chain[0], "HACKED");
        assert_eq!(find_last_valid(&chain), 0);
    }
}
