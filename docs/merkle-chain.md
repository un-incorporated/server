# Per-User Merkle Chain Implementation

> ⚠️ **Experimental / pre-1.0.** The `UNINC_CHAIN_V1` hash algorithm described below is stable and implemented in both Rust and the JS reference mirror. Per-user sharding, compaction, and chain-migration paths are designed here but not yet exercised at scale. See [../README.md §Status](../README.md).

This document describes the per-user hash chain the proxy writes to record admin access events. The normative byte layout and hash algorithm are specified in [protocol/draft-wang-data-access-transparency-00.md](../protocol/draft-wang-data-access-transparency-00.md) §4.1, §4.9, and §5.1; this document records reference-implementation detail (directory layout, concurrency, migration) that sits outside the spec.

## Properties

1. **Tamper-evident.** Modifying any entry invalidates every subsequent `prev_hash`; a verifier holding a previously-served head detects the change.
2. **Append-only.** New entries extend the tail. Prior entries cannot be rewritten without producing a head that contradicts every previously-published one.
3. **Per-user isolation.** Each user's chain is an independent directory keyed by `HMAC-SHA-256(deployment_salt, user_id)`; deleting one chain does not affect any other.
4. **Client-side verifiable.** The user, or any party in possession of a chain and its head, recomputes the hash construction of protocol spec §5.1 locally and compares bytes; no server participation is required.

---

## Chain Structure

### Single Entry

```
ChainEntry {
  index:             u64          // Sequential position in this user's chain (0, 1, 2, ...)
  previous_hash:     [u8; 32]     // SHA-256 of the prior entry (zeroed for genesis)
  timestamp:         i64          // Unix timestamp (milliseconds) when the event was captured
  admin_id:          String       // Identity of the admin who performed the action
  action:            ActionType   // Enum: Read | Write | Delete | Export | SchemaChange
  resource:          String       // Table/collection/bucket that was accessed
  scope:             String       // Which records or fields were touched (normalized descriptor)
  query_fingerprint: [u8; 32]     // SHA-256 of the normalized query (see Query Fingerprinting)
  metadata:          Option<Map>  // Optional: IP address, user-agent, session ID, request context
  entry_hash:        [u8; 32]     // UNINC_CHAIN_V1 hash over the length-prefixed fields — see below
}
```

The `entry_hash` is **not** a naive concatenation — it follows the canonical `UNINC_CHAIN_V1` algorithm: a version prefix (`UNINC_CHAIN_V1\0`), fixed-width fields (`u64be(index)`, `previous_hash`, `i64be(timestamp)`, `query_fingerprint`), length-prefixed variable-width UTF-8 fields (`admin_id`, `action`, `resource`, `scope`), and length-prefixed sorted metadata key/value pairs, all SHA-256'd together. The authoritative implementation lives in [`crates/chain-store/src/entry.rs`](../crates/chain-store/src/entry.rs); a full byte-level spec is in [`chain-api.md` §"UNINC_CHAIN_V1 hash"](chain-api.md).

### Genesis Entry

When a user account is created:

```
ChainEntry {
  index:             0
  previous_hash:     [0u8; 32]
  timestamp:         <account creation time>
  admin_id:          "SYSTEM"
  action:            AccountCreated
  resource:          "user_account"
  scope:             "initial_creation"
  query_fingerprint: [0u8; 32]
  metadata:          None
  entry_hash:        SHA-256(0 || [0;32] || timestamp || "SYSTEM" || AccountCreated || ...)
}
```

### How Entries Chain Together

```
Entry 0 (Genesis)
  entry_hash: H0 = SHA-256(0 || 00...0 || ts0 || ...)
       │
       ▼
Entry 1
  previous_hash: H0
  entry_hash: H1 = SHA-256(1 || H0 || ts1 || ...)
       │
       ▼
Entry 2
  previous_hash: H1
  entry_hash: H2 = SHA-256(2 || H1 || ts2 || ...)
       │
       ▼
  ... and so on
```

Modifying Entry 1 changes H1. Entry 2's `previous_hash` still contains the original H1. The chain breaks. Verification detects this instantly.

---

## Query Fingerprinting

Raw SQL is never stored in the chain — it could leak user data.

```
Raw query:     SELECT name, email FROM users WHERE id = 42 AND status = 'active'
Normalized:    select name, email from users where id = ? and status = ?
Fingerprint:   SHA-256("select name, email from users where id = ? and status = ?")
```

The `scope` field provides a human-readable summary rendered by any frontend reading the :9091 chain API:
`"users table, columns: name, email; filter: id, status"`

---

## Storage

### On-Disk Format

```
/data/chains/
  ├── {user_id_hash}/
  │   ├── chain.dat          // Encrypted chain entries (append-only)
  │   ├── chain.idx          // Index: entry_number → byte_offset in chain.dat
  │   ├── head.hash          // Current head hash (last entry_hash)
  │   └── meta.json          // Creation time, entry count, encryption key ID
```

Directory name is `SHA-256(user_id + server_salt)` — the filesystem doesn't leak which users exist.

### Encryption

Each chain is encrypted with a unique AES-256-GCM key stored in a separate key management system (local keystore for dev, HashiCorp Vault / AWS KMS for production).

**On account deletion:**
1. User's encryption key is destroyed
2. `chain.dat` becomes undecryptable garbage
3. After configurable grace period (default: 30 days), hard-delete from disk
4. No other user's chain is affected
5. Satisfies GDPR Article 17 right-to-erasure

### Sharding

For long chains (tens of thousands of entries):

```
/data/chains/{user_id_hash}/
  ├── chain_0000.dat         // Entries 0–9999
  ├── chain_0001.dat         // Entries 10000–19999
  ├── chain.idx              // Global index
  ├── head.hash
  └── meta.json
```

Shard boundary configurable (default: 10,000 entries). Chain is unbroken across shards via `previous_hash`. Old shards can be compressed and archived.

---

## Concurrency Handling

When multiple admin queries affect the same user simultaneously, the chain engine must serialize appends to maintain chain integrity.

### Per-User Write Lock

```rust
// Each user's chain has a dedicated mutex
let chain_locks: DashMap<UserId, Mutex<()>> = DashMap::new();

async fn append_to_chain(user_id: UserId, event: AccessEvent) {
    let lock = chain_locks.entry(user_id).or_insert_with(|| Mutex::new(()));
    let _guard = lock.lock().await;
    
    // Read current head
    let head = read_head_hash(&user_id);
    
    // Construct entry with previous_hash = head
    let entry = ChainEntry::new(head, event);
    
    // Append and update head
    append_entry(&user_id, &entry);
    write_head_hash(&user_id, entry.entry_hash);
}
```

The lock is per-user, not global. Two different users' chains can be appended to simultaneously. Only appends to the same user's chain are serialized.

### Ordering Guarantee

Events for the same user are consumed from NATS in order (NATS JetStream provides per-subject ordering). Combined with the per-user mutex, this guarantees that chain entries appear in the same order as the original admin operations.

If an event fails to append (disk error, encryption failure), it is re-queued with exponential backoff. The chain engine never skips an event — a gap would break the sequential index requirement.

---

## Error Recovery

### Corrupted Chain Detection

If a chain file is corrupted (partial write, disk failure):

1. Verify from genesis to find the last valid entry
2. Truncate the chain file at the last valid entry boundary
3. Re-process any events that were lost (NATS retains unacknowledged messages)
4. Log the recovery event as a special chain entry (action: `ChainRecovery`)

### Dual-Write Safety

The chain engine writes in this order:
1. Append entry to `chain.dat` (fsync)
2. Update `chain.idx`
3. Update `head.hash`

If the process crashes between steps 1 and 3, on restart:
- Read the last entry from `chain.dat`
- Recompute and update `chain.idx` and `head.hash`
- No data loss — the entry is already on disk

---

## Verification

### Full Chain Verification

```rust
fn verify_chain(entries: &[ChainEntry]) -> Result<(), VerificationError> {
    for (i, entry) in entries.iter().enumerate() {
        if entry.index != i as u64 {
            return Err(VerificationError::IndexGap { expected: i, got: entry.index });
        }
        if i == 0 {
            if entry.previous_hash != [0u8; 32] {
                return Err(VerificationError::InvalidGenesis);
            }
        } else {
            if entry.previous_hash != entries[i - 1].entry_hash {
                return Err(VerificationError::BrokenChain { at_index: i });
            }
        }
        let computed = compute_hash(entry);
        if computed != entry.entry_hash {
            return Err(VerificationError::TamperedEntry { at_index: i });
        }
    }
    Ok(())
}
```

O(n) in entry count. 1000 entries verifies in ~2ms.

### Head-Only Verification (Fast Check)

Read `head.hash`, read last entry, recompute hash, compare. Full verification runs nightly as background job.

### Client-Side Verification

Any frontend reading the :9091 chain API renders a "Verify My Chain" button that downloads the chain to the browser and runs verification in Rust-compiled-to-WASM. The server cannot fake a passing check because it doesn't control the client-side code.

### CLI Verification

```bash
uninc verify --user <user_id>
uninc verify --all
uninc export --user <user_id> --format json > chain.json
```

---

## Affected User Resolution

### Schema Annotation

```yaml
schema:
  user_tables:
    - table: users
      user_id_column: id
    - table: orders
      user_id_column: user_id
    - table: messages
      user_id_column: [sender_id, recipient_id]
  excluded_tables: [migrations, schema_versions]
```

### Resolution Policies

| Policy | Behavior | Default for |
|---|---|---|
| **Strict** | Execute WHERE clause to get exact user IDs | Writes, deletes |
| **Conservative** | If can't cheaply determine, log to ALL users in table | Reads |
| **Aggregation-aware** | Skip pure aggregation (COUNT, SUM, AVG) | Optional |

---

## Performance

| Operation | Cost | Notes |
|---|---|---|
| Event emission (NATS publish) | < 0.1ms | Non-blocking |
| Chain append (per user) | ~0.5ms | SHA-256 + file append + index update |
| Full chain verify (1000 entries) | ~2ms | 1000 SHA-256 computations |
| Storage per entry | 256–512 bytes | Depends on metadata |
| Storage per user per year | 25–50 KB | At 100 events/year |
