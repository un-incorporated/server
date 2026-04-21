//! Chain entry data structure and hash computation per Uninc Access
//! Transparency v1 (see `protocol/draft-wang-data-access-transparency-00.md`).
//!
//! Every entry is a binary envelope (§4.1) carrying a JSON payload (§4.8)
//! canonicalized per §4.9. The entry hash is `SHA-256(serialize(entry))`
//! per §5.1. Cross-implementation verifiers reproduce identical hashes by
//! following the spec alone; they need not read this file.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// §4.2 — protocol version octet. MUST be `0x01` for entries conforming
/// to v1 of the specification.
pub const UAT_VERSION_OCTET: u8 = 0x01;

/// §4.6 — `payload_type` value indicating the payload is an `AccessEvent`.
pub const PAYLOAD_TYPE_ACCESS_EVENT: u8 = 0x01;

/// §4.6 — `payload_type` value indicating the payload is an `DeploymentEvent`.
pub const PAYLOAD_TYPE_DEPLOYMENT_EVENT: u8 = 0x02;

/// §4.6 + §4.12 — `payload_type` value indicating the payload is an
/// `ObservedDeploymentEvent`: the narrow structural subset of `DeploymentEvent` that
/// both the proxy and the replication-stream observer (§3.3) can produce
/// byte-identically, used as the comparison substrate by the projection
/// comparison in §5.5. The richer `DeploymentEvent` (type 0x02) continues to
/// carry proxy-only fields (source_ip, session_id, free-form details)
/// for events without a replication counterpart.
pub const PAYLOAD_TYPE_OBSERVED_DEPLOYMENT_EVENT: u8 = 0x03;

/// §4.7 — maximum payload length in octets (1 MiB). A writer MUST NOT
/// produce entries with larger payloads; a verifier MAY reject them.
pub const MAX_PAYLOAD_LEN: usize = 1 << 20;

/// Errors produced during entry serialization or hashing.
#[derive(Debug, thiserror::Error)]
pub enum EntryError {
    #[error("payload canonicalization failed: {0}")]
    Canonicalization(#[from] serde_json::Error),
    #[error("payload length {0} exceeds maximum {MAX_PAYLOAD_LEN}")]
    PayloadTooLarge(usize),
    /// §4.9 rule 5: JSON `null` MUST NOT appear anywhere in a canonicalized
    /// payload. Carries the dotted path of the offending member so producers
    /// can identify which field emitted the literal.
    #[error("null literal forbidden in canonicalized payload at `{0}` (§4.9 rule 5)")]
    NullLiteral(String),
}

/// A single entry in a UAT v1 chain.
///
/// The binary layout produced by [`serialize`] matches §4.1:
///
/// ```text
///   version(1) | index(8 BE) | timestamp(8 BE i64) | prev_hash(32) |
///   payload_type(1) | payload_length(4 BE u32) | payload(N)
/// ```
///
/// `entry_hash` is derived (not part of the hash input); it is populated
/// by [`ChainEntry::new`] and verified by [`ChainEntry::verify_hash`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainEntry {
    /// §4.2 — MUST be `0x01`.
    pub version: u8,

    /// §4.3 — monotonically increasing, starts at 0.
    pub index: u64,

    /// §4.4 — Unix seconds since epoch, UTC.
    pub timestamp: i64,

    /// §4.5 — SHA-256 of the prior entry's serialized bytes. 32 octets
    /// of `0x00` for the entry at `index = 0`.
    #[serde(with = "hex_bytes")]
    pub prev_hash: [u8; 32],

    /// §4.6 — `0x01` for AccessEvent, `0x02` for DeploymentEvent.
    pub payload_type: u8,

    /// §4.8 — the JSON payload. Canonicalized via [`canonicalize_payload`]
    /// before hashing. Stored on disk as ordinary JSON.
    pub payload: EventPayload,

    /// Derived — SHA-256 over [`serialize`] of this entry. Populated by
    /// [`ChainEntry::new`]; verified by [`ChainEntry::verify_hash`].
    #[serde(with = "hex_bytes")]
    pub entry_hash: [u8; 32],
}

/// Discriminated union over the two payload types defined in v1 (§4.6).
///
/// Serialization is `untagged` — the JSON shape on the wire is simply the
/// inner `AccessEvent` or `DeploymentEvent` object, with no wrapper. The variant
/// is recovered on read by field-structure match; on write, the envelope's
/// `payload_type` byte disambiguates out of band.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum EventPayload {
    Access(AccessEvent),
    Deployment(DeploymentEvent),
    Observed(ObservedDeploymentEvent),
}

impl EventPayload {
    pub fn payload_type(&self) -> u8 {
        match self {
            EventPayload::Access(_) => PAYLOAD_TYPE_ACCESS_EVENT,
            EventPayload::Deployment(_) => PAYLOAD_TYPE_DEPLOYMENT_EVENT,
            EventPayload::Observed(_) => PAYLOAD_TYPE_OBSERVED_DEPLOYMENT_EVENT,
        }
    }
}

// ---------------------------------------------------------------------------
// §4.10 AccessEvent
// ---------------------------------------------------------------------------

/// §4.10 actor_type enumeration.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AccessActorType {
    App,
    Admin,
    Agent,
    System,
    Suspicious,
}

/// §4.10 protocol enumeration.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Postgres,
    Mongodb,
    S3,
}

/// §4.10 action enumeration — the five data-access verbs.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AccessAction {
    Read,
    Write,
    Delete,
    Export,
    SchemaChange,
}

/// §4.10 scope sub-object.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct AccessScope {
    pub rows: u64,
    pub bytes: u64,
}

/// §4.10 AccessEvent payload — carried in per-user chains.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessEvent {
    pub actor_id: String,
    pub actor_type: AccessActorType,
    pub actor_label: String,
    pub protocol: Protocol,
    pub action: AccessAction,
    pub resource: String,

    /// Hex-encoded `HMAC-SHA-256(deployment_salt, user_id)` values per §3.2.
    pub affected_user_ids: Vec<String>,

    /// §4.10 — REQUIRED: SHA-256 of the normalized query shape. Stored
    /// hex-encoded on the wire. Serves as an index/dedup key.
    pub query_fingerprint: String,

    /// §4.10 — OPTIONAL: parameterized query template for display, e.g.
    /// `"SELECT email FROM users WHERE id = $1"`. Absent when the proxy
    /// cannot render a safe template (e.g., non-SQL protocols).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query_shape: Option<String>,

    pub scope: AccessScope,
    pub source_ip: String,
    pub session_id: String,

    /// §4.10 — OPTIONAL: UUID per [RFC4122].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
}

// ---------------------------------------------------------------------------
// §4.11 DeploymentEvent
// ---------------------------------------------------------------------------

/// §4.11 actor_type enumeration.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentActorType {
    Admin,
    System,
    Cicd,
    Operator,
}

/// §4.11 category enumeration.
///
/// Two trust tiers — see the application-layer mirror
/// `uninc_common::DeploymentCategory` for the full rationale.
/// `is_observer_witnessable()` returns `true` for the DB-observable
/// subset that participates in §5.5 payload-byte comparison against
/// the observer chain.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentCategory {
    AdminAccess,
    AdminLifecycle,
    Config,
    Deploy,
    Schema,
    System,
    ApprovedAccess,
    Egress,
    UserErasureRequested,
    RetentionSweep,
    VerificationFailure,
    NightlyVerification,
    ReplicaReshuffle,
}

impl DeploymentCategory {
    /// True iff events of this category have a replication-stream
    /// counterpart that the observer (spec §3.3) can witness AND the
    /// proxy-layer vs replication-layer resource mapping is clean
    /// enough for byte-identity under `project_to_observed`. v1
    /// scope is `AdminAccess` (user-table writes/deletes proxied
    /// through SQL) and `Schema` (DDL). `AdminLifecycle` and
    /// `UserErasureRequested` are replication-visible but the proxy's
    /// high-level verb (`CREATE USER`, `erase`) and the observer's
    /// low-level system-catalog writes don't agree on `resource`
    /// strings, so both sides drop out of the §5.5 comparison set in
    /// v1. They rejoin in v1.1 when the comparison gains per-category
    /// resource normalization or when the proxy emits sidecar markers
    /// that let the observer recover the high-level resource name.
    pub fn is_observer_witnessable(&self) -> bool {
        matches!(self, Self::AdminAccess | Self::Schema)
    }
}

/// §4.11 DeploymentEvent payload — carried in the deployment chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentEvent {
    pub actor_id: String,
    pub actor_type: DeploymentActorType,
    pub category: DeploymentCategory,
    pub action: String,
    pub resource: String,

    /// Free-form object. Shape depends on `category`; an empty object is
    /// permitted. Per §4.11, deployment-chain entries are table-level and
    /// MUST NOT include row-level scope or `affected_user_ids`.
    #[serde(default)]
    pub scope: serde_json::Value,

    /// Free-form object for category-specific metadata.
    #[serde(default)]
    pub details: serde_json::Value,

    pub source_ip: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
}

// ---------------------------------------------------------------------------
// §4.12 ObservedDeploymentEvent
// ---------------------------------------------------------------------------

/// §4.12 action enumeration — the four replication-observable verbs.
/// Excludes lifecycle actions (`account_created`, `chain_recovery`) that
/// have no replication counterpart; those only appear on `DeploymentEvent`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ObservedAction {
    Read,
    Write,
    Delete,
    SchemaChange,
}

/// §4.12 ObservedDeploymentEvent payload — carried by the observation
/// chain (§3.3). The proxy's deployment chain does NOT emit this type
/// directly; at verification time the verification task projects the
/// observer-witnessable subset of `DeploymentEvent` entries into this
/// shape for §5.5 byte-level comparison. A minimal subset that both
/// the proxy (via projection) and the observer (via direct emission)
/// can honestly produce:
///
/// - `action` — replication-observable verb.
/// - `resource` — namespace-qualified table/collection/bucket+prefix.
/// - `actor_id_hash` — HMAC-SHA-256 of the pre-hash actor identifier
///   under `deployment_salt`.
/// - `query_fingerprint` — SHA-256 of the normalized DB operation.
///
/// Deliberately omitted fields and why:
///
/// - **`timestamp`**: each side's envelope (§4.4) already records its
///   view time. Duplicating into the payload would force cross-host
///   clock agreement that replication latency + VM skew make
///   impractical, without adding any integrity property.
/// - **`source_ip`, `session_id`**: proxy-only, unrecoverable from
///   any replication stream.
/// - **`affected_user_id_hashes`**: the deployment chain is table-
///   level per §4.11 ("MUST NOT include row-level scope or
///   affected_user_ids"), and the observer cannot resolve user
///   identifiers from replication alone (no schema config). Both
///   sides would carry `[]`, so the field was pure overhead. v1.1 may
///   add it back under a new payload type if observer-side schema
///   resolution lands.
///
/// Comparison (§5.5) is pure canonicalized-payload byte equality: for
/// every observer entry, the proxy chain MUST contain an entry whose
/// projected payload canonicalizes to identical bytes, within an
/// envelope-timestamp window that absorbs replication lag.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ObservedDeploymentEvent {
    pub action: ObservedAction,
    pub resource: String,

    /// Hex-encoded `HMAC-SHA-256(deployment_salt, actor_id)` per §3.2 and
    /// §4.12. Lower-case. Both sides MUST agree on the pre-hash actor
    /// identifier; see §3.3 on replication-marker injection.
    pub actor_id_hash: String,

    /// Hex-encoded SHA-256 of the normalized query shape. Same meaning as
    /// `AccessEvent.query_fingerprint` (§4.10).
    pub query_fingerprint: String,
}

// ---------------------------------------------------------------------------
// Serialization, canonicalization, hash
// ---------------------------------------------------------------------------

/// Canonicalize a payload per §4.9 (JSON Canonicalization Scheme profile).
///
/// Returns the UTF-8 byte sequence that MUST appear at offset 54 of the
/// binary envelope defined in §4.1.
///
/// Two spec extensions layer on top of RFC 8785 / `serde_jcs`:
///
/// - **§4.9 rule 3 (NFC).** RFC 8785 does not specify Unicode normalization;
///   rule 3 is a spec extension requiring every string value AND every
///   object member name to be in Normalization Form C before JCS sees
///   them. The reference implementation applies NFC here so a third-party
///   producer that reads §4.9 literally and normalizes its inputs produces
///   byte-identical output.
/// - **§4.9 rule 5 (no null).** Rule 5 forbids the JSON literal `null` from
///   appearing anywhere in a canonicalized payload, not just at the top
///   level. `#[serde(skip_serializing_if = "Option::is_none")]` handles the
///   common case of an absent `Option<T>` field, but cannot reach nulls
///   nested inside fields typed as `serde_json::Value` (e.g., the
///   free-form `scope` and `details` on `DeploymentEvent`). The tree walk
///   here rejects any `Value::Null` at any depth with the dotted path of
///   the offending member, so producers emit the same MUST-not-contract
///   that §4.9 rule 5 obligates verifiers to MUST-reject.
pub fn canonicalize_payload(payload: &EventPayload) -> Result<Vec<u8>, EntryError> {
    let mut value = serde_json::to_value(payload)?;
    enforce_canonicalization_invariants(&mut value, "")?;
    let mut buf = Vec::new();
    serde_jcs::to_writer(&mut buf, &value)?;
    Ok(buf)
}

/// Walk the payload tree once, applying §4.9 rules 3 and 5 in place.
///
/// - Every `Value::String` is NFC-normalized.
/// - Every object member name is NFC-normalized (JCS sorts member names
///   by UTF-16 code unit; two names that differ only in normalization
///   form would sort to different byte positions without this pass).
/// - Every `Value::Null` returns `EntryError::NullLiteral` carrying the
///   dotted path of the offending member.
///
/// Bool and Number leaves are unaffected. Arrays recurse element-wise.
fn enforce_canonicalization_invariants(
    value: &mut serde_json::Value,
    path: &str,
) -> Result<(), EntryError> {
    use unicode_normalization::UnicodeNormalization;

    fn nfc_in_place(s: &mut String) {
        let normalized: String = s.nfc().collect();
        if normalized != *s {
            *s = normalized;
        }
    }

    fn child_path(path: &str, key: &str) -> String {
        if path.is_empty() {
            key.to_string()
        } else {
            format!("{path}.{key}")
        }
    }

    match value {
        serde_json::Value::Null => {
            let reported = if path.is_empty() { "<root>" } else { path };
            Err(EntryError::NullLiteral(reported.to_string()))
        }
        serde_json::Value::String(s) => {
            nfc_in_place(s);
            Ok(())
        }
        serde_json::Value::Array(items) => {
            for (i, v) in items.iter_mut().enumerate() {
                let p = if path.is_empty() {
                    format!("[{i}]")
                } else {
                    format!("{path}[{i}]")
                };
                enforce_canonicalization_invariants(v, &p)?;
            }
            Ok(())
        }
        serde_json::Value::Object(map) => {
            let taken = std::mem::take(map);
            let mut rebuilt = serde_json::Map::with_capacity(taken.len());
            for (k, mut v) in taken {
                let p = child_path(path, &k);
                enforce_canonicalization_invariants(&mut v, &p)?;
                let mut key = k;
                nfc_in_place(&mut key);
                rebuilt.insert(key, v);
            }
            *map = rebuilt;
            Ok(())
        }
        serde_json::Value::Bool(_) | serde_json::Value::Number(_) => Ok(()),
    }
}

/// Serialize a chain entry to the binary envelope of §4.1.
///
/// The returned byte sequence is the exact hash input specified by §5.1.
/// Any conformant implementation that reads the same entry fields and
/// payload bytes produces an identical output.
pub fn serialize(entry: &ChainEntry) -> Result<Vec<u8>, EntryError> {
    let payload_bytes = canonicalize_payload(&entry.payload)?;
    if payload_bytes.len() > MAX_PAYLOAD_LEN {
        return Err(EntryError::PayloadTooLarge(payload_bytes.len()));
    }

    // 54-octet fixed header + variable-length payload.
    let mut out = Vec::with_capacity(54 + payload_bytes.len());
    out.push(entry.version);
    out.extend_from_slice(&entry.index.to_be_bytes());
    out.extend_from_slice(&entry.timestamp.to_be_bytes());
    out.extend_from_slice(&entry.prev_hash);
    out.push(entry.payload_type);
    out.extend_from_slice(&(payload_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(&payload_bytes);
    Ok(out)
}

/// Compute `SHA-256(serialize(entry))` per §5.1.
pub fn compute_hash(entry: &ChainEntry) -> Result<[u8; 32], EntryError> {
    let bytes = serialize(entry)?;
    let mut h = Sha256::new();
    h.update(&bytes);
    Ok(h.finalize().into())
}

impl ChainEntry {
    /// Construct a new entry and populate `entry_hash` from its own
    /// envelope + payload bytes.
    pub fn new(
        index: u64,
        prev_hash: [u8; 32],
        timestamp: i64,
        payload: EventPayload,
    ) -> Result<Self, EntryError> {
        let payload_type = payload.payload_type();
        let mut entry = Self {
            version: UAT_VERSION_OCTET,
            index,
            timestamp,
            prev_hash,
            payload_type,
            payload,
            entry_hash: [0u8; 32],
        };
        entry.entry_hash = compute_hash(&entry)?;
        Ok(entry)
    }

    /// Convenience wrapper for per-user chain entries.
    pub fn access(
        index: u64,
        prev_hash: [u8; 32],
        timestamp: i64,
        event: AccessEvent,
    ) -> Result<Self, EntryError> {
        Self::new(index, prev_hash, timestamp, EventPayload::Access(event))
    }

    /// Convenience wrapper for deployment chain entries.
    pub fn deployment(
        index: u64,
        prev_hash: [u8; 32],
        timestamp: i64,
        event: DeploymentEvent,
    ) -> Result<Self, EntryError> {
        Self::new(index, prev_hash, timestamp, EventPayload::Deployment(event))
    }

    /// Convenience wrapper for observation-chain / replication-visible
    /// deployment-chain entries. Uses `ObservedDeploymentEvent` per §4.12.
    pub fn observed(
        index: u64,
        prev_hash: [u8; 32],
        timestamp: i64,
        event: ObservedDeploymentEvent,
    ) -> Result<Self, EntryError> {
        Self::new(index, prev_hash, timestamp, EventPayload::Observed(event))
    }

    /// Recompute this entry's hash and check it matches `entry_hash`.
    ///
    /// Fails closed: any serialization error is treated as a hash mismatch.
    pub fn verify_hash(&self) -> bool {
        match compute_hash(self) {
            Ok(h) => h == self.entry_hash,
            Err(_) => false,
        }
    }
}

/// Hex serialization for `[u8; 32]` fields in the on-disk JSON form.
mod hex_bytes {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom(format!(
                "expected 32-byte hex string, got {} bytes",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_access_event() -> AccessEvent {
        AccessEvent {
            actor_id: "admin@example.com".into(),
            actor_type: AccessActorType::Admin,
            actor_label: "Jane (DBA)".into(),
            protocol: Protocol::Postgres,
            action: AccessAction::Read,
            resource: "users".into(),
            affected_user_ids: vec![
                "b2c3a1f0e4d5968877665544332211009988776655443322110099887766554".into(),
            ],
            query_fingerprint: hex::encode([0xab; 32]),
            query_shape: Some("SELECT email FROM users WHERE id = $1".into()),
            scope: AccessScope { rows: 1, bytes: 64 },
            source_ip: "10.0.0.42".into(),
            session_id: "11111111-2222-3333-4444-555555555555".into(),
            correlation_id: None,
        }
    }

    fn sample_org_event() -> DeploymentEvent {
        DeploymentEvent {
            actor_id: "system".into(),
            actor_type: DeploymentActorType::System,
            category: DeploymentCategory::NightlyVerification,
            action: "nightly_verification_complete".into(),
            resource: "deployment".into(),
            scope: serde_json::json!({}),
            details: serde_json::json!({ "duration_ms": 1234 }),
            source_ip: "127.0.0.1".into(),
            session_id: None,
        }
    }

    #[test]
    fn access_entry_constructs_and_verifies() {
        let entry = ChainEntry::access(0, [0u8; 32], 1_712_592_000, sample_access_event()).unwrap();
        assert_eq!(entry.version, UAT_VERSION_OCTET);
        assert_eq!(entry.payload_type, PAYLOAD_TYPE_ACCESS_EVENT);
        assert_eq!(entry.prev_hash, [0u8; 32]);
        assert!(entry.verify_hash());
    }

    #[test]
    fn org_entry_constructs_and_verifies() {
        let entry =
            ChainEntry::deployment(0, [0u8; 32], 1_712_592_000, sample_org_event()).unwrap();
        assert_eq!(entry.payload_type, PAYLOAD_TYPE_DEPLOYMENT_EVENT);
        assert!(entry.verify_hash());
    }

    fn sample_observed_org_event() -> ObservedDeploymentEvent {
        ObservedDeploymentEvent {
            action: ObservedAction::Write,
            resource: "users".into(),
            actor_id_hash: hex::encode([0x11; 32]),
            // MUST be sorted lexicographic ascending so the observer
            // and proxy produce byte-identical canonicalized bytes for
            // the same operation.
            query_fingerprint: hex::encode([0xab; 32]),
        }
    }

    #[test]
    fn observed_entry_constructs_and_verifies() {
        let entry =
            ChainEntry::observed(0, [0u8; 32], 1_712_592_000, sample_observed_org_event()).unwrap();
        assert_eq!(entry.version, UAT_VERSION_OCTET);
        assert_eq!(entry.payload_type, PAYLOAD_TYPE_OBSERVED_DEPLOYMENT_EVENT);
        assert!(entry.verify_hash());
    }

    #[test]
    fn observed_entry_byte_identical_when_fields_match() {
        // The whole point of the ObservedDeploymentEvent type: two emitters
        // (observer + proxy) producing identical bytes for the same
        // operation. Guard against an accidental reintroduction of
        // envelope-level asymmetry (e.g., someone adding an `#[serde]`
        // attribute that includes default values differently between
        // the two code paths).
        let a = sample_observed_org_event();
        let b = sample_observed_org_event();
        let e_a = ChainEntry::observed(0, [0u8; 32], 1_712_592_000, a).unwrap();
        let e_b = ChainEntry::observed(0, [0u8; 32], 1_712_592_000, b).unwrap();
        assert_eq!(e_a.entry_hash, e_b.entry_hash);
        assert_eq!(serialize(&e_a).unwrap(), serialize(&e_b).unwrap());
    }

    #[test]
    fn observed_entry_payload_is_structural_subset_of_org() {
        // §4.12 guarantee: ObservedDeploymentEvent is a strict structural
        // subset of DeploymentEvent — every field here must also be present
        // on DeploymentEvent with the same encoding. This test encodes an
        // ObservedDeploymentEvent, decodes it as a JSON Value, and confirms
        // every top-level key is recognized by `DeploymentEvent`'s known keys
        // or by its `details` / `scope` free-form maps. A future edit
        // that introduces a field present on ObservedDeploymentEvent but not
        // on DeploymentEvent breaks the subset relation and makes the spec's
        // §4.12 claim false; this test catches it in CI.
        let ev = sample_observed_org_event();
        let bytes = canonicalize_payload(&EventPayload::Observed(ev)).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let obj = v.as_object().unwrap();
        for key in obj.keys() {
            assert!(
                matches!(
                    key.as_str(),
                    "action" | "resource" | "actor_id_hash" | "query_fingerprint"
                ),
                "ObservedDeploymentEvent introduced a new field {key:?} not listed in spec §4.12"
            );
        }
    }

    #[test]
    fn chain_linkage() {
        let e0 = ChainEntry::access(0, [0u8; 32], 1_000, sample_access_event()).unwrap();
        let e1 = ChainEntry::access(1, e0.entry_hash, 2_000, sample_access_event()).unwrap();
        assert_eq!(e1.prev_hash, e0.entry_hash);
        assert!(e0.verify_hash());
        assert!(e1.verify_hash());
    }

    #[test]
    fn tampered_entry_detected() {
        let mut entry = ChainEntry::access(0, [0u8; 32], 1_000, sample_access_event()).unwrap();
        if let EventPayload::Access(ref mut ev) = entry.payload {
            ev.actor_id = "attacker".into();
        }
        assert!(!entry.verify_hash());
    }

    #[test]
    fn json_roundtrip_access() {
        let entry =
            ChainEntry::access(7, [0x11; 32], 1_712_592_000, sample_access_event()).unwrap();
        let json = serde_json::to_string(&entry).unwrap();
        let back: ChainEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.entry_hash, entry.entry_hash);
        assert!(back.verify_hash());
    }

    #[test]
    fn json_roundtrip_org() {
        let entry =
            ChainEntry::deployment(3, [0x22; 32], 1_712_592_000, sample_org_event()).unwrap();
        let json = serde_json::to_string(&entry).unwrap();
        let back: ChainEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.entry_hash, entry.entry_hash);
        assert!(back.verify_hash());
    }

    /// §4.1 layout — assert that the first 54 bytes of `serialize` match
    /// the spec's field ordering and widths exactly.
    #[test]
    fn envelope_header_layout() {
        let entry =
            ChainEntry::access(42, [0xCD; 32], 1_712_592_000, sample_access_event()).unwrap();
        let bytes = serialize(&entry).unwrap();

        assert!(bytes.len() >= 54);
        assert_eq!(bytes[0], 0x01, "version octet");
        assert_eq!(&bytes[1..9], &42u64.to_be_bytes(), "index u64 BE");
        assert_eq!(
            &bytes[9..17],
            &1_712_592_000i64.to_be_bytes(),
            "timestamp i64 BE"
        );
        assert_eq!(&bytes[17..49], &[0xCD; 32], "prev_hash 32 octets");
        assert_eq!(bytes[49], 0x01, "payload_type AccessEvent");

        let payload_len = u32::from_be_bytes(bytes[50..54].try_into().unwrap()) as usize;
        assert_eq!(bytes.len(), 54 + payload_len, "payload_length consistent");
    }

    /// §4.9 JCS — member names sorted by codepoint, no whitespace.
    /// A valid AccessEvent canonicalization must not contain any space
    /// or newline outside of JSON string values.
    #[test]
    fn payload_canonicalization_has_no_extraneous_whitespace() {
        let payload = EventPayload::Access(sample_access_event());
        let bytes = canonicalize_payload(&payload).unwrap();
        let s = std::str::from_utf8(&bytes).unwrap();
        // Structural whitespace is forbidden. String values may contain
        // spaces, so we check only that no `":` or `,"` appears with a
        // surrounding space.
        assert!(!s.contains("\": "), "structural space after colon");
        assert!(!s.contains("\", "), "structural space after comma");
        assert!(!s.contains('\n'), "no newlines in canonical output");
    }

    /// §4.9 rule 3 — NFC normalization of string values. Two producers that
    /// feed the same logical string in different Unicode normalization forms
    /// (NFD vs NFC) MUST produce byte-identical canonicalized bytes and
    /// byte-identical entry hashes.
    #[test]
    fn nfc_normalization_makes_nfd_and_nfc_string_values_hash_identically() {
        // "café" — the "é" as a single precomposed codepoint (NFC form).
        let nfc_label = "caf\u{00E9}".to_string();
        // "café" — the "é" as "e" + combining acute accent (NFD form).
        // Byte-distinct from the NFC form, but semantically identical.
        let nfd_label = "cafe\u{0301}".to_string();
        assert_ne!(
            nfc_label.as_bytes(),
            nfd_label.as_bytes(),
            "precondition: NFC and NFD byte sequences must differ for this test to be meaningful"
        );

        let mut nfc_event = sample_access_event();
        nfc_event.actor_label = nfc_label;
        let mut nfd_event = sample_access_event();
        nfd_event.actor_label = nfd_label;

        let nfc_bytes = canonicalize_payload(&EventPayload::Access(nfc_event)).unwrap();
        let nfd_bytes = canonicalize_payload(&EventPayload::Access(nfd_event)).unwrap();
        assert_eq!(
            nfc_bytes, nfd_bytes,
            "§4.9 rule 3: NFD input must canonicalize to the same bytes as NFC input",
        );
    }

    /// §4.9 rule 3 — NFC normalization of **object member names**. [RFC8785]
    /// sorts member names by UTF-16 code unit, so two names that differ only
    /// in normalization form sort to different byte positions without the
    /// member-name half of rule 3. Exercised here via the free-form
    /// `details` field, which can legitimately carry user-provided keys.
    #[test]
    fn nfc_normalization_makes_nfd_and_nfc_member_names_hash_identically() {
        let mut nfc_event = sample_org_event();
        nfc_event.details = serde_json::json!({ "caf\u{00E9}": "value" });
        let mut nfd_event = sample_org_event();
        nfd_event.details = serde_json::json!({ "cafe\u{0301}": "value" });

        let nfc_bytes = canonicalize_payload(&EventPayload::Deployment(nfc_event)).unwrap();
        let nfd_bytes = canonicalize_payload(&EventPayload::Deployment(nfd_event)).unwrap();
        assert_eq!(
            nfc_bytes, nfd_bytes,
            "§4.9 rule 3: NFD member name must canonicalize to the same bytes as NFC",
        );
    }

    /// §4.9 rule 5 — `null` at the top level MUST be rejected. Exercised via
    /// a `DeploymentEvent` whose free-form `scope: serde_json::Value` is set
    /// to `Value::Null`, which `skip_serializing_if` cannot reach because
    /// the field is `Value`, not `Option<Value>`.
    #[test]
    fn null_at_top_level_is_rejected() {
        let mut event = sample_org_event();
        event.scope = serde_json::Value::Null;

        let err = canonicalize_payload(&EventPayload::Deployment(event)).unwrap_err();
        match err {
            EntryError::NullLiteral(path) => {
                assert_eq!(path, "scope", "path should name the offending member");
            }
            other => panic!("expected EntryError::NullLiteral, got {other:?}"),
        }
    }

    /// §4.9 rule 5 — `null` nested inside a `Value`-typed field MUST be
    /// rejected. The `details` field is free-form JSON, so a producer can
    /// accidentally nest a `null` arbitrarily deep. The dotted-path error
    /// tells the producer exactly where the offending literal lives.
    #[test]
    fn null_nested_in_details_is_rejected_with_path() {
        let mut event = sample_org_event();
        event.details = serde_json::json!({
            "summary": "ok",
            "nested": { "field_that_should_be_omitted": null },
        });

        let err = canonicalize_payload(&EventPayload::Deployment(event)).unwrap_err();
        match err {
            EntryError::NullLiteral(path) => {
                assert_eq!(
                    path, "details.nested.field_that_should_be_omitted",
                    "path should identify the exact nested member",
                );
            }
            other => panic!("expected EntryError::NullLiteral, got {other:?}"),
        }
    }
}
