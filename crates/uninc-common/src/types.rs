use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Core enums
// ---------------------------------------------------------------------------

/// Which database protocol generated the event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    Postgres,
    MongoDB,
    S3,
}

/// The type of operation an admin performed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionType {
    Read,
    Write,
    Delete,
    Export,
    SchemaChange,
    AccountCreated,
    ChainRecovery,
}

impl std::fmt::Display for ActionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Read => write!(f, "read"),
            Self::Write => write!(f, "write"),
            Self::Delete => write!(f, "delete"),
            Self::Export => write!(f, "export"),
            Self::SchemaChange => write!(f, "schema_change"),
            Self::AccountCreated => write!(f, "account_created"),
            Self::ChainRecovery => write!(f, "chain_recovery"),
        }
    }
}

// ---------------------------------------------------------------------------
// Deployment chain types
// ---------------------------------------------------------------------------

/// Category of a deployment-chain event.
///
/// Per-user chains answer "what happened to whom."
/// The deployment chain answers "what did the admin do" — the complete
/// admin activity log.
///
/// ## Two trust tiers
///
/// Categories are grouped by whether the event leaves a trace in the
/// database's native replication stream (Postgres WAL / Mongo oplog /
/// MinIO bucket notifications). The observer VM (spec §3.3) can
/// cross-witness the first tier; the second tier has no replication
/// counterpart and relies on chain tamper-evidence + external anchoring
/// alone. [`DeploymentCategory::is_observer_witnessable`] returns `true`
/// for the first tier.
///
/// **Observer-witnessable (DB-observable)** — events caused by or
/// visible to a write/delete/DDL hitting a primitive. The proxy emits
/// these as `ObservedDeploymentEvent` (payload type `0x03`, spec §4.12)
/// so §5.5 payload-byte comparison against the observer chain holds.
///
/// **Proxy-only** — events that happen entirely above the database
/// layer (config, deploy, control-plane, chain-engine internals). No
/// replication event exists, so the observer cannot witness these.
/// They live on the proxy's deployment chain as `DeploymentEvent`
/// (payload `0x02`) and are protected by chain prev_hash lineage +
/// external anchoring against rewrites — but NOT against omission.
/// Closing the omission gap requires operator-side infra attestation
/// (Terraform state, CI audit log) which is out of scope for v1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentCategory {
    // ─── DB-observable (observer cross-witnesses per §5.5) ───

    /// Every admin database operation — SELECT / INSERT / UPDATE /
    /// DELETE issued through the proxy with an admin credential.
    /// Writes/deletes are replicated; reads are not, so the observer
    /// witnesses only the write/delete side of this category.
    AdminAccess,

    /// Admin credential added/removed/modified, role changes,
    /// permission grants. Postgres `CREATE USER` / `GRANT` reach the
    /// WAL under logical-replication configs that include DDL; Mongo
    /// `admin.system.users` writes reach the oplog.
    AdminLifecycle,

    /// Database migration executed, table created/dropped, column
    /// added/removed. DDL is replication-visible for Mongo index ops
    /// and for Postgres when event triggers or pg_ddlx are enabled;
    /// plain `pgoutput` logical replication does NOT carry DDL.
    Schema,

    /// GDPR Article 17 (right to erasure) user request — tombstone
    /// recording that a per-user chain was deleted. The underlying row
    /// deletions are in the replication stream; the tombstone itself
    /// is a proxy-side workflow record but the EFFECT is observable.
    UserErasureRequested,

    // ─── Proxy-only (no replication counterpart) ───

    /// Proxy config modified, schema annotation updated, verification
    /// settings changed. File on disk, not DB.
    Config,

    /// New app version deployed, proxy binary updated, container image
    /// hash changed. Infrastructure layer.
    Deploy,

    /// Chain engine restart, verification failure, replica added/
    /// removed, maintenance window. Control-plane, not DB.
    System,

    /// Admin access request submitted and approved (for access-approval
    /// workflows). Proxy-internal authorization flow.
    ApprovedAccess,

    /// Outbound connection attempt from the co-located customer app in
    /// a multi-VM topology with egress containment (allow or deny).
    /// Emitted by the `egress_monitor` binary from Envoy access logs.
    Egress,

    /// Retention reaper deleted a batch of chain entries older than
    /// `retention_days`. Operates on the chain itself, not DB data.
    RetentionSweep,

    /// Replica role reshuffle applied (drand-seeded, [30m, 4h]
    /// interval). Proxy-side orchestration signal.
    ReplicaReshuffle,

    /// Cross-replica verification detected a divergence (head hash
    /// mismatch, session replay mismatch, or chain corruption). Emitted
    /// by the verification task, not caused by any DB event.
    VerificationFailure,

    /// Scheduled verification run completed (clean or otherwise).
    /// Summary written by the verification task at the end of each
    /// tick. Includes the drand round proof and a count of sessions
    /// checked.
    NightlyVerification,
}

impl DeploymentCategory {
    /// True iff events of this category are both (a) observable in
    /// the DB's native replication stream AND (b) cleanly projectable
    /// from `DeploymentEvent` to `ObservedDeploymentEvent` without
    /// resource-name drift between the proxy-layer verb and the
    /// replication-layer effect.
    ///
    /// v1 scope: `AdminAccess` + `Schema`. `AdminLifecycle` and
    /// `UserErasureRequested` are observable but have proxy-layer vs
    /// replication-layer resource mismatches (e.g. `CREATE USER`
    /// lowers to writes against `pg_auth_members`), so byte-identity
    /// would require per-category resource normalization not yet
    /// designed. Those two categories remain on the deployment chain
    /// as regular `DeploymentEvent` entries (payload type `0x02`),
    /// tamper-evident via chain prev_hash lineage, but NOT part of
    /// the §5.5 observer cross-comparison until v1.1.
    pub fn is_observer_witnessable(&self) -> bool {
        matches!(self, Self::AdminAccess | Self::Schema)
    }
}

impl std::fmt::Display for DeploymentCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AdminAccess => write!(f, "admin_access"),
            Self::AdminLifecycle => write!(f, "admin_lifecycle"),
            Self::Config => write!(f, "config"),
            Self::Deploy => write!(f, "deploy"),
            Self::Schema => write!(f, "schema"),
            Self::System => write!(f, "system"),
            Self::ApprovedAccess => write!(f, "approved_access"),
            Self::Egress => write!(f, "egress"),
            Self::UserErasureRequested => write!(f, "user_erasure_requested"),
            Self::RetentionSweep => write!(f, "retention_sweep"),
            Self::ReplicaReshuffle => write!(f, "replica_reshuffle"),
            Self::VerificationFailure => write!(f, "verification_failure"),
            Self::NightlyVerification => write!(f, "nightly_verification"),
        }
    }
}

/// Outbound-connection attempt observed by the Envoy egress proxy in a
/// multi-VM topology with egress containment.
///
/// Published to NATS by `chain-engine::egress_monitor` (a tail of Envoy's
/// access log) as an `DeploymentCategory::Egress` event. Enforcement is a property
/// of the deployment's `egressMode`:
///
/// * `"dev"`         — everything is allowed, everything is logged. Discovery posture.
/// * `"allowlisted"` — Envoy enforces the per-deployment allowlist via SNI match.
///                     `allowed: true` means the destination was on the allowlist.
/// * `"locked"`      — everything is denied. Every event here has `allowed: false`.
///
/// Payload stays narrow on purpose: destination hostname (SNI or HTTP Host) is
/// the only identifier we ever record. Request/response bodies are never
/// observed — Envoy is a transparent forward proxy, not a TLS-interception MITM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EgressEvent {
    /// Unix epoch milliseconds when Envoy observed the connection.
    pub timestamp_ms: i64,
    /// Hostname from TLS SNI (for HTTPS) or HTTP Host header (for HTTP).
    /// Exact string, no normalization — this is what the allowlist matched against.
    pub destination: String,
    /// True if Envoy forwarded the connection upstream. False if it was denied.
    pub allowed: bool,
    /// The `egressMode` in effect at the moment Envoy rendered its current config.
    /// One of `"dev"`, `"allowlisted"`, `"locked"`. Chain readers can use this to
    /// distinguish "logged in Dev" from "enforced in Prod."
    pub enforcement_mode: String,
    /// The allowlist version number that produced this decision. Matches
    /// `Deployment.egressAllowlistVersion` at the time Envoy was reloaded.
    pub allowlist_version: u32,
    /// If `allowed == true`, the free-text `purpose` from the allowlist entry
    /// that matched (e.g. "Stripe API"). Present for readability in the chain UI.
    pub purpose: Option<String>,
    /// Bytes uploaded in the request, if Envoy recorded them in the access log.
    pub request_bytes: Option<u64>,
    /// Upstream HTTP status, if applicable and recorded. Not set for raw TCP.
    pub upstream_status: Option<u16>,
}

/// Who performed an org-level action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorType {
    /// Human admin (psql, mongosh, GUI client, support engineer).
    Admin,
    /// Automated system process (chain engine, proxy, cron job).
    System,
    /// CI/CD pipeline (deploys, migrations).
    CiCd,
    /// Unincorporated platform operator (us).
    Operator,
}

impl std::fmt::Display for ActorType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Admin => write!(f, "admin"),
            Self::System => write!(f, "system"),
            Self::CiCd => write!(f, "ci_cd"),
            Self::Operator => write!(f, "operator"),
        }
    }
}

/// Cross-replica verification status for chain entries.
///
/// Stored separately from the chain entry (in `verified_ranges.json`),
/// NOT included in the entry hash. Mutable metadata — entries transition
/// from Unverified → Verified after the nightly cross-replica comparison
/// passes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "status")]
pub enum VerificationStatus {
    /// Entry has not yet been checked by the cross-replica verifier.
    Unverified,
    /// Nightly cross-replica comparison passed — replicas agree on the data state.
    Verified {
        /// Unix timestamp in milliseconds when verification succeeded.
        verified_at: i64,
    },
    /// Cross-replica comparison found a divergence — replicas disagree.
    Failed {
        /// Unix timestamp in milliseconds when the failure was detected.
        failed_at: i64,
    },
}

// ---------------------------------------------------------------------------
// Connection classification
// ---------------------------------------------------------------------------

/// How the proxy classified an incoming connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionClass {
    /// Whitelisted application traffic — passthrough, no logging.
    App,
    /// Human admin — log everything to affected users' chains.
    Admin(AdminIdentity),
    /// Something unexpected from an app source — alert.
    Suspicious(String),
}

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

/// Information about an identified admin connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminIdentity {
    pub username: String,
    pub source_ip: IpAddr,
    pub session_id: Uuid,
}

// ---------------------------------------------------------------------------
// Access event — produced ONLY by admin connections (not app traffic)
// ---------------------------------------------------------------------------

/// A single admin access event, protocol-agnostic.
///
/// Only admin connections (classified as `ConnectionClass::Admin` or
/// `Suspicious`) produce AccessEvents. App connections (`ConnectionClass::App`)
/// are raw-forwarded with zero logging. The protocol audits admin access,
/// not end-user app traffic.
///
/// Published to NATS on two subjects:
/// - `uninc.access._deployment` (always — the admin activity chain)
/// - `uninc.access.{user_id}` (per affected user — the per-user chain)
///
/// The chain-engine consumes both and routes accordingly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessEvent {
    /// Which protocol generated this event (Postgres, MongoDB, or S3).
    pub protocol: Protocol,

    /// Identity of the admin who performed the action.
    /// Always present — only admin connections produce AccessEvents.
    pub admin_id: String,

    /// What kind of operation (Read, Write, Delete, Export, SchemaChange).
    pub action: ActionType,

    /// Table name, collection name, or S3 bucket+key that was accessed.
    /// e.g. "users", "orders", "uploads/users/42/avatar.jpg", or "(utility)"
    /// for queries with no identified tables.
    /// Same field as `ChainEntry.resource` and `DeploymentChainEntry.resource`.
    pub resource: String,

    /// Human-readable summary — **row-level detail**.
    /// Includes columns and WHERE filters: "columns: email, name; filter: id = 42"
    /// This goes into per-user chains as-is. The admin activity chain strips
    /// it to table-level only ("table: users, action: read") for GDPR compliance.
    /// Same field as `ChainEntry.scope`; the deployment chain gets a stripped version.
    pub scope: String,

    /// SHA-256 of the normalized query (never the raw SQL/BSON).
    /// Same across ChainEntry and DeploymentChainEntry.
    #[serde(with = "hex_hash")]
    pub query_fingerprint: [u8; 32],

    /// User IDs whose data was accessed. May be empty for DDL, utility
    /// queries, or cross-table operations that can't be resolved to users.
    /// Per-user chains get one entry per user ID. The admin activity chain
    /// stores only the count ("3_users_affected"), not the IDs.
    pub affected_users: Vec<String>,

    /// Unix timestamp in milliseconds when the event was captured.
    pub timestamp: i64,

    /// Unique session identifier (one per admin connection).
    pub session_id: Uuid,

    /// Optional context: IP, user-agent, request headers, etc.
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

// ---------------------------------------------------------------------------
// Org event — system-level events published directly to the deployment chain
// ---------------------------------------------------------------------------

/// A system-level event that goes directly to the deployment chain.
///
/// Unlike `AccessEvent` (which the proxy produces for admin database queries),
/// `DeploymentEvent` is produced by internal system components — the verification
/// engine, the chain engine on restart, config reloads, etc.
///
/// Published to NATS on `uninc.system._deployment`. The chain-engine consumer
/// routes these to `DeploymentChainManager.append_deployment_event()`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentEvent {
    /// Identity of the system component producing the event.
    /// e.g. "uninc-verifier", "chain-engine", "uninc-proxy"
    pub actor_id: String,

    /// Always `System` for system-generated events.
    pub actor_type: ActorType,

    /// Which category this event belongs to.
    pub category: DeploymentCategory,

    /// What kind of operation.
    pub action: ActionType,

    /// What was acted on (e.g. "replicas", "chain_engine", "config").
    pub resource: String,

    /// Human-readable summary.
    pub scope: String,

    /// Structured metadata specific to the event.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<HashMap<String, String>>,

    /// SHA-256 of an artifact that changed (config file, binary, etc.).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_hash: Option<[u8; 32]>,

    /// Unix timestamp in milliseconds.
    pub timestamp: i64,

    /// Session identifier, if this event is tied to an admin session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<Uuid>,

    /// Source IP of the caller that triggered this event, if one exists.
    /// `None` for events with no human caller (retention sweeps, scheduled
    /// verification summaries, observer-unreachable notices, quorum-failed
    /// best-effort records). `Some(ip)` for events driven by an HTTP caller
    /// (erasure requests) or by the proxy forwarding a DB operation. Flowed
    /// into `chain_store::DeploymentEvent.source_ip` at append time; spec
    /// §4.11 allows any string, so a missing real IP surfaces as `"unknown"`
    /// at the chain boundary rather than an absent field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_ip: Option<String>,
}

// ---------------------------------------------------------------------------
// Erasure request / receipt — §7.3.1 + §8.1 (right to erasure)
// ---------------------------------------------------------------------------

/// A request from the proxy to chain-engine asking for a `UserErasureRequested`
/// tombstone to be appended to the deployment chain. Travels via NATS core
/// request/reply on subject `uninc.control.erasure` so the proxy can return
/// the resulting `(index, entry_hash)` to the HTTP caller in the same request.
///
/// Carries the *hashed* user id (HMAC-SHA-256(salt, user_id)) — never the
/// plaintext id. The tombstone records the erasure event without re-leaking
/// the identity that was just erased.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErasureRequest {
    /// Hex-encoded HMAC-SHA-256(server_salt, user_id). 64 characters.
    pub user_id_hash: String,
    /// Source IP of the HTTP caller that requested erasure. Recorded on the
    /// tombstone for forensic continuity.
    pub source_ip: String,
    /// Session id from the authenticating JWT (`sid` claim), if present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<Uuid>,
    /// Unix seconds when the proxy received the DELETE call.
    pub requested_at: i64,
}

/// Reply from chain-engine after the tombstone has been committed to the
/// deployment chain. Populates the HTTP response body per spec §7.3.1.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErasureReceipt {
    /// Hex-encoded SHA-256 of the tombstone entry (64 characters).
    pub tombstone_entry_id: String,
    /// Zero-based index of the tombstone on the deployment chain.
    pub tombstone_deployment_chain_index: u64,
}

/// NATS subject used for erasure request/reply. Core NATS (not JetStream) —
/// inherently synchronous and low-latency, which matches the semantics of a
/// user-initiated DELETE that blocks on the tombstone commit.
pub const ERASURE_NATS_SUBJECT: &str = "uninc.control.erasure";

// ---------------------------------------------------------------------------
// Parsed operation — intermediate representation before user resolution
// ---------------------------------------------------------------------------

/// A reference to a table or collection mentioned in the query.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TableRef {
    pub name: String,
    pub alias: Option<String>,
}

/// A predicate from a WHERE clause or MongoDB filter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilterPredicate {
    pub column: String,
    pub operator: String,
    pub value: Option<String>,
}

/// Protocol-specific parsed query, before user resolution.
#[derive(Debug, Clone, Default)]
pub struct ParsedOperation {
    pub tables: Vec<TableRef>,
    pub columns: Vec<String>,
    pub filters: Vec<FilterPredicate>,
    pub action: Option<ActionType>,
    /// Raw WHERE clause string (Postgres).
    pub raw_where: Option<String>,
    /// Raw BSON filter document (MongoDB).
    pub raw_bson_filter: Option<Vec<u8>>,
}

// ---------------------------------------------------------------------------
// User resolver trait
// ---------------------------------------------------------------------------

/// Implemented by each protocol module to resolve affected user IDs.
pub trait UserResolver: Send + Sync {
    fn resolve(
        &self,
        operation: &ParsedOperation,
    ) -> impl std::future::Future<Output = Vec<String>> + Send;
}

// ---------------------------------------------------------------------------
// Hex serialization helper for [u8; 32]
// ---------------------------------------------------------------------------

mod hex_hash {
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
        let mut arr = [0u8; 32];
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("expected 32-byte hex string"));
        }
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_event_roundtrip_json() {
        let event = AccessEvent {
            protocol: Protocol::Postgres,
            admin_id: "admin@company.com".into(),
            action: ActionType::Read,
            resource: "users".into(),
            scope: "columns: email, name; filter: id".into(),
            query_fingerprint: [0xab; 32],
            affected_users: vec!["user_42".into()],
            timestamp: 1712592000000,
            session_id: Uuid::new_v4(),
            metadata: HashMap::new(),
        };

        let json = serde_json::to_string(&event).unwrap();
        let deserialized: AccessEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.admin_id, "admin@company.com");
        assert_eq!(deserialized.query_fingerprint, [0xab; 32]);
    }
}
