use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

use crate::error::UnincError;

// ---------------------------------------------------------------------------
// Canonical proxy listen ports — the "+1000 shift" (see LOCAL-DEV.md §"Why
// the proxy is on :6432 / :28017 / :10000"). Hard-coded, not config-driven:
// clients point their drivers at these numbers, full stop. Overriding them
// would let a self-hoster ship a non-standard port and break the "paste
// this connection string" UX that the whole dev-ergonomics argument rests
// on. If you need a different port, change these constants and rebuild —
// don't add a config knob.
// ---------------------------------------------------------------------------

pub const PROXY_POSTGRES_PORT: u16 = 6432;
pub const PROXY_MONGODB_PORT: u16 = 28017;
pub const PROXY_S3_PORT: u16 = 10000;

// HTTP control surface. /health is unauthenticated status, polled by
// docker-compose healthchecks and by any out-of-band control plane.
// /api/v1/chain/* is the JWT-gated transparency read API served by a
// separate Axum listener in the same binary. See docs/chain-api.md.
pub const PROXY_HEALTH_PORT: u16 = 9090;
pub const PROXY_CHAIN_API_PORT: u16 = 9091;

// Chain-MinIO port on each replica VM (multi-VM topology). Reachable only
// from the proxy VM service account tag. Carries the uninc-chain bucket
// (prefixes chains/user/... and chains/_deployment/...) with per-replica
// MinIO instances for quorum-replicated chain storage.
//
// Why :9002 and not :9001 or :9100 — :9001 is reserved for MinIO's console
// UI (customer MinIO deployments use it); :9100 is the Prometheus
// node_exporter default and would collide if an operator later adds
// host-level monitoring to replica VMs. :9002 sits adjacent to the MinIO
// :9000/:9001 family so it reads as "another MinIO" in netstat without
// conflicting with either neighbour.
pub const REPLICA_CHAIN_MINIO_PORT: u16 = 9002;

// NOTE: there is NO metering API on the proxy. Metering, if any, is an
// out-of-band concern for whoever operates the control plane — not the
// data plane the proxy implements.

// ---------------------------------------------------------------------------
// Top-level config — parsed from uninc.yml
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnincConfig {
    pub proxy: ProxyConfig,

    #[serde(default)]
    pub chain: ChainConfig,

    #[serde(default)]
    pub verification: Option<VerificationConfig>,
}

impl UnincConfig {
    /// Load config from a YAML file, with environment variable overrides.
    pub fn load(path: &Path) -> Result<Self, UnincError> {
        let contents = std::fs::read_to_string(path)
            .map_err(|e| UnincError::Config(format!("failed to read {}: {e}", path.display())))?;
        let config: Self = serde_yaml::from_str(&contents)?;
        Ok(config)
    }
}

// ---------------------------------------------------------------------------
// Proxy config
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    #[serde(default)]
    pub postgres: Option<ProtocolListenerConfig>,

    #[serde(default)]
    pub mongodb: Option<ProtocolListenerConfig>,

    #[serde(default)]
    pub s3: Option<S3Config>,

    #[serde(default)]
    pub tls: TlsConfig,

    pub nats: NatsConfig,

    pub identity: IdentityConfig,

    pub schema: SchemaConfig,

    #[serde(default)]
    pub mode: DeploymentMode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolListenerConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,

    pub upstream: String,

    #[serde(default)]
    pub pool: PoolConfig,

    #[serde(default)]
    pub timeouts: TimeoutConfig,

    #[serde(default)]
    pub rate_limit: RateLimitConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct S3Config {
    #[serde(default = "default_true")]
    pub enabled: bool,

    pub upstream: String,

    #[serde(default)]
    pub user_data_patterns: Vec<S3UserDataPattern>,

    #[serde(default)]
    pub excluded_prefixes: Vec<String>,

    #[serde(default = "default_true")]
    pub log_presigned_url_generation: bool,

    #[serde(default = "default_true")]
    pub multipart_log_on_complete_only: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct S3UserDataPattern {
    pub bucket: String,
    pub key_pattern: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolConfig {
    #[serde(default = "default_min_connections")]
    pub min: u32,

    #[serde(default = "default_max_connections")]
    pub max: u32,

    #[serde(default = "default_idle_timeout")]
    pub idle_timeout_secs: u64,

    #[serde(default = "default_connect_timeout")]
    pub connection_timeout_secs: u64,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            min: default_min_connections(),
            max: default_max_connections(),
            idle_timeout_secs: default_idle_timeout(),
            connection_timeout_secs: default_connect_timeout(),
        }
    }
}

/// Item B of the round-1 overload-protection plan. Bounds the time the proxy
/// will wait on a stalled upstream or idle admin session before dropping the
/// connection. See ARCHITECTURE.md §"Capacity & overload protection" Layer 1.
///
/// All values are seconds. Override via `uninc.yml`:
///
/// ```yaml
/// postgres:
///   timeouts:
///     admin_idle_secs: 30
///     app_idle_secs: 600
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeoutConfig {
    /// Max time an ADMIN-class connection can spend between IO events before
    /// the proxy drops it. This is the de-facto query timeout: a slow query
    /// with no upstream progress for this long gets killed. Postgres backs
    /// this up with `statement_timeout` set in `startup-db.sh` (item F).
    #[serde(default = "default_admin_idle_timeout")]
    pub admin_idle_secs: u64,

    /// Max time an APP-class connection can sit idle before the proxy drops
    /// it. Significantly longer than `admin_idle_secs` because normal app
    /// connection pools idle for long stretches between requests.
    #[serde(default = "default_app_idle_timeout")]
    pub app_idle_secs: u64,
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        Self {
            admin_idle_secs: default_admin_idle_timeout(),
            app_idle_secs: default_app_idle_timeout(),
        }
    }
}

/// Item G of the round-1 overload-protection plan — per-IP and per-credential
/// token-bucket rate limiting. See ARCHITECTURE.md §"Capacity & overload
/// protection" Layer 1.
///
/// Disabled by default in round 1 — enable per-customer in `uninc.yml`:
///
/// ```yaml
/// postgres:
///   rate_limit:
///     enabled: true
///     per_ip_rps: 100
///     per_ip_burst: 200
///     per_credential_rps: 50
///     per_credential_burst: 100
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default = "default_per_ip_rps")]
    pub per_ip_rps: u32,

    #[serde(default = "default_per_ip_burst")]
    pub per_ip_burst: u32,

    #[serde(default = "default_per_credential_rps")]
    pub per_credential_rps: u32,

    #[serde(default = "default_per_credential_burst")]
    pub per_credential_burst: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            per_ip_rps: default_per_ip_rps(),
            per_ip_burst: default_per_ip_burst(),
            per_credential_rps: default_per_credential_rps(),
            per_credential_burst: default_per_credential_burst(),
        }
    }
}

// ---------------------------------------------------------------------------
// TLS
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TlsConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default)]
    pub cert_path: Option<String>,

    #[serde(default)]
    pub key_path: Option<String>,
}

// ---------------------------------------------------------------------------
// NATS
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatsConfig {
    #[serde(default = "default_nats_url")]
    pub url: String,

    #[serde(default = "default_nats_subject_prefix")]
    pub subject_prefix: String,
}

// ---------------------------------------------------------------------------
// Identity classification
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityConfig {
    #[serde(default)]
    pub mode: IdentityMode,

    #[serde(default)]
    pub app_sources: Vec<AppSource>,

    #[serde(default)]
    pub admin_credentials: HashMap<String, Vec<CredentialEntry>>,

    #[serde(default)]
    pub app_credentials: HashMap<String, Vec<CredentialEntry>>,

    #[serde(default)]
    pub behavioral_fingerprinting: bool,

    #[serde(default)]
    pub mtls: Option<MtlsConfig>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityMode {
    Credential,
    #[default]
    SourceCredential,
    MtlsSourceCredential,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSource {
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default)]
    pub ip: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialEntry {
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub access_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MtlsConfig {
    pub enabled: bool,
    pub app_cert: String,
    pub ca_cert: String,
}

// ---------------------------------------------------------------------------
// Schema annotation — tells the proxy which tables/collections hold user data
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaConfig {
    #[serde(default)]
    pub user_tables: Vec<UserTableConfig>,

    #[serde(default)]
    pub user_collections: Vec<UserCollectionConfig>,

    #[serde(default)]
    pub excluded_tables: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserTableConfig {
    pub table: String,
    pub user_id_column: UserIdColumn,
    #[serde(default)]
    pub sensitive_columns: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserCollectionConfig {
    pub collection: String,
    pub user_id_field: UserIdColumn,
}

/// The user_id_column can be a single string or a list of strings
/// (for tables like `messages` with `sender_id` and `recipient_id`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum UserIdColumn {
    Single(String),
    Multiple(Vec<String>),
}

impl UserIdColumn {
    pub fn columns(&self) -> Vec<&str> {
        match self {
            Self::Single(s) => vec![s.as_str()],
            Self::Multiple(v) => v.iter().map(|s| s.as_str()).collect(),
        }
    }
}

// ---------------------------------------------------------------------------
// Deployment mode
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DeploymentMode {
    ProxyOnly,
    #[default]
    Greenfield,
    Full,
}

// ---------------------------------------------------------------------------
// Egress containment (multi-VM topology)
// ---------------------------------------------------------------------------

/// Outbound containment posture for the co-located customer app in a
/// multi-VM topology.
///
/// Orthogonal to `DeploymentMode` above — the multi-VM topology can
/// co-locate the customer app behind an Envoy egress proxy whose
/// allowlist becomes a chain-visible control. `EgressMode` is that
/// posture and only makes sense when an egress proxy is in front of
/// the app. Defaults to `Dev` — open-but-recording rather than
/// fail-closed — so a fresh deployment does not instantly black-hole
/// legitimate outbound traffic.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum EgressMode {
    /// Default for new egress-contained deployments. Envoy in log-only
    /// mode: every outbound destination is recorded on the chain but
    /// nothing is blocked. Cloud DNS response policy is disabled
    /// (queries fall through to upstream resolvers). Custom domain
    /// mapping is refused. Customer-facing label: "Dev mode."
    #[default]
    Dev,
    /// Prod mode. Envoy enforces a per-deployment SNI allowlist,
    /// Cloud DNS response policy returns NXDOMAIN for unlisted names,
    /// custom domain mapping is permitted, deployment is allowed to
    /// carry real production traffic.
    Allowlisted,
    /// Fail-safe. Used for 30-day Dev auto-lock (v1.1), emergency
    /// customer-triggered lockdown, or explicit demotion from Prod.
    /// Envoy denies all public egress, DNS returns NXDOMAIN for
    /// everything.
    Locked,
}

impl std::fmt::Display for EgressMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Dev => write!(f, "dev"),
            Self::Allowlisted => write!(f, "allowlisted"),
            Self::Locked => write!(f, "locked"),
        }
    }
}

/// A single entry in the per-deployment egress allowlist.
///
/// Exact-hostname only in v1 — no wildcards. Wildcard support is deferred
/// because it requires extending Envoy SNI matchers, the Cloud DNS zone
/// generator, and the UI validator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EgressAllowlistEntry {
    /// Exact hostname the Cloud Run app is permitted to reach.
    /// Example: "api.stripe.com". No wildcards in v1.
    pub domain: String,
    /// Free-text description of why this domain is on the allowlist.
    /// Surfaces in chain events so auditors and end users can see what
    /// was permitted and why. Example: "Stripe Checkout API".
    pub purpose: String,
    /// TCP ports permitted on this destination. Defaults to `[443]`
    /// when omitted. SMTP and other non-HTTPS ports are v2.
    #[serde(default)]
    pub ports: Option<Vec<u16>>,
    /// User ID (from whatever operator identity system added this entry).
    /// Recorded for audit purposes.
    pub added_by: String,
    /// ISO-8601 timestamp when the entry was added.
    pub added_at: String,
}

/// Rendered egress configuration — the input to the Envoy config renderer
/// that runs during the `containment` provisioning phase.
///
/// The shape matches the JSON a control plane would persist per
/// deployment (fields: `egressAllowlist`, `egressMode`,
/// `egressAllowlistVersion`). Kept in `uninc-common` so both ends of
/// the wire agree on the type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EgressConfig {
    pub mode: EgressMode,
    #[serde(default)]
    pub allowlist: Vec<EgressAllowlistEntry>,
    #[serde(default)]
    pub version: u32,
}

impl Default for EgressConfig {
    fn default() -> Self {
        Self {
            mode: EgressMode::default(),
            allowlist: Vec::new(),
            version: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Chain config
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainConfig {
    #[serde(default = "default_chain_storage")]
    pub storage_path: String,

    #[serde(default = "default_shard_size")]
    pub shard_size: u64,

    #[serde(default)]
    pub server_salt: Option<String>,

    #[serde(default)]
    pub keystore: KeystoreConfig,

    /// S3-compatible durable backup for chain data.
    /// When configured, entries are dual-written: local disk (hot) + S3 (durable).
    /// Legacy single-target config — retained for backward compatibility.
    /// Prefer `durability` for multi-VM multi-replica quorum storage.
    #[serde(default)]
    pub s3: Option<ChainS3Config>,

    /// Multi-replica durable chain storage (multi-VM topology). Each
    /// entry in `replicas` corresponds to one replica VM's chain-MinIO
    /// instance, and chain-engine fan-outs quorum writes. Single-host
    /// topologies leave this unset (the proxy-local MinIO is the single
    /// target). See docs/chain-storage-architecture.md.
    #[serde(default)]
    pub durability: Option<ChainDurabilityConfig>,

    /// LRU disk cache eviction settings.
    #[serde(default)]
    pub lru_cache: LruCacheConfig,

    /// Chain data retention in days. After this period, chain entries are
    /// auto-deleted. Default: 365 (1 year). SOC2/PCI require 1 year minimum;
    /// GDPR Article 5(1)(e) says "no longer than necessary" — 1 year is the
    /// accepted industry norm for audit logs.
    #[serde(default = "default_retention_days")]
    pub retention_days: u32,
}

impl Default for ChainConfig {
    fn default() -> Self {
        Self {
            storage_path: default_chain_storage(),
            shard_size: default_shard_size(),
            server_salt: None,
            keystore: KeystoreConfig::default(),
            s3: None,
            durability: None,
            lru_cache: LruCacheConfig::default(),
            retention_days: default_retention_days(),
        }
    }
}

/// S3-compatible storage backend for durable chain backup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainS3Config {
    pub endpoint: String,
    pub bucket: String,
    pub access_key: String,
    pub secret_key: String,
    /// S3 region (required by some providers, defaults to "us-east-1").
    #[serde(default = "default_s3_region")]
    pub region: String,
}

/// N-way replicated chain storage across replica MinIOs. When `replicas` is
/// non-empty, chain-engine fans out each chain write to all replicas and
/// waits for ⌊N/2⌋+1 acks before considering the write committed.
///
/// Single-host collapse: when `replicas` is empty, the ChainDurabilityConfig
/// is effectively a pass-through to the single proxy-local MinIO. The code
/// path is identical — quorum of 1-of-1 is trivially satisfied.
///
/// See docs/chain-storage-architecture.md for the full architecture.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ChainDurabilityConfig {
    /// Per-replica MinIO endpoints. Each entry corresponds to one replica
    /// VM's chain-MinIO instance at :9002. Single-host topologies: empty.
    #[serde(default)]
    pub replicas: Vec<ChainReplicaStoreConfig>,

    /// Quorum threshold. If 0 (default), computed as ⌊N/2⌋+1 of replicas.len().
    #[serde(default)]
    pub quorum_threshold: usize,

    /// Write timeout in ms. Quorum must be reached within this window or
    /// the write fails and fires the failure handler chain.
    #[serde(default = "default_write_timeout_ms")]
    pub write_timeout_ms: u64,

    /// Bucket name (same across all replica MinIOs). Default: "uninc-chain".
    #[serde(default = "default_chain_bucket")]
    pub bucket: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainReplicaStoreConfig {
    /// Replica identifier matching `ReplicaConfig.id` for the sibling DB replica.
    pub replica_id: String,
    /// Full endpoint URL, e.g. "http://10.0.2.5:9002".
    pub endpoint: String,
    pub access_key: String,
    pub secret_key: String,
    #[serde(default = "default_s3_region")]
    pub region: String,
}

fn default_write_timeout_ms() -> u64 {
    5000
}

fn default_chain_bucket() -> String {
    "uninc-chain".into()
}

/// LRU disk cache settings for chain data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LruCacheConfig {
    /// Maximum local disk usage for chain data (bytes). Default: 1 GB.
    #[serde(default = "default_lru_max_bytes")]
    pub max_bytes: u64,
    /// Only evict entries that have been marked verified by the nightly
    /// cross-replica comparison. Unverified entries are never evicted.
    /// Default: true.
    #[serde(default = "default_true")]
    pub evict_after_verified: bool,
}

impl Default for LruCacheConfig {
    fn default() -> Self {
        Self {
            max_bytes: default_lru_max_bytes(),
            evict_after_verified: true,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum KeystoreConfig {
    #[default]
    LocalFile,
    Vault {
        url: String,
        token: String,
    },
}

// ---------------------------------------------------------------------------
// Verification config (multi-VM topology)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,

    #[serde(default = "default_replica_count")]
    pub replica_count: u32,

    /// Retained for backward-compat with existing YAML files; the 2026-04-15
    /// redesign pins exactly one Verifier per session, so this field is
    /// effectively ignored. Deployments with `verifier_count: 0` from
    /// pre-redesign config files still work — the engine always uses 1.
    #[serde(default = "default_verifier_count")]
    pub verifier_count: u32,

    /// Connection info for each replica. Empty in the free Playground tier;
    /// populated with 3+ entries in the paid tier.
    #[serde(default)]
    pub replicas: Vec<ReplicaConfig>,

    #[serde(default)]
    pub assignment: AssignmentConfig,

    #[serde(default)]
    pub timing: VerificationTimingConfig,

    #[serde(default)]
    pub batch: BatchConfig,

    #[serde(default)]
    pub on_failure: FailureResponseConfig,

    /// Base URL of this deployment's observer VM HTTP surface, used by
    /// the scheduled verification task to fetch the observer's chain
    /// head and cross-compare with the proxy's own head (UAT §3.3).
    /// Example: `"http://10.0.3.5:2026"`. `None` disables the comparison
    /// (single-host / Playground topologies with no observer).
    #[serde(default)]
    pub observer_url: Option<String>,

    /// Shared secret the observer expects in the `x-uninc-read-secret`
    /// header on its `/observer/chain/:chain_id/head` endpoint. Matches
    /// the observer's `ObserverConfig.read_secret`. Required if
    /// `observer_url` is set; silently ignored otherwise.
    #[serde(default)]
    pub observer_read_secret: Option<String>,
}

/// Connection details for a single database replica.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicaConfig {
    pub id: String,
    pub host: String,
    #[serde(default = "default_pg_port")]
    pub port: u16,
    pub user: String,
    pub password: String,
    pub database: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AssignmentConfig {
    #[serde(default = "default_entropy_sources")]
    pub entropy_sources: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationTimingConfig {
    #[serde(default = "default_true")]
    pub verify_on_session_end: bool,

    #[serde(default = "default_periodic_hours")]
    pub periodic_hours: u32,

    #[serde(default = "default_true")]
    pub nightly_full_compare: bool,

    /// Hour of day (UTC) to run nightly full comparison. Default: 2 (02:00 UTC).
    #[serde(default = "default_nightly_hour")]
    pub nightly_compare_hour_utc: u32,

    #[serde(default = "default_replication_lag_buffer")]
    pub replication_lag_buffer_ms: u64,
}

impl Default for VerificationTimingConfig {
    fn default() -> Self {
        Self {
            verify_on_session_end: true,
            periodic_hours: default_periodic_hours(),
            nightly_full_compare: true,
            nightly_compare_hour_utc: default_nightly_hour(),
            replication_lag_buffer_ms: default_replication_lag_buffer(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchConfig {
    #[serde(default = "default_summarize_threshold")]
    pub summarize_threshold: u64,

    #[serde(default = "default_checkpoint_interval")]
    pub checkpoint_interval_rows: u64,
}

impl Default for BatchConfig {
    fn default() -> Self {
        Self {
            summarize_threshold: default_summarize_threshold(),
            checkpoint_interval_rows: default_checkpoint_interval(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailureResponseConfig {
    #[serde(default = "default_true")]
    pub alert: bool,

    #[serde(default = "default_true")]
    pub lock_admin: bool,

    #[serde(default)]
    pub auto_rollback: bool,

    #[serde(default)]
    pub quarantine_replica: bool,
}

impl Default for FailureResponseConfig {
    fn default() -> Self {
        Self {
            alert: true,
            lock_admin: true,
            auto_rollback: false,
            quarantine_replica: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Default value helpers
// ---------------------------------------------------------------------------

fn default_true() -> bool {
    true
}
fn default_min_connections() -> u32 {
    2
}
fn default_max_connections() -> u32 {
    20
}
fn default_idle_timeout() -> u64 {
    300
}
fn default_connect_timeout() -> u64 {
    5
}
fn default_admin_idle_timeout() -> u64 {
    30
}
fn default_app_idle_timeout() -> u64 {
    600
}
fn default_per_ip_rps() -> u32 {
    100
}
fn default_per_ip_burst() -> u32 {
    200
}
fn default_per_credential_rps() -> u32 {
    50
}
fn default_per_credential_burst() -> u32 {
    100
}
fn default_nats_url() -> String {
    "nats://nats:4222".into()
}
fn default_nats_subject_prefix() -> String {
    "uninc.access".into()
}
fn default_chain_storage() -> String {
    "/data/chains".into()
}
fn default_shard_size() -> u64 {
    10_000
}
fn default_pg_port() -> u16 {
    5432
}
fn default_s3_region() -> String {
    "us-east-1".into()
}
fn default_lru_max_bytes() -> u64 {
    1_073_741_824 // 1 GB
}
fn default_retention_days() -> u32 {
    365
}
fn default_nightly_hour() -> u32 {
    2
}
fn default_replica_count() -> u32 {
    3
}
fn default_verifier_count() -> u32 {
    1
}
fn default_entropy_sources() -> Vec<String> {
    vec![
        "chain_head".into(),
        "system_random".into(),
        "drand".into(),
    ]
}
fn default_periodic_hours() -> u32 {
    6
}
fn default_replication_lag_buffer() -> u64 {
    5000
}
fn default_summarize_threshold() -> u64 {
    1000
}
fn default_checkpoint_interval() -> u64 {
    2500
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_config() {
        let yaml = r#"
proxy:
  postgres:
    enabled: true
    upstream: "postgres://user:pass@postgres:5432/mydb"
  nats:
    url: "nats://localhost:4222"
  identity:
    mode: credential
    admin_credentials:
      postgres:
        - username: admin
    app_credentials:
      postgres:
        - username: app_user
  schema:
    user_tables:
      - table: users
        user_id_column: id
        sensitive_columns: [email, phone]
    excluded_tables: [migrations]
"#;
        let config: UnincConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(config.proxy.postgres.is_some());
        assert!(config.proxy.mongodb.is_none());
        assert_eq!(config.proxy.schema.user_tables.len(), 1);
        assert_eq!(config.proxy.schema.user_tables[0].user_id_column.columns(), vec!["id"]);
    }

    #[test]
    fn parse_multi_column_user_id() {
        let yaml = r#"
proxy:
  nats:
    url: "nats://localhost:4222"
  identity:
    mode: credential
  schema:
    user_tables:
      - table: messages
        user_id_column: [sender_id, recipient_id]
"#;
        let config: UnincConfig = serde_yaml::from_str(yaml).unwrap();
        let cols = config.proxy.schema.user_tables[0].user_id_column.columns();
        assert_eq!(cols, vec!["sender_id", "recipient_id"]);
    }
}
