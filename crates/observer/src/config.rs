//! Observer configuration — loaded from `observer.yml` at startup.
//!
//! The observer VM gets its config from a yaml file mounted into the
//! container by the provisioning worker. Credentials are sourced from
//! GCP Secret Manager by the provisioning worker and written into the
//! yaml file at deploy time — the observer itself does not reach out to
//! Secret Manager.

use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObserverConfig {
    /// Deployment identifier — used as a label in chain entries and
    /// telemetry. Matches the www-side `Deployment.id` (ULID or UUID).
    pub deployment_id: String,

    /// Local disk path where the observer chain lives. Same on-disk
    /// format as the proxy chain (see `chain-store` crate).
    #[serde(default = "default_chain_storage")]
    pub chain_storage_path: String,

    /// HTTP port for the verification-read endpoint. Exposed only to
    /// the proxy VM service account tag via the deployment VPC firewall.
    #[serde(default = "default_http_port")]
    pub http_port: u16,

    /// Shared secret that the proxy (and any out-of-band control plane)
    /// use to read observer-chain data over the verification-read
    /// endpoint. The observer never
    /// writes the chain to anywhere except its own local disk; only the
    /// verification task reads it to compare against the proxy chain.
    pub read_secret: String,

    /// Deployment salt — HMAC key used to derive the `actor_id_hash`
    /// field of `ObservedDeploymentEvent` (spec §4.12). MUST match the
    /// proxy's `chain.server_salt` so observer-side and proxy-side
    /// hashes over the same pre-hash actor identifier agree byte-for-byte
    /// (required by §5.5 payload-level comparison). The provisioning
    /// worker is responsible for writing the same value into both the
    /// proxy's `uninc.yml` and the observer's `observer.yml` at deploy
    /// time.
    pub deployment_salt: String,

    /// Per-primitive subscriber configs. Missing entries mean the
    /// primitive isn't enabled for this deployment.
    #[serde(default)]
    pub postgres: Option<PostgresSubscriberConfig>,
    #[serde(default)]
    pub mongodb: Option<MongoSubscriberConfig>,
    #[serde(default)]
    pub minio: Option<MinioSubscriberConfig>,
}

impl ObserverConfig {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        let cfg: Self = serde_yaml::from_str(&contents)?;
        Ok(cfg)
    }
}

/// Postgres subscriber — connects to the DB primary using a
/// replication-enabled role and streams pgoutput WAL records.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostgresSubscriberConfig {
    /// Host of the DB primary. In the 5-VM topology this is the first
    /// replica VM's private IP.
    pub host: String,
    #[serde(default = "default_pg_port")]
    pub port: u16,
    /// Replication-enabled user. Created by the provisioning worker
    /// with `REPLICATION` role grant and no data-modification rights.
    pub user: String,
    pub password: String,
    pub database: String,
    /// Logical replication slot name. Must be unique per observer so
    /// two observers don't step on each other. Default: `uninc_observer_<deployment_id>`.
    #[serde(default)]
    pub replication_slot: Option<String>,
    /// Logical replication publication name — created by the
    /// provisioning worker via `CREATE PUBLICATION ... FOR ALL TABLES`.
    #[serde(default = "default_publication_name")]
    pub publication: String,
}

/// MongoDB subscriber — tails the oplog of the replica set primary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MongoSubscriberConfig {
    /// `mongodb://` URI for the replica set. Includes credentials.
    pub uri: String,
    /// Database to tail. Empty = all databases.
    #[serde(default)]
    pub database: Option<String>,
}

/// MinIO subscriber — receives bucket notifications over NATS.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MinioSubscriberConfig {
    /// NATS URL where MinIO publishes bucket events. Typically the
    /// deployment's internal NATS server.
    pub nats_url: String,
    /// Subject MinIO publishes on. Configured at deploy time via
    /// `mc admin config set notify_nats`.
    #[serde(default = "default_minio_subject")]
    pub subject: String,
}

fn default_chain_storage() -> String {
    "/data/observer-chains".into()
}

fn default_http_port() -> u16 {
    2026
}

fn default_pg_port() -> u16 {
    5432
}

fn default_publication_name() -> String {
    "uninc_observer_pub".into()
}

fn default_minio_subject() -> String {
    "uninc.observer.minio".into()
}
