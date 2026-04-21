//! Postgres client for querying replica state during cross-replica verification.
//!
//! Connects to individual replica instances to compute table checksums,
//! check replication lag, and replay operations for state comparison.

use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio_postgres::{Client, NoTls};
use tracing::{debug, error, info};
use uninc_common::config::ReplicaConfig;

#[derive(Debug, Error)]
pub enum ReplicaError {
    #[error("connection failed: {0}")]
    Connection(String),
    #[error("query failed: {0}")]
    Query(String),
    #[error("checksum computation failed: {0}")]
    Checksum(String),
}

/// Client for querying a single Postgres replica.
pub struct ReplicaClient {
    client: Client,
    replica_id: String,
    // The background connection task handle — must be kept alive.
    _conn_handle: tokio::task::JoinHandle<()>,
}

impl ReplicaClient {
    /// Connect to a replica.
    pub async fn connect(config: &ReplicaConfig) -> Result<Self, ReplicaError> {
        let conn_string = format!(
            "host={} port={} user={} password={} dbname={}",
            config.host, config.port, config.user, config.password, config.database
        );

        let (client, connection) = tokio_postgres::connect(&conn_string, NoTls)
            .await
            .map_err(|e| ReplicaError::Connection(format!("{}: {e}", config.id)))?;

        let replica_id = config.id.clone();
        let handle = tokio::spawn(async move {
            if let Err(e) = connection.await {
                error!(error = %e, "replica connection error");
            }
        });

        info!(replica = %config.id, host = %config.host, "connected to replica");

        Ok(Self {
            client,
            replica_id,
            _conn_handle: handle,
        })
    }

    /// Compute a SHA-256 checksum of a table's contents.
    ///
    /// Uses `md5(string_agg(t::text, '' ORDER BY ctid))` as the Postgres-level
    /// hash, then wraps it in SHA-256 for consistency with the chain format.
    pub async fn table_checksum(&self, table: &str) -> Result<[u8; 32], ReplicaError> {
        // Sanitize table name (defense-in-depth, not the primary SQL injection barrier).
        let safe_table = table.replace(|c: char| !c.is_alphanumeric() && c != '_', "");

        let query = format!(
            "SELECT COALESCE(md5(string_agg(t::text, '' ORDER BY ctid)), 'empty') FROM {safe_table} t"
        );

        let row = self
            .client
            .query_one(&query, &[])
            .await
            .map_err(|e| ReplicaError::Query(format!("{}: {e}", self.replica_id)))?;

        let md5_hex: String = row.get(0);
        let mut hasher = Sha256::new();
        hasher.update(md5_hex.as_bytes());
        Ok(hasher.finalize().into())
    }

    /// Compute a combined checksum across multiple tables.
    ///
    /// Concatenates per-table checksums (sorted by table name for determinism)
    /// and hashes the result.
    pub async fn full_state_checksum(
        &self,
        tables: &[String],
    ) -> Result<[u8; 32], ReplicaError> {
        let mut sorted_tables = tables.to_vec();
        sorted_tables.sort();

        let mut hasher = Sha256::new();
        for table in &sorted_tables {
            let table_hash = self.table_checksum(table).await?;
            hasher.update(table_hash);
        }
        Ok(hasher.finalize().into())
    }

    /// Check replication lag in milliseconds.
    ///
    /// On a streaming replica, this queries the difference between the
    /// last WAL receive position and the last replay position.
    /// Returns 0 on the primary (no lag).
    pub async fn replication_lag_ms(&self) -> Result<u64, ReplicaError> {
        let query = r#"
            SELECT COALESCE(
                EXTRACT(EPOCH FROM (
                    now() - pg_last_xact_replay_timestamp()
                )) * 1000,
                0
            )::bigint AS lag_ms
        "#;

        let row = self
            .client
            .query_one(query, &[])
            .await
            .map_err(|e| ReplicaError::Query(format!("{}: {e}", self.replica_id)))?;

        let lag: i64 = row.get(0);
        debug!(replica = %self.replica_id, lag_ms = lag, "replication lag");
        Ok(lag.max(0) as u64)
    }

    /// Get the replica ID.
    pub fn id(&self) -> &str {
        &self.replica_id
    }
}

#[cfg(test)]
mod tests {
    // Integration tests for ReplicaClient require a running Postgres instance.
    // They are in the verification checklist (FOLLOWUPS.md V.1-V.8), not here.
    // Unit tests verify the module compiles and types are correct.

    use super::*;

    #[test]
    fn replica_error_display() {
        let e = ReplicaError::Connection("test".into());
        assert_eq!(e.to_string(), "connection failed: test");
    }
}
