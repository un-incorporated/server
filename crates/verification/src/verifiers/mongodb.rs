//! MongoDB cross-replica state verifier.
//!
//! Uses MongoDB's `dbHash` admin command, which returns a deterministic
//! md5 checksum for every collection in a database. The verifier
//! connects to each replica in the assignment, runs `dbHash` on the
//! customer's database, and compares the per-collection checksums.
//!
//! Any divergence at the collection level is reported as a
//! `Divergence` in the `VerificationReport`. The real oplog-based
//! replay model is more nuanced (MongoDB's replica set already gives
//! consistency guarantees when configured with `w: "majority"`), but
//! `dbHash` is the standard tool for confirming that two replicas hold
//! byte-for-byte identical state.
//!
//! Connection pattern: each verification spawns fresh connections and
//! drops them at the end. For hot-path verification we'd want a shared
//! pool, but nightly-cadence verification doesn't need one.

use super::shared::{Divergence, HeadMatch, VerificationReport, VerifierError};
use super::ReplicaStateVerifier;
use crate::assignment::RoleAssignment;
use crate::session::AdminSession;
use mongodb::bson::{doc, Document};
use mongodb::options::{Credential, ServerAddress, ClientOptions};
use mongodb::Client;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;
use tracing::{debug, warn};
use uninc_common::config::ReplicaConfig;
use uninc_common::types::Protocol;

pub struct MongoVerifier {
    /// Connection timeout for each replica. Short so nightly runs don't
    /// hang on a dead replica.
    pub connect_timeout: Duration,
}

impl MongoVerifier {
    pub fn new() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
        }
    }

    async fn connect(&self, replica: &ReplicaConfig) -> Result<Client, VerifierError> {
        // Build ClientOptions directly instead of via a URI so passwords
        // with special characters don't need URL encoding. directConnection
        // forces the driver to talk to this exact host instead of doing
        // replica-set discovery — we want to query this specific replica.
        let options = ClientOptions::builder()
            .hosts(vec![ServerAddress::Tcp {
                host: replica.host.clone(),
                port: Some(replica.port),
            }])
            .credential(
                Credential::builder()
                    .username(replica.user.clone())
                    .password(replica.password.clone())
                    .build(),
            )
            .direct_connection(true)
            .connect_timeout(Some(self.connect_timeout))
            .server_selection_timeout(Some(self.connect_timeout))
            .build();
        Client::with_options(options)
            .map_err(|e| VerifierError::Connection(format!("{}: {e}", replica.id)))
    }

    /// Run `dbHash` on the replica and return the per-collection md5 map.
    /// The MongoDB docs define the response shape: `{collections: {name: md5,
    /// ...}, md5: "aggregate", ...}`.
    async fn db_hash(
        &self,
        client: &Client,
        database: &str,
    ) -> Result<HashMap<String, String>, VerifierError> {
        let db = client.database(database);
        let response: Document = db
            .run_command(doc! { "dbHash": 1 }, None)
            .await
            .map_err(|e| VerifierError::Query(format!("dbHash failed: {e}")))?;

        let collections = response
            .get_document("collections")
            .map_err(|e| VerifierError::Query(format!("dbHash response missing collections: {e}")))?;

        let mut out = HashMap::with_capacity(collections.len());
        for (name, value) in collections {
            if let Some(md5) = value.as_str() {
                out.insert(name.clone(), md5.to_string());
            }
        }
        Ok(out)
    }
}

impl Default for MongoVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplicaStateVerifier for MongoVerifier {
    fn protocol(&self) -> Protocol {
        Protocol::MongoDB
    }

    fn verify_session<'a>(
        &'a self,
        session: &'a AdminSession,
        assignment: &'a RoleAssignment,
    ) -> Pin<Box<dyn Future<Output = Result<VerificationReport, VerifierError>> + Send + 'a>>
    {
        Box::pin(async move {
            let mut report = VerificationReport::new(session.session_id, "mongodb");

            if session.operations.is_empty() {
                report
                    .notes
                    .push("session had no operations, trivially verified".into());
                return Ok(report);
            }

            // Connect to primary and the verifier replica.
            let primary_client = self.connect(&assignment.primary).await?;
            let primary_hashes = self
                .db_hash(&primary_client, &assignment.primary.database)
                .await?;

            let verifier = &assignment.verifier;
            let client = match self.connect(verifier).await {
                Ok(c) => c,
                Err(e) => {
                    warn!(
                        replica = verifier.id.as_str(),
                        error = %e,
                        "mongodb verifier: replica connect failed"
                    );
                    report.divergences.push(Divergence {
                        replica_a: assignment.primary.id.clone(),
                        replica_b: verifier.id.clone(),
                        detail: format!("replica unreachable: {e}"),
                        first_diverging_index: None,
                    });
                    return Ok(report);
                }
            };
            let verifier_hashes = match self.db_hash(&client, &verifier.database).await {
                Ok(h) => h,
                Err(e) => {
                    warn!(
                        replica = verifier.id.as_str(),
                        error = %e,
                        "mongodb verifier: dbHash failed"
                    );
                    report.divergences.push(Divergence {
                        replica_a: assignment.primary.id.clone(),
                        replica_b: verifier.id.clone(),
                        detail: format!("dbHash failed: {e}"),
                        first_diverging_index: None,
                    });
                    return Ok(report);
                }
            };

            // Compare per-collection hashes. Any mismatch is a
            // divergence. Collections present on one side but not
            // the other also count.
            let mut all_keys: Vec<&String> = primary_hashes.keys().collect();
            for k in verifier_hashes.keys() {
                if !primary_hashes.contains_key(k) {
                    all_keys.push(k);
                }
            }
            for key in all_keys {
                let a = primary_hashes.get(key);
                let b = verifier_hashes.get(key);
                if a != b {
                    report.divergences.push(Divergence {
                        replica_a: assignment.primary.id.clone(),
                        replica_b: verifier.id.clone(),
                        detail: format!(
                            "collection '{key}' md5 mismatch: primary={:?} verifier={:?}",
                            a, b
                        ),
                        first_diverging_index: None,
                    });
                }
            }
            debug!(
                replica = verifier.id.as_str(),
                collections = verifier_hashes.len(),
                "mongodb verifier: replica compared"
            );

            Ok(report)
        })
    }

    fn verify_chain_head<'a>(
        &'a self,
        _replica: &'a ReplicaConfig,
        _chain_id: &'a str,
        _expected_head: &'a [u8; 32],
    ) -> Pin<Box<dyn Future<Output = Result<HeadMatch, VerifierError>> + Send + 'a>> {
        // MongoDB-shaped deployments still store chain data in the
        // replica MinIO tier (bucket uninc-chain), same as Postgres. The
        // chain head reader lives on PostgresVerifier — it's not
        // primitive-specific. If someone calls into the Mongo verifier
        // for a chain-head read, return NotImplemented so the engine
        // falls back to PostgresVerifier::verify_chain_head.
        Box::pin(async { Err(VerifierError::NotImplemented) })
    }

    fn bisect_divergence<'a>(
        &'a self,
        _replica_a: &'a ReplicaConfig,
        _replica_b: &'a ReplicaConfig,
        _chain_id: &'a str,
        _lo: u64,
        _hi: u64,
    ) -> Pin<Box<dyn Future<Output = Result<Option<u64>, VerifierError>> + Send + 'a>> {
        Box::pin(async { Ok(None) })
    }
}
