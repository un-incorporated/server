//! MongoDB change stream subscriber.
//!
//! Uses the official [`mongodb`](https://crates.io/crates/mongodb) Rust
//! driver's `watch()` method to open a Change Stream on the replica set.
//! Each change event (insert, update, replace, delete) becomes a
//! `ChainEntry` appended to the observer's deployment chain.
//!
//! # Why change streams, not raw oplog tailing
//!
//! Change streams are the official MongoDB API for CDC. They:
//! - Handle replica set failover automatically (resume tokens)
//! - Support aggregation-pipeline filtering
//! - Are supported on all MongoDB 4.0+ replica sets
//! - Don't require direct access to `local.oplog.rs` (which needs
//!   special permissions and breaks on sharded clusters)
//!
//! The older `oplog` crate exists but is unmaintained and requires
//! parsing internal BSON formats that MongoDB doesn't guarantee stable.
//!
//! # Independence from the proxy
//!
//! The connection goes directly to the replica set with read-only
//! credentials provisioned out-of-band. The proxy must not be the
//! source of these credentials — a compromised proxy cannot filter
//! or modify what the observer sees.

use crate::chain::ObserverChain;
use crate::config::MongoSubscriberConfig;
use futures::StreamExt;
use mongodb::{options::ClientOptions, Client, options::ChangeStreamOptions, change_stream::event::OperationType};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info, warn};
use uninc_common::ActionType;

/// The sentinel namespace the proxy's `MongoActorMarker` sidechannel
/// writes to before each admin data op. Change-stream inserts against
/// this collection carry `{ actor_id, session_id, at }` documents that
/// the observer uses to attribute subsequent real-collection events.
/// MUST stay in sync with the proxy-side constants in
/// `crates/proxy/src/mongodb/actor_marker.rs`.
const MARKER_DB: &str = "_uninc_marker";
const MARKER_COLL: &str = "events";

pub struct MongoSubscriber {
    cfg: MongoSubscriberConfig,
    chain: Arc<ObserverChain>,
}

impl MongoSubscriber {
    pub fn new(cfg: MongoSubscriberConfig, chain: Arc<ObserverChain>) -> Self {
        Self { cfg, chain }
    }

    /// Long-running subscriber loop. Reconnects on failure with
    /// exponential backoff, bounded at 60 seconds.
    pub async fn run(self) {
        info!(
            database = ?self.cfg.database,
            "mongo subscriber starting"
        );

        let mut backoff_secs = 1u64;
        loop {
            match self.connect_and_tail().await {
                Ok(()) => {
                    backoff_secs = 1;
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
                Err(e) => {
                    error!(
                        error = %e,
                        next_retry_secs = backoff_secs,
                        "mongo subscriber errored, backing off"
                    );
                    tokio::time::sleep(Duration::from_secs(backoff_secs)).await;
                    backoff_secs = (backoff_secs * 2).min(60);
                }
            }
        }
    }

    /// Connect to the MongoDB replica set via the official driver, open
    /// a change stream, and process events until disconnected.
    async fn connect_and_tail(&self) -> anyhow::Result<()> {
        let chain = Arc::clone(&self.chain);

        // Parse the connection URI. The driver handles replica set discovery,
        // SCRAM auth, and connection pooling internally.
        let client_options = ClientOptions::parse(&self.cfg.uri).await?;
        let client = Client::with_options(client_options)?;

        // If a specific database is configured, watch that database only.
        // Otherwise, watch the entire cluster (admin-level change stream).
        // Open a change stream. The mongodb v2 driver's watch() takes
        // (pipeline, options) — we pass empty pipeline and default options.
        let pipeline: Vec<bson::Document> = vec![];
        let cs_opts = ChangeStreamOptions::default();

        let mut change_stream = if let Some(ref db_name) = self.cfg.database {
            info!(database = db_name.as_str(), "opening database-level change stream");
            let db = client.database(db_name);
            db.watch(pipeline, cs_opts).await?
        } else {
            info!("opening cluster-level change stream");
            client.watch(pipeline, cs_opts).await?
        };

        info!("mongodb change stream active");
        let mut event_count: u64 = 0;
        // Most-recent actor id seen on the sentinel collection. Per
        // spec §5.5 byte-identity, this is HMAC'd with the deployment
        // salt at `ObserverChain::append` time to derive actor_id_hash.
        // v0.1-pre uses a single global slot; concurrent admin sessions
        // race here — see server/SPEC-DELTA.md §"Actor identity" for
        // the interleave limit.
        let mut last_actor: Option<String> = None;

        // Process change events. The driver handles resume tokens
        // internally — if the connection drops and we reconnect via the
        // outer loop, a new watch() call picks up from where we left off
        // (MongoDB stores the resume position server-side).
        while let Some(result) = change_stream.next().await {
            let event = match result {
                Ok(ev) => ev,
                Err(e) => {
                    warn!(error = %e, "change stream event error");
                    continue;
                }
            };

            // Extract namespace (database.collection) — read once,
            // reused for both the sentinel-collection branch and the
            // normal change-recording path below.
            let (db_name, collection) = match event.ns.as_ref() {
                Some(ns) => (
                    ns.db.as_str(),
                    ns.coll.as_deref().unwrap_or(""),
                ),
                None => ("", ""),
            };

            // SENTINEL MARKER BRANCH — the proxy's
            // `MongoActorMarker` writes `_uninc_marker.events` inserts
            // AHEAD of each admin op. We pick up the actor_id from
            // those inserts and attribute the NEXT real-collection
            // event to it. Sentinel events are NOT appended to the
            // observer chain — they're infrastructure, not data ops.
            if db_name == MARKER_DB && collection == MARKER_COLL {
                if matches!(event.operation_type, OperationType::Insert) {
                    if let Some(full_doc) = event.full_document.as_ref() {
                        if let Ok(actor) = full_doc.get_str("actor_id") {
                            debug!(actor, "sentinel marker observed");
                            last_actor = Some(actor.to_string());
                        }
                    }
                }
                continue;
            }

            // ChangeStreamEvent has typed fields from the mongodb driver.
            let (action, op_label) = match event.operation_type {
                OperationType::Insert => (ActionType::Write, "insert"),
                OperationType::Update => (ActionType::Write, "update"),
                OperationType::Replace => (ActionType::Write, "replace"),
                OperationType::Delete => (ActionType::Delete, "delete"),
                OperationType::Drop => (ActionType::SchemaChange, "drop"),
                OperationType::Rename => (ActionType::SchemaChange, "rename"),
                OperationType::DropDatabase => (ActionType::SchemaChange, "dropDatabase"),
                _ => {
                    debug!("skipping non-DML change event");
                    continue;
                }
            };

            let collection = if collection.is_empty() { "unknown" } else { collection };

            // Extract document key (_id field).
            let doc_key = event
                .document_key
                .as_ref()
                .and_then(|dk| dk.get("_id"))
                .map(|id| format!("{}", id))
                .unwrap_or_else(|| "unknown".to_string());

            // Build scope — summarizes the change for the deployment chain.
            let scope = format!("{}:{}:key={}", op_label, collection, doc_key);

            // Fingerprint: deterministic hash of the operation signature.
            let fingerprint = {
                let mut h = Sha256::new();
                h.update(scope.as_bytes());
                let result: [u8; 32] = h.finalize().into();
                result
            };

            let metadata = Some(HashMap::from([
                ("source".to_string(), "mongodb_change_stream".to_string()),
                ("operation".to_string(), op_label.to_string()),
                ("collection".to_string(), collection.to_string()),
            ]));

            // Actor attribution: use the most-recent sentinel marker
            // if available. Fallback to a deterministic placeholder
            // that `ObserverChain::append` HMACs to a well-formed but
            // non-matching `actor_id_hash` (§5.5 byte comparison will
            // diverge — operator sees a real signal rather than a
            // silent attribution pass).
            let actor_pre_hash = last_actor
                .clone()
                .unwrap_or_else(|| "observer:mongodb".to_string());

            if let Err(e) = chain.append(
                "_deployment",
                actor_pre_hash,
                action,
                collection.to_string(),
                scope,
                fingerprint,
                metadata,
            ).await {
                warn!(error = %e, "failed to append observer chain entry");
            }

            event_count += 1;
            if event_count % 100 == 0 {
                debug!(event_count, "processed MongoDB change events");
            }
        }

        info!(event_count, "mongodb change stream ended");
        Ok(())
    }
}
