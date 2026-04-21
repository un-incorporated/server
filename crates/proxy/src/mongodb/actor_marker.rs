//! MongoDB actor-marker sidechannel.
//!
//! # Why a sidechannel
//!
//! The §5.5 observer/proxy payload-byte comparison requires both sides
//! to agree on the pre-hash actor identifier used to derive
//! `ObservedDeploymentEvent.actor_id_hash` (spec §4.12). The proxy knows
//! the actor because it authenticated the client; the observer reads
//! MongoDB change streams and has no path to the client's identity
//! unless the proxy injects a marker the change stream can carry.
//!
//! MongoDB's `$comment` operation option is NOT propagated to change
//! streams — the driver-side comment is used for server-log correlation
//! and doesn't appear in oplog or change-stream events. Verified via
//! official docs: [Change Events](https://www.mongodb.com/docs/manual/reference/change-events/)
//! enumerates exactly the fields included in each event type, and
//! neither `operationDescription` (present only with
//! `showExpandedEvents: true` for DDL events in MongoDB 6.0+ per
//! [Change Streams](https://www.mongodb.com/docs/manual/changestreams/))
//! nor any other field carries per-op `$comment`.
//!
//! This module writes to a dedicated audit collection
//! `_uninc_marker.events` *before* forwarding each admin data-op on a
//! separate MongoDB connection (sidechannel). The observer's change
//! stream — which by default watches the entire cluster — sees the
//! insert and records the actor/session for correlation with the next
//! real op on the observer's chain. See `crates/observer/src/
//! subscribers/mongo.rs` for the extraction path.
//!
//! # Concurrency semantics
//!
//! Marker writes happen on a shared sidechannel client ahead of the
//! forwarded client op (we `await` the insert before writing to
//! upstream). For a single admin session this preserves marker → op
//! ordering in wall-clock time, which change streams honour. Under
//! concurrent admin sessions the global order is still correct (client
//! library and MongoDB's oplog both serialize writes), but the
//! observer's "most-recent-marker" heuristic cannot by itself attribute
//! interleaved markers from multiple sessions to the right subsequent
//! op. The marker row carries the proxy's `session_id` so future
//! observer logic can refine attribution per-session; v0.1-pre
//! documents the interleave race as an honest limit (see
//! `server/SPEC-DELTA.md` §"Actor identity").
//!
//! # Why not sentinel collection on same connection?
//!
//! Embedding the marker in the client's own wire stream would require
//! forging OP_MSG frames and consuming their reply frames before
//! letting the client's real reply through — feasible but complex.
//! A sidechannel is simpler, isolates the proxy's internal writes from
//! the client's protocol state, and can be pooled independently.

use std::sync::Arc;
use std::time::Duration;

use bson::{doc, Document};
use chrono::Utc;
use mongodb::options::ClientOptions;
use mongodb::{Client, Collection};
use tokio::sync::Mutex;
use tracing::{debug, info, warn};
use uninc_common::error::UnincError;
use uuid::Uuid;

/// Sentinel database and collection where actor markers are written.
/// Two underscores on the database prefix is a convention that keeps
/// admin lists (`show dbs`) visually distinct from customer data, and
/// mirrors MongoDB's own convention for server-reserved databases like
/// `admin`, `local`, `config`. The sentinel database is intentionally
/// out-of-band of customer schemas.
pub const MARKER_DB: &str = "_uninc_marker";
pub const MARKER_COLLECTION: &str = "events";

/// A persistent sidechannel to the upstream MongoDB replica set used to
/// write actor markers. Construction connects and ensures the marker
/// collection exists (idempotent). Emissions are single-document
/// inserts.
#[derive(Clone)]
pub struct MongoActorMarker {
    coll: Collection<Document>,
    /// Serialize emits so two concurrent proxy tasks don't interleave
    /// their insert_one calls in a surprising order. The mongodb driver
    /// is thread-safe, but serializing at the proxy preserves the
    /// "marker strictly before forwarded op" invariant per-session.
    emit_lock: Arc<Mutex<()>>,
}

impl MongoActorMarker {
    /// Connect to the upstream MongoDB via the given URI (`mongodb://…`
    /// connection string — same URI the forwarding path uses) and
    /// return a sidechannel handle. Creates the `_uninc_marker.events`
    /// collection if absent (best-effort — idempotent create is fine).
    pub async fn connect(upstream_uri: &str) -> Result<Self, UnincError> {
        let mut opts = ClientOptions::parse(upstream_uri)
            .await
            .map_err(|e| UnincError::Config(format!("mongo marker parse: {e}")))?;
        // Short connect timeout — marker failures should NOT block
        // listener startup if the upstream is briefly unreachable;
        // the retry happens on the next emit.
        opts.connect_timeout = Some(Duration::from_secs(5));
        opts.server_selection_timeout = Some(Duration::from_secs(5));
        // Label so customer ops-tooling can distinguish these
        // connections from the forwarding path.
        opts.app_name = Some("uninc-proxy-marker".to_string());

        let client = Client::with_options(opts)
            .map_err(|e| UnincError::Config(format!("mongo marker client: {e}")))?;

        let db = client.database(MARKER_DB);
        let coll: Collection<Document> = db.collection(MARKER_COLLECTION);

        // Create the collection if missing. `list_collection_names`
        // returns empty if neither DB nor collection exist — we still
        // call create which will no-op if already present in most
        // recent MongoDB versions, or return NamespaceExists which we
        // swallow.
        match db.create_collection(MARKER_COLLECTION, None).await {
            Ok(_) => info!(
                database = MARKER_DB,
                collection = MARKER_COLLECTION,
                "marker collection created"
            ),
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("NamespaceExists") || msg.contains("already exists") {
                    debug!("marker collection already exists");
                } else {
                    warn!(error = %e, "marker collection create failed — will retry on first emit");
                }
            }
        }

        Ok(Self {
            coll,
            emit_lock: Arc::new(Mutex::new(())),
        })
    }

    /// Emit an actor marker. MUST be called and awaited BEFORE
    /// forwarding the client's op to upstream — observer correlates
    /// markers with subsequent change-stream events by arrival order.
    pub async fn emit(&self, actor_id: &str, session_id: Uuid) -> Result<(), UnincError> {
        let _guard = self.emit_lock.lock().await;
        let doc = doc! {
            "actor_id": actor_id,
            "session_id": session_id.to_string(),
            "at": Utc::now().timestamp_millis(),
        };
        // Single insert; use `InsertManyOptions` default (no journal,
        // writeConcern default) — the emit is best-effort attribution,
        // not a durability primitive. If the upstream Mongo rejects
        // the insert we return an error; the caller fail-closes the
        // client connection (same policy as the main log-before-access
        // NATS publish).
        let _ = self
            .coll
            .insert_one(doc, None)
            .await
            .map_err(|e| UnincError::Proxy(format!("mongo marker insert: {e}")))?;
        Ok(())
    }
}

/// Type-erased emit trait so callers can inject a test double. The
/// concrete `MongoActorMarker` implements this; tests can supply a
/// recording mock.
#[async_trait::async_trait]
pub trait ActorMarkerEmitter: Send + Sync {
    async fn emit(&self, actor_id: &str, session_id: Uuid) -> Result<(), UnincError>;
}

#[async_trait::async_trait]
impl ActorMarkerEmitter for MongoActorMarker {
    async fn emit(&self, actor_id: &str, session_id: Uuid) -> Result<(), UnincError> {
        MongoActorMarker::emit(self, actor_id, session_id).await
    }
}

/// Marker constants re-exported so the observer-side extraction
/// subscriber can match the exact database/collection name without
/// copy-paste drift.
pub const fn marker_namespace() -> (&'static str, &'static str) {
    (MARKER_DB, MARKER_COLLECTION)
}
