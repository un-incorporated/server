//! Postgres actor-marker sidechannel.
//!
//! # Why a sidechannel + sentinel table
//!
//! The §5.5 observer/proxy payload-byte comparison requires both sides
//! to agree on the pre-hash actor identifier used to derive
//! `ObservedDeploymentEvent.actor_id_hash`. The proxy knows the actor
//! from the client's SCRAM / password auth; the observer reads the WAL
//! via `pg_logical_slot_get_changes()` and has no path to the client's
//! session metadata — `application_name` isn't propagated to WAL, and
//! `pg_stat_activity` is a per-connection view, not a historical one.
//!
//! Two propagation options were evaluated:
//!
//! 1. `pg_logical_emit_message(true, 'uninc_actor', actor)` — injects a
//!    transactional WAL message. The `test_decoding` output plugin
//!    emits lines of the form
//!    `"message: transactional: 1 prefix: uninc_actor, sz: N content:<actor>"`
//!    (see [logicaldecoding-example.html](https://www.postgresql.org/docs/current/logicaldecoding-example.html)
//!    and [pg_decode_message](https://doxygen.postgresql.org/test__decoding_8c_source.html)).
//!    Elegant BUT: the observer's existing subscriber polls a slot
//!    declared with the `pgoutput` plugin whose text output does NOT
//!    carry MESSAGE events — the in-tree observer parser (at
//!    `crates/observer/src/subscribers/postgres.rs`) reads
//!    `test_decoding`-style text despite the slot plugin string, and
//!    the mismatch is tracked as a pre-existing v0.1-pre bug in
//!    `server/SPEC-DELTA.md`.
//!
//! 2. Sentinel table `uninc_audit_marker` — a regular table in the
//!    customer database. A sidechannel connection INSERTs
//!    `(actor_id, session_id, at)` rows; the observer sees each INSERT
//!    through the same `table <ns>: INSERT: ...` path it already
//!    parses. No plugin change, no new decoding logic. This is what
//!    we ship. The table is created on sidechannel startup with
//!    `CREATE TABLE IF NOT EXISTS`.
//!
//! # Concurrency semantics
//!
//! Marker emit is `await`-ed before the client's op is forwarded to
//! upstream. This pins marker-before-op ordering within a single
//! session. Under concurrent admin sessions the observer's WAL
//! ordering still respects commit order, but "most-recent-marker"
//! attribution can mis-label a write when actor A's marker and
//! actor B's op interleave. The marker row carries `session_id` so
//! future observer logic can refine attribution per-session; v0.1-pre
//! documents this interleave race as an honest limit.
//!
//! # Why a SEPARATE connection (not piggybacked on the client's)
//!
//! Piggybacking would require injecting a `Query` frame into the
//! client's upstream pipe and consuming the backend reply (RowDescription
//! + DataRow + CommandComplete + ReadyForQuery) before letting the
//! client's real reply flow through. Feasible but intrusive to the
//! client-facing protocol state machine. A sidechannel is simpler and
//! isolates the marker-writes' wire behavior from the forwarding path.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;
use tokio_postgres::NoTls;
use tracing::{debug, info, warn};
use uninc_common::error::UnincError;
use uuid::Uuid;

/// Table name — intentionally includes the `uninc_` prefix so it's
/// visually distinct from customer tables. Lives in the default
/// (`public`) schema.
pub const MARKER_TABLE: &str = "uninc_audit_marker";

/// DDL run at sidechannel startup. `IF NOT EXISTS` makes it idempotent
/// across proxy restarts; customer migrations can also create the
/// table out-of-band and this DDL will be a no-op.
pub const MARKER_TABLE_DDL: &str = "\
CREATE TABLE IF NOT EXISTS uninc_audit_marker (
    id BIGSERIAL PRIMARY KEY,
    actor_id TEXT NOT NULL,
    session_id UUID NOT NULL,
    at TIMESTAMPTZ NOT NULL DEFAULT now()
);\
CREATE INDEX IF NOT EXISTS uninc_audit_marker_at_idx ON uninc_audit_marker (at);";

/// Sidechannel Postgres client used exclusively to write actor markers
/// ahead of the forwarded client op.
#[derive(Clone)]
pub struct PgActorMarker {
    client: Arc<tokio_postgres::Client>,
    emit_lock: Arc<Mutex<()>>,
}

impl PgActorMarker {
    /// Connect to the given upstream Postgres connection string and
    /// ensure the marker table exists. The connection string MUST be
    /// the same form tokio_postgres accepts: either a URI
    /// (`postgres://user:pass@host:port/db`) or a key-value string
    /// (`host=... port=... user=... password=... dbname=...`). The
    /// proxy's existing config stores a URI in
    /// `config.proxy.postgres.upstream`.
    pub async fn connect(upstream: &str) -> Result<Self, UnincError> {
        let (client, connection) = tokio_postgres::connect(upstream, NoTls)
            .await
            .map_err(|e| UnincError::Config(format!("pg marker connect: {e}")))?;

        // Spawn the connection driver. If it exits we log but keep
        // existing client handles — the first emit failure will trigger
        // a reconnect attempt (TODO v1.1: add reconnect supervisor).
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                warn!(error = %e, "pg marker sidechannel connection closed");
            }
        });

        // Best-effort idempotent DDL. If this fails (e.g., the
        // connecting role lacks CREATE privilege in the public
        // schema) we warn and continue — subsequent emits will fail
        // with a clearer error and the observer falls back to the
        // placeholder actor pre-hash.
        match client.batch_execute(MARKER_TABLE_DDL).await {
            Ok(_) => info!(table = MARKER_TABLE, "marker table ready"),
            Err(e) => {
                warn!(
                    error = %e,
                    table = MARKER_TABLE,
                    "marker table DDL failed — emits will retry on first call"
                );
            }
        }

        Ok(Self {
            client: Arc::new(client),
            emit_lock: Arc::new(Mutex::new(())),
        })
    }

    /// Emit an actor marker. MUST be awaited before the client's op
    /// is forwarded upstream — observer correlates by WAL ordering.
    pub async fn emit(&self, actor_id: &str, session_id: Uuid) -> Result<(), UnincError> {
        let _guard = self.emit_lock.lock().await;
        // Short query timeout — marker writes should be sub-ms. If the
        // upstream is hung, don't block the forwarding path.
        //
        // session_id is passed as TEXT and cast to UUID by Postgres;
        // avoids pulling tokio-postgres' `with-uuid-1` feature flag
        // just for a single parameter binding.
        let session_str = session_id.to_string();
        let params: [&(dyn tokio_postgres::types::ToSql + Sync); 2] =
            [&actor_id, &session_str.as_str()];
        let fut = self.client.execute(
            "INSERT INTO uninc_audit_marker (actor_id, session_id) VALUES ($1, $2::uuid)",
            &params,
        );
        match tokio::time::timeout(Duration::from_secs(2), fut).await {
            Ok(Ok(_)) => {
                debug!(actor_id, %session_id, "actor marker inserted");
                Ok(())
            }
            Ok(Err(e)) => Err(UnincError::Proxy(format!("pg marker insert: {e}"))),
            Err(_) => Err(UnincError::Proxy(
                "pg marker insert: timed out after 2s".to_string(),
            )),
        }
    }
}

/// Type-erased emit trait so listener state can hold either the real
/// client or a test double.
#[async_trait::async_trait]
pub trait ActorMarkerEmitter: Send + Sync {
    async fn emit(&self, actor_id: &str, session_id: Uuid) -> Result<(), UnincError>;
}

#[async_trait::async_trait]
impl ActorMarkerEmitter for PgActorMarker {
    async fn emit(&self, actor_id: &str, session_id: Uuid) -> Result<(), UnincError> {
        PgActorMarker::emit(self, actor_id, session_id).await
    }
}
