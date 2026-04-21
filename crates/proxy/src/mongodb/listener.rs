//! MongoDB TCP listener.
//!
//! Accepts incoming connections on the configured port, reads MongoDB wire
//! protocol messages, classifies connections via the SCRAM handshake, and
//! either forwards transparently (APP) or intercepts and emits access events
//! (ADMIN).

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info, warn};

use uninc_common::config::{
    IdentityConfig, PROXY_MONGODB_PORT, ProtocolListenerConfig, SchemaConfig,
};
use uninc_common::error::UnincError;
use uninc_common::nats_client::NatsClient;
use uninc_common::types::ConnectionClass;

use crate::mongodb::actor_marker::ActorMarkerEmitter;
use crate::mongodb::connection::{mark_authenticated, MongoConnection, MongoConnectionState};
use crate::mongodb::wire::{self, HEADER_SIZE, MAX_MSG_SIZE};
use crate::pool::ConnectionCap;
use crate::rate_limit::RateLimiter;

// ---------------------------------------------------------------------------
// Listener configuration
// ---------------------------------------------------------------------------

/// Shared state for the MongoDB listener, passed into each connection task.
pub struct MongoListenerState {
    pub listener_config: ProtocolListenerConfig,
    pub identity_config: IdentityConfig,
    pub schema_config: SchemaConfig,
    pub nats: Arc<NatsClient>,
    /// Items A.1 + D — shared connection cap. Created in `main.rs` so the
    /// same cap can be registered with `HealthState` for the `/health`
    /// endpoint (item E).
    pub cap: ConnectionCap,
    /// Item G — rate limiter, shared across all connections to this listener.
    pub rate_limiter: Arc<RateLimiter>,
    /// Actor-marker sidechannel (spec §5.5 byte-identity support).
    /// `None` in dev/test stacks where the sidechannel can't be
    /// constructed; production stacks MUST have this wired or observer
    /// byte-identity fails open (observer records a placeholder
    /// actor_id_hash that won't match the proxy's projection). See
    /// `crate::mongodb::actor_marker` for the semantic contract.
    pub marker: Option<Arc<dyn ActorMarkerEmitter>>,
}

// ---------------------------------------------------------------------------
// Listener entry point
// ---------------------------------------------------------------------------

/// Start the MongoDB proxy listener.
///
/// Binds to the canonical MongoDB proxy port [`PROXY_MONGODB_PORT`] and
/// spawns a task per connection.
///
/// Concurrent-connection cap: items A.1 + D of the round-1 overload-protection
/// plan. The accept loop acquires a [`ConnectionPermit`] from a
/// [`ConnectionCap`] before spawning the per-connection task, failing fast by
/// closing the socket if the cap is exhausted.
pub async fn start(state: Arc<MongoListenerState>) -> Result<(), UnincError> {
    let addr: SocketAddr = format!("0.0.0.0:{PROXY_MONGODB_PORT}")
        .parse()
        .map_err(|e| UnincError::Config(format!("invalid listen address: {e}")))?;

    let listener = TcpListener::bind(addr)
        .await
        .map_err(|e| UnincError::Proxy(format!("failed to bind {addr}: {e}")))?;

    info!(
        %addr,
        max_clients = state.cap.max(),
        "MongoDB proxy listener started"
    );

    loop {
        let (mut client_stream, peer_addr) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                error!("failed to accept connection: {e}");
                continue;
            }
        };

        // Item G — per-IP rate limit at accept time. MongoDB has no protocol
        // error frame before handshake; on rate-limit violation we just drop
        // the TCP connection.
        if !state.rate_limiter.check_ip(&peer_addr.ip().to_string()) {
            warn!(
                %peer_addr,
                "mongodb per-IP rate limit exceeded — dropping"
            );
            let _ = client_stream.shutdown().await;
            continue;
        }

        // Items A.1 + D — fail-fast connection cap. MongoDB's wire protocol
        // has no clean "server error before handshake" frame, so we just
        // shutdown the socket when exhausted. Mongo drivers retry on TCP
        // errors with backoff.
        let permit = match state.cap.try_acquire() {
            Some(p) => p,
            None => {
                warn!(
                    %peer_addr,
                    max = state.cap.max(),
                    in_use = state.cap.in_use(),
                    "mongodb connection cap exhausted — rejecting client (TCP close)"
                );
                let _ = client_stream.shutdown().await;
                continue;
            }
        };

        let state = Arc::clone(&state);
        tokio::spawn(async move {
            // Move the permit into the per-connection task — dropped on
            // return, releasing the semaphore.
            let _permit = permit;
            if let Err(e) = handle_connection(client_stream, peer_addr, state).await {
                warn!(%peer_addr, error = %e, "connection handler error");
            }
        });
    }
}

// ---------------------------------------------------------------------------
// Per-connection handler
// ---------------------------------------------------------------------------

/// Handle a single MongoDB client connection.
///
/// 1. Connect to the upstream MongoDB server.
/// 2. Forward the handshake and authentication transparently (both sides
///    need to see the SCRAM exchange).
/// 3. After auth completes, classify the connection.
/// 4. APP: bidirectional raw byte forwarding.
/// 5. ADMIN: parse each OP_MSG from the client, forward it, then emit events.
async fn handle_connection(
    mut client: TcpStream,
    peer_addr: SocketAddr,
    state: Arc<MongoListenerState>,
) -> Result<(), UnincError> {
    let source_ip = peer_addr.ip();
    info!(%peer_addr, "new MongoDB connection");

    // Connect to upstream.
    let mut upstream = TcpStream::connect(&state.listener_config.upstream)
        .await
        .map_err(|e| {
            UnincError::UpstreamConnection(format!(
                "failed to connect to {}: {e}",
                state.listener_config.upstream
            ))
        })?;

    debug!(%peer_addr, upstream = %state.listener_config.upstream, "connected to upstream");

    let mut conn = MongoConnection::new(
        source_ip,
        state.identity_config.clone(),
        state.schema_config.clone(),
    );

    // Phase 1: Forward handshake and authentication transparently.
    // We read from the client, inspect the message, forward to upstream,
    // then read the upstream response and forward back to the client.
    loop {
        if *conn.state() == MongoConnectionState::Ready {
            break;
        }
        if *conn.state() == MongoConnectionState::Terminated {
            return Ok(());
        }

        // Read a message from the client.
        let (client_read, client_write) = client.split();
        let (upstream_read, upstream_write) = upstream.split();
        drop(client_read);
        drop(client_write);
        drop(upstream_read);
        drop(upstream_write);

        let raw_msg = read_raw_message(&mut client).await?;

        // Inspect if it is OP_MSG for state tracking.
        if let Ok(op_msg) = wire::parse_op_msg(&raw_msg) {
            conn.handle_client_message(&op_msg);
        }

        // Forward the raw bytes to upstream.
        upstream.write_all(&raw_msg).await.map_err(|e| {
            UnincError::Proxy(format!("failed to forward to upstream: {e}"))
        })?;

        // Read the upstream response and forward to client.
        let response = read_raw_message(&mut upstream).await?;

        // Check if the response indicates auth success for saslContinue.
        if let Ok(resp_msg) = wire::parse_op_msg(&response) {
            // If the response has "done": true, authentication is complete.
            if resp_msg.body.get_bool("done").unwrap_or(false) {
                debug!("SCRAM authentication completed (done=true)");
                mark_authenticated(&mut conn);
            }
        }

        client.write_all(&response).await.map_err(|e| {
            UnincError::Proxy(format!("failed to forward response to client: {e}"))
        })?;
    }

    // Phase 2: ALL connections go through the parsed/logged path.
    // The class (App/Admin/Suspicious) is a label, not a gate.
    match conn.class() {
        Some(ConnectionClass::Suspicious(reason)) => {
            warn!(%peer_addr, reason, "suspicious connection — logging then dropping");
            let _ = client.shutdown().await;
            Ok(())
        }
        Some(ConnectionClass::Admin(id)) => {
            info!(%peer_addr, user = %id.username, "ADMIN connection — intercepting commands");
            if !state.rate_limiter.check_credential(&id.username) {
                warn!(
                    %peer_addr,
                    user = %id.username,
                    "mongodb per-credential rate limit exceeded — dropping session"
                );
                let _ = client.shutdown().await;
                return Ok(());
            }
            handle_admin_session(&mut client, &mut upstream, &mut conn, &state).await
        }
        Some(ConnectionClass::App) => {
            let username = conn.username().unwrap_or("app").to_string();
            info!(%peer_addr, user = %username, "APP connection — intercepting commands (logging all queries)");
            // App connections go through the same parsed path as admin.
            // The class label distinguishes them in chain entries.
            handle_admin_session(&mut client, &mut upstream, &mut conn, &state).await
        }
        None => {
            warn!(%peer_addr, "connection classified as None — dropping");
            Ok(())
        }
    }
}

/// Handle an admin session: intercept each OP_MSG, forward, emit events.
///
/// Item B (idle timeout). Each client read and upstream read is wrapped in
/// `tokio::time::timeout(admin_idle_secs)`. If either side fails to produce a
/// message within that window, the connection is dropped and MongoDB's server
/// side eventually reaps the orphaned cursor. Default 30s.
async fn handle_admin_session(
    client: &mut TcpStream,
    upstream: &mut TcpStream,
    conn: &mut MongoConnection,
    state: &MongoListenerState,
) -> Result<(), UnincError> {
    let idle = std::time::Duration::from_secs(
        state.listener_config.timeouts.admin_idle_secs,
    );
    loop {
        // Read a message from the client (item B — idle-bounded).
        let raw_msg = match tokio::time::timeout(idle, read_raw_message(client)).await {
            Ok(Ok(msg)) => msg,
            Ok(Err(_)) => {
                debug!(session_id = %conn.session_id(), "client disconnected");
                conn.terminate();
                return Ok(());
            }
            Err(_elapsed) => {
                warn!(
                    session_id = %conn.session_id(),
                    idle_secs = state.listener_config.timeouts.admin_idle_secs,
                    "mongodb admin client idle timeout — dropping"
                );
                conn.terminate();
                return Ok(());
            }
        };

        // LOG-BEFORE-ACCESS GATE — item C of the round-1 overload-protection
        // plan. See postgres/listener.rs::emit_event and ARCHITECTURE.md
        // §"Capacity & overload protection" → "The trust-story invariant"
        // for the full reasoning. The NATS publish is synchronous and
        // fail-closed: if the publish fails or times out, we return an
        // error from this function, which drops the client connection via
        // the outer handler, BEFORE the upstream.write_all call below.
        if let Ok(op_msg) = wire::parse_op_msg(&raw_msg) {
            // ACTOR-MARKER INJECTION — spec §5.5 byte-identity support.
            // Before the log-before-access NATS gate we write an actor
            // marker to `_uninc_marker.events` via the sidechannel. The
            // observer's change stream sees this insert and correlates
            // it with the real op that follows in the oplog. Marker-
            // emit failure is WARN (not fail-closed): the real op still
            // forwards, but the observer's actor_id_hash will be a
            // placeholder that won't byte-match the proxy projection.
            // Operators see this as a §5.5 divergence at scheduled
            // verification time, which is a legitimate signal.
            if let (Some(marker), Some(ConnectionClass::Admin(id))) =
                (state.marker.as_ref(), conn.class())
            {
                if is_marker_worthy(&op_msg) {
                    if let Err(e) = marker.emit(&id.username, conn.session_id()).await {
                        warn!(
                            error = %e,
                            session_id = %conn.session_id(),
                            "actor marker emit failed — observer attribution will fall back to placeholder"
                        );
                    }
                }
            }

            if let Some(event) = conn.handle_client_message(&op_msg) {
                let timeout_ms: u64 = std::env::var("UNINC_AUDIT_PUBLISH_TIMEOUT_MS")
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(500);
                match tokio::time::timeout(
                    std::time::Duration::from_millis(timeout_ms),
                    state.nats.publish_for_affected_users(&event),
                )
                .await
                {
                    Ok(Ok(())) => {
                        debug!(
                            action = %event.action,
                            resource = %event.resource,
                            "mongodb access event published (log-before-access gate satisfied)"
                        );
                    }
                    Ok(Err(e)) => {
                        error!(
                            error = %e,
                            "NATS publish failed — FAIL-CLOSED: dropping client connection, mongodb op NOT forwarded"
                        );
                        conn.terminate();
                        return Err(UnincError::Proxy(format!(
                            "audit pipeline unavailable: {e} (fail-closed — see ARCHITECTURE.md §'Capacity & overload protection')"
                        )));
                    }
                    Err(_elapsed) => {
                        error!(
                            timeout_ms,
                            "NATS publish timed out — FAIL-CLOSED: dropping client connection, mongodb op NOT forwarded"
                        );
                        conn.terminate();
                        return Err(UnincError::Proxy(format!(
                            "audit pipeline timed out after {timeout_ms}ms (fail-closed)"
                        )));
                    }
                }
            }
        }

        // Forward raw bytes to upstream.
        upstream.write_all(&raw_msg).await.map_err(|e| {
            UnincError::Proxy(format!("failed to forward to upstream: {e}"))
        })?;

        // Read upstream response and forward to client (item B — idle-bounded).
        // This branch is the classic "slow query" failure mode: client sent
        // a command, we forwarded, now we wait for mongod. If mongod hangs,
        // timeout and drop rather than wedge the task forever.
        let response = match tokio::time::timeout(idle, read_raw_message(upstream)).await {
            Ok(Ok(msg)) => msg,
            Ok(Err(_)) => {
                debug!(session_id = %conn.session_id(), "upstream disconnected");
                conn.terminate();
                return Ok(());
            }
            Err(_elapsed) => {
                warn!(
                    session_id = %conn.session_id(),
                    idle_secs = state.listener_config.timeouts.admin_idle_secs,
                    "mongodb upstream reply idle timeout — dropping (slow query)"
                );
                conn.terminate();
                return Ok(());
            }
        };

        client.write_all(&response).await.map_err(|e| {
            UnincError::Proxy(format!("failed to forward response to client: {e}"))
        })?;
    }
}

// ---------------------------------------------------------------------------
// Raw message reading
// ---------------------------------------------------------------------------

/// Read a complete MongoDB wire protocol message as raw bytes.
///
/// Returns the full message including the header, suitable for forwarding.
async fn read_raw_message(stream: &mut TcpStream) -> Result<Vec<u8>, UnincError> {
    use tokio::io::AsyncReadExt;

    // Read the first 4 bytes to get message length.
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await.map_err(|e| {
        UnincError::ProtocolParse(format!("failed to read message length: {e}"))
    })?;
    let message_length = i32::from_le_bytes(len_buf) as usize;

    if message_length < HEADER_SIZE {
        return Err(UnincError::ProtocolParse(format!(
            "invalid message length: {message_length}"
        )));
    }
    if message_length > MAX_MSG_SIZE {
        return Err(UnincError::ProtocolParse(format!(
            "message too large: {message_length}"
        )));
    }

    let mut buf = vec![0u8; message_length];
    buf[..4].copy_from_slice(&len_buf);

    stream.read_exact(&mut buf[4..]).await.map_err(|e| {
        UnincError::ProtocolParse(format!("failed to read message body: {e}"))
    })?;

    Ok(buf)
}

/// Classify whether a MongoDB OP_MSG is worth emitting an actor marker
/// for. Returns true for DML verbs that §4.12 and the observer's change
/// stream can witness — insert / update / delete / findAndModify /
/// replace. Returns false for reads (find/aggregate/count) and control
/// verbs (hello/ping/isMaster/etc.) so we don't amplify marker writes
/// for events the observer won't record anyway.
///
/// Rationale: the observer-side change stream (per
/// [Change Events](https://www.mongodb.com/docs/manual/reference/change-events/))
/// emits events for document mutations and collection lifecycle
/// changes. Read operations and handshake commands do NOT produce
/// oplog entries and so never reach the observer — attaching a marker
/// to them wastes a round-trip and pollutes `_uninc_marker.events`.
fn is_marker_worthy(op_msg: &wire::OpMsg) -> bool {
    let Some((cmd_name, _)) = op_msg.body.iter().next() else {
        return false;
    };
    matches!(
        cmd_name.as_str(),
        "insert"
            | "update"
            | "delete"
            | "findAndModify"
            | "findandmodify"
            | "drop"
            | "dropDatabase"
            | "create"
            | "createIndexes"
            | "dropIndexes"
            | "renameCollection"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listener_state_can_be_constructed() {
        // Smoke test that the types compose.
        // We cannot actually start the listener in a unit test (needs NATS),
        // but we verify the types are well-formed.
        let _config = ProtocolListenerConfig {
            enabled: true,
            upstream: "mongodb://localhost:27017".to_string(),
            pool: Default::default(),
            timeouts: Default::default(),
            rate_limit: Default::default(),
        };
    }
}
