//! TCP listener for the Postgres wire-protocol proxy.
//!
//! Accepts incoming Postgres connections, reads the StartupMessage to classify
//! the connection, then either:
//! - **APP**: bidirectional byte forwarding with no parsing (minimal latency)
//! - **ADMIN**: full message parsing through the state machine with event emission

use std::net::IpAddr;
use std::sync::Arc;

use bytes::BytesMut;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info, warn};

use std::time::Duration;

use uninc_common::config::{
    IdentityConfig, PROXY_POSTGRES_PORT, SchemaConfig, TimeoutConfig,
};
use uninc_common::nats_client::NatsClient;
use uninc_common::types::{ConnectionClass, Protocol};

use crate::identity::classifier;
use crate::pool::ConnectionCap;
use crate::postgres::actor_marker::ActorMarkerEmitter;
use crate::postgres::connection::PostgresConnection;
use crate::postgres::wire::{self, FrontendMessage, InitialMessage};
use crate::rate_limit::RateLimiter;

/// Start the Postgres proxy listener.
///
/// Binds to the canonical Postgres proxy port [`PROXY_POSTGRES_PORT`] and
/// proxies connections to the upstream Postgres server. Each connection is
/// classified and either forwarded raw (APP) or parsed (ADMIN).
///
/// Concurrent-connection cap: items A.1 + D of the round-1 overload-protection
/// plan. The accept loop acquires a [`ConnectionPermit`] from a
/// [`ConnectionCap`] before spawning the per-connection task, failing fast
/// with a clear Postgres ErrorResponse if the cap is exhausted.
///
/// Rate limiting (item G): the [`RateLimiter`] is checked at accept time
/// (per-IP) and again after classification (per-admin-credential). Both
/// checks must pass or the connection is dropped with a Postgres
/// ErrorResponse.
pub async fn start_listener(
    upstream: &str,
    identity_config: IdentityConfig,
    schema_config: SchemaConfig,
    nats_client: Option<Arc<NatsClient>>,
    cap: ConnectionCap,
    timeout_config: TimeoutConfig,
    rate_limiter: Arc<RateLimiter>,
    verification_engine: Option<Arc<verification::VerificationEngine>>,
    marker: Option<Arc<dyn ActorMarkerEmitter>>,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(format!("0.0.0.0:{PROXY_POSTGRES_PORT}")).await?;
    info!(
        port = PROXY_POSTGRES_PORT,
        max_clients = cap.max(),
        admin_idle_secs = timeout_config.admin_idle_secs,
        app_idle_secs = timeout_config.app_idle_secs,
        rate_limit_enabled = rate_limiter.enabled(),
        "postgres proxy listening"
    );

    let upstream = upstream.to_string();
    let identity_config = Arc::new(identity_config);
    let schema_config = Arc::new(schema_config);
    let timeouts = Arc::new(timeout_config);

    loop {
        let (mut client_stream, client_addr) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                error!(error = %e, "failed to accept connection");
                continue;
            }
        };

        let source_ip_str = client_addr.ip().to_string();

        // Item G — per-IP rate limit check at accept time. Cheapest check
        // first: if the IP has exceeded its budget, reject before touching
        // the connection cap or opening an upstream.
        if !rate_limiter.check_ip(&source_ip_str) {
            warn!(
                source_ip = %source_ip_str,
                "postgres per-IP rate limit exceeded — rejecting"
            );
            let err = wire::encode_error_response(
                "53400",
                "rate limit exceeded for source IP",
            );
            let _ = client_stream.write_all(&err).await;
            let _ = client_stream.shutdown().await;
            continue;
        }

        // Items A.1 + D — fail-fast connection cap. Try to grab a permit
        // without blocking; if the cap is exhausted, send a clear Postgres
        // ErrorResponse and close the connection so the client library sees
        // "too_many_connections" rather than a silent hang.
        let permit = match cap.try_acquire() {
            Some(p) => p,
            None => {
                warn!(
                    source_ip = %source_ip_str,
                    max = cap.max(),
                    in_use = cap.in_use(),
                    "postgres connection cap exhausted — rejecting client"
                );
                let err = wire::encode_error_response(
                    "53300",
                    "too_many_connections: uninc-proxy connection cap exhausted",
                );
                let _ = client_stream.write_all(&err).await;
                let _ = client_stream.shutdown().await;
                continue;
            }
        };

        let upstream = upstream.clone();
        let identity_config = Arc::clone(&identity_config);
        let schema_config = Arc::clone(&schema_config);
        let nats = nats_client.as_ref().map(Arc::clone);
        let timeouts = Arc::clone(&timeouts);
        let rate_limiter = Arc::clone(&rate_limiter);
        let ve = verification_engine.clone();
        let marker = marker.clone();

        tokio::spawn(async move {
            // Move the permit into the per-connection task so it lives as
            // long as the connection does. Dropped on return → releases
            // semaphore and decrements in_use.
            let _permit = permit;
            let source_ip = client_addr.ip();
            debug!(%source_ip, "new postgres connection");

            if let Err(e) = handle_connection(
                client_stream,
                source_ip,
                &upstream,
                &identity_config,
                &schema_config,
                nats,
                &timeouts,
                &rate_limiter,
                ve,
                marker,
            )
            .await
            {
                warn!(%source_ip, error = %e, "connection error");
            }
        });
    }
}

/// Handle a single client connection end-to-end.
async fn handle_connection(
    mut client: TcpStream,
    source_ip: IpAddr,
    upstream_addr: &str,
    identity_config: &IdentityConfig,
    schema_config: &SchemaConfig,
    nats: Option<Arc<NatsClient>>,
    timeouts: &TimeoutConfig,
    rate_limiter: &RateLimiter,
    verification_engine: Option<Arc<verification::VerificationEngine>>,
    marker: Option<Arc<dyn ActorMarkerEmitter>>,
) -> anyhow::Result<()> {
    let mut buf = BytesMut::with_capacity(8192);

    // Step 1: Handle SSL negotiation.
    // Read the initial bytes to check for SSL request.
    loop {
        client.read_buf(&mut buf).await?;

        if buf.len() < 8 {
            continue;
        }

        let len = i32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        if buf.len() < len {
            continue;
        }

        let initial = wire::parse_initial_message(&buf[..len])?;
        match initial {
            InitialMessage::SslRequest => {
                // Deny SSL in V1 — respond with 'N'
                client.write_all(&wire::encode_ssl_deny()).await?;
                buf.clear();
                debug!("SSL request denied, waiting for startup");
                continue;
            }
            InitialMessage::Startup(startup_msg) => {
                buf.clear();
                return handle_startup(
                    client,
                    source_ip,
                    startup_msg,
                    upstream_addr,
                    identity_config,
                    schema_config,
                    nats,
                    timeouts,
                    rate_limiter,
                    verification_engine,
                    marker,
                )
                .await;
            }
            InitialMessage::CancelRequest { pid, secret } => {
                debug!(pid, secret, "cancel request — forwarding to upstream");
                // Forward cancel request directly to upstream and close
                if let Ok(mut upstream) = TcpStream::connect(upstream_addr).await {
                    let _ = upstream.write_all(&buf).await;
                }
                return Ok(());
            }
        }
    }
}

/// After receiving the StartupMessage, classify the connection and either
/// forward raw bytes (APP) or parse messages (ADMIN).
async fn handle_startup(
    mut client: TcpStream,
    source_ip: IpAddr,
    startup_msg: FrontendMessage,
    upstream_addr: &str,
    identity_config: &IdentityConfig,
    schema_config: &SchemaConfig,
    nats: Option<Arc<NatsClient>>,
    timeouts: &TimeoutConfig,
    rate_limiter: &RateLimiter,
    verification_engine: Option<Arc<verification::VerificationEngine>>,
    marker: Option<Arc<dyn ActorMarkerEmitter>>,
) -> anyhow::Result<()> {
    let (user, database, params) = match &startup_msg {
        FrontendMessage::StartupMessage {
            user,
            database,
            params,
        } => (user.clone(), database.clone(), params.clone()),
        _ => anyhow::bail!("expected StartupMessage"),
    };

    // Classify the connection based on username
    let class = classifier::classify(source_ip, &user, Protocol::Postgres, identity_config);

    info!(
        user = %user,
        database = %database,
        class = ?class,
        "postgres connection classified"
    );

    // Item G — per-credential rate limit. Checked AFTER classification so we
    // know the real admin username (not whatever the TCP peer IP happens to
    // be). Scope to admin/suspicious classes — APP connections are the
    // customer's own backend and are already bounded by the cap (item D)
    // plus the customer's own app-level pool.
    if matches!(class, ConnectionClass::Admin(_) | ConnectionClass::Suspicious(_))
        && !rate_limiter.check_credential(&user)
    {
        warn!(
            user = %user,
            "postgres per-credential rate limit exceeded — rejecting"
        );
        let err = wire::encode_error_response(
            "53400",
            "rate limit exceeded for admin credential",
        );
        let _ = client.write_all(&err).await;
        let _ = client.shutdown().await;
        return Ok(());
    }

    // Connect to upstream
    let mut upstream = TcpStream::connect(upstream_addr).await?;

    // Forward the startup message to upstream
    let startup_bytes = wire::encode_startup_message(&user, &database, &params);
    upstream.write_all(&startup_bytes).await?;

    // ALL connections go through the parsed path. Every query is logged.
    // The class (App / Admin / Suspicious) is a label on the chain entry,
    // not a gate that decides whether to log.
    {
        let class_label = match &class {
            ConnectionClass::App => "app",
            ConnectionClass::Admin(_) => "admin",
            ConnectionClass::Suspicious(_) => "suspicious",
        };
        debug!(class = class_label, "connection — parsing messages, logging all queries");

        let mut conn = PostgresConnection::new(source_ip, schema_config.clone());
        conn.set_class(class.clone());
        conn.handle_frontend_message(&startup_msg);

        // Register session with the verification engine (admin/suspicious only).
        let session_id = conn.session_id();
        if matches!(class, ConnectionClass::Admin(_) | ConnectionClass::Suspicious(_)) {
            if let Some(ref engine) = verification_engine {
                let admin_id = match &class {
                    ConnectionClass::Admin(id) => id.username.clone(),
                    ConnectionClass::Suspicious(msg) => format!("suspicious:{msg}"),
                    ConnectionClass::App => unreachable!(),
                };
                engine.start_session(session_id, admin_id).await;
            }
        }

        let result =
            proxy_admin_connection(client, upstream, &mut conn, nats, timeouts, marker).await;

        // End session on disconnect (admin/suspicious only).
        if matches!(class, ConnectionClass::Admin(_) | ConnectionClass::Suspicious(_)) {
            if let Some(ref engine) = verification_engine {
                let vr = engine.end_session(&session_id).await;
                match vr {
                    verification::VerificationResult::Failed { ref reason } => {
                        error!(
                            %session_id,
                            %reason,
                            "session verification FAILED"
                        );
                    }
                    verification::VerificationResult::Passed => {
                        debug!(%session_id, "session verification passed");
                    }
                    verification::VerificationResult::Pending => {
                        debug!(%session_id, "session verification deferred");
                    }
                }
            }
        }

        result
    }
}

/// Proxy an admin connection: read messages from both sides, parse them
/// through the connection state machine, forward them, and emit events.
///
/// **Log-before-access invariant.** Every admin frontend message that would
/// generate a chain event is published to NATS *synchronously* (with a bounded
/// timeout) before its bytes are forwarded upstream. If the publish fails or
/// times out, this function returns an error — which drops the client TCP
/// connection — and the message is **never** forwarded to the real database.
/// This is item C of the round-1 overload-protection plan; see
/// ARCHITECTURE.md §"Capacity & overload protection" → "The trust-story
/// invariant" for the full reasoning.
///
/// **Idle timeout (item B).** The outer select is wrapped in a
/// `tokio::time::timeout` equal to `timeouts.admin_idle_secs`. If NEITHER the
/// client nor the upstream produces data within that window, the connection
/// is dropped. This bounds the cascading-failure mode where a slow upstream
/// query ties up a worker task forever. Postgres's `statement_timeout` in
/// `startup-db.sh` is the Layer-4 backstop that kills the actual query
/// server-side when this proxy-level timeout fires.
async fn proxy_admin_connection(
    mut client: TcpStream,
    mut upstream: TcpStream,
    conn: &mut PostgresConnection,
    nats: Option<Arc<NatsClient>>,
    timeouts: &TimeoutConfig,
    marker: Option<Arc<dyn ActorMarkerEmitter>>,
) -> anyhow::Result<()> {
    let mut client_buf = BytesMut::with_capacity(8192);
    let mut upstream_buf = BytesMut::with_capacity(8192);
    let idle = Duration::from_secs(timeouts.admin_idle_secs);

    loop {
        tokio::select! {
            // Item B — idle timeout branch. If NEITHER client nor upstream
            // produces data within `admin_idle_secs`, the connection is
            // considered wedged (slow query, dead peer, hung upstream) and
            // dropped. Postgres's `statement_timeout` backstops this at the
            // DB layer via `startup-db.sh`.
            _ = tokio::time::sleep(idle) => {
                warn!(
                    idle_secs = timeouts.admin_idle_secs,
                    "admin connection idle timeout — dropping (slow query or dead peer)"
                );
                return Ok(());
            }

            // Data from client -> parse -> forward to upstream
            n = client.read_buf(&mut client_buf) => {
                let n = n?;
                if n == 0 {
                    debug!("client disconnected");
                    return Ok(());
                }

                // Process all complete messages in the buffer
                while let Some(msg_len) = wire::frame_length(&client_buf, false) {
                    let msg_bytes = client_buf.split_to(msg_len);

                    match wire::parse_frontend_message(&msg_bytes) {
                        Ok(msg) => {
                            if let Some(event) = conn.handle_frontend_message(&msg) {
                                // ACTOR-MARKER INJECTION — spec §5.5
                                // byte-identity support. Before the
                                // log-before-access NATS gate we write an
                                // actor-marker row to uninc_audit_marker
                                // via the sidechannel. The WAL records
                                // this INSERT ahead of the forwarded
                                // client op, so the observer's pgoutput
                                // reader can attribute the next real
                                // INSERT/UPDATE/DELETE to this actor.
                                // Marker-emit failure is WARN (not fail-
                                // closed): the real op still forwards;
                                // the observer's actor_id_hash falls
                                // back to a placeholder that won't
                                // byte-match. See
                                // `crate::postgres::actor_marker`.
                                if let (Some(marker), Some(ConnectionClass::Admin(id))) =
                                    (marker.as_ref(), conn.class())
                                {
                                    if let Err(e) = marker
                                        .emit(&id.username, conn.session_id())
                                        .await
                                    {
                                        warn!(
                                            error = %e,
                                            session_id = %conn.session_id(),
                                            "pg actor marker emit failed — observer \
                                             attribution will fall back to placeholder"
                                        );
                                    }
                                }

                                // LOG-BEFORE-ACCESS GATE — see the doc comment
                                // on proxy_admin_connection above. This await
                                // blocks until NATS has acked the publish (or
                                // the timeout fires). On error, we return `?`
                                // BEFORE the upstream.write_all below, so the
                                // query never reaches the database.
                                emit_event(&nats, event).await?;
                            }

                            if matches!(msg, FrontendMessage::Terminate) {
                                // Forward terminate and close
                                let _ = upstream.write_all(&msg_bytes).await;
                                return Ok(());
                            }
                        }
                        Err(e) => {
                            warn!(error = %e, "failed to parse frontend message");
                        }
                    }

                    // Forward the raw bytes to upstream
                    upstream.write_all(&msg_bytes).await?;
                }
            }

            // Data from upstream -> parse -> forward to client
            n = upstream.read_buf(&mut upstream_buf) => {
                let n = n?;
                if n == 0 {
                    debug!("upstream disconnected");
                    return Ok(());
                }

                // Process all complete messages in the buffer
                while let Some(msg_len) = wire::frame_length(&upstream_buf, false) {
                    let msg_bytes = upstream_buf.split_to(msg_len);

                    match wire::parse_backend_message(&msg_bytes) {
                        Ok(msg) => {
                            conn.handle_backend_message(&msg);
                        }
                        Err(e) => {
                            warn!(error = %e, "failed to parse backend message");
                        }
                    }

                    // Forward to client
                    client.write_all(&msg_bytes).await?;
                }
            }
        }
    }
}

/// Emit an access event to NATS — **synchronous, fail-closed**.
///
/// This is the log-before-access gate. Returns `Ok(())` only after NATS has
/// acknowledged the publish (durably persisted in JetStream). Callers MUST
/// propagate the error before forwarding the query upstream; otherwise the
/// proxy violates the trust-story invariant that every data access has a
/// chain entry.
///
/// # Timeout
///
/// Defaults to 500ms per publish. Override via `UNINC_AUDIT_PUBLISH_TIMEOUT_MS`.
/// On timeout, returns an error and the caller drops the client connection.
///
/// # When `nats` is `None`
///
/// In production `nats` is always `Some` (see `main.rs`). The `None` branch
/// exists for unit tests and developer-convenience stacks where NATS is not
/// wired up. It logs a warning and returns `Ok(())` so tests don't have to
/// stand up a NATS broker. **Never deploy a production proxy with `nats =
/// None`** — doing so silently disables the audit trail.
async fn emit_event(
    nats: &Option<Arc<NatsClient>>,
    event: uninc_common::types::AccessEvent,
) -> anyhow::Result<()> {
    // NOTE: we no longer skip events with empty affected_users.
    // publish_for_affected_users() always publishes to the deployment chain first
    // (uninc.access._deployment), then to each per-user chain. The deployment chain gets
    // EVERY admin operation, closing the audit gap for DDL, utility queries,
    // and cross-table scans that don't map to specific users.
    if event.affected_users.is_empty() {
        debug!(
            resource = %event.resource,
            action = %event.action,
            "access event with no affected users — publishing to deployment chain only"
        );
    }

    let Some(nats) = nats else {
        warn!("NATS not configured — access event not published (dev/test stack only, NEVER deploy to prod without NATS)");
        return Ok(());
    };

    let timeout_ms: u64 = std::env::var("UNINC_AUDIT_PUBLISH_TIMEOUT_MS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(500);

    match tokio::time::timeout(
        std::time::Duration::from_millis(timeout_ms),
        nats.publish_for_affected_users(&event),
    )
    .await
    {
        Ok(Ok(())) => {
            info!(
                affected_users = ?event.affected_users,
                action = %event.action,
                resource = %event.resource,
                "postgres access event published (log-before-access gate satisfied)"
            );
            Ok(())
        }
        Ok(Err(e)) => {
            error!(
                error = %e,
                affected_users = ?event.affected_users,
                action = %event.action,
                resource = %event.resource,
                "NATS publish failed — FAIL-CLOSED: dropping client connection, query NOT forwarded"
            );
            Err(anyhow::anyhow!(
                "audit pipeline unavailable: {e} (fail-closed — see ARCHITECTURE.md §'Capacity & overload protection' → 'The trust-story invariant')"
            ))
        }
        Err(_elapsed) => {
            error!(
                timeout_ms,
                affected_users = ?event.affected_users,
                action = %event.action,
                resource = %event.resource,
                "NATS publish timed out — FAIL-CLOSED: dropping client connection, query NOT forwarded"
            );
            Err(anyhow::anyhow!(
                "audit pipeline timed out after {timeout_ms}ms (fail-closed — override via UNINC_AUDIT_PUBLISH_TIMEOUT_MS)"
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Listener tests are integration-level and require a running Postgres + NATS.
    // Here we test the helper logic that doesn't require network.

    #[test]
    fn ssl_deny_is_single_byte_n() {
        let deny = wire::encode_ssl_deny();
        assert_eq!(deny.as_ref(), &[b'N']);
    }

    #[test]
    fn startup_encodes_correctly() {
        let mut params = std::collections::HashMap::new();
        params.insert("application_name".to_string(), "test".to_string());
        let bytes = wire::encode_startup_message("user1", "db1", &params);

        // Should be parseable
        let msg = wire::parse_initial_message(&bytes).unwrap();
        match msg {
            InitialMessage::Startup(FrontendMessage::StartupMessage {
                user, database, ..
            }) => {
                assert_eq!(user, "user1");
                assert_eq!(database, "db1");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }
}
