//! S3 HTTP server — starts the axum listener and routes all traffic
//! to the S3 request handler.

use std::sync::Arc;

use axum::Router;
use tokio::net::TcpListener;
use tracing::{error, info};

use uninc_common::config::{IdentityConfig, PROXY_S3_PORT, S3Config};
use uninc_common::error::UnincError;
use uninc_common::nats_client::NatsClient;

use crate::pool::ConnectionCap;
use crate::rate_limit::RateLimiter;

use super::handler::{handle_s3_request, S3ProxyState};

/// Start the S3 proxy HTTP server.
///
/// Listens on the canonical S3 proxy port [`PROXY_S3_PORT`] and forwards all
/// requests to the configured upstream S3 endpoint.
///
/// Concurrent-request cap: items A.1 + D of the round-1 overload-protection
/// plan. The [`S3ProxyState`] holds a [`ConnectionCap`] used by the handler
/// to fail-fast with a 503 when the in-flight request count hits the limit.
/// The cap is per-request rather than per-TCP-connection because HTTP
/// keep-alive decouples the two.
///
/// This function runs until the server is shut down (e.g., via signal).
pub async fn start(
    s3_config: S3Config,
    identity_config: IdentityConfig,
    nats: Option<Arc<NatsClient>>,
    cap: ConnectionCap,
    rate_limiter: Arc<RateLimiter>,
) -> Result<(), UnincError> {
    let upstream = s3_config.upstream.clone();
    let max = cap.max();

    let state = Arc::new(S3ProxyState::new(
        s3_config,
        identity_config,
        nats,
        cap,
        rate_limiter,
    ));

    // Route ALL methods and paths to the handler — the S3 proxy is transparent.
    let app = Router::new()
        .fallback(handle_s3_request)
        .with_state(state);

    let bind_addr = format!("0.0.0.0:{PROXY_S3_PORT}");
    let listener = TcpListener::bind(&bind_addr)
        .await
        .map_err(|e| UnincError::Proxy(format!("failed to bind S3 listener on {bind_addr}: {e}")))?;

    info!(
        port = PROXY_S3_PORT,
        upstream = %upstream,
        max_clients = max,
        "S3 proxy listening"
    );

    axum::serve(listener, app)
        .await
        .map_err(|e| {
            error!(error = %e, "S3 proxy server error");
            UnincError::Proxy(format!("S3 server error: {e}"))
        })?;

    Ok(())
}
