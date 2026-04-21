//! S3 request handler — the core axum handler that classifies, forwards,
//! and optionally logs S3 requests.

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, Response, StatusCode, Uri};
use chrono::Utc;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use uninc_common::config::{IdentityConfig, S3Config};
use uninc_common::nats_client::NatsClient;
use uninc_common::types::{AccessEvent, ActionType, ConnectionClass, Protocol};

use crate::identity::classifier;
use crate::pool::ConnectionCap;
use crate::rate_limit::RateLimiter;
use crate::s3::auth;
use crate::s3::fingerprint;
use crate::s3::resolver::{self, CompiledPattern};

/// Shared state passed to the axum handler.
pub struct S3ProxyState {
    /// The upstream S3 endpoint to forward requests to.
    pub upstream: String,
    /// Hyper HTTP client for forwarding.
    pub client: Client<hyper_util::client::legacy::connect::HttpConnector, Body>,
    /// NATS client for publishing access events.
    pub nats: Option<Arc<NatsClient>>,
    /// Identity classification config.
    pub identity_config: IdentityConfig,
    /// S3-specific config.
    pub s3_config: S3Config,
    /// Compiled user-data patterns.
    pub patterns: Vec<CompiledPattern>,
    /// Items A.1 + D — per-request concurrency cap. See ARCHITECTURE.md
    /// §"Capacity & overload protection" layer 1.
    pub cap: ConnectionCap,
    /// Item G — per-IP / per-access-key rate limiter.
    pub rate_limiter: Arc<RateLimiter>,
}

impl S3ProxyState {
    /// Create a new S3ProxyState from config.
    pub fn new(
        s3_config: S3Config,
        identity_config: IdentityConfig,
        nats: Option<Arc<NatsClient>>,
        cap: ConnectionCap,
        rate_limiter: Arc<RateLimiter>,
    ) -> Self {
        let patterns = resolver::compile_patterns(&s3_config.user_data_patterns);
        let client = Client::builder(TokioExecutor::new()).build_http();

        Self {
            upstream: s3_config.upstream.clone(),
            client,
            nats,
            identity_config,
            s3_config,
            patterns,
            cap,
            rate_limiter,
        }
    }
}

/// The main S3 proxy handler. All requests are routed here.
///
/// Order of operations (**log-before-access invariant**, item C of round-1
/// overload protection — see ARCHITECTURE.md §"Capacity & overload protection"
/// → "The trust-story invariant"):
///
/// 1. Extract credential from Authorization header (or presigned URL query)
/// 2. Classify as APP or ADMIN
/// 3. **If ADMIN and the resource has affected users:** build the event,
///    publish to NATS **synchronously with a bounded timeout, fail-closed**.
///    If the publish fails, return 503 and DO NOT forward the request upstream.
/// 4. Forward the request to upstream S3
/// 5. Return the response
pub async fn handle_s3_request(
    State(state): State<Arc<S3ProxyState>>,
    req: Request<Body>,
) -> Response<Body> {
    // Items A.1 + D — per-request concurrency cap. Check BEFORE doing any
    // parse or forward work, so cap exhaustion has minimal cost. The permit
    // is held for the rest of this function via the local `_permit` binding
    // and released on return.
    let _permit = match state.cap.try_acquire() {
        Some(p) => p,
        None => {
            warn!(
                max = state.cap.max(),
                in_use = state.cap.in_use(),
                "s3 connection cap exhausted — returning 503"
            );
            return Response::builder()
                .status(StatusCode::SERVICE_UNAVAILABLE)
                .header("content-type", "application/xml")
                .header("retry-after", "5")
                .body(Body::from(
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>SlowDown</Code><Message>uninc-proxy connection cap exhausted</Message></Error>"
                ))
                .unwrap();
        }
    };

    let method = req.method().clone();
    let uri = req.uri().clone();
    let headers = req.headers().clone();

    // Extract source IP from headers or connection info
    let source_ip = extract_source_ip(&headers).unwrap_or("0.0.0.0".parse().unwrap());

    // Extract credential (access key ID) from Authorization header or query string
    let credential = extract_credential(&headers, uri.query());

    // Item G — rate limiting. Per-IP and (when available) per-credential
    // token bucket. 503 SlowDown response if exceeded — same as
    // cap-exhaustion so S3 clients handle both via the same retry path.
    if !state.rate_limiter.check_ip(&source_ip.to_string()) {
        warn!(%source_ip, "s3 per-IP rate limit exceeded");
        return Response::builder()
            .status(StatusCode::SERVICE_UNAVAILABLE)
            .header("content-type", "application/xml")
            .header("retry-after", "1")
            .body(Body::from(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>SlowDown</Code><Message>rate limit exceeded for source IP</Message></Error>"
            ))
            .unwrap();
    }
    if let Some(ref cred) = credential {
        if !state.rate_limiter.check_credential(cred) {
            warn!(credential = %cred, "s3 per-credential rate limit exceeded");
            return Response::builder()
                .status(StatusCode::SERVICE_UNAVAILABLE)
                .header("content-type", "application/xml")
                .header("retry-after", "1")
                .body(Body::from(
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>SlowDown</Code><Message>rate limit exceeded for access key</Message></Error>"
                ))
                .unwrap();
        }
    }

    // Classify the connection
    let class = classifier::classify(
        source_ip,
        credential.as_deref().unwrap_or("unknown"),
        Protocol::S3,
        &state.identity_config,
    );

    debug!(
        %method,
        %uri,
        ?class,
        "S3 request classified"
    );

    // Parse bucket and key from path
    let (bucket, key) = parse_bucket_key(uri.path());

    // Check for multipart upload handling
    let is_complete_multipart = method == "POST"
        && uri
            .query()
            .is_some_and(|q| q.contains("uploadId"));
    let is_initiate_multipart = method == "POST"
        && uri.query().is_some_and(|q| q.contains("uploads"));

    // If configured to only log on CompleteMultipartUpload, skip InitiateMultipartUpload
    // (InitiateMultipartUpload just returns an upload ID; no user data is touched.)
    if state.s3_config.multipart_log_on_complete_only && is_initiate_multipart {
        debug!("skipping log for InitiateMultipartUpload (will log on complete)");
        // InitiateMultipartUpload carries no object body and generates
        // no MinIO bucket notification on completion of *this* request,
        // so there is no observer-visible event and no need to attach
        // an actor marker. CompleteMultipartUpload (POST with uploadId
        // in query) takes the normal path below where the marker IS
        // attached.
        return forward_request(&state, req, None).await;
    }

    // ALL connections go through the audit gate — app and admin alike.
    // The class is a label on the chain entry, not a skip gate.

    // LOG-BEFORE-ACCESS gate — all connections (app, admin, suspicious).
    {
        let action = method_to_action(&method, is_complete_multipart, uri.query());

        // Check for presigned URL generation
        let is_presigned = uri.query().is_some_and(|q| {
            q.contains("X-Amz-Algorithm") || q.contains("X-Amz-Credential")
        });
        let action = if is_presigned && state.s3_config.log_presigned_url_generation {
            ActionType::Read // Presigned URL generation is logged as Read
        } else {
            action
        };

        let affected_users = resolver::resolve_affected_users(
            &bucket,
            &key,
            &state.patterns,
            &state.s3_config.excluded_prefixes,
        );

        // NOTE: we no longer skip events with empty affected_users.
        // publish_for_affected_users() always publishes to the deployment chain
        // (uninc.access._deployment) first, then to per-user chains. The deployment chain
        // gets EVERY admin S3 operation, including system files and logs
        // that don't map to specific users.

        let admin_username = match &class {
            ConnectionClass::Admin(id) => id.username.clone(),
            ConnectionClass::Suspicious(msg) => format!("suspicious:{msg}"),
            ConnectionClass::App => "app".to_string(),
        };
        let session_id = match &class {
            ConnectionClass::Admin(id) => id.session_id,
            _ => Uuid::new_v4(),
        };

        let fp = fingerprint::fingerprint_request(
            method.as_str(),
            &bucket,
            &key,
            &state.patterns,
        );

        let mut metadata = HashMap::new();
        metadata.insert("bucket".to_string(), bucket.clone());
        metadata.insert("key".to_string(), key.clone());
        metadata.insert("source_ip".to_string(), source_ip.to_string());
        if let Some(ua) = headers.get("user-agent").and_then(|v| v.to_str().ok()) {
            metadata.insert("user_agent".to_string(), ua.to_string());
        }

        let event = AccessEvent {
            protocol: Protocol::S3,
            admin_id: admin_username,
            action,
            resource: format!("{bucket}/{key}"),
            scope: format!(
                "bucket: {bucket}; key: {key}; action: {action}",
            ),
            query_fingerprint: fp,
            affected_users: affected_users.clone(),
            timestamp: Utc::now().timestamp_millis(),
            session_id,
            metadata,
        };

        // LOG-BEFORE-ACCESS GATE — synchronous publish, fail-closed.
        // If NATS is unreachable or acks too slowly, we return 503 to the
        // client and do NOT forward the request to upstream S3. This
        // preserves the invariant that every data access has a chain entry.
        //
        // `nats = None` is dev/test only (see postgres/listener.rs::emit_event
        // doc comment); in that case we let the request through without
        // publishing. NEVER deploy a production proxy with nats unconfigured.
        if let Some(ref nats) = state.nats {
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
                        "S3 access event published (log-before-access gate satisfied)"
                    );
                    // Fall through to forward_request below.
                }
                Ok(Err(e)) => {
                    error!(
                        error = %e,
                        "NATS publish failed — FAIL-CLOSED: returning 503, S3 request NOT forwarded"
                    );
                    return Response::builder()
                        .status(StatusCode::SERVICE_UNAVAILABLE)
                        .header("content-type", "application/xml")
                        .body(Body::from(
                            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>ServiceUnavailable</Code><Message>audit pipeline unavailable (fail-closed)</Message></Error>"
                        ))
                        .unwrap();
                }
                Err(_elapsed) => {
                    error!(
                        timeout_ms,
                        "NATS publish timed out — FAIL-CLOSED: returning 503, S3 request NOT forwarded"
                    );
                    return Response::builder()
                        .status(StatusCode::SERVICE_UNAVAILABLE)
                        .header("content-type", "application/xml")
                        .body(Body::from(
                            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>ServiceUnavailable</Code><Message>audit pipeline timed out (fail-closed)</Message></Error>"
                        ))
                        .unwrap();
                }
            }
        } else {
            warn!("NATS client not configured — access event not published (dev/test stack only)");
        }
    }

    // Gate satisfied (or skipped for dev). Determine the actor-marker to
    // attach on PUT so the observer's MinIO subscriber can recover the
    // admin identity from the bucket notification `userMetadata` field.
    // App and Suspicious connections don't carry a useful actor id, so
    // the header is only attached for Admin class (see §5.5 actor
    // alignment in protocol/draft-wang-data-access-transparency-00.md).
    let actor_marker = match &class {
        ConnectionClass::Admin(id) => Some(id.username.clone()),
        _ => None,
    };

    forward_request(&state, req, actor_marker).await
}

/// HTTP header carrying the admin actor id on admin S3 PUTs. MinIO's
/// bucket-notification payload exposes `x-amz-meta-*` headers inside the
/// `s3.object.userMetadata` JSON field, which the observer's MinIO
/// subscriber reads to HMAC the same pre-hash identifier the proxy's
/// projection uses at §5.5 comparison time.
///
/// Ref: `minio/docs/bucket/notifications/README.md` — notification schema
/// includes `s3.object.userMetadata`; custom metadata headers are
/// preserved through the notification pipeline.
const ACTOR_HEADER: &str = "x-amz-meta-uninc-actor";

/// Forward an HTTP request to the upstream S3 endpoint.
///
/// If `actor_marker` is `Some` and the method is a PUT / POST (object
/// create / multipart complete), an `x-amz-meta-uninc-actor` header is
/// attached before forwarding. The MinIO bucket-notification payload
/// surfaces this in `s3.object.userMetadata`, which lets the observer
/// recover the actor pre-hash from the replication stream for §5.5
/// byte-identity comparison. GET / HEAD requests get no marker (no
/// object is created; user-metadata isn't attachable to a read).
async fn forward_request(
    state: &S3ProxyState,
    req: Request<Body>,
    actor_marker: Option<String>,
) -> Response<Body> {
    let method = req.method().clone();
    let original_uri = req.uri().clone();
    let headers = req.headers().clone();

    // Build the upstream URI
    let upstream_uri = match build_upstream_uri(&state.upstream, &original_uri) {
        Ok(uri) => uri,
        Err(e) => {
            error!(error = %e, "failed to build upstream URI");
            return Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Body::from("bad gateway: invalid upstream URI"))
                .unwrap();
        }
    };

    // Build the forwarded request
    let mut builder = Request::builder().method(method.clone()).uri(upstream_uri);

    // Copy headers, skipping hop-by-hop headers. If the client set
    // `x-amz-meta-uninc-actor` themselves, we strip it — the proxy is
    // the only source of truth for actor attribution.
    for (name, value) in headers.iter() {
        let name_str = name.as_str();
        if is_hop_by_hop(name_str) {
            continue;
        }
        if name_str.eq_ignore_ascii_case(ACTOR_HEADER) {
            continue;
        }
        builder = builder.header(name, value);
    }

    // Attach the actor marker on object-create verbs only. DELETE has
    // no request body or user-metadata to carry the marker; delete
    // attribution for observer cross-witness is deferred — see
    // server/SPEC-DELTA.md.
    if let Some(ref actor) = actor_marker {
        if method == axum::http::Method::PUT || method == axum::http::Method::POST {
            builder = builder.header(ACTOR_HEADER, actor.as_str());
        }
    }

    let body = req.into_body();
    let forwarded_req = match builder.body(body) {
        Ok(r) => r,
        Err(e) => {
            error!(error = %e, "failed to build forwarded request");
            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from("internal error"))
                .unwrap();
        }
    };

    // Send to upstream, bounded by a hard timeout (item B). The hyper client
    // has its own connect timeout, but there is no default read-response
    // timeout, so without this wrapper a hung upstream S3 service would hold
    // the per-request permit (item D) indefinitely. 30s is the default and
    // matches the postgres admin_idle_secs.
    //
    // Future: lift this into `TimeoutConfig` as `s3_request_secs` if S3
    // workloads need different tuning.
    let upstream_timeout = std::time::Duration::from_secs(30);
    match tokio::time::timeout(upstream_timeout, state.client.request(forwarded_req)).await {
        Ok(Ok(resp)) => {
            let (parts, incoming) = resp.into_parts();
            Response::from_parts(parts, Body::new(incoming))
        }
        Ok(Err(e)) => {
            error!(error = %e, "upstream S3 request failed");
            Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Body::from(format!("upstream error: {e}")))
                .unwrap()
        }
        Err(_elapsed) => {
            warn!(
                timeout_secs = upstream_timeout.as_secs(),
                "upstream S3 request timed out"
            );
            Response::builder()
                .status(StatusCode::GATEWAY_TIMEOUT)
                .header("content-type", "application/xml")
                .body(Body::from(
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>GatewayTimeout</Code><Message>upstream S3 request timed out</Message></Error>"
                ))
                .unwrap()
        }
    }
}

/// Build the upstream URI by combining the upstream base with the request path + query.
fn build_upstream_uri(upstream: &str, original: &Uri) -> Result<Uri, String> {
    let base = upstream.trim_end_matches('/');
    let path_and_query = original
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let full = format!("{base}{path_and_query}");
    full.parse::<Uri>().map_err(|e| e.to_string())
}

/// Parse bucket and key from an S3-style path.
///
/// Path format: `/{bucket}/{key...}`
/// For virtual-hosted style, bucket comes from Host header (not handled here).
fn parse_bucket_key(path: &str) -> (String, String) {
    let trimmed = path.trim_start_matches('/');
    if let Some(slash_pos) = trimmed.find('/') {
        let bucket = &trimmed[..slash_pos];
        let key = &trimmed[slash_pos + 1..];
        (bucket.to_string(), key.to_string())
    } else {
        // Bucket-only request (e.g., ListObjects)
        (trimmed.to_string(), String::new())
    }
}

/// Map HTTP method to ActionType.
fn method_to_action(
    method: &axum::http::Method,
    is_complete_multipart: bool,
    _query: Option<&str>,
) -> ActionType {
    match method.as_str() {
        "GET" | "HEAD" => ActionType::Read,
        "PUT" => ActionType::Write,
        "POST" if is_complete_multipart => ActionType::Write,
        "POST" => ActionType::Write,
        "DELETE" => ActionType::Delete,
        _ => ActionType::Read, // Default to Read for unknown methods
    }
}

/// Extract source IP from X-Forwarded-For or X-Real-IP headers.
fn extract_source_ip(
    headers: &axum::http::HeaderMap,
) -> Option<std::net::IpAddr> {
    // Try X-Forwarded-For first (first IP in the chain)
    if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        if let Some(first) = xff.split(',').next() {
            if let Ok(ip) = first.trim().parse() {
                return Some(ip);
            }
        }
    }
    // Try X-Real-IP
    if let Some(xri) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
        if let Ok(ip) = xri.trim().parse() {
            return Some(ip);
        }
    }
    None
}

/// Extract credential from request (Authorization header or presigned URL query).
fn extract_credential(
    headers: &axum::http::HeaderMap,
    query: Option<&str>,
) -> Option<String> {
    // Try Authorization header first
    if let Some(authz) = headers.get("authorization").and_then(|v| v.to_str().ok()) {
        if let Some(key) = auth::extract_access_key(authz) {
            return Some(key.to_string());
        }
    }
    // Try presigned URL query parameters
    if let Some(q) = query {
        return auth::extract_access_key_from_query(q);
    }
    None
}

/// Check if a header is a hop-by-hop header that shouldn't be forwarded.
fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailers"
            | "transfer-encoding"
            | "upgrade"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_bucket_key_normal() {
        let (b, k) = parse_bucket_key("/my-bucket/path/to/object.jpg");
        assert_eq!(b, "my-bucket");
        assert_eq!(k, "path/to/object.jpg");
    }

    #[test]
    fn parse_bucket_key_bucket_only() {
        let (b, k) = parse_bucket_key("/my-bucket");
        assert_eq!(b, "my-bucket");
        assert_eq!(k, "");
    }

    #[test]
    fn parse_bucket_key_root() {
        let (b, k) = parse_bucket_key("/");
        assert_eq!(b, "");
        assert_eq!(k, "");
    }

    #[test]
    fn method_get_is_read() {
        assert_eq!(
            method_to_action(&axum::http::Method::GET, false, None),
            ActionType::Read
        );
    }

    #[test]
    fn method_put_is_write() {
        assert_eq!(
            method_to_action(&axum::http::Method::PUT, false, None),
            ActionType::Write
        );
    }

    #[test]
    fn method_delete_is_delete() {
        assert_eq!(
            method_to_action(&axum::http::Method::DELETE, false, None),
            ActionType::Delete
        );
    }

    #[test]
    fn method_post_complete_multipart_is_write() {
        assert_eq!(
            method_to_action(&axum::http::Method::POST, true, None),
            ActionType::Write
        );
    }

    #[test]
    fn build_upstream_uri_works() {
        let uri = "/my-bucket/key.txt?acl".parse().unwrap();
        let result = build_upstream_uri("http://minio:9000", &uri).unwrap();
        assert_eq!(result.to_string(), "http://minio:9000/my-bucket/key.txt?acl");
    }

    #[test]
    fn build_upstream_uri_strips_trailing_slash() {
        let uri = "/bucket/key".parse().unwrap();
        let result = build_upstream_uri("http://minio:9000/", &uri).unwrap();
        assert_eq!(result.to_string(), "http://minio:9000/bucket/key");
    }

    #[test]
    fn hop_by_hop_detection() {
        assert!(is_hop_by_hop("connection"));
        assert!(is_hop_by_hop("Transfer-Encoding"));
        assert!(!is_hop_by_hop("content-type"));
        assert!(!is_hop_by_hop("authorization"));
    }
}
