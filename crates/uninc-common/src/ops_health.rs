//! Cross-process relay for per-subsystem health stamping.
//!
//! The proxy's `/health/detailed` endpoint tracks a `SubsystemHealth` cell
//! for each named subsystem (NATS, chain-commit, observer-head, drand, …).
//! Most subsystems run in-process with the proxy and can stamp those cells
//! directly. Two don't:
//!
//! - `chain_commit` — chain-engine is a separate process. When it succeeds
//!   or fails to commit a chain entry (particularly under quorum failure,
//!   Wire 1/2), it publishes on NATS using [`publish_subsystem_health`]
//!   and the proxy subscriber translates that into a `SubsystemHealth`
//!   stamp.
//!
//! - Future subsystems that live in yet-other processes (e.g. the drand
//!   relay sidecar) can use the same relay without new plumbing.
//!
//! # Subject scheme
//!
//! Subject: `{ops_prefix}.subsystem_health.{subsystem_name}` where
//! `ops_prefix` is derived from the access-event prefix by swapping the
//! trailing `access` segment for `ops` (e.g. `uninc.access` → `uninc.ops`).
//! Messages are published on core NATS (not JetStream) — ops-health pings
//! are ephemeral. Losing one on a NATS restart is not a correctness
//! problem; the next publish overwrites the cell and the
//! stale-detection logic in `SubsystemHealth::status()` will mark the
//! subsystem `"stale"` if stamps stop arriving.
//!
//! # Payload
//!
//! Small JSON object:
//!
//! ```json
//! { "status": "ok" | "err", "reason": "<string, optional>" }
//! ```
//!
//! The `reason` field is optional and expected only on `"err"`. It is
//! truncated on the receiver to `SubsystemHealth::MAX_ERR_REASON_LEN`.

use crate::error::UnincError;
use crate::health::SubsystemHealth;
use async_nats::Subject;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{debug, warn};

/// Suffix appended to the ops prefix to form the subsystem-health subject
/// root. Full subject is
/// `{ops_prefix}.{SUBSYSTEM_HEALTH_SUFFIX}.{subsystem_name}`.
pub const SUBSYSTEM_HEALTH_SUFFIX: &str = "subsystem_health";

/// Derive the ops-event prefix from the configured access-event prefix.
/// For the default `uninc.access`, returns `uninc.ops`. For an arbitrary
/// prefix `foo.bar.baz`, returns `foo.bar.ops` — we swap the last
/// dot-separated segment.
pub fn ops_prefix_from_access(access_prefix: &str) -> String {
    match access_prefix.rsplit_once('.') {
        Some((base, _last)) => format!("{base}.ops"),
        None => format!("{access_prefix}.ops"),
    }
}

/// Wire format for a single subsystem-health ping.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SubsystemHealthPing {
    /// Either `"ok"` or `"err"`. No other values are defined; receivers
    /// MAY ignore unknown statuses and log a warning.
    pub status: String,
    /// Short error reason, only meaningful on `status == "err"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl SubsystemHealthPing {
    pub fn ok() -> Self {
        Self {
            status: "ok".into(),
            reason: None,
        }
    }

    pub fn err(reason: impl Into<String>) -> Self {
        Self {
            status: "err".into(),
            reason: Some(reason.into()),
        }
    }
}

/// Publish a subsystem-health ping on core NATS. Fire-and-forget — the
/// caller does not wait for JetStream ack because there is no JetStream
/// stream backing this subject. Publishes are best-effort by design.
pub async fn publish_subsystem_health(
    client: &async_nats::Client,
    ops_prefix: &str,
    subsystem: &str,
    ping: &SubsystemHealthPing,
) -> Result<(), UnincError> {
    let subject = format!("{ops_prefix}.{SUBSYSTEM_HEALTH_SUFFIX}.{subsystem}");
    let payload = serde_json::to_vec(ping)
        .map_err(|e| UnincError::Serialization(e.to_string()))?;
    client
        .publish(Subject::from(subject), payload.into())
        .await
        .map_err(|e| UnincError::Nats(format!("publish subsystem health failed: {e}")))?;
    Ok(())
}

/// Subscribe to `{ops_prefix}.{SUBSYSTEM_HEALTH_SUFFIX}.*` and stamp the
/// matching `SubsystemHealth` cell on each message. Unknown subsystem
/// names are ignored (with a debug log). Malformed payloads are dropped
/// with a warning — this is a best-effort channel, we don't surface
/// parse errors to the publisher.
///
/// Returns a task handle; the caller owns it and can `.abort()` at
/// shutdown. The task runs forever under normal operation.
///
/// `lookup` is a closure mapping a subsystem name to the cell to stamp.
/// The proxy implements this as `|name| health_state.subsystem(name)`.
pub fn spawn_subsystem_health_subscriber<F>(
    client: async_nats::Client,
    ops_prefix: String,
    lookup: F,
) -> tokio::task::JoinHandle<()>
where
    F: Fn(&str) -> Option<Arc<SubsystemHealth>> + Send + Sync + 'static,
{
    tokio::spawn(async move {
        let subject = format!("{ops_prefix}.{SUBSYSTEM_HEALTH_SUFFIX}.*");
        let mut sub = match client.subscribe(Subject::from(subject.clone())).await {
            Ok(s) => s,
            Err(e) => {
                warn!(
                    subject,
                    error = %e,
                    "subsystem-health subscriber failed to bind; /health/detailed will miss \
                    cross-process stamps until the proxy restarts"
                );
                return;
            }
        };

        use futures::StreamExt;
        while let Some(msg) = sub.next().await {
            // Subject format is guaranteed by the wildcard binding; the
            // last dot-separated segment is the subsystem name.
            let subsystem = match msg.subject.rsplit('.').next() {
                Some(s) => s,
                None => {
                    warn!(subject = %msg.subject, "subsystem-health message with empty subject");
                    continue;
                }
            };
            let cell = match lookup(subsystem) {
                Some(c) => c,
                None => {
                    debug!(subsystem, "subsystem-health ping for unknown subsystem — ignored");
                    continue;
                }
            };
            let ping: SubsystemHealthPing = match serde_json::from_slice(&msg.payload) {
                Ok(p) => p,
                Err(e) => {
                    warn!(subsystem, error = %e, "subsystem-health payload not JSON");
                    continue;
                }
            };
            match ping.status.as_str() {
                "ok" => cell.stamp_ok(),
                "err" => cell.stamp_err(ping.reason.unwrap_or_else(|| "(no reason)".into())),
                other => {
                    warn!(
                        subsystem,
                        status = other,
                        "subsystem-health ping with unknown status; ignored"
                    );
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ops_prefix_swaps_trailing_segment() {
        assert_eq!(ops_prefix_from_access("uninc.access"), "uninc.ops");
        assert_eq!(ops_prefix_from_access("foo.bar.access"), "foo.bar.ops");
    }

    #[test]
    fn ops_prefix_without_dot_appends_ops() {
        assert_eq!(ops_prefix_from_access("standalone"), "standalone.ops");
    }

    #[test]
    fn ping_ok_serializes_without_reason() {
        let p = SubsystemHealthPing::ok();
        let s = serde_json::to_string(&p).unwrap();
        assert_eq!(s, r#"{"status":"ok"}"#);
    }

    #[test]
    fn ping_err_serializes_with_reason() {
        let p = SubsystemHealthPing::err("quorum failed: 1/3 acked");
        let s = serde_json::to_string(&p).unwrap();
        assert!(s.contains(r#""status":"err""#));
        assert!(s.contains(r#""reason":"quorum failed: 1/3 acked""#));
    }
}
