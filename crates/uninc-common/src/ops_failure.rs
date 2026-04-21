//! Cross-process relay for `FailureEvent` notifications.
//!
//! The `FailureHandlerChain` (in the `verification` crate) runs on the
//! proxy. Chain-engine runs in a separate process and has no direct way
//! to invoke the handler chain. When chain-engine detects a persistent
//! quorum failure, it publishes a `ChainFailurePing` on
//! `{ops_prefix}.failure_event.{label}` using core NATS (not JetStream).
//! The proxy subscribes and feeds each ping into its handler chain.
//!
//! Core NATS is used deliberately: failure-signal messages MUST NOT
//! queue behind the stuck chain-append work that caused them. A
//! JetStream-backed subject with ordered delivery would make the
//! failure alert wait in the same queue as the failing entry — the
//! opposite of what we want. Dropping a ping on a NATS restart is
//! acceptable; the next quorum failure will re-raise it.
//!
//! # Payload
//!
//! A discriminated union (`kind` field) keeps this wire format
//! extensible. Two `kind`s are defined today:
//!
//! - `"chain_commit_failed"`: chain-engine's durable fan-out has failed
//!   `consecutive_failures` times in a row on `chain_id`. Threshold
//!   crossing (3 consecutive) triggers the handler chain.
//!
//! - `"observer_mismatch"`: the scheduled verification task found an
//!   observer head that diverges from the proxy head. Not used by
//!   chain-engine; the verification task emits this in-process today
//!   but the subject is reserved for future cross-process observers.

use crate::error::UnincError;
use async_nats::Subject;
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use tracing::warn;

pub const FAILURE_EVENT_SUFFIX: &str = "failure_event";

/// Payload shape. `kind` discriminates the variant; each `kind` carries
/// the fields listed below via `#[serde(flatten)]`-friendly extra fields.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ChainFailurePing {
    /// Chain-engine's durable (quorum) fan-out has failed
    /// `consecutive_failures` times in a row for `chain_id`. The reason
    /// is the last error string returned from the quorum storage layer.
    /// `chain_id` may be a per-user chain id or `"_deployment"`.
    ChainCommitFailed {
        chain_id: String,
        consecutive_failures: u32,
        last_reason: String,
    },
    /// Reserved for future cross-process observers. Not emitted today.
    ObserverMismatch {
        chain_id: String,
        proxy_head_hex: String,
        observer_head_hex: String,
    },
}

impl ChainFailurePing {
    /// Short label used in the subject suffix and logs.
    pub fn label(&self) -> &'static str {
        match self {
            Self::ChainCommitFailed { .. } => "chain_commit_failed",
            Self::ObserverMismatch { .. } => "observer_mismatch",
        }
    }
}

/// Publish a failure ping on core NATS.
pub async fn publish_failure_event(
    client: &async_nats::Client,
    ops_prefix: &str,
    ping: &ChainFailurePing,
) -> Result<(), UnincError> {
    let subject = format!("{ops_prefix}.{FAILURE_EVENT_SUFFIX}.{}", ping.label());
    let payload = serde_json::to_vec(ping)
        .map_err(|e| UnincError::Serialization(e.to_string()))?;
    client
        .publish(Subject::from(subject), payload.into())
        .await
        .map_err(|e| UnincError::Nats(format!("publish failure event failed: {e}")))?;
    Ok(())
}

/// Subscribe to `{ops_prefix}.failure_event.*` and hand each ping to
/// `handler`. Malformed payloads are dropped with a warn log. Returns
/// immediately with the task handle; the caller can `.abort()` on
/// shutdown.
pub fn spawn_failure_event_subscriber<H, Fut>(
    client: async_nats::Client,
    ops_prefix: String,
    handler: H,
) -> tokio::task::JoinHandle<()>
where
    H: Fn(ChainFailurePing) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = ()> + Send,
{
    tokio::spawn(async move {
        let subject = format!("{ops_prefix}.{FAILURE_EVENT_SUFFIX}.*");
        let mut sub = match client.subscribe(Subject::from(subject.clone())).await {
            Ok(s) => s,
            Err(e) => {
                warn!(
                    subject,
                    error = %e,
                    "failure-event subscriber failed to bind; chain-engine failure alerts \
                    will not reach the handler chain until the proxy restarts"
                );
                return;
            }
        };
        while let Some(msg) = sub.next().await {
            let ping: ChainFailurePing = match serde_json::from_slice(&msg.payload) {
                Ok(p) => p,
                Err(e) => {
                    warn!(subject = %msg.subject, error = %e, "failure-event payload not JSON");
                    continue;
                }
            };
            handler(ping).await;
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_commit_failed_roundtrip() {
        let p = ChainFailurePing::ChainCommitFailed {
            chain_id: "_deployment".into(),
            consecutive_failures: 5,
            last_reason: "1/3 replicas acked".into(),
        };
        let j = serde_json::to_string(&p).unwrap();
        assert!(j.contains(r#""kind":"chain_commit_failed""#));
        assert!(j.contains(r#""chain_id":"_deployment""#));
        assert!(j.contains(r#""consecutive_failures":5"#));
        let back: ChainFailurePing = serde_json::from_str(&j).unwrap();
        assert_eq!(back.label(), "chain_commit_failed");
    }

    #[test]
    fn observer_mismatch_roundtrip() {
        let p = ChainFailurePing::ObserverMismatch {
            chain_id: "_deployment".into(),
            proxy_head_hex: "deadbeef".into(),
            observer_head_hex: "cafef00d".into(),
        };
        let j = serde_json::to_string(&p).unwrap();
        assert!(j.contains(r#""kind":"observer_mismatch""#));
        let back: ChainFailurePing = serde_json::from_str(&j).unwrap();
        assert_eq!(back.label(), "observer_mismatch");
    }
}
