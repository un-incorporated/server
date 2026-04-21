//! Connection pool module.
//!
//! Two concerns live here:
//!
//! 1. [`HttpPool`] — thin wrapper around hyper's HTTP client for S3 proxy
//!    forwarding. Hyper handles keep-alive and connection reuse on its own.
//!
//! 2. [`ConnectionCap`] — a semaphore-bounded cap on concurrent client
//!    connections for Postgres and MongoDB listeners. Items A.1 + D of
//!    the round-1 overload-protection plan. See ARCHITECTURE.md §"Capacity
//!    & overload protection" for the full model.
//!
//!    The cap serves a dual purpose today because `uninc-proxy` does not
//!    reuse upstream streams — each accepted client spawns exactly one
//!    upstream `TcpStream`, so bounding concurrent clients also bounds
//!    concurrent upstream streams. Real upstream reuse lives in the
//!    `pgbouncer` sidecar (item A.2), not in the Rust pool.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tracing::warn;

use axum::body::Body;
use uninc_common::config::PoolConfig;

/// An HTTP connection pool backed by hyper's built-in connection pooling.
///
/// For S3 proxying, hyper already handles keep-alive and connection reuse.
/// This wrapper exists so that future TCP pool logic (Postgres, MongoDB)
/// can share the same interface.
pub struct HttpPool {
    client: Client<hyper_util::client::legacy::connect::HttpConnector, Body>,
}

impl HttpPool {
    /// Create a new HTTP connection pool with default settings.
    pub fn new() -> Self {
        let client = Client::builder(TokioExecutor::new()).build_http();
        Self { client }
    }

    /// Get a reference to the underlying hyper client.
    pub fn client(
        &self,
    ) -> &Client<hyper_util::client::legacy::connect::HttpConnector, Body> {
        &self.client
    }
}

impl Default for HttpPool {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ConnectionCap — bounded concurrent-client semaphore for wire listeners
// ---------------------------------------------------------------------------

/// Semaphore-bounded cap on concurrent active client connections for a
/// wire-protocol listener (Postgres, MongoDB). Items A.1 and D of the
/// round-1 overload-protection plan.
///
/// # Why one type serves both A.1 and D
///
/// `uninc-proxy` is a wire-protocol passthrough. Each accepted client causes
/// exactly one upstream `TcpStream::connect` — there is no reuse. Bounding
/// concurrent clients therefore also bounds concurrent upstream streams, and
/// the same semaphore serves both "client connection cap" (item D, protects
/// the proxy from runaway accept + `tokio::spawn`) and "upstream pool cap"
/// (item A.1, protects the real database from exhausting `max_connections`).
///
/// Real connection reuse for Postgres lives in the `pgbouncer` sidecar (item
/// A.2), which sits between `uninc-proxy` and the real Postgres on the data
/// VMs. If a customer ever enables Postgres session-mode pooling and wants
/// real in-proxy Rust-side reuse, a separate stream-cache type can be added
/// here later. For v1, this cap plus pgbouncer is the whole pooling story.
///
/// # Behavior on exhaustion
///
/// Callers use [`Self::try_acquire`] (non-blocking) to decide what to do on
/// cap exhaustion. The listener returns an immediate error rather than
/// blocking accept, so clients get a clear "too many connections" signal
/// instead of a hung TCP handshake.
#[derive(Clone)]
pub struct ConnectionCap {
    sem: Arc<Semaphore>,
    in_use: Arc<AtomicU64>,
    max: u32,
    label: &'static str,
    #[allow(dead_code)]
    acquire_timeout: Duration,
}

impl ConnectionCap {
    /// Create a new connection cap from a [`PoolConfig`].
    ///
    /// `label` is used in log lines and should identify the listener, e.g.
    /// `"postgres"` or `"mongodb"`.
    pub fn from_config(cfg: &PoolConfig, label: &'static str) -> Self {
        let max = cfg.max.max(1);
        Self {
            sem: Arc::new(Semaphore::new(max as usize)),
            in_use: Arc::new(AtomicU64::new(0)),
            max,
            label,
            acquire_timeout: Duration::from_secs(cfg.connection_timeout_secs),
        }
    }

    /// Configured maximum concurrent clients.
    pub fn max(&self) -> u32 {
        self.max
    }

    /// Current number of active connections holding a permit.
    pub fn in_use(&self) -> u64 {
        self.in_use.load(Ordering::Relaxed)
    }

    /// Try to acquire a permit without waiting.
    ///
    /// Returns `None` if the cap is exhausted. Used by the listener's accept
    /// loop to fail fast rather than queue clients behind a hung upstream.
    /// The returned [`ConnectionPermit`] releases the permit and decrements
    /// `in_use` on drop.
    pub fn try_acquire(&self) -> Option<ConnectionPermit> {
        match Arc::clone(&self.sem).try_acquire_owned() {
            Ok(permit) => {
                self.in_use.fetch_add(1, Ordering::Relaxed);
                Some(ConnectionPermit {
                    _permit: permit,
                    in_use: Arc::clone(&self.in_use),
                })
            }
            Err(_) => {
                warn!(
                    listener = self.label,
                    max = self.max,
                    "connection cap exhausted — refusing new client"
                );
                None
            }
        }
    }

    /// Acquire a permit, waiting up to `connection_timeout_secs` for one to
    /// become available. Returns `None` on timeout or if the semaphore was closed.
    ///
    /// Reserved for future use by a "wait-briefly-then-fail" accept strategy.
    /// The current listener code uses [`Self::try_acquire`] for simpler
    /// fail-fast semantics.
    #[allow(dead_code)]
    pub async fn acquire_with_timeout(&self) -> Option<ConnectionPermit> {
        let sem = Arc::clone(&self.sem);
        match tokio::time::timeout(self.acquire_timeout, sem.acquire_owned()).await {
            Ok(Ok(permit)) => {
                self.in_use.fetch_add(1, Ordering::Relaxed);
                Some(ConnectionPermit {
                    _permit: permit,
                    in_use: Arc::clone(&self.in_use),
                })
            }
            Ok(Err(_closed)) => None,
            Err(_elapsed) => {
                warn!(
                    listener = self.label,
                    max = self.max,
                    timeout_secs = self.acquire_timeout.as_secs(),
                    "connection cap acquire timed out — refusing new client"
                );
                None
            }
        }
    }
}

/// RAII guard returned by [`ConnectionCap::try_acquire`]. Releases the
/// underlying semaphore permit and decrements the `in_use` counter on drop.
pub struct ConnectionPermit {
    _permit: OwnedSemaphorePermit,
    in_use: Arc<AtomicU64>,
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        self.in_use.fetch_sub(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pool_creates_successfully() {
        let pool = HttpPool::new();
        // Smoke test — just verify it doesn't panic
        let _ = pool.client();
    }

    #[test]
    fn pool_default_works() {
        let pool = HttpPool::default();
        let _ = pool.client();
    }

    #[test]
    fn connection_cap_from_config_respects_max() {
        let cfg = PoolConfig {
            min: 0,
            max: 3,
            idle_timeout_secs: 300,
            connection_timeout_secs: 5,
        };
        let cap = ConnectionCap::from_config(&cfg, "test");
        assert_eq!(cap.max(), 3);
        assert_eq!(cap.in_use(), 0);

        let p1 = cap.try_acquire().expect("permit 1");
        let p2 = cap.try_acquire().expect("permit 2");
        let p3 = cap.try_acquire().expect("permit 3");
        assert_eq!(cap.in_use(), 3);

        assert!(
            cap.try_acquire().is_none(),
            "fourth acquire must fail"
        );

        drop(p1);
        assert_eq!(cap.in_use(), 2);
        let _p4 = cap.try_acquire().expect("permit 4 after drop");
        assert_eq!(cap.in_use(), 3);

        drop(p2);
        drop(p3);
    }

    #[test]
    fn connection_cap_zero_max_coerces_to_one() {
        let cfg = PoolConfig {
            min: 0,
            max: 0,
            idle_timeout_secs: 300,
            connection_timeout_secs: 5,
        };
        let cap = ConnectionCap::from_config(&cfg, "test");
        assert_eq!(cap.max(), 1);
        let _p = cap.try_acquire().expect("at least one permit");
        assert!(cap.try_acquire().is_none());
    }
}
