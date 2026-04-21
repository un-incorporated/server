//! Per-subsystem liveness stamping used by the proxy's `/health/detailed`
//! endpoint.
//!
//! Each subsystem (NATS publish, chain-engine commit, observer head fetch,
//! drand relay, etc.) owns one `SubsystemHealth` cell. Call sites that
//! succeed invoke `.stamp_ok()`; call sites that fail invoke
//! `.stamp_err(reason)`. The `/health/detailed` handler on the proxy reads
//! these cells without blocking — the atomics are lock-free and the mutex
//! around `err_reason` is uncontended in practice (stamp writers fire on
//! the hot path, handler reads are polled a few times a minute).
//!
//! The struct lives in `uninc-common` rather than the proxy crate because
//! it needs to be shared with the `verification` crate (which holds an
//! `Arc<SubsystemHealth>` for the `observer_head` subsystem) and, via
//! the NATS ops relay subscriber on the proxy, with the chain-engine
//! crate. Keeping it here avoids a circular dependency on `uninc-proxy`.

use std::sync::Mutex;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};
use tracing::warn;

/// Cap on the `last_err_reason` string kept per subsystem. Reasons longer
/// than this are truncated with a `"…"` ellipsis — keeps
/// `/health/detailed` responses small and avoids unbounded growth when a
/// subsystem returns a large error body.
pub const MAX_ERR_REASON_LEN: usize = 256;

/// Stale thresholds used by the rollup logic. Shared between the readiness
/// probe and the detailed handler on the proxy so they agree.
pub const RECENT_ERR_WINDOW_MS: i64 = 30_000;
pub const STALE_OK_WINDOW_MS: i64 = 60_000;

/// Per-subsystem liveness cell. Cheap to clone behind an `Arc` — no
/// per-subsystem locks are held across async boundaries and reads are
/// lock-free on the atomics.
#[derive(Debug)]
pub struct SubsystemHealth {
    ok_ms: AtomicI64,
    err_ms: AtomicI64,
    err_reason: Mutex<String>,
}

impl SubsystemHealth {
    pub fn new() -> Self {
        Self {
            ok_ms: AtomicI64::new(0),
            err_ms: AtomicI64::new(0),
            err_reason: Mutex::new(String::new()),
        }
    }

    /// Stamp a success. Clears no state — `err_ms` and `err_reason`
    /// persist until overwritten, so rollup logic can infer recovery by
    /// comparing the two timestamps.
    pub fn stamp_ok(&self) {
        self.ok_ms.store(now_ms(), Ordering::Relaxed);
    }

    /// Stamp a failure with a short reason. Reason is truncated (char-
    /// boundary aware) to `MAX_ERR_REASON_LEN` with an ellipsis suffix
    /// if too long. Lock poisoning is recovered transparently — a
    /// poisoned mutex means a previous stamper panicked, and the best
    /// we can do is overwrite the string and keep going.
    pub fn stamp_err(&self, reason: impl Into<String>) {
        self.err_ms.store(now_ms(), Ordering::Relaxed);
        let mut s = reason.into();
        if s.len() > MAX_ERR_REASON_LEN {
            let cut = (0..=MAX_ERR_REASON_LEN - 1)
                .rev()
                .find(|&i| s.is_char_boundary(i))
                .unwrap_or(0);
            s.truncate(cut);
            s.push('…');
        }
        match self.err_reason.lock() {
            Ok(mut g) => *g = s,
            Err(poisoned) => {
                warn!("subsystem health err_reason mutex poisoned — previous stamper panicked");
                *poisoned.into_inner() = s;
            }
        }
    }

    pub fn last_ok_ms(&self) -> i64 {
        self.ok_ms.load(Ordering::Relaxed)
    }

    pub fn last_err_ms(&self) -> i64 {
        self.err_ms.load(Ordering::Relaxed)
    }

    pub fn last_err_reason(&self) -> String {
        match self.err_reason.lock() {
            Ok(g) => g.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// Rollup status for this subsystem. `configured` lets the caller
    /// distinguish "no observer in this deployment" (→ `"not_configured"`)
    /// from "observer is present but hasn't stamped yet" (→ `"idle"`
    /// once past the `uptime_secs` grace window).
    pub fn status(&self, now_ms_val: i64, configured: bool, uptime_secs: u64) -> &'static str {
        if !configured {
            return "not_configured";
        }
        let last_ok = self.last_ok_ms();
        let last_err = self.last_err_ms();
        if last_err > 0 && (now_ms_val - last_err) < RECENT_ERR_WINDOW_MS && last_ok < last_err {
            "down"
        } else if last_ok == 0 && uptime_secs > 30 {
            "idle"
        } else if last_ok > 0 && (now_ms_val - last_ok) > STALE_OK_WINDOW_MS {
            "stale"
        } else {
            "ok"
        }
    }

    /// JSON snapshot used by `/health/detailed`.
    pub fn to_json(&self, now_ms_val: i64, configured: bool, uptime_secs: u64) -> Value {
        let status = self.status(now_ms_val, configured, uptime_secs);
        json!({
            "status": status,
            "last_ok_ms": self.last_ok_ms(),
            "last_err_ms": self.last_err_ms(),
            "last_err_reason": self.last_err_reason(),
        })
    }
}

impl Default for SubsystemHealth {
    fn default() -> Self {
        Self::new()
    }
}

pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stamp_ok_writes_current_time() {
        let sh = SubsystemHealth::new();
        assert_eq!(sh.last_ok_ms(), 0);
        sh.stamp_ok();
        assert!(sh.last_ok_ms() > 0);
    }

    #[test]
    fn stamp_err_records_reason() {
        let sh = SubsystemHealth::new();
        sh.stamp_err("quorum not reached: 1/3 replicas acked");
        assert!(sh.last_err_ms() > 0);
        assert_eq!(
            sh.last_err_reason(),
            "quorum not reached: 1/3 replicas acked"
        );
    }

    #[test]
    fn long_reason_is_truncated_with_ellipsis() {
        let sh = SubsystemHealth::new();
        let long: String = "x".repeat(MAX_ERR_REASON_LEN + 200);
        sh.stamp_err(long);
        let kept = sh.last_err_reason();
        assert!(kept.ends_with('…'));
        assert!(kept.len() <= MAX_ERR_REASON_LEN + 4);
    }

    #[test]
    fn utf8_boundary_truncation_does_not_panic() {
        let sh = SubsystemHealth::new();
        let long: String = "漢".repeat(MAX_ERR_REASON_LEN);
        sh.stamp_err(long);
        assert!(sh.last_err_reason().ends_with('…'));
    }

    #[test]
    fn status_classifies_idle_ok_stale_down() {
        let sh = SubsystemHealth::new();
        let now = now_ms();
        assert_eq!(sh.status(now, true, 10), "ok");
        assert_eq!(sh.status(now, true, 60), "idle");
        sh.stamp_ok();
        assert_eq!(sh.status(now_ms(), false, 60), "not_configured");
        assert_eq!(sh.status(now_ms(), true, 60), "ok");
        std::thread::sleep(std::time::Duration::from_millis(5));
        sh.stamp_err("boom");
        assert_eq!(sh.status(now_ms(), true, 60), "down");
        std::thread::sleep(std::time::Duration::from_millis(5));
        sh.stamp_ok();
        assert_eq!(sh.status(now_ms(), true, 60), "ok");
    }
}
