//! Per-credential / per-IP rate limiting — item G of the round-1
//! overload-protection plan.
//!
//! A hand-rolled token bucket (no new external dependency) that bounds
//! request rate per key. Keys are protocol-specific:
//!
//! - Postgres / MongoDB: `(source_ip, admin_username)` — IP catches
//!   unauthenticated-flood attacks; username catches "one misbehaving
//!   credential starves the platform."
//! - S3: `source_ip` + the extracted access-key id.
//!
//! The bucket uses monotonic `Instant` timestamps so clock drift does not
//! affect accuracy. Each call to [`TokenBucket::try_consume`] refills the
//! bucket based on elapsed time since the last operation, then attempts
//! to atomically subtract the requested number of tokens.
//!
//! See ARCHITECTURE.md §"Capacity & overload protection" Layer 1.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use uninc_common::config::RateLimitConfig;

/// How long a bucket can sit idle before it's eligible for cleanup.
/// After this many seconds of inactivity, the bucket is at full capacity
/// anyway (refill has caught up), so keeping it in memory is pure waste.
const STALE_BUCKET_SECS: u64 = 300; // 5 minutes

/// Maximum number of buckets per map before a forced cleanup sweep runs.
/// Prevents pathological memory growth from DDoS with random source IPs.
const MAX_BUCKETS_BEFORE_SWEEP: usize = 10_000;

/// A single token bucket. Not `Clone` — the intended usage is to hold it
/// behind a `Mutex` inside a map in [`RateLimiter`], and `try_consume` takes
/// `&mut self` which the Mutex guard provides.
#[derive(Debug)]
pub struct TokenBucket {
    /// Current tokens in the bucket. Fractional to allow sub-second refill.
    tokens: f64,

    /// Max capacity — the burst the caller can take in one instant before
    /// the bucket runs dry.
    capacity: f64,

    /// Refill rate in tokens per second.
    refill_rate: f64,

    /// Last refill time. Used to compute how many tokens to add on the
    /// next check.
    last_refill: Instant,
}

impl TokenBucket {
    pub fn new(rate_per_sec: f64, capacity: f64) -> Self {
        Self {
            tokens: capacity,
            capacity,
            refill_rate: rate_per_sec,
            last_refill: Instant::now(),
        }
    }

    /// Refill then attempt to consume `n` tokens.
    ///
    /// Returns `true` if `n` tokens were successfully subtracted. Returns
    /// `false` if the bucket doesn't have enough — in which case no tokens
    /// are consumed and the caller should reject the request.
    pub fn try_consume(&mut self, n: f64) -> bool {
        let now = Instant::now();
        let elapsed_secs = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed_secs * self.refill_rate).min(self.capacity);
        self.last_refill = now;

        if self.tokens >= n {
            self.tokens -= n;
            true
        } else {
            false
        }
    }
}

/// Per-key rate limiter. Two independent maps so per-IP and per-credential
/// limits compose (a request must pass both).
///
/// Stale buckets are cleaned up automatically: when a map exceeds
/// `MAX_BUCKETS_BEFORE_SWEEP` entries, all buckets idle for longer than
/// `STALE_BUCKET_SECS` are evicted. A bucket that's been idle for 5 minutes
/// is at full capacity anyway (refill has caught up), so removing it has
/// no behavioral effect — the next request from that key simply creates
/// a fresh full bucket, which is identical to what the stale one would
/// have been. This prevents memory growth under DDoS with random source IPs.
pub struct RateLimiter {
    config: RateLimitConfig,
    per_ip: Mutex<HashMap<String, TokenBucket>>,
    per_credential: Mutex<HashMap<String, TokenBucket>>,
}

/// Remove buckets that have been idle for longer than `STALE_BUCKET_SECS`.
/// Only runs when the map size exceeds `MAX_BUCKETS_BEFORE_SWEEP` to avoid
/// scanning on every request. A stale bucket at full capacity is functionally
/// identical to a freshly created one, so eviction has no behavioral impact.
fn maybe_sweep(map: &mut HashMap<String, TokenBucket>) {
    if map.len() < MAX_BUCKETS_BEFORE_SWEEP {
        return;
    }
    let cutoff = Duration::from_secs(STALE_BUCKET_SECS);
    let now = Instant::now();
    map.retain(|_key, bucket| now.duration_since(bucket.last_refill) < cutoff);
}

impl RateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            per_ip: Mutex::new(HashMap::new()),
            per_credential: Mutex::new(HashMap::new()),
        }
    }

    /// Whether rate limiting is enabled in config. Callers can skip the
    /// lock acquisition entirely when disabled.
    pub fn enabled(&self) -> bool {
        self.config.enabled
    }

    /// Check and consume one request's worth of capacity against the
    /// per-IP bucket for `ip`. Returns `true` if the request is allowed.
    ///
    /// Cheap when disabled (returns `true` immediately without touching
    /// the lock). Triggers stale-bucket cleanup when the map is large.
    pub fn check_ip(&self, ip: &str) -> bool {
        if !self.config.enabled {
            return true;
        }
        let mut map = self.per_ip.lock().expect("per_ip mutex poisoned");
        maybe_sweep(&mut map);
        let bucket = map.entry(ip.to_string()).or_insert_with(|| {
            TokenBucket::new(
                self.config.per_ip_rps as f64,
                self.config.per_ip_burst as f64,
            )
        });
        bucket.try_consume(1.0)
    }

    /// Check and consume one request's worth of capacity against the
    /// per-credential bucket.
    pub fn check_credential(&self, credential: &str) -> bool {
        if !self.config.enabled {
            return true;
        }
        let mut map = self
            .per_credential
            .lock()
            .expect("per_credential mutex poisoned");
        maybe_sweep(&mut map);
        let bucket = map.entry(credential.to_string()).or_insert_with(|| {
            TokenBucket::new(
                self.config.per_credential_rps as f64,
                self.config.per_credential_burst as f64,
            )
        });
        bucket.try_consume(1.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_allows_up_to_capacity_immediately() {
        let mut b = TokenBucket::new(10.0, 5.0);
        for _ in 0..5 {
            assert!(b.try_consume(1.0));
        }
        assert!(!b.try_consume(1.0), "6th request should be rejected");
    }

    #[test]
    fn bucket_refills_over_time() {
        let mut b = TokenBucket::new(1000.0, 2.0);
        assert!(b.try_consume(2.0));
        assert!(!b.try_consume(1.0));
        std::thread::sleep(std::time::Duration::from_millis(10));
        // At 1000 rps, 10ms = 10 tokens of refill, but capped at capacity=2.
        assert!(b.try_consume(1.0));
        assert!(b.try_consume(1.0));
        assert!(!b.try_consume(1.0));
    }

    #[test]
    fn disabled_limiter_passes_everything() {
        let cfg = RateLimitConfig {
            enabled: false,
            per_ip_rps: 1,
            per_ip_burst: 1,
            per_credential_rps: 1,
            per_credential_burst: 1,
        };
        let rl = RateLimiter::new(cfg);
        for _ in 0..100 {
            assert!(rl.check_ip("1.2.3.4"));
            assert!(rl.check_credential("admin"));
        }
    }

    #[test]
    fn per_ip_isolates_keys() {
        let cfg = RateLimitConfig {
            enabled: true,
            per_ip_rps: 1,
            per_ip_burst: 2,
            per_credential_rps: 1000,
            per_credential_burst: 1000,
        };
        let rl = RateLimiter::new(cfg);
        // Attacker IP hits its limit...
        assert!(rl.check_ip("1.1.1.1"));
        assert!(rl.check_ip("1.1.1.1"));
        assert!(!rl.check_ip("1.1.1.1"));
        // ...but a different IP is unaffected.
        assert!(rl.check_ip("2.2.2.2"));
    }

    #[test]
    fn per_credential_isolates_keys() {
        let cfg = RateLimitConfig {
            enabled: true,
            per_ip_rps: 1000,
            per_ip_burst: 1000,
            per_credential_rps: 2,
            per_credential_burst: 2,
        };
        let rl = RateLimiter::new(cfg);
        assert!(rl.check_credential("dba"));
        assert!(rl.check_credential("dba"));
        assert!(!rl.check_credential("dba"));
        assert!(rl.check_credential("analyst"));
    }
}
