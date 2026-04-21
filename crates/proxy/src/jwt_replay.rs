//! Per-process JWT `jti` replay deny-list.
//!
//! Implements §10.5 of `protocol/draft-wang-data-access-transparency-00.md`: a conformant server
//! MUST reject any JWT whose `jti` claim it has already accepted within the
//! `exp` window of a previously-accepted token. Combined with the §7.1 cap
//! of `exp <= iat + 3600`, this turns HS256 bearer tokens into effectively
//! single-use credentials — a stolen token replayable at most once before
//! the legitimate holder uses it, and zero times after.
//!
//! ## Shape
//!
//! One bounded LRU keyed by `jti`. The value stored is the token's `exp`
//! (unix seconds). Lookup is O(1); eviction on capacity overflow is O(1);
//! a cheap lazy purge on insert drops entries whose `exp` is already in
//! the past so the deny-list cannot grow indefinitely if a client keeps
//! minting tokens with absurdly long lifetimes.
//!
//! ## Sizing
//!
//! Default capacity is 100,000 `jti` values. At the §7.1 worst-case of
//! one-hour tokens, that tolerates ~28 authenticated requests per second
//! for a full hour without LRU churn evicting an unexpired entry. The cap
//! is configurable via the `UNINC_JTI_CAPACITY` env var read in `main.rs`
//! — operators running extremely high-rate chain APIs can raise it. If
//! the cap is hit before `exp` elapses, an unexpired entry can be evicted,
//! which would let *that* specific token be replayed once more. The tradeoff
//! is unbounded memory growth; the cap is the honest option.
//!
//! ## Concurrency
//!
//! A std `Mutex<LruCache>` is sufficient — the critical section is a single
//! hash probe + insert, measured in hundreds of nanoseconds. An async mutex
//! is not needed and would be strictly worse (stack frame, awake cost).
//!
//! ## Multi-replica deployments
//!
//! This deny-list is local to the process. Deployments running more than
//! one proxy behind a load balancer need shared state across replicas
//! (Redis, NATS KV, etc.) to prevent a token presented to replica A from
//! being replayable on replica B. That is out of scope for v1 — every v1
//! deployment shape is single-proxy (see server/ARCHITECTURE.md
//! §"Deployment topologies"). The spec (§10.5) flags this explicitly.

use lru::LruCache;
use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// Default in-memory capacity for the `jti` deny-list.
pub const DEFAULT_JTI_CAPACITY: usize = 100_000;

/// Outcome of an attempted `jti` admission.
#[derive(Debug, PartialEq, Eq)]
pub enum JtiAdmit {
    /// The `jti` was unseen and has been recorded — the request MAY proceed.
    Fresh,
    /// The `jti` has already been admitted inside its `exp` window — the
    /// server MUST reject the request per §10.5.
    Replayed,
    /// The token has already expired; the caller should let normal `exp`
    /// validation reject it (this deny-list does not care about tokens the
    /// jwt crate will reject anyway).
    Expired,
}

/// Bounded, process-local `jti` deny-list.
pub struct JtiDenyList {
    inner: Mutex<LruCache<String, u64>>,
}

impl JtiDenyList {
    /// New deny-list with the given capacity. Capacity of 0 is treated as 1
    /// (the `lru` crate requires NonZeroUsize and we want a default that
    /// refuses to build without panicking).
    pub fn new(capacity: usize) -> Self {
        let cap = NonZeroUsize::new(capacity.max(1)).expect("capacity >= 1");
        Self {
            inner: Mutex::new(LruCache::new(cap)),
        }
    }

    /// Try to record `jti` with the given `exp` (unix seconds). Returns
    /// whether the presentation should be admitted, rejected as a replay,
    /// or left to normal `exp` validation.
    pub fn admit(&self, jti: &str, exp_unix_secs: u64) -> JtiAdmit {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if exp_unix_secs <= now {
            return JtiAdmit::Expired;
        }

        let mut guard = self.inner.lock().expect("jti deny-list mutex poisoned");
        // Cheap lazy purge: drop any entry at the head of the LRU whose exp
        // has already passed. Bounded by capacity; amortized O(1) per call.
        while let Some((_, &stale_exp)) = guard.peek_lru() {
            if stale_exp <= now {
                guard.pop_lru();
            } else {
                break;
            }
        }

        if guard.contains(jti) {
            return JtiAdmit::Replayed;
        }
        guard.put(jti.to_string(), exp_unix_secs);
        JtiAdmit::Fresh
    }

    /// Current count of retained `jti` entries. For metrics / tests only.
    pub fn len(&self) -> usize {
        self.inner.lock().map(|g| g.len()).unwrap_or(0)
    }

    /// Whether the deny-list is empty. For metrics / tests only.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for JtiDenyList {
    fn default() -> Self {
        Self::new(DEFAULT_JTI_CAPACITY)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn future_exp(secs_from_now: u64) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + secs_from_now
    }

    #[test]
    fn fresh_jti_is_admitted() {
        let list = JtiDenyList::new(8);
        assert_eq!(list.admit("a", future_exp(300)), JtiAdmit::Fresh);
        assert_eq!(list.len(), 1);
    }

    #[test]
    fn repeat_jti_is_replay() {
        let list = JtiDenyList::new(8);
        assert_eq!(list.admit("dupe", future_exp(300)), JtiAdmit::Fresh);
        assert_eq!(list.admit("dupe", future_exp(300)), JtiAdmit::Replayed);
    }

    #[test]
    fn expired_is_short_circuited() {
        let list = JtiDenyList::new(8);
        // exp=0 is in the past; should report Expired and not store anything.
        assert_eq!(list.admit("old", 0), JtiAdmit::Expired);
        assert_eq!(list.len(), 0);
    }

    #[test]
    fn capacity_evicts_oldest() {
        let list = JtiDenyList::new(2);
        assert_eq!(list.admit("a", future_exp(300)), JtiAdmit::Fresh);
        assert_eq!(list.admit("b", future_exp(300)), JtiAdmit::Fresh);
        // Third insert evicts "a" (oldest). Deny-list now retains {b, c}.
        assert_eq!(list.admit("c", future_exp(300)), JtiAdmit::Fresh);
        // "c" and "b" both still tracked.
        assert_eq!(list.admit("c", future_exp(300)), JtiAdmit::Replayed);
        assert_eq!(list.admit("b", future_exp(300)), JtiAdmit::Replayed);
        // "a" was evicted so it admits as Fresh again — documented tradeoff
        // of a bounded per-process deny-list (see module docs).
        assert_eq!(list.admit("a", future_exp(300)), JtiAdmit::Fresh);
    }

    #[test]
    fn zero_capacity_is_clamped_to_one() {
        let list = JtiDenyList::new(0);
        assert_eq!(list.admit("only", future_exp(300)), JtiAdmit::Fresh);
    }
}
