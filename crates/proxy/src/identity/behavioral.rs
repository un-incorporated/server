//! Behavioral fingerprinting — soft-signal anomaly detection.
//!
//! Tracks connection patterns per source IP to detect anomalous behavior
//! from app-classified sources. V1 is alerting-only (non-blocking).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Instant;

use tracing::warn;

/// Tracks connection patterns for behavioral anomaly detection.
pub struct BehavioralTracker {
    inner: Mutex<TrackerState>,
    /// Minimum expected connections from a pooled app source within
    /// `window_secs`. If an app source opens fewer connections than this,
    /// it may be a human using stolen app credentials.
    pub min_pool_connections: u32,
    /// Observation window in seconds.
    pub window_secs: u64,
}

struct TrackerState {
    /// connection timestamps per source IP
    connections: HashMap<IpAddr, Vec<Instant>>,
}

/// An anomaly detected by the behavioral tracker.
#[derive(Debug, Clone)]
pub struct BehavioralAnomaly {
    pub source_ip: IpAddr,
    pub reason: String,
    pub connection_count: u32,
    pub window_secs: u64,
}

impl BehavioralTracker {
    /// Create a new tracker with default thresholds.
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(TrackerState {
                connections: HashMap::new(),
            }),
            min_pool_connections: 2,
            window_secs: 60,
        }
    }

    /// Create a tracker with custom thresholds.
    pub fn with_thresholds(min_pool_connections: u32, window_secs: u64) -> Self {
        Self {
            inner: Mutex::new(TrackerState {
                connections: HashMap::new(),
            }),
            min_pool_connections,
            window_secs,
        }
    }

    /// Record a new connection from a source IP.
    ///
    /// Returns `Some(anomaly)` if the connection pattern looks suspicious
    /// (e.g., a single non-pooled connection from an IP that should be
    /// running a connection pool).
    pub fn record_connection(&self, source_ip: IpAddr) -> Option<BehavioralAnomaly> {
        let mut state = self.inner.lock().expect("tracker lock poisoned");
        let now = Instant::now();
        let cutoff = now - std::time::Duration::from_secs(self.window_secs);

        let timestamps = state.connections.entry(source_ip).or_default();

        // Prune old entries outside the window
        timestamps.retain(|t| *t > cutoff);

        // Record this connection
        timestamps.push(now);

        let count = timestamps.len() as u32;

        // An app source with a connection pool should maintain multiple
        // connections. A single connection in the window is suspicious.
        if count == 1 {
            let anomaly = BehavioralAnomaly {
                source_ip,
                reason: format!(
                    "single connection in {}-second window (expected pool with >= {})",
                    self.window_secs, self.min_pool_connections
                ),
                connection_count: count,
                window_secs: self.window_secs,
            };
            warn!(
                %source_ip,
                reason = %anomaly.reason,
                "behavioral anomaly detected"
            );
            return Some(anomaly);
        }

        None
    }

    /// Check current connection count for a source IP within the window.
    pub fn connection_count(&self, source_ip: IpAddr) -> u32 {
        let mut state = self.inner.lock().expect("tracker lock poisoned");
        let now = Instant::now();
        let cutoff = now - std::time::Duration::from_secs(self.window_secs);

        if let Some(timestamps) = state.connections.get_mut(&source_ip) {
            timestamps.retain(|t| *t > cutoff);
            timestamps.len() as u32
        } else {
            0
        }
    }

    /// Clear all tracked state.
    pub fn reset(&self) {
        let mut state = self.inner.lock().expect("tracker lock poisoned");
        state.connections.clear();
    }
}

impl Default for BehavioralTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_connection_is_anomalous() {
        let tracker = BehavioralTracker::new();
        let ip: IpAddr = "10.0.0.5".parse().unwrap();

        let anomaly = tracker.record_connection(ip);
        assert!(anomaly.is_some());
    }

    #[test]
    fn second_connection_is_not_anomalous() {
        let tracker = BehavioralTracker::new();
        let ip: IpAddr = "10.0.0.5".parse().unwrap();

        let _ = tracker.record_connection(ip);
        let anomaly = tracker.record_connection(ip);
        assert!(anomaly.is_none());
    }

    #[test]
    fn different_ips_tracked_independently() {
        let tracker = BehavioralTracker::new();
        let ip1: IpAddr = "10.0.0.5".parse().unwrap();
        let ip2: IpAddr = "10.0.0.6".parse().unwrap();

        let _ = tracker.record_connection(ip1);
        let _ = tracker.record_connection(ip1);

        // ip2 has no prior connections, should be anomalous
        let anomaly = tracker.record_connection(ip2);
        assert!(anomaly.is_some());
    }

    #[test]
    fn connection_count_tracks_correctly() {
        let tracker = BehavioralTracker::new();
        let ip: IpAddr = "10.0.0.5".parse().unwrap();

        assert_eq!(tracker.connection_count(ip), 0);
        let _ = tracker.record_connection(ip);
        assert_eq!(tracker.connection_count(ip), 1);
        let _ = tracker.record_connection(ip);
        assert_eq!(tracker.connection_count(ip), 2);
    }

    #[test]
    fn reset_clears_all() {
        let tracker = BehavioralTracker::new();
        let ip: IpAddr = "10.0.0.5".parse().unwrap();

        let _ = tracker.record_connection(ip);
        let _ = tracker.record_connection(ip);
        tracker.reset();
        assert_eq!(tracker.connection_count(ip), 0);
    }
}
