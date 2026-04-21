//! Verification and durability status tracking for chain entries.
//!
//! Each chain directory has TWO sidecar files:
//!
//!   1. `verified_ranges.json` — records which entry ranges have been
//!      verified by the nightly cross-replica comparison. Written when
//!      the nightly pipeline completes cleanly.
//!
//!   2. `durable_ranges.json` — records which entry ranges are quorum-
//!      durable on the replica MinIOs (multi-VM topology) or flushed to
//!      the single local MinIO (single-host topology). Written by
//!      `ChainManager::append_event` / `DeploymentChainManager::append_*`
//!      immediately after a successful `MultiReplicaStorage::put_entry`.
//!
//! The LRU cache uses BOTH sidecars to decide which entries are safe to
//! evict from local disk. Only entries that are both (a) durable on
//! replicas AND (b) verified by the nightly trigger can be evicted.
//! Without this gate, the LRU could evict an entry whose replica write
//! failed silently, leaving the entry only on disk.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use tokio::sync::RwLock;
use tracing::debug;

/// A range of entries that have been verified.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedRange {
    /// First index in the range (inclusive).
    pub from_index: u64,
    /// Last index in the range (inclusive).
    pub to_index: u64,
    /// Unix timestamp (milliseconds) when verification succeeded.
    pub verified_at: i64,
}

/// Manages the verified_ranges.json sidecar for a chain directory.
pub struct VerificationTracker {
    path: PathBuf,
}

impl VerificationTracker {
    /// Open a tracker for the given chain directory.
    pub fn new(chain_dir: &Path) -> Self {
        Self {
            path: chain_dir.join("verified_ranges.json"),
        }
    }

    /// Read all verified ranges.
    pub fn read_ranges(&self) -> Vec<VerifiedRange> {
        if !self.path.exists() {
            return Vec::new();
        }
        match fs::read_to_string(&self.path) {
            Ok(contents) => serde_json::from_str(&contents).unwrap_or_default(),
            Err(_) => Vec::new(),
        }
    }

    /// Mark a range of entries as verified.
    ///
    /// Merges with existing ranges and writes back to disk.
    pub fn mark_verified(
        &self,
        from_index: u64,
        to_index: u64,
        verified_at: i64,
    ) -> std::io::Result<()> {
        let mut ranges = self.read_ranges();
        ranges.push(VerifiedRange {
            from_index,
            to_index,
            verified_at,
        });
        // Merge overlapping/adjacent ranges.
        ranges = merge_ranges(ranges);
        let json = serde_json::to_string_pretty(&ranges)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        fs::write(&self.path, json)?;
        debug!(
            from = from_index,
            to = to_index,
            path = %self.path.display(),
            "marked entries as verified"
        );
        Ok(())
    }

    /// Check if a specific entry index has been verified.
    pub fn is_verified(&self, index: u64) -> bool {
        self.read_ranges()
            .iter()
            .any(|r| index >= r.from_index && index <= r.to_index)
    }

    /// Get the highest verified index, or None if no entries are verified.
    pub fn last_verified_index(&self) -> Option<u64> {
        self.read_ranges().iter().map(|r| r.to_index).max()
    }

    /// Check if ALL entries up to (inclusive) `up_to` are verified.
    pub fn all_verified_up_to(&self, up_to: u64) -> bool {
        let ranges = self.read_ranges();
        if ranges.is_empty() {
            return false;
        }
        // After merging, there should be a single range starting at 0 that covers up_to.
        ranges
            .iter()
            .any(|r| r.from_index == 0 && r.to_index >= up_to)
    }
}

// ── Durable ranges (quorum-committed to replica MinIOs) ────────────────

/// A range of entries that have been quorum-durably committed. Same shape
/// as `VerifiedRange` but a distinct type to prevent accidental confusion
/// at the LRU eviction gate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DurableRange {
    pub from_index: u64,
    pub to_index: u64,
    pub durable_at: i64,
}

/// Append a new durable range to the chain's `durable_ranges.json` sidecar.
/// Called from `ChainManager::durable_commit` / `DeploymentChainManager::durable_commit`
/// after a successful `MultiReplicaStorage::put_entry`.
///
/// Tolerant of concurrent writes: the caller holds the per-chain write
/// lock, so this function assumes single-writer access to the sidecar.
pub async fn record_durable_range(
    sidecar: &Path,
    from_index: u64,
    to_index: u64,
) -> std::io::Result<()> {
    let now = chrono::Utc::now().timestamp_millis();
    if let Some(parent) = sidecar.parent() {
        if !parent.exists() {
            tokio::fs::create_dir_all(parent).await?;
        }
    }
    let existing: Vec<DurableRange> = if sidecar.exists() {
        let contents = tokio::fs::read_to_string(sidecar).await?;
        serde_json::from_str(&contents).unwrap_or_default()
    } else {
        Vec::new()
    };
    let mut ranges = existing;
    ranges.push(DurableRange {
        from_index,
        to_index: to_index.saturating_sub(1),
        durable_at: now,
    });
    ranges = merge_durable_ranges(ranges);
    let json = serde_json::to_string_pretty(&ranges)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    tokio::fs::write(sidecar, json).await?;
    Ok(())
}

pub fn read_durable_ranges(sidecar: &Path) -> Vec<DurableRange> {
    if !sidecar.exists() {
        return Vec::new();
    }
    match fs::read_to_string(sidecar) {
        Ok(contents) => serde_json::from_str(&contents).unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

pub fn is_durable(sidecar: &Path, index: u64) -> bool {
    read_durable_ranges(sidecar)
        .iter()
        .any(|r| index >= r.from_index && index <= r.to_index)
}

fn merge_durable_ranges(mut ranges: Vec<DurableRange>) -> Vec<DurableRange> {
    if ranges.is_empty() {
        return ranges;
    }
    ranges.sort_by_key(|r| r.from_index);
    let mut merged = vec![ranges[0].clone()];
    for r in &ranges[1..] {
        let last = merged.last_mut().unwrap();
        if r.from_index <= last.to_index + 1 {
            last.to_index = last.to_index.max(r.to_index);
            last.durable_at = last.durable_at.max(r.durable_at);
        } else {
            merged.push(r.clone());
        }
    }
    merged
}

/// In-memory durability tracker. The on-disk `durable_ranges.json` is the
/// persistent form; this struct caches recent writes so hot-path eviction
/// decisions don't hit disk on every LRU check.
#[derive(Default)]
pub struct DurabilityTracker {
    inner: RwLock<HashMap<String, Vec<DurableRange>>>,
}

impl DurabilityTracker {
    pub async fn mark_durable(&self, chain_id: &str, index: u64) {
        let mut guard = self.inner.write().await;
        let ranges = guard.entry(chain_id.to_string()).or_default();
        ranges.push(DurableRange {
            from_index: index,
            to_index: index,
            durable_at: chrono::Utc::now().timestamp_millis(),
        });
        *ranges = merge_durable_ranges(std::mem::take(ranges));
    }

    pub async fn is_durable(&self, chain_id: &str, index: u64) -> bool {
        let guard = self.inner.read().await;
        guard
            .get(chain_id)
            .map(|ranges| {
                ranges
                    .iter()
                    .any(|r| index >= r.from_index && index <= r.to_index)
            })
            .unwrap_or(false)
    }
}

// ── Range merge (used by both verified and durable trackers) ───────────

/// Merge overlapping or adjacent ranges.
fn merge_ranges(mut ranges: Vec<VerifiedRange>) -> Vec<VerifiedRange> {
    if ranges.is_empty() {
        return ranges;
    }
    ranges.sort_by_key(|r| r.from_index);
    let mut merged = vec![ranges[0].clone()];
    for r in &ranges[1..] {
        let last = merged.last_mut().unwrap();
        if r.from_index <= last.to_index + 1 {
            // Overlapping or adjacent — extend.
            last.to_index = last.to_index.max(r.to_index);
            last.verified_at = last.verified_at.max(r.verified_at);
        } else {
            merged.push(r.clone());
        }
    }
    merged
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn empty_tracker_has_no_verified() {
        let tmp = TempDir::new().unwrap();
        let tracker = VerificationTracker::new(tmp.path());
        assert!(!tracker.is_verified(0));
        assert!(tracker.last_verified_index().is_none());
        assert!(!tracker.all_verified_up_to(0));
    }

    #[test]
    fn mark_and_check_verified() {
        let tmp = TempDir::new().unwrap();
        let tracker = VerificationTracker::new(tmp.path());

        tracker.mark_verified(0, 10, 1712592000000).unwrap();
        assert!(tracker.is_verified(0));
        assert!(tracker.is_verified(5));
        assert!(tracker.is_verified(10));
        assert!(!tracker.is_verified(11));
        assert_eq!(tracker.last_verified_index(), Some(10));
    }

    #[test]
    fn merge_overlapping_ranges() {
        let tmp = TempDir::new().unwrap();
        let tracker = VerificationTracker::new(tmp.path());

        tracker.mark_verified(0, 5, 1000).unwrap();
        tracker.mark_verified(3, 10, 2000).unwrap();

        let ranges = tracker.read_ranges();
        assert_eq!(ranges.len(), 1); // Merged into one.
        assert_eq!(ranges[0].from_index, 0);
        assert_eq!(ranges[0].to_index, 10);
    }

    #[test]
    fn merge_adjacent_ranges() {
        let tmp = TempDir::new().unwrap();
        let tracker = VerificationTracker::new(tmp.path());

        tracker.mark_verified(0, 5, 1000).unwrap();
        tracker.mark_verified(6, 10, 2000).unwrap();

        let ranges = tracker.read_ranges();
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].from_index, 0);
        assert_eq!(ranges[0].to_index, 10);
    }

    #[test]
    fn non_adjacent_ranges_stay_separate() {
        let tmp = TempDir::new().unwrap();
        let tracker = VerificationTracker::new(tmp.path());

        tracker.mark_verified(0, 5, 1000).unwrap();
        tracker.mark_verified(8, 10, 2000).unwrap();

        let ranges = tracker.read_ranges();
        assert_eq!(ranges.len(), 2);
        assert!(!tracker.is_verified(6));
        assert!(!tracker.is_verified(7));
        assert!(tracker.is_verified(8));
    }

    #[test]
    fn all_verified_up_to() {
        let tmp = TempDir::new().unwrap();
        let tracker = VerificationTracker::new(tmp.path());

        tracker.mark_verified(0, 100, 1000).unwrap();
        assert!(tracker.all_verified_up_to(50));
        assert!(tracker.all_verified_up_to(100));
        assert!(!tracker.all_verified_up_to(101));
    }
}
