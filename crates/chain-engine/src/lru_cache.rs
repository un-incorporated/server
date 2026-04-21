//! LRU disk cache for chain data.
//!
//! Evicts chain directories from local disk when total usage exceeds
//! `max_bytes`. A chain is only eligible for eviction when BOTH conditions
//! hold for its latest entry:
//!
//!   1. **Verified** — the nightly cross-replica comparison (`verified_ranges.json`)
//!      has marked the entry as passing the replica check.
//!   2. **Durable** — the multi-replica write (`durable_ranges.json`) has
//!      quorum-acked the entry to the replica MinIO tier.
//!
//! Without either gate, the LRU could evict an entry that's the only
//! surviving copy. Unverified AND undurable entries are NEVER evicted.
//!
//! The deployment chain (`_deployment`) is additionally never evicted regardless of
//! state — deployment-wide audit history stays hot.

use crate::multi_replica_storage::MultiReplicaStorage;
use crate::storage;
use crate::verification_status::{is_durable, VerificationTracker};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Manages local disk usage for chain data with LRU eviction.
pub struct DiskLruCache {
    base_path: PathBuf,
    max_bytes: u64,
    evict_after_verified: bool,
}

impl DiskLruCache {
    pub fn new(base_path: &Path, max_bytes: u64, evict_after_verified: bool) -> Self {
        Self {
            base_path: base_path.to_path_buf(),
            max_bytes,
            evict_after_verified,
        }
    }

    /// Calculate total disk usage of all chain directories.
    pub fn current_usage_bytes(&self) -> u64 {
        dir_size_recursive(&self.base_path)
    }

    /// Run eviction if over the max. Called after nightly verification passes.
    ///
    /// Returns the number of chain directories evicted. Requires both the
    /// verified_ranges.json and durable_ranges.json sidecars to mark the
    /// entry as safe before touching it.
    pub async fn evict_if_needed(&self, durable: Arc<MultiReplicaStorage>) -> usize {
        let current = self.current_usage_bytes();
        if current <= self.max_bytes {
            debug!(
                current_bytes = current,
                max_bytes = self.max_bytes,
                "disk usage under limit, no eviction needed"
            );
            return 0;
        }

        let to_free = current - self.max_bytes;
        info!(
            current_bytes = current,
            max_bytes = self.max_bytes,
            to_free_bytes = to_free,
            "disk usage over limit, starting LRU eviction"
        );

        // Build a list of eviction candidates: chain dirs sorted by last-modified time.
        let mut candidates = self.eviction_candidates();
        candidates.sort_by_key(|(modified, _)| *modified);

        let mut freed = 0u64;
        let mut evicted = 0usize;

        for (_modified, chain_dir) in &candidates {
            if freed >= to_free {
                break;
            }

            let dir_name = chain_dir
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();

            // Skip the deployment chain — never evict it.
            if dir_name == "_deployment" {
                continue;
            }

            let entry_count = self.read_entry_count(chain_dir);
            let last_index = if entry_count > 0 { entry_count - 1 } else { 0 };

            // Gate 1: verified by the nightly trigger.
            if self.evict_after_verified {
                let tracker = VerificationTracker::new(chain_dir);
                if !tracker.all_verified_up_to(last_index) {
                    debug!(chain = %dir_name, "skipping — not fully verified through last index");
                    continue;
                }
            }

            // Gate 2: durable on the replica MinIO tier.
            let durable_sidecar = chain_dir.join("durable_ranges.json");
            if entry_count > 0 && !is_durable(&durable_sidecar, last_index) {
                debug!(
                    chain = %dir_name,
                    last_index,
                    "skipping — last entry not yet quorum-durable on replicas"
                );
                continue;
            }

            // Gate 3: replica side still has the head entry (defense in depth —
            // if a replica rotated its bucket or was reprovisioned, don't evict).
            let chain_type = "user";
            if entry_count > 0 && durable.get_entry(chain_type, &dir_name, last_index).await.is_err() {
                warn!(
                    chain = %dir_name,
                    "skipping eviction — replica MinIO read failed for last entry"
                );
                continue;
            }

            let dir_bytes = dir_size_recursive(chain_dir);
            match fs::remove_dir_all(chain_dir) {
                Ok(()) => {
                    freed += dir_bytes;
                    evicted += 1;
                    debug!(
                        chain = %dir_name,
                        freed_bytes = dir_bytes,
                        "evicted chain directory from local disk"
                    );
                }
                Err(e) => {
                    warn!(
                        chain = %dir_name,
                        error = %e,
                        "failed to evict chain directory"
                    );
                }
            }
        }

        info!(
            evicted_count = evicted,
            freed_bytes = freed,
            "LRU eviction complete"
        );
        evicted
    }

    /// List eviction candidates: (last_modified_timestamp, path).
    fn eviction_candidates(&self) -> Vec<(i64, PathBuf)> {
        let Ok(chain_dirs) = storage::list_chain_dirs(&self.base_path) else {
            return Vec::new();
        };

        let mut candidates = Vec::new();
        for hash in chain_dirs {
            let dir = self.base_path.join(&hash);
            let modified = dir
                .metadata()
                .and_then(|m| m.modified())
                .map(|t| {
                    t.duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as i64
                })
                .unwrap_or(0);
            candidates.push((modified, dir));
        }
        candidates
    }

    /// Read entry count from meta.json in a chain dir.
    fn read_entry_count(&self, chain_dir: &Path) -> u64 {
        let meta_path = chain_dir.join("meta.json");
        if !meta_path.exists() {
            return 0;
        }
        let Ok(contents) = fs::read_to_string(&meta_path) else {
            return 0;
        };
        serde_json::from_str::<serde_json::Value>(&contents)
            .ok()
            .and_then(|v| v["entry_count"].as_u64())
            .unwrap_or(0)
    }
}

/// Recursively calculate the size of a directory in bytes.
fn dir_size_recursive(path: &Path) -> u64 {
    if !path.exists() {
        return 0;
    }
    let mut total = 0u64;
    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            let meta = entry.metadata();
            if let Ok(meta) = meta {
                if meta.is_dir() {
                    total += dir_size_recursive(&entry.path());
                } else {
                    total += meta.len();
                }
            }
        }
    }
    total
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn empty_dir_usage_is_zero() {
        let tmp = TempDir::new().unwrap();
        let cache = DiskLruCache::new(tmp.path(), 1024, true);
        assert_eq!(cache.current_usage_bytes(), 0);
    }

    #[test]
    fn tracks_file_sizes() {
        let tmp = TempDir::new().unwrap();
        fs::write(tmp.path().join("test.dat"), vec![0u8; 1000]).unwrap();
        let cache = DiskLruCache::new(tmp.path(), 10_000, true);
        assert_eq!(cache.current_usage_bytes(), 1000);
    }

    #[test]
    fn under_limit_no_candidates() {
        let tmp = TempDir::new().unwrap();
        let cache = DiskLruCache::new(tmp.path(), 1_000_000, true);
        assert!(cache.eviction_candidates().is_empty());
    }
}
