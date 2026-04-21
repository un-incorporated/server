//! Per-user write locks using DashMap<UserId, Mutex>.

use dashmap::DashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Per-user chain write locks.
///
/// Two different users' chains can be appended to simultaneously.
/// Only appends to the SAME user's chain are serialized.
pub struct ChainLocks {
    locks: DashMap<String, Arc<Mutex<()>>>,
}

impl ChainLocks {
    pub fn new() -> Self {
        Self {
            locks: DashMap::new(),
        }
    }

    /// Get (or create) the lock for a specific user.
    pub fn get(&self, user_id: &str) -> Arc<Mutex<()>> {
        self.locks
            .entry(user_id.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    /// Remove the lock for a user (after chain deletion).
    pub fn remove(&self, user_id: &str) {
        self.locks.remove(user_id);
    }
}

impl Default for ChainLocks {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn locks_are_per_user() {
        let locks = ChainLocks::new();
        let l1 = locks.get("user1");
        let l2 = locks.get("user2");
        // Both can be acquired simultaneously
        let _g1 = l1.lock().await;
        let _g2 = l2.lock().await;
    }

    #[tokio::test]
    async fn same_user_serialized() {
        let locks = ChainLocks::new();
        let l1 = locks.get("user1");
        let l2 = locks.get("user1");
        // Same user, same lock
        assert!(Arc::ptr_eq(&l1, &l2));
    }
}
