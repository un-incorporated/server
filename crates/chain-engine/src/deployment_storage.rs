//! On-disk storage for the org-level chain.
//!
//! Identical format to per-user chain storage but at a fixed path:
//! ```text
//! /data/chains/_deployment/
//!   chain.dat   — JSON-lines, one DeploymentChainEntry per line (append-only)
//!   chain.idx   — entry_number → byte_offset (binary, 8 bytes per entry)
//!   head.hash   — current head hash (32 bytes, raw)
//!   meta.json   — creation time, entry count
//! ```
//!
//! The `_deployment` directory name uses an underscore prefix which cannot collide
//! with per-user chain directories (those are 64-char hex strings from
//! SHA-256 hashing).

use crate::deployment_entry::DeploymentChainEntry;
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read as _, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DeploymentStorageError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),

    #[error("entry deserialization failed at byte offset {offset}: {reason}")]
    Deserialize { offset: u64, reason: String },

    #[error("deployment chain directory not found")]
    ChainNotFound,
}

/// Metadata for the deployment chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentChainMeta {
    pub created_at: i64,
    pub entry_count: u64,
}

/// Handle for reading and writing the deployment chain on disk.
pub struct DeploymentChainStore {
    dir: PathBuf,
}

impl DeploymentChainStore {
    /// Open (or create) the deployment chain store.
    pub fn open(base_path: &Path) -> Result<Self, DeploymentStorageError> {
        let dir = base_path.join("_deployment");
        fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    fn chain_dat(&self) -> PathBuf {
        self.dir.join("chain.dat")
    }
    fn chain_idx(&self) -> PathBuf {
        self.dir.join("chain.idx")
    }
    fn head_hash_path(&self) -> PathBuf {
        self.dir.join("head.hash")
    }
    fn meta_path(&self) -> PathBuf {
        self.dir.join("meta.json")
    }

    /// Append an entry to the deployment chain.
    ///
    /// Write order (crash-safe):
    /// 1. Append entry to chain.dat (fsync)
    /// 2. Append offset to chain.idx
    /// 3. Update head.hash
    /// 4. Update meta.json entry count
    pub fn append(&self, entry: &DeploymentChainEntry) -> Result<(), DeploymentStorageError> {
        let mut dat_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.chain_dat())?;

        let offset = dat_file.seek(SeekFrom::End(0))?;

        let mut line =
            serde_json::to_string(entry).map_err(|e| DeploymentStorageError::Deserialize {
                offset,
                reason: e.to_string(),
            })?;
        line.push('\n');
        dat_file.write_all(line.as_bytes())?;
        dat_file.sync_all()?;

        let mut idx_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.chain_idx())?;
        idx_file.write_all(&offset.to_le_bytes())?;

        fs::write(self.head_hash_path(), entry.entry_hash)?;

        self.update_meta_count(entry.index + 1)?;
        Ok(())
    }

    /// Read the current head hash, or None if chain doesn't exist yet.
    pub fn read_head_hash(&self) -> Result<Option<[u8; 32]>, DeploymentStorageError> {
        let path = self.head_hash_path();
        if !path.exists() {
            return Ok(None);
        }
        let bytes = fs::read(&path)?;
        if bytes.len() != 32 {
            return Ok(None);
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&bytes);
        Ok(Some(hash))
    }

    /// Read a single entry by index.
    pub fn read_entry(&self, index: u64) -> Result<DeploymentChainEntry, DeploymentStorageError> {
        let offset = self.read_offset(index)?;
        let file = File::open(self.chain_dat())?;
        let mut reader = BufReader::new(file);
        reader.seek(SeekFrom::Start(offset))?;
        let mut line = String::new();
        reader.read_line(&mut line)?;
        serde_json::from_str(&line).map_err(|e| DeploymentStorageError::Deserialize {
            offset,
            reason: e.to_string(),
        })
    }

    /// Read all entries in the deployment chain.
    pub fn read_all(&self) -> Result<Vec<DeploymentChainEntry>, DeploymentStorageError> {
        let path = self.chain_dat();
        if !path.exists() {
            return Ok(Vec::new());
        }
        let file = File::open(&path)?;
        let reader = BufReader::new(file);
        let mut entries = Vec::new();
        let mut byte_offset = 0u64;

        for line in reader.lines() {
            let line = line?;
            if line.is_empty() {
                continue;
            }
            let entry: DeploymentChainEntry =
                serde_json::from_str(&line).map_err(|e| DeploymentStorageError::Deserialize {
                    offset: byte_offset,
                    reason: e.to_string(),
                })?;
            byte_offset += line.len() as u64 + 1;
            entries.push(entry);
        }
        Ok(entries)
    }

    /// Read a paginated range of entries.
    pub fn read_range(
        &self,
        start_index: u64,
        limit: usize,
    ) -> Result<Vec<DeploymentChainEntry>, DeploymentStorageError> {
        let all = self.read_all()?;
        let start = start_index as usize;
        if start >= all.len() {
            return Ok(Vec::new());
        }
        let end = (start + limit).min(all.len());
        Ok(all[start..end].to_vec())
    }

    /// Get the entry count.
    pub fn entry_count(&self) -> Result<u64, DeploymentStorageError> {
        match self.read_meta()? {
            Some(m) => Ok(m.entry_count),
            None => Ok(0),
        }
    }

    /// Check if this chain exists (has at least a genesis entry).
    pub fn exists(&self) -> bool {
        self.chain_dat().exists()
    }

    /// Read metadata.
    pub fn read_meta(&self) -> Result<Option<DeploymentChainMeta>, DeploymentStorageError> {
        let path = self.meta_path();
        if !path.exists() {
            return Ok(None);
        }
        let contents = fs::read_to_string(&path)?;
        let meta: DeploymentChainMeta =
            serde_json::from_str(&contents).map_err(|e| DeploymentStorageError::Deserialize {
                offset: 0,
                reason: e.to_string(),
            })?;
        Ok(Some(meta))
    }

    /// Write metadata.
    pub fn write_meta(&self, meta: &DeploymentChainMeta) -> Result<(), DeploymentStorageError> {
        let json =
            serde_json::to_string_pretty(meta).map_err(|e| DeploymentStorageError::Deserialize {
                offset: 0,
                reason: e.to_string(),
            })?;
        fs::write(self.meta_path(), json)?;
        Ok(())
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn read_offset(&self, index: u64) -> Result<u64, DeploymentStorageError> {
        let path = self.chain_idx();
        let mut file = File::open(&path)?;
        file.seek(SeekFrom::Start(index * 8))?;
        let mut buf = [0u8; 8];
        file.read_exact(&mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }

    fn update_meta_count(&self, count: u64) -> Result<(), DeploymentStorageError> {
        let mut meta = self.read_meta()?.unwrap_or(DeploymentChainMeta {
            created_at: chrono::Utc::now().timestamp_millis(),
            entry_count: 0,
        });
        meta.entry_count = count;
        self.write_meta(&meta)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deployment_entry::{build_deployment_event, DeploymentChainEntry};
    use tempfile::TempDir;
    use uninc_common::{ActionType, ActorType, DeploymentCategory};

    fn sample_entry(index: u64, prev_hash: [u8; 32], timestamp: i64) -> DeploymentChainEntry {
        let payload = build_deployment_event(
            "admin",
            ActorType::Admin,
            DeploymentCategory::AdminAccess,
            ActionType::Read,
            "users",
            "test",
            None,
            None,
            None,
            None,
        );
        DeploymentChainEntry::deployment(index, prev_hash, timestamp, payload).unwrap()
    }

    #[test]
    fn create_and_read_deployment_chain() {
        let tmp = TempDir::new().unwrap();
        let store = DeploymentChainStore::open(tmp.path()).unwrap();

        let e0 = sample_entry(0, [0u8; 32], 1_712_592_000);
        store.append(&e0).unwrap();

        assert_eq!(store.entry_count().unwrap(), 1);
        assert!(store.exists());

        let head = store.read_head_hash().unwrap().unwrap();
        assert_eq!(head, e0.entry_hash);

        let entries = store.read_all().unwrap();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].verify_hash());
    }

    #[test]
    fn append_and_link() {
        let tmp = TempDir::new().unwrap();
        let store = DeploymentChainStore::open(tmp.path()).unwrap();

        let e0 = sample_entry(0, [0u8; 32], 1_000);
        store.append(&e0).unwrap();

        let e1 = sample_entry(1, e0.entry_hash, 2_000);
        store.append(&e1).unwrap();

        assert_eq!(store.entry_count().unwrap(), 2);

        let entries = store.read_all().unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1].prev_hash, entries[0].entry_hash);

        let single = store.read_entry(1).unwrap();
        assert_eq!(single.entry_hash, e1.entry_hash);
    }

    #[test]
    fn read_range_pagination() {
        let tmp = TempDir::new().unwrap();
        let store = DeploymentChainStore::open(tmp.path()).unwrap();

        let mut prev_hash = [0u8; 32];
        for i in 0..10 {
            let entry = sample_entry(i, prev_hash, 1_000 + i as i64);
            prev_hash = entry.entry_hash;
            store.append(&entry).unwrap();
        }

        let page = store.read_range(3, 4).unwrap();
        assert_eq!(page.len(), 4);
        assert_eq!(page[0].index, 3);
        assert_eq!(page[3].index, 6);
    }

    #[test]
    fn underscore_deployment_dir_created() {
        let tmp = TempDir::new().unwrap();
        let _store = DeploymentChainStore::open(tmp.path()).unwrap();
        assert!(tmp.path().join("_deployment").exists());
    }
}
