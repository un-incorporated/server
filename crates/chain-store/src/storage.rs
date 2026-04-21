//! On-disk storage: chain.dat (entries), chain.idx (index), head.hash, meta.json.
//!
//! Directory structure per user:
//! ```text
//! /data/chains/{user_id_hash}/
//!   chain.dat   — JSON-lines, one entry per line (append-only)
//!   chain.idx   — entry_number → byte_offset (binary, 8 bytes per entry)
//!   head.hash   — current head hash (32 bytes, raw)
//!   meta.json   — creation time, entry count, key ID
//! ```

use crate::entry::ChainEntry;
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read as _, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use thiserror::Error;
use uninc_common::crypto::hash_user_id;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),

    #[error("entry deserialization failed at byte offset {offset}: {reason}")]
    Deserialize { offset: u64, reason: String },

    #[error("chain directory not found for user hash: {0}")]
    ChainNotFound(String),

    #[error("corrupted index file")]
    CorruptedIndex,
}

/// Metadata stored in meta.json for each user's chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainMeta {
    pub user_id_hash: String,
    pub created_at: i64,
    pub entry_count: u64,
    pub key_id: Option<String>,
}

/// Handle for reading and writing a single user's chain on disk.
pub struct ChainStore {
    dir: PathBuf,
}

impl ChainStore {
    /// Open (or create) a chain store for the given user.
    pub fn open(base_path: &Path, user_id: &str, salt: &str) -> Result<Self, StorageError> {
        let user_hash = hash_user_id(user_id, salt);
        let dir = base_path.join(&user_hash);
        fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    /// Open a chain store by its directory hash directly.
    pub fn open_by_hash(base_path: &Path, user_hash: &str) -> Result<Self, StorageError> {
        let dir = base_path.join(user_hash);
        if !dir.exists() {
            return Err(StorageError::ChainNotFound(user_hash.to_string()));
        }
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

    /// Append an entry to the chain.
    ///
    /// Write order (crash-safe):
    /// 1. Append entry to chain.dat (fsync)
    /// 2. Append offset to chain.idx
    /// 3. Update head.hash
    /// 4. Update meta.json entry count
    pub fn append(&self, entry: &ChainEntry) -> Result<(), StorageError> {
        let mut dat_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.chain_dat())?;

        let offset = dat_file.seek(SeekFrom::End(0))?;

        let mut line = serde_json::to_string(entry).map_err(|e| StorageError::Deserialize {
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
    pub fn read_head_hash(&self) -> Result<Option<[u8; 32]>, StorageError> {
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
    pub fn read_entry(&self, index: u64) -> Result<ChainEntry, StorageError> {
        let offset = self.read_offset(index)?;
        let file = File::open(self.chain_dat())?;
        let mut reader = BufReader::new(file);
        reader.seek(SeekFrom::Start(offset))?;
        let mut line = String::new();
        reader.read_line(&mut line)?;
        serde_json::from_str(&line).map_err(|e| StorageError::Deserialize {
            offset,
            reason: e.to_string(),
        })
    }

    /// Read all entries in the chain.
    pub fn read_all(&self) -> Result<Vec<ChainEntry>, StorageError> {
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
            let entry: ChainEntry =
                serde_json::from_str(&line).map_err(|e| StorageError::Deserialize {
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
    ) -> Result<Vec<ChainEntry>, StorageError> {
        let all = self.read_all()?;
        let start = start_index as usize;
        if start >= all.len() {
            return Ok(Vec::new());
        }
        let end = (start + limit).min(all.len());
        Ok(all[start..end].to_vec())
    }

    /// Get the entry count.
    pub fn entry_count(&self) -> Result<u64, StorageError> {
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
    pub fn read_meta(&self) -> Result<Option<ChainMeta>, StorageError> {
        let path = self.meta_path();
        if !path.exists() {
            return Ok(None);
        }
        let contents = fs::read_to_string(&path)?;
        let meta: ChainMeta = serde_json::from_str(&contents).map_err(|e| {
            StorageError::Deserialize {
                offset: 0,
                reason: e.to_string(),
            }
        })?;
        Ok(Some(meta))
    }

    /// Write metadata.
    pub fn write_meta(&self, meta: &ChainMeta) -> Result<(), StorageError> {
        let json = serde_json::to_string_pretty(meta).map_err(|e| StorageError::Deserialize {
            offset: 0,
            reason: e.to_string(),
        })?;
        fs::write(self.meta_path(), json)?;
        Ok(())
    }

    /// Delete the entire chain directory.
    pub fn delete(&self) -> Result<(), StorageError> {
        if self.dir.exists() {
            fs::remove_dir_all(&self.dir)?;
        }
        Ok(())
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn read_offset(&self, index: u64) -> Result<u64, StorageError> {
        let path = self.chain_idx();
        let mut file = File::open(&path)?;
        file.seek(SeekFrom::Start(index * 8))?;
        let mut buf = [0u8; 8];
        file.read_exact(&mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }

    fn update_meta_count(&self, count: u64) -> Result<(), StorageError> {
        let mut meta = self.read_meta()?.unwrap_or(ChainMeta {
            user_id_hash: self
                .dir
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned(),
            created_at: chrono::Utc::now().timestamp(),
            entry_count: 0,
            key_id: None,
        });
        meta.entry_count = count;
        self.write_meta(&meta)
    }
}

/// List all user chain directories under the base path.
pub fn list_chain_dirs(base_path: &Path) -> Result<Vec<String>, StorageError> {
    let mut hashes = Vec::new();
    if !base_path.exists() {
        return Ok(hashes);
    }
    for entry in fs::read_dir(base_path)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            if let Some(name) = entry.file_name().to_str() {
                if name.len() == 64 && name.chars().all(|c| c.is_ascii_hexdigit()) {
                    hashes.push(name.to_string());
                }
            }
        }
    }
    Ok(hashes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::{
        AccessAction, AccessActorType, AccessEvent, AccessScope, Protocol,
    };

    fn sample_access_event() -> AccessEvent {
        AccessEvent {
            actor_id: "admin".into(),
            actor_type: AccessActorType::Admin,
            actor_label: "Jane".into(),
            protocol: Protocol::Postgres,
            action: AccessAction::Read,
            resource: "users".into(),
            affected_user_ids: vec![],
            query_fingerprint: hex::encode([0u8; 32]),
            query_shape: None,
            scope: AccessScope::default(),
            source_ip: "127.0.0.1".into(),
            session_id: "00000000-0000-0000-0000-000000000000".into(),
            correlation_id: None,
        }
    }

    #[test]
    fn append_and_read_entries() {
        let tmp = tempfile::tempdir().unwrap();
        let store = ChainStore::open(tmp.path(), "user_42", "salt").unwrap();

        let e0 = ChainEntry::access(0, [0u8; 32], 1_000, sample_access_event()).unwrap();
        store.append(&e0).unwrap();

        let e1 = ChainEntry::access(1, e0.entry_hash, 2_000, sample_access_event()).unwrap();
        store.append(&e1).unwrap();

        let all = store.read_all().unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].index, 0);
        assert_eq!(all[1].index, 1);
        assert_eq!(all[1].prev_hash, e0.entry_hash);
    }

    #[test]
    fn read_entry_by_index() {
        let tmp = tempfile::tempdir().unwrap();
        let store = ChainStore::open(tmp.path(), "user_42", "salt").unwrap();

        let e0 = ChainEntry::access(0, [0u8; 32], 1_000, sample_access_event()).unwrap();
        store.append(&e0).unwrap();
        let e1 = ChainEntry::access(1, e0.entry_hash, 2_000, sample_access_event()).unwrap();
        store.append(&e1).unwrap();

        let entry = store.read_entry(1).unwrap();
        assert_eq!(entry.index, 1);
    }

    #[test]
    fn head_hash_updates() {
        let tmp = tempfile::tempdir().unwrap();
        let store = ChainStore::open(tmp.path(), "user_42", "salt").unwrap();
        assert!(store.read_head_hash().unwrap().is_none());

        let e0 = ChainEntry::access(0, [0u8; 32], 1_000, sample_access_event()).unwrap();
        store.append(&e0).unwrap();
        assert_eq!(store.read_head_hash().unwrap().unwrap(), e0.entry_hash);
    }

    #[test]
    fn entry_count_tracks() {
        let tmp = tempfile::tempdir().unwrap();
        let store = ChainStore::open(tmp.path(), "user_42", "salt").unwrap();
        assert_eq!(store.entry_count().unwrap(), 0);
        let e0 = ChainEntry::access(0, [0u8; 32], 1_000, sample_access_event()).unwrap();
        store.append(&e0).unwrap();
        assert_eq!(store.entry_count().unwrap(), 1);
    }

    #[test]
    fn list_chain_dirs_works() {
        let tmp = tempfile::tempdir().unwrap();
        let e = ChainEntry::access(0, [0u8; 32], 1_000, sample_access_event()).unwrap();
        ChainStore::open(tmp.path(), "user_1", "salt")
            .unwrap()
            .append(&e)
            .unwrap();
        ChainStore::open(tmp.path(), "user_2", "salt")
            .unwrap()
            .append(&e)
            .unwrap();
        let dirs = list_chain_dirs(tmp.path()).unwrap();
        assert_eq!(dirs.len(), 2);
    }

    #[test]
    fn delete_chain() {
        let tmp = tempfile::tempdir().unwrap();
        let store = ChainStore::open(tmp.path(), "user_42", "salt").unwrap();
        let e0 = ChainEntry::access(0, [0u8; 32], 1_000, sample_access_event()).unwrap();
        store.append(&e0).unwrap();
        assert!(store.exists());
        store.delete().unwrap();
        assert!(!store.exists());
    }
}
