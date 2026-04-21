//! KeyStore trait and implementations (LocalFileKeystore for dev, VaultKeystore for prod).

use crate::encryption;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum KeystoreError {
    #[error("key not found for user: {0}")]
    KeyNotFound(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Trait for key management backends.
pub trait KeyStore: Send + Sync {
    /// Get the encryption key for a user. Creates one if it doesn't exist.
    fn get_or_create_key(&self, user_id_hash: &str) -> Result<[u8; 32], KeystoreError>;

    /// Get the encryption key for a user. Returns error if not found.
    fn get_key(&self, user_id_hash: &str) -> Result<[u8; 32], KeystoreError>;

    /// Destroy the encryption key for a user (GDPR deletion).
    fn destroy_key(&self, user_id_hash: &str) -> Result<(), KeystoreError>;
}

/// Local file-based keystore for development.
/// Keys stored as hex in `{keys_dir}/{user_id_hash}.key`
pub struct LocalFileKeystore {
    keys_dir: PathBuf,
    cache: RwLock<HashMap<String, [u8; 32]>>,
}

impl LocalFileKeystore {
    pub fn new(keys_dir: &Path) -> Result<Self, KeystoreError> {
        fs::create_dir_all(keys_dir)?;
        Ok(Self {
            keys_dir: keys_dir.to_path_buf(),
            cache: RwLock::new(HashMap::new()),
        })
    }

    fn key_path(&self, user_id_hash: &str) -> PathBuf {
        self.keys_dir.join(format!("{}.key", user_id_hash))
    }
}

impl KeyStore for LocalFileKeystore {
    fn get_or_create_key(&self, user_id_hash: &str) -> Result<[u8; 32], KeystoreError> {
        // Check cache first
        if let Some(key) = self.cache.read().unwrap().get(user_id_hash) {
            return Ok(*key);
        }

        let path = self.key_path(user_id_hash);
        let key = if path.exists() {
            let hex_str = fs::read_to_string(&path)?;
            let bytes = hex::decode(hex_str.trim()).map_err(|_| {
                KeystoreError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid hex key",
                ))
            })?;
            let mut key = [0u8; 32];
            key.copy_from_slice(&bytes);
            key
        } else {
            let key = encryption::generate_key();
            fs::write(&path, hex::encode(key))?;
            key
        };

        self.cache
            .write()
            .unwrap()
            .insert(user_id_hash.to_string(), key);
        Ok(key)
    }

    fn get_key(&self, user_id_hash: &str) -> Result<[u8; 32], KeystoreError> {
        if let Some(key) = self.cache.read().unwrap().get(user_id_hash) {
            return Ok(*key);
        }

        let path = self.key_path(user_id_hash);
        if !path.exists() {
            return Err(KeystoreError::KeyNotFound(user_id_hash.to_string()));
        }

        let hex_str = fs::read_to_string(&path)?;
        let bytes = hex::decode(hex_str.trim()).map_err(|_| {
            KeystoreError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid hex key",
            ))
        })?;
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        self.cache
            .write()
            .unwrap()
            .insert(user_id_hash.to_string(), key);
        Ok(key)
    }

    fn destroy_key(&self, user_id_hash: &str) -> Result<(), KeystoreError> {
        self.cache.write().unwrap().remove(user_id_hash);
        let path = self.key_path(user_id_hash);
        if path.exists() {
            fs::remove_file(&path)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_retrieve_key() {
        let tmp = tempfile::tempdir().unwrap();
        let ks = LocalFileKeystore::new(tmp.path()).unwrap();
        let key1 = ks.get_or_create_key("abc123").unwrap();
        let key2 = ks.get_or_create_key("abc123").unwrap();
        assert_eq!(key1, key2);
    }

    #[test]
    fn different_users_different_keys() {
        let tmp = tempfile::tempdir().unwrap();
        let ks = LocalFileKeystore::new(tmp.path()).unwrap();
        let k1 = ks.get_or_create_key("user1").unwrap();
        let k2 = ks.get_or_create_key("user2").unwrap();
        assert_ne!(k1, k2);
    }

    #[test]
    fn destroy_key_works() {
        let tmp = tempfile::tempdir().unwrap();
        let ks = LocalFileKeystore::new(tmp.path()).unwrap();
        ks.get_or_create_key("user1").unwrap();
        ks.destroy_key("user1").unwrap();
        assert!(ks.get_key("user1").is_err());
    }
}
