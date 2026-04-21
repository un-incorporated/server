//! S3-compatible durable backup for chain data.
//!
//! All chain entries are dual-written: local disk (hot, fast) + S3 (durable).
//! When entries are evicted from local disk by the LRU cache, the S3 copy
//! is the only remaining copy. The :9091 chain API and the CLI fall back to
//! S3 for evicted entries.
//!
//! Key layout:
//! - Per-user chains: `chains/user/{user_id_hash}/entries.jsonl`
//! - Deployment chain: `chains/deployment/entries.jsonl`
//! - Head hashes: `chains/{type}/{id}/head.hash`

use s3::creds::Credentials;
use s3::{Bucket, Region};
use thiserror::Error;
use tracing::{debug, error};
use uninc_common::config::ChainS3Config;

#[derive(Debug, Error)]
pub enum S3StorageError {
    #[error("S3 error: {0}")]
    S3(String),
    #[error("credentials error: {0}")]
    Credentials(String),
}

/// S3-compatible storage client for chain data backup.
pub struct S3ChainStorage {
    bucket: Box<Bucket>,
}

impl S3ChainStorage {
    /// Create a new S3 storage client from config.
    pub fn new(config: &ChainS3Config) -> Result<Self, S3StorageError> {
        let region = Region::Custom {
            region: config.region.clone(),
            endpoint: config.endpoint.clone(),
        };
        let credentials = Credentials::new(
            Some(&config.access_key),
            Some(&config.secret_key),
            None,
            None,
            None,
        )
        .map_err(|e| S3StorageError::Credentials(e.to_string()))?;

        let bucket = Bucket::new(&config.bucket, region, credentials)
            .map_err(|e| S3StorageError::S3(e.to_string()))?
            .with_path_style();

        Ok(Self { bucket })
    }

    /// Upload a serialized chain entry (JSON line) to S3.
    ///
    /// Key: `chains/{chain_type}/{chain_id}/{index}.json`
    pub async fn put_entry(
        &self,
        chain_type: &str,
        chain_id: &str,
        index: u64,
        json_bytes: &[u8],
    ) -> Result<(), S3StorageError> {
        let key = format!("chains/{chain_type}/{chain_id}/{index:010}.json");
        self.bucket
            .put_object(&key, json_bytes)
            .await
            .map_err(|e| S3StorageError::S3(e.to_string()))?;
        debug!(key, "chain entry uploaded to S3");
        Ok(())
    }

    /// Read a single chain entry from S3.
    pub async fn get_entry(
        &self,
        chain_type: &str,
        chain_id: &str,
        index: u64,
    ) -> Result<Vec<u8>, S3StorageError> {
        let key = format!("chains/{chain_type}/{chain_id}/{index:010}.json");
        let response = self
            .bucket
            .get_object(&key)
            .await
            .map_err(|e| S3StorageError::S3(e.to_string()))?;
        Ok(response.to_vec())
    }

    /// Upload the head hash for a chain.
    pub async fn put_head(
        &self,
        chain_type: &str,
        chain_id: &str,
        hash: &[u8; 32],
    ) -> Result<(), S3StorageError> {
        let key = format!("chains/{chain_type}/{chain_id}/head.hash");
        self.bucket
            .put_object(&key, hash)
            .await
            .map_err(|e| S3StorageError::S3(e.to_string()))?;
        Ok(())
    }

    /// Check if a chain entry exists in S3.
    pub async fn entry_exists(
        &self,
        chain_type: &str,
        chain_id: &str,
        index: u64,
    ) -> bool {
        let key = format!("chains/{chain_type}/{chain_id}/{index:010}.json");
        match self.bucket.head_object(&key).await {
            Ok(_) => true,
            Err(e) => {
                debug!(key, error = %e, "S3 entry not found");
                false
            }
        }
    }

    /// Best-effort upload — logs errors but doesn't fail the caller.
    /// Used for dual-write on append where local disk is authoritative.
    pub async fn put_entry_best_effort(
        &self,
        chain_type: &str,
        chain_id: &str,
        index: u64,
        json_bytes: &[u8],
    ) {
        if let Err(e) = self.put_entry(chain_type, chain_id, index, json_bytes).await {
            error!(
                chain_type,
                chain_id,
                index,
                error = %e,
                "S3 backup write failed (local copy is authoritative, will retry on next append)"
            );
        }
    }

    /// Delete every object under `chains/{chain_type}/{chain_id}/`.
    ///
    /// Lists then deletes. Used by the erasure path (§8.1) and the
    /// retention reaper (§8.2). Returns the number of objects deleted,
    /// or the first S3 error encountered.
    pub async fn delete_prefix(
        &self,
        chain_type: &str,
        chain_id: &str,
    ) -> Result<usize, S3StorageError> {
        let prefix = format!("chains/{chain_type}/{chain_id}/");
        let pages = self
            .bucket
            .list(prefix.clone(), None)
            .await
            .map_err(|e| S3StorageError::S3(e.to_string()))?;

        let mut deleted = 0usize;
        for page in pages {
            for obj in page.contents {
                self.bucket
                    .delete_object(&obj.key)
                    .await
                    .map_err(|e| S3StorageError::S3(e.to_string()))?;
                deleted += 1;
            }
        }
        debug!(prefix, deleted, "chain prefix deleted from S3");
        Ok(deleted)
    }
}
