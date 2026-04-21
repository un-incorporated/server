//! AES-256-GCM per-user encryption/decryption of chain data.

use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use rand::RngCore;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EncryptionError {
    #[error("encryption failed: {0}")]
    Encrypt(String),
    #[error("decryption failed: {0}")]
    Decrypt(String),
    #[error("invalid key length")]
    InvalidKeyLength,
}

/// Encrypt data with AES-256-GCM.
/// Returns: nonce (12 bytes) || ciphertext
pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, EncryptionError> {
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|_| EncryptionError::InvalidKeyLength)?;
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| EncryptionError::Encrypt(e.to_string()))?;
    let mut result = Vec::with_capacity(12 + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// Decrypt data encrypted with AES-256-GCM.
/// Input: nonce (12 bytes) || ciphertext
pub fn decrypt(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, EncryptionError> {
    if data.len() < 12 {
        return Err(EncryptionError::Decrypt("data too short".into()));
    }
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|_| EncryptionError::InvalidKeyLength)?;
    let nonce = Nonce::from_slice(&data[..12]);
    let plaintext = cipher
        .decrypt(nonce, &data[12..])
        .map_err(|e| EncryptionError::Decrypt(e.to_string()))?;
    Ok(plaintext)
}

/// Generate a random 256-bit key.
pub fn generate_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = generate_key();
        let plaintext = b"hello world, this is secret data";
        let encrypted = encrypt(&key, plaintext).unwrap();
        let decrypted = decrypt(&key, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_key_fails() {
        let key1 = generate_key();
        let key2 = generate_key();
        let encrypted = encrypt(&key1, b"secret").unwrap();
        assert!(decrypt(&key2, &encrypted).is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = generate_key();
        let mut encrypted = encrypt(&key, b"secret").unwrap();
        if let Some(last) = encrypted.last_mut() {
            *last ^= 0xff;
        }
        assert!(decrypt(&key, &encrypted).is_err());
    }
}
