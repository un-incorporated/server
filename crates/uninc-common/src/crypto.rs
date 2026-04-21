use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// Compute SHA-256 hash of arbitrary data.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Compute SHA-256 hash of multiple byte slices concatenated.
pub fn sha256_concat(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// Compute a query fingerprint by normalizing and hashing a SQL query.
///
/// Normalization: lowercase, replace all literal values with `?`.
/// This is a simplified version — the full SQL parser in the proxy module
/// does proper AST-based normalization.
pub fn fingerprint_query(normalized_query: &str) -> [u8; 32] {
    sha256(normalized_query.as_bytes())
}

/// Derive a per-user chain identifier from a user ID using a per-deployment secret.
///
/// Computes `HMAC-SHA-256(key = salt, msg = UTF-8(user_id))` per §3.2 of Uninc Access
/// Transparency v1, returning the hex-encoded 32-byte MAC as a filesystem-safe
/// pseudonymous directory name. HMAC (rather than `SHA-256(salt || user_id)`) is the
/// cryptographically correct primitive for a keyed pseudorandom identifier function
/// per RFC 2104, and matches the threat model described in §10.3 of the specification.
pub fn hash_user_id(user_id: &str, salt: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(salt.as_bytes())
        .expect("HMAC-SHA-256 accepts a key of any length");
    mac.update(user_id.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_deterministic() {
        let h1 = sha256(b"hello world");
        let h2 = sha256(b"hello world");
        assert_eq!(h1, h2);
    }

    #[test]
    fn sha256_different_inputs() {
        let h1 = sha256(b"hello");
        let h2 = sha256(b"world");
        assert_ne!(h1, h2);
    }

    #[test]
    fn sha256_concat_works() {
        let h1 = sha256(b"helloworld");
        let h2 = sha256_concat(&[b"hello", b"world"]);
        assert_eq!(h1, h2);
    }

    #[test]
    fn user_id_hash_is_hex() {
        let h = hash_user_id("user_42", "salt123");
        assert_eq!(h.len(), 64); // 32 bytes = 64 hex chars
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn user_id_hash_deterministic() {
        let h1 = hash_user_id("user_42", "salt");
        let h2 = hash_user_id("user_42", "salt");
        assert_eq!(h1, h2);
    }

    #[test]
    fn user_id_hash_different_salt() {
        let h1 = hash_user_id("user_42", "salt_a");
        let h2 = hash_user_id("user_42", "salt_b");
        assert_ne!(h1, h2);
    }
}
