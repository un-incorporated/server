//! S3 path normalization and fingerprinting.
//!
//! Normalizes S3 request paths by replacing user-specific segments with
//! placeholders, then hashes the result for fingerprinting.
//!
//! Example:
//! `GET /uploads/users/42/avatar.jpg` -> `SHA-256("GET /uploads/users/{user_id}/*")`

use sha2::{Digest, Sha256};

use crate::s3::resolver::CompiledPattern;

/// Fingerprint an S3 request by normalizing the path and hashing it.
///
/// The normalized form replaces matched user_id segments with `{user_id}`
/// and trailing path components with `*`.
pub fn fingerprint_request(
    method: &str,
    bucket: &str,
    key: &str,
    patterns: &[CompiledPattern],
) -> [u8; 32] {
    let normalized = normalize_path(method, bucket, key, patterns);
    let mut hasher = Sha256::new();
    hasher.update(normalized.as_bytes());
    hasher.finalize().into()
}

/// Normalize an S3 path for fingerprinting.
///
/// Replaces matched user_id capture groups with `{user_id}` and any
/// path components after the user_id with `*`.
///
/// If no pattern matches, uses the raw method + bucket + key.
pub fn normalize_path(
    method: &str,
    bucket: &str,
    key: &str,
    patterns: &[CompiledPattern],
) -> String {
    for pattern in patterns {
        if pattern.bucket != "*" && pattern.bucket != bucket {
            continue;
        }

        if let Some(caps) = pattern.regex.captures(key) {
            if let Some(uid_match) = caps.name("user_id") {
                let start = uid_match.start();
                let end = uid_match.end();

                // Build normalized path:
                // prefix up to user_id + {user_id} + wildcard for the rest
                let prefix = &key[..start];
                let suffix_start = end;
                let has_suffix = suffix_start < key.len();

                let normalized_key = if has_suffix {
                    format!("{prefix}{{user_id}}/*")
                } else {
                    format!("{prefix}{{user_id}}")
                };

                return format!("{method} /{bucket}/{normalized_key}");
            }
        }
    }

    // No pattern matched — use raw path
    format!("{method} /{bucket}/{key}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::s3::resolver::compile_patterns;
    use uninc_common::config::S3UserDataPattern;

    fn test_patterns() -> Vec<CompiledPattern> {
        compile_patterns(&[S3UserDataPattern {
            bucket: "user-data".to_string(),
            key_pattern: r"^uploads/users/(?P<user_id>[^/]+)/.*$".to_string(),
        }])
    }

    #[test]
    fn normalize_user_path() {
        let patterns = test_patterns();
        let norm = normalize_path("GET", "user-data", "uploads/users/42/avatar.jpg", &patterns);
        assert_eq!(norm, "GET /user-data/uploads/users/{user_id}/*");
    }

    #[test]
    fn fingerprint_is_deterministic() {
        let patterns = test_patterns();
        let f1 =
            fingerprint_request("GET", "user-data", "uploads/users/42/avatar.jpg", &patterns);
        let f2 =
            fingerprint_request("GET", "user-data", "uploads/users/99/photo.png", &patterns);
        // Both normalize to the same pattern, so fingerprints should be equal
        assert_eq!(f1, f2);
    }

    #[test]
    fn different_methods_different_fingerprints() {
        let patterns = test_patterns();
        let f_get =
            fingerprint_request("GET", "user-data", "uploads/users/42/avatar.jpg", &patterns);
        let f_put =
            fingerprint_request("PUT", "user-data", "uploads/users/42/avatar.jpg", &patterns);
        assert_ne!(f_get, f_put);
    }

    #[test]
    fn no_pattern_match_uses_raw() {
        let patterns = test_patterns();
        let norm = normalize_path("GET", "other-bucket", "system/config.json", &patterns);
        assert_eq!(norm, "GET /other-bucket/system/config.json");
    }
}
