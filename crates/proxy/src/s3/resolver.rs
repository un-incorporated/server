//! S3 user ID resolver — match object keys against configured patterns.
//!
//! Given an S3 key like `uploads/users/42/avatar.jpg` and a pattern like
//! `uploads/users/(?P<user_id>[^/]+)/.*`, extract `42` as the affected user.

use regex::Regex;
use tracing::debug;

use uninc_common::config::S3UserDataPattern;

/// Compiled version of an S3UserDataPattern for efficient matching.
pub struct CompiledPattern {
    pub bucket: String,
    pub regex: Regex,
}

impl CompiledPattern {
    /// Compile an S3UserDataPattern. Returns `None` if the regex is invalid.
    pub fn compile(pattern: &S3UserDataPattern) -> Option<Self> {
        Regex::new(&pattern.key_pattern).ok().map(|regex| Self {
            bucket: pattern.bucket.clone(),
            regex,
        })
    }
}

/// Resolve affected user IDs from an S3 bucket + key using configured patterns.
///
/// Returns a deduplicated list of user IDs extracted via named capture group
/// `user_id` in the key patterns.
pub fn resolve_affected_users(
    bucket: &str,
    key: &str,
    patterns: &[CompiledPattern],
    excluded_prefixes: &[String],
) -> Vec<String> {
    // Check excluded prefixes first
    for prefix in excluded_prefixes {
        if key.starts_with(prefix.as_str()) {
            debug!(key, prefix, "key matches excluded prefix, skipping");
            return Vec::new();
        }
    }

    let mut user_ids = Vec::new();

    for pattern in patterns {
        // Bucket must match
        if pattern.bucket != "*" && pattern.bucket != bucket {
            continue;
        }

        if let Some(caps) = pattern.regex.captures(key) {
            if let Some(uid) = caps.name("user_id") {
                let id = uid.as_str().to_string();
                if !user_ids.contains(&id) {
                    user_ids.push(id);
                }
            }
        }
    }

    debug!(bucket, key, count = user_ids.len(), "resolved user IDs");
    user_ids
}

/// Compile all configured patterns, skipping any with invalid regex.
pub fn compile_patterns(patterns: &[S3UserDataPattern]) -> Vec<CompiledPattern> {
    patterns
        .iter()
        .filter_map(|p| {
            let compiled = CompiledPattern::compile(p);
            if compiled.is_none() {
                tracing::warn!(
                    bucket = %p.bucket,
                    pattern = %p.key_pattern,
                    "failed to compile S3 key pattern regex"
                );
            }
            compiled
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_patterns() -> Vec<CompiledPattern> {
        compile_patterns(&[
            S3UserDataPattern {
                bucket: "user-data".to_string(),
                key_pattern: r"^uploads/users/(?P<user_id>[^/]+)/.*$".to_string(),
            },
            S3UserDataPattern {
                bucket: "user-data".to_string(),
                key_pattern: r"^avatars/(?P<user_id>[^/]+)\.jpg$".to_string(),
            },
            S3UserDataPattern {
                bucket: "*".to_string(),
                key_pattern: r"^user-exports/(?P<user_id>[^/]+)/.*$".to_string(),
            },
        ])
    }

    #[test]
    fn match_uploads_pattern() {
        let patterns = make_patterns();
        let ids = resolve_affected_users(
            "user-data",
            "uploads/users/42/avatar.jpg",
            &patterns,
            &[],
        );
        assert_eq!(ids, vec!["42"]);
    }

    #[test]
    fn match_avatar_pattern() {
        let patterns = make_patterns();
        let ids = resolve_affected_users("user-data", "avatars/user99.jpg", &patterns, &[]);
        assert_eq!(ids, vec!["user99"]);
    }

    #[test]
    fn wildcard_bucket_matches_any() {
        let patterns = make_patterns();
        let ids = resolve_affected_users(
            "any-bucket",
            "user-exports/abc123/report.csv",
            &patterns,
            &[],
        );
        assert_eq!(ids, vec!["abc123"]);
    }

    #[test]
    fn no_match_returns_empty() {
        let patterns = make_patterns();
        let ids =
            resolve_affected_users("user-data", "system/config.json", &patterns, &[]);
        assert!(ids.is_empty());
    }

    #[test]
    fn wrong_bucket_no_match() {
        let patterns = make_patterns();
        let ids = resolve_affected_users(
            "wrong-bucket",
            "uploads/users/42/avatar.jpg",
            &patterns,
            &[],
        );
        assert!(ids.is_empty());
    }

    #[test]
    fn excluded_prefix_skips() {
        let patterns = make_patterns();
        let excluded = vec!["uploads/users/system/".to_string()];
        let ids = resolve_affected_users(
            "user-data",
            "uploads/users/system/internal.dat",
            &patterns,
            &excluded,
        );
        assert!(ids.is_empty());
    }

    #[test]
    fn deduplication() {
        // If the same user_id would be captured by multiple patterns,
        // it should appear only once.
        let patterns = compile_patterns(&[
            S3UserDataPattern {
                bucket: "b".to_string(),
                key_pattern: r"^data/(?P<user_id>[^/]+)/a$".to_string(),
            },
            S3UserDataPattern {
                bucket: "b".to_string(),
                key_pattern: r"^data/(?P<user_id>[^/]+)/.*$".to_string(),
            },
        ]);
        let ids = resolve_affected_users("b", "data/uid1/a", &patterns, &[]);
        assert_eq!(ids, vec!["uid1"]);
    }
}
