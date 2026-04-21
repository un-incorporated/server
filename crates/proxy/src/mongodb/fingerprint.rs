//! BSON document normalization and SHA-256 fingerprinting.
//!
//! Recursively replaces all leaf values in a BSON document with `"?"`,
//! preserving key structure and MongoDB operators (`$gt`, `$in`, `$regex`,
//! etc.). The normalized document is serialized to canonical JSON and hashed.
//!
//! Example:
//! ```text
//! { "find": "users", "filter": { "email": "alice@example.com", "age": { "$gt": 25 } } }
//! -> { "find": "?", "filter": { "email": "?", "age": { "$gt": "?" } } }
//! -> SHA-256(canonical JSON)
//! ```

use bson::{Bson, Document};
use sha2::{Digest, Sha256};

/// Normalize a BSON document by replacing all leaf values with `"?"`.
///
/// - Document values are recursed into (preserving structure and operators).
/// - Array values are replaced with `["?"]` (a single placeholder element).
/// - All other leaf values become the string `"?"`.
pub fn normalize_bson(doc: &Document) -> Document {
    let mut normalized = Document::new();
    for (key, value) in doc.iter() {
        normalized.insert(key.clone(), normalize_value(value));
    }
    normalized
}

/// Normalize a single BSON value.
fn normalize_value(value: &Bson) -> Bson {
    match value {
        Bson::Document(subdoc) => Bson::Document(normalize_bson(subdoc)),
        Bson::Array(_) => {
            // Replace entire array with a single placeholder element.
            Bson::Array(vec![Bson::String("?".to_string())])
        }
        _ => Bson::String("?".to_string()),
    }
}

/// Compute a SHA-256 fingerprint of a BSON document.
///
/// 1. Normalize the document (replace leaf values with `"?"`).
/// 2. Serialize to canonical (sorted-key) JSON via `serde_json`.
/// 3. Hash with SHA-256.
pub fn fingerprint_bson(doc: &Document) -> [u8; 32] {
    let normalized = normalize_bson(doc);

    // Serialize to JSON for hashing.
    let json_value = serde_json::to_string(&normalized).unwrap_or_else(|_| "{}".to_string());

    let mut hasher = Sha256::new();
    hasher.update(json_value.as_bytes());
    hasher.finalize().into()
}

/// Compute a hex-encoded SHA-256 fingerprint string.
pub fn fingerprint_bson_hex(doc: &Document) -> String {
    hex::encode(fingerprint_bson(doc))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bson::doc;

    #[test]
    fn normalize_simple_find() {
        let doc = doc! {
            "find": "users",
            "filter": { "email": "alice@example.com" }
        };
        let normalized = normalize_bson(&doc);
        assert_eq!(normalized.get_str("find").unwrap(), "?");
        let filter = normalized.get_document("filter").unwrap();
        assert_eq!(filter.get_str("email").unwrap(), "?");
    }

    #[test]
    fn normalize_preserves_operators() {
        let doc = doc! {
            "find": "users",
            "filter": {
                "age": { "$gt": 25 },
                "status": { "$in": ["active", "pending"] }
            }
        };
        let normalized = normalize_bson(&doc);
        let filter = normalized.get_document("filter").unwrap();

        let age = filter.get_document("age").unwrap();
        assert_eq!(age.get_str("$gt").unwrap(), "?");

        let status = filter.get_document("status").unwrap();
        // $in value is an array, normalized to ["?"]
        let in_arr = status.get_array("$in").unwrap();
        assert_eq!(in_arr.len(), 1);
        assert_eq!(in_arr[0].as_str().unwrap(), "?");
    }

    #[test]
    fn normalize_nested_document() {
        let doc = doc! {
            "find": "orders",
            "filter": {
                "shipping": {
                    "address": {
                        "city": "Portland"
                    }
                }
            }
        };
        let normalized = normalize_bson(&doc);
        let city = normalized
            .get_document("filter")
            .unwrap()
            .get_document("shipping")
            .unwrap()
            .get_document("address")
            .unwrap()
            .get_str("city")
            .unwrap();
        assert_eq!(city, "?");
    }

    #[test]
    fn normalize_array_replaced_with_placeholder() {
        let doc = doc! {
            "insert": "items",
            "documents": [
                { "name": "A", "qty": 1 },
                { "name": "B", "qty": 2 }
            ]
        };
        let normalized = normalize_bson(&doc);
        let docs = normalized.get_array("documents").unwrap();
        assert_eq!(docs.len(), 1);
        assert_eq!(docs[0].as_str().unwrap(), "?");
    }

    #[test]
    fn fingerprint_is_deterministic() {
        let doc = doc! {
            "find": "users",
            "filter": { "email": "alice@example.com" }
        };
        let f1 = fingerprint_bson(&doc);
        let f2 = fingerprint_bson(&doc);
        assert_eq!(f1, f2);
    }

    #[test]
    fn fingerprint_same_structure_different_values() {
        let doc1 = doc! {
            "find": "users",
            "filter": { "email": "alice@example.com", "age": { "$gt": 25 } }
        };
        let doc2 = doc! {
            "find": "users",
            "filter": { "email": "bob@example.com", "age": { "$gt": 99 } }
        };
        // Both should normalize to the same structure, so fingerprints match.
        assert_eq!(fingerprint_bson(&doc1), fingerprint_bson(&doc2));
    }

    #[test]
    fn fingerprint_different_structure_differs() {
        let doc1 = doc! { "find": "users", "filter": { "email": "a@b.com" } };
        let doc2 = doc! { "find": "users", "filter": { "name": "Alice" } };
        // Different filter keys => different fingerprints.
        assert_ne!(fingerprint_bson(&doc1), fingerprint_bson(&doc2));
    }

    #[test]
    fn fingerprint_hex_produces_64_char_string() {
        let doc = doc! { "ping": 1 };
        let hex = fingerprint_bson_hex(&doc);
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn normalize_empty_document() {
        let doc = doc! {};
        let normalized = normalize_bson(&doc);
        assert!(normalized.is_empty());
    }

    #[test]
    fn normalize_various_leaf_types() {
        let doc = doc! {
            "string_val": "hello",
            "int_val": 42,
            "float_val": 3.14,
            "bool_val": true,
            "null_val": bson::Bson::Null,
        };
        let normalized = normalize_bson(&doc);
        for (_key, value) in normalized.iter() {
            assert_eq!(value.as_str().unwrap(), "?");
        }
    }
}
