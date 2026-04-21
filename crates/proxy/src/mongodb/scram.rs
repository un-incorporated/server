//! SCRAM handshake username extraction for MongoDB authentication.
//!
//! MongoDB authenticates via `saslStart` / `saslContinue` commands using
//! SCRAM-SHA-1 or SCRAM-SHA-256. The `saslStart` payload carries the
//! client-first-message in the format: `n,,n=<username>,r=<nonce>`.
//!
//! We also handle the `isMaster` / `hello` command which can carry
//! `saslSupportedMechs` as `<db>.<username>`.

use bson::Document;
use tracing::debug;

/// Extract the username from a `saslStart` command's SCRAM payload.
///
/// The binary payload contains a SCRAM client-first-message:
/// ```text
/// n,,n=username,r=clientnonce
/// ```
///
/// Returns `None` if the document is not a `saslStart` or the payload
/// cannot be parsed.
pub fn extract_username_from_sasl_start(doc: &Document) -> Option<String> {
    // Ensure this is actually a saslStart command.
    let _ = doc.get_i32("saslStart").ok().or_else(|| {
        // Some drivers send saslStart as the first key with value 1
        doc.get("saslStart")?;
        Some(1)
    })?;

    let payload = extract_binary_payload(doc)?;
    let payload_str = String::from_utf8_lossy(payload);

    debug!(payload = %payload_str, "parsing SCRAM client-first-message");

    parse_scram_username(&payload_str)
}

/// Extract username from the SCRAM client-first-message string.
///
/// Format: `n,,n=<username>,r=<nonce>`
/// The GS2 header is `n,,` (no channel binding, no authzid).
fn parse_scram_username(message: &str) -> Option<String> {
    for part in message.split(',') {
        if let Some(username) = part.strip_prefix("n=") {
            if !username.is_empty() {
                return Some(username.to_string());
            }
        }
    }
    None
}

/// Extract the binary payload from a saslStart document.
///
/// The `payload` field is a BSON Binary (subtype Generic).
fn extract_binary_payload(doc: &Document) -> Option<&[u8]> {
    match doc.get("payload")? {
        bson::Bson::Binary(bin) => Some(&bin.bytes),
        _ => None,
    }
}

/// Extract a username from the `saslSupportedMechs` field of `isMaster` or `hello`.
///
/// The field value is `"<db>.<username>"`, e.g. `"admin.alice"`.
/// Returns the username portion.
pub fn extract_username_from_hello(doc: &Document) -> Option<String> {
    // Check if this is a hello or isMaster command.
    let is_hello = doc.get("hello").is_some()
        || doc.get("ismaster").is_some()
        || doc.get("isMaster").is_some();

    if !is_hello {
        return None;
    }

    let mechs = doc.get_str("saslSupportedMechs").ok()?;

    // Format: "db.username"
    let username = mechs.split_once('.')?.1;
    if username.is_empty() {
        return None;
    }

    debug!(username, "extracted username from saslSupportedMechs");
    Some(username.to_string())
}

/// Extract the database name from an `isMaster`, `hello`, or `saslStart` command.
///
/// MongoDB sends `$db` as a top-level field in OP_MSG.
pub fn extract_database(doc: &Document) -> Option<String> {
    doc.get_str("$db").ok().map(|s| s.to_string())
}

/// Determine if the document is a `saslContinue` command.
pub fn is_sasl_continue(doc: &Document) -> bool {
    doc.get("saslContinue").is_some()
}

/// Determine if the document is a `saslStart` command.
pub fn is_sasl_start(doc: &Document) -> bool {
    doc.get("saslStart").is_some()
}

/// Determine if the document is an `isMaster` or `hello` handshake.
pub fn is_handshake(doc: &Document) -> bool {
    doc.get("hello").is_some()
        || doc.get("ismaster").is_some()
        || doc.get("isMaster").is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bson::{doc, spec::BinarySubtype, Binary};

    fn make_scram_payload(message: &str) -> bson::Bson {
        bson::Bson::Binary(Binary {
            subtype: BinarySubtype::Generic,
            bytes: message.as_bytes().to_vec(),
        })
    }

    #[test]
    fn extract_username_from_scram_sha256() {
        let doc = doc! {
            "saslStart": 1,
            "mechanism": "SCRAM-SHA-256",
            "payload": make_scram_payload("n,,n=alice,r=abc123def456"),
            "$db": "admin"
        };
        let username = extract_username_from_sasl_start(&doc);
        assert_eq!(username, Some("alice".to_string()));
    }

    #[test]
    fn extract_username_from_scram_sha1() {
        let doc = doc! {
            "saslStart": 1,
            "mechanism": "SCRAM-SHA-1",
            "payload": make_scram_payload("n,,n=bob,r=nonce789"),
            "$db": "admin"
        };
        let username = extract_username_from_sasl_start(&doc);
        assert_eq!(username, Some("bob".to_string()));
    }

    #[test]
    fn extract_username_with_special_chars() {
        let doc = doc! {
            "saslStart": 1,
            "mechanism": "SCRAM-SHA-256",
            "payload": make_scram_payload("n,,n=admin@company.com,r=nonce"),
            "$db": "admin"
        };
        let username = extract_username_from_sasl_start(&doc);
        assert_eq!(username, Some("admin@company.com".to_string()));
    }

    #[test]
    fn non_sasl_start_returns_none() {
        let doc = doc! {
            "find": "users",
            "filter": {},
            "$db": "mydb"
        };
        assert!(extract_username_from_sasl_start(&doc).is_none());
    }

    #[test]
    fn extract_from_hello_sasl_supported_mechs() {
        let doc = doc! {
            "hello": 1,
            "saslSupportedMechs": "admin.alice",
            "$db": "admin"
        };
        let username = extract_username_from_hello(&doc);
        assert_eq!(username, Some("alice".to_string()));
    }

    #[test]
    fn extract_from_ismaster_sasl_supported_mechs() {
        let doc = doc! {
            "isMaster": 1,
            "saslSupportedMechs": "mydb.charlie",
            "$db": "admin"
        };
        let username = extract_username_from_hello(&doc);
        assert_eq!(username, Some("charlie".to_string()));
    }

    #[test]
    fn hello_without_sasl_mechs_returns_none() {
        let doc = doc! {
            "hello": 1,
            "$db": "admin"
        };
        assert!(extract_username_from_hello(&doc).is_none());
    }

    #[test]
    fn extract_database_from_doc() {
        let doc = doc! {
            "find": "users",
            "$db": "production"
        };
        assert_eq!(extract_database(&doc), Some("production".to_string()));
    }

    #[test]
    fn is_handshake_detects_hello() {
        assert!(is_handshake(&doc! { "hello": 1 }));
        assert!(is_handshake(&doc! { "isMaster": 1 }));
        assert!(is_handshake(&doc! { "ismaster": 1 }));
        assert!(!is_handshake(&doc! { "find": "users" }));
    }

    #[test]
    fn is_sasl_start_and_continue() {
        assert!(is_sasl_start(&doc! { "saslStart": 1 }));
        assert!(!is_sasl_start(&doc! { "saslContinue": 1 }));
        assert!(is_sasl_continue(&doc! { "saslContinue": 1 }));
        assert!(!is_sasl_continue(&doc! { "saslStart": 1 }));
    }

    #[test]
    fn parse_scram_username_basic() {
        assert_eq!(
            parse_scram_username("n,,n=testuser,r=abc"),
            Some("testuser".to_string())
        );
    }

    #[test]
    fn parse_scram_username_empty_returns_none() {
        assert_eq!(parse_scram_username("n,,n=,r=abc"), None);
    }
}
