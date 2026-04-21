//! Appendix F byte-count regression test (spec finding S2).
//!
//! Reproduces the entry-0 payload shown in Appendix F of
//! [protocol/draft-wang-data-access-transparency-00.md], runs it through the reference
//! `serde_jcs` canonicalizer, and asserts the byte count matches what the
//! spec's `payload_length` field declares. If the spec and reference
//! implementation disagree on bytes, a conformant third-party implementer
//! following the spec will produce a chain whose hashes diverge from the
//! reference — exactly the S2 failure mode this test exists to prevent.

use serde_json::json;

/// The `payload_length` value currently stated in Appendix F, entry 0.
/// Keep in sync with [protocol/draft-wang-data-access-transparency-00.md] §F.1.
const APPENDIX_F_ENTRY_0_PAYLOAD_LENGTH: usize = 0x0000_0196; // 406 octets

#[test]
fn appendix_f_entry_0_canonicalizes_to_declared_length() {
    let payload = json!({
        "action": "read",
        "actor_id": "app:app_user",
        "actor_label": "app:app_user",
        "actor_type": "app",
        "affected_user_ids": ["a1b2c3"],
        "protocol": "postgres",
        "query_fingerprint": "0000000000000000000000000000000000000000000000000000000000000000",
        "query_shape": "SELECT * FROM users WHERE id = $1",
        "resource": "users",
        "scope": { "bytes": 256, "rows": 1 },
        "session_id": "d1e2f3a4-0000-0000-0000-000000000000",
        "source_ip": "10.0.1.5"
    });
    let mut buf = Vec::new();
    serde_jcs::to_writer(&mut buf, &payload).expect("JCS canonicalize payload");

    assert_eq!(
        buf.len(),
        APPENDIX_F_ENTRY_0_PAYLOAD_LENGTH,
        "Appendix F says payload_length = {} (0x{:08X}) but serde_jcs produced {} octets. \
         Either the spec's declared length is wrong (update Appendix F) or the payload text \
         in Appendix F has drifted from the reference canonicalization. Canonical bytes:\n{}",
        APPENDIX_F_ENTRY_0_PAYLOAD_LENGTH,
        APPENDIX_F_ENTRY_0_PAYLOAD_LENGTH,
        buf.len(),
        String::from_utf8_lossy(&buf),
    );
}
