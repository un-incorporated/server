//! Extract access key ID from AWS SigV4 Authorization headers.
//!
//! Format:
//! ```text
//! AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,
//! SignedHeaders=host;range;x-amz-date, Signature=fe5f80f77d5fa3beca...
//! ```
//!
//! We extract `AKIAIOSFODNN7EXAMPLE` — just the access key ID.
//! The proxy does NOT verify the signature; that's the upstream S3's job.

use regex::Regex;
use std::sync::LazyLock;

static SIGV4_CREDENTIAL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"Credential=([A-Za-z0-9_\-]+)/").expect("invalid sigv4 regex")
});

/// Extract the AWS access key ID from an Authorization header value.
///
/// Returns `None` if the header doesn't contain a valid SigV4 Credential.
pub fn extract_access_key(authorization: &str) -> Option<&str> {
    SIGV4_CREDENTIAL_RE
        .captures(authorization)
        .and_then(|caps| caps.get(1))
        .map(|m| m.as_str())
}

/// Try to extract an access key from either the Authorization header
/// or query parameters (presigned URL case).
///
/// For presigned URLs, the credential is in `X-Amz-Credential` query param:
/// `?X-Amz-Credential=AKID/date/region/s3/aws4_request&...`
pub fn extract_access_key_from_query(query: &str) -> Option<String> {
    for param in query.split('&') {
        if let Some(value) = param.strip_prefix("X-Amz-Credential=") {
            // URL-decoded value: AKID/date/region/s3/aws4_request
            let decoded = urldecode(value);
            if let Some(slash_pos) = decoded.find('/') {
                return Some(decoded[..slash_pos].to_string());
            }
        }
    }
    None
}

/// Minimal URL decoding — handles %XX sequences.
fn urldecode(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.bytes();
    while let Some(b) = chars.next() {
        if b == b'%' {
            let hi = chars.next();
            let lo = chars.next();
            if let (Some(h), Some(l)) = (hi, lo) {
                let hex = [h, l];
                if let Ok(s) = std::str::from_utf8(&hex) {
                    if let Ok(byte) = u8::from_str_radix(s, 16) {
                        result.push(byte as char);
                        continue;
                    }
                }
            }
            // Malformed %-encoding, pass through
            result.push('%');
        } else {
            result.push(b as char);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_standard_sigv4() {
        let header = "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;range;x-amz-date, Signature=fe5f80f77d5fa3beca038a248ff027d0445342fe2855ddc963176630326f1024";
        assert_eq!(
            extract_access_key(header),
            Some("AKIAIOSFODNN7EXAMPLE")
        );
    }

    #[test]
    fn extract_custom_key_id() {
        let header =
            "AWS4-HMAC-SHA256 Credential=MY_APP_KEY_123/20240101/us-west-2/s3/aws4_request, SignedHeaders=host, Signature=abc";
        assert_eq!(extract_access_key(header), Some("MY_APP_KEY_123"));
    }

    #[test]
    fn no_credential_returns_none() {
        assert_eq!(extract_access_key("Bearer token123"), None);
    }

    #[test]
    fn empty_header_returns_none() {
        assert_eq!(extract_access_key(""), None);
    }

    #[test]
    fn extract_from_presigned_query() {
        let query = "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20130524T000000Z";
        let key = extract_access_key_from_query(query);
        assert_eq!(key.as_deref(), Some("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn presigned_no_credential_returns_none() {
        let query = "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Date=20130524T000000Z";
        assert_eq!(extract_access_key_from_query(query), None);
    }
}
