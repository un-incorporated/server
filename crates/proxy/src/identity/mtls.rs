//! mTLS client certificate validation stub.
//!
//! When `IdentityMode::MtlsSourceCredential` is active, this module
//! validates the client certificate presented during the TLS handshake
//! against the configured app certificate. If the cert matches, the
//! connection is additionally trusted as originating from the app.
//!
//! V1: stub — returns `false` (no mTLS validation). Will be implemented
//! when TLS termination is added to the proxy.

use uninc_common::config::MtlsConfig;

/// Result of mTLS client certificate validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MtlsResult {
    /// Client presented a valid app certificate.
    ValidAppCert,
    /// Client presented a certificate that doesn't match the app cert.
    UnknownCert,
    /// No client certificate was presented.
    NoCert,
    /// mTLS is not configured.
    Disabled,
}

/// Validate a client certificate against the configured mTLS settings.
///
/// # Arguments
/// * `_peer_cert_der` - DER-encoded client certificate bytes (if any)
/// * `_config` - mTLS configuration from uninc.yml
///
/// # Returns
/// `MtlsResult` indicating validation outcome.
pub fn validate_client_cert(
    _peer_cert_der: Option<&[u8]>,
    _config: Option<&MtlsConfig>,
) -> MtlsResult {
    // V1 stub: mTLS validation not yet implemented.
    // When implemented, this will:
    // 1. Parse the DER-encoded peer certificate
    // 2. Compare its public key / fingerprint against config.app_cert
    // 3. Verify the chain against config.ca_cert
    MtlsResult::Disabled
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_returns_disabled() {
        assert_eq!(validate_client_cert(None, None), MtlsResult::Disabled);
    }

    #[test]
    fn stub_with_cert_returns_disabled() {
        let fake_cert = b"fake-cert-bytes";
        let config = MtlsConfig {
            enabled: true,
            app_cert: "/path/to/app.crt".into(),
            ca_cert: "/path/to/ca.crt".into(),
        };
        assert_eq!(
            validate_client_cert(Some(fake_cert), Some(&config)),
            MtlsResult::Disabled
        );
    }
}
