//! Identity classification — determines whether a connection is APP or ADMIN.
//!
//! Uses a multi-signal matrix: source IP + credential matching.

use std::net::{IpAddr, ToSocketAddrs};

use tracing::{debug, warn};
use uuid::Uuid;

use uninc_common::config::{AppSource, IdentityConfig, IdentityMode};
use uninc_common::types::{AdminIdentity, ConnectionClass, Protocol};

/// Classify an incoming connection as App, Admin, or Suspicious.
///
/// Classification matrix (SourceCredential mode):
///
/// | Source matches app? | Credential matches app? | Result      |
/// |---------------------|-------------------------|-------------|
/// | Yes                 | Yes                     | App         |
/// | Yes                 | No                      | Suspicious  |
/// | No                  | Yes                     | Admin (stolen cred) |
/// | No                  | No                      | Admin       |
pub fn classify(
    source_ip: IpAddr,
    credential: &str,
    protocol: Protocol,
    config: &IdentityConfig,
) -> ConnectionClass {
    let protocol_key = protocol_key(protocol);

    let cred_is_app = credential_matches_app(credential, protocol_key, config);

    match config.mode {
        IdentityMode::Credential => {
            if cred_is_app {
                debug!(credential, "classified as App (credential match)");
                ConnectionClass::App
            } else {
                debug!(credential, "classified as Admin (credential mode)");
                ConnectionClass::Admin(AdminIdentity {
                    username: credential.to_string(),
                    source_ip,
                    session_id: Uuid::new_v4(),
                })
            }
        }
        IdentityMode::SourceCredential | IdentityMode::MtlsSourceCredential => {
            let source_is_app = source_matches_app(source_ip, &config.app_sources);

            match (source_is_app, cred_is_app) {
                (true, true) => {
                    debug!(%source_ip, credential, "classified as App");
                    ConnectionClass::App
                }
                (true, false) => {
                    warn!(
                        %source_ip,
                        credential,
                        "suspicious: app source with non-app credential"
                    );
                    ConnectionClass::Suspicious(format!(
                        "app source {source_ip} used non-app credential '{credential}'"
                    ))
                }
                (false, true) => {
                    warn!(
                        %source_ip,
                        credential,
                        "admin connection using app credential (possible credential theft)"
                    );
                    ConnectionClass::Admin(AdminIdentity {
                        username: format!("stolen:{credential}"),
                        source_ip,
                        session_id: Uuid::new_v4(),
                    })
                }
                (false, false) => {
                    debug!(%source_ip, credential, "classified as Admin");
                    ConnectionClass::Admin(AdminIdentity {
                        username: credential.to_string(),
                        source_ip,
                        session_id: Uuid::new_v4(),
                    })
                }
            }
        }
    }
}

/// Map protocol enum to the config key used in credential maps.
fn protocol_key(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Postgres => "postgres",
        Protocol::MongoDB => "mongodb",
        Protocol::S3 => "s3",
    }
}

/// Check whether the credential matches a known app credential for this protocol.
fn credential_matches_app(credential: &str, protocol_key: &str, config: &IdentityConfig) -> bool {
    let Some(entries) = config.app_credentials.get(protocol_key) else {
        return false;
    };
    entries.iter().any(|entry| {
        entry
            .username
            .as_deref()
            .is_some_and(|u| u == credential)
            || entry
                .access_key
                .as_deref()
                .is_some_and(|k| k == credential)
    })
}

/// Check whether the source IP matches any configured app source.
///
/// Resolves hostnames to IPs if needed.
fn source_matches_app(source_ip: IpAddr, app_sources: &[AppSource]) -> bool {
    for source in app_sources {
        // Direct IP match
        if let Some(ref ip_str) = source.ip {
            if let Ok(configured_ip) = ip_str.parse::<IpAddr>() {
                if configured_ip == source_ip {
                    return true;
                }
            }
            // Support CIDR-style /32 notation (just strip it)
            if let Some(bare) = ip_str.strip_suffix("/32") {
                if let Ok(configured_ip) = bare.parse::<IpAddr>() {
                    if configured_ip == source_ip {
                        return true;
                    }
                }
            }
        }

        // Hostname resolution
        if let Some(ref hostname) = source.hostname {
            if let Ok(addrs) = (hostname.as_str(), 0u16).to_socket_addrs() {
                for addr in addrs {
                    if addr.ip() == source_ip {
                        return true;
                    }
                }
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use uninc_common::config::CredentialEntry;

    fn make_config(mode: IdentityMode) -> IdentityConfig {
        let mut app_credentials = HashMap::new();
        app_credentials.insert(
            "s3".to_string(),
            vec![CredentialEntry {
                username: None,
                access_key: Some("APPKEY123".to_string()),
            }],
        );
        app_credentials.insert(
            "postgres".to_string(),
            vec![CredentialEntry {
                username: Some("app_user".to_string()),
                access_key: None,
            }],
        );

        IdentityConfig {
            mode,
            app_sources: vec![AppSource {
                hostname: None,
                ip: Some("10.0.0.5".to_string()),
            }],
            admin_credentials: HashMap::new(),
            app_credentials,
            behavioral_fingerprinting: false,
            mtls: None,
        }
    }

    // --- SourceCredential mode: all 4 matrix cells ---

    #[test]
    fn source_app_cred_app_returns_app() {
        let config = make_config(IdentityMode::SourceCredential);
        let result = classify(
            "10.0.0.5".parse().unwrap(),
            "APPKEY123",
            Protocol::S3,
            &config,
        );
        assert_eq!(result, ConnectionClass::App);
    }

    #[test]
    fn source_app_cred_not_app_returns_suspicious() {
        let config = make_config(IdentityMode::SourceCredential);
        let result = classify(
            "10.0.0.5".parse().unwrap(),
            "ADMINKEY999",
            Protocol::S3,
            &config,
        );
        assert!(matches!(result, ConnectionClass::Suspicious(_)));
    }

    #[test]
    fn source_not_app_cred_app_returns_admin_stolen() {
        let config = make_config(IdentityMode::SourceCredential);
        let result = classify(
            "192.168.1.100".parse().unwrap(),
            "APPKEY123",
            Protocol::S3,
            &config,
        );
        match &result {
            ConnectionClass::Admin(id) => {
                assert!(id.username.starts_with("stolen:"));
            }
            other => panic!("expected Admin, got {other:?}"),
        }
    }

    #[test]
    fn source_not_app_cred_not_app_returns_admin() {
        let config = make_config(IdentityMode::SourceCredential);
        let result = classify(
            "192.168.1.100".parse().unwrap(),
            "ADMINKEY999",
            Protocol::S3,
            &config,
        );
        match &result {
            ConnectionClass::Admin(id) => {
                assert_eq!(id.username, "ADMINKEY999");
            }
            other => panic!("expected Admin, got {other:?}"),
        }
    }

    // --- Credential-only mode ---

    #[test]
    fn credential_mode_app_cred_returns_app() {
        let config = make_config(IdentityMode::Credential);
        let result = classify(
            "192.168.1.100".parse().unwrap(), // source doesn't matter
            "APPKEY123",
            Protocol::S3,
            &config,
        );
        assert_eq!(result, ConnectionClass::App);
    }

    #[test]
    fn credential_mode_non_app_cred_returns_admin() {
        let config = make_config(IdentityMode::Credential);
        let result = classify(
            "10.0.0.5".parse().unwrap(), // source doesn't matter
            "ADMINKEY999",
            Protocol::S3,
            &config,
        );
        assert!(matches!(result, ConnectionClass::Admin(_)));
    }

    // --- Postgres protocol uses username matching ---

    #[test]
    fn postgres_credential_match_by_username() {
        let config = make_config(IdentityMode::Credential);
        let result = classify(
            "10.0.0.5".parse().unwrap(),
            "app_user",
            Protocol::Postgres,
            &config,
        );
        assert_eq!(result, ConnectionClass::App);
    }

    // --- Source matching edge cases ---

    #[test]
    fn source_matches_cidr_32() {
        let sources = vec![AppSource {
            hostname: None,
            ip: Some("10.0.0.5/32".to_string()),
        }];
        assert!(source_matches_app("10.0.0.5".parse().unwrap(), &sources));
    }

    #[test]
    fn source_no_match() {
        let sources = vec![AppSource {
            hostname: None,
            ip: Some("10.0.0.5".to_string()),
        }];
        assert!(!source_matches_app("10.0.0.6".parse().unwrap(), &sources));
    }
}
