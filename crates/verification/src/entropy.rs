//! External entropy via the drand public randomness beacon.
//!
//! drand (https://drand.love) publishes a new round of 32-byte random
//! output every ~30 seconds, signed with BLS by a threshold of independent
//! operators. Anyone can fetch any round, verify its signature against the
//! public key of the chain, and use the randomness.
//!
//! We use drand to seed per-session role assignments (see assignment.rs)
//! so that the seed is:
//!   1. Public — anyone can re-derive the assignment after the fact.
//!   2. Unpredictable by us — the proxy can't cheat by picking a "lucky"
//!      round that puts a compromised replica in the Verifier slot.
//!   3. Cryptographically verifiable — the BLS signature proves the round
//!      came from drand and wasn't forged by the proxy.
//!
//! Egress containment and relays. A deployment whose proxy VM is egress-
//! contained may not be allowed to reach `drand.love` directly. In that
//! case, operators can configure an operator-controlled relay that
//! fetches drand on the deployment's behalf and returns the round
//! verbatim (including the BLS signature). The proxy verifies the BLS
//! signature locally against drand's hardcoded public key, so such a
//! relay is structurally a network hop, not a trust endpoint — it can
//! delay or drop rounds but cannot forge them.
//!
//! v1 ships with relay fetch + BLS signature verification + OS random
//! fallback. Every fetched drand round has its BLS signature verified
//! against the hardcoded League of Entropy public key before use (via
//! the `drand-verify` crate). If verification fails, the round is
//! rejected and the next relay is tried. If all relays fail or are
//! unreachable, the client falls back to OS random and records this as
//! `EntropySource::Fallback` so auditors can see it.
//!
//! The `UNINC_ENABLE_DRAND` env var gates whether drand is attempted
//! at all (default: true in production, false in local dev where the
//! drand relays may be unreachable).

use drand_verify::{G1Pubkey, Pubkey};
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime};
use tracing::{info, warn};

/// Default drand HTTP relays — direct League-of-Entropy endpoints.
/// Path shape matches drand's native API (`{base}/public/latest`).
/// Operators whose proxy VMs are egress-contained can override via
/// `DrandClient::with_relays` to point at an operator-controlled relay
/// that fronts drand; the BLS signature is verified locally in either
/// case so the relay is a network hop, not a trust endpoint.
const DEFAULT_RELAYS: &[&str] = &[
    "https://api.drand.sh",
    "https://api2.drand.sh",
    "https://api3.drand.sh",
];

/// The canonical drand "league-of-entropy" chain hash (mainnet, 30s interval).
pub const DEFAULT_CHAIN_HASH: &str =
    "8990e7a9aaed2ffed73dbd7092123d6f289930540d7651336225dc172e51b2ce";

/// League of Entropy mainnet public key (G1 point, hex-encoded).
/// This is the BLS public key used to verify drand round signatures.
/// Source: https://api.drand.sh/8990e7a9aaed2ffed73dbd7092123d6f289930540d7651336225dc172e51b2ce/info
/// Scheme: bls-unchained-g1-rfc9380 (G1Pubkey in drand-verify).
///
/// IMPORTANT: This key is hardcoded because it's the trust anchor for role
/// assignment entropy. If it were configurable, a compromised operator could
/// substitute a key they control and forge rounds. Hardcoding means the key
/// is auditable in source control and must survive code review to change.
const LOE_PUBLIC_KEY_HEX: &str = "868f005eb8e6e4ca0a47c8a77ceaa5309a47978a7c71bc5cce96366b5d7a569937c529eeda66c7293784a9402801af31";

/// Verify a drand round's BLS signature against the League of Entropy
/// public key. Returns `true` if the signature is valid, `false` if
/// verification fails or the inputs are malformed.
///
/// Uses the `drand-verify` crate which implements BLS12-381 verification
/// for drand's `bls-unchained-g1-rfc9380` scheme.
fn verify_drand_bls(round: &DrandRound) -> bool {
    let pk_bytes = match hex::decode(LOE_PUBLIC_KEY_HEX) {
        Ok(b) => b,
        Err(e) => {
            warn!(error = %e, "failed to decode LoE public key hex — this is a code bug");
            return false;
        }
    };

    let pubkey = match G1Pubkey::from_variable(&pk_bytes) {
        Ok(pk) => pk,
        Err(e) => {
            warn!(error = ?e, "failed to parse LoE public key — this is a code bug");
            return false;
        }
    };

    let sig_bytes = match hex::decode(&round.signature_hex) {
        Ok(b) => b,
        Err(e) => {
            warn!(error = %e, round = round.round, "invalid signature hex from drand relay");
            return false;
        }
    };

    // For unchained mode, previous_signature is not used in verification.
    // drand-verify's G1Pubkey::verify verifies (round, signature) against the public key.
    match pubkey.verify(round.round, b"", &sig_bytes) {
        Ok(valid) => valid,
        Err(e) => {
            warn!(error = ?e, round = round.round, "BLS verification failed");
            false
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DrandRound {
    pub round: u64,
    /// Hex-decoded 32-byte randomness output.
    #[serde(with = "hex_serde")]
    pub randomness: [u8; 32],
    /// Hex-encoded BLS signature. Left as a string because its length
    /// depends on the BLS scheme (48 or 96 bytes typically).
    pub signature_hex: String,
    pub previous_signature_hex: Option<String>,
    #[serde(skip, default = "default_fetched_at")]
    pub fetched_at: SystemTime,
}

fn default_fetched_at() -> SystemTime {
    SystemTime::now()
}

/// Where the seed came from. Stored on each assignment record so auditors
/// know whether to trust the drand signature or the fallback path.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EntropySource {
    /// Authentic drand round. `signature_hex` is the BLS signature that
    /// an auditor can verify against drand's published public key.
    Drand {
        round: u64,
        signature_hex: String,
    },
    /// Drand was unreachable at seed time. We used a deterministic hash
    /// of session inputs + wall clock as a fallback. NOT externally
    /// verifiable — flagged explicitly so auditors can see it.
    Fallback { reason: String },
}

#[derive(Debug, thiserror::Error)]
pub enum DrandError {
    #[error("http request failed: {0}")]
    Http(String),
    #[error("invalid response: {0}")]
    Parse(String),
    #[error("all relays failed")]
    AllRelaysFailed,
}

pub struct DrandClient {
    client: reqwest::Client,
    relays: Vec<String>,
    chain_hash: String,
}

impl DrandClient {
    pub fn new() -> Self {
        Self::with_relays(DEFAULT_RELAYS.iter().map(|s| s.to_string()).collect())
    }

    pub fn with_relays(relays: Vec<String>) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .user_agent("uninc-verifier/0.1")
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self {
            client,
            relays,
            chain_hash: DEFAULT_CHAIN_HASH.to_string(),
        }
    }

    /// Fetch the most recent drand round from any available relay and
    /// verify its BLS signature against the League of Entropy public key.
    ///
    /// If the signature is invalid (forged relay, MITM, corruption), the
    /// round is rejected and the next relay is tried. This is the trust
    /// anchor for role assignment entropy — without BLS verification, a
    /// compromised relay could steer the Fisher-Yates shuffle to put a
    /// specific replica in the Verifier slot.
    pub async fn latest_round(&self) -> Result<DrandRound, DrandError> {
        for relay in &self.relays {
            let url = format!("{}/public/latest", relay);
            match self.fetch_round(&url).await {
                Ok(round) => {
                    if verify_drand_bls(&round) {
                        info!(
                            relay,
                            round = round.round,
                            "drand round fetched and BLS-verified"
                        );
                        return Ok(round);
                    }
                    warn!(
                        relay,
                        round = round.round,
                        "drand BLS verification FAILED — relay may be compromised, trying next"
                    );
                }
                Err(e) => {
                    warn!(relay, error = %e, "drand relay failed, trying next");
                }
            }
        }
        Err(DrandError::AllRelaysFailed)
    }

    /// Fetch a specific round by number and verify its BLS signature.
    pub async fn round(&self, round_num: u64) -> Result<DrandRound, DrandError> {
        for relay in &self.relays {
            let url = format!("{}/public/{}", relay, round_num);
            match self.fetch_round(&url).await {
                Ok(r) => {
                    if verify_drand_bls(&r) {
                        info!(relay, round = r.round, "drand round fetched and BLS-verified");
                        return Ok(r);
                    }
                    warn!(relay, round = round_num, "drand BLS verification FAILED for specific round");
                }
                Err(e) => warn!(relay, round = round_num, error = %e, "drand round fetch failed"),
            }
        }
        Err(DrandError::AllRelaysFailed)
    }

    async fn fetch_round(&self, url: &str) -> Result<DrandRound, DrandError> {
        let resp = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|e| DrandError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(DrandError::Http(format!("status {}", resp.status())));
        }
        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| DrandError::Parse(e.to_string()))?;
        parse_drand_json(&body)
    }

    pub fn chain_hash(&self) -> &str {
        &self.chain_hash
    }
}

impl Default for DrandClient {
    fn default() -> Self {
        Self::new()
    }
}

fn parse_drand_json(v: &serde_json::Value) -> Result<DrandRound, DrandError> {
    let round = v
        .get("round")
        .and_then(|x| x.as_u64())
        .ok_or_else(|| DrandError::Parse("missing 'round'".into()))?;
    let randomness_hex = v
        .get("randomness")
        .and_then(|x| x.as_str())
        .ok_or_else(|| DrandError::Parse("missing 'randomness'".into()))?;
    let signature_hex = v
        .get("signature")
        .and_then(|x| x.as_str())
        .ok_or_else(|| DrandError::Parse("missing 'signature'".into()))?
        .to_string();
    let previous_signature_hex = v
        .get("previous_signature")
        .and_then(|x| x.as_str())
        .map(|s| s.to_string());

    let randomness_bytes = hex::decode(randomness_hex)
        .map_err(|e| DrandError::Parse(format!("randomness hex decode: {e}")))?;
    if randomness_bytes.len() != 32 {
        return Err(DrandError::Parse(format!(
            "randomness length = {}, expected 32",
            randomness_bytes.len()
        )));
    }
    let mut randomness = [0u8; 32];
    randomness.copy_from_slice(&randomness_bytes);

    Ok(DrandRound {
        round,
        randomness,
        signature_hex,
        previous_signature_hex,
        fetched_at: SystemTime::now(),
    })
}

// Tiny serde adapter that decodes a hex string into [u8; 32].
// Used only for the DrandRound serde impl above.
mod hex_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<[u8; 32], D::Error> {
        let s: String = String::deserialize(de)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom(format!(
                "expected 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_drand_json_happy_path() {
        let json = serde_json::json!({
            "round": 12345,
            "randomness": "a".repeat(64),
            "signature": "ff".repeat(48),
            "previous_signature": "ee".repeat(48),
        });
        let round = parse_drand_json(&json).expect("should parse");
        assert_eq!(round.round, 12345);
        assert_eq!(round.randomness, [0xaa; 32]);
    }

    #[test]
    fn parse_drand_json_missing_randomness() {
        let json = serde_json::json!({ "round": 1, "signature": "ff" });
        assert!(parse_drand_json(&json).is_err());
    }

    #[test]
    fn entropy_source_serialization_round_trip() {
        let drand = EntropySource::Drand {
            round: 42,
            signature_hex: "ff".repeat(48),
        };
        let s = serde_json::to_string(&drand).unwrap();
        let back: EntropySource = serde_json::from_str(&s).unwrap();
        match back {
            EntropySource::Drand { round, .. } => assert_eq!(round, 42),
            _ => panic!("wrong variant"),
        }

        let fallback = EntropySource::Fallback {
            reason: "test".into(),
        };
        let s = serde_json::to_string(&fallback).unwrap();
        let back: EntropySource = serde_json::from_str(&s).unwrap();
        match back {
            EntropySource::Fallback { reason } => assert_eq!(reason, "test"),
            _ => panic!("wrong variant"),
        }
    }
}
