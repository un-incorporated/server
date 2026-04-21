use thiserror::Error;

#[derive(Debug, Error)]
pub enum UnincError {
    // -- Configuration --
    #[error("configuration error: {0}")]
    Config(String),

    #[error("missing required config field: {0}")]
    ConfigMissing(String),

    // -- Chain --
    #[error("chain error: {0}")]
    Chain(String),

    #[error("chain verification failed at index {at_index}: {reason}")]
    ChainVerification { at_index: u64, reason: String },

    #[error("chain corrupted: {0}")]
    ChainCorrupted(String),

    // -- Encryption --
    #[error("encryption error: {0}")]
    Encryption(String),

    #[error("key not found for user: {0}")]
    KeyNotFound(String),

    // -- Storage / IO --
    #[error("storage error: {0}")]
    Storage(#[from] std::io::Error),

    // -- NATS --
    #[error("NATS error: {0}")]
    Nats(String),

    // -- Proxy --
    #[error("proxy error: {0}")]
    Proxy(String),

    #[error("protocol parse error: {0}")]
    ProtocolParse(String),

    #[error("upstream connection failed: {0}")]
    UpstreamConnection(String),

    // -- Identity --
    #[error("identity classification error: {0}")]
    Identity(String),

    // -- Verification --
    #[error("verification error: {0}")]
    Verification(String),

    // -- Serialization --
    #[error("serialization error: {0}")]
    Serialization(String),
}

impl From<serde_json::Error> for UnincError {
    fn from(e: serde_json::Error) -> Self {
        Self::Serialization(e.to_string())
    }
}

impl From<serde_yaml::Error> for UnincError {
    fn from(e: serde_yaml::Error) -> Self {
        Self::Config(e.to_string())
    }
}
