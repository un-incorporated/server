//! Thin re-export shim — the real implementation lives in the `chain-store`
//! crate. `chain-store` is consumed by both the writer (this crate's NATS
//! consumer binary) and the reader (`proxy::chain_api`). Keeping the shim
//! preserves the existing `crate::entry::ChainEntry` import paths used by
//! chain-engine's 14 other modules.

pub use chain_store::entry::*;
