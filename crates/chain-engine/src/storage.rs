//! Thin re-export shim — the real implementation lives in the `chain-store`
//! crate. See chain-engine's `entry.rs` shim for the rationale.

pub use chain_store::storage::*;
