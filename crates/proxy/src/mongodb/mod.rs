//! MongoDB wire-protocol proxy module.
//!
//! Parses BSON commands, classifies connections, and emits `AccessEvent`s
//! for admin traffic. Behind the `mongodb` feature flag.

pub mod actor_marker;
pub mod connection;
pub mod fingerprint;
pub mod listener;
pub mod parser;
pub mod resolver;
pub mod scram;
pub mod wire;
