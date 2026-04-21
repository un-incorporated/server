//! Postgres wire-protocol proxy module.
//!
//! Parses SQL queries via `sqlparser`, classifies connections, and emits
//! `AccessEvent`s for admin traffic. Behind the `postgres` feature flag.

pub mod actor_marker;
pub mod connection;
pub mod fingerprint;
pub mod listener;
pub mod resolver;
pub mod sql_parser;
pub mod wire;
