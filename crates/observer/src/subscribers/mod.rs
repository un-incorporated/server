//! Per-primitive replication-stream subscribers.
//!
//! Each subscriber runs as an independent tokio task. On connection
//! failure it reconnects with exponential backoff; on parse failure it
//! logs and continues (a single malformed WAL record should not stop
//! the observer from processing later records).
//!
//! Every subscriber funnels operations into the shared `ObserverChain`
//! via `chain.append(...)` so the proxy and observer chains stay
//! byte-identical for the same sequence of events.

pub mod minio;
pub mod mongo;
pub mod postgres;
