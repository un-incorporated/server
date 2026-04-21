//! End-to-end integration test for the erasure-tombstone NATS round trip.
//!
//! This test exercises the full wire path used in production:
//!
//! 1. Spawns a real `nats-server` on a loopback port.
//! 2. Starts `chain_engine::erasure_handler::run_erasure_handler` inside a
//!    tokio task backed by a real `DeploymentChainManager` writing to a
//!    tempdir — the same components that run inside the chain-engine binary.
//! 3. Connects a real `uninc_common::NatsClient` and calls
//!    `write_erasure_tombstone` — the same call site the proxy's DELETE
//!    handler makes.
//! 4. Asserts the returned receipt matches the shape the spec requires AND
//!    that the tombstone actually landed on the deployment chain with the
//!    `UserErasureRequested` category.
//!
//! Unit tests (in `chain_api::tests`) cover the handler logic; this test
//! covers the *wire* — subject routing, JSON payload shape, request/reply
//! timing, and the fact that two independently-built binaries actually
//! agree on the protocol. That's the class of bug unit tests can't catch.
//!
//! # Prerequisites
//!
//! Requires `nats-server` on PATH. Install on macOS:
//!
//! ```text
//! brew install nats-server
//! ```
//!
//! On Linux:
//!
//! ```text
//! go install github.com/nats-io/nats-server/v2@latest
//! ```
//!
//! If the binary is absent the test is skipped with a warning rather than
//! failing — CI runners without NATS won't see a red cross, and developers
//! who have it installed run the real round trip automatically.

use chain_engine::chain::ChainManager;
use chain_engine::deployment_chain::DeploymentChainManager;
use chain_engine::deployment_entry::as_deployment;
use chain_engine::erasure_handler;
use chain_store::DeploymentCategory;
use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use tempfile::TempDir;
use tokio::time::{Duration, sleep};
use uninc_common::nats_client::NatsClient;
use uninc_common::tombstone::TombstoneWriter;
use uninc_common::types::ErasureRequest;

/// RAII guard — kills the `nats-server` child process on drop so a panicking
/// test doesn't leave an orphan listening on the loopback port.
struct NatsServer {
    child: Child,
    port: u16,
}

impl NatsServer {
    fn url(&self) -> String {
        format!("nats://127.0.0.1:{}", self.port)
    }
}

impl Drop for NatsServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Bind to an ephemeral port, then release it so `nats-server` can claim
/// it. Small race window — acceptable for local tests, not prod.
fn ephemeral_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener
        .local_addr()
        .expect("local_addr")
        .port()
}

fn try_spawn_nats() -> Option<NatsServer> {
    let port = ephemeral_port();
    let child = Command::new("nats-server")
        .args(["-p", &port.to_string(), "-a", "127.0.0.1"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    Some(NatsServer { child, port })
}

/// Poll until the NATS port accepts a TCP connection or the deadline
/// passes. Simpler than a handshake because NATS sends INFO on connect;
/// TCP accept is a sufficient readiness signal for tests.
async fn wait_for_nats(port: u16) -> bool {
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while std::time::Instant::now() < deadline {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return true;
        }
        sleep(Duration::from_millis(50)).await;
    }
    false
}

#[tokio::test]
async fn erasure_round_trip_through_real_nats() {
    let Some(nats) = try_spawn_nats() else {
        eprintln!(
            "skipping erasure_round_trip_through_real_nats: `nats-server` \
             not on PATH. Install with `brew install nats-server` (macOS) \
             or see README."
        );
        return;
    };

    assert!(
        wait_for_nats(nats.port).await,
        "nats-server did not accept connections within 3s"
    );

    // Real DeploymentChainManager writing to a tempdir — chain-engine's
    // actual write path, not a mock.
    let tmp = TempDir::new().expect("tempdir");
    let manager = Arc::new(
        DeploymentChainManager::new(tmp.path()).expect("build deployment chain manager"),
    );

    // ChainManager without a durable tier — single-host topology. The
    // physical-delete step in the handler will run against local fs only;
    // `delete_chain_by_hash` is idempotent on missing local dirs so the
    // fake user hash used below does not need a pre-populated chain
    // directory.
    let chain_manager = Arc::new(ChainManager::new(tmp.path(), "test-salt"));

    // Spawn the erasure handler the same way chain-engine's main.rs does.
    let handler_dcm = Arc::clone(&manager);
    let handler_cm = Arc::clone(&chain_manager);
    let handler_url = nats.url();
    let handler_task = tokio::spawn(async move {
        // Errors are reported via logs in production; here we just let the
        // task exit — the test will fail at the request step if the
        // handler never came up.
        let _ =
            erasure_handler::run_erasure_handler(&handler_url, handler_dcm, handler_cm).await;
    });

    // Give the subscriber a moment to bind before the proxy publishes.
    // core NATS subscriptions become active synchronously on subscribe(),
    // but we're racing a tokio spawn boundary, so 200ms is generous.
    sleep(Duration::from_millis(200)).await;

    // Proxy-side: connect a real NatsClient and ask for a tombstone.
    let client = NatsClient::connect(&nats.url(), "uninc.access")
        .await
        .expect("NatsClient::connect");

    let fake_user_hash = "a".repeat(64);
    let req = ErasureRequest {
        user_id_hash: fake_user_hash.clone(),
        source_ip: "203.0.113.7".into(),
        session_id: None,
        requested_at: 1_713_600_000,
    };
    let receipt = client
        .write_erasure_tombstone(req)
        .await
        .expect("tombstone write_erasure_tombstone");

    // Receipt shape: spec §7.3.1.
    assert_eq!(
        receipt.tombstone_entry_id.len(),
        64,
        "tombstone_entry_id MUST be hex-encoded SHA-256 (64 chars)"
    );
    assert_eq!(
        receipt.tombstone_deployment_chain_index, 0,
        "first tombstone on a fresh chain lands at index 0"
    );

    // The tombstone must actually be on the deployment chain.
    assert_eq!(manager.entry_count().unwrap(), 1);
    let entries = manager.read_all().unwrap();
    assert_eq!(entries.len(), 1);

    let org = as_deployment(&entries[0]).expect("DeploymentEvent payload");
    assert_eq!(org.category, DeploymentCategory::UserErasureRequested);
    assert_eq!(
        org.actor_id, fake_user_hash,
        "tombstone actor_id is the hashed user id (spec §8.1)"
    );
    assert_eq!(org.resource, "user_chain");

    // The entry_hash reported by the handler MUST match the one computed
    // by the chain — if it doesn't, the handler and the store disagree on
    // compute_hash, which would be a protocol-breaking regression.
    assert_eq!(
        receipt.tombstone_entry_id,
        hex::encode(entries[0].entry_hash),
        "handler-reported entry_hash must match on-chain entry_hash"
    );

    // Details were preserved end-to-end.
    let details = org.details.as_object().expect("details object");
    assert_eq!(
        details.get("requested_by").and_then(|v| v.as_str()),
        Some("data_subject"),
        "details.requested_by distinguishes user-initiated from retention-policy"
    );
    assert_eq!(
        details.get("source_ip").and_then(|v| v.as_str()),
        Some("203.0.113.7"),
    );

    handler_task.abort();
}
