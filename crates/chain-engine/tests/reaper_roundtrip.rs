//! End-to-end integration test for the retention reaper (G11 regression).
//!
//! Seeds three per-user chain directories under a tempdir with controlled
//! `meta.json::created_at` values (seconds), plus a `_deployment/` directory
//! (which the reaper MUST skip). Runs the reaper once with a 180-day
//! cutoff, then asserts:
//!
//!   1. Only the "old" chain is gone from disk.
//!   2. The two "young" chains remain.
//!   3. `_deployment/` is untouched.
//!   4. Exactly one `RetentionSweep` tombstone lands on the deployment chain.
//!   5. Tombstone `details.created_at` is a seconds-scale integer (spec §8.2).
//!   6. The obsolete `details.created_at_ms` key is NOT present.
//!
//! Regression target: before the G11 fix, the reaper read a non-existent
//! `created_at_ms` meta field, fell through an `unwrap_or(0)` default to
//! UNIX_EPOCH, and reaped every directory on the first run. This test would
//! have caught that by asserting at least one young chain survives.
//!
//! Requires `nats-server` on PATH; skips with a warning if absent, matching
//! `erasure_roundtrip.rs`.

use chain_engine::chain::ChainManager;
use chain_engine::deployment_chain::DeploymentChainManager;
use chain_engine::deployment_entry::as_deployment;
use chain_engine::reaper::{self, ReaperConfig};
use chain_store::DeploymentCategory;
use serde_json::json;
use std::net::TcpListener;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::time::sleep;
use uninc_common::nats_client::NatsClient;

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

fn ephemeral_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener.local_addr().expect("local_addr").port()
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

fn seed_chain_dir(storage_root: &Path, dir_name: &str, created_at_secs: i64, entry_count: u64) {
    let dir = storage_root.join(dir_name);
    std::fs::create_dir_all(&dir).expect("create chain dir");
    let meta = json!({
        "user_id_hash": dir_name,
        "created_at": created_at_secs,
        "entry_count": entry_count,
        "key_id": null,
    });
    std::fs::write(dir.join("meta.json"), serde_json::to_string(&meta).unwrap())
        .expect("write meta.json");
    // Dummy chain.dat so the dir looks like a real chain.
    std::fs::write(dir.join("chain.dat"), b"").expect("seed chain.dat");
}

#[tokio::test]
async fn reaper_spares_young_chains_and_deployment_dir() {
    let Some(nats) = try_spawn_nats() else {
        eprintln!(
            "skipping reaper_spares_young_chains_and_deployment_dir: \
             `nats-server` not on PATH"
        );
        return;
    };
    assert!(wait_for_nats(nats.port).await, "nats-server did not start");

    let tmp = TempDir::new().expect("tempdir");
    let storage_root = tmp.path();

    // Retention cutoff in seconds-since-epoch for 180 days ago.
    let now = chrono::Utc::now().timestamp();
    let two_years_ago = now - (2 * 365 * 24 * 60 * 60);
    let one_day_ago = now - (24 * 60 * 60);

    // Seed: one old chain, two young chains, one deployment dir.
    let old_hash = "0".repeat(64);
    let young_hash_a = "a".repeat(64);
    let young_hash_b = "b".repeat(64);
    seed_chain_dir(storage_root, &old_hash, two_years_ago, 42);
    seed_chain_dir(storage_root, &young_hash_a, one_day_ago, 3);
    seed_chain_dir(storage_root, &young_hash_b, one_day_ago, 5);

    // The real deployment chain dir. DeploymentChainManager::new creates it.
    let deployment_manager = Arc::new(
        DeploymentChainManager::new(storage_root).expect("build deployment chain manager"),
    );
    // Wire the NATS consumer so tombstones published by the reaper actually
    // land on the deployment chain. Without the consumer loop the publish
    // is fire-and-forget and the tombstone never appears.
    let nats_url = nats.url();
    let consumer_mgr = Arc::clone(&deployment_manager);
    let consumer_url = nats_url.clone();
    let consumer_task = tokio::spawn(async move {
        // Bind a subscriber on the system-events subject the reaper publishes to.
        // Mirrors `consumer::run_deployment_consumer` but inlined here so the
        // test doesn't have to wire the full JetStream stack.
        use futures::StreamExt;
        let client = async_nats::connect(&consumer_url).await.expect("nats connect");
        let mut sub = client
            .subscribe("uninc.access.system")
            .await
            .expect("subscribe");
        while let Some(msg) = sub.next().await {
            if let Ok(event) =
                serde_json::from_slice::<uninc_common::types::DeploymentEvent>(&msg.payload)
            {
                // Shape matches the reaper's `publish_system_deployment_event`
                // body; append straight to the deployment chain.
                let _ = consumer_mgr
                    .append_deployment_event(
                        &event.actor_id,
                        event.actor_type,
                        event.category,
                        event.action,
                        &event.resource,
                        &event.scope,
                        event
                            .details
                            .map(|d| d.into_iter().collect()),
                        event.artifact_hash,
                        event.session_id,
                        event.source_ip.as_deref(),
                    )
                    .await;
            }
        }
    });

    // Give the subscriber a moment to bind.
    sleep(Duration::from_millis(200)).await;

    // Chain manager without a durable tier. `delete_chain_by_hash` will only
    // hit local fs — matches single-host topology.
    let chain_manager = Arc::new(ChainManager::new(storage_root, "test-salt"));

    let reaper_nats =
        Arc::new(NatsClient::connect(&nats_url, "uninc.access").await.expect("reaper NATS"));

    // Reaper with a 180-day retention. `run_interval` is irrelevant because
    // we only run once manually via the internal helper — but ReaperConfig
    // requires it.
    let cfg = ReaperConfig {
        storage_root: storage_root.to_path_buf(),
        retention_days: 180,
        run_interval: Duration::from_secs(60),
    };

    // Spawn run_reaper and let it tick once. Because run_reaper loops
    // forever, we abort after the first sleep cycle — the config's
    // interval is clamped to REAPER_MIN_INTERVAL (60s), so one pass
    // happens well inside the window.
    let reaper_task = tokio::spawn(async move {
        reaper::run_reaper(cfg, reaper_nats, chain_manager).await;
    });

    // Wait for the reaper to finish its first pass. The delete + NATS
    // publish should complete in tens of milliseconds; 1s is generous.
    sleep(Duration::from_secs(1)).await;
    reaper_task.abort();

    // Give the NATS consumer a moment to drain the tombstone publish.
    sleep(Duration::from_millis(300)).await;
    consumer_task.abort();

    // Assertions.
    assert!(
        !storage_root.join(&old_hash).exists(),
        "old chain should be deleted by the reaper"
    );
    assert!(
        storage_root.join(&young_hash_a).exists(),
        "young chain A must survive (G11 regression: reaper used to reap everything)"
    );
    assert!(
        storage_root.join(&young_hash_b).exists(),
        "young chain B must survive"
    );
    assert!(
        storage_root.join("_deployment").exists(),
        "_deployment dir MUST NOT be touched by the reaper"
    );

    // Tombstone assertions.
    let dep_entries = deployment_manager.read_all().expect("read deployment chain");
    let retention_tombstones: Vec<_> = dep_entries
        .iter()
        .filter_map(|e| as_deployment(e))
        .filter(|org| org.category == DeploymentCategory::RetentionSweep)
        .collect();
    assert_eq!(
        retention_tombstones.len(),
        1,
        "exactly one retention_sweep tombstone for the one old chain"
    );
    let tombstone = retention_tombstones[0];
    assert_eq!(tombstone.actor_id, "system:retention-reaper");
    assert_eq!(tombstone.resource, "chain");

    let details = tombstone.details.as_object().expect("details object");
    let chain_id = details
        .get("chain_id")
        .and_then(|v| v.as_str())
        .expect("details.chain_id");
    assert_eq!(chain_id, &old_hash, "tombstone names the reaped chain");

    // G11 spec conformance: `created_at` in Unix seconds, NOT `created_at_ms`.
    assert!(
        details.get("created_at").is_some(),
        "tombstone must carry details.created_at per §8.2"
    );
    assert!(
        details.get("created_at_ms").is_none(),
        "tombstone MUST NOT carry the obsolete details.created_at_ms key"
    );
    let created_at_str = details
        .get("created_at")
        .and_then(|v| v.as_str())
        .expect("details.created_at string");
    let created_at: i64 = created_at_str
        .parse()
        .expect("details.created_at parses as int");
    // Seconds-scale: 2-years-ago is around 1.7e9, milliseconds would be ~1.7e12.
    assert!(
        (1_000_000_000..2_000_000_000).contains(&created_at),
        "details.created_at must be a reasonable Unix-seconds value (got {created_at})"
    );
    assert_eq!(
        created_at, two_years_ago,
        "tombstone's created_at must match the reaped chain's meta.json created_at"
    );
}
