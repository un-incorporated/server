//! `uninc-observer` — the independent data-access transparency log
//! observer binary.
//!
//! See `lib.rs` for the architectural context. This binary loads an
//! `observer.yml` config file, starts one subscriber task per configured
//! primitive, and serves the internal HTTP endpoint on `:2026` so the
//! verification task can read observer chain state during verification
//! passes.

use observer::{
    chain::ObserverChain,
    config::ObserverConfig,
    http::{serve, HttpState},
    subscribers::{
        minio::MinioSubscriber, mongo::MongoSubscriber, postgres::PostgresSubscriber,
    },
};
use std::path::PathBuf;
use std::sync::Arc;
use tracing::info;
use tracing_subscriber::{fmt, EnvFilter};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    info!("uninc-observer starting — independent data-access transparency log observer");

    let config_path = std::env::var("OBSERVER_CONFIG")
        .unwrap_or_else(|_| "/etc/uninc/observer.yml".to_string());
    let config = ObserverConfig::load(&PathBuf::from(&config_path))?;

    info!(
        deployment_id = config.deployment_id.as_str(),
        chain_storage = config.chain_storage_path.as_str(),
        http_port = config.http_port,
        "observer config loaded"
    );

    let chain = Arc::new(ObserverChain::new(
        config.chain_storage_path.clone(),
        config.deployment_salt.clone(),
    ));
    info!(base = ?chain.base_path(), "observer chain initialized");

    // Spawn a subscriber task per configured primitive.
    let mut subscriber_handles = Vec::new();

    if let Some(pg) = config.postgres.clone() {
        let chain = Arc::clone(&chain);
        subscriber_handles.push(tokio::spawn(async move {
            PostgresSubscriber::new(pg, chain).run().await;
        }));
    }

    if let Some(mongo) = config.mongodb.clone() {
        let chain = Arc::clone(&chain);
        subscriber_handles.push(tokio::spawn(async move {
            MongoSubscriber::new(mongo, chain).run().await;
        }));
    }

    if let Some(minio) = config.minio.clone() {
        let chain = Arc::clone(&chain);
        subscriber_handles.push(tokio::spawn(async move {
            MinioSubscriber::new(minio, chain).run().await;
        }));
    }

    info!(
        subscriber_count = subscriber_handles.len(),
        "all subscribers spawned; observer is live"
    );

    // Serve the verification-read HTTP endpoint on the main task.
    let state = Arc::new(HttpState {
        chain: Arc::clone(&chain),
        read_secret: config.read_secret.clone(),
    });
    serve(state, config.http_port).await?;

    Ok(())
}
