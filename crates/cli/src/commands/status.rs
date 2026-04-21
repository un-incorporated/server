use anyhow::Result;
use chain_engine::storage::{self, ChainStore};
use std::path::Path;
use tracing::info;

pub async fn run() -> Result<()> {
    info!("checking system status...");

    let storage_path =
        std::env::var("CHAIN_STORAGE_PATH").unwrap_or_else(|_| "/data/chains".into());
    let base_path = Path::new(&storage_path);

    let dirs = storage::list_chain_dirs(base_path).unwrap_or_default();
    let total_entries: u64 = dirs
        .iter()
        .map(|d| {
            ChainStore::open_by_hash(base_path, d)
                .ok()
                .and_then(|s| s.entry_count().ok())
                .unwrap_or(0)
        })
        .sum();

    println!("Uninc Server Status");
    println!("  Chains: {}", dirs.len());
    println!("  Total entries: {}", total_entries);
    println!("  Storage path: {}", storage_path);

    Ok(())
}
