use anyhow::{Context, Result};
use chain_engine::storage::ChainStore;
use std::path::Path;
use tracing::info;

pub async fn run(user: &str, format: &str) -> Result<()> {
    info!(user, format, "exporting chain...");

    let storage_path =
        std::env::var("CHAIN_STORAGE_PATH").unwrap_or_else(|_| "/data/chains".into());
    // Spec §10.3: the salt MUST be CSPRNG-generated and MUST match the
    // value on proxy + chain-engine. Fallback to a literal would look up
    // chains under a different hash and silently 404.
    let salt = std::env::var("CHAIN_SERVER_SALT").context(
        "CHAIN_SERVER_SALT must be set — §10.3 requires a CSPRNG-generated \
         per-deployment secret; use the same value that was passed to the \
         proxy and chain-engine processes",
    )?;

    let store = ChainStore::open(Path::new(&storage_path), user, &salt)?;
    let entries = store.read_all()?;

    match format {
        "json" => println!("{}", chain_engine::export::to_json(&entries)?),
        "csv" => print!("{}", chain_engine::export::to_csv(&entries)),
        _ => anyhow::bail!("unsupported format: {}", format),
    }

    Ok(())
}
