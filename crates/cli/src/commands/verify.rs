use anyhow::{Context, Result};
use chain_engine::storage::{self, ChainStore};
use std::path::Path;
use tracing::info;

pub async fn run(user: Option<String>, all: bool) -> Result<()> {
    let storage_path =
        std::env::var("CHAIN_STORAGE_PATH").unwrap_or_else(|_| "/data/chains".into());
    // Spec §10.3: the salt MUST be CSPRNG-generated and MUST match the
    // value configured on the proxy + chain-engine; a silent fallback
    // would compute chain_id_user under a different salt than production
    // and silently 404 / report-bogus every chain.
    let salt = std::env::var("CHAIN_SERVER_SALT").context(
        "CHAIN_SERVER_SALT must be set — §10.3 requires a CSPRNG-generated \
         per-deployment secret; use the same value that was passed to the \
         proxy and chain-engine processes",
    )?;
    let base_path = Path::new(&storage_path);

    if all {
        info!("verifying all users' chains...");
        let dirs = storage::list_chain_dirs(base_path)?;
        println!("Verifying {} chains...", dirs.len());

        let mut passed = 0;
        let mut failed = 0;

        for dir_hash in &dirs {
            let store = ChainStore::open_by_hash(base_path, dir_hash)?;
            let entries = store.read_all()?;

            match chain_engine::verify::verify_chain(&entries) {
                Ok(()) => passed += 1,
                Err(e) => {
                    failed += 1;
                    println!("FAIL {}: {}", dir_hash, e);
                }
            }
        }

        println!("{} passed, {} failed", passed, failed);
    } else if let Some(user_id) = user {
        info!(user_id = %user_id, "verifying chain...");
        let store = ChainStore::open(base_path, &user_id, &salt)?;
        let entries = store.read_all()?;

        match chain_engine::verify::verify_chain(&entries) {
            Ok(()) => println!("\u{2713} Chain verified ({} entries)", entries.len()),
            Err(e) => {
                println!("\u{2717} Verification failed: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        anyhow::bail!("specify --user <id> or --all");
    }

    Ok(())
}
