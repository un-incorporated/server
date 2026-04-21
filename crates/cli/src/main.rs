use anyhow::Result;
use clap::{Parser, Subcommand};

mod commands;

#[derive(Parser)]
#[command(name = "uninc", about = "The Unincorporated Server CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Verify chain integrity for a user or all users.
    Verify {
        /// User ID to verify (omit for --all).
        #[arg(long)]
        user: Option<String>,
        /// Verify all users' chains.
        #[arg(long)]
        all: bool,
    },
    /// Export a user's chain as JSON.
    Export {
        /// User ID to export.
        #[arg(long)]
        user: String,
        /// Output format.
        #[arg(long, default_value = "json")]
        format: String,
    },
    /// Show system status.
    Status,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Verify { user, all } => commands::verify::run(user, all).await,
        Commands::Export { user, format } => commands::export::run(&user, &format).await,
        Commands::Status => commands::status::run().await,
    }
}
