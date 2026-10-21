//! # Propylea CLI Application
//! Thin lifecycle shell (< 80 lines) delegating to `propylea::cli`.

use clap::Parser;
use propylea::cli::{execute_cli, Cli};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "propylea=info,tower_http=info".into()),
        )
        .init();

    let cli = Cli::parse();
    execute_cli(cli).await
}
