//! # Sovereign Buffalo Crucible Test Gate
//! Thin lifecycle shell (< 80 lines) delegating to `propylea::crucible`.

use clap::Parser;
use propylea::crucible::{run_crucible_gate, CrucibleOpts};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opts = CrucibleOpts::parse();
    run_crucible_gate(opts).await
}
