//! # Propylea CLI Application
//! Sovereign ultra-low-memory L7 reverse proxy & perimeter defense gateway.

use clap::{Parser, Subcommand};
use propylea::config::PropyleaConfig;
use propylea::maintenance::{MaintenanceConfig, ResourceGovernor};
use propylea::telemetry::TelemetryRingBuffer;
use propylea::tls::{build_sni_tls_acceptor, load_certs, load_private_key};
use std::path::PathBuf;
use std::time::Duration;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

const BANNER: &str = r#"
   ____                               __              
  / __ \_________  ____  __  ______  / /__  ____ _    
 / /_/ / ___/ __ \/ __ \/ / / / / _ \/ / _ \/ __ `/    
/ ____/ /  / /_/ / /_/ / /_/ / /  __/ /  __/ /_/ /     
\/    \/   \____/ .___/\__, /_/\___/_/\___/\__,_/      
               /_/    /____/                           
  Sovereign L7 Reverse Proxy & Perimeter Defense Gate
"#;

#[derive(Parser, Debug)]
#[command(name = "propylea")]
#[command(author = "Rick <rick@rmediatech.com>")]
#[command(version)]
#[command(about = "Sovereign ultra-low-memory L7 reverse proxy & perimeter defense gateway")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Path to TOML configuration file
    #[arg(short, long, global = true, default_value = "propylea.toml")]
    config: PathBuf,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Start the sovereign reverse proxy and defense gateway
    Serve {
        #[arg(short, long, default_value = "propylea.toml")]
        config: PathBuf,
    },
    /// Validate configuration and certificate syntax without binding ports
    Check {
        #[arg(short, long, default_value = "propylea.toml")]
        config: PathBuf,

        /// Validate configuration syntax and schema only without requiring TLS files on disk
        #[arg(long)]
        syntax_only: bool,
    },
    /// Sovereign autonomous quarantine management and multi-format intelligence
    Quarantine {
        #[command(subcommand)]
        cmd: propylea::quarantine::QuarantineCommands,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "propylea=info,tower_http=info".into()),
        )
        .init();

    let cli = Cli::parse();
    match cli.command {
        Some(Commands::Serve { config }) => run_serve(config).await,
        Some(Commands::Check {
            config,
            syntax_only,
        }) => run_check(config, syntax_only),
        Some(Commands::Quarantine { cmd }) => {
            propylea::quarantine::handle_quarantine_command(cli.config, cmd).await
        }
        None => run_serve(cli.config).await,
    }
}

fn run_check(path: PathBuf, syntax_only: bool) -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", BANNER);
    info!(
        "🔍 Validating Propylea configuration at '{}'...",
        path.display()
    );

    let config = PropyleaConfig::load_from_file(&path)?;

    info!("  • HTTP Redirect Bind:  {}", config.server.http_bind);
    info!("  • HTTPS Proxy Bind:    {}", config.server.https_bind);
    info!(
        "  • Active Defense:      {}",
        if config.security.enable_defense {
            "Enabled"
        } else {
            "Disabled"
        }
    );
    info!(
        "  • Memory Vacuum:       {}",
        if config.maintenance.memory_vacuum {
            "Active (malloc_trim)"
        } else {
            "Disabled"
        }
    );
    info!(
        "  • Hygiene Interval:    {}s",
        config.maintenance.hygiene_interval_secs
    );
    info!(
        "  • Verifying {} configured route(s)...",
        config.routes.len()
    );

    for (i, route) in config.routes.iter().enumerate() {
        if syntax_only {
            info!(
                "    [{}] Domains: {:?} -> {} (Syntax valid, TLS cert: '{}', key: '{}')",
                i,
                route.domains,
                route.upstream,
                route.cert.display(),
                route.key.display()
            );
        } else {
            let certs = load_certs(&route.cert)
                .map_err(|e| format!("Route[{}] ({:?}): cert error: {}", i, route.domains, e))?;
            let _key = load_private_key(&route.key)
                .map_err(|e| format!("Route[{}] ({:?}): key error: {}", i, route.domains, e))?;
            info!(
                "    [{}] Domains: {:?} -> {} (TLS certs verified: {} certificates loaded)",
                i,
                route.domains,
                route.upstream,
                certs.len()
            );
        }
    }

    println!("\n✅ [PROPYLEA] Configuration is valid and verified.\n");
    Ok(())
}

async fn run_serve(path: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", BANNER);
    info!(
        "🚀 Initializing Propylea Sovereign Reverse Proxy v{}...",
        env!("CARGO_PKG_VERSION")
    );

    let config = match PropyleaConfig::load_from_file(&path) {
        Ok(c) => c,
        Err(e) => {
            error!("Fatal configuration error in '{}': {}", path.display(), e);
            std::process::exit(1);
        }
    };

    // 1. Build Multi-Domain SNI TLS Acceptor
    let tls_acceptor = match build_sni_tls_acceptor(&config.routes) {
        Ok(a) => a,
        Err(e) => {
            error!("Fatal TLS configuration error: {}", e);
            std::process::exit(1);
        }
    };

    // 2. Initialize Autonomous Resource Governor & Telemetry Ring Buffer
    let maintenance_cfg = MaintenanceConfig {
        interval: Duration::from_secs(config.maintenance.hygiene_interval_secs),
        max_retained_records: config.maintenance.max_telemetry_records,
        memory_vacuum: config.maintenance.memory_vacuum,
    };

    let governor = ResourceGovernor::new(maintenance_cfg);
    let telemetry = TelemetryRingBuffer::new(config.maintenance.max_telemetry_records);

    // Initial memory hygiene pass
    governor.run_hygiene_pass();

    // Spawn background maintenance governor task
    let _governor_handle = governor.clone().spawn_maintenance_worker();

    // 3. Spawn HTTP-to-HTTPS redirector
    let http_bind = config.server.http_bind;
    let sec_http = config.security.clone();
    let acme_webroot = config.server.acme_webroot.clone();
    tokio::spawn(async move {
        if let Err(e) = propylea::run_http_redirect_server(http_bind, sec_http, acme_webroot).await
        {
            error!("HTTP redirect server failed on {}: {}", http_bind, e);
        }
    });

    // 4. Spawn HTTPS reverse proxy engine
    let https_bind = config.server.https_bind;
    let proxy_config = config.clone();
    let proxy_governor = governor.clone();
    let proxy_telemetry = telemetry.clone();

    tokio::spawn(async move {
        if let Err(e) = propylea::run_https_proxy_server(
            https_bind,
            tls_acceptor,
            proxy_config,
            proxy_governor,
            proxy_telemetry,
        )
        .await
        {
            error!("HTTPS proxy server failed on {}: {}", https_bind, e);
        }
    });

    info!("🛡️  Propylea is running and armed with sovereign edge defense.");
    info!(
        "    Ingress Ports: HTTP [{}] -> HTTPS [{}]",
        http_bind, https_bind
    );

    // Wait for graceful shutdown signal (SIGINT / SIGTERM)
    tokio::signal::ctrl_c().await?;
    info!("🛑 Shutdown signal received. Performing final memory hygiene pass...");
    governor.run_hygiene_pass();
    info!("👋 Propylea shutdown cleanly.");

    Ok(())
}
