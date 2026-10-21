//! # Propylea CLI & Daemon Bootstrap Engine (`cli.rs`)
//!
//! Handles CLI argument parsing, configuration/certificate verification (`check`),
//! and full multi-service daemon lifecycle orchestration (`serve`).

use crate::config::PropyleaConfig;
use crate::maintenance::{MaintenanceConfig, ResourceGovernor};
use crate::sanitize::scrub_ansi_and_control;
use crate::telemetry::TelemetryRingBuffer;
use crate::tls::{build_sni_tls_acceptor, load_certs, load_private_key};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::time::Duration;
use tracing::{error, info};

pub const BANNER: &str = r#"
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
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Path to TOML configuration file
    #[arg(short, long, global = true, default_value = "propylea.toml")]
    pub config: PathBuf,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
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
        cmd: crate::quarantine::QuarantineCommands,
    },
}

/// Dispatch parsed CLI commands to the appropriate execution engine
pub async fn execute_cli(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    match cli.command {
        Some(Commands::Serve { config }) => run_serve(config).await,
        Some(Commands::Check {
            config,
            syntax_only,
        }) => run_check(config, syntax_only),
        Some(Commands::Quarantine { cmd }) => {
            crate::quarantine::handle_quarantine_command(cli.config, cmd).await
        }
        None => run_serve(cli.config).await,
    }
}

/// Validate TOML syntax, routes, and optional TLS certificate/key pairs on disk
pub fn run_check(path: PathBuf, syntax_only: bool) -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", BANNER);
    let safe_path = scrub_ansi_and_control(&path.display().to_string(), 512);
    info!("🔍 Validating Propylea configuration at '{}'...", safe_path);

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
                route.primary_upstream(),
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
                route.primary_upstream(),
                certs.len()
            );
        }
    }

    println!("\n✅ [PROPYLEA] Configuration is valid and verified.\n");
    Ok(())
}

/// Launch the HTTP redirector, HTTPS SNI reverse proxy, and autonomous maintenance governor
pub async fn run_serve(path: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
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

    let tls_acceptor = match build_sni_tls_acceptor(&config.routes) {
        Ok(a) => a,
        Err(e) => {
            error!("Fatal TLS configuration error: {}", e);
            std::process::exit(1);
        }
    };

    let maintenance_cfg = MaintenanceConfig {
        interval: Duration::from_secs(config.maintenance.hygiene_interval_secs),
        max_retained_records: config.maintenance.max_telemetry_records,
        memory_vacuum: config.maintenance.memory_vacuum,
    };

    let governor = ResourceGovernor::new(maintenance_cfg);
    let telemetry = TelemetryRingBuffer::new(config.maintenance.max_telemetry_records);

    governor.run_hygiene_pass();
    let _governor_handle = governor.clone().spawn_maintenance_worker();

    let http_bind = config.server.http_bind;
    let sec_http = config.security.clone();
    let acme_webroot = config.server.acme_webroot.clone();
    tokio::spawn(async move {
        if let Err(e) = crate::run_http_redirect_server(http_bind, sec_http, acme_webroot).await {
            error!("HTTP redirect server failed on {}: {}", http_bind, e);
        }
    });

    let https_bind = config.server.https_bind;
    let proxy_config = config.clone();
    let proxy_governor = governor.clone();
    let proxy_telemetry = telemetry.clone();

    tokio::spawn(async move {
        if let Err(e) = crate::run_https_proxy_server(
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

    tokio::signal::ctrl_c().await?;
    info!("🛑 Shutdown signal received. Performing final memory hygiene pass...");
    governor.run_hygiene_pass();
    info!("👋 Propylea shutdown cleanly.");

    Ok(())
}
