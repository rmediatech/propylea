//! # Sovereign Quarantine CLI Interface (`quarantine/cli/mod.rs`)

mod parsers;

pub use parsers::{
    exec_cli_ban, exec_cli_ingest, extract_ips_from_line, is_excluded, parse_duration_str,
    resolve_target_cidr,
};

use super::export::{export_records, ExportFormat};
use super::ipc::{IpcClient, IpcRequest, IpcResponse};
use super::store::QuarantineStore;
use crate::config::PropyleaConfig;
use clap::Subcommand;
use std::path::PathBuf;
use std::str::FromStr;

#[derive(Subcommand, Debug, Clone)]
pub enum QuarantineCommands {
    /// List quarantined subnets across multiple formats
    List {
        #[arg(short, long, default_value = "md")]
        format: String,
        #[arg(short, long)]
        active_only: bool,
        #[arg(short, long, default_value_t = 100)]
        limit: usize,
    },
    /// Export quarantine records to a file in any supported format
    Export {
        file: PathBuf,
        #[arg(short, long, default_value = "html")]
        format: String,
        #[arg(short, long)]
        active_only: bool,
    },
    /// Quarantine one or more IP addresses or CIDR blocks
    Ban {
        #[arg(required = true)]
        targets: Vec<String>,
        #[arg(short, long, default_value = "Manual operator ban")]
        reason: String,
        #[arg(short, long, default_value = "24h")]
        duration: String,
        #[arg(short, long)]
        exact: bool,
    },
    /// Unquarantine one or more IP addresses or CIDR subnets
    Unban {
        #[arg(required = true)]
        targets: Vec<String>,
    },
    /// Ingest historical bad actors from log files or journalctl into persistent quarantine
    IngestLogs {
        #[arg(short, long, default_value = "-")]
        input: String,
        #[arg(short, long, default_value = "historical_journal_ingest")]
        reason: String,
        #[arg(short, long, default_value = "24h")]
        duration: String,
        #[arg(short, long)]
        exclude: Vec<String>,
        #[arg(short, long)]
        exact: bool,
    },
    /// Unquarantine all active bans in one shot
    Clear,
    /// Inspect status of the quarantine engine and running daemon
    Status,
}

pub async fn handle_quarantine_command(
    config_path: PathBuf,
    cmd: QuarantineCommands,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = PropyleaConfig::load_from_file(&config_path).unwrap_or_default();
    let db_path = config.security.resolved_quarantine_db();
    let sock_path = config.security.resolved_control_socket();
    let client = IpcClient::new(&sock_path);

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    match cmd {
        QuarantineCommands::Ban {
            targets,
            reason,
            duration,
            exact,
        } => {
            exec_cli_ban(
                &client, &db_path, targets, reason, &duration, exact, now_ms,
            )
            .await?;
        }
        QuarantineCommands::IngestLogs {
            input,
            reason,
            duration,
            exclude,
            exact,
        } => {
            exec_cli_ingest(
                &client, &db_path, &input, &reason, &duration, &exclude, exact, now_ms,
            )
            .await?;
        }
        QuarantineCommands::Unban { targets } => {
            if client.is_alive().await {
                match client.send_request(&IpcRequest::Unban { targets }).await? {
                    IpcResponse::Unbanned {
                        count,
                        unbanned_cidrs,
                    } => {
                        println!("✅ [QUARANTINE-IPC] Successfully unbanned {} subnet(s) in running daemon:", count);
                        for cidr in unbanned_cidrs {
                            println!("   • {}", cidr);
                        }
                    }
                    IpcResponse::Error { message } => {
                        eprintln!("❌ [QUARANTINE-IPC] Daemon error: {}", message);
                    }
                    _ => {}
                }
            } else {
                let store = QuarantineStore::open(&db_path)?;
                let mut total_unbanned = 0;
                let mut all_cidrs = Vec::new();
                for target in targets {
                    let unbanned = store.unban(&target, "Offline CLI unban", now_ms)?;
                    total_unbanned += unbanned.len();
                    all_cidrs.extend(unbanned);
                }
                println!(
                    "✅ [QUARANTINE-STORE] Offline store unbanned {} subnet(s) in SQLite (daemon not running):",
                    total_unbanned
                );
                for cidr in all_cidrs {
                    println!("   • {}", cidr);
                }
            }
        }
        QuarantineCommands::Clear => {
            if client.is_alive().await {
                match client.send_request(&IpcRequest::UnbanAll).await? {
                    IpcResponse::Unbanned { count, .. } => {
                        println!("✅ [QUARANTINE-IPC] Live daemon cleared all active bans ({} subnets unbanned).", count);
                    }
                    IpcResponse::Error { message } => {
                        eprintln!("❌ [QUARANTINE-IPC] Daemon error: {}", message);
                    }
                    _ => {}
                }
            } else {
                let store = QuarantineStore::open(&db_path)?;
                let count = store.unban_all("Offline CLI unban_all", now_ms)?;
                println!(
                    "✅ [QUARANTINE-STORE] Offline store cleared all active bans ({} subnets unbanned in SQLite).",
                    count
                );
            }
        }
        QuarantineCommands::List {
            format,
            active_only,
            limit,
        } => {
            let export_fmt = ExportFormat::from_str(&format)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
            let store = QuarantineStore::open(&db_path)?;
            let records = if active_only {
                store.get_active_bans(now_ms)?
            } else {
                store.get_all_records(limit)?
            };
            let rendered =
                export_records(&records, export_fmt, now_ms).map_err(std::io::Error::other)?;
            print!("{}", rendered);
        }
        QuarantineCommands::Export {
            file,
            format,
            active_only,
        } => {
            let export_fmt = ExportFormat::from_str(&format)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
            let store = QuarantineStore::open(&db_path)?;
            let records = if active_only {
                store.get_active_bans(now_ms)?
            } else {
                store.get_all_records(100_000)?
            };
            let rendered =
                export_records(&records, export_fmt, now_ms).map_err(std::io::Error::other)?;
            if let Some(parent) = file.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            std::fs::write(&file, rendered)?;
            println!(
                "✅ [QUARANTINE] Exported {} records to '{}' (format: {}).",
                records.len(),
                file.display(),
                format
            );
        }
        QuarantineCommands::Status => {
            let is_daemon_running = client.is_alive().await;
            println!("🛡️  Propylea Autonomous Quarantine Status");
            println!("───────────────────────────────────────────────────");
            println!("  • Daemon Control Socket: {}", sock_path.display());
            println!(
                "  • Daemon IPC State:      {}",
                if is_daemon_running {
                    "🟢 ONLINE (live proxy running)"
                } else {
                    "⚪ OFFLINE (standby)"
                }
            );
            println!("  • SQLite Database:       {}", db_path.display());
            if let Ok(store) = QuarantineStore::open(&db_path) {
                let active = store.get_active_bans(now_ms).map(|r| r.len()).unwrap_or(0);
                let total = store.get_all_records(100_000).map(|r| r.len()).unwrap_or(0);
                println!("  • Active Enforced Bans:  {}", active);
                println!("  • Total Recorded Events: {}", total);
            } else {
                println!("  • Database Status:       Uninitialized");
            }
            println!("───────────────────────────────────────────────────\n");
        }
    }
    Ok(())
}
