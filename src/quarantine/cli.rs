//! # Sovereign Quarantine CLI Interface
//!
//! Subcommands for querying, exporting, and managing quarantined subnets.
//! Seamlessly orchestrates live Unix Domain Socket IPC commands when the daemon is running,
//! or falls back to direct SQLite store mutations when operating offline.

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
        /// Output format (txt, json, jsonl, md, csv, html)
        #[arg(short, long, default_value = "md")]
        format: String,

        /// Display only currently active enforced bans
        #[arg(short, long)]
        active_only: bool,

        /// Maximum number of records to return
        #[arg(short, long, default_value_t = 100)]
        limit: usize,
    },
    /// Export quarantine records to a file in any supported format
    Export {
        /// Target file path
        file: PathBuf,

        /// Output format (txt, json, jsonl, md, csv, html)
        #[arg(short, long, default_value = "html")]
        format: String,

        /// Export only currently active enforced bans
        #[arg(short, long)]
        active_only: bool,
    },
    /// Unquarantine one or more IP addresses or CIDR subnets
    Unban {
        /// IP addresses or CIDR blocks to unban (e.g. 198.51.100.42 203.0.113.0/24)
        #[arg(required = true)]
        targets: Vec<String>,
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
                // Offline fallback directly to SQLite store
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

            let rendered = export_records(&records, export_fmt, now_ms)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

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

            let rendered = export_records(&records, export_fmt, now_ms)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

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
