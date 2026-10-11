//! # Sovereign Quarantine CLI Interface
//!
//! Subcommands for querying, exporting, and managing quarantined subnets.
//! Seamlessly orchestrates live Unix Domain Socket IPC commands when the daemon is running,
//! or falls back to direct SQLite store mutations when operating offline.

use super::export::{export_records, ExportFormat};
use super::ipc::{IpcClient, IpcRequest, IpcResponse};
use super::store::{QuarantineRecord, QuarantineStore};
use crate::config::PropyleaConfig;
use clap::Subcommand;
use ipnet::IpNet;
use phylax::AutonomousQuarantine;
use std::net::IpAddr;
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
    /// Quarantine one or more IP addresses or CIDR blocks
    Ban {
        /// IP addresses or CIDR blocks to ban (e.g. 198.51.100.42 203.0.113.0/24)
        #[arg(required = true)]
        targets: Vec<String>,

        /// Reason or infraction category for the ban
        #[arg(short, long, default_value = "Manual operator ban")]
        reason: String,

        /// Ban duration (e.g. 30m, 1h, 24h, 7d, 86400)
        #[arg(short, long, default_value = "24h")]
        duration: String,

        /// Quarantine exact host IP (/32 or /128) rather than default subnet (/24 or /48)
        #[arg(short, long)]
        exact: bool,
    },
    /// Unquarantine one or more IP addresses or CIDR subnets
    Unban {
        /// IP addresses or CIDR blocks to unban (e.g. 198.51.100.42 203.0.113.0/24)
        #[arg(required = true)]
        targets: Vec<String>,
    },
    /// Ingest historical bad actors from log files or journalctl into persistent quarantine
    IngestLogs {
        /// Path to log file or '-' for stdin
        #[arg(short, long, default_value = "-")]
        input: String,

        /// Default infraction type / reason
        #[arg(short, long, default_value = "historical_journal_ingest")]
        reason: String,

        /// Ban duration (e.g. 24h, 7d, 30d)
        #[arg(short, long, default_value = "24h")]
        duration: String,

        /// IPs or CIDR blocks to exclude (e.g. trusted operator IPs)
        #[arg(short, long)]
        exclude: Vec<String>,

        /// Quarantine exact host IP (/32 or /128) rather than default subnet (/24 or /48)
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
            let duration_secs = parse_duration_str(&duration)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

            if client.is_alive().await {
                match client
                    .send_request(&IpcRequest::Ban {
                        targets: targets.clone(),
                        reason: Some(reason.clone()),
                        duration_secs: Some(duration_secs),
                        exact,
                    })
                    .await?
                {
                    IpcResponse::Banned {
                        count,
                        banned_cidrs,
                    } => {
                        println!(
                            "✅ [QUARANTINE-IPC] Successfully quarantined {} subnet(s) in running daemon:",
                            count
                        );
                        for cidr in banned_cidrs {
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
                let duration_ms = duration_secs * 1000;
                let expires_at = now_ms + duration_ms;
                let mut banned_cidrs = Vec::new();

                for target in targets {
                    if let Some((net, trigger_ip)) = resolve_target_cidr(&target, exact) {
                        let cidr_str = net.to_string();
                        let ip_version = if net.addr().is_ipv4() { 4 } else { 6 };

                        let rec = QuarantineRecord {
                            cidr: cidr_str.clone(),
                            ip_version,
                            trigger_ip,
                            infraction_type: reason.clone(),
                            infraction_count: 1,
                            quarantined_at: now_ms,
                            expires_at,
                            user_agent: None,
                            active: true,
                        };

                        store.record_ban(&rec)?;
                        banned_cidrs.push(cidr_str);
                    }
                }

                println!(
                    "✅ [QUARANTINE-STORE] Offline store quarantined {} subnet(s) in SQLite (daemon not running):",
                    banned_cidrs.len()
                );
                for cidr in banned_cidrs {
                    println!("   • {}", cidr);
                }
            }
        }
        QuarantineCommands::IngestLogs {
            input,
            reason,
            duration,
            exclude,
            exact,
        } => {
            let duration_secs = parse_duration_str(&duration)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

            // Read lines from stdin or file
            let lines: Vec<String> = if input == "-" {
                use std::io::BufRead;
                let stdin = std::io::stdin();
                stdin.lock().lines().filter_map(|l| l.ok()).collect()
            } else {
                use std::io::BufRead;
                let f = std::fs::File::open(&input)?;
                std::io::BufReader::new(f)
                    .lines()
                    .filter_map(|l| l.ok())
                    .collect()
            };

            let mut targets = std::collections::HashSet::new();
            for line in lines {
                for ip_str in extract_ips_from_line(&line) {
                    if let Ok(addr) = std::net::IpAddr::from_str(&ip_str) {
                        if !is_excluded(addr, &exclude) {
                            targets.insert(ip_str);
                        }
                    } else if let Ok(net) = ipnet::IpNet::from_str(&ip_str) {
                        if !is_excluded(net.addr(), &exclude) {
                            targets.insert(ip_str);
                        }
                    }
                }
            }

            let target_list: Vec<String> = targets.into_iter().collect();
            let total_targets = target_list.len();

            if total_targets == 0 {
                println!("ℹ️  [QUARANTINE-INGEST] No eligible offending IP addresses or subnets discovered in input.");
                return Ok(());
            }

            println!(
                "🛡️  [QUARANTINE-INGEST] Discovered {} unique candidate offending IP/subnet targets. Ingesting...",
                total_targets
            );

            // Ingest discovered targets in batches of 500
            for chunk in target_list.chunks(500) {
                let chunk_vec = chunk.to_vec();
                if client.is_alive().await {
                    match client
                        .send_request(&IpcRequest::Ban {
                            targets: chunk_vec,
                            reason: Some(reason.clone()),
                            duration_secs: Some(duration_secs),
                            exact,
                        })
                        .await?
                    {
                        IpcResponse::Banned { count, .. } => {
                            println!("   • Ingested batch of {} subnets into running daemon", count);
                        }
                        IpcResponse::Error { message } => {
                            eprintln!("❌ [QUARANTINE-IPC] Ingest batch error: {}", message);
                        }
                        _ => {}
                    }
                } else {
                    let store = QuarantineStore::open(&db_path)?;
                    let duration_ms = duration_secs * 1000;
                    let expires_at = now_ms + duration_ms;
                    let mut batch_count = 0;

                    for target in chunk_vec {
                        if let Some((net, trigger_ip)) = resolve_target_cidr(&target, exact) {
                            let cidr_str = net.to_string();
                            let ip_version = if net.addr().is_ipv4() { 4 } else { 6 };

                            let rec = QuarantineRecord {
                                cidr: cidr_str,
                                ip_version,
                                trigger_ip,
                                infraction_type: reason.clone(),
                                infraction_count: 1,
                                quarantined_at: now_ms,
                                expires_at,
                                user_agent: None,
                                active: true,
                            };

                            if store.record_ban(&rec).is_ok() {
                                batch_count += 1;
                            }
                        }
                    }
                    println!("   • Ingested batch of {} subnets into SQLite WAL store", batch_count);
                }
            }

            println!("✅ [QUARANTINE-INGEST] Ingest complete: {} candidates processed.", total_targets);
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

/// Parse a human duration string (e.g. "30m", "1h", "24h", "7d", "86400") into seconds
pub fn parse_duration_str(s: &str) -> Result<u64, String> {
    let s = s.trim().to_lowercase();
    if s.is_empty() {
        return Ok(86_400);
    }
    if let Ok(num) = s.parse::<u64>() {
        return Ok(num);
    }
    let (num_part, multiplier) = if s.ends_with('s') {
        (&s[..s.len() - 1], 1)
    } else if s.ends_with('m') {
        (&s[..s.len() - 1], 60)
    } else if s.ends_with('h') {
        (&s[..s.len() - 1], 3600)
    } else if s.ends_with('d') {
        (&s[..s.len() - 1], 86400)
    } else if s.ends_with('w') {
        (&s[..s.len() - 1], 7 * 86400)
    } else {
        return Err(format!("Unrecognized duration format: '{}'", s));
    };

    let num: u64 = num_part
        .parse()
        .map_err(|_| format!("Invalid duration number: '{}'", num_part))?;
    Ok(num * multiplier)
}

/// Resolve a user target (IP or CIDR) into an IpNet subnet block and trigger IP
pub fn resolve_target_cidr(target: &str, exact: bool) -> Option<(IpNet, String)> {
    let target = target.trim();
    if target.is_empty() {
        return None;
    }

    if target.contains('/') {
        let net = IpNet::from_str(target).ok()?;
        Some((net, target.to_string()))
    } else if exact {
        let addr = IpAddr::from_str(target).ok()?;
        match addr {
            IpAddr::V4(v4) => {
                let net = ipnet::Ipv4Net::new(v4, 32).ok()?;
                Some((IpNet::V4(net), target.to_string()))
            }
            IpAddr::V6(v6) => {
                let net = ipnet::Ipv6Net::new(v6, 128).ok()?;
                Some((IpNet::V6(net), target.to_string()))
            }
        }
    } else {
        let cidr_str = AutonomousQuarantine::derive_quarantine_cidr(target)?;
        let net = IpNet::from_str(&cidr_str).ok()?;
        Some((net, target.to_string()))
    }
}

/// Check if an IP address falls within any excluded IP or subnet
pub fn is_excluded(addr: IpAddr, excludes: &[String]) -> bool {
    for ex in excludes {
        let ex = ex.trim();
        if ex.is_empty() {
            continue;
        }
        if let Ok(net) = IpNet::from_str(ex) {
            if net.contains(&addr) {
                return true;
            }
        } else if let Ok(ex_addr) = IpAddr::from_str(ex) {
            if ex_addr == addr {
                return true;
            }
        }
    }
    false
}

/// Extract offending IP addresses or CIDR blocks from arbitrary log lines
pub fn extract_ips_from_line(line: &str) -> Vec<String> {
    let mut ips = Vec::new();
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return ips;
    }

    // 1. Look for `ip=` or `ip: ` key-value pairs
    if trimmed.contains("ip=") || trimmed.contains("ip:") {
        for part in trimmed.split(|c: char| c == ' ' || c == ',' || c == ';' || c == '\t') {
            let part = part.trim();
            if let Some(val) = part.strip_prefix("ip=").or_else(|| part.strip_prefix("ip:")) {
                let cleaned = val.trim_matches(|c: char| c == '"' || c == '\'' || c == '[' || c == ']');
                if IpAddr::from_str(cleaned).is_ok() || IpNet::from_str(cleaned).is_ok() {
                    ips.push(cleaned.to_string());
                }
            }
        }
    }

    // 2. Fallback: Check each whitespace-separated token
    if ips.is_empty() {
        for token in trimmed.split_whitespace() {
            let cleaned = token.trim_matches(|c: char| c == '"' || c == '\'' || c == ',' || c == ';' || c == '[' || c == ']');
            if IpAddr::from_str(cleaned).is_ok() || IpNet::from_str(cleaned).is_ok() {
                ips.push(cleaned.to_string());
            }
        }
    }

    ips
}
