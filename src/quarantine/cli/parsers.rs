//! # Quarantine CLI Target, Duration & Log Parsers (`quarantine/cli/parsers.rs`)

use super::super::ipc::{IpcClient, IpcRequest, IpcResponse};
use super::super::store::{QuarantineRecord, QuarantineStore};
use ipnet::IpNet;
use phylax::AutonomousQuarantine;
use std::net::IpAddr;
use std::path::PathBuf;
use std::str::FromStr;

pub async fn exec_cli_ban(
    client: &IpcClient,
    db_path: &PathBuf,
    targets: Vec<String>,
    reason: String,
    duration: &str,
    exact: bool,
    now_ms: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let duration_secs = parse_duration_str(duration)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

    if client.is_alive().await {
        match client
            .send_request(&IpcRequest::Ban {
                targets,
                reason: Some(reason),
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
        let store = QuarantineStore::open(db_path)?;
        let expires_at = now_ms + duration_secs * 1000;
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
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn exec_cli_ingest(
    client: &IpcClient,
    db_path: &PathBuf,
    input: &str,
    reason: &str,
    duration: &str,
    exclude: &[String],
    exact: bool,
    now_ms: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let duration_secs = parse_duration_str(duration)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

    let lines: Vec<String> = if input == "-" {
        use std::io::BufRead;
        std::io::stdin()
            .lock()
            .lines()
            .map_while(Result::ok)
            .collect()
    } else {
        use std::io::BufRead;
        let f = std::fs::File::open(input)?;
        std::io::BufReader::new(f)
            .lines()
            .map_while(Result::ok)
            .collect()
    };

    let mut targets = std::collections::HashSet::new();
    for line in lines {
        for ip_str in extract_ips_from_line(&line) {
            if let Ok(addr) = IpAddr::from_str(&ip_str) {
                if !is_excluded(addr, exclude) {
                    targets.insert(ip_str);
                }
            } else if let Ok(net) = IpNet::from_str(&ip_str) {
                if !is_excluded(net.addr(), exclude) {
                    targets.insert(ip_str);
                }
            }
        }
    }

    let target_list: Vec<String> = targets.into_iter().collect();
    if target_list.is_empty() {
        println!("ℹ️  [QUARANTINE-INGEST] No eligible offending IP addresses or subnets discovered in input.");
        return Ok(());
    }

    println!(
        "🛡️  [QUARANTINE-INGEST] Discovered {} unique candidate offending IP/subnet targets. Ingesting...",
        target_list.len()
    );

    for chunk in target_list.chunks(500) {
        exec_cli_ban(
            client,
            db_path,
            chunk.to_vec(),
            reason.to_string(),
            &duration_secs.to_string(),
            exact,
            now_ms,
        )
        .await?;
    }
    println!(
        "✅ [QUARANTINE-INGEST] Ingest complete: {} candidates processed.",
        target_list.len()
    );
    Ok(())
}

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

pub fn extract_ips_from_line(line: &str) -> Vec<String> {
    let mut ips = Vec::new();
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return ips;
    }

    if trimmed.contains("ip=") || trimmed.contains("ip:") {
        for part in trimmed.split([' ', ',', ';', '\t']) {
            let part = part.trim();
            if let Some(val) = part
                .strip_prefix("ip=")
                .or_else(|| part.strip_prefix("ip:"))
            {
                let cleaned =
                    val.trim_matches(|c: char| c == '"' || c == '\'' || c == '[' || c == ']');
                if IpAddr::from_str(cleaned).is_ok() || IpNet::from_str(cleaned).is_ok() {
                    ips.push(cleaned.to_string());
                }
            }
        }
    }

    if ips.is_empty() {
        for token in trimmed.split_whitespace() {
            let cleaned = token.trim_matches(|c: char| {
                c == '"' || c == '\'' || c == ',' || c == ';' || c == '[' || c == ']'
            });
            if IpAddr::from_str(cleaned).is_ok() || IpNet::from_str(cleaned).is_ok() {
                ips.push(cleaned.to_string());
            }
        }
    }

    ips
}
