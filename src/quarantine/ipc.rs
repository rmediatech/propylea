//! # Sovereign Quarantine IPC Control Plane
//!
//! Provides zero-latency, local-only inter-process communication over POSIX Unix Domain Sockets (UDS).
//! Enables operators to unquarantine single or multiple subnets from the CLI in real-time
//! without restarting the running `propylea serve` daemon.

use super::store::{QuarantineRecord, QuarantineStore};
#[cfg(unix)]
use ipnet::IpNet;
use phylax::AutonomousQuarantine;
use serde::{Deserialize, Serialize};
#[cfg(unix)]
use std::net::IpAddr;
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::str::FromStr;
use std::sync::Arc;
use thiserror::Error;
#[cfg(unix)]
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};

#[cfg(not(unix))]
pub struct UnixListener;

#[cfg(not(unix))]
pub struct UnixStream;

#[derive(Debug, Error)]
pub enum IpcError {
    #[error("I/O error on control socket: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("Daemon control socket unavailable at {0} (daemon not running)")]
    DaemonOffline(PathBuf),
    #[error("Daemon response error: {0}")]
    DaemonError(String),
}

/// Request payloads sent from CLI to daemon
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IpcRequest {
    Ban {
        targets: Vec<String>,
        reason: Option<String>,
        duration_secs: Option<u64>,
        exact: bool,
    },
    Unban {
        targets: Vec<String>,
    },
    UnbanAll,
    ListActive,
    Status,
}

/// Response payloads sent from daemon to CLI
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IpcResponse {
    Banned {
        count: usize,
        banned_cidrs: Vec<String>,
    },
    Unbanned {
        count: usize,
        unbanned_cidrs: Vec<String>,
    },
    List {
        records: Vec<QuarantineRecord>,
    },
    Status {
        active_count: usize,
        total_records: usize,
    },
    Error {
        message: String,
    },
}

/// Server actor running inside `propylea serve`
pub struct IpcServer;

impl IpcServer {
    /// Bind the Unix Domain Socket, ensuring strict `0600` permissions
    #[cfg(unix)]
    pub fn bind<P: AsRef<Path>>(path: P) -> Result<UnixListener, IpcError> {
        let p = path.as_ref().to_path_buf();
        if let Some(parent) = p.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        // Remove existing stale socket if present
        if p.exists() {
            let _ = std::fs::remove_file(&p);
        }

        let listener = UnixListener::bind(&p)?;

        // Enforce owner-only permissions
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600));

        Ok(listener)
    }

    /// Bind stub for non-Unix targets
    #[cfg(not(unix))]
    pub fn bind<P: AsRef<Path>>(_path: P) -> Result<UnixListener, IpcError> {
        Err(IpcError::DaemonError(
            "Unix domain sockets are not supported on this platform".to_string(),
        ))
    }

    /// Run the IPC listener loop in the background
    #[cfg(unix)]
    pub async fn run_loop(
        listener: UnixListener,
        sock_path: PathBuf,
        in_memory: Arc<AutonomousQuarantine>,
        store: Arc<QuarantineStore>,
    ) {
        tracing::info!(socket = %sock_path.display(), "🛡️ [QUARANTINE-IPC] Control socket listening for live operator commands");

        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let in_mem = in_memory.clone();
                    let st = store.clone();
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_connection(stream, in_mem, st).await {
                            tracing::debug!(error = %e, "[QUARANTINE-IPC] Error handling control socket connection");
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!(error = %e, "[QUARANTINE-IPC] Socket accept error");
                    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                }
            }
        }
    }

    /// Run loop stub for non-Unix targets
    #[cfg(not(unix))]
    pub async fn run_loop(
        _listener: UnixListener,
        _sock_path: PathBuf,
        _in_memory: Arc<AutonomousQuarantine>,
        _store: Arc<QuarantineStore>,
    ) {
    }

    #[cfg(unix)]
    async fn handle_connection(
        stream: UnixStream,
        in_memory: Arc<AutonomousQuarantine>,
        store: Arc<QuarantineStore>,
    ) -> Result<(), IpcError> {
        let (reader, mut writer) = stream.into_split();
        let mut buf_reader = BufReader::new(reader);
        let mut line = String::new();

        if buf_reader.read_line(&mut line).await? == 0 {
            return Ok(());
        }

        let req: IpcRequest = serde_json::from_str(&line)?;
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let res = match req {
            IpcRequest::Ban {
                targets,
                reason,
                duration_secs,
                exact,
            } => {
                let duration_ms = duration_secs.unwrap_or(86_400) * 1000;
                let reason_str = reason.unwrap_or_else(|| "Manual operator ban".to_string());
                let expires_at = now_ms + duration_ms;
                let mut banned_cidrs = Vec::new();

                for target in targets {
                    let target = target.trim();
                    if target.is_empty() {
                        continue;
                    }

                    let resolved = if target.contains('/') {
                        IpNet::from_str(target)
                            .ok()
                            .map(|n| (n, target.to_string()))
                    } else if exact {
                        match IpAddr::from_str(target) {
                            Ok(IpAddr::V4(v4)) => ipnet::Ipv4Net::new(v4, 32)
                                .ok()
                                .map(|n| (IpNet::V4(n), target.to_string())),
                            Ok(IpAddr::V6(v6)) => ipnet::Ipv6Net::new(v6, 128)
                                .ok()
                                .map(|n| (IpNet::V6(n), target.to_string())),
                            Err(_) => None,
                        }
                    } else {
                        AutonomousQuarantine::derive_quarantine_cidr(target)
                            .and_then(|cidr_str| IpNet::from_str(&cidr_str).ok())
                            .map(|n| (n, target.to_string()))
                    };

                    if let Some((net, trigger_ip)) = resolved {
                        let cidr_str = net.to_string();
                        let ip_version = if net.addr().is_ipv4() { 4 } else { 6 };

                        // 1. Immediately insert into live memory fast-path
                        in_memory.add_ban(net, expires_at);

                        // 2. Persist to SQLite WAL store
                        let rec = QuarantineRecord {
                            cidr: cidr_str.clone(),
                            ip_version,
                            trigger_ip,
                            infraction_type: reason_str.clone(),
                            infraction_count: 1,
                            quarantined_at: now_ms,
                            expires_at,
                            user_agent: None,
                            active: true,
                        };

                        if let Err(e) = store.record_ban(&rec) {
                            tracing::error!(error = %e, "[QUARANTINE-IPC] Database ban record failed");
                        }

                        banned_cidrs.push(cidr_str);
                    }
                }

                IpcResponse::Banned {
                    count: banned_cidrs.len(),
                    banned_cidrs,
                }
            }
            IpcRequest::Unban { targets } => {
                let mut total_unbanned = 0;
                let mut all_cidrs = Vec::new();

                for target in targets {
                    // 1. Immediately remove from live memory fast-path
                    let mem_unbanned = in_memory.unban(&target);

                    // 2. Persist state change to SQLite WAL
                    match store.unban(&target, "Live IPC command", now_ms) {
                        Ok(cidrs) => {
                            if !cidrs.is_empty() {
                                total_unbanned += cidrs.len();
                                all_cidrs.extend(cidrs);
                            } else if mem_unbanned {
                                total_unbanned += 1;
                                all_cidrs.push(target);
                            }
                        }
                        Err(e) => {
                            tracing::error!(error = %e, "[QUARANTINE-IPC] Database unban failed");
                        }
                    }
                }

                IpcResponse::Unbanned {
                    count: total_unbanned,
                    unbanned_cidrs: all_cidrs,
                }
            }
            IpcRequest::UnbanAll => {
                let _ = in_memory.unban_all();
                match store.unban_all("Live IPC unban_all command", now_ms) {
                    Ok(count) => IpcResponse::Unbanned {
                        count,
                        unbanned_cidrs: Vec::new(),
                    },
                    Err(e) => IpcResponse::Error {
                        message: e.to_string(),
                    },
                }
            }
            IpcRequest::ListActive => match store.get_active_bans(now_ms) {
                Ok(records) => IpcResponse::List { records },
                Err(e) => IpcResponse::Error {
                    message: e.to_string(),
                },
            },
            IpcRequest::Status => {
                let active_count = in_memory.active_bans_count();
                let total_records = store.get_all_records(100_000).map(|r| r.len()).unwrap_or(0);
                IpcResponse::Status {
                    active_count,
                    total_records,
                }
            }
        };

        let res_bytes = serde_json::to_vec(&res)?;
        writer.write_all(&res_bytes).await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;

        Ok(())
    }
}

/// Client helper used by CLI tools to talk to the live daemon
pub struct IpcClient {
    #[allow(dead_code)]
    sock_path: PathBuf,
}

impl IpcClient {
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        Self {
            sock_path: path.as_ref().to_path_buf(),
        }
    }

    /// Check if the daemon's control socket is active and responsive
    #[cfg(unix)]
    pub async fn is_alive(&self) -> bool {
        UnixStream::connect(&self.sock_path).await.is_ok()
    }

    /// Check if the daemon's control socket is active (stub for non-Unix)
    #[cfg(not(unix))]
    pub async fn is_alive(&self) -> bool {
        false
    }

    /// Send a request to the live daemon and await the response
    #[cfg(unix)]
    pub async fn send_request(&self, req: &IpcRequest) -> Result<IpcResponse, IpcError> {
        let stream = UnixStream::connect(&self.sock_path)
            .await
            .map_err(|_| IpcError::DaemonOffline(self.sock_path.clone()))?;

        let (reader, mut writer) = stream.into_split();
        let mut req_bytes = serde_json::to_vec(req)?;
        req_bytes.push(b'\n');

        writer.write_all(&req_bytes).await?;
        writer.flush().await?;

        let mut buf_reader = BufReader::new(reader);
        let mut line = String::new();
        buf_reader.read_line(&mut line).await?;

        let res: IpcResponse = serde_json::from_str(&line)?;
        Ok(res)
    }

    /// Send a request to the live daemon (stub for non-Unix)
    #[cfg(not(unix))]
    pub async fn send_request(&self, _req: &IpcRequest) -> Result<IpcResponse, IpcError> {
        Err(IpcError::DaemonError(
            "Unix domain sockets are not supported on this platform".to_string(),
        ))
    }
}
