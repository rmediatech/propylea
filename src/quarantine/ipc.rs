//! # Sovereign Quarantine IPC Control Plane (`quarantine/ipc.rs`)

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

#[rustfmt::skip]
#[derive(Debug, Error)]
pub enum IpcError {
    #[error("I/O error on control socket: {0}")] Io(#[from] std::io::Error),
    #[error("Serialization error: {0}")] Serialization(#[from] serde_json::Error),
    #[error("Daemon control socket unavailable at {0} (daemon not running)")] DaemonOffline(PathBuf),
    #[error("Daemon response error: {0}")] DaemonError(String),
}

#[rustfmt::skip]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IpcRequest {
    Ban { targets: Vec<String>, reason: Option<String>, duration_secs: Option<u64>, exact: bool },
    Unban { targets: Vec<String> },
    UnbanAll,
    ListActive,
    Status,
}

#[rustfmt::skip]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IpcResponse {
    Banned { count: usize, banned_cidrs: Vec<String> },
    Unbanned { count: usize, unbanned_cidrs: Vec<String> },
    List { records: Vec<QuarantineRecord> },
    Status { active_count: usize, total_records: usize },
    Error { message: String },
}

pub struct IpcServer;

impl IpcServer {
    #[cfg(unix)]
    pub fn bind<P: AsRef<Path>>(path: P) -> Result<UnixListener, IpcError> {
        let p = path.as_ref().to_path_buf();
        if let Some(parent) = p.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if p.exists() {
            let _ = std::fs::remove_file(&p);
        }
        let listener = UnixListener::bind(&p)?;
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600));
        Ok(listener)
    }

    #[cfg(not(unix))]
    pub fn bind<P: AsRef<Path>>(_path: P) -> Result<UnixListener, IpcError> {
        Err(IpcError::DaemonError(
            "Unix domain sockets not supported".into(),
        ))
    }

    #[cfg(unix)]
    pub async fn run_loop(
        listener: UnixListener,
        sock_path: PathBuf,
        in_memory: Arc<AutonomousQuarantine>,
        store: Arc<QuarantineStore>,
    ) {
        tracing::info!(socket = %sock_path.display(), "🛡️ [QUARANTINE-IPC] Control socket listening");
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let in_mem = in_memory.clone();
                    let st = store.clone();
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_connection(stream, in_mem, st).await {
                            tracing::debug!(error = %e, "[QUARANTINE-IPC] Connection error");
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
            } => Self::exec_ban(
                &in_memory,
                &store,
                targets,
                reason,
                duration_secs,
                exact,
                now_ms,
            ),
            IpcRequest::Unban { targets } => Self::exec_unban(&in_memory, &store, targets, now_ms),
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

    #[cfg(unix)]
    fn exec_ban(
        in_memory: &AutonomousQuarantine,
        store: &QuarantineStore,
        targets: Vec<String>,
        reason: Option<String>,
        duration_secs: Option<u64>,
        exact: bool,
        now_ms: u64,
    ) -> IpcResponse {
        let expires_at = now_ms + duration_secs.unwrap_or(86_400) * 1000;
        let reason_str = reason.unwrap_or_else(|| "Manual operator ban".to_string());
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
                    .and_then(|c| IpNet::from_str(&c).ok())
                    .map(|n| (n, target.to_string()))
            };

            if let Some((net, trigger_ip)) = resolved {
                let cidr_str = net.to_string();
                let ip_version = if net.addr().is_ipv4() { 4 } else { 6 };
                in_memory.add_ban(net, expires_at);
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
                let _ = store.record_ban(&rec);
                banned_cidrs.push(cidr_str);
            }
        }
        IpcResponse::Banned {
            count: banned_cidrs.len(),
            banned_cidrs,
        }
    }

    #[cfg(unix)]
    #[rustfmt::skip]
    fn exec_unban(in_memory: &AutonomousQuarantine, store: &QuarantineStore, targets: Vec<String>, now_ms: u64) -> IpcResponse {
        let (mut total_unbanned, mut all_cidrs) = (0, Vec::new());
        for target in targets {
            let mem_unbanned = in_memory.unban(&target);
            if let Ok(cidrs) = store.unban(&target, "Live IPC command", now_ms) {
                if !cidrs.is_empty() {
                    total_unbanned += cidrs.len();
                    all_cidrs.extend(cidrs);
                } else if mem_unbanned {
                    total_unbanned += 1;
                    all_cidrs.push(target);
                }
            }
        }
        IpcResponse::Unbanned { count: total_unbanned, unbanned_cidrs: all_cidrs }
    }
}

pub struct IpcClient {
    #[allow(dead_code)]
    sock_path: PathBuf,
}

#[rustfmt::skip]
impl IpcClient {
    pub fn new<P: AsRef<Path>>(path: P) -> Self { Self { sock_path: path.as_ref().to_path_buf() } }
    #[cfg(unix)]
    pub async fn is_alive(&self) -> bool { UnixStream::connect(&self.sock_path).await.is_ok() }
    #[cfg(not(unix))]
    pub async fn is_alive(&self) -> bool { false }

    #[cfg(unix)]
    pub async fn send_request(&self, req: &IpcRequest) -> Result<IpcResponse, IpcError> {
        let stream = UnixStream::connect(&self.sock_path).await.map_err(|_| IpcError::DaemonOffline(self.sock_path.clone()))?;
        let (reader, mut writer) = stream.into_split();
        let mut req_bytes = serde_json::to_vec(req)?;
        req_bytes.push(b'\n');
        writer.write_all(&req_bytes).await?;
        writer.flush().await?;
        let mut line = String::new();
        BufReader::new(reader).read_line(&mut line).await?;
        Ok(serde_json::from_str(&line)?)
    }

    #[cfg(not(unix))]
    pub async fn send_request(&self, _req: &IpcRequest) -> Result<IpcResponse, IpcError> {
        Err(IpcError::DaemonError("Unix domain sockets not supported".into()))
    }
}
