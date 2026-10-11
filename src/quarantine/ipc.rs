//! # Sovereign Quarantine IPC Control Plane
//!
//! Provides zero-latency, local-only inter-process communication over POSIX Unix Domain Sockets (UDS).
//! Enables operators to unquarantine single or multiple subnets from the CLI in real-time
//! without restarting the running `propylea serve` daemon.

use super::store::{QuarantineRecord, QuarantineStore};
use phylax::AutonomousQuarantine;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

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
    Unban { targets: Vec<String> },
    UnbanAll,
    ListActive,
    Status,
}

/// Response payloads sent from daemon to CLI
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IpcResponse {
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
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600));
        }

        Ok(listener)
    }

    /// Run the IPC listener loop in the background
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
    sock_path: PathBuf,
}

impl IpcClient {
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        Self {
            sock_path: path.as_ref().to_path_buf(),
        }
    }

    /// Check if the daemon's control socket is active and responsive
    pub async fn is_alive(&self) -> bool {
        UnixStream::connect(&self.sock_path).await.is_ok()
    }

    /// Send a request to the live daemon and await the response
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
}
