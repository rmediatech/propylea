//! # Sovereign Quarantine Subsystem
//!
//! Autonomous, persistent, and operator-governed CIDR quarantine management.
//! Bridges sub-microsecond in-memory fast-path defense with SQLite WAL auditability
//! and Unix Domain Socket (UDS) multi-process control.

pub mod cli;
pub mod export;
pub mod ipc;
pub mod store;

pub use cli::{
    extract_ips_from_line, handle_quarantine_command, is_excluded, parse_duration_str,
    resolve_target_cidr, QuarantineCommands,
};
pub use export::{
    export_records, format_csv, format_html, format_json, format_jsonl, format_md, format_txt,
    sanitize_csv_field, ExportFormat,
};
pub use ipc::{IpcClient, IpcError, IpcRequest, IpcResponse, IpcServer};
pub use store::{QuarantineAuditEvent, QuarantineRecord, QuarantineStore, QuarantineStoreError};

use ipnet::IpNet;
use phylax::AutonomousQuarantine;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

/// Coordinates live in-memory defense, asynchronous SQLite persistence, and IPC
#[derive(Clone)]
pub struct QuarantineManager {
    in_memory: Arc<AutonomousQuarantine>,
    store: Arc<QuarantineStore>,
    tx: UnboundedSender<QuarantineRecord>,
    control_sock: PathBuf,
}

impl QuarantineManager {
    /// Initialize a new QuarantineManager with in-memory quarantine and persistent store
    pub fn new(
        in_memory: Arc<AutonomousQuarantine>,
        store: Arc<QuarantineStore>,
        control_sock: PathBuf,
    ) -> (Self, UnboundedReceiver<QuarantineRecord>) {
        let (tx, rx) = unbounded_channel();
        let manager = Self {
            in_memory,
            store,
            tx,
            control_sock,
        };
        (manager, rx)
    }

    /// Access the underlying in-memory quarantine engine
    pub fn in_memory(&self) -> &Arc<AutonomousQuarantine> {
        &self.in_memory
    }

    /// Access the SQLite persistent store
    pub fn store(&self) -> &Arc<QuarantineStore> {
        &self.store
    }

    /// Path to the Unix Domain Socket control plane
    pub fn control_sock(&self) -> &Path {
        &self.control_sock
    }

    /// Asynchronously queue a quarantine record to be persisted in SQLite without blocking
    pub fn queue_record(&self, record: QuarantineRecord) {
        let _ = self.tx.send(record);
    }

    /// Re-hydrate in-memory defense on startup by loading all active, unexpired bans from SQLite
    pub fn rehydrate_on_boot(&self) -> Result<usize, QuarantineStoreError> {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        self.rehydrate_with_timestamp(now_ms)
    }

    /// Re-hydrate in-memory defense with an explicit timestamp cutoff
    pub fn rehydrate_with_timestamp(&self, now_ms: u64) -> Result<usize, QuarantineStoreError> {
        let active_records = self.store.get_active_bans(now_ms)?;
        let count = active_records.len();

        for rec in &active_records {
            if let Ok(net) = IpNet::from_str(&rec.cidr) {
                self.in_memory.add_ban(net, rec.expires_at);
            }
        }

        if count > 0 {
            tracing::info!(
                active_bans = count,
                "🛡️ [QUARANTINE-REHYDRATION] Successfully re-hydrated active quarantined subnets into memory"
            );
        }

        Ok(count)
    }

    /// Run the background persistence worker task draining asynchronous ban events into SQLite
    pub async fn run_persistence_worker(store: Arc<QuarantineStore>, mut rx: UnboundedReceiver<QuarantineRecord>) {
        while let Some(record) = rx.recv().await {
            if let Err(e) = store.record_ban(&record) {
                tracing::error!(
                    cidr = %record.cidr,
                    error = %e,
                    "🚨 [QUARANTINE-STORE] Failed to persist quarantine record to SQLite"
                );
            }
        }
    }
}
