//! # Sovereign Quarantine Persistent Store (`quarantine/store.rs`)

use ipnet::IpNet;
use rusqlite::{params, Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Mutex;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum QuarantineStoreError {
    #[error("SQLite database error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Invalid CIDR or IP representation: {0}")]
    InvalidNetwork(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QuarantineRecord {
    pub cidr: String,
    pub ip_version: u8,
    pub trigger_ip: String,
    pub infraction_type: String,
    pub infraction_count: u32,
    pub quarantined_at: u64,
    pub expires_at: u64,
    pub user_agent: Option<String>,
    pub active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QuarantineAuditEvent {
    pub id: i64,
    pub cidr: String,
    pub event_type: String,
    pub event_ts: u64,
    pub details: Option<String>,
}

pub struct QuarantineStore {
    path: PathBuf,
    conn: Mutex<Connection>,
}

impl QuarantineStore {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, QuarantineStoreError> {
        let p = path.as_ref().to_path_buf();
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open_with_flags(
            &p,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        conn.busy_timeout(std::time::Duration::from_millis(5000))?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL; PRAGMA foreign_keys = ON; PRAGMA temp_store = MEMORY;",
        )?;
        let store = Self {
            path: p,
            conn: Mutex::new(conn),
        };
        store.init_schema()?;
        Ok(store)
    }

    pub fn in_memory() -> Result<Self, QuarantineStoreError> {
        let conn = Connection::open_in_memory()?;
        conn.busy_timeout(std::time::Duration::from_millis(5000))?;
        let store = Self {
            path: PathBuf::from(":memory:"),
            conn: Mutex::new(conn),
        };
        store.init_schema()?;
        Ok(store)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn init_schema(&self) -> Result<(), QuarantineStoreError> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS quarantined_subnets (
                cidr TEXT PRIMARY KEY, ip_version INTEGER NOT NULL, trigger_ip TEXT NOT NULL,
                infraction_type TEXT NOT NULL, infraction_count INTEGER NOT NULL,
                quarantined_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
                user_agent TEXT, active INTEGER NOT NULL DEFAULT 1
            );
            CREATE TABLE IF NOT EXISTS quarantine_audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT, cidr TEXT NOT NULL,
                event_type TEXT NOT NULL, event_ts INTEGER NOT NULL, details TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_quarantine_active ON quarantined_subnets(active, expires_at);
            CREATE INDEX IF NOT EXISTS idx_quarantine_audit_ts ON quarantine_audit_log(event_ts);",
        )?;
        Ok(())
    }

    pub fn record_ban(&self, rec: &QuarantineRecord) -> Result<(), QuarantineStoreError> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        tx.execute(
            "INSERT INTO quarantined_subnets (
                cidr, ip_version, trigger_ip, infraction_type, infraction_count,
                quarantined_at, expires_at, user_agent, active
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
            ON CONFLICT(cidr) DO UPDATE SET
                infraction_count = infraction_count + excluded.infraction_count,
                expires_at = excluded.expires_at,
                user_agent = COALESCE(excluded.user_agent, user_agent),
                active = 1;",
            params![
                rec.cidr,
                rec.ip_version,
                rec.trigger_ip,
                rec.infraction_type,
                rec.infraction_count,
                rec.quarantined_at,
                rec.expires_at,
                rec.user_agent,
                if rec.active { 1 } else { 0 }
            ],
        )?;
        tx.execute(
            "INSERT INTO quarantine_audit_log (cidr, event_type, event_ts, details) VALUES (?1, 'quarantined', ?2, ?3);",
            params![rec.cidr, rec.quarantined_at, format!("Trigger IP: {}, Infraction: {}", rec.trigger_ip, rec.infraction_type)],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn unban(
        &self,
        target: &str,
        details: &str,
        now_ms: u64,
    ) -> Result<Vec<String>, QuarantineStoreError> {
        let mut conn = self.conn.lock().unwrap();
        let mut unbanned = Vec::new();
        {
            let mut stmt = conn
                .prepare("SELECT cidr FROM quarantined_subnets WHERE cidr = ?1 AND active = 1;")?;
            let exact: Vec<String> = stmt
                .query_map(params![target], |r| r.get(0))?
                .filter_map(|r| r.ok())
                .collect();
            if !exact.is_empty() {
                unbanned.extend(exact);
            } else if let Ok(addr) = IpAddr::from_str(target) {
                let mut stmt =
                    conn.prepare("SELECT cidr FROM quarantined_subnets WHERE active = 1;")?;
                let active: Vec<String> = stmt
                    .query_map([], |r| r.get(0))?
                    .filter_map(|r| r.ok())
                    .collect();
                for cidr in active {
                    if let Ok(net) = IpNet::from_str(&cidr) {
                        if net.contains(&addr) {
                            unbanned.push(cidr);
                        }
                    }
                }
            }
        }
        if unbanned.is_empty() {
            return Ok(Vec::new());
        }
        let tx = conn.transaction()?;
        for cidr in &unbanned {
            tx.execute(
                "UPDATE quarantined_subnets SET active = 0 WHERE cidr = ?1;",
                params![cidr],
            )?;
            tx.execute(
                "INSERT INTO quarantine_audit_log (cidr, event_type, event_ts, details) VALUES (?1, 'unbanned', ?2, ?3);",
                params![cidr, now_ms, details],
            )?;
        }
        tx.commit()?;
        Ok(unbanned)
    }

    pub fn unban_all(&self, details: &str, now_ms: u64) -> Result<usize, QuarantineStoreError> {
        let mut conn = self.conn.lock().unwrap();
        let active_cidrs: Vec<String> = {
            let mut stmt =
                conn.prepare("SELECT cidr FROM quarantined_subnets WHERE active = 1;")?;
            let rows: Vec<String> = stmt
                .query_map([], |r| r.get(0))?
                .filter_map(|r| r.ok())
                .collect();
            rows
        };
        let count = active_cidrs.len();
        if count == 0 {
            return Ok(0);
        }
        let tx = conn.transaction()?;
        tx.execute(
            "UPDATE quarantined_subnets SET active = 0 WHERE active = 1;",
            [],
        )?;
        for cidr in active_cidrs {
            tx.execute(
                "INSERT INTO quarantine_audit_log (cidr, event_type, event_ts, details) VALUES (?1, 'unbanned_all', ?2, ?3);",
                params![cidr, now_ms, details],
            )?;
        }
        tx.commit()?;
        Ok(count)
    }

    pub fn get_active_bans(
        &self,
        now_ms: u64,
    ) -> Result<Vec<QuarantineRecord>, QuarantineStoreError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT cidr, ip_version, trigger_ip, infraction_type, infraction_count,
                    quarantined_at, expires_at, user_agent, active
             FROM quarantined_subnets WHERE active = 1 AND expires_at > ?1 ORDER BY quarantined_at DESC;",
        )?;
        let records = stmt
            .query_map(params![now_ms], map_quarantine_row)?
            .filter_map(|r| r.ok())
            .collect();
        Ok(records)
    }

    pub fn get_all_records(
        &self,
        limit: usize,
    ) -> Result<Vec<QuarantineRecord>, QuarantineStoreError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT cidr, ip_version, trigger_ip, infraction_type, infraction_count,
                    quarantined_at, expires_at, user_agent, active
             FROM quarantined_subnets ORDER BY quarantined_at DESC LIMIT ?1;",
        )?;
        let records = stmt
            .query_map(params![limit as i64], map_quarantine_row)?
            .filter_map(|r| r.ok())
            .collect();
        Ok(records)
    }

    pub fn get_audit_log(
        &self,
        limit: usize,
    ) -> Result<Vec<QuarantineAuditEvent>, QuarantineStoreError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, cidr, event_type, event_ts, details FROM quarantine_audit_log ORDER BY id DESC LIMIT ?1;",
        )?;
        let events = stmt
            .query_map(params![limit as i64], |r| {
                Ok(QuarantineAuditEvent {
                    id: r.get(0)?,
                    cidr: r.get(1)?,
                    event_type: r.get(2)?,
                    event_ts: r.get(3)?,
                    details: r.get(4)?,
                })
            })?
            .filter_map(|r| r.ok())
            .collect();
        Ok(events)
    }
}

fn map_quarantine_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<QuarantineRecord> {
    Ok(QuarantineRecord {
        cidr: row.get(0)?,
        ip_version: row.get(1)?,
        trigger_ip: row.get(2)?,
        infraction_type: row.get(3)?,
        infraction_count: row.get(4)?,
        quarantined_at: row.get(5)?,
        expires_at: row.get(6)?,
        user_agent: row.get(7)?,
        active: row.get::<_, i32>(8)? == 1,
    })
}
