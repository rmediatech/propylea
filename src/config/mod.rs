//! # Configuration Engine for Propylea
//! Strictly validated TOML configuration engine.

pub mod route;

pub use route::RouteConfig;

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("I/O error reading config file '{0}': {1}")]
    Io(PathBuf, #[source] std::io::Error),
    #[error("TOML syntax/deserialization error: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("Validation error: {0}")]
    Validation(String),
}

/// Root configuration container
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PropyleaConfig {
    pub server: ServerConfig,
    #[serde(default)]
    pub security: SecurityConfig,
    #[serde(default)]
    pub maintenance: MaintenanceSettings,
    #[serde(default)]
    pub routes: Vec<RouteConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Port 80 HTTP redirect listener address
    #[serde(default = "default_http_bind")]
    pub http_bind: SocketAddr,
    /// Port 443 HTTPS reverse proxy listener address
    #[serde(default = "default_https_bind")]
    pub https_bind: SocketAddr,
    /// ACME challenge webroot directory (defaults to /var/www/letsencrypt)
    #[serde(default = "default_acme_webroot")]
    pub acme_webroot: Option<PathBuf>,
    /// Optional worker thread limit (defaults to logical CPU count)
    #[serde(default)]
    pub worker_threads: Option<usize>,
}

fn default_http_bind() -> SocketAddr {
    "0.0.0.0:80".parse().unwrap()
}

fn default_https_bind() -> SocketAddr {
    "0.0.0.0:443".parse().unwrap()
}

fn default_acme_webroot() -> Option<PathBuf> {
    Some(PathBuf::from("/var/www/letsencrypt"))
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            http_bind: default_http_bind(),
            https_bind: default_https_bind(),
            acme_webroot: default_acme_webroot(),
            worker_threads: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Enable active Phylax edge perimeter defense (honeypots & decoy URIs)
    #[serde(default = "default_true")]
    pub enable_defense: bool,
    /// Optional AbuseIPDB API key for automatic threat reporting
    #[serde(default)]
    pub abuseipdb_api_key: Option<String>,
    /// Optional generic webhook URL (Slack, Discord, SIEM) for security alerts
    #[serde(default)]
    pub webhook_url: Option<String>,
    /// Optional RFC 5424 Syslog / CEF (Common Event Format) logging
    #[serde(default)]
    pub syslog_cef: bool,
    /// Obfuscated Server header (defaults to Propylea-Edge-Gateway/1.0)
    #[serde(default = "default_server_banner")]
    pub server_banner: String,
    /// Enable HTTP Strict Transport Security (HSTS)
    #[serde(default = "default_true")]
    pub hsts: bool,
    /// X-Frame-Options (DENY, SAMEORIGIN)
    #[serde(default = "default_frame_options")]
    pub frame_options: String,
    /// Persistent SQLite database path for autonomous quarantine
    #[serde(default)]
    pub quarantine_db: Option<PathBuf>,
    /// Control socket path for Unix Domain Socket IPC (live unquarantine / status)
    #[serde(default)]
    pub control_socket: Option<PathBuf>,
    /// Enable persistence of quarantined subnets across restarts
    #[serde(default = "default_true")]
    pub persist_quarantine: bool,
}

pub(crate) fn default_true() -> bool {
    true
}

fn default_server_banner() -> String {
    "Propylea-Edge-Gateway/1.0".to_string()
}

fn default_frame_options() -> String {
    "DENY".to_string()
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            enable_defense: true,
            abuseipdb_api_key: None,
            webhook_url: None,
            syslog_cef: false,
            server_banner: default_server_banner(),
            hsts: true,
            frame_options: default_frame_options(),
            quarantine_db: None,
            control_socket: None,
            persist_quarantine: true,
        }
    }
}

impl SecurityConfig {
    pub fn resolved_quarantine_db(&self) -> PathBuf {
        if let Some(ref p) = self.quarantine_db {
            p.clone()
        } else if std::fs::create_dir_all("/var/lib/propylea").is_ok() {
            PathBuf::from("/var/lib/propylea/quarantine.db")
        } else if let Ok(home) = std::env::var("HOME") {
            PathBuf::from(home).join(".local/share/propylea/quarantine.db")
        } else {
            PathBuf::from("./data/quarantine.db")
        }
    }

    pub fn resolved_control_socket(&self) -> PathBuf {
        if let Some(ref p) = self.control_socket {
            p.clone()
        } else if std::fs::create_dir_all("/run/propylea").is_ok() {
            PathBuf::from("/run/propylea/control.sock")
        } else {
            PathBuf::from("/tmp/propylea_control.sock")
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaintenanceSettings {
    /// Seconds between autonomous memory and resource hygiene passes
    #[serde(default = "default_hygiene_interval")]
    pub hygiene_interval_secs: u64,
    /// Maximum retained records in the in-memory telemetry ring buffer
    #[serde(default = "default_max_records")]
    pub max_telemetry_records: usize,
    /// Aggressively release unmapped pages back to the kernel
    #[serde(default = "default_true")]
    pub memory_vacuum: bool,
}

fn default_hygiene_interval() -> u64 {
    300
}

fn default_max_records() -> usize {
    10_000
}

impl Default for MaintenanceSettings {
    fn default() -> Self {
        Self {
            hygiene_interval_secs: default_hygiene_interval(),
            max_telemetry_records: default_max_records(),
            memory_vacuum: true,
        }
    }
}
