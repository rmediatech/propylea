//! # Configuration Engine for Propylea
//! Strictly validated TOML configuration engine.

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
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

fn default_true() -> bool {
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
    300 // 5 minutes
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteConfig {
    /// Domain or hostnames matching SNI and Host header
    pub domains: Vec<String>,
    /// Primary upstream address (e.g. 127.0.0.1:3000)
    #[serde(default)]
    pub upstream: Option<SocketAddr>,
    /// Upstream addresses pool for speculative hedged tournament racing
    #[serde(default)]
    pub upstreams: Option<Vec<SocketAddr>>,
    /// Path to TLS fullchain certificate (PEM)
    pub cert: PathBuf,
    /// Path to TLS private key (PEM)
    pub key: PathBuf,
    /// Enable bi-directional WebSocket upgrade forwarding
    #[serde(default = "default_true")]
    pub websocket: bool,
    /// Enable speculative hedged racing across upstream pool (default: true if multiple upstreams)
    #[serde(default)]
    pub hedged_racing: Option<bool>,
}

impl RouteConfig {
    /// Resolve all configured upstream addresses into a non-empty list.
    pub fn resolved_upstreams(&self) -> Result<Vec<SocketAddr>, ConfigError> {
        let mut list = Vec::new();
        if let Some(ref u) = self.upstream {
            list.push(*u);
        }
        if let Some(ref ups) = self.upstreams {
            for u in ups {
                if !list.contains(u) {
                    list.push(*u);
                }
            }
        }
        if list.is_empty() {
            return Err(ConfigError::Validation(
                "Route must specify either 'upstream' or 'upstreams'".into(),
            ));
        }
        Ok(list)
    }

    /// Primary fallback upstream address.
    pub fn primary_upstream(&self) -> SocketAddr {
        self.resolved_upstreams()
            .ok()
            .and_then(|list| list.first().copied())
            .unwrap_or_else(|| "127.0.0.1:8080".parse().unwrap())
    }

    /// Construct a single upstream route convenience constructor.
    pub fn single(
        domains: Vec<String>,
        upstream: SocketAddr,
        cert: PathBuf,
        key: PathBuf,
        websocket: bool,
    ) -> Self {
        Self {
            domains,
            upstream: Some(upstream),
            upstreams: None,
            cert,
            key,
            websocket,
            hedged_racing: None,
        }
    }
}

impl PropyleaConfig {
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let p = path.as_ref();
        let content =
            std::fs::read_to_string(p).map_err(|e| ConfigError::Io(p.to_path_buf(), e))?;
        Self::from_str(&content)
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(toml_str: &str) -> Result<Self, ConfigError> {
        <Self as std::str::FromStr>::from_str(toml_str)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.routes.is_empty() {
            return Err(ConfigError::Validation(
                "At least one [[routes]] entry must be defined".into(),
            ));
        }

        for (i, route) in self.routes.iter().enumerate() {
            if route.domains.is_empty() {
                return Err(ConfigError::Validation(format!(
                    "Route[{}] has no domains configured",
                    i
                )));
            }
            route.resolved_upstreams().map_err(|e| {
                ConfigError::Validation(format!(
                    "Route[{}] invalid upstream configuration: {}",
                    i, e
                ))
            })?;
        }

        Ok(())
    }
}

impl std::str::FromStr for PropyleaConfig {
    type Err = ConfigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let config: PropyleaConfig = toml::from_str(s)?;
        config.validate()?;
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_config_parsing() {
        let toml_data = r#"
        [server]
        http_bind = "127.0.0.1:8080"
        https_bind = "127.0.0.1:8443"

        [security]
        enable_defense = true
        server_banner = "Test-Proxy"

        [[routes]]
        domains = ["example.com", "www.example.com"]
        upstream = "127.0.0.1:3000"
        cert = "/tmp/cert.pem"
        key = "/tmp/key.pem"
        websocket = true
        "#;

        let config = PropyleaConfig::from_str(toml_data).unwrap();
        assert_eq!(config.server.http_bind.port(), 8080);
        assert_eq!(config.server.https_bind.port(), 8443);
        assert_eq!(config.routes.len(), 1);
        assert_eq!(
            config.routes[0].domains,
            vec!["example.com", "www.example.com"]
        );
        assert_eq!(config.routes[0].primary_upstream().port(), 3000);
        assert!(config.routes[0].websocket);
    }

    #[test]
    fn test_empty_routes_fails_validation() {
        let toml_data = r#"
        routes = []

        [server]
        http_bind = "127.0.0.1:80"
        https_bind = "127.0.0.1:443"
        "#;

        let err = PropyleaConfig::from_str(toml_data).unwrap_err();
        assert!(matches!(err, ConfigError::Validation(_)));
    }
}
