//! # Route Configuration & Validation (`config/route.rs`)
//!
//! Defines SNI/Host route mappings, upstream pools, and TOML configuration validation.

use super::{default_true, ConfigError, PropyleaConfig};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

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
