//! # Sovereign Domain & Upstream Router
//! Fast O(1) lookup mapping HTTP `Host` headers and TLS SNI names to backend upstreams.

use crate::config::RouteConfig;
use std::collections::HashMap;
use std::net::SocketAddr;
#[cfg(feature = "hedged-racing")]
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct UpstreamTarget {
    pub addr: SocketAddr,
    pub addrs: Vec<SocketAddr>,
    pub websocket_allowed: bool,
    pub primary_host: String,
    pub hedged_racing: bool,
    pub tls_passthrough: bool,
    #[cfg(feature = "hedged-racing")]
    pub racer: Option<Arc<hippodrome::HippodromeHttpRacer>>,
}

#[derive(Debug, Clone, Default)]
pub struct UpstreamRouter {
    routes: HashMap<String, UpstreamTarget>,
    default_target: Option<UpstreamTarget>,
}

impl UpstreamRouter {
    /// Construct a router from configured routes
    pub fn new(routes: &[RouteConfig]) -> Self {
        let mut map = HashMap::new();
        let mut default_target = None;

        for route in routes {
            let primary_host = route.domains.first().cloned().unwrap_or_default();
            let addrs = route
                .resolved_upstreams()
                .unwrap_or_else(|_| vec![route.primary_upstream()]);
            let primary_addr = addrs
                .first()
                .copied()
                .unwrap_or_else(|| route.primary_upstream());
            let hedged_racing = route.hedged_racing.unwrap_or(addrs.len() > 1);

            #[cfg(feature = "hedged-racing")]
            let racer = if hedged_racing && addrs.len() > 1 {
                let race_config = hippodrome::RaceConfig {
                    hedged_delay: std::time::Duration::from_millis(5),
                    hard_timeout: std::time::Duration::from_millis(1500),
                    adaptive: true,
                    ewma_multiplier: 1.25,
                    min_hedged_delay: std::time::Duration::from_millis(2),
                    max_hedged_delay: std::time::Duration::from_millis(50),
                };
                let tournament = hippodrome::HippodromeTournament::new(race_config);
                for (idx, addr) in addrs.iter().enumerate() {
                    tournament.register(hippodrome::Steed::new(
                        format!("{}-{}", primary_host, idx),
                        addr.to_string(),
                    ));
                }
                Some(Arc::new(hippodrome::HippodromeHttpRacer::new(tournament)))
            } else {
                None
            };

            let target = UpstreamTarget {
                addr: primary_addr,
                addrs,
                websocket_allowed: route.websocket,
                primary_host,
                hedged_racing,
                tls_passthrough: route.is_tls_passthrough(),
                #[cfg(feature = "hedged-racing")]
                racer,
            };

            if default_target.is_none() && !target.tls_passthrough {
                default_target = Some(target.clone());
            }

            for host in &route.domains {
                let clean = host.trim().to_ascii_lowercase();
                map.insert(clean, target.clone());
            }
        }

        if default_target.is_none() {
            default_target = map.values().next().cloned();
        }

        Self {
            routes: map,
            default_target,
        }
    }

    /// Resolve an incoming Host header (e.g. "example.com:443" -> "example.com").
    /// Uses a zero-allocation fast path when the hostname is already ASCII lowercase.
    #[inline]
    pub fn resolve(&self, raw_host: &str) -> Option<&UpstreamTarget> {
        let trimmed = raw_host.trim();
        let host_only = match trimmed.find(':') {
            Some(idx) => &trimmed[..idx],
            None => trimmed,
        };
        if !host_only.bytes().any(|b| b.is_ascii_uppercase()) {
            return self.routes.get(host_only).or(self.default_target.as_ref());
        }
        let clean = host_only.to_ascii_lowercase();
        self.routes.get(&clean).or(self.default_target.as_ref())
    }

    /// Resolve an exact TLS SNI hostname without falling back to the default route.
    /// Operates in $O(1)$ with zero heap allocation when `sni_host` is ASCII lowercase.
    #[inline]
    pub fn resolve_sni_exact(&self, sni_host: &str) -> Option<&UpstreamTarget> {
        let trimmed = sni_host.trim();
        if !trimmed.bytes().any(|b| b.is_ascii_uppercase()) {
            return self.routes.get(trimmed);
        }
        let clean = trimmed.to_ascii_lowercase();
        self.routes.get(&clean)
    }

    /// Clean hostname by converting to lowercase and stripping port if present
    pub fn clean_host(raw: &str) -> String {
        let trimmed = raw.trim();
        let host_only = if let Some(idx) = trimmed.find(':') {
            &trimmed[..idx]
        } else {
            trimmed
        };
        host_only.to_ascii_lowercase()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_router_resolution() {
        let routes = vec![
            RouteConfig {
                domains: vec!["example.com".into(), "www.example.com".into()],
                cert: PathBuf::new(),
                key: PathBuf::new(),
                upstream: Some("127.0.0.1:8081".parse().unwrap()),
                upstreams: None,
                websocket: true,
                hedged_racing: None,
            },
            RouteConfig {
                domains: vec!["api.example.com".into()],
                cert: PathBuf::new(),
                key: PathBuf::new(),
                upstream: Some("127.0.0.1:8082".parse().unwrap()),
                upstreams: None,
                websocket: false,
                hedged_racing: None,
            },
        ];

        let router = UpstreamRouter::new(&routes);

        let target = router.resolve("api.example.com:443").unwrap();
        assert_eq!(target.addr.port(), 8082);
        assert!(!target.websocket_allowed);

        let target2 = router.resolve("www.example.com").unwrap();
        assert_eq!(target2.addr.port(), 8081);
        assert!(target2.websocket_allowed);

        let target3 = router.resolve("EXAMPLE.COM").unwrap();
        assert_eq!(target3.addr.port(), 8081);

        // Unknown host falls back to default route (first route)
        let target_default = router.resolve("unknown.org").unwrap();
        assert_eq!(target_default.addr.port(), 8081);
    }
}
