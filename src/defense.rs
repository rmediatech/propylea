//! # Sovereign Perimeter Defense & Honeyroute Trap Engine
//! Direct integration of `phylax` Shield Pipeline at the outer L7 reverse proxy boundary.
//! Drops hostile reconnaissance probes in sub-microsecond time and dispatches
//! asynchronous incident dossiers to threat intelligence (AbuseIPDB, Webhooks).

use crate::config::SecurityConfig;
use bytes::Bytes;
use http_body_util::Full;
use hyper::header::{CONTENT_LENGTH, CONTENT_TYPE};
use hyper::{Response, StatusCode};
use phylax::abuse_reporting::InformantConfig;
use phylax::{ShieldPipeline, ShieldRequest, ShieldVerdict};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone)]
pub struct EdgeDefense {
    pipeline: Arc<ShieldPipeline>,
    bot_guard: Arc<phylax::BotGuard>,
    quarantine_manager: Option<crate::quarantine::QuarantineManager>,
    trusted_subnets: Vec<ipnet::IpNet>,
}

impl Default for EdgeDefense {
    fn default() -> Self {
        Self::new(&SecurityConfig::default())
    }
}

impl EdgeDefense {
    pub fn new(config: &SecurityConfig) -> Self {
        let mut builder = ShieldPipeline::builder()
            .enable_pow(false)
            .enable_timing(false);

        if config.enable_defense {
            if config.abuseipdb_api_key.is_some()
                || config.webhook_url.is_some()
                || config.syslog_cef
            {
                let informant_config = InformantConfig {
                    enabled: true,
                    dry_run: false,
                    api_key: config.abuseipdb_api_key.clone(),
                    webhook_url: config.webhook_url.clone(),
                    webhook_auth: None,
                    syslog_cef: config.syslog_cef,
                    cooldown: Default::default(),
                };
                builder = builder.with_abuse_reporting(informant_config);
            } else {
                builder = builder.with_default_abuse_reporting();
            }
        }

        let mut trusted_subnets = Vec::new();
        for cidr_str in &config.trusted_cidrs {
            if let Ok(net) = cidr_str.parse::<ipnet::IpNet>() {
                trusted_subnets.push(net);
            } else if let Ok(ip) = cidr_str.parse::<IpAddr>() {
                trusted_subnets.push(ipnet::IpNet::from(ip));
            }
        }

        Self {
            pipeline: Arc::new(builder.build()),
            bot_guard: Arc::new(phylax::BotGuard::new()),
            quarantine_manager: None,
            trusted_subnets,
        }
    }

    pub fn with_pipeline(pipeline: Arc<ShieldPipeline>) -> Self {
        Self {
            pipeline,
            bot_guard: Arc::new(phylax::BotGuard::new()),
            quarantine_manager: None,
            trusted_subnets: Vec::new(),
        }
    }

    pub fn with_quarantine_manager(mut self, qm: crate::quarantine::QuarantineManager) -> Self {
        self.quarantine_manager = Some(qm);
        self
    }

    /// Returns true if client IP falls within explicitly trusted operator or mesh CIDR ranges
    #[inline]
    pub fn is_trusted(&self, ip: IpAddr) -> bool {
        for net in &self.trusted_subnets {
            if net.contains(&ip) {
                return true;
            }
        }
        false
    }

    pub fn quarantine_manager(&self) -> Option<&crate::quarantine::QuarantineManager> {
        self.quarantine_manager.as_ref()
    }

    fn notify_quarantine(
        &self,
        client_ip: IpAddr,
        reason: &str,
        user_agent: Option<&str>,
        now_ms: u64,
    ) {
        if let Some(ref qm) = self.quarantine_manager {
            let ip_str = client_ip.to_string();
            if let Some(cidr) = phylax::AutonomousQuarantine::derive_quarantine_cidr(&ip_str) {
                let is_v4 = client_ip.is_ipv4();
                qm.queue_record(crate::quarantine::QuarantineRecord {
                    cidr,
                    ip_version: if is_v4 { 4 } else { 6 },
                    trigger_ip: ip_str,
                    infraction_type: reason.to_string(),
                    infraction_count: 1,
                    quarantined_at: now_ms,
                    expires_at: now_ms + 24 * 60 * 60 * 1000,
                    user_agent: user_agent.map(|s| s.to_string()),
                    active: true,
                });
            }
        }
    }

    pub fn bot_guard(&self) -> &phylax::BotGuard {
        &self.bot_guard
    }

    pub fn pipeline(&self) -> &ShieldPipeline {
        &self.pipeline
    }

    /// Record an anomalous unmapped URI probe into the underlying Threat Harvester (Layer 13).
    pub fn record_anomalous_uri(
        &self,
        path: &str,
        client_ip: IpAddr,
    ) -> Option<phylax::threat_harvester::PromotionVerdict> {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        self.pipeline.record_anomalous_uri(path, client_ip, now_ms)
    }

    /// Evaluates incoming request. If hostile, returns stealth 404 response
    /// and asynchronously dispatches an incident report.
    pub fn evaluate_request(
        &self,
        client_ip: IpAddr,
        method: &str,
        path: &str,
        user_agent: Option<&str>,
    ) -> Option<Response<Full<Bytes>>> {
        self.evaluate_request_full(client_ip, method, path, None, user_agent, None)
    }

    /// Evaluates incoming request along with optional TLS ClientHello profile.
    pub fn evaluate_request_with_tls(
        &self,
        client_ip: IpAddr,
        method: &str,
        path: &str,
        user_agent: Option<&str>,
        tls_profile: Option<&crate::tls_fingerprint::ClientTlsProfile>,
    ) -> Option<Response<Full<Bytes>>> {
        self.evaluate_request_full(client_ip, method, path, None, user_agent, tls_profile)
    }

    /// Evaluates incoming request with full query inspection, zero-alloc payload defense, and TLS profiling.
    pub fn evaluate_request_full(
        &self,
        client_ip: IpAddr,
        method: &str,
        path: &str,
        query: Option<&str>,
        user_agent: Option<&str>,
        tls_profile: Option<&crate::tls_fingerprint::ClientTlsProfile>,
    ) -> Option<Response<Full<Bytes>>> {
        // 0. Operator & Sovereign Mesh Allowlist: Bypass all checks for trusted IP ranges
        if self.is_trusted(client_ip) {
            return None;
        }

        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let ip_str = client_ip.to_string();
        let query_str = query.unwrap_or("");

        // 0. PayloadGuard: Zero-allocation inspection of path and query for SQLi, traversal, RCE, XSS
        if let Err(threat) = phylax::PayloadGuard::inspect(path, query_str) {
            self.pipeline.quarantine().record_and_check(&ip_str, now_ms);
            self.notify_quarantine(client_ip, threat.category_name(), user_agent, now_ms);
            if let Some(ua) = user_agent {
                self.bot_guard
                    .harvest_canary_probe(Some(ua), &threat.description(), now_ms);
            }
            tracing::warn!(
                ip = %client_ip, path = %path, query = %query_str, threat = %threat.description(),
                "🚨 [PROPYLEA-PAYLOAD] Hostile exploit payload intercepted and neutralized at edge perimeter."
            );
            return Some(forbidden_payload_response(&threat.description()));
        }

        let norm_path = phylax::decoy_uri::DecoyUriSentinel::normalize_path(path);

        if let Some(profile) = tls_profile {
            if let crate::tls_fingerprint::UserAgentCoherenceVerdict::Spoofed { reason } =
                profile.verify_user_agent_coherence(user_agent)
            {
                self.pipeline.quarantine().record_and_check(&ip_str, now_ms);
                self.notify_quarantine(client_ip, "tls_clienthello_spoof", user_agent, now_ms);
                if let Some(ua) = user_agent {
                    self.bot_guard
                        .harvest_canary_probe(Some(ua), reason, now_ms);
                }
                tracing::warn!(
                    ip = %client_ip, path = %path, ua = ?user_agent, reason = %reason,
                    "🚨 [PROPYLEA-TLS-SPOOF] Detected User-Agent spoofing via TLS ClientHello mismatch!"
                );
                return Some(stealth_404_response());
            }
        }

        let empty_fields: [(String, String); 0] = [];
        let shield_req = ShieldRequest {
            client_ip: &ip_str,
            submitted_fields: &empty_fields,
            target_uri: Some(&norm_path),
            http_method: Some(method),
            user_agent,
            now_ms,
            ..Default::default()
        };

        let is_canary = norm_path == "/_sovereign/canary_trap"
            || norm_path.starts_with("/_sovereign/canary_trap/")
            || norm_path == "/decoy/canary"
            || norm_path.starts_with("/decoy/canary/");

        if is_canary {
            let harvested = self.bot_guard.harvest_canary_probe(
                user_agent,
                "Tripped invisible canary trap honeylink",
                now_ms,
            );
            self.pipeline.quarantine().record_and_check(&ip_str, now_ms);
            self.notify_quarantine(client_ip, "canary_trap_honeylink", user_agent, now_ms);
            tracing::warn!(
                ip = %client_ip, path = %path, norm_path = %norm_path, ua = ?user_agent, harvested = ?harvested,
                "🚨 [PROPYLEA-CANARY] Invisible Canary Trap tripped!"
            );
            return Some(stealth_404_response());
        }

        if let ShieldVerdict::Deny(reason) = self.pipeline.evaluate_perimeter(&shield_req) {
            if let Some(ua) = user_agent {
                self.bot_guard
                    .harvest_canary_probe(Some(ua), reason.public_message(), now_ms);
            }
            tracing::warn!(
                ip = %client_ip, path = %path, norm_path = %norm_path, method = %method, reason = %reason.public_message(),
                "🚨 [PROPYLEA-EDGE] Hostile reconnaissance scan trapped at ingress."
            );
            return Some(stealth_404_response());
        }

        let bot_verdict = if client_ip.is_loopback() && user_agent.is_none() {
            phylax::bot_guard::BotVerdict::Allowed {
                category: phylax::bot_guard::BotCategory::Unknown,
            }
        } else {
            self.bot_guard.evaluate_perimeter(user_agent, &norm_path)
        };

        if let phylax::bot_guard::BotVerdict::Blocked {
            category,
            matched_token,
        } = bot_verdict
        {
            if category == phylax::bot_guard::BotCategory::AutomationTool {
                tracing::warn!(
                    ip = %client_ip, path = %path, norm_path = %norm_path, method = %method,
                    category = %category.name(), token = %matched_token, ua = ?user_agent,
                    "🚨 [PROPYLEA-STEALTH] Hostile automation / penetration tool deflected with stealth 404."
                );
                return Some(stealth_404_response());
            } else {
                tracing::warn!(
                    ip = %client_ip, path = %path, norm_path = %norm_path, method = %method,
                    category = %category.name(), token = %matched_token, ua = ?user_agent,
                    "⛔ [PROPYLEA-EDGE] Automated commercial scraper intercepted at perimeter boundary."
                );
                return Some(forbidden_bot_response(category.name(), &matched_token));
            }
        }

        None
    }
}

fn stealth_404_response() -> Response<Full<Bytes>> {
    let mut res = Response::new(Full::new(Bytes::from_static(b"404 Not Found\n")));
    *res.status_mut() = StatusCode::NOT_FOUND;
    res.headers_mut().insert(
        CONTENT_TYPE,
        hyper::header::HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    res.headers_mut().insert(
        CONTENT_LENGTH,
        hyper::header::HeaderValue::from_static("14"),
    );
    res
}

#[rustfmt::skip]
fn forbidden_bot_response(category_name: &str, matched_token: &str) -> Response<Full<Bytes>> {
    let body_bytes = Bytes::from(format!("Access Denied: {} ({}) is prohibited on Sovereign infrastructure (RFC 9309).\n", category_name, matched_token));
    let body_len_str = body_bytes.len().to_string();
    let mut res = Response::new(Full::new(body_bytes));
    *res.status_mut() = StatusCode::FORBIDDEN;
    res.headers_mut().insert(CONTENT_TYPE, hyper::header::HeaderValue::from_static("text/plain; charset=utf-8"));
    res.headers_mut().insert(CONTENT_LENGTH, hyper::header::HeaderValue::from_str(&body_len_str).unwrap());
    res
}

#[rustfmt::skip]
fn forbidden_payload_response(description: &str) -> Response<Full<Bytes>> {
    let body_bytes = Bytes::from(format!("Access Denied: Adversarial Exploit Payload ({}) is prohibited on Sovereign infrastructure.\n", description));
    let body_len_str = body_bytes.len().to_string();
    let mut res = Response::new(Full::new(body_bytes));
    *res.status_mut() = StatusCode::FORBIDDEN;
    res.headers_mut().insert(CONTENT_TYPE, hyper::header::HeaderValue::from_static("text/plain; charset=utf-8"));
    res.headers_mut().insert(CONTENT_LENGTH, hyper::header::HeaderValue::from_str(&body_len_str).unwrap());
    res
}

#[cfg(test)]
#[rustfmt::skip]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn test_edge_defense_suite() {
        let defense = EdgeDefense::default();
        let ip_local = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        assert!(defense.evaluate_request(ip_local, "GET", "/", None).is_none());
        assert!(defense.evaluate_request(ip_local, "POST", "/api/v1/data", None).is_none());

        let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
        // Headerless request from external IP is blocked
        let res_no_ua = defense.evaluate_request(ip, "GET", "/products", None).unwrap();
        assert_eq!(res_no_ua.status(), StatusCode::NOT_FOUND);

        let res = defense.evaluate_request(ip, "GET", "/.env", None).unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
        assert_eq!(res.headers().get("content-length").unwrap(), "14");

        let res_bot = defense.evaluate_request(ip, "GET", "/sitemap.xml", Some("Claude-SearchBot/1.0")).unwrap();
        assert_eq!(res_bot.status(), StatusCode::FORBIDDEN);
        assert!(defense.evaluate_request(ip, "GET", "/robots.txt", Some("Claude-SearchBot/1.0")).is_none());
        assert!(defense.evaluate_request(ip, "GET", "/tools", Some("Googlebot/2.1")).is_none());
        assert!(defense.evaluate_request(ip, "GET", "/install/metaforge", Some("curl/8.5.0")).is_none());

        // Adversarial payload defense test
        let res_sqli = defense.evaluate_request_full(ip, "GET", "/api/items", Some("id=1' UNION SELECT 1,2,3--"), None, None).unwrap();
        assert_eq!(res_sqli.status(), StatusCode::FORBIDDEN);

        let res_trav = defense.evaluate_request_full(ip, "GET", "/../../etc/passwd", None, None, None).unwrap();
        assert_eq!(res_trav.status(), StatusCode::FORBIDDEN);

        // SSRF probe
        let res_ssrf = defense.evaluate_request_full(ip, "GET", "/fetch", Some("target=http://169.254.169.254/latest/meta-data"), None, None).unwrap();
        assert_eq!(res_ssrf.status(), StatusCode::FORBIDDEN);

        // SSTI probe
        let res_ssti = defense.evaluate_request_full(ip, "GET", "/render", Some("name={{7*7}}"), None, None).unwrap();
        assert_eq!(res_ssti.status(), StatusCode::FORBIDDEN);

        // NoSQL probe
        let res_nosql = defense.evaluate_request_full(ip, "GET", "/users", Some("filter={\"$gt\":\"\"}"), None, None).unwrap();
        assert_eq!(res_nosql.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_trusted_cidrs_allowlist_bypass() {
        let config = SecurityConfig {
            trusted_cidrs: vec!["198.51.100.0/24".to_string(), "203.0.113.42".to_string()],
            ..Default::default()
        };
        let defense = EdgeDefense::new(&config);

        let trusted_ip: IpAddr = "198.51.100.77".parse().unwrap();
        // Headerless requests or sensitive endpoints are cleanly permitted for trusted IPs
        assert!(defense.evaluate_request(trusted_ip, "GET", "/products", None).is_none());
        assert!(defense.evaluate_request(trusted_ip, "GET", "/.env", None).is_none());

        let untrusted_ip: IpAddr = "192.0.2.10".parse().unwrap();
        assert!(defense.evaluate_request(untrusted_ip, "GET", "/products", None).is_some());
    }
}
