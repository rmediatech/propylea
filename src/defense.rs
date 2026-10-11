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

        Self {
            pipeline: Arc::new(builder.build()),
            bot_guard: Arc::new(phylax::BotGuard::new()),
            quarantine_manager: None,
        }
    }

    pub fn with_pipeline(pipeline: Arc<ShieldPipeline>) -> Self {
        Self {
            pipeline,
            bot_guard: Arc::new(phylax::BotGuard::new()),
            quarantine_manager: None,
        }
    }

    pub fn with_quarantine_manager(mut self, qm: crate::quarantine::QuarantineManager) -> Self {
        self.quarantine_manager = Some(qm);
        self
    }

    pub fn quarantine_manager(&self) -> Option<&crate::quarantine::QuarantineManager> {
        self.quarantine_manager.as_ref()
    }

    fn notify_quarantine(&self, client_ip: IpAddr, reason: &str, user_agent: Option<&str>, now_ms: u64) {
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
    /// Autonomously correlates multi-subnet zero-day campaigns into live decoy traps.
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
        self.evaluate_request_with_tls(client_ip, method, path, user_agent, None)
    }

    /// Evaluates incoming request along with optional TLS ClientHello profile.
    /// Defeats User-Agent spoofing where clients impersonate Chrome/Safari over Python/Go/CLI stacks.
    pub fn evaluate_request_with_tls(
        &self,
        client_ip: IpAddr,
        method: &str,
        path: &str,
        user_agent: Option<&str>,
        tls_profile: Option<&crate::tls_fingerprint::ClientTlsProfile>,
    ) -> Option<Response<Full<Bytes>>> {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let norm_path = phylax::decoy_uri::DecoyUriSentinel::normalize_path(path);
        let ip_str = client_ip.to_string();

        // 0. Layer 0.1: TLS Profile vs User-Agent Coherence Verification (Anti-Spoofing)
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
                    ip = %client_ip,
                    path = %path,
                    ua = ?user_agent,
                    reason = %reason,
                    "🚨 [PROPYLEA-TLS-SPOOF] Detected User-Agent spoofing via TLS ClientHello mismatch! Deflected with stealth 404 Not Found."
                );

                let body = Bytes::from_static(b"404 Not Found\n");
                let mut res = Response::new(Full::new(body));
                *res.status_mut() = StatusCode::NOT_FOUND;
                res.headers_mut().insert(
                    CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("text/plain; charset=utf-8"),
                );
                res.headers_mut().insert(
                    CONTENT_LENGTH,
                    hyper::header::HeaderValue::from_static("14"),
                );
                return Some(res);
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

        // 0. Layer 0.25: Canary Trap Honeylink Interception & Dynamic Auto-Harvesting
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
                ip = %client_ip,
                path = %path,
                norm_path = %norm_path,
                ua = ?user_agent,
                harvested = ?harvested,
                "🚨 [PROPYLEA-CANARY] Invisible Canary Trap tripped! Signature autonomously harvested into dynamic threat registry."
            );

            let body = Bytes::from_static(b"404 Not Found\n");
            let mut res = Response::new(Full::new(body));
            *res.status_mut() = StatusCode::NOT_FOUND;
            res.headers_mut().insert(
                CONTENT_TYPE,
                hyper::header::HeaderValue::from_static("text/plain; charset=utf-8"),
            );
            res.headers_mut().insert(
                CONTENT_LENGTH,
                hyper::header::HeaderValue::from_static("14"),
            );
            return Some(res);
        }

        // 1. Layer 0 & 0.5: Autonomous Quarantine, Decoy URI Honeyroute, Subnet Guard
        match self.pipeline.evaluate_perimeter(&shield_req) {
            ShieldVerdict::Deny(reason) => {
                // Dynamically harvest malicious User-Agent from honeyroute probes
                if let Some(ua) = user_agent {
                    self.bot_guard
                        .harvest_canary_probe(Some(ua), reason.public_message(), now_ms);
                }

                tracing::warn!(
                    ip = %client_ip,
                    path = %path,
                    norm_path = %norm_path,
                    method = %method,
                    reason = %reason.public_message(),
                    "🚨 [PROPYLEA-EDGE] Hostile reconnaissance scan trapped at ingress (stealth 404 returned + incident reported)."
                );

                let body = Bytes::from_static(b"404 Not Found\n");
                let mut res = Response::new(Full::new(body));
                *res.status_mut() = StatusCode::NOT_FOUND;
                res.headers_mut().insert(
                    CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("text/plain; charset=utf-8"),
                );
                res.headers_mut().insert(
                    CONTENT_LENGTH,
                    hyper::header::HeaderValue::from_static("14"),
                );

                return Some(res);
            }
            ShieldVerdict::Allow { .. } => {}
        }

        // 2. Sub-microsecond Bot Guard Interception (RFC 9309) on surviving routes
        let bot_verdict = self.bot_guard.evaluate_perimeter(user_agent, &norm_path);
        if let phylax::bot_guard::BotVerdict::Blocked {
            category,
            matched_token,
        } = bot_verdict
        {
            if category == phylax::bot_guard::BotCategory::AutomationTool {
                // Hostile tool, penetration scanner, or trapped honeylink bot -> Stealth 404
                tracing::warn!(
                    ip = %client_ip,
                    path = %path,
                    norm_path = %norm_path,
                    method = %method,
                    category = %category.name(),
                    token = %matched_token,
                    ua = ?user_agent,
                    "🚨 [PROPYLEA-STEALTH] Hostile automation / penetration tool deflected with stealth 404 Not Found."
                );

                let body = Bytes::from_static(b"404 Not Found\n");
                let mut res = Response::new(Full::new(body));
                *res.status_mut() = StatusCode::NOT_FOUND;
                res.headers_mut().insert(
                    CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("text/plain; charset=utf-8"),
                );
                res.headers_mut().insert(
                    CONTENT_LENGTH,
                    hyper::header::HeaderValue::from_static("14"),
                );
                return Some(res);
            } else {
                // Commercial AI Scraper / SEO Profiler -> Explicit 403 Forbidden with RFC 9309 notice
                tracing::warn!(
                    ip = %client_ip,
                    path = %path,
                    norm_path = %norm_path,
                    method = %method,
                    category = %category.name(),
                    token = %matched_token,
                    ua = ?user_agent,
                    "⛔ [PROPYLEA-EDGE] Automated commercial scraper intercepted at perimeter boundary (403 Forbidden returned)."
                );

                let body_msg = format!(
                    "Access Denied: {} ({}) is prohibited on Sovereign infrastructure (RFC 9309).\n",
                    category.name(),
                    matched_token
                );
                let body_bytes = Bytes::from(body_msg);
                let body_len_str = body_bytes.len().to_string();

                let mut res = Response::new(Full::new(body_bytes));
                *res.status_mut() = StatusCode::FORBIDDEN;
                res.headers_mut().insert(
                    CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("text/plain; charset=utf-8"),
                );
                res.headers_mut().insert(
                    CONTENT_LENGTH,
                    hyper::header::HeaderValue::from_str(&body_len_str).unwrap(),
                );

                return Some(res);
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn test_benign_request_passes() {
        let defense = EdgeDefense::default();
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        assert!(defense.evaluate_request(ip, "GET", "/", None).is_none());
        assert!(defense
            .evaluate_request(ip, "POST", "/api/v1/data", None)
            .is_none());
        assert!(defense
            .evaluate_request(ip, "GET", "/assets/main.css", None)
            .is_none());
    }

    #[tokio::test]
    async fn test_hostile_probe_trapped() {
        let defense = EdgeDefense::default();
        let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));

        let res = defense.evaluate_request(ip, "GET", "/.env", None);
        assert!(res.is_some());
        let res = res.unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            res.headers().get("content-type").unwrap(),
            "text/plain; charset=utf-8"
        );
        assert_eq!(res.headers().get("content-length").unwrap(), "14");

        let res2 = defense.evaluate_request(ip, "GET", "/wp-login.php", Some("Mozilla/5.0"));
        assert!(res2.is_some());
        assert_eq!(res2.unwrap().status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_bot_interception_returns_403() {
        let defense = EdgeDefense::default();
        let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));

        // Claude-SearchBot blocked on storefront
        let res = defense.evaluate_request(ip, "GET", "/sitemap.xml", Some("Claude-SearchBot/1.0"));
        assert!(res.is_some());
        let res = res.unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            res.headers().get("content-type").unwrap(),
            "text/plain; charset=utf-8"
        );

        // BuiltWith blocked
        let res2 = defense.evaluate_request(ip, "GET", "/llms.txt", Some("BuiltWith/1.4"));
        assert!(res2.is_some());
        assert_eq!(res2.unwrap().status(), StatusCode::FORBIDDEN);

        // CensysInspect blocked
        let res3 = defense.evaluate_request(ip, "GET", "/security.txt", Some("CensysInspect/1.1"));
        assert!(res3.is_some());
        assert_eq!(res3.unwrap().status(), StatusCode::FORBIDDEN);

        // Robots.txt is ALWAYS allowed for any bot
        let res_robots =
            defense.evaluate_request(ip, "GET", "/robots.txt", Some("Claude-SearchBot/1.0"));
        assert!(res_robots.is_none());

        // Googlebot is allowed on public storefront
        let res_google = defense.evaluate_request(ip, "GET", "/tools", Some("Googlebot/2.1"));
        assert!(res_google.is_none());

        // Curl allowed on installer path
        let res_curl =
            defense.evaluate_request(ip, "GET", "/install/metaforge", Some("curl/8.5.0"));
        assert!(res_curl.is_none());
    }
}
