//! # Sovereign Reverse Proxy & Streaming Engine (`proxy/mod.rs`)

mod forward;
mod websocket;

use crate::config::{PropyleaConfig, SecurityConfig};
use crate::defense::EdgeDefense;
use crate::headers::inject_response_security_headers;
use crate::maintenance::ResourceGovernor;
use crate::router::UpstreamRouter;
use crate::telemetry::{
    current_time_ms, sanitize_query_string, ExecutionTimer, TelemetryRecord, TelemetryRingBuffer,
};
use bytes::Bytes;
use forward::forward_http_request;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::header::{HOST, UPGRADE, USER_AGENT};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use thiserror::Error;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};
use websocket::handle_websocket_upgrade;

pub type BoxedBody = BoxBody<Bytes, hyper::Error>;

#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Hyper error: {0}")]
    Hyper(#[from] hyper::Error),
}

struct ConnectionGuard(ResourceGovernor);
impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.0.deregister_connection();
    }
}

#[derive(Clone)]
pub struct ProxyState {
    pub router: Arc<UpstreamRouter>,
    pub security: Arc<SecurityConfig>,
    pub defense: Arc<EdgeDefense>,
    pub governor: ResourceGovernor,
    pub telemetry: TelemetryRingBuffer,
    pub acme_webroot: Option<Arc<std::path::PathBuf>>,
    pub framing_guard: Arc<crate::framing_guard::FramingGuard>,
}

pub async fn run_https_proxy_server(
    bind_addr: SocketAddr,
    tls_acceptor: TlsAcceptor,
    config: PropyleaConfig,
    governor: ResourceGovernor,
    telemetry: TelemetryRingBuffer,
) -> Result<(), std::io::Error> {
    let listener = TcpListener::bind(bind_addr).await?;
    info!("🚀 [PROPYLEA] Sovereign HTTPS reverse proxy active on {}", bind_addr);
    run_https_proxy_listener(listener, tls_acceptor, config, governor, telemetry).await
}

pub async fn run_https_proxy_listener(
    listener: TcpListener,
    tls_acceptor: TlsAcceptor,
    config: PropyleaConfig,
    governor: ResourceGovernor,
    telemetry: TelemetryRingBuffer,
) -> Result<(), std::io::Error> {
    let defense = build_edge_defense(&config);
    let state = ProxyState {
        router: Arc::new(UpstreamRouter::new(&config.routes)),
        security: Arc::new(config.security),
        defense,
        governor,
        telemetry,
        acme_webroot: config.server.acme_webroot.map(Arc::new),
        framing_guard: Arc::new(crate::framing_guard::FramingGuard::default()),
    };

    loop {
        let (raw_stream, remote_addr) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                warn!("Failed to accept incoming TCP stream: {}", e);
                continue;
            }
        };

        let acceptor = tls_acceptor.clone();
        let state = state.clone();
        state.governor.register_connection();
        let _guard = ConnectionGuard(state.governor.clone());

        tokio::spawn(async move {
            let _conn_guard = _guard;
            let mut peek_buf = [0u8; 1024];
            let tls_profile = match raw_stream.peek(&mut peek_buf).await {
                Ok(n) if n > 0 => crate::tls_fingerprint::ClientTlsProfile::parse_client_hello(&peek_buf[..n]),
                _ => None,
            }
            .map(Arc::new);

            let tls_stream = match acceptor.accept(raw_stream).await {
                Ok(s) => s,
                Err(e) => {
                    debug!("TLS handshake failed from {}: {}", remote_addr, e);
                    return;
                }
            };

            let io = TokioIo::new(tls_stream);
            let service = service_fn(move |req: Request<hyper::body::Incoming>| {
                let state = state.clone();
                let client_ip = remote_addr.ip();
                let profile = tls_profile.clone();
                async move { handle_proxy_request_with_tls(req, client_ip, state, profile).await }
            });

            if let Err(err) = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                .serve_connection_with_upgrades(io, service)
                .await
            {
                debug!("Connection closed with {}: {}", remote_addr, err);
            }
        });
    }
}

fn build_edge_defense(config: &PropyleaConfig) -> Arc<EdgeDefense> {
    if !config.security.persist_quarantine {
        return Arc::new(EdgeDefense::new(&config.security));
    }
    let db_path = config.security.resolved_quarantine_db();
    let sock_path = config.security.resolved_control_socket();

    match crate::quarantine::QuarantineStore::open(&db_path) {
        Ok(store) => {
            let store = Arc::new(store);
            let edge_defense = EdgeDefense::new(&config.security);
            let in_mem = Arc::new(edge_defense.pipeline().quarantine().clone());
            let (manager, rx) = crate::quarantine::QuarantineManager::new(
                in_mem.clone(),
                store.clone(),
                sock_path.clone(),
            );
            if let Err(e) = manager.rehydrate_on_boot() {
                warn!("Failed to rehydrate active quarantine records: {}", e);
            }
            let store_clone = store.clone();
            tokio::spawn(async move {
                crate::quarantine::QuarantineManager::run_persistence_worker(store_clone, rx).await;
            });
            match crate::quarantine::IpcServer::bind(&sock_path) {
                Ok(ipc_listener) => {
                    let sock_clone = sock_path.clone();
                    tokio::spawn(async move {
                        crate::quarantine::IpcServer::run_loop(ipc_listener, sock_clone, in_mem, store).await;
                    });
                }
                Err(e) => warn!("Failed to bind quarantine IPC socket at {}: {}", sock_path.display(), e),
            }
            Arc::new(edge_defense.with_quarantine_manager(manager))
        }
        Err(e) => {
            warn!("Failed to open quarantine store at {}: {}. In-memory fallback.", db_path.display(), e);
            Arc::new(EdgeDefense::new(&config.security))
        }
    }
}

pub async fn handle_proxy_request(
    req: Request<hyper::body::Incoming>,
    client_ip: IpAddr,
    state: ProxyState,
) -> Result<Response<BoxedBody>, hyper::Error> {
    handle_proxy_request_with_tls(req, client_ip, state, None).await
}

pub async fn handle_proxy_request_with_tls(
    mut req: Request<hyper::body::Incoming>,
    client_ip: IpAddr,
    state: ProxyState,
    tls_profile: Option<Arc<crate::tls_fingerprint::ClientTlsProfile>>,
) -> Result<Response<BoxedBody>, hyper::Error> {
    let timer = ExecutionTimer::start();

    if let Err(violation) = state.framing_guard.validate_headers(req.headers(), req.method()) {
        warn!(ip = %client_ip, error = %violation, "🚨 [PROPYLEA-FRAMING] HTTP Framing violation rejected");
        state.governor.record_threat();
        let (parts, body) = violation.public_response().into_parts();
        return Ok(Response::from_parts(parts, body.map_err(|e| match e {}).boxed()));
    }

    crate::framing_guard::FramingGuard::sanitize_ingress_headers(&mut req, client_ip);

    let method = req.method().to_string();
    let raw_path = req.uri().path().to_string();
    let sanitized_query = sanitize_query_string(req.uri().query().unwrap_or(""));
    let full_path = if sanitized_query.is_empty() {
        raw_path.clone()
    } else {
        format!("{}?{}", raw_path, sanitized_query)
    };
    let user_agent = req.headers().get(USER_AGENT).and_then(|v| v.to_str().ok()).map(String::from);

    if let Some(mut acme_res) = crate::acme::try_serve_acme_challenge(
        &raw_path,
        state.acme_webroot.as_deref().map(|p| p.as_path()),
    )
    .await
    {
        inject_response_security_headers(&mut acme_res, &state.security);
        let (parts, body) = acme_res.into_parts();
        return Ok(Response::from_parts(parts, body.map_err(|e| match e {}).boxed()));
    }

    if state.security.enable_defense {
        if let Some(mut def_res) = state.defense.evaluate_request_with_tls(
            client_ip,
            &method,
            &raw_path,
            user_agent.as_deref(),
            tls_profile.as_deref(),
        ) {
            state.governor.record_threat();
            inject_response_security_headers(&mut def_res, &state.security);
            let status = def_res.status().as_u16();
            let threat_category = if status == StatusCode::FORBIDDEN.as_u16() {
                "Bot Perimeter Intercept".to_string()
            } else {
                "Hostile Recon Probe".to_string()
            };
            state.telemetry.record(TelemetryRecord {
                timestamp_ms: current_time_ms(), client_ip: client_ip.to_string(), method, path: full_path,
                status, duration_us: timer.elapsed_micros(), upstream_target: None,
                threat_trapped: true, threat_category: Some(threat_category), user_agent,
            });
            let (parts, body) = def_res.into_parts();
            return Ok(Response::from_parts(parts, body.map_err(|e| match e {}).boxed()));
        }
    }

    let host_header = req.uri().host().or_else(|| req.headers().get(HOST).and_then(|h| h.to_str().ok())).unwrap_or("");
    let target = match state.router.resolve(host_header) {
        Some(t) => t.clone(),
        None => {
            warn!(ip = %client_ip, host = %host_header, "No route configured for host");
            let mut res = Response::new(Full::new(Bytes::from("502 Bad Gateway: Unrecognized Sovereign Host\n")).map_err(|e| match e {}).boxed());
            *res.status_mut() = StatusCode::BAD_GATEWAY;
            inject_response_security_headers(&mut res, &state.security);
            state.telemetry.record(TelemetryRecord {
                timestamp_ms: current_time_ms(), client_ip: client_ip.to_string(), method, path: full_path,
                status: StatusCode::BAD_GATEWAY.as_u16(), duration_us: timer.elapsed_micros(),
                upstream_target: None, threat_trapped: false, threat_category: None, user_agent,
            });
            return Ok(res);
        }
    };

    let is_ws = req.headers().get(UPGRADE).and_then(|v| v.to_str().ok()).map(|s| s.eq_ignore_ascii_case("websocket")).unwrap_or(false);
    if is_ws && target.websocket_allowed {
        return handle_websocket_upgrade(req, client_ip, target, state, timer, method, full_path, user_agent).await;
    }

    forward_http_request(req, client_ip, target, state, timer, method, full_path, user_agent).await
}
