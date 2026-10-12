//! # Sovereign Reverse Proxy & Streaming Engine
//! Low-latency, zero-allocation L7 proxy with bi-directional WebSocket tunneling,
//! full HTTP/1.1 & HTTP/2 streaming via Hyper 1.4 and Tokio, and integrated
//! autonomous resource governance and telemetry.

use crate::config::{PropyleaConfig, SecurityConfig};
use crate::defense::EdgeDefense;
use crate::headers::{
    inject_downstream_security_headers, inject_response_security_headers, prepare_upstream_headers,
};
use crate::maintenance::ResourceGovernor;
use crate::router::{UpstreamRouter, UpstreamTarget};
use crate::telemetry::{
    current_time_ms, sanitize_query_string, ExecutionTimer, TelemetryRecord, TelemetryRingBuffer,
};
use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, Limited};
use hyper::header::{HeaderValue, HOST, UPGRADE, USER_AGENT};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use thiserror::Error;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

pub type BoxedBody = BoxBody<Bytes, hyper::Error>;

#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Hyper error: {0}")]
    Hyper(#[from] hyper::Error),
}

/// RAII connection tracker that ensures active connection counter is always decremented
struct ConnectionGuard(ResourceGovernor);

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.0.deregister_connection();
    }
}

/// Shared proxy state across all incoming connections
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
    info!(
        "🚀 [PROPYLEA] Sovereign HTTPS reverse proxy active on {}",
        bind_addr
    );
    run_https_proxy_listener(listener, tls_acceptor, config, governor, telemetry).await
}

pub async fn run_https_proxy_listener(
    listener: TcpListener,
    tls_acceptor: TlsAcceptor,
    config: PropyleaConfig,
    governor: ResourceGovernor,
    telemetry: TelemetryRingBuffer,
) -> Result<(), std::io::Error> {
    let defense = if config.security.persist_quarantine {
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

                // 1. Re-hydrate active bans into memory on startup
                if let Err(e) = manager.rehydrate_on_boot() {
                    warn!("Failed to rehydrate active quarantine records: {}", e);
                }

                // 2. Spawn async persistence worker
                let store_clone = store.clone();
                tokio::spawn(async move {
                    crate::quarantine::QuarantineManager::run_persistence_worker(store_clone, rx)
                        .await;
                });

                // 3. Spawn Unix Domain Socket IPC control server
                match crate::quarantine::IpcServer::bind(&sock_path) {
                    Ok(ipc_listener) => {
                        let sock_clone = sock_path.clone();
                        tokio::spawn(async move {
                            crate::quarantine::IpcServer::run_loop(
                                ipc_listener,
                                sock_clone,
                                in_mem,
                                store,
                            )
                            .await;
                        });
                    }
                    Err(e) => {
                        warn!(
                            "Failed to bind quarantine IPC control socket at {}: {}",
                            sock_path.display(),
                            e
                        );
                    }
                }

                Arc::new(edge_defense.with_quarantine_manager(manager))
            }
            Err(e) => {
                warn!(
                    "Failed to open quarantine store at {}: {}. Falling back to in-memory only.",
                    db_path.display(),
                    e
                );
                Arc::new(EdgeDefense::new(&config.security))
            }
        }
    } else {
        Arc::new(EdgeDefense::new(&config.security))
    };

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
            let _conn_guard = _guard; // Held until task completion

            // Sniff ClientHello from raw stream without consuming socket buffer
            let mut peek_buf = [0u8; 1024];
            let tls_profile = match raw_stream.peek(&mut peek_buf).await {
                Ok(n) if n > 0 => {
                    crate::tls_fingerprint::ClientTlsProfile::parse_client_hello(&peek_buf[..n])
                }
                _ => None,
            };
            let tls_profile = tls_profile.map(Arc::new);

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

/// Core request handler dispatching requests upstream or into WebSocket tunnels
pub async fn handle_proxy_request(
    req: Request<hyper::body::Incoming>,
    client_ip: IpAddr,
    state: ProxyState,
) -> Result<Response<BoxedBody>, hyper::Error> {
    handle_proxy_request_with_tls(req, client_ip, state, None).await
}

/// Core request handler dispatching requests upstream with TLS profile verification
pub async fn handle_proxy_request_with_tls(
    mut req: Request<hyper::body::Incoming>,
    client_ip: IpAddr,
    state: ProxyState,
    tls_profile: Option<Arc<crate::tls_fingerprint::ClientTlsProfile>>,
) -> Result<Response<BoxedBody>, hyper::Error> {
    let timer = ExecutionTimer::start();

    // 0. Layer 0: HTTP Protocol Framing & Request Smuggling Defense
    if let Err(violation) = state
        .framing_guard
        .validate_headers(req.headers(), req.method())
    {
        warn!(ip = %client_ip, error = %violation, "🚨 [PROPYLEA-FRAMING] HTTP Framing violation rejected at edge");
        state.governor.record_threat();
        let res = violation.public_response();
        let (parts, body) = res.into_parts();
        let boxed = body.map_err(|e| match e {}).boxed();
        return Ok(Response::from_parts(parts, boxed));
    }

    // Sanitize ingress proxy headers (strip spoofed X-Forwarded-*, insert verified peer IP)
    crate::framing_guard::FramingGuard::sanitize_ingress_headers(&mut req, client_ip);

    let method = req.method().to_string();
    let raw_path = req.uri().path().to_string();
    let raw_query = req.uri().query().unwrap_or("");
    let sanitized_query = sanitize_query_string(raw_query);
    let full_path = if sanitized_query.is_empty() {
        raw_path.clone()
    } else {
        format!("{}?{}", raw_path, sanitized_query)
    };

    let user_agent = req
        .headers()
        .get(USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // 0.5 ACME HTTP-01 Challenge Passthrough (in case validator connects over HTTPS)
    if let Some(mut acme_res) = crate::acme::try_serve_acme_challenge(
        &raw_path,
        state.acme_webroot.as_deref().map(|p| p.as_path()),
    )
    .await
    {
        inject_response_security_headers(&mut acme_res, &state.security);
        let (parts, body) = acme_res.into_parts();
        let boxed = body.map_err(|e| match e {}).boxed();
        return Ok(Response::from_parts(parts, boxed));
    }

    // 1. Edge Perimeter Defense: Check for hostile scan / decoy URI / TLS spoofing
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
                timestamp_ms: current_time_ms(),
                client_ip: client_ip.to_string(),
                method,
                path: full_path,
                status,
                duration_us: timer.elapsed_micros(),
                upstream_target: None,
                threat_trapped: true,
                threat_category: Some(threat_category),
                user_agent,
            });

            let (parts, body) = def_res.into_parts();
            let boxed = body.map_err(|e| match e {}).boxed();
            return Ok(Response::from_parts(parts, boxed));
        }
    }

    // 2. Resolve Upstream Target from HTTP/2 :authority or HTTP/1 Host header
    let host_header = req
        .uri()
        .host()
        .or_else(|| req.headers().get(HOST).and_then(|h| h.to_str().ok()))
        .unwrap_or("");

    let target = match state.router.resolve(host_header) {
        Some(t) => t.clone(),
        None => {
            warn!(ip = %client_ip, host = %host_header, "No route configured for host");
            let mut res = Response::new(
                Full::new(Bytes::from(
                    "502 Bad Gateway: Unrecognized Sovereign Host\n",
                ))
                .map_err(|e| match e {})
                .boxed(),
            );
            *res.status_mut() = StatusCode::BAD_GATEWAY;
            inject_response_security_headers(&mut res, &state.security);

            state.telemetry.record(TelemetryRecord {
                timestamp_ms: current_time_ms(),
                client_ip: client_ip.to_string(),
                method,
                path: full_path,
                status: StatusCode::BAD_GATEWAY.as_u16(),
                duration_us: timer.elapsed_micros(),
                upstream_target: None,
                threat_trapped: false,
                threat_category: None,
                user_agent,
            });

            return Ok(res);
        }
    };

    // 3. Check for WebSocket Upgrade
    let is_websocket = req
        .headers()
        .get(UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);

    if is_websocket && target.websocket_allowed {
        return handle_websocket_upgrade(
            req, client_ip, target, state, timer, method, full_path, user_agent,
        )
        .await;
    }

    // 4. Standard HTTP Reverse Proxying
    forward_http_request(
        req, client_ip, target, state, timer, method, full_path, user_agent,
    )
    .await
}

/// Forwards standard HTTP requests to the resolved upstream server
#[allow(clippy::too_many_arguments)]
async fn forward_http_request(
    mut req: Request<hyper::body::Incoming>,
    client_ip: IpAddr,
    target: UpstreamTarget,
    state: ProxyState,
    timer: ExecutionTimer,
    method: String,
    full_path: String,
    user_agent: Option<String>,
) -> Result<Response<BoxedBody>, hyper::Error> {
    // Ingest proxy headers
    prepare_upstream_headers(&mut req, client_ip);

    // Ensure Host header matches primary domain
    if let Ok(host_val) = HeaderValue::from_str(&target.primary_host) {
        req.headers_mut().insert(HOST, host_val);
    }

    #[cfg(feature = "hedged-racing")]
    if target.hedged_racing && target.addrs.len() > 1 {
        if let Some(racer) = target.racer {
            return forward_http_request_hedged(
                req, client_ip, racer, state, timer, method, full_path, user_agent,
            )
            .await;
        }
    }

    forward_http_request_direct(
        req,
        client_ip,
        target.addr,
        state,
        timer,
        method,
        full_path,
        user_agent,
    )
    .await
}

#[cfg(feature = "hedged-racing")]
#[allow(clippy::too_many_arguments)]
async fn forward_http_request_hedged(
    req: Request<hyper::body::Incoming>,
    client_ip: IpAddr,
    racer: Arc<hippodrome::HippodromeHttpRacer>,
    state: ProxyState,
    timer: ExecutionTimer,
    method: String,
    full_path: String,
    user_agent: Option<String>,
) -> Result<Response<BoxedBody>, hyper::Error> {
    // 1. Ingest body bytes with bounded ceiling so it can be re-transmitted if hedged or failed over
    let (parts, body) = req.into_parts();
    let max_bytes = state.framing_guard.max_body_bytes() as usize;
    let limited_body = Limited::new(body, max_bytes);
    let body_bytes = match limited_body.collect().await {
        Ok(c) => c.to_bytes(),
        Err(e) => {
            error!(
                "Incoming request body exceeded limit or transfer failed: {}",
                e
            );
            let mut res = Response::new(
                Full::new(Bytes::from("413 Payload Too Large\n"))
                    .map_err(|e| match e {})
                    .boxed(),
            );
            *res.status_mut() = StatusCode::PAYLOAD_TOO_LARGE;
            inject_response_security_headers(&mut res, &state.security);
            return Ok(res);
        }
    };

    let parts = Arc::new(parts);
    let method_for_racer = method.clone();

    let race_outcome = racer
        .dispatch(&method_for_racer, {
            let parts = Arc::clone(&parts);
            let body_bytes = body_bytes.clone();
            move |steed| {
                let parts = (*parts).clone();
                let body_bytes = body_bytes.clone();
                async move {
                    let addr: SocketAddr = steed
                        .endpoint
                        .parse()
                        .map_err(|_| hippodrome::HippodromeError::AllSteedsFailed)?;
                    let upstream_stream = TcpStream::connect(addr)
                        .await
                        .map_err(|_| hippodrome::HippodromeError::AllSteedsFailed)?;
                    let io = TokioIo::new(upstream_stream);
                    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
                        .await
                        .map_err(|_| hippodrome::HippodromeError::AllSteedsFailed)?;
                    tokio::spawn(async move {
                        if let Err(err) = conn.await {
                            debug!("Upstream connection closed with error: {}", err);
                        }
                    });
                    let upstream_req = Request::from_parts(parts, Full::new(body_bytes));
                    let res = sender
                        .send_request(upstream_req)
                        .await
                        .map_err(|_| hippodrome::HippodromeError::AllSteedsFailed)?;

                    // If upstream returns 5xx server error, trigger hedged failover
                    if res.status().is_server_error() {
                        warn!(
                            status = %res.status(),
                            endpoint = %steed.endpoint,
                            "Upstream returned 5xx server error; triggering hedged failover"
                        );
                        return Err(hippodrome::HippodromeError::AllSteedsFailed);
                    }

                    Ok(res)
                }
            }
        })
        .await;

    let (mut parts, body, winner_endpoint) = match race_outcome {
        Ok(outcome) => {
            let (parts, body) = outcome.value.into_parts();
            (parts, body.boxed(), outcome.winner.endpoint)
        }
        Err(e) => {
            error!("All hedged upstreams failed or timed out: {}", e);
            let mut res = Response::new(
                Full::new(Bytes::from("502 Bad Gateway: Upstream Unavailable\n"))
                    .map_err(|e| match e {})
                    .boxed(),
            );
            *res.status_mut() = StatusCode::BAD_GATEWAY;
            inject_response_security_headers(&mut res, &state.security);

            state.telemetry.record(TelemetryRecord {
                timestamp_ms: current_time_ms(),
                client_ip: client_ip.to_string(),
                method,
                path: full_path,
                status: StatusCode::BAD_GATEWAY.as_u16(),
                duration_us: timer.elapsed_micros(),
                upstream_target: None,
                threat_trapped: false,
                threat_category: None,
                user_agent,
            });

            return Ok(res);
        }
    };

    inject_downstream_security_headers(&mut parts.headers, &state.security);

    // If upstream returned 404 Not Found, feed anomalous probe to Layer 13 Threat Harvester
    if state.security.enable_defense && parts.status == StatusCode::NOT_FOUND {
        let path_only = full_path.split('?').next().unwrap_or(&full_path);
        if let Some(promotion) = state.defense.record_anomalous_uri(path_only, client_ip) {
            info!(
                path = %promotion.path,
                category = %promotion.category.name(),
                distinct_subnets = promotion.distinct_subnets,
                total_hits = promotion.total_hits,
                "🛡️ [PROPYLEA-HARVESTER] Zero-day probe autonomously elevated to active perimeter trap!"
            );
        }
    }

    state.telemetry.record(TelemetryRecord {
        timestamp_ms: current_time_ms(),
        client_ip: client_ip.to_string(),
        method,
        path: full_path,
        status: parts.status.as_u16(),
        duration_us: timer.elapsed_micros(),
        upstream_target: Some(winner_endpoint),
        threat_trapped: false,
        threat_category: None,
        user_agent,
    });

    Ok(Response::from_parts(parts, body))
}

/// Direct forward path to a single upstream server with zero buffering.
#[allow(clippy::too_many_arguments)]
async fn forward_http_request_direct(
    req: Request<hyper::body::Incoming>,
    client_ip: IpAddr,
    addr: SocketAddr,
    state: ProxyState,
    timer: ExecutionTimer,
    method: String,
    full_path: String,
    user_agent: Option<String>,
) -> Result<Response<BoxedBody>, hyper::Error> {
    let upstream_stream = match TcpStream::connect(addr).await {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to connect to upstream {}: {}", addr, e);
            let mut res = Response::new(
                Full::new(Bytes::from("502 Bad Gateway: Upstream Unavailable\n"))
                    .map_err(|e| match e {})
                    .boxed(),
            );
            *res.status_mut() = StatusCode::BAD_GATEWAY;
            inject_response_security_headers(&mut res, &state.security);

            state.telemetry.record(TelemetryRecord {
                timestamp_ms: current_time_ms(),
                client_ip: client_ip.to_string(),
                method,
                path: full_path,
                status: StatusCode::BAD_GATEWAY.as_u16(),
                duration_us: timer.elapsed_micros(),
                upstream_target: Some(addr.to_string()),
                threat_trapped: false,
                threat_category: None,
                user_agent,
            });

            return Ok(res);
        }
    };

    let io = TokioIo::new(upstream_stream);

    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;

    tokio::spawn(async move {
        if let Err(err) = conn.await {
            debug!("Upstream connection closed with error: {}", err);
        }
    });

    let upstream_res = match sender.send_request(req).await {
        Ok(r) => r,
        Err(e) => {
            error!("Failed to send request upstream: {}", e);
            let mut res = Response::new(
                Full::new(Bytes::from("502 Bad Gateway: Upstream Protocol Error\n"))
                    .map_err(|e| match e {})
                    .boxed(),
            );
            *res.status_mut() = StatusCode::BAD_GATEWAY;
            inject_response_security_headers(&mut res, &state.security);

            state.telemetry.record(TelemetryRecord {
                timestamp_ms: current_time_ms(),
                client_ip: client_ip.to_string(),
                method,
                path: full_path,
                status: StatusCode::BAD_GATEWAY.as_u16(),
                duration_us: timer.elapsed_micros(),
                upstream_target: Some(addr.to_string()),
                threat_trapped: false,
                threat_category: None,
                user_agent,
            });

            return Ok(res);
        }
    };

    let (mut parts, body) = upstream_res.into_parts();
    inject_downstream_security_headers(&mut parts.headers, &state.security);

    // If upstream returned 404 Not Found, feed anomalous probe to Layer 13 Threat Harvester
    if state.security.enable_defense && parts.status == StatusCode::NOT_FOUND {
        let path_only = full_path.split('?').next().unwrap_or(&full_path);
        if let Some(promotion) = state.defense.record_anomalous_uri(path_only, client_ip) {
            info!(
                path = %promotion.path,
                category = %promotion.category.name(),
                distinct_subnets = promotion.distinct_subnets,
                total_hits = promotion.total_hits,
                "🛡️ [PROPYLEA-HARVESTER] Zero-day probe autonomously elevated to active perimeter trap!"
            );
        }
    }

    state.telemetry.record(TelemetryRecord {
        timestamp_ms: current_time_ms(),
        client_ip: client_ip.to_string(),
        method,
        path: full_path,
        status: parts.status.as_u16(),
        duration_us: timer.elapsed_micros(),
        upstream_target: Some(addr.to_string()),
        threat_trapped: false,
        threat_category: None,
        user_agent,
    });

    Ok(Response::from_parts(parts, body.boxed()))
}

/// Bi-directionally tunnels WebSockets between client and upstream server
#[allow(clippy::too_many_arguments)]
async fn handle_websocket_upgrade(
    mut req: Request<hyper::body::Incoming>,
    client_ip: IpAddr,
    target: UpstreamTarget,
    state: ProxyState,
    timer: ExecutionTimer,
    method: String,
    full_path: String,
    user_agent: Option<String>,
) -> Result<Response<BoxedBody>, hyper::Error> {
    prepare_upstream_headers(&mut req, client_ip);

    if let Ok(host_val) = HeaderValue::from_str(&target.primary_host) {
        req.headers_mut().insert(HOST, host_val);
    }

    let upstream_stream = match TcpStream::connect(target.addr).await {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to connect upstream for WebSocket: {}", e);
            let mut res = Response::new(
                Full::new(Bytes::from("502 Bad Gateway: Upstream Unavailable\n"))
                    .map_err(|e| match e {})
                    .boxed(),
            );
            *res.status_mut() = StatusCode::BAD_GATEWAY;
            inject_response_security_headers(&mut res, &state.security);
            return Ok(res);
        }
    };

    let io = TokioIo::new(upstream_stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;

    tokio::spawn(async move {
        if let Err(err) = conn.with_upgrades().await {
            debug!("Upstream connection closed: {}", err);
        }
    });

    let client_upgrade = hyper::upgrade::on(&mut req);
    let mut upstream_res = sender.send_request(req).await?;

    if upstream_res.status() == StatusCode::SWITCHING_PROTOCOLS {
        let upstream_upgrade = hyper::upgrade::on(&mut upstream_res);
        tokio::spawn(async move {
            match tokio::try_join!(client_upgrade, upstream_upgrade) {
                Ok((client_upgraded, upstream_upgraded)) => {
                    let mut client_io = TokioIo::new(client_upgraded);
                    let mut upstream_io = TokioIo::new(upstream_upgraded);
                    if let Err(e) =
                        tokio::io::copy_bidirectional(&mut client_io, &mut upstream_io).await
                    {
                        debug!("WebSocket bidirectional tunnel finished: {}", e);
                    }
                }
                Err(e) => {
                    error!("WebSocket upgrade bridging error: {}", e);
                }
            }
        });

        let (mut parts, body) = upstream_res.into_parts();
        inject_downstream_security_headers(&mut parts.headers, &state.security);

        state.telemetry.record(TelemetryRecord {
            timestamp_ms: current_time_ms(),
            client_ip: client_ip.to_string(),
            method,
            path: full_path,
            status: StatusCode::SWITCHING_PROTOCOLS.as_u16(),
            duration_us: timer.elapsed_micros(),
            upstream_target: Some(target.addr.to_string()),
            threat_trapped: false,
            threat_category: None,
            user_agent,
        });

        return Ok(Response::from_parts(parts, body.boxed()));
    }

    let (mut parts, body) = upstream_res.into_parts();
    inject_downstream_security_headers(&mut parts.headers, &state.security);

    state.telemetry.record(TelemetryRecord {
        timestamp_ms: current_time_ms(),
        client_ip: client_ip.to_string(),
        method,
        path: full_path,
        status: parts.status.as_u16(),
        duration_us: timer.elapsed_micros(),
        upstream_target: Some(target.addr.to_string()),
        threat_trapped: false,
        threat_category: None,
        user_agent,
    });

    Ok(Response::from_parts(parts, body.boxed()))
}
