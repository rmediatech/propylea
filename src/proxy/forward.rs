//! # Upstream HTTP Forwarding & Hedged Racing (`proxy/forward.rs`)

use super::{BoxedBody, ProxyState};
use crate::headers::{
    inject_downstream_security_headers, inject_response_security_headers, prepare_upstream_headers,
};
use crate::router::UpstreamTarget;
use crate::telemetry::{current_time_ms, ExecutionTimer, TelemetryRecord};
use bytes::Bytes;
#[cfg(feature = "hedged-racing")]
use http_body_util::Limited;
use http_body_util::{BodyExt, Full};
use hyper::header::{HeaderValue, HOST};
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::net::{IpAddr, SocketAddr};
#[cfg(feature = "hedged-racing")]
use std::sync::Arc;
use tokio::net::TcpStream;
#[cfg(feature = "hedged-racing")]
use tracing::warn;
use tracing::{debug, error, info};

#[allow(clippy::too_many_arguments)]
pub(super) async fn forward_http_request(
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
        req, client_ip, target.addr, state, timer, method, full_path, user_agent,
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
    let (parts, body) = req.into_parts();
    let max_bytes = state.framing_guard.max_body_bytes() as usize;
    let body_bytes = match Limited::new(body, max_bytes).collect().await {
        Ok(c) => c.to_bytes(),
        Err(e) => {
            error!("Incoming request body exceeded limit or transfer failed: {}", e);
            let mut res = Response::new(Full::new(Bytes::from("413 Payload Too Large\n")).map_err(|e| match e {}).boxed());
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
                    let addr: SocketAddr = steed.endpoint.parse().map_err(|_| hippodrome::HippodromeError::AllSteedsFailed)?;
                    let upstream_stream = TcpStream::connect(addr).await.map_err(|_| hippodrome::HippodromeError::AllSteedsFailed)?;
                    let io = TokioIo::new(upstream_stream);
                    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.map_err(|_| hippodrome::HippodromeError::AllSteedsFailed)?;
                    tokio::spawn(async move {
                        if let Err(err) = conn.await {
                            debug!("Upstream connection closed: {}", err);
                        }
                    });
                    let upstream_req = Request::from_parts(parts, Full::new(body_bytes));
                    let res = sender.send_request(upstream_req).await.map_err(|_| hippodrome::HippodromeError::AllSteedsFailed)?;
                    if res.status().is_server_error() {
                        warn!(status = %res.status(), endpoint = %steed.endpoint, "Upstream 5xx; hedged failover");
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
            error!("All hedged upstreams failed: {}", e);
            return Ok(build_502_response(
                "502 Bad Gateway: Upstream Unavailable\n",
                client_ip, &state, &timer, method, full_path, None, user_agent,
            ));
        }
    };

    inject_downstream_security_headers(&mut parts.headers, &state.security);
    check_harvester_promotion(&state, parts.status, &full_path, client_ip);
    state.telemetry.record(TelemetryRecord {
        timestamp_ms: current_time_ms(), client_ip: client_ip.to_string(), method, path: full_path,
        status: parts.status.as_u16(), duration_us: timer.elapsed_micros(),
        upstream_target: Some(winner_endpoint), threat_trapped: false, threat_category: None, user_agent,
    });
    Ok(Response::from_parts(parts, body))
}

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
            return Ok(build_502_response(
                "502 Bad Gateway: Upstream Unavailable\n",
                client_ip, &state, &timer, method, full_path, Some(addr.to_string()), user_agent,
            ));
        }
    };

    let io = TokioIo::new(upstream_stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
    tokio::spawn(async move {
        if let Err(err) = conn.await {
            debug!("Upstream connection closed: {}", err);
        }
    });

    let upstream_res = match sender.send_request(req).await {
        Ok(r) => r,
        Err(e) => {
            error!("Failed to send request upstream: {}", e);
            return Ok(build_502_response(
                "502 Bad Gateway: Upstream Protocol Error\n",
                client_ip, &state, &timer, method, full_path, Some(addr.to_string()), user_agent,
            ));
        }
    };

    let (mut parts, body) = upstream_res.into_parts();
    inject_downstream_security_headers(&mut parts.headers, &state.security);
    check_harvester_promotion(&state, parts.status, &full_path, client_ip);
    state.telemetry.record(TelemetryRecord {
        timestamp_ms: current_time_ms(), client_ip: client_ip.to_string(), method, path: full_path,
        status: parts.status.as_u16(), duration_us: timer.elapsed_micros(),
        upstream_target: Some(addr.to_string()), threat_trapped: false, threat_category: None, user_agent,
    });
    Ok(Response::from_parts(parts, body.boxed()))
}

fn check_harvester_promotion(state: &ProxyState, status: StatusCode, full_path: &str, client_ip: IpAddr) {
    if state.security.enable_defense && status == StatusCode::NOT_FOUND {
        let path_only = full_path.split('?').next().unwrap_or(full_path);
        if let Some(promotion) = state.defense.record_anomalous_uri(path_only, client_ip) {
            info!(
                path = %promotion.path, category = %promotion.category.name(),
                distinct_subnets = promotion.distinct_subnets, total_hits = promotion.total_hits,
                "🛡️ [PROPYLEA-HARVESTER] Zero-day probe autonomously elevated to active perimeter trap!"
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn build_502_response(
    msg: &'static str,
    client_ip: IpAddr,
    state: &ProxyState,
    timer: &ExecutionTimer,
    method: String,
    full_path: String,
    upstream_target: Option<String>,
    user_agent: Option<String>,
) -> Response<BoxedBody> {
    let mut res = Response::new(Full::new(Bytes::from(msg)).map_err(|e| match e {}).boxed());
    *res.status_mut() = StatusCode::BAD_GATEWAY;
    inject_response_security_headers(&mut res, &state.security);
    state.telemetry.record(TelemetryRecord {
        timestamp_ms: current_time_ms(), client_ip: client_ip.to_string(), method, path: full_path,
        status: StatusCode::BAD_GATEWAY.as_u16(), duration_us: timer.elapsed_micros(),
        upstream_target, threat_trapped: false, threat_category: None, user_agent,
    });
    res
}
