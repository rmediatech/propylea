//! # Bi-Directional WebSocket Upgrade & Tunneling (`proxy/websocket.rs`)

use super::{BoxedBody, ProxyState};
use crate::headers::{
    inject_downstream_security_headers, inject_response_security_headers, prepare_upstream_headers,
};
use crate::router::UpstreamTarget;
use crate::telemetry::{current_time_ms, ExecutionTimer, TelemetryRecord};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::header::{HeaderValue, HOST};
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::net::IpAddr;
use tokio::net::TcpStream;
use tracing::{debug, error};

/// Bi-directionally tunnels WebSockets between client and upstream server
#[allow(clippy::too_many_arguments)]
pub(super) async fn handle_websocket_upgrade(
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
