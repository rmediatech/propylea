//! # Integration Tests for Propylea
//! End-to-end testing of TLS SNI multiplexing, HTTP redirect, reverse proxy streaming,
//! perimeter defense traps, telemetry recording, and resource governance.

use bytes::Bytes;
use http_body_util::Full;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use propylea::config::{
    MaintenanceSettings, PropyleaConfig, RouteConfig, SecurityConfig, ServerConfig,
};
use propylea::maintenance::{MaintenanceConfig, ResourceGovernor};
use propylea::telemetry::{TelemetryFilter, TelemetryRingBuffer};
use propylea::tls::build_sni_tls_acceptor;
use std::io::Write;
use tempfile::NamedTempFile;
use tokio::net::TcpListener;

/// Helper to generate TLS certificate and key files for a given domain
fn generate_tls_files(domain: &str) -> (NamedTempFile, NamedTempFile) {
    let cert = rcgen::generate_simple_self_signed(vec![domain.to_string()]).unwrap();
    let cert_pem = cert.cert.pem();
    let key_pem = cert.key_pair.serialize_pem();

    let mut cert_file = NamedTempFile::new().unwrap();
    cert_file.write_all(cert_pem.as_bytes()).unwrap();

    let mut key_file = NamedTempFile::new().unwrap();
    key_file.write_all(key_pem.as_bytes()).unwrap();

    (cert_file, key_file)
}

#[tokio::test]
async fn test_http_to_https_redirect_with_query_preservation() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let _ =
            propylea::run_http_redirect_listener(listener, SecurityConfig::default(), None).await;
    });

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let res = client
        .get(format!(
            "http://{}/v1/checkout?sku=9988&discount=SAVE20",
            addr
        ))
        .header("Host", "store.example.com")
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::MOVED_PERMANENTLY);
    let loc = res.headers().get("location").unwrap().to_str().unwrap();
    assert_eq!(
        loc,
        "https://store.example.com/v1/checkout?sku=9988&discount=SAVE20"
    );
    assert_eq!(
        res.headers().get("server").unwrap().to_str().unwrap(),
        "Propylea-Edge-Gateway/1.0"
    );
}

#[tokio::test]
async fn test_https_reverse_proxy_end_to_end_and_defense_trap() {
    // 1. Spawn Mock Upstream HTTP Server
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let (stream, _) = match upstream_listener.accept().await {
                Ok(c) => c,
                Err(_) => break,
            };
            let io = TokioIo::new(stream);
            let service = service_fn(|req: Request<hyper::body::Incoming>| async move {
                // Verify upstream received proxy headers
                let has_forwarded = req.headers().contains_key("x-forwarded-for");
                let has_via = req.headers().contains_key("via");

                if !has_forwarded || !has_via {
                    let mut bad = Response::new(Full::new(Bytes::from("Missing headers")));
                    *bad.status_mut() = StatusCode::BAD_REQUEST;
                    return Ok::<_, hyper::Error>(bad);
                }

                let mut res = Response::new(Full::new(Bytes::from("Hello from Upstream!")));
                *res.status_mut() = StatusCode::OK;
                Ok::<_, hyper::Error>(res)
            });

            tokio::spawn(async move {
                let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                    .serve_connection(io, service)
                    .await;
            });
        }
    });

    // 2. Setup TLS and Propylea Config
    let (cert_file, key_file) = generate_tls_files("app.example.com");

    let route = RouteConfig::single(
        vec!["app.example.com".into()],
        upstream_addr,
        cert_file.path().to_path_buf(),
        key_file.path().to_path_buf(),
        true,
    );

    let config = PropyleaConfig {
        server: ServerConfig {
            http_bind: "127.0.0.1:0".parse().unwrap(),
            https_bind: "127.0.0.1:0".parse().unwrap(),
            worker_threads: None,
            ..Default::default()
        },
        security: SecurityConfig {
            enable_defense: true,
            abuseipdb_api_key: None,
            webhook_url: None,
            syslog_cef: false,
            server_banner: "Test-Propylea-Edge".into(),
            hsts: true,
            frame_options: "DENY".into(),
            ..Default::default()
        },
        maintenance: MaintenanceSettings::default(),
        routes: vec![route],
    };

    let tls_acceptor = build_sni_tls_acceptor(&config.routes).unwrap();
    let governor = ResourceGovernor::new(MaintenanceConfig::default());
    let telemetry = TelemetryRingBuffer::new(100);

    // 3. Spawn HTTPS Proxy Listener
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    let proxy_cfg = config.clone();
    let proxy_gov = governor.clone();
    let proxy_tel = telemetry.clone();

    tokio::spawn(async move {
        let _ = propylea::run_https_proxy_listener(
            proxy_listener,
            tls_acceptor,
            proxy_cfg,
            proxy_gov,
            proxy_tel,
        )
        .await;
    });

    // 4. Test Client: Benign Request Forwarded to Upstream
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    let res = client
        .get(format!("https://{}/index.html?token=secret123", proxy_addr))
        .header("Host", "app.example.com")
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        res.headers().get("server").unwrap().to_str().unwrap(),
        "Test-Propylea-Edge"
    );
    let body = res.text().await.unwrap();
    assert_eq!(body, "Hello from Upstream!");

    // Verify Telemetry captured the request with query sanitization
    let records = telemetry.query(&TelemetryFilter {
        limit: 10,
        ..Default::default()
    });
    assert!(!records.is_empty());
    assert_eq!(records[0].status, 200);
    assert_eq!(records[0].path, "/index.html?token=[REDACTED]");
    assert!(!records[0].threat_trapped);

    // 5. Test Decoy Probe / Scanner Trap
    let probe_res = client
        .get(format!("https://{}/.env", proxy_addr))
        .header("Host", "app.example.com")
        .send()
        .await
        .unwrap();

    // Must return stealth 404
    assert_eq!(probe_res.status(), StatusCode::NOT_FOUND);
    let probe_body = probe_res.text().await.unwrap();
    assert_eq!(probe_body, "404 Not Found\n");

    // Governor and Telemetry verification
    let threats = telemetry.query(&TelemetryFilter {
        threats_only: true,
        ..Default::default()
    });
    assert_eq!(threats.len(), 1);
    assert_eq!(threats[0].path, "/.env");
    assert!(threats[0].threat_trapped);
    assert_eq!(
        governor
            .metrics()
            .total_trapped_threats
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
}

#[cfg(feature = "hedged-racing")]
#[tokio::test]
async fn test_hedged_racing_multi_upstream_beating_tail_latency() {
    use std::time::Duration;

    // 1. Spawn Upstream 1: Slow/Stalled (150ms delay)
    let listener_1 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr_1 = listener_1.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener_1.accept().await {
            let io = TokioIo::new(stream);
            let service = service_fn(|_: Request<hyper::body::Incoming>| async move {
                tokio::time::sleep(Duration::from_millis(150)).await;
                let mut res = Response::new(Full::new(Bytes::from("From Upstream 1 (Slow)")));
                *res.status_mut() = StatusCode::OK;
                Ok::<_, hyper::Error>(res)
            });
            tokio::spawn(async move {
                let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                    .serve_connection(io, service)
                    .await;
            });
        }
    });

    // 2. Spawn Upstream 2: Fast (Immediate response)
    let listener_2 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr_2 = listener_2.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener_2.accept().await {
            let io = TokioIo::new(stream);
            let service = service_fn(|_: Request<hyper::body::Incoming>| async move {
                let mut res = Response::new(Full::new(Bytes::from("From Upstream 2 (Fast)")));
                *res.status_mut() = StatusCode::OK;
                Ok::<_, hyper::Error>(res)
            });
            tokio::spawn(async move {
                let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                    .serve_connection(io, service)
                    .await;
            });
        }
    });

    // 3. Configure Propylea with both upstreams and hedged racing enabled
    let (cert_file, key_file) = generate_tls_files("hedged.example.com");
    let route = RouteConfig {
        domains: vec!["hedged.example.com".into()],
        upstream: None,
        upstreams: Some(vec![addr_1, addr_2]),
        cert: cert_file.path().to_path_buf(),
        key: key_file.path().to_path_buf(),
        websocket: true,
        hedged_racing: Some(true),
    };

    let config = PropyleaConfig {
        server: ServerConfig {
            http_bind: "127.0.0.1:0".parse().unwrap(),
            https_bind: "127.0.0.1:0".parse().unwrap(),
            worker_threads: None,
            ..Default::default()
        },
        security: SecurityConfig {
            enable_defense: false,
            ..Default::default()
        },
        maintenance: MaintenanceSettings::default(),
        routes: vec![route],
    };

    let tls_acceptor = build_sni_tls_acceptor(&config.routes).unwrap();
    let governor = ResourceGovernor::new(MaintenanceConfig::default());
    let telemetry = TelemetryRingBuffer::new(100);

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    let proxy_cfg = config.clone();
    let proxy_gov = governor.clone();
    let proxy_tel = telemetry.clone();

    tokio::spawn(async move {
        let _ = propylea::run_https_proxy_listener(
            proxy_listener,
            tls_acceptor,
            proxy_cfg,
            proxy_gov,
            proxy_tel,
        )
        .await;
    });

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    // 4. Client issues GET request
    let start = std::time::Instant::now();
    let res = client
        .get(format!("https://{}/api/race", proxy_addr))
        .header("Host", "hedged.example.com")
        .send()
        .await
        .unwrap();

    let elapsed = start.elapsed();
    assert_eq!(res.status(), StatusCode::OK);
    let body = res.text().await.unwrap();

    // Invariant: Speculative hedging dispatched to Upstream 2 and returned before Upstream 1's 150ms!
    assert_eq!(body, "From Upstream 2 (Fast)");
    assert!(
        elapsed < Duration::from_millis(100),
        "Expected race to complete under 100ms, took {:?}",
        elapsed
    );
}

#[cfg(feature = "hedged-racing")]
#[tokio::test]
async fn test_hedged_racing_fails_over_on_instant_503_server_error() {
    use std::time::Duration;

    // 1. Spawn Upstream 1: Crashed / Instant 503 Service Unavailable
    let listener_1 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr_1 = listener_1.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener_1.accept().await {
            let io = TokioIo::new(stream);
            let service = service_fn(|_: Request<hyper::body::Incoming>| async move {
                let mut res = Response::new(Full::new(Bytes::from("503 Backend Crash")));
                *res.status_mut() = StatusCode::SERVICE_UNAVAILABLE;
                Ok::<_, hyper::Error>(res)
            });
            tokio::spawn(async move {
                let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                    .serve_connection(io, service)
                    .await;
            });
        }
    });

    // 2. Spawn Upstream 2: Healthy 200 OK after 10ms
    let listener_2 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr_2 = listener_2.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener_2.accept().await {
            let io = TokioIo::new(stream);
            let service = service_fn(|_: Request<hyper::body::Incoming>| async move {
                tokio::time::sleep(Duration::from_millis(10)).await;
                let mut res = Response::new(Full::new(Bytes::from("From Upstream 2 (Rescued)")));
                *res.status_mut() = StatusCode::OK;
                Ok::<_, hyper::Error>(res)
            });
            tokio::spawn(async move {
                let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                    .serve_connection(io, service)
                    .await;
            });
        }
    });

    // 3. Configure Propylea with both upstreams
    let (cert_file, key_file) = generate_tls_files("failover.example.com");
    let route = RouteConfig {
        domains: vec!["failover.example.com".into()],
        upstream: None,
        upstreams: Some(vec![addr_1, addr_2]),
        cert: cert_file.path().to_path_buf(),
        key: key_file.path().to_path_buf(),
        websocket: false,
        hedged_racing: Some(true),
    };

    let config = PropyleaConfig {
        server: ServerConfig {
            http_bind: "127.0.0.1:0".parse().unwrap(),
            https_bind: "127.0.0.1:0".parse().unwrap(),
            worker_threads: None,
            ..Default::default()
        },
        security: SecurityConfig {
            enable_defense: false,
            ..Default::default()
        },
        maintenance: MaintenanceSettings::default(),
        routes: vec![route],
    };

    let tls_acceptor = build_sni_tls_acceptor(&config.routes).unwrap();
    let governor = ResourceGovernor::new(MaintenanceConfig::default());
    let telemetry = TelemetryRingBuffer::new(100);

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    let proxy_cfg = config.clone();
    let proxy_gov = governor.clone();
    let proxy_tel = telemetry.clone();

    tokio::spawn(async move {
        let _ = propylea::run_https_proxy_listener(
            proxy_listener,
            tls_acceptor,
            proxy_cfg,
            proxy_gov,
            proxy_tel,
        )
        .await;
    });

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    // 4. Issue request: Upstream 1 returns 503 immediately, but proxy must fail over to Upstream 2!
    let res = client
        .get(format!("https://{}/api/data", proxy_addr))
        .header("Host", "failover.example.com")
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    let body = res.text().await.unwrap();
    assert_eq!(body, "From Upstream 2 (Rescued)");
}

#[cfg(feature = "hedged-racing")]
#[tokio::test]
async fn test_hedged_racing_payload_too_large_rejection() {
    // 1. Spawn Mock Upstream
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr_1 = listener.local_addr().unwrap();
    let addr_2 = listener.local_addr().unwrap(); // point to same for pooling

    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let io = TokioIo::new(stream);
            let service = service_fn(|_: Request<hyper::body::Incoming>| async move {
                let mut res = Response::new(Full::new(Bytes::from("OK")));
                *res.status_mut() = StatusCode::OK;
                Ok::<_, hyper::Error>(res)
            });
            tokio::spawn(async move {
                let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                    .serve_connection(io, service)
                    .await;
            });
        }
    });

    // 2. Configure Propylea
    let (cert_file, key_file) = generate_tls_files("limit.example.com");
    let route = RouteConfig {
        domains: vec!["limit.example.com".into()],
        upstream: None,
        upstreams: Some(vec![addr_1, addr_2]),
        cert: cert_file.path().to_path_buf(),
        key: key_file.path().to_path_buf(),
        websocket: false,
        hedged_racing: Some(true),
    };

    let config = PropyleaConfig {
        server: ServerConfig {
            http_bind: "127.0.0.1:0".parse().unwrap(),
            https_bind: "127.0.0.1:0".parse().unwrap(),
            worker_threads: None,
            ..Default::default()
        },
        security: SecurityConfig {
            enable_defense: false,
            ..Default::default()
        },
        maintenance: MaintenanceSettings::default(),
        routes: vec![route],
    };

    let tls_acceptor = build_sni_tls_acceptor(&config.routes).unwrap();
    let governor = ResourceGovernor::new(MaintenanceConfig::default());
    let telemetry = TelemetryRingBuffer::new(100);

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    let proxy_cfg = config.clone();
    let proxy_gov = governor.clone();
    let proxy_tel = telemetry.clone();

    tokio::spawn(async move {
        let _ = propylea::run_https_proxy_listener(
            proxy_listener,
            tls_acceptor,
            proxy_cfg,
            proxy_gov,
            proxy_tel,
        )
        .await;
    });

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    // 3. Issue POST request exceeding standard body limit (>10MB)
    // We send Content-Length > 10MB to verify framing rejection
    let huge_dummy_body = vec![b'A'; 11 * 1024 * 1024]; // 11 MB
    let res = client
        .post(format!("https://{}/upload", proxy_addr))
        .header("Host", "limit.example.com")
        .body(huge_dummy_body)
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

