//! # Adversarial & Fault-Tolerance Integration Tests for Propylea
//! Rigorous stress testing against active attackers, vulnerability sprayers,
//! abrupt socket termination, upstream outages, and parameter credential leaks.

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
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tempfile::NamedTempFile;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

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
async fn test_adversarial_vulnerability_scanner_battery() {
    let upstream_requests_received = Arc::new(AtomicUsize::new(0));
    let upstream_counter = upstream_requests_received.clone();

    // 1. Mock Upstream HTTP Server
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let (stream, _) = match upstream_listener.accept().await {
                Ok(c) => c,
                Err(_) => break,
            };
            let counter = upstream_counter.clone();
            let io = TokioIo::new(stream);
            let service = service_fn(move |_: Request<hyper::body::Incoming>| {
                counter.fetch_add(1, Ordering::SeqCst);
                async move {
                    let mut res = Response::new(Full::new(Bytes::from("Upstream OK")));
                    *res.status_mut() = StatusCode::OK;
                    Ok::<_, hyper::Error>(res)
                }
            });

            tokio::spawn(async move {
                let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                    .serve_connection(io, service)
                    .await;
            });
        }
    });

    // 2. Setup Propylea Gateway
    let (cert_file, key_file) = generate_tls_files("secure.example.com");
    let route = RouteConfig {
        domains: vec!["secure.example.com".into()],
        upstream: upstream_addr,
        cert: cert_file.path().to_path_buf(),
        key: key_file.path().to_path_buf(),
        websocket: true,
    };

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
            server_banner: "Propylea-Boundary/3.0".into(),
            hsts: true,
            frame_options: "DENY".into(),
            ..Default::default()
        },
        maintenance: MaintenanceSettings::default(),
        routes: vec![route],
    };

    let tls_acceptor = build_sni_tls_acceptor(&config.routes).unwrap();
    let governor = ResourceGovernor::new(MaintenanceConfig::default());
    let telemetry = TelemetryRingBuffer::new(500);

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

    // 3. Attack Wave: Hostile scanner paths
    let hostile_probes = [
        "/.env",
        "/.git/config",
        "/.aws/credentials",
        "/wp-login.php",
        "/xmlrpc.php",
        "/phpmyadmin/index.php",
    ];

    for probe_path in &hostile_probes {
        let res = client
            .get(format!("https://{}{}", proxy_addr, probe_path))
            .header("Host", "secure.example.com")
            .header(
                "User-Agent",
                "Mozilla/5.0 (compatible; Nmap Scripting Engine)",
            )
            .send()
            .await
            .unwrap();

        // Must drop with stealth 404
        assert_eq!(
            res.status(),
            StatusCode::NOT_FOUND,
            "Failed on probe {}",
            probe_path
        );
        assert_eq!(
            res.headers().get("server").unwrap().to_str().unwrap(),
            "Propylea-Boundary/3.0"
        );
    }

    // Invariant: ZERO hostile probes reached the upstream server
    assert_eq!(
        upstream_requests_received.load(Ordering::SeqCst),
        0,
        "Upstream server received malicious traffic!"
    );

    // Invariant: Governor recorded every trapped threat
    assert_eq!(
        governor
            .metrics()
            .total_trapped_threats
            .load(Ordering::Relaxed) as usize,
        hostile_probes.len()
    );

    // Invariant: Telemetry ring buffer holds all threats with threat_trapped = true
    let trapped = telemetry.query(&TelemetryFilter {
        threats_only: true,
        limit: 50,
        ..Default::default()
    });
    assert_eq!(trapped.len(), hostile_probes.len());
}

#[tokio::test]
async fn test_upstream_crash_and_resilience() {
    // 1. Point route to a non-existent port (dead upstream)
    let dead_upstream_port = 29999;
    let (cert_file, key_file) = generate_tls_files("resilience.example.com");

    let route = RouteConfig {
        domains: vec!["resilience.example.com".into()],
        upstream: format!("127.0.0.1:{}", dead_upstream_port).parse().unwrap(),
        cert: cert_file.path().to_path_buf(),
        key: key_file.path().to_path_buf(),
        websocket: true,
    };

    let config = PropyleaConfig {
        server: ServerConfig {
            http_bind: "127.0.0.1:0".parse().unwrap(),
            https_bind: "127.0.0.1:0".parse().unwrap(),
            worker_threads: None,
            ..Default::default()
        },
        security: SecurityConfig {
            enable_defense: true,
            server_banner: "Propylea-Boundary/3.0".into(),
            ..Default::default()
        },
        maintenance: MaintenanceSettings::default(),
        routes: vec![route],
    };

    let tls_acceptor = build_sni_tls_acceptor(&config.routes).unwrap();
    let governor = ResourceGovernor::new(MaintenanceConfig::default());
    let telemetry = TelemetryRingBuffer::new(50);

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    let proxy_gov = governor.clone();
    let proxy_tel = telemetry.clone();

    tokio::spawn(async move {
        let _ = propylea::run_https_proxy_listener(
            proxy_listener,
            tls_acceptor,
            config,
            proxy_gov,
            proxy_tel,
        )
        .await;
    });

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    // 2. Send request when backend is completely offline
    let res = client
        .get(format!("https://{}/api/data", proxy_addr))
        .header("Host", "resilience.example.com")
        .send()
        .await
        .unwrap();

    // Invariant: Returns clean 502 Bad Gateway without panicking or hanging
    assert_eq!(res.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(
        res.headers().get("server").unwrap().to_str().unwrap(),
        "Propylea-Boundary/3.0"
    );

    // Invariant: Telemetry recorded 502 status
    let records = telemetry.query(&TelemetryFilter {
        limit: 10,
        ..Default::default()
    });
    assert_eq!(records[0].status, 502);

    // Invariant: Active connection count decremented back to 0 once client closes keep-alive
    drop(client);
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
    assert_eq!(
        governor
            .metrics()
            .current_active_connections
            .load(Ordering::Relaxed),
        0
    );
}

#[tokio::test]
async fn test_abrupt_client_disconnect_connection_drain() {
    let (cert_file, key_file) = generate_tls_files("drain.example.com");

    let route = RouteConfig {
        domains: vec!["drain.example.com".into()],
        upstream: "127.0.0.1:8080".parse().unwrap(),
        cert: cert_file.path().to_path_buf(),
        key: key_file.path().to_path_buf(),
        websocket: true,
    };

    let config = PropyleaConfig {
        server: ServerConfig {
            http_bind: "127.0.0.1:0".parse().unwrap(),
            https_bind: "127.0.0.1:0".parse().unwrap(),
            worker_threads: None,
            ..Default::default()
        },
        security: SecurityConfig::default(),
        maintenance: MaintenanceSettings::default(),
        routes: vec![route],
    };

    let tls_acceptor = build_sni_tls_acceptor(&config.routes).unwrap();
    let governor = ResourceGovernor::new(MaintenanceConfig::default());
    let telemetry = TelemetryRingBuffer::new(50);

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    let proxy_gov = governor.clone();
    let proxy_tel = telemetry.clone();

    tokio::spawn(async move {
        let _ = propylea::run_https_proxy_listener(
            proxy_listener,
            tls_acceptor,
            config,
            proxy_gov,
            proxy_tel,
        )
        .await;
    });

    // 1. Open raw TCP connection and abruptly drop it (simulating network cut / attack)
    {
        let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
        // Send a few garbage bytes and immediately close socket
        let _ = stream.write_all(b"GARBAGE_PAYLOAD\r\n").await;
        stream.shutdown().await.unwrap();
        drop(stream);
    }

    // 2. Allow brief moment for Tokio task to conclude
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Invariant: Governor active connection count MUST be 0 (no connection leak!)
    assert_eq!(
        governor
            .metrics()
            .current_active_connections
            .load(Ordering::Relaxed),
        0,
        "Connection count leaked after abrupt client disconnect!"
    );
}

#[tokio::test]
async fn test_adversarial_query_parameter_credential_scrubbing() {
    let (cert_file, key_file) = generate_tls_files("leak.example.com");

    // Spawn mock upstream
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let (stream, _) = match upstream_listener.accept().await {
                Ok(c) => c,
                Err(_) => break,
            };
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

    let route = RouteConfig {
        domains: vec!["leak.example.com".into()],
        upstream: upstream_addr,
        cert: cert_file.path().to_path_buf(),
        key: key_file.path().to_path_buf(),
        websocket: true,
    };

    let config = PropyleaConfig {
        server: ServerConfig {
            http_bind: "127.0.0.1:0".parse().unwrap(),
            https_bind: "127.0.0.1:0".parse().unwrap(),
            worker_threads: None,
            ..Default::default()
        },
        security: SecurityConfig::default(),
        maintenance: MaintenanceSettings::default(),
        routes: vec![route],
    };

    let tls_acceptor = build_sni_tls_acceptor(&config.routes).unwrap();
    let governor = ResourceGovernor::new(MaintenanceConfig::default());
    let telemetry = TelemetryRingBuffer::new(50);

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    let proxy_gov = governor.clone();
    let proxy_tel = telemetry.clone();

    tokio::spawn(async move {
        let _ = propylea::run_https_proxy_listener(
            proxy_listener,
            tls_acceptor,
            config,
            proxy_gov,
            proxy_tel,
        )
        .await;
    });

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    // Adversarial query with high-value secrets
    let hostile_query_url = format!(
        "https://{}/auth/callback?user=alice&token=SUPER_SECRET_TOKEN&api_key=sk_live_998877&client_secret=TOP_SECRET&code=AUTH_CODE_XYZ",
        proxy_addr
    );

    let res = client
        .get(&hostile_query_url)
        .header("Host", "leak.example.com")
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);

    // Invariant: Verify telemetry ring buffer did NOT record any raw secret
    let records = telemetry.query(&TelemetryFilter {
        limit: 10,
        ..Default::default()
    });
    assert!(!records.is_empty());
    let recorded_path = &records[0].path;

    assert!(!recorded_path.contains("SUPER_SECRET_TOKEN"));
    assert!(!recorded_path.contains("sk_live_998877"));
    assert!(!recorded_path.contains("TOP_SECRET"));
    assert!(!recorded_path.contains("AUTH_CODE_XYZ"));

    // Invariant: Non-sensitive parameter 'user=alice' remains preserved
    assert!(recorded_path.contains("user=alice"));
    assert!(recorded_path.contains("token=[REDACTED]"));
    assert!(recorded_path.contains("api_key=[REDACTED]"));
    assert!(recorded_path.contains("client_secret=[REDACTED]"));
    assert!(recorded_path.contains("code=[REDACTED]"));
}

#[tokio::test]
async fn test_adversarial_acme_challenge_security_and_traversal() {
    let dir = tempfile::tempdir().unwrap();
    let challenge_dir = dir.path().join(".well-known").join("acme-challenge");
    std::fs::create_dir_all(&challenge_dir).unwrap();

    // 1. Create a legitimate challenge token file
    let valid_token = "valid_acme-token-ABC_123";
    let token_file = challenge_dir.join(valid_token);
    let mut f = std::fs::File::create(&token_file).unwrap();
    f.write_all(b"valid_acme-token-ABC_123.auth_signature_xyz")
        .unwrap();

    // 2. Create an oversized allocation bomb file (5000 bytes > 4096 cap)
    let bomb_token = "oversized_token_bomb";
    let bomb_file = challenge_dir.join(bomb_token);
    let mut f_bomb = std::fs::File::create(&bomb_file).unwrap();
    f_bomb.write_all(&vec![b'A'; 5000]).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let webroot = dir.path().to_path_buf();
    tokio::spawn(async move {
        let _ = propylea::run_http_redirect_listener(
            listener,
            SecurityConfig::default(),
            Some(webroot),
        )
        .await;
    });

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    // Invariant 1: Raw directory traversal attempt over wire is rejected with 400 Bad Request
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"GET /.well-known/acme-challenge/../../etc/passwd HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await
        .unwrap();
    let mut response_buf = [0u8; 512];
    let n = stream.read(&mut response_buf).await.unwrap();
    let response_str = String::from_utf8_lossy(&response_buf[..n]);
    assert!(response_str.starts_with("HTTP/1.1 400 Bad Request"));

    // Invariant 2: Non-alphanumeric / invalid characters are rejected with 400 Bad Request
    let res_invalid = client
        .get(format!(
            "http://{}/.well-known/acme-challenge/token!admin$attack",
            addr
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(res_invalid.status(), StatusCode::BAD_REQUEST);

    // Invariant 3: Oversized token path is rejected with 400 Bad Request
    let huge_token = "a".repeat(200);
    let res_huge = client
        .get(format!(
            "http://{}/.well-known/acme-challenge/{}",
            addr, huge_token
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(res_huge.status(), StatusCode::BAD_REQUEST);

    // Invariant 4: Allocation bomb file (>4096 bytes) is refused with 404
    let res_bomb = client
        .get(format!(
            "http://{}/.well-known/acme-challenge/{}",
            addr, bomb_token
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(res_bomb.status(), StatusCode::NOT_FOUND);

    // Invariant 5: Legitimate challenge token is served with 200 OK and text/plain
    let res_ok = client
        .get(format!(
            "http://{}/.well-known/acme-challenge/{}",
            addr, valid_token
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(res_ok.status(), StatusCode::OK);
    assert_eq!(
        res_ok.headers().get(hyper::header::CONTENT_TYPE).unwrap(),
        "text/plain; charset=utf-8"
    );
    let text = res_ok.text().await.unwrap();
    assert_eq!(text, "valid_acme-token-ABC_123.auth_signature_xyz");
}

#[tokio::test]
async fn test_adversarial_canary_trap_and_dynamic_bot_harvesting() {
    let defense = propylea::defense::EdgeDefense::default();
    let ip = "198.51.100.42".parse().unwrap();
    let hostile_ua = "ShadowCrawler/4.0 (Autonomous Web Scraper)";

    // 1. Initial request to normal route prior to tripping canary trap
    let normal_res = defense.evaluate_request(ip, "GET", "/products", Some(hostile_ua));
    assert!(
        normal_res.is_none(),
        "Normal route should pass prior to tripping canary"
    );

    // 2. Crawler trips invisible Canary Trap Honeylink: /_sovereign/canary_trap
    let canary_res =
        defense.evaluate_request(ip, "GET", "/_sovereign/canary_trap", Some(hostile_ua));
    assert!(canary_res.is_some(), "Canary trap must intercept probe");
    let resp = canary_res.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "Canary trap must return stealth 404"
    );

    // 3. Preemptive dynamic harvesting active: ANY request with that User-Agent from ANY IP is now stealth 404'd!
    let different_ip = "203.0.113.88".parse().unwrap();
    let blocked_res = defense.evaluate_request(different_ip, "GET", "/pricing", Some(hostile_ua));
    assert!(
        blocked_res.is_some(),
        "Harvested bot must be blocked across all IPs"
    );
    let resp2 = blocked_res.unwrap();
    assert_eq!(
        resp2.status(),
        StatusCode::NOT_FOUND,
        "Harvested bot must receive stealth 404 Not Found"
    );

    // 4. Adversarial Path Evasions against Canary Trap:
    // Scanners attempting multi-slash, dot-segments, trailing slashes, or percent-encoding
    let evasion_ip = "192.0.2.111".parse().unwrap();
    let evasion_ua = "EvadingDarkScraper/1.0";

    // Evasion A: Multi-slash "//_sovereign//canary_trap"
    let res_multi = defense.evaluate_request(
        evasion_ip,
        "GET",
        "//_sovereign//canary_trap",
        Some(evasion_ua),
    );
    assert!(
        res_multi.is_some(),
        "Multi-slash canary evasion must be trapped"
    );
    assert_eq!(res_multi.unwrap().status(), StatusCode::NOT_FOUND);

    // Evasion B: Percent-encoding "/%5fsovereign/canary_trap"
    let res_enc = defense.evaluate_request(
        evasion_ip,
        "GET",
        "/%5fsovereign/canary_trap",
        Some(evasion_ua),
    );
    assert!(
        res_enc.is_some(),
        "Percent-encoded canary evasion must be trapped"
    );
    assert_eq!(res_enc.unwrap().status(), StatusCode::NOT_FOUND);

    // Evasion C: Dot-segment "/./_sovereign/canary_trap/"
    let res_dot = defense.evaluate_request(
        evasion_ip,
        "GET",
        "/./_sovereign/canary_trap/",
        Some(evasion_ua),
    );
    assert!(
        res_dot.is_some(),
        "Dot-segment canary evasion must be trapped"
    );
    assert_eq!(res_dot.unwrap().status(), StatusCode::NOT_FOUND);

    // Evasion bot was harvested during evasion attempts and must now be stealth 404'd on root
    let evasion_blocked = defense.evaluate_request(evasion_ip, "GET", "/", Some(evasion_ua));
    assert!(evasion_blocked.is_some());
    assert_eq!(evasion_blocked.unwrap().status(), StatusCode::NOT_FOUND);

    // 5. Commercial scrapers receive explicit RFC 9309 403 Forbidden
    let ai_res = defense.evaluate_request(different_ip, "GET", "/products", Some("ClaudeBot/1.0"));
    assert!(ai_res.is_some());
    assert_eq!(
        ai_res.unwrap().status(),
        StatusCode::FORBIDDEN,
        "Commercial AI scraper must receive 403 Forbidden"
    );
}

#[tokio::test]
async fn test_adversarial_http_smuggling_and_framing_attacks() {
    let guard = propylea::FramingGuard::new(1024 * 1024); // 1 MB limit
    let client_ip = "198.51.100.88".parse().unwrap();

    // 1. Attack Vector: TE.CL Desync / Request Smuggling (RFC 9112 §6.1 / RFC 7230 §3.3.3)
    let req_te_cl = Request::builder()
        .method("POST")
        .header("Content-Length", "42")
        .header("Transfer-Encoding", "chunked")
        .body(())
        .unwrap();

    let res_te_cl = guard.validate_headers(req_te_cl.headers(), req_te_cl.method());
    assert_eq!(
        res_te_cl,
        Err(propylea::FramingViolation::ConflictingFraming)
    );

    // 2. Attack Vector: Multiple Differing Content-Length Headers
    let mut req_multi_cl = Request::builder()
        .method("POST")
        .header("Content-Length", "42")
        .body(())
        .unwrap();
    req_multi_cl
        .headers_mut()
        .append("Content-Length", "100".parse().unwrap());

    let res_multi = guard.validate_headers(req_multi_cl.headers(), req_multi_cl.method());
    assert_eq!(
        res_multi,
        Err(propylea::FramingViolation::MultipleContentLengths)
    );

    // 3. Attack Vector: Allocation Bomb / Payload Exceeding Limit
    let req_bomb = Request::builder()
        .method("POST")
        .header("Content-Length", "50000000") // 50 MB
        .body(())
        .unwrap();

    let res_bomb = guard.validate_headers(req_bomb.headers(), req_bomb.method());
    assert!(matches!(
        res_bomb,
        Err(propylea::FramingViolation::PayloadTooLarge { .. })
    ));

    // 4. Attack Vector: Untrusted Ingress Header Spoofing
    let mut req_spoof = Request::builder()
        .header("X-Forwarded-For", "127.0.0.1")
        .header("X-Real-IP", "127.0.0.1")
        .header("CF-Connecting-IP", "10.0.0.1")
        .body(())
        .unwrap();

    propylea::FramingGuard::sanitize_ingress_headers(&mut req_spoof, client_ip);

    assert_eq!(
        req_spoof
            .headers()
            .get("X-Forwarded-For")
            .unwrap()
            .to_str()
            .unwrap(),
        "198.51.100.88"
    );
    assert_eq!(
        req_spoof
            .headers()
            .get("X-Real-IP")
            .unwrap()
            .to_str()
            .unwrap(),
        "198.51.100.88"
    );
    assert!(req_spoof.headers().get("CF-Connecting-IP").is_none());
}

#[tokio::test]
async fn test_adversarial_tls_fingerprint_spoofed_browser_detection() {
    let defense = propylea::defense::EdgeDefense::default();
    let client_ip = "198.51.100.99".parse().unwrap();

    // 1. Attack Vector: Python/Go script masquerading as Chrome 128
    let python_tls_profile = propylea::ClientTlsProfile {
        has_grease: false,
        cipher_count: 17,
        offers_h2: false,
        has_sni: true,
        primary_ciphers: vec![0x1301, 0x1302, 0x1303],
    };

    let spoofed_chrome_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36";

    // EdgeDefense must detect mismatch and return stealth 404
    let spoof_res = defense.evaluate_request_with_tls(
        client_ip,
        "GET",
        "/api/v1/auth/login",
        Some(spoofed_chrome_ua),
        Some(&python_tls_profile),
    );

    assert!(
        spoof_res.is_some(),
        "TLS spoofing attack must be intercepted"
    );
    let resp = spoof_res.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "Spoofed browser must receive stealth 404"
    );

    // 2. Genuine Chrome Client: Has GREASE and h2
    let real_chrome_tls_profile = propylea::ClientTlsProfile {
        has_grease: true,
        cipher_count: 16,
        offers_h2: true,
        has_sni: true,
        primary_ciphers: vec![0x1301, 0x1302, 0x1303],
    };

    let genuine_res = defense.evaluate_request_with_tls(
        client_ip,
        "GET",
        "/products",
        Some(spoofed_chrome_ua),
        Some(&real_chrome_tls_profile),
    );

    assert!(
        genuine_res.is_none(),
        "Genuine Chrome client with GREASE must pass edge defense cleanly"
    );

    // 3. Search Engine Spider (Googlebot): Allowed even without GREASE
    let googlebot_ua = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)";
    let googlebot_res = defense.evaluate_request_with_tls(
        client_ip,
        "GET",
        "/terms",
        Some(googlebot_ua),
        Some(&python_tls_profile),
    );

    assert!(
        googlebot_res.is_none(),
        "Googlebot must not be falsely flagged as a spoofing attack"
    );
}
