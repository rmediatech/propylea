//! # Adversarial & Digital Twin Test Suite: `splice(2)`, Keep-Alive Pool & Zero-Alloc SNI
//!
//! Validates Propylea v0.6.0's three core architectural upgrades:
//! 1. Zero-allocation RFC 6066 `ClientHello` SNI wire parser & adversarial payload rejection.
//! 2. Linux `splice(2)` Ring-0 kernel pipe bidirectional socket splicing & L4 TLS passthrough.
//! 3. Keep-Alive upstream connection pooling with kernel `MSG_PEEK | MSG_DONTWAIT` liveness &
//!    HTTP response-smuggling eviction.

use bytes::Bytes;
use http_body_util::Full;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use propylea::config::{MaintenanceSettings, PropyleaConfig, RouteConfig, SecurityConfig, ServerConfig};
use propylea::{
    build_sni_tls_acceptor, extract_sni_hostname_zero_alloc, splice_bidirectional,
    ClientTlsProfile, MaintenanceConfig, ResourceGovernor, TelemetryRingBuffer,
    UpstreamConnectionPool,
};
use std::io::Write;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tempfile::NamedTempFile;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Craft a valid raw TLS 1.2/1.3 ClientHello record containing an RFC 6066 SNI extension.
fn build_client_hello_with_sni(sni_bytes: &[u8]) -> Vec<u8> {
    let mut ext = Vec::new();
    // Extension type 0x0000 (server_name)
    ext.extend_from_slice(&[0x00, 0x00]);
    let sni_list_len = (3 + sni_bytes.len()) as u16;
    let ext_len = sni_list_len + 2;
    ext.extend_from_slice(&ext_len.to_be_bytes());
    ext.extend_from_slice(&sni_list_len.to_be_bytes());
    ext.push(0x00); // host_name type
    ext.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
    ext.extend_from_slice(sni_bytes);

    // ALPN extension (0x0010) advertising "h2"
    let alpn_payload = [0x00, 0x03, 0x02, b'h', b'2'];
    ext.extend_from_slice(&[0x00, 0x10]);
    ext.extend_from_slice(&(alpn_payload.len() as u16).to_be_bytes());
    ext.extend_from_slice(&alpn_payload);

    let mut body = Vec::new();
    // Client version TLS 1.2 (0x0303)
    body.extend_from_slice(&[0x03, 0x03]);
    // 32-byte random
    body.extend_from_slice(&[0xAA; 32]);
    // Session ID length = 0
    body.push(0x00);
    // Cipher suites: GREASE (0x1a1a) + TLS_AES_128_GCM_SHA256 (0x1301)
    body.extend_from_slice(&[0x00, 0x04, 0x1a, 0x1a, 0x13, 0x01]);
    // Compression methods: 1 byte (null)
    body.extend_from_slice(&[0x01, 0x00]);
    // Extensions length + extensions
    body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext);

    let mut record = Vec::new();
    record.push(0x16); // Handshake record
    record.extend_from_slice(&[0x03, 0x01]);
    let handshake_len = body.len() + 4;
    record.extend_from_slice(&(handshake_len as u16).to_be_bytes());
    record.push(0x01); // ClientHello
    let blen = body.len() as u32;
    record.extend_from_slice(&[(blen >> 16) as u8, (blen >> 8) as u8, blen as u8]);
    record.extend_from_slice(&body);
    record
}

#[test]
fn test_zero_alloc_sni_extractor_and_adversarial_wire_frames() {
    let valid_hello = build_client_hello_with_sni(b"vox.rmediatech.com");
    assert_eq!(
        extract_sni_hostname_zero_alloc(&valid_hello),
        Some("vox.rmediatech.com")
    );

    let profile = ClientTlsProfile::parse_client_hello(&valid_hello).unwrap();
    assert!(profile.has_grease);
    assert!(profile.offers_h2);
    assert!(profile.has_sni);

    // Adversarial Vector 1: Path traversal inside SNI
    let traversal_hello = build_client_hello_with_sni(b"../../etc/shadow");
    assert_eq!(extract_sni_hostname_zero_alloc(&traversal_hello), None);

    // Adversarial Vector 2: Null byte & ANSI escape injection in SNI
    let null_hello = build_client_hello_with_sni(b"evil\x00.rmediatech.com");
    assert_eq!(extract_sni_hostname_zero_alloc(&null_hello), None);
    let ansi_hello = build_client_hello_with_sni(b"evil\x1b[31m.com");
    assert_eq!(extract_sni_hostname_zero_alloc(&ansi_hello), None);

    // Adversarial Vector 3: Malformed DNS syntax (empty labels, leading/trailing dots/hyphens)
    assert_eq!(
        extract_sni_hostname_zero_alloc(&build_client_hello_with_sni(b".leading-dot.com")),
        None
    );
    assert_eq!(
        extract_sni_hostname_zero_alloc(&build_client_hello_with_sni(b"trailing-dot.com.")),
        None
    );
    assert_eq!(
        extract_sni_hostname_zero_alloc(&build_client_hello_with_sni(b"double..dot.com")),
        None
    );
    assert_eq!(
        extract_sni_hostname_zero_alloc(&build_client_hello_with_sni(&[b'a'; 64])),
        None
    );

    // Adversarial Vector 4: Oversized length bomb / truncated packet
    let mut corrupted = valid_hello.clone();
    let len = corrupted.len();
    // Corrupt the SNI name length field near the end to 0xFFFF
    corrupted[len - 27] = 0xFF;
    corrupted[len - 26] = 0xFF;
    assert_eq!(extract_sni_hostname_zero_alloc(&corrupted), None);
}

#[tokio::test]
async fn test_ring0_splice_bidirectional_high_volume_integrity() {
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();

    // Upstream server reads all bytes until EOF, XORs each byte with 0x5A, and writes back
    tokio::spawn(async move {
        if let Ok((mut stream, _)) = upstream_listener.accept().await {
            let mut buf = Vec::new();
            stream.read_to_end(&mut buf).await.unwrap();
            for b in &mut buf {
                *b ^= 0x5A;
            }
            stream.write_all(&buf).await.unwrap();
            let _ = stream.shutdown().await;
        }
    });

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    tokio::spawn(async move {
        if let Ok((client_sock, _)) = proxy_listener.accept().await {
            let upstream_sock = TcpStream::connect(upstream_addr).await.unwrap();
            let (c2u, u2c) = splice_bidirectional(&client_sock, &upstream_sock)
                .await
                .unwrap();
            assert_eq!(c2u, 256 * 1024);
            assert_eq!(u2c, 256 * 1024);
        }
    });

    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    let payload: Vec<u8> = (0..(256 * 1024)).map(|i| (i % 251) as u8).collect();
    let expected: Vec<u8> = payload.iter().map(|b| b ^ 0x5A).collect();

    client.write_all(&payload).await.unwrap();
    client.shutdown().await.unwrap();

    let mut received = Vec::new();
    client.read_to_end(&mut received).await.unwrap();
    assert_eq!(received.len(), expected.len());
    assert_eq!(received, expected);
}

#[tokio::test]
async fn test_keepalive_pool_reuse_and_kernel_peek_desync_eviction() {
    let accept_count = Arc::new(AtomicUsize::new(0));
    let accept_count_clone = Arc::clone(&accept_count);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            accept_count_clone.fetch_add(1, Ordering::SeqCst);
            let io = TokioIo::new(stream);
            let service = service_fn(|_req: Request<hyper::body::Incoming>| async move {
                Ok::<_, hyper::Error>(Response::new(Full::new(Bytes::from("POOLED_OK"))))
            });
            tokio::spawn(async move {
                let _ = hyper::server::conn::http1::Builder::new()
                    .keep_alive(true)
                    .serve_connection(io, service)
                    .await;
            });
        }
    });

    let pool = UpstreamConnectionPool::new(16, Duration::from_secs(30));

    // Request 1: Cold miss -> dials 1st TCP connection
    {
        let lease = pool.acquire(addr).await.unwrap();
        assert!(!lease.reused);
        // Release the idle ready sender back to pool
        pool.release(addr, lease);
    }

    // Request 2: Warm hit -> reuses existing TCP connection without calling accept() again!
    {
        let lease2 = pool.acquire(addr).await.unwrap();
        assert!(lease2.reused);
        assert_eq!(pool.hits(), 1);
        assert_eq!(pool.misses(), 1);
        assert_eq!(accept_count.load(Ordering::SeqCst), 1);
    }

    // Part B: Adversarial HTTP response smuggling / unsolicited bytes on idle socket
    let poison_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let poison_addr = poison_listener.local_addr().unwrap();
    let (tx_poison, rx_poison) = tokio::sync::oneshot::channel();
    let (tx_done, rx_done) = tokio::sync::oneshot::channel();

    tokio::spawn(async move {
        if let Ok((mut stream, _)) = poison_listener.accept().await {
            let _ = rx_poison.await;
            // Upstream injects unsolicited smuggled HTTP response onto idle keep-alive socket!
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nPWNED").await;
            let _ = tx_done.send(());
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        // Accept the clean replacement connection
        let _ = poison_listener.accept().await;
    });

    let lease_clean = pool.acquire(poison_addr).await.unwrap();
    pool.release(poison_addr, lease_clean);

    // Trigger upstream response-queue poisoning while connection is idle in pool
    let _ = tx_poison.send(());
    let _ = rx_done.await;
    tokio::time::sleep(Duration::from_millis(10)).await;

    // Next acquire must detect unread smuggled bytes via MSG_PEEK, evict the poisoned socket, and dial a fresh one!
    let replacement = pool.acquire(poison_addr).await.unwrap();
    assert!(!replacement.reused);
    assert!(pool.stale_evictions() >= 1);
}

#[tokio::test]
async fn test_l4_sni_tls_passthrough_end_to_end() {
    // 1. Generate TLS cert for upstream server that terminates its own TLS ("vault.example.com")
    let cert = rcgen::generate_simple_self_signed(vec!["vault.example.com".to_string()]).unwrap();
    let mut cert_file = NamedTempFile::new().unwrap();
    cert_file.write_all(cert.cert.pem().as_bytes()).unwrap();
    let mut key_file = NamedTempFile::new().unwrap();
    key_file
        .write_all(cert.key_pair.serialize_pem().as_bytes())
        .unwrap();

    // Also generate TLS cert for Propylea's L7 route ("edge.example.com")
    let edge_cert =
        rcgen::generate_simple_self_signed(vec!["edge.example.com".to_string()]).unwrap();
    let mut edge_cert_file = NamedTempFile::new().unwrap();
    edge_cert_file
        .write_all(edge_cert.cert.pem().as_bytes())
        .unwrap();
    let mut edge_key_file = NamedTempFile::new().unwrap();
    edge_key_file
        .write_all(edge_cert.key_pair.serialize_pem().as_bytes())
        .unwrap();

    // 2. Spawn the upstream TLS server for vault.example.com
    let vault_routes = vec![RouteConfig::single(
        vec!["vault.example.com".into()],
        "127.0.0.1:9".parse().unwrap(),
        cert_file.path().to_path_buf(),
        key_file.path().to_path_buf(),
        false,
    )];
    let vault_acceptor = build_sni_tls_acceptor(&vault_routes).unwrap();
    let vault_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let vault_addr = vault_listener.local_addr().unwrap();

    tokio::spawn(async move {
        while let Ok((raw, _)) = vault_listener.accept().await {
            let acc = vault_acceptor.clone();
            tokio::spawn(async move {
                if let Ok(tls_stream) = acc.accept(raw).await {
                    let io = TokioIo::new(tls_stream);
                    let service = service_fn(|_req: Request<hyper::body::Incoming>| async move {
                        let mut res =
                            Response::new(Full::new(Bytes::from("END_TO_END_PASSTHROUGH_OK")));
                        *res.status_mut() = StatusCode::OK;
                        Ok::<_, hyper::Error>(res)
                    });
                    let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                        .serve_connection(io, service)
                        .await;
                }
            });
        }
    });

    // 3. Configure Propylea with an L7 route + an L4 Zero-Copy Passthrough route
    let routes = vec![
        RouteConfig::single(
            vec!["edge.example.com".into()],
            vault_addr,
            edge_cert_file.path().to_path_buf(),
            edge_key_file.path().to_path_buf(),
            false,
        ),
        RouteConfig::passthrough(vec!["vault.example.com".into()], vault_addr),
    ];

    let config = PropyleaConfig {
        server: ServerConfig::default(),
        security: SecurityConfig {
            enable_defense: false,
            persist_quarantine: false,
            ..Default::default()
        },
        maintenance: MaintenanceSettings::default(),
        routes: routes.clone(),
    };

    let tls_acceptor = build_sni_tls_acceptor(&routes).unwrap();
    let governor = ResourceGovernor::new(MaintenanceConfig::default());
    let telemetry = TelemetryRingBuffer::new(100);

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let tel_clone = telemetry.clone();

    tokio::spawn(async move {
        let _ = propylea::run_https_proxy_listener(
            proxy_listener,
            tls_acceptor,
            config,
            governor,
            tel_clone,
        )
        .await;
    });

    // 4. Connect to proxy_addr using SNI "vault.example.com"
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .resolve("vault.example.com", proxy_addr)
        .build()
        .unwrap();

    let res = client
        .get(format!("https://vault.example.com:{}/secret", proxy_addr.port()))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    let text = res.text().await.unwrap();
    assert_eq!(text, "END_TO_END_PASSTHROUGH_OK");
}
