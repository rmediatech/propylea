//! # Adversarial TDD Suite for Propylea v0.5.0: Fleet Deception Mesh Sync & Zero-Downtime Hot TLS
//!
//! Verifies:
//! 1. Cross-Node Fleet Deception & Quarantine Mesh Sync over TCP (`MeshSyncEngine`), asserting
//!    bidirectional CIDR quarantine + `XdpWireShield` + promoted zero-day `DecoyUriSentinel` sync.
//! 2. Adversarial HMAC-SHA256 forgery rejection, replay window enforcement (`+-60s`), and
//!    trusted/private CIDR protection against mesh self-lockout.
//! 3. Zero-downtime atomic multi-domain SNI TLS hot-reloading (`SovereignSniResolver::reload_from_routes`),
//!    including fail-safe preservation of active certificates when a disk file is corrupted.

use phylax::xdp_shield::XdpAction;
use propylea::config::{RouteConfig, SecurityConfig};
use propylea::defense::EdgeDefense;
use propylea::mesh_sync::{MeshSyncEngine, MeshSyncError};
use propylea::tls::build_sni_tls_acceptor_with_resolver;
use std::io::Write;
use std::net::IpAddr;
use std::sync::Arc;
use tempfile::NamedTempFile;
use tokio::net::TcpListener;

#[tokio::test]
async fn test_fleet_deception_mesh_sync_bidirectional_tcp_and_xdp_shield() {
    let sec_node1 = SecurityConfig {
        enable_defense: true,
        trusted_cidrs: vec!["198.74.57.89/32".to_string()],
        ..Default::default()
    };
    let sec_node2 = SecurityConfig {
        enable_defense: true,
        trusted_cidrs: vec!["173.255.227.159/32".to_string()],
        ..Default::default()
    };

    let defense_node1 = Arc::new(EdgeDefense::new(&sec_node1));
    let defense_node2 = Arc::new(EdgeDefense::new(&sec_node2));

    let now_ms = 10_000_000;

    // 1. Node 1 traps an attacker 198.51.100.44 hitting /.env 3 times -> quarantined on Node 1
    for _ in 0..3 {
        let res = defense_node1.evaluate_request(
            "198.51.100.44".parse().unwrap(),
            "GET",
            "/.env",
            Some("Scanner/1.0"),
        );
        assert!(res.is_some());
    }
    assert!(defense_node1
        .pipeline()
        .quarantine()
        .is_quarantined("198.51.100.99", now_ms + 100));

    // 2. Node 1 promotes a zero-day path `/api/v2/debug_shell` via 3 distinct subnets
    for ip_str in ["192.0.2.10", "203.0.113.20", "198.18.0.30"] {
        let ip: IpAddr = ip_str.parse().unwrap();
        defense_node1
            .pipeline()
            .record_anomalous_uri("/api/v2/debug_shell", ip, now_ms);
    }
    assert!(defense_node1
        .pipeline()
        .decoy_uri()
        .contains_trap("/api/v2/debug_shell"));

    // Node 2 has not seen either yet
    assert!(!defense_node2
        .pipeline()
        .quarantine()
        .is_quarantined("198.51.100.99", now_ms + 100));
    assert!(!defense_node2
        .pipeline()
        .decoy_uri()
        .contains_trap("/api/v2/debug_shell"));

    // 3. Synchronize Node 1 <-> Node 2 over TCP via MeshSyncEngine
    let secret = b"sovereign-fleet-mesh-hmac-secret-2026";
    let mesh_node1 = MeshSyncEngine::new("node-1-lin", secret.as_slice(), defense_node1.clone());
    let mesh_node2 = MeshSyncEngine::new("node-2-edge", secret.as_slice(), defense_node2.clone());

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let peer_addr = listener.local_addr().unwrap();

    let server_task = tokio::spawn({
        let mesh_node2 = mesh_node2.clone();
        async move { mesh_node2.serve_tcp_once(&listener, now_ms).await.unwrap() }
    });

    let _client_report = mesh_node1
        .sync_with_tcp_peer(peer_addr, now_ms)
        .await
        .unwrap();
    let node2_report = server_task.await.unwrap();

    assert_eq!(node2_report.bans_ingested, 1);
    assert_eq!(node2_report.decoys_ingested, 1);

    // 4. Verify Node 2 now blocks 198.51.100.0/24 in both Quarantine AND sub-kernel XdpWireShield,
    //    and traps `/api/v2/debug_shell` in DecoyUriSentinel!
    assert!(defense_node2
        .pipeline()
        .quarantine()
        .is_quarantined("198.51.100.200", now_ms + 100));
    assert_eq!(
        defense_node2
            .pipeline()
            .xdp_shield()
            .evaluate_ip("198.51.100.200".parse().unwrap(), 64, now_ms + 100)
            .action,
        XdpAction::Drop
    );
    assert!(defense_node2
        .pipeline()
        .decoy_uri()
        .contains_trap("/api/v2/debug_shell"));
}

#[test]
fn test_mesh_sync_adversarial_hmac_forgery_replay_and_trusted_cidr_immunity() {
    let sec = SecurityConfig {
        enable_defense: true,
        trusted_cidrs: vec!["173.255.227.159/32".to_string()],
        ..Default::default()
    };
    let defense = Arc::new(EdgeDefense::new(&sec));
    let secret = b"sovereign-fleet-mesh-hmac-secret-2026";
    let engine = MeshSyncEngine::new("node-1", secret.as_slice(), defense.clone());
    let now_ms = 20_000_000;

    // Manually add a legitimate public ban + a private LAN ban + a trusted peer ban
    defense
        .pipeline()
        .quarantine()
        .add_ban("198.51.100.0/24".parse().unwrap(), now_ms + 300_000);
    defense
        .pipeline()
        .quarantine()
        .add_ban("192.168.1.50/32".parse().unwrap(), now_ms + 300_000);
    defense
        .pipeline()
        .quarantine()
        .add_ban("173.255.227.159/32".parse().unwrap(), now_ms + 300_000);

    let env = engine.export_envelope(now_ms).unwrap();

    // 1. Tampered HMAC signature must fail with SignatureInvalid
    let mut forged = env.clone();
    forged.payload.node_id = "rogue-attacker".to_string();
    assert!(matches!(
        engine.ingest_envelope(&forged, now_ms),
        Err(MeshSyncError::SignatureInvalid)
    ));

    // 2. Stale replay envelope (> 60s old) must fail with ReplayWindowExceeded
    assert!(matches!(
        engine.ingest_envelope(&env, now_ms + 120_000),
        Err(MeshSyncError::ReplayWindowExceeded { .. })
    ));

    // 3. Valid ingestion into target node must skip RFC 1918 private and trusted_cidrs!
    let target_defense = Arc::new(EdgeDefense::new(&sec));
    let target_engine = MeshSyncEngine::new("node-2", secret.as_slice(), target_defense.clone());
    let report = target_engine.ingest_envelope(&env, now_ms + 500).unwrap();
    assert_eq!(report.bans_ingested, 1); // Only 198.51.100.0/24 ingested!
    assert_eq!(report.bans_skipped_protected, 2); // 192.168.1.50 & 173.255.227.159 protected!
    assert!(!target_defense
        .pipeline()
        .quarantine()
        .is_quarantined("173.255.227.159", now_ms + 1000));
}

#[test]
fn test_zero_downtime_hot_reloadable_multi_domain_sni_tls_and_failsafe() {
    let cert1 = rcgen::generate_simple_self_signed(vec!["rmediatech.com".to_string()]).unwrap();
    let mut cert_file = NamedTempFile::new().unwrap();
    cert_file.write_all(cert1.cert.pem().as_bytes()).unwrap();
    let mut key_file = NamedTempFile::new().unwrap();
    key_file
        .write_all(cert1.key_pair.serialize_pem().as_bytes())
        .unwrap();

    let routes = vec![RouteConfig::single(
        vec!["rmediatech.com".into()],
        "127.0.0.1:8080".parse().unwrap(),
        cert_file.path().to_path_buf(),
        key_file.path().to_path_buf(),
        true,
    )];

    let (_acceptor, resolver) = build_sni_tls_acceptor_with_resolver(&routes).unwrap();
    assert_eq!(resolver.reload_generation(), 1);

    // 1. Renew certificate on disk and hot-reload atomically
    let cert2 = rcgen::generate_simple_self_signed(vec![
        "rmediatech.com".to_string(),
        "vox.rmediatech.com".to_string(),
    ])
    .unwrap();
    std::fs::write(cert_file.path(), cert2.cert.pem()).unwrap();
    std::fs::write(key_file.path(), cert2.key_pair.serialize_pem()).unwrap();

    let gen = resolver.reload_from_routes(&routes).unwrap();
    assert_eq!(gen, 2);
    assert_eq!(resolver.reload_generation(), 2);

    // 2. Corrupt certificate file on disk -> reload_from_routes must fail-safe without bumping generation
    std::fs::write(cert_file.path(), b"---CORRUPTED PEM DATA---").unwrap();
    assert!(resolver.reload_from_routes(&routes).is_err());
    assert_eq!(resolver.reload_generation(), 2);
}
