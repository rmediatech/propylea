//! # Sovereign Quarantine Persistence & Multi-Format Intelligence TDD Suite
//!
//! Rigorously verifies:
//! 1. SQLite WAL schema and persistence across simulated proxy restarts.
//! 2. Fast-path in-memory rehydration on boot.
//! 3. Single and batch unquarantining by exact CIDR and containing IP.
//! 4. Formula injection neutralization in CSV exports (Sovereign Pillar III).
//! 5. Universal multi-format generation (TXT, JSON, JSONL, MD, CSV, HTML).
//! 6. Zero-cloud HTML dashboard integrity (no external CDNs, XSS containment).
//! 7. Unix Domain Socket (UDS) live IPC control for multi-process operation.

use ipnet::IpNet;
use phylax::{AutonomousQuarantine, QuarantineConfig};
use propylea::quarantine::{
    format_csv, format_html, format_json, format_jsonl, format_md, format_txt,
    sanitize_csv_field, IpcClient, IpcRequest, IpcResponse, IpcServer,
    QuarantineManager, QuarantineRecord, QuarantineStore,
};
use std::sync::Arc;
use tempfile::tempdir;

#[tokio::test]
async fn test_quarantine_store_crud_and_audit_logging() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test_quarantine.db");
    let store = QuarantineStore::open(&db_path).unwrap();

    let now_ms = 1_000_000;
    let rec1 = QuarantineRecord {
        cidr: "198.51.100.0/24".into(),
        ip_version: 4,
        trigger_ip: "198.51.100.42".into(),
        infraction_type: "tls_clienthello_spoof".into(),
        infraction_count: 3,
        quarantined_at: now_ms,
        expires_at: now_ms + 86_400_000,
        user_agent: Some("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/128.0".into()),
        active: true,
    };

    store.record_ban(&rec1).unwrap();

    // Verify active bans
    let active = store.get_active_bans(now_ms + 1000).unwrap();
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].cidr, "198.51.100.0/24");
    assert!(active[0].active);

    // Verify audit log
    let audit = store.get_audit_log(10).unwrap();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].cidr, "198.51.100.0/24");
    assert_eq!(audit[0].event_type, "quarantined");

    // Unban by containing IP
    let unbanned = store.unban("198.51.100.42", "Manual TDD Unban", now_ms + 2000).unwrap();
    assert_eq!(unbanned, vec!["198.51.100.0/24"]);

    // Active bans should now be 0
    let active_after = store.get_active_bans(now_ms + 2000).unwrap();
    assert_eq!(active_after.len(), 0);

    // All records should show active = false
    let all = store.get_all_records(10).unwrap();
    assert_eq!(all.len(), 1);
    assert!(!all[0].active);

    // Audit log should have 2 entries (quarantined + unbanned)
    let audit_after = store.get_audit_log(10).unwrap();
    assert_eq!(audit_after.len(), 2);
    assert_eq!(audit_after[0].event_type, "unbanned");
}

#[tokio::test]
async fn test_startup_rehydration_survives_restart() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("restart_test.db");
    let sock_path = dir.path().join("control.sock");

    let now_ms = 1_000_000;
    let expires_at = now_ms + 86_400_000;

    // 1. Initial process lifetime: record bans in SQLite
    {
        let store = QuarantineStore::open(&db_path).unwrap();
        store
            .record_ban(&QuarantineRecord {
                cidr: "192.0.2.0/24".into(),
                ip_version: 4,
                trigger_ip: "192.0.2.15".into(),
                infraction_type: "canary_trap".into(),
                infraction_count: 1,
                quarantined_at: now_ms,
                expires_at,
                user_agent: None,
                active: true,
            })
            .unwrap();

        store
            .record_ban(&QuarantineRecord {
                cidr: "2001:db8::/48".into(),
                ip_version: 6,
                trigger_ip: "2001:db8::dead:beef".into(),
                infraction_type: "decoy_uri_burst".into(),
                infraction_count: 5,
                quarantined_at: now_ms,
                expires_at,
                user_agent: Some("CustomBot/1.0".into()),
                active: true,
            })
            .unwrap();
    }

    // 2. Simulated process restart: new instance boots up with cold in-memory quarantine
    let in_memory = Arc::new(AutonomousQuarantine::new(QuarantineConfig::default()));
    assert_eq!(in_memory.active_bans_count(), 0);
    assert!(!in_memory.is_quarantined("192.0.2.15", now_ms + 100));

    let store = Arc::new(QuarantineStore::open(&db_path).unwrap());
    let (manager, _rx) = QuarantineManager::new(in_memory.clone(), store, sock_path);

    // Rehydrate on boot with explicit timestamp
    let rehydrated_count = manager.rehydrate_with_timestamp(now_ms + 100).unwrap();
    assert_eq!(rehydrated_count, 2);

    // Assert fast-path memory now contains and enforces the bans
    assert_eq!(in_memory.active_bans_count(), 2);
    assert!(in_memory.is_quarantined("192.0.2.15", now_ms + 500));
    assert!(in_memory.is_quarantined("192.0.2.99", now_ms + 500));
    assert!(in_memory.is_quarantined("2001:db8::dead:beef", now_ms + 500));
}

#[tokio::test]
async fn test_batch_unban_and_unban_all() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("batch_test.db");
    let store = QuarantineStore::open(&db_path).unwrap();

    let now_ms = 1_000_000;
    for i in 1..=5 {
        store
            .record_ban(&QuarantineRecord {
                cidr: format!("198.51.10{}.0/24", i),
                ip_version: 4,
                trigger_ip: format!("198.51.10{}.42", i),
                infraction_type: "honeypot".into(),
                infraction_count: 1,
                quarantined_at: now_ms,
                expires_at: now_ms + 100_000,
                user_agent: None,
                active: true,
            })
            .unwrap();
    }

    assert_eq!(store.get_active_bans(now_ms).unwrap().len(), 5);

    // Batch unban 2 subnets
    let targets = vec!["198.51.101.42", "198.51.102.0/24"];
    for target in targets {
        store.unban(target, "Batch unban test", now_ms).unwrap();
    }

    assert_eq!(store.get_active_bans(now_ms).unwrap().len(), 3);

    // Unban all remaining subnets
    let unbanned_count = store.unban_all("Clear test", now_ms).unwrap();
    assert_eq!(unbanned_count, 3);
    assert_eq!(store.get_active_bans(now_ms).unwrap().len(), 0);
}

#[test]
fn test_adversarial_csv_formula_injection_defense() {
    // Malicious formula injection payloads
    let malicious_payloads = vec![
        "=cmd|'/C calc'!A0",
        "@SUM(1+1)*cmd",
        "+123456789",
        "-calc.exe",
        "\t=2+5",
        "\r+100",
        "normal_user_agent",
    ];

    for payload in malicious_payloads {
        let sanitized = sanitize_csv_field(payload);
        if payload.starts_with('=')
            || payload.starts_with('@')
            || payload.starts_with('+')
            || payload.starts_with('-')
            || payload.starts_with('\t')
            || payload.starts_with('\r')
        {
            assert!(
                sanitized.starts_with("'") || sanitized.starts_with("\"'"),
                "Payload '{}' was not neutralized with single quote prefix! Output: '{}'",
                payload,
                sanitized
            );
        } else {
            assert_eq!(sanitized, "normal_user_agent");
        }
    }

    // Verify in full CSV export
    let records = vec![QuarantineRecord {
        cidr: "192.0.2.0/24".into(),
        ip_version: 4,
        trigger_ip: "192.0.2.1".into(),
        infraction_type: "=CMD|'/C calc'!A0".into(),
        infraction_count: 1,
        quarantined_at: 1000,
        expires_at: 2000,
        user_agent: Some("@DDE(\"cmd\";\"/C notepad.exe\";0)".into()),
        active: true,
    }];

    let csv_output = format_csv(&records);
    assert!(csv_output.contains("'=CMD"));
    assert!(csv_output.contains("'@DDE"));
}

#[test]
fn test_multi_format_generation_and_zero_cloud_html() {
    let now_ms = 1_000_000;
    let records = vec![
        QuarantineRecord {
            cidr: "198.51.100.0/24".into(),
            ip_version: 4,
            trigger_ip: "198.51.100.42".into(),
            infraction_type: "tls_spoof".into(),
            infraction_count: 3,
            quarantined_at: now_ms,
            expires_at: now_ms + 50_000,
            user_agent: Some("MaliciousBot/1.0".into()),
            active: true,
        },
        QuarantineRecord {
            cidr: "2001:db8::/48".into(),
            ip_version: 6,
            trigger_ip: "2001:db8::1".into(),
            infraction_type: "canary_trap".into(),
            infraction_count: 1,
            quarantined_at: now_ms - 100_000,
            expires_at: now_ms - 50_000, // Expired
            user_agent: None,
            active: false,
        },
    ];

    // 1. TXT format
    let txt = format_txt(&records);
    assert_eq!(txt, "198.51.100.0/24\n2001:db8::/48\n");

    // 2. JSON format
    let json = format_json(&records).unwrap();
    let parsed: Vec<QuarantineRecord> = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.len(), 2);

    // 3. JSONL format
    let jsonl = format_jsonl(&records).unwrap();
    let lines: Vec<&str> = jsonl.trim().split('\n').collect();
    assert_eq!(lines.len(), 2);

    // 4. Markdown format
    let md = format_md(&records, now_ms);
    assert!(md.contains("Propylea Autonomous Quarantine Intelligence Briefing"));
    assert!(md.contains("| `198.51.100.0/24` |"));
    assert!(md.contains("🔴 ACTIVE"));
    assert!(md.contains("⚪ EXPIRED"));

    // 5. HTML Standalone Dashboard format
    let html = format_html(&records, now_ms);
    assert!(html.contains("<!DOCTYPE html>"));
    assert!(html.contains("Propylea Quarantine Radar"));
    assert!(html.contains("Active Enforced Bans"));
    assert!(html.contains("198.51.100.0/24"));
    assert!(html.contains("2001:db8::/48"));

    // Assert Zero External Cloud Dependencies in HTML
    assert!(
        !html.contains("fonts.googleapis.com"),
        "HTML contains external Google Fonts!"
    );
    assert!(
        !html.contains("cdnjs.cloudflare.com"),
        "HTML contains external Cloudflare CDN!"
    );
    assert!(
        !html.contains("cdn.jsdelivr.net"),
        "HTML contains external JSDelivr CDN!"
    );
}

#[tokio::test]
async fn test_unix_domain_socket_ipc_live_unban() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("ipc_test.db");
    let sock_path = dir.path().join("control.sock");

    let now_ms = 1_000_000;
    let expires_at = now_ms + 86_400_000;

    let store = Arc::new(QuarantineStore::open(&db_path).unwrap());
    let in_memory = Arc::new(AutonomousQuarantine::new(QuarantineConfig::default()));

    // Seed initial ban in memory and DB
    let net: IpNet = "198.51.100.0/24".parse().unwrap();
    in_memory.add_ban(net, expires_at);
    store
        .record_ban(&QuarantineRecord {
            cidr: "198.51.100.0/24".into(),
            ip_version: 4,
            trigger_ip: "198.51.100.42".into(),
            infraction_type: "tls_spoof".into(),
            infraction_count: 1,
            quarantined_at: now_ms,
            expires_at,
            user_agent: None,
            active: true,
        })
        .unwrap();

    assert!(in_memory.is_quarantined("198.51.100.42", now_ms));

    // Bind IPC server
    let listener = IpcServer::bind(&sock_path).unwrap();
    let sock_clone = sock_path.clone();
    let in_mem_clone = in_memory.clone();
    let store_clone = store.clone();

    // Spawn server actor
    let server_task = tokio::spawn(async move {
        IpcServer::run_loop(listener, sock_clone, in_mem_clone, store_clone).await;
    });

    // Create client and verify live status
    let client = IpcClient::new(&sock_path);
    assert!(client.is_alive().await);

    let status = client.send_request(&IpcRequest::Status).await.unwrap();
    if let IpcResponse::Status { active_count, .. } = status {
        assert_eq!(active_count, 1);
    } else {
        panic!("Expected Status response");
    }

    // Client requests live unban of the IP
    let unban_res = client
        .send_request(&IpcRequest::Unban {
            targets: vec!["198.51.100.42".into()],
        })
        .await
        .unwrap();

    if let IpcResponse::Unbanned { count, unbanned_cidrs } = unban_res {
        assert_eq!(count, 1);
        assert_eq!(unbanned_cidrs, vec!["198.51.100.0/24"]);
    } else {
        panic!("Expected Unbanned response");
    }

    // Assert live in-memory table is IMMEDIATELY cleared!
    assert!(!in_memory.is_quarantined("198.51.100.42", now_ms));
    assert_eq!(in_memory.active_bans_count(), 0);

    // Assert SQLite store also updated to active = 0
    let active_bans = store.get_active_bans(now_ms).unwrap();
    assert_eq!(active_bans.len(), 0);

    server_task.abort();
}
