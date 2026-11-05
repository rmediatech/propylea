//! # Adversarial TDD Suite: Propylea Synthetic Mirage Deception & Surface Exposure Auditor
//!
//! Verifies:
//! 1. `EdgeDefense` with `enable_mirage: true` serves deterministic `200 OK` poison payloads
//!    with attacker-bound HMAC canaries across `.env`, `.git/config`, `wp-login.php`, `dump.sql`,
//!    `id_rsa`, and `/_sovereign/canary_trap` while still enforcing autonomous CIDR quarantine.
//! 2. `audit_config_surface` evaluates perimeter posture (`A+ (Sovereign Mirage Fortress)` when
//!    Mirage + HSTS are active, `A (Hardened Perimeter)` when Stealth 404 is active).

use http_body_util::BodyExt;
use hyper::StatusCode;
use propylea::config::{PropyleaConfig, SecurityConfig};
use propylea::defense::EdgeDefense;
use propylea::surface_audit::audit_config_surface;
use std::net::{IpAddr, Ipv4Addr};

#[tokio::test]
async fn test_propylea_mirage_mode_poisons_scanners_and_enforces_quarantine() {
    let config = SecurityConfig {
        enable_defense: true,
        enable_mirage: true,
        ..Default::default()
    };
    let defense = EdgeDefense::new(&config);
    let attacker_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 88));
    let ua = Some("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36");

    // 1. First probe: /.env -> 200 OK Synthetic Mirage poison payload
    let res_env = defense
        .evaluate_request(attacker_ip, "GET", "/.env", ua)
        .expect("Should trap /.env");
    assert_eq!(res_env.status(), StatusCode::OK);
    assert!(res_env.headers().contains_key("x-mirage-canary"));
    let body_bytes = res_env.into_body().collect().await.unwrap().to_bytes();
    let body_str = String::from_utf8_lossy(&body_bytes);
    assert!(body_str.contains("AWS_ACCESS_KEY_ID=AKIA"));
    assert!(body_str.contains("STRIPE_SECRET_KEY=sk_live_"));

    // 2. Second probe from distinct IP: /dump.sql -> 200 OK SQL dump mirage
    let ip2 = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 44));
    let res_sql = defense
        .evaluate_request(ip2, "GET", "/dump.sql", ua)
        .expect("Should trap /dump.sql");
    assert_eq!(res_sql.status(), StatusCode::OK);
    let sql_bytes = res_sql.into_body().collect().await.unwrap().to_bytes();
    let sql_str = String::from_utf8_lossy(&sql_bytes);
    assert!(sql_str.contains("CREATE TABLE `operator_accounts`"));

    // 3. Canary trap: /_sovereign/canary_trap -> 200 OK Mirage JSON + immediate quarantine
    let ip3 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 77));
    let res_canary = defense
        .evaluate_request(ip3, "GET", "/_sovereign/canary_trap", ua)
        .expect("Should trap canary");
    assert_eq!(res_canary.status(), StatusCode::OK);
    assert!(res_canary.headers().contains_key("x-canary-trace"));
}

#[tokio::test]
async fn test_propylea_surface_audit_grades_mirage_and_stealth_modes() {
    let mut cfg = PropyleaConfig::default();
    cfg.security.enable_mirage = false;

    let stealth_report = audit_config_surface(&cfg, "propylea://stealth-404").await;
    assert_eq!(stealth_report.exposed_risk_count, 0);
    assert_eq!(stealth_report.ghost_404_count, 12);
    assert_eq!(stealth_report.posture_grade, "A (Hardened Perimeter)");

    cfg.security.enable_mirage = true;
    let mirage_report = audit_config_surface(&cfg, "propylea://mirage-fortress").await;
    assert_eq!(mirage_report.exposed_risk_count, 0);
    assert!(mirage_report.mirage_protected_count >= 11);
    assert_eq!(
        mirage_report.posture_grade,
        "A+ (Sovereign Mirage Fortress)"
    );
}
