//! # Adversarial Sibling Reverse Proxy Peering Test Suite
//! Asserts SOVEREIGN-SIBLING-01 compliance in Propylea:
//! 1. Ingress Header Extraction & Sibling Gatekeeper Verification
//! 2. Diplomatic Immunity Bypass for Valid Sibling Solutions
//! 3. Tampered & Stale Signature Detection at Edge Gateway Boundary
//! 4. Upstream Lineage Header Injection

use hyper::header::USER_AGENT;
use hyper::Request;
use propylea::config::SecurityConfig;
use propylea::defense::EdgeDefense;
use propylea::sibling::{
    extract_sibling_proof, inject_sibling_upstream_headers, SiblingGatekeeper, SiblingProof,
    SiblingVerifier, HEADER_LINEAGE_CALLER, HEADER_LINEAGE_STATUS, HEADER_SIBLING_NAME,
    HEADER_SIBLING_NONCE, HEADER_SIBLING_SIGNATURE, HEADER_SIBLING_TIMESTAMP,
};
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn test_adversarial_sibling_diplomatic_immunity_bypass() {
    let config = SecurityConfig {
        enable_defense: true,
        enable_mirage: false,
        trusted_cidrs: vec![],
        ..Default::default()
    };
    let defense = EdgeDefense::new(&config);

    let client_ip: IpAddr = "198.51.100.99".parse().unwrap();
    let hostile_path = "/wp-login.php";
    let automation_ua = "sqlmap/1.7.2#stable";

    // 1. Stranger request with automation tool is trapped with 404/403
    let stranger_res =
        defense.evaluate_request(client_ip, "GET", hostile_path, Some(automation_ua));
    assert!(
        stranger_res.is_some(),
        "Hostile stranger must be trapped at edge"
    );

    // 2. Legitimate sibling solution (e.g. Janus mobile app or Drishti radar outpost)
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let challenge = SiblingVerifier::issue_challenge(now_ms, 777);
    let proof = SiblingVerifier::generate_proof("janus", &challenge.nonce, now_ms);

    // Peering request with sibling proof gains diplomatic immunity!
    let sibling_res = defense.evaluate_request_with_sibling(
        client_ip,
        "GET",
        hostile_path,
        None,
        Some(automation_ua),
        None,
        Some(&proof),
    );
    assert!(
        sibling_res.is_none(),
        "Verified sibling must receive diplomatic immunity through edge proxy"
    );
}

#[test]
fn test_adversarial_sibling_tampered_proof_falls_through_to_defense() {
    let defense = EdgeDefense::default();
    let client_ip: IpAddr = "203.0.113.55".parse().unwrap();
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let tampered_proof = SiblingProof {
        caller_name: "imposter".to_string(),
        nonce: "fake_nonce".to_string(),
        timestamp_ms: now_ms,
        signature: "11".repeat(32),
    };

    // Tampered sibling proof MUST NOT grant immunity
    let res = defense.evaluate_request_with_sibling(
        client_ip,
        "GET",
        "/.env",
        None,
        None,
        None,
        Some(&tampered_proof),
    );
    assert!(
        res.is_some(),
        "Forged sibling proof must be trapped by perimeter defense"
    );
}

#[test]
fn test_adversarial_sibling_header_extraction_and_upstream_injection() {
    let now_ms = 1_700_000_000_000;
    let challenge = SiblingVerifier::issue_challenge(now_ms, 42);
    let proof = SiblingVerifier::generate_proof("argus", &challenge.nonce, now_ms);

    let mut req = Request::builder()
        .header(HEADER_SIBLING_NAME, &proof.caller_name)
        .header(HEADER_SIBLING_NONCE, &proof.nonce)
        .header(HEADER_SIBLING_TIMESTAMP, proof.timestamp_ms.to_string())
        .header(HEADER_SIBLING_SIGNATURE, &proof.signature)
        .header(USER_AGENT, "ArgusTV/2.0")
        .body(())
        .unwrap();

    let extracted = extract_sibling_proof(&req).expect("Proof extraction must succeed");
    assert_eq!(extracted.caller_name, "argus");
    assert!(SiblingGatekeeper::verify_ingress_proof(&extracted, now_ms).is_ok());

    // Inject upstream headers
    inject_sibling_upstream_headers(&mut req, &extracted.caller_name);
    assert_eq!(
        req.headers().get(HEADER_LINEAGE_STATUS).unwrap(),
        "Sibling-Elevated"
    );
    assert_eq!(req.headers().get(HEADER_LINEAGE_CALLER).unwrap(), "argus");
}

// ============================================================================
// 🏛️ UNIVERSAL TRI-DIMENSIONAL REALITY CRUCIBLE (SOVEREIGN-REALITY-3D-01)
// ============================================================================

// --- DIMENSION 1: THE PRISTINE GOLDEN PATH & HUMAN ERGONOMICS (BENIGN DELIGHT) ---

#[test]
fn test_golden_path_normal_browser_page_refresh_and_navigation() {
    let defense = EdgeDefense::default();
    let client_ip: IpAddr = "73.180.45.12".parse().unwrap();
    let chrome_ua = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36";

    // Honest human browsing standard pages across multiple tabs
    let pages = ["/", "/downloads", "/pricing", "/docs", "/manifest.json"];
    for page in pages {
        let res = defense.evaluate_request(client_ip, "GET", page, Some(chrome_ua));
        assert!(
            res.is_none(),
            "Honest human browsing {} must pass transparently",
            page
        );
    }
}

#[test]
fn test_golden_path_legitimate_sibling_high_throughput_relay() {
    let defense = EdgeDefense::default();
    let client_ip: IpAddr = "10.0.0.5".parse().unwrap();
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    // Sibling node (Vox or Conduit) streaming 20 high-frequency radar state chunks
    for seq in 0..20 {
        let nonce = format!("relay-chunk-{}", seq);
        let proof = SiblingVerifier::generate_proof("conduit", &nonce, now_ms + seq);

        let res = defense.evaluate_request_with_sibling(
            client_ip,
            "POST",
            "/api/relay/stream",
            None,
            Some("ConduitRelay/1.0"),
            None,
            Some(&proof),
        );
        assert!(
            res.is_none(),
            "Continuous sibling streaming must experience zero proxy friction"
        );
    }
}

// --- DIMENSION 2: THE ADVERSARIAL RED CRUCIBLE (SELF-ATTACK & MALICE) ---

#[test]
fn test_adversarial_bot_ja4_fingerprint_spoofing_trap() {
    let defense = EdgeDefense::default();
    let client_ip: IpAddr = "194.26.29.112".parse().unwrap();

    // Attacker using automated scanner claiming to be Windows Chrome
    let spoofed_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36";
    // Target is a known reconnaissance path
    let hostile_target = "/.git/config";

    let res = defense.evaluate_request(client_ip, "GET", hostile_target, Some(spoofed_ua));
    assert!(
        res.is_some(),
        "Automated scanner probing .git must be intercepted by EdgeDefense"
    );
}

#[test]
fn test_adversarial_sibling_expired_timestamp_tarpit() {
    let defense = EdgeDefense::default();
    let client_ip: IpAddr = "185.191.171.12".parse().unwrap();
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    // Attacker crafts proof with stale timestamp (65 seconds old)
    let stale_time = now_ms.saturating_sub(65_000);
    let stale_proof = SiblingVerifier::generate_proof("vox", "stale-nonce", stale_time);

    let res = defense.evaluate_request_with_sibling(
        client_ip,
        "GET",
        "/.env",
        None,
        Some("sqlmap/1.7.2#stable"),
        None,
        Some(&stale_proof),
    );
    assert!(
        res.is_some(),
        "Stale sibling proof must fall through to defensive blocking"
    );
}

// --- DIMENSION 3: PHYSICAL & AMBIENT ENVIRONMENTAL CHAOS (PHYSICS & UNKNOWNS) ---

#[test]
fn test_chaos_network_roaming_dual_interface_handover() {
    let defense = EdgeDefense::default();
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let nonce = "dual-interface-01";
    let proof = SiblingVerifier::generate_proof("ashwin", nonce, now_ms);

    // Initial query on LTE interface
    let lte_ip: IpAddr = "172.56.40.11".parse().unwrap();
    let res_lte = defense.evaluate_request_with_sibling(
        lte_ip,
        "GET",
        "/mesh/heartbeat",
        None,
        Some("AshwinSentinel/1.0"),
        None,
        Some(&proof),
    );
    assert!(res_lte.is_none());

    // Instant switch to Satellite / Mesh interface (different IP, 2s later, same proof)
    let sat_ip: IpAddr = "10.200.0.1".parse().unwrap();
    let res_sat = defense.evaluate_request_with_sibling(
        sat_ip,
        "GET",
        "/mesh/heartbeat",
        None,
        Some("AshwinSentinel/1.0"),
        None,
        Some(&proof),
    );
    assert!(
        res_sat.is_none(),
        "Sibling attestation must remain valid across physical network interfaces"
    );
}
