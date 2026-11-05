//! # Propylea Outside-In Attack Surface & Mirage Auditor (`surface_audit.rs`)
//!
//! Single Job: Audit a `PropyleaConfig` (or live edge endpoint) against the 12 canonical
//! outside-in scanner exposure vectors (`phylax::surface_audit::CANONICAL_SURFACE_VECTORS`)
//! to verify 100% perimeter containment, Synthetic Mirage decoy poisoning, and security
//! header posture (`HSTS`, `X-Content-Type-Options`, `X-Frame-Options`).

use crate::config::PropyleaConfig;
use crate::defense::EdgeDefense;
use http_body_util::BodyExt;
use phylax::surface_audit::{
    ExposureVerdict, ProbeAuditResult, SurfaceAuditEngine, SurfaceExposureReport,
};
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;

/// Audits a `PropyleaConfig` directly against all canonical outside-in attack surface vectors.
pub async fn audit_config_surface(
    config: &PropyleaConfig,
    target_label: &str,
) -> SurfaceExposureReport {
    let scanner_ua = Some(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    );

    let mut results = Vec::new();
    for (idx, vec) in SurfaceAuditEngine::canonical_vectors().iter().enumerate() {
        let defense = EdgeDefense::new(&config.security);
        let scanner_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, (idx as u8).saturating_add(10)));
        if let Some(resp) =
            defense.evaluate_request_full(scanner_ip, "GET", vec.path, None, scanner_ua, None)
        {
            let status = resp.status().as_u16();
            let mut hdrs = Vec::new();
            for (k, v) in resp.headers() {
                if let Ok(val) = v.to_str() {
                    hdrs.push((k.as_str().to_string(), val.to_string()));
                }
            }
            let body_bytes = resp
                .into_body()
                .collect()
                .await
                .map(|c| c.to_bytes())
                .unwrap_or_default();
            let body_str = String::from_utf8_lossy(&body_bytes);
            results.push(SurfaceAuditEngine::evaluate_probe_response(
                vec, status, &hdrs, &body_str,
            ));
        } else {
            results.push(ProbeAuditResult {
                path: vec.path.to_string(),
                category: vec.category,
                status_code: 200,
                verdict: ExposureVerdict::ExposedRisk {
                    status_code: 200,
                    reason: "Defense disabled or vector bypassed".to_string(),
                },
            });
        }
    }

    let mut root_headers = vec![("X-Content-Type-Options".to_string(), "nosniff".to_string())];
    if config.security.hsts {
        root_headers.push((
            "Strict-Transport-Security".to_string(),
            "max-age=63072000; includeSubDomains; preload".to_string(),
        ));
    }
    if !config.security.frame_options.is_empty() {
        root_headers.push((
            "X-Frame-Options".to_string(),
            config.security.frame_options.clone(),
        ));
    }

    SurfaceAuditEngine::compile_report(target_label, results, &root_headers)
}

/// CLI entry point for `propylea audit-surface`
pub async fn run_surface_audit(
    config_path: &Path,
    enable_mirage_override: bool,
    json_output: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = if config_path.exists() {
        PropyleaConfig::load_from_file(config_path)?
    } else {
        PropyleaConfig::default()
    };
    if enable_mirage_override {
        config.security.enable_mirage = true;
    }

    let label = format!("propylea://{}", config_path.display());
    let report = audit_config_surface(&config, &label).await;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!(
            "🏛️  Propylea Outside-In Attack Surface Audit: {}",
            report.target
        );
        println!("   Posture Grade: {}\n", report.posture_grade);
        for r in &report.results {
            let badge = match &r.verdict {
                ExposureVerdict::ProtectedByMirage { canary_hint } => {
                    format!("🎭 MIRAGE DECOY ({})", canary_hint)
                }
                ExposureVerdict::ProtectedByBlock { status_code } => {
                    format!("🛑 BLOCKED (HTTP {})", status_code)
                }
                ExposureVerdict::CleanGhost404 { status_code } => {
                    format!("👻 GHOST 404 (HTTP {})", status_code)
                }
                ExposureVerdict::Redirected { status_code } => {
                    format!("↪️  REDIRECT (HTTP {})", status_code)
                }
                ExposureVerdict::ExposedRisk { reason, .. } => format!("❌ EXPOSED: {}", reason),
            };
            println!("  • {:<26} -> {}", r.path, badge);
        }
    }
    Ok(())
}
