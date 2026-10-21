//! # Sovereign Buffalo Crucible Test Gate Engine (`crucible.rs`)
//!
//! Single Responsibility (OJP): Live multi-OS red-team attack ingestion gate.
//! Directly integrates Propylea Quarantine and Phylax BotGuard with ANSI-scrubbed output
//! and bounded connection timeouts.

use crate::quarantine::{QuarantineRecord, QuarantineStore};
use crate::sanitize::{scrub_ansi_and_control, MAX_BANNER_BYTES};
use bytes::Bytes;
use clap::Parser;
use http_body_util::Full;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use phylax::{AutonomousQuarantine, BotVerdict, QuarantineConfig};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;

#[derive(Parser, Debug, Clone)]
#[command(name = "crucible_gate")]
#[command(about = "Sovereign Buffalo Crucible Defensive Test Ingress")]
pub struct CrucibleOpts {
    #[arg(short, long, default_value = "127.0.0.1:8999")]
    pub bind: String,

    #[arg(
        short,
        long,
        default_value = "/mnt/nas/lab/telemetry_vault/crucible_quarantine.db"
    )]
    pub db: PathBuf,
}

pub struct GateContext {
    pub quarantine: Arc<AutonomousQuarantine>,
    pub store: Arc<QuarantineStore>,
    pub bot_guard: Arc<phylax::BotGuard>,
}

/// Run the Buffalo Crucible test gate server
pub async fn run_crucible_gate(opts: CrucibleOpts) -> Result<(), Box<dyn std::error::Error>> {
    let addr: SocketAddr = opts.bind.parse()?;

    println!(
        "[*] Initializing Buffalo Crucible Quarantine Store at {:?}",
        opts.db
    );
    let store = Arc::new(QuarantineStore::open(&opts.db)?);
    let q_cfg = QuarantineConfig {
        infraction_threshold: 1,
        quarantine_duration_ms: 3600 * 1000,
        ..Default::default()
    };
    let quarantine = Arc::new(AutonomousQuarantine::new(q_cfg));
    let bot_guard = Arc::new(phylax::BotGuard::new());

    let ctx = Arc::new(GateContext {
        quarantine,
        store,
        bot_guard,
    });

    let listener = TcpListener::bind(addr).await?;
    println!("[+] Buffalo Crucible Gate listening on http://{}", addr);

    loop {
        let (stream, remote_addr) = match listener.accept().await {
            Ok(res) => res,
            Err(e) => {
                eprintln!("[-] Accept error: {}", e);
                continue;
            }
        };

        let _ = stream.set_nodelay(true);
        let io = TokioIo::new(stream);
        let ctx_clone = ctx.clone();

        tokio::spawn(async move {
            let service = service_fn(move |req: Request<hyper::body::Incoming>| {
                let ctx = ctx_clone.clone();
                let client_ip = remote_addr.ip();
                async move { handle_crucible_request(ctx, client_ip, req).await }
            });

            let conn_fut = http1::Builder::new().serve_connection(io, service);
            let _ = tokio::time::timeout(Duration::from_secs(30), conn_fut).await;
        });
    }
}

/// Evaluate a single HTTP request against Crucible Gate quarantine, framing, and BotGuard rules
pub async fn handle_crucible_request(
    ctx: Arc<GateContext>,
    client_ip: IpAddr,
    req: Request<hyper::body::Incoming>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let start_t = Instant::now();
    let raw_path = req.uri().path();
    let safe_path = scrub_ansi_and_control(raw_path, 1024);
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let now_sec = now_ms / 1000;
    let ip_str = client_ip.to_string();

    // 1. In-Memory Microsecond Quarantine Check
    if ctx.quarantine.is_quarantined(&ip_str, now_ms) {
        let elapsed_us = start_t.elapsed().as_micros();
        println!(
            "[DEFLECT] Quarantined IP {} hit {} -> Dropped ({}µs)",
            client_ip, safe_path, elapsed_us
        );
        let mut resp = Response::new(Full::new(Bytes::from("{\"error\":\"quarantined\"}\n")));
        *resp.status_mut() = StatusCode::FORBIDDEN;
        return Ok(resp);
    }

    // 2. HTTP Framing / Smuggling Check
    let te = req.headers().get("transfer-encoding").is_some();
    let cl = req.headers().get("content-length").is_some();
    if te && cl {
        println!(
            "[DEFLECT] Smuggling anomaly TE+CL from {} -> 400 Bad Request",
            client_ip
        );
        let mut resp = Response::new(Full::new(Bytes::from("{\"error\":\"framing_conflict\"}\n")));
        *resp.status_mut() = StatusCode::BAD_REQUEST;
        return Ok(resp);
    }

    // 3. User-Agent Scanner Inspection (BotGuard)
    let raw_ua = req
        .headers()
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let safe_ua = scrub_ansi_and_control(raw_ua, MAX_BANNER_BYTES);

    let verdict = ctx.bot_guard.evaluate_perimeter(Some(&safe_ua), &safe_path);
    if let BotVerdict::Blocked {
        category,
        matched_token,
    } = verdict
    {
        let elapsed_us = start_t.elapsed().as_micros();
        println!(
            "[DEFENSE] Scanner detected UA: '{}' (token: {:?}, cat: {:?}) from {} ({}µs) -> Enforcing Quarantine",
            safe_ua, matched_token, category, client_ip, elapsed_us
        );

        let cidr = AutonomousQuarantine::derive_quarantine_cidr(&ip_str)
            .unwrap_or_else(|| format!("{}/32", client_ip));
        let rec = QuarantineRecord {
            cidr,
            ip_version: if client_ip.is_ipv4() { 4 } else { 6 },
            trigger_ip: client_ip.to_string(),
            infraction_type: format!("bot_scanner:{:?}", category),
            infraction_count: 1,
            quarantined_at: now_sec,
            expires_at: now_sec + 3600,
            user_agent: Some(safe_ua),
            active: true,
        };

        let _ = ctx.store.record_ban(&rec);
        ctx.quarantine.record_and_check(&ip_str, now_ms);

        let mut resp = Response::new(Full::new(Bytes::from("{\"error\":\"hostile_scanner\"}\n")));
        *resp.status_mut() = StatusCode::FORBIDDEN;
        return Ok(resp);
    }

    // 4. Honeypot Trap Decoy Paths
    let is_honeypot = safe_path.starts_with("/wp-")
        || safe_path.starts_with("/.env")
        || safe_path.starts_with("/.git")
        || safe_path.starts_with("/phpmyadmin");

    if is_honeypot {
        let elapsed_us = start_t.elapsed().as_micros();
        println!(
            "[HONEYPOT] Decoy breach path '{}' from {} ({}µs) -> Enforcing Quarantine",
            safe_path, client_ip, elapsed_us
        );

        let cidr = AutonomousQuarantine::derive_quarantine_cidr(&ip_str)
            .unwrap_or_else(|| format!("{}/32", client_ip));
        let rec = QuarantineRecord {
            cidr,
            ip_version: if client_ip.is_ipv4() { 4 } else { 6 },
            trigger_ip: client_ip.to_string(),
            infraction_type: "honeypot_decoy_breach".to_string(),
            infraction_count: 1,
            quarantined_at: now_sec,
            expires_at: now_sec + 3600,
            user_agent: Some(safe_ua),
            active: true,
        };

        let _ = ctx.store.record_ban(&rec);
        ctx.quarantine.record_and_check(&ip_str, now_ms);

        let mut resp = Response::new(Full::new(Bytes::from("{\"error\":\"not_found\"}\n")));
        *resp.status_mut() = StatusCode::NOT_FOUND;
        return Ok(resp);
    }

    // 5. Clean Request
    let mut resp = Response::new(Full::new(Bytes::from(
        "{\"status\":\"healthy\",\"crucible\":\"nominal\"}\n",
    )));
    *resp.status_mut() = StatusCode::OK;
    Ok(resp)
}
