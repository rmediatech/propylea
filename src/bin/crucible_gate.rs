//! # Sovereign Buffalo Crucible Test Gate
//! Single Responsibility (OJP): Live multi-OS red-team attack ingestion gate.
//! Directly integrates Propylea Quarantine and Phylax BotGuard.

use bytes::Bytes;
use clap::Parser;
use http_body_util::Full;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use phylax::{AutonomousQuarantine, BotVerdict, QuarantineConfig};
use propylea::quarantine::{QuarantineRecord, QuarantineStore};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;

#[derive(Parser, Debug)]
#[command(name = "crucible_gate")]
#[command(about = "Sovereign Buffalo Crucible Defensive Test Ingress")]
struct Opts {
    #[arg(short, long, default_value = "192.168.122.1:8999")]
    bind: String,

    #[arg(
        short,
        long,
        default_value = "/mnt/nas/lab/telemetry_vault/crucible_quarantine.db"
    )]
    db: PathBuf,
}

struct GateContext {
    quarantine: Arc<AutonomousQuarantine>,
    store: Arc<QuarantineStore>,
    bot_guard: Arc<phylax::BotGuard>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opts = Opts::parse();
    let addr: SocketAddr = opts.bind.parse()?;

    println!(
        "[*] Initializing Buffalo Crucible Quarantine Store at {:?}",
        opts.db
    );
    let store = Arc::new(QuarantineStore::open(&opts.db)?);
    let q_cfg = QuarantineConfig {
        infraction_threshold: 1, // Instant ban on attack trigger for crucible verification
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

        let io = TokioIo::new(stream);
        let ctx_clone = ctx.clone();

        tokio::spawn(async move {
            let service = service_fn(move |req: Request<hyper::body::Incoming>| {
                let ctx = ctx_clone.clone();
                let client_ip = remote_addr.ip();
                async move { handle_request(ctx, client_ip, req).await }
            });

            if let Err(e) = http1::Builder::new().serve_connection(io, service).await {
                let _ = e;
            }
        });
    }
}

async fn handle_request(
    ctx: Arc<GateContext>,
    client_ip: std::net::IpAddr,
    req: Request<hyper::body::Incoming>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let start_t = Instant::now();
    let path = req.uri().path().to_string();
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let now_sec = now_ms / 1000;
    let ip_str = client_ip.to_string();

    // 1. In-Memory Microsecond Quarantine Check
    if ctx.quarantine.is_quarantined(&ip_str, now_ms) {
        let elapsed_us = start_t.elapsed().as_micros();
        println!(
            "[DEFLECT] Quarantined IP {} hit {} -> Dropped ({}µs)",
            client_ip, path, elapsed_us
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
    let ua = req
        .headers()
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let verdict = ctx.bot_guard.evaluate_perimeter(Some(ua), &path);
    if let BotVerdict::Blocked {
        category,
        matched_token,
    } = verdict
    {
        let elapsed_us = start_t.elapsed().as_micros();
        println!(
            "[DEFENSE] Scanner detected UA: '{}' (token: {:?}, cat: {:?}) from {} ({}µs) -> Enforcing Quarantine",
            ua, matched_token, category, client_ip, elapsed_us
        );

        let cidr = AutonomousQuarantine::derive_quarantine_cidr(&ip_str)
            .unwrap_or_else(|| format!("{}/32", client_ip));
        let rec = QuarantineRecord {
            cidr: cidr.clone(),
            ip_version: if client_ip.is_ipv4() { 4 } else { 6 },
            trigger_ip: client_ip.to_string(),
            infraction_type: format!("bot_scanner:{:?}", category),
            infraction_count: 1,
            quarantined_at: now_sec,
            expires_at: now_sec + 3600,
            user_agent: Some(ua.to_string()),
            active: true,
        };

        let _ = ctx.store.record_ban(&rec);
        ctx.quarantine.record_and_check(&ip_str, now_ms);

        let mut resp = Response::new(Full::new(Bytes::from("{\"error\":\"hostile_scanner\"}\n")));
        *resp.status_mut() = StatusCode::FORBIDDEN;
        return Ok(resp);
    }

    // 4. Honeypot Trap Decoy Paths
    let is_honeypot = path.starts_with("/wp-")
        || path.starts_with("/.env")
        || path.starts_with("/.git")
        || path.starts_with("/phpmyadmin");

    if is_honeypot {
        let elapsed_us = start_t.elapsed().as_micros();
        println!(
            "[HONEYPOT] Decoy breach path '{}' from {} ({}µs) -> Enforcing Quarantine",
            path, client_ip, elapsed_us
        );

        let cidr = AutonomousQuarantine::derive_quarantine_cidr(&ip_str)
            .unwrap_or_else(|| format!("{}/32", client_ip));
        let rec = QuarantineRecord {
            cidr: cidr.clone(),
            ip_version: if client_ip.is_ipv4() { 4 } else { 6 },
            trigger_ip: client_ip.to_string(),
            infraction_type: "honeypot_decoy_breach".to_string(),
            infraction_count: 1,
            quarantined_at: now_sec,
            expires_at: now_sec + 3600,
            user_agent: Some(ua.to_string()),
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
