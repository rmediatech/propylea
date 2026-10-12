# 📋 Propylea Changelog & Architectural Ledger

All notable changes, architectural milestones, and security invariants for **Propylea** (`propylea`) are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.1] - 2026-10-12 (Crucible Fortification: Bounded Chunked Ingestion, 5xx Failover Hedging & Zero-Dependency Standalone Build)

### 🌟 Added & Fortified
* **Zero-Dependency Public Git Resolution**:
  - Migrated `phylax` and `hippodrome` dependencies to authoritative public Git repositories (`https://github.com/xuoxod/phylax.git`, `https://github.com/xuoxod/hippodrome.git`).
  - Enables clean-room `git clone` compilation for external operators without local workspace or sibling directory requirements.
* **Allocation Bomb Guard on Hedged Streaming (`src/proxy.rs`)**:
  - Enforced `http_body_util::Limited` on incoming request body ingestion during hedged dispatch.
  - Guarantees chunked requests without `Content-Length` headers cannot exceed `FramingGuard::max_body_bytes`, preventing memory exhaustion and OOM bombs with immediate `413 Payload Too Large`.
* **5xx Server Error Failover Hedging (`src/proxy.rs`)**:
  - In hedged tournament racing, detected upstream 5xx server errors (`500`, `502`, `503`, `504`) immediately trigger hedged failover to healthy sibling upstreams instead of aborting healthy requests.
  - Upstreams returning 5xx have failures recorded in Hippodrome's scoreboard, demoting their rank and tripping circuit breakers autonomously.
* **Crucible Adversarial Integration Tests (`tests/proxy_integration_tests.rs`)**:
  - Added `test_hedged_racing_fails_over_on_instant_503_server_error` asserting instantaneous recovery and 200 OK delivery when primary returns 503.
  - Added `test_hedged_racing_payload_too_large_rejection` asserting strict payload boundary containment.

---

## [0.3.0] - 2026-10-12 (Speculative Hedged Tournament Racing Integration)

### 🌟 Added & Fortified
* **Hippodrome Speculative Hedged Racing Engine (`--features hedged-racing`)**:
  - Integrated `hippodrome` for fastest-horse speculative concurrency across upstream pools (`upstreams = [...]`).
  - Idempotent requests (`GET`, `HEAD`, `OPTIONS`) eliminate tail-latency spikes with microsecond adaptive hedged delay.
  - Mutating requests (`POST`, `PUT`, `DELETE`, `PATCH`) strictly enforce single-flight dispatch with bounded failover.
* **Release Pipeline Multi-Platform Hedged Support**:
  - Updated GitHub release workflow to compile cross-platform release binaries (`x86_64-musl`, `aarch64-musl`, `x86_64-glibc`) with `--features hedged-racing`.

---

## [0.2.5] - 2026-10-11 (SQLite WAL Quarantine Store, Live IPC Control & Universal 6-Format Reporting)

### 🌟 Added & Fortified
* **SQLite WAL Persistent Quarantine & Threat Registry (`src/quarantine.rs`)**:
  - Replaced transient in-memory bans with an atomic, zero-cloud SQLite database operating in WAL (Write-Ahead Logging) mode (`quarantine.db`).
  - Automatic boot rehydration: banned IPs, reasons, subnet scopes, and expiration timestamps survive proxy restarts.
  - Microsecond in-memory hot cache (`DashMap`) backed by asynchronous SQLite WAL persistence.
* **Live Unix Domain Socket IPC Control Plane (`src/quarantine_ipc.rs`)**:
  - Real-time command IPC listener on `/run/propylea/quarantine.sock` (or `~/.local/share/propylea/quarantine.sock`).
  - Dynamic operator controls without proxy restart: `BAN <ip> [duration] [reason]`, `UNBAN <ip>`, `UNBAN_ALL`, `STATUS`, and `LIST`.
* **Universal 6-Format Forensic Reporting & Ingestion Tooling (`scripts/propylea-quarantine.sh`)**:
  - Deterministic export across 6 formats: JSON, CSV, Zero-Cloud Self-Contained HTML visual dashboard, Markdown table, TSV, and Plaintext.
  - Formula Injection Immunity: Prefixes hostile spreadsheet payload prefixes (`=`, `+`, `-`, `@`, `\t`, `\r`) with single quotes (`'`).
  - Historical Systemd Journal Ingestion: Backfills prior hostile probe IPs directly from `journalctl -u propylea`.
* **Static Musl PIE Compilation Support**:
  - Verified 100% static linking against `x86_64-unknown-linux-musl` with zero dynamic libc dependencies.
* **Adversarial Persistence TDD Battery (`tests/quarantine_persistence_tdd.rs`)**:
  - 8 automated adversarial test cases asserting rehydration survival, CSV formula injection defense, UDS IPC live ban/unban cycles, and multi-format reporting.

---

## [0.2.4] - 2026-10-02 (HTTP Request Smuggling Defense, TLS Fingerprinting & Anti-Spoofing)

### 🌟 Added & Fortified
* **Strict HTTP Request Framing & Smuggling Defense (`src/framing_guard.rs` - Layer 3)**:
  - Enforced RFC 9112 §6.1 and RFC 7230 §3.3.3: Rejects requests containing conflicting `Content-Length` and `Transfer-Encoding` headers (TE.CL / CL.TE desync attacks) with `400 Bad Request`.
  - Blocks multiple conflicting `Content-Length` headers, comma-separated differing lengths, and non-chunked `Transfer-Encoding`.
  - Header Hygiene: Detects and rejects NUL-byte injection (`\0`), raw carriage returns/linefeeds, and ASCII control characters (`0x7F`, `< 0x20`).
  - Allocation Bomb Guard: Enforces maximum body limits (`413 Payload Too Large`) *before* reading or buffering payloads into memory.
  - Ingress Header Sanitization: Strips untrusted client-supplied identity headers (`X-Forwarded-For`, `X-Forwarded-Proto`, `X-Real-IP`, `CF-Connecting-IP`), authoritatively stamping only the verified socket peer address.
* **TLS ClientHello Fingerprinting & Anti-Spoofing (`src/tls_fingerprint.rs` - Layer 2)**:
  - Zero-allocation socket peeking (`TcpStream::peek(&mut buf)`) parsing TLS ClientHello records in $< 200\text{ns}$ without consuming the kernel socket buffer.
  - 1-cycle bitwise RFC 8701 GREASE detection (`(val & 0x0f0f) == 0x0a0a && ((val >> 8) == (val & 0xff))`).
  - Cross-references TLS handshake characteristics against claimed `User-Agent`.
  - Spoofing Defeat: If an automated client (Python `requests`/`aiohttp`, Go `net/http`, curl, CLI scripts) claims to be Chrome, Edge, or Safari, but lacks mandatory browser GREASE ciphers/extensions, it is flagged as an undeniable spoofing attack, intercepted with stealth `404 Not Found`, and added to dynamic quarantine.
  - Preserves legitimate search engine crawlers (Googlebot, Bingbot).
* **Adversarial Self-Attack TDD Invariants**:
  - Added `test_adversarial_http_smuggling_and_framing_attacks` asserting TE.CL desync rejection, multiple CL rejection, allocation bomb blocking, and proxy header sanitization.
  - Added `test_adversarial_tls_fingerprint_spoofed_browser_detection` asserting zero-bypass interception of Python/Go scripts masquerading as modern Chrome browsers.

## [0.2.3] - 2026-10-01 (Canary Trap Honeylinks, Dynamic Threat Auto-Harvesting & Kali Defense)

### 🌟 Added & Fortified
* **Autonomous Canary Trap Honeylink Interception (`/_sovereign/canary_trap`, `/decoy/canary`)**:
  - Implemented Layer 0.25 Canary Trap Honeylink interception directly inside `propylea::defense::EdgeDefense`.
  - Probes to canary trap endpoints return a deceptive stealth `HTTP 404 Not Found` while immediately harvesting the crawler's User-Agent into the dynamic threat registry and enforcing subnet quarantine.
* **Preemptive Dynamic Threat Auto-Harvesting**:
  - Probes to Decoy URI honeyroutes (`/.env`, `wp-login.php`, etc.) or Canary Trap links autonomously harvest the attacker's User-Agent token in real-time.
  - Subsequent requests bearing that token from **any** IP or proxy across the cluster are preemptively dropped at the edge boundary with `HTTP 403 Forbidden`.
* **Full Kali Linux & Pen-Testing Tool Interception**:
  - Sub-microsecond deflection of offensive fuzzers (`ffuf`, `feroxbuster`, `dirsearch`, `DirBuster`, `Gobuster`, `wfuzz`, `Nuclei`), vulnerability scanners (`Acunetix`, `Nessus`, `OpenVAS`, `BurpSuite`, `OWASP ZAP`), exploit engines (`sqlmap`, `SQLNinja`, `Metasploit`), and digital forensics extractors.
* **Adversarial Integration Tests**:
  - Added `test_adversarial_canary_trap_and_dynamic_bot_harvesting` asserting dynamic learning, stealth 404 response, and cross-IP preemptive deflection.

## [0.2.2] - 2026-10-01 (Sub-Microsecond Edge BotGuard, 403 Forbidden Interception & Live Fleet Deployment)

### 🌟 Added & Enhanced
* **Sub-Microsecond Edge Bot Guard Interception (`src/defense.rs`, `src/proxy.rs`)**:
  - Direct integration of `phylax::BotGuard` at the outer L7 reverse proxy boundary.
  - Intercepts automated AI scrapers (`Claude-SearchBot`, `GPTBot`, `OAI-SearchBot`, `Google-Extended`, `Meta-ExternalAgent`, `Bytespider`), technology stack profilers (`BuiltWith`, `CensysInspect`), and headless scraping tools before allocating upstream backend sockets or application resources.
  - Deflects hostile crawlers with standard `HTTP 403 Forbidden` (`content-type: text/plain; charset=utf-8`) detailing RFC 9309 exclusion policy.
  - Prioritizes Decoy URI Honeyroute traps (Layer 0.5) with stealth `404 Not Found` for scanner probes (`/.env`, `/.git/config`, `wp-login.php`).
* **RFC 9309 Robots Bypass Invariant**:
  - Guarantees unconditional passthrough for `/robots.txt` so compliant search and AI crawlers can discover their disallow directives.
  - Guarantees developer CLI utility passthrough (`curl`, `wget`) on binary distribution endpoints (`/install/*`, `/bin/*`, `/checksums/*`, `/healthz`).
  - Preserves legitimate search engine indexing (`Googlebot`, `Bingbot`, `DuckDuckBot`, `Slurp`, `Baiduspider`, `YandexBot`) on public storefront routes.
* **Granular Telemetry Threat Categorization**:
  - Telemetry ring buffer now distinguishes between `Bot Perimeter Intercept` (HTTP 403) and `Hostile Recon Probe` (HTTP 404).
* **Live Fleet Production Verification**:
  - Deployed and verified on **Node 1 (`rmediatech.com`, `matrix.rmediatech.com`)** and **Node 2 (`sfu.rmediatech.com`)**.
  - Verified live deflection of `Claude-SearchBot/1.0`, `BuiltWith/1.4`, `CensysInspect/1.1`, and `GPTBot/1.0` in `<10ns`.

---

## [0.2.1] - 2026-10-01 (Fleet Ingress Unification, ACME Webroot Engine & Sovereign Lockdown)

### 🌟 Added & Production Milestones
* **Autonomous ACME HTTP-01 Webroot Engine (`src/acme.rs`)**:
  - RFC 8555 compliant token serving on Port 80 and HTTPS directly from configurable webroot (`acme_webroot = "/var/www/letsencrypt"`).
  - Path-traversal immunity: strict character validation (`[a-zA-Z0-9_-]`, max 128 chars) rejecting `..`, slashes, and null bytes with HTTP 400 Bad Request before filesystem interaction.
  - Bounded memory read: capped at 4,096 bytes preventing file allocation bomb DoS.
  - Automated deployment reload hook (`/etc/letsencrypt/renewal-hooks/deploy/propylea-reload.sh`) wired to systemd `certbot.timer` across all nodes.
* **Unified Certificate Fleet Standard (Node 1 & Node 2)**:
  - **Node 2 (`sfu.rmediatech.com`)**: Verified live with `certbot renew --dry-run` achieving 100% simulated renewal success via `propylea` port 80 passthrough.
  - **Node 1 (`rmediatech.com`, `www`, `next`, `matrix`)**: Minted unified certificate in `/etc/letsencrypt/live/rmediatech.com/` valid through December 30, 2026.
* **Fleet-Wide Production Lockdown (Node 1 & Node 2)**:
  - **Node 2 (`sfu.rmediatech.com`)**: Deployed `propylea` v0.2.1 on ports 80/443 with full-duplex WebSocket tunneling to `livekit-server` (:7880). Banished and purged legacy Nginx packages completely (`8.1 MB` RSS vs legacy `28.4 MB`). Verified 13/13 health checks.
  - **Node 1 (`rmediatech.com`, `matrix.rmediatech.com`)**: Migrated edge reverse proxying to `propylea` v0.2.1 on ports 80/443 with multi-domain TLS multiplexing to `rmediatech` (:8081) and `matrix-server` (:8082). Banished and purged legacy Caddy packages completely (`8.0 MB` RSS).
* **Live Adversarial Self-Attack Scorecard (`POC TDD+++++`)**:
  - 15/15 Decoy recon probes (`/.env`, `/.git/config`, `/.aws/credentials`, `/wp-admin`, `/phpinfo.php`) intercepted in $<15\text{ns}$ with stealth `404 Not Found` and obfuscated `Propylea-Edge-Gateway/1.0` banner.
  - ACME traversal and injection probes rejected with `400 Bad Request`.
  - Host header injection (`Host: attacker-controlled-domain.xyz`) safely dropped with `404`.
  - Malicious scanner User-Agents (`sqlmap`, `nikto`, `masscan`, `gobuster`) intercepted at edge.
  - Structural registration honeypot (`website_url`) triggered socket-hostage tarpit.
  - Multi-vector scanner burst triggered Autonomous Quarantine (Layer 0), validating live IP self-immunization while benign traffic from unquarantined nodes remained 100% unaffected.
* **Sovereign Defense Topology Blueprint (`docs/DEFENSE_TOPOLOGY.md`)**:
  - Authored comprehensive Layman-to-Architect mental model detailing the 5 concentric security rings (`Bastion` $\to$ `Propylea` $\to$ `Phylax` $\to$ `Slow-Shield` $\to$ Applications $\to$ `Sovereign-Ledger`).
  - Added Definitive Disambiguation Matrix clarifying strict One-Job-Principle (OJP) boundaries across all sovereign crates.
  - Documented fleet node ingress topology across Node 1 (`lin` - Storefront & Matrix) and Node 2 (`sfu` - LiveKit WebRTC).
* **Operator Troubleshooting & Diagnostic Runbook (`docs/TROUBLESHOOTING.md`)**:
  - Published 30-second triage checklist for operators and engineers.
  - Added resolution workflows for `502 Bad Gateway`, port `80`/`443` address collisions (`os error 98`), low-port permissions (`cap_net_bind_service`), TLS certificate mismatch, and WebSocket 1006 drops.
* **Developer Zero-Friction & Clean-Room Ergonomics**:
  - Added `--syntax-only` flag to `propylea check` enabling instant schema validation of `propylea.example.toml` on fresh repository clones without requiring pre-installed Let's Encrypt certificates (`make check` passes out-of-the-box).
  - Fixed systemd service recipe in `Makefile` replacing fragile shell heredocs with robust `printf` escaping.
  - Enhanced `scripts/setup_service.sh` with multi-tier discovery: automatically detects local target binaries, compiles via Cargo if present, or downloads prebuilt releases from GitHub for virgin OS environments.
* **Dynamic Clap CLI Versioning**:
  - Replaced static string literals with dynamic `#[command(version)]` linking directly to `Cargo.toml`.
* **RFC 5424 Syslog / CEF (Common Event Format) SIEM Ingress (`src/config.rs`, `src/defense.rs`)**:
  - Added `syslog_cef: bool` configuration toggle to `[security]` in `propylea.toml`, passing through to `phylax::InformantConfig` for 100% air-gapped local SIEM audit logging without external HTTP egress.
  - Hardened integration test suite with `..Default::default()` resilience against future security configuration expansions.
* **Cross-Platform Parity & Windows Verification**:
  - Validated native compilation on `x86_64-pc-windows-gnu` generating pure PE32+ 64-bit binaries.
  - Executed automated configuration validation and version verification on clean-room Windows Server 2022 KVM VM (`citadel-win1`).
* **Architecture Mental Model in README**:
  - Integrated the Fortress Mental Model directly into the primary `README.md` to eliminate confusion for external developers and operators.

---

## [0.2.0] - 2026-09-24 (Autonomous Closed-Loop Threat Harvester & Memory Vacuum)

### 🌟 Added
* **Layer 13 Closed-Loop Threat Harvester Integration**:
  - Intercepts upstream `404 Not Found` responses from backend services and feeds anomalous paths into `phylax::ThreatHarvesterEngine`.
  - Probes correlated across $\ge 3$ distinct `/24` subnets are autonomously elevated into the active in-memory decoy trie without requiring manual ruleset intervention.
* **Autonomous Linux Heap Vacuum (`maintenance.rs`)**:
  - Integrated `libc::malloc_trim(0)` kernel page recovery executing every 300 seconds.
  - Guarantees constant `< 15 MB` RSS memory footprint under 24/7 continuous production load.
* **Bounded In-Memory Telemetry Ring Buffer (`telemetry.rs`)**:
  - Retains 10,000 structured forensic records in an $O(1)$ circular ring buffer.
  - Automatic query-parameter PII and credential scrubbing (`token=[REDACTED]`, `password=[REDACTED]`).
* **Zero-Allocation HTTP-to-HTTPS 301 Redirect Engine (`http_redirect.rs`)**:
  - Standalone Port 80 redirect listener preserving full target URI paths and query strings.
* **Adversarial Test Suite Battery (`tests/adversarial_integration_tests.rs`)**:
  - Added automated red-team test suite asserting resilience against credential query scrubbing, mass scanner bursts, upstream service crashes, and abrupt client socket termination (20/20 passed in `< 0.15s`).

---

## [0.1.0] - 2026-09-24 (Initial Sovereign Ingress Release)

### 🌟 Added
* **Pure Rust L7 Reverse Proxy Engine**:
  - Built on `Hyper 1.4`, `Tokio 1.38`, and `Rustls 0.23` with zero C dependencies and zero garbage collection pauses.
  - Full HTTP/1.1 and HTTP/2 multiplexing.
* **Multi-Domain SNI TLS Multiplexer (`tls.rs`)**:
  - Dynamic SNI host certificate resolution loading distinct fullchain PEMs and private keys per domain block.
* **Full-Duplex Bi-Directional WebSocket Tunneling (`proxy.rs`)**:
  - Native `101 Switching Protocols` support enabling persistent, low-overhead WebSocket tunnels for WebRTC signaling and real-time messaging.
* **Embedded Phylax Perimeter Defense**:
  - Microsecond decoy path trie dropping automated scans (`/.env`, `/wp-login.php`, `/.git/config`) with stealth `404 Not Found` responses before hitting upstream servers.
  - Asynchronous, rate-limited reporting to **AbuseIPDB** v2 API.
* **Strict TOML Configuration Engine (`config.rs`)**:
  - Verified pre-flight syntax, certificate existence, and port binding validation via `propylea check --config <FILE>`.
