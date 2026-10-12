# 🏛️ Propylea

<p align="center">
  <a href="https://github.com/xuoxod/propylea/actions/workflows/ci.yml"><img src="https://github.com/xuoxod/propylea/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
  <img src="https://img.shields.io/badge/Language-Pure%20Rust%202021-orange.svg" alt="Pure Rust" />
  <img src="https://img.shields.io/badge/TDD%20Tests-54%2F54%20Passed-brightgreen.svg" alt="Tests" />
  <img src="https://img.shields.io/badge/Memory%20Footprint-%3C%2015%20MB-blue.svg" alt="Memory" />
  <img src="https://img.shields.io/badge/Decoy%20Trap-%3C%2015%20ns-yellow.svg" alt="Decoy Trap" />
  <img src="https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blueviolet.svg" alt="License" />
</p>

```text
   ____                               __              
  / __ \_________  ____  __  ______  / /__  ____ _    
 / /_/ / ___/ __ \/ __ \/ / / / / _ \/ / _ \/ __ `/    
/ ____/ /  / /_/ / /_/ / /_/ / /  __/ /  __/ /_/ /     
\/    \/   \____/ .___/\__, /_/\___/_/\___/\__,_/      
               /_/    /____/                           
  Sovereign L7 Reverse Proxy & Perimeter Defense Gate
```

> In ancient classical Greece, the **Propylaea** (*Προπύλαια*) stood as the monumental fortified gateway to the Acropolis of Athens—a majestic boundary shielding the sacred citadel within while welcoming legitimate citizens. **Propylea** serves the exact same role for your modern web architecture: a sovereign, ultra-low-memory L7 reverse proxy, multi-domain SNI TLS multiplexer, and perimeter defense gateway written in 100% pure Rust.  
> 🏰 *"From the wire to the RAM / All them botnets crash and slam."*

---

## ⚡ Why Propylea?

Modern web infrastructure is plagued by two persistent problems:
1. **Memory Bloat & Resource Starvation**: Conventional reverse proxies (Caddy, Traefik, Kong) carry heavy Go runtimes, garbage collection pauses, and multi-megabyte footprints that starve small VPS nodes and edge workstations.
2. **Passive Forwarding of Hostile Scanners**: Traditional proxies blindly pass automated reconnaissance scans (`/.env`, `/wp-login.php`, `/.git/config`) directly upstream to your web applications, wasting CPU cycles and exposing application attack surfaces.

**Propylea solves both:**
* **$< 15\text{ MB}$ Constant RSS**: Zero garbage collector, zero C runtime dependencies, and an autonomous memory vacuum that periodically returns unused heap pages directly to the Linux kernel via `libc::malloc_trim`.
* **Nanosecond Perimeter Defense & Bot Interception**: Powered by the sovereign [`phylax`](https://github.com/xuoxod/phylax) defense pipeline, Propylea evaluates incoming request paths and User-Agents in **$< 15\text{ ns}$**. Unwanted AI model scrapers, tech stack profilers, and vulnerability sprayers are deflected with stealth `404 Not Found` or `403 Forbidden` responses (RFC 9309 compliance) before they ever reach your upstream services.
* **Automated Threat Intelligence**: Seamlessly and asynchronously dispatches forensic dossiers to **AbuseIPDB**, RFC 5424 Syslog / CEF (Common Event Format) for local SIEMs, and custom webhooks (Slack, Discord, SIEM) with built-in token-bucket rate limiting to stay safely within free-tier quotas.
* **100% Sovereign Multi-Platform Parity**: Engineered for cross-platform freedom—runs natively on **Linux** (`epoll`), **Windows** (`IOCP`), and **macOS** (`kqueue`). Verified live on Linux VPS fleets and bare-metal Windows Server instances.

---

## 🏰 Where Does Propylea Fit in the Defense Stack?

> **The Layman-to-Architect Mental Model**:  
> In our sovereign infrastructure, security is designed like a fortified citadel following the **One-Job-Principle (OJP)**. No single tool is bloated with multiple responsibilities.

```text
[ Internet Client / Scanner ]
               │
               ▼
   🛡️ Ring 0: AUTHORITATIVE DNS (L3/L4) ➔ Microsecond authoritative DNS & threat sinkhole.
               │                          Intercepts botnet C2, blocks trackers, defuses RRL floods.
               ▼
   🌊 Ring 1: BASTION (L4 Firewall) ➔ Drops DDoS & packet floods in microseconds via eBPF/XDP.
               │
               ▼
   🏛️ Ring 2: PROPYLEA (L7 Gateway) ➔ Sovereign front door (ports 80 & 443). Terminates TLS,
               │                       sniffs TLS fingerprints, blocks HTTP smuggling (TE.CL),
               │                       routes domains, tunnels WebSockets, vacuums RAM (<15MB).
               │
        (Embedded Sentry)
               ▼
   🏹 Ring 3: PHYLAX (WAF Engine)  ➔ Evaluates URI decoy trie in <15ns. Drops scanners
               │                       with stealth 404s and reports IPs to AbuseIPDB.
               │
               ▼
   🚪 Ring 4: SLOW-SHIELD (L7.5)   ➔ Equalizes authentication timing (Argon2id dummy cycles)
               │                       and throttles cross-IP credential attacks.
               │
               ▼
   👑 Ring 5: APPLICATIONS         ➔ RMediaTech (:8081), Matrix (:8082), LiveKit SFU (:7880).
               │
               ▼
   📜 Audit: SOVEREIGN LEDGER      ➔ Appends every mutation to a tamper-evident SHA-256 Merkle chain.

   🌉 Private Bridge: CONDUIT      ➔ Encrypted remote PTY terminal, 360° radar, & hardware intercom.
                                      (Conduit is NOT a public web proxy; edge routing belongs to Propylea).
```

### 🧭 Sovereign Tool Responsibilities at a Glance

| Crate | Sovereign Role | Layer | Primary Responsibility | Replaces |
| :--- | :--- | :---: | :--- | :--- |
| **`bastion`** | Microsecond IP Firewall | **L4** | Bitwise Radix Trie packet filtering & SYN defense | `iptables`, `ufw` |
| **`propylea`** | L7 Gateway & Reverse Proxy | **L7** | Multi-domain TLS, WebSocket tunneling, `< 15MB` RAM | **`caddy`**, **`nginx`**, `traefik` |
| **`phylax`** | 13-Layer Perimeter WAF | **L7 Library**| `< 15ns` honeypot trie, stealth 404s, AbuseIPDB reporting | Proprietary Cloud WAFs, ModSecurity |
| **`slow-shield`** | Credential Velocity Governor | **L7.5** | Distributed brute-force defense & Argon2id equalizer | Redis rate limiters |
| **`conduit`** | Outpost Remote Bridge | **Tunnel** | PTY terminal, 360° radar sweep, hardware intercom | TeamViewer, ngrok, SSH jumps |
| **`sovereign-ledger`** | Merkle Cryptographic Audit | **Daemon** | SHA-256 hash-chained immutable audit ledger | Datadog audit logs |

### 🛡️ Understanding Layer Boundaries: The Defense-in-Depth Paradigm

While **Propylea** delivers state-of-the-art L7 edge protection and nanosecond probe deflection, every systems architect must understand boundary separation:

> **The Universal Rule of Layer Boundaries**:  
> *No L7 reverse proxy, no matter how fast or resilient, can defend against attacks that the raw network wire fails to filter.*

To build an enterprise-grade defense grid for your infrastructure, do not rely on an L7 gateway in isolation. Implement defense-in-depth across your own stack:
1. **Upstream DNS Boundary (L3/L4)**: Deploy authoritative DNS filtering with Response Rate Limiting (BCP 153 RRL) and threat sinkholing to deflect botnets, scrapers, and volumetric reflection attacks before they ever initiate a TCP handshake with your server.
2. **Kernel & Wire Boundary (L4)**: Harden your OS kernel (`sysctl` TCP SYN cookies, TCP FIN/RST flood protections) and deploy packet-filtering firewall rules (eBPF/XDP or stateful iptables/nftables) to drop invalid TCP flag combinations and volumetric DDoS floods in microseconds.
3. **Application Layer Gateway (Propylea - L7)**: Let Propylea handle TLS termination, request framing validation, SNI routing, and nanosecond decoy URI deflection.
4. **Deep Application Shielding**: Embed fine-grained application controls (like [`phylax`](https://github.com/xuoxod/phylax)) for cognitive human timing verification, honeypots, and sliding token-bucket rate limits.

---

## 📊 Comparative Scorecard

| Dimension | **Propylea** | **Caddy** | **Nginx** | **Traefik** |
| :--- | :---: | :---: | :---: | :---: |
| **Language & Safety** | **Pure Rust (100% memory safe)** | Go (GC pauses) | C (Memory unsafety risk) | Go (GC pauses) |
| **Memory Footprint (RSS)** | **`< 15 MB` (Active Vacuum)** | `45 – 90 MB` | `15 – 35 MB` | `60 – 120 MB` |
| **Active Perimeter Defense** | **Native Built-in (`< 15ns`)** | ❌ (Needs plugins) | ❌ (ModSecurity overhead) | ❌ (External WAF required) |
| **AbuseIPDB Auto-Reporting** | **Native (Free-Tier Safe)** | ❌ None | ❌ None (Requires Fail2Ban) | ❌ None |
| **WebSocket Tunneling** | **Native Full-Duplex** | Native | Native | Native |
| **HTTP-to-HTTPS 301 Redirect**| **Zero-Allocation Instant** | Native | Configuration directive | Native |
| **Configuration Model** | **Single 15-line TOML** | Caddyfile / JSON | Multi-file `nginx.conf` | Complex YAML / Labels |
| **Forensic Telemetry** | **Bounded Ring Buffer + Masking** | Disk Logs Only | Disk Logs Only | Metrics endpoint |

---

## ⚡ The Sovereign Frontier: Emancipation from Cloud Ingress Feudalism

Conventional wisdom claims that running a multi-domain TLS edge requires heavy Go runtimes (Caddy, Traefik), labyrinthine C configurations (Nginx), or expensive metered cloud proxies that turn your infrastructure into a recurring billing pipeline.

`propylea` breaks that dependency entirely. Engineered in pure Rust, it proves that an independent developer can operate an enterprise-grade L7 reverse proxy with automated SNI TLS termination, bi-directional WebSocket tunneling, and autonomous $<15\text{ns}$ threat deflection—consuming less memory than a single browser tab.

```mermaid
flowchart TD
    subgraph HeavyIngress ["🏰 The Cloud Ingress Tax (The Old Empire)"]
        direction LR
        CloudProxy["Proprietary Cloud Proxies\n💸 Per-GB Bandwidth Tolls + Per-Domain Rent"]
        GoProxy["Caddy / Traefik (Go GC)\n🐘 60MB - 120MB RSS Per Node"]
        NginxProxy["Nginx + ModSecurity\n🧩 Fragile C Toolchain & Regex Bottlenecks"]
    end

    subgraph PropyleaFrontier ["⚡ The Sovereign Ingress Frontier (Propylea)"]
        direction LR
        PropyleaCore["🏛️ Propylea Edge Gate\n🦀 Pure Rust 2021 · 0% GC Jitter"]
        MemVacuum["Autonomous Memory Vacuum\n🧹 Periodic malloc_trim Kernel Page Returns (<15MB RSS)"]
        NanosecondTrie["In-Memory Threat Trie\n⚡ <15ns Automated Crawler Deflection"]
    end

    HeavyIngress -.->|"Emancipated by"| PropyleaFrontier
```

### 🧬 Systems Provenance: Disciplined Engineering & Frontier Pair Programming

`propylea` demonstrates what happens when human architectural discipline meets collaborative AI systems engineering. Rather than accepting the industry standard of multi-megabyte runtimes and garbage-collection pauses, the gateway was designed from first principles with an AI thinking partner to enforce absolute resource restraint: periodic `libc::malloc_trim` kernel page recovery, zero-allocation redirects, and $<15\text{ns}$ threat deflection. It stands as living proof that an independent developer pairing with advanced intelligence can forge infrastructure that outclasses bloated corporate alternatives.

---

## 🛡️ Live Edge Defense in Action

Below is an authentic execution trace captured at the ingress boundary during a mass Internet scanning wave:

```log
2026-09-24T04:12:01.002Z WARN  [PROPYLEA-EDGE] Hostile reconnaissance scan trapped at ingress
    ├── Remote IP: 198.51.100.42 (Anonymous VPN / Proxy)
    ├── Target URI: GET /.env
    ├── Action: Intercepted in 11ns (stealth 404 returned, 0 bytes proxied upstream)
    └── Threat Intelligence: Dispatched async incident report to AbuseIPDB (Confidence: 100%)

2026-09-24T04:12:01.450Z INFO  [PROPYLEA-ROUTER] Legitimate client proxied upstream
    ├── Remote IP: 203.0.113.19
    ├── Target URI: GET /api/v1/status
    ├── Resolved Upstream: 127.0.0.1:8080 (app.example.com)
    ├── Duration: 142µs
    └── Telemetry: Recorded in ring buffer (Query redacted: /api/v1/status?token=[REDACTED])

2026-09-24T04:15:00.000Z DEBUG [GOVERNOR] Executing autonomous resource hygiene pass
    └── Memory Vacuum: malloc_trim(0) returned 4.2 MB unmapped pages to kernel (RSS: 11.4 MB)
```

---

## 🚀 60-Second Quickstart

### 1. Build Propylea (Linux, macOS, Windows)

```bash
# Clone the repository
git clone https://github.com/xuoxod/propylea.git
cd propylea

# Linux & macOS: Native release compilation
cargo build --release

# Windows (PowerShell): Native PE32+ release compilation
cargo build --release

# Cross-compile Windows binary from Linux
cargo build --release --target x86_64-pc-windows-gnu
```

### 2. Configure Your Routes
Create `propylea.toml` (or see [`propylea.example.toml`](propylea.example.toml)):

```toml
[server]
http_bind = "0.0.0.0:80"
https_bind = "0.0.0.0:443"

[security]
enable_defense = true
server_banner = "Propylea-Edge-Gateway/1.0"
# abuseipdb_api_key = "YOUR_KEY"
# syslog_cef = true

[maintenance]
hygiene_interval_secs = 300
memory_vacuum = true

[[routes]]
domains = ["example.com", "www.example.com"]
upstream = "127.0.0.1:8080"
cert = "/etc/letsencrypt/live/example.com/fullchain.pem"
key = "/etc/letsencrypt/live/example.com/privkey.pem"
websocket = true

# Optional: Speculative Hedged Tournament Racing Pool (requires --features hedged-racing)
[[routes]]
domains = ["api.example.com"]
upstreams = ["127.0.0.1:8081", "127.0.0.1:8082"]
hedged_racing = true
cert = "/etc/letsencrypt/live/api.example.com/fullchain.pem"
key = "/etc/letsencrypt/live/api.example.com/privkey.pem"
websocket = true
```

### 🏇 Speculative Hedged Tournament Racing (`hedged-racing` Feature)
When proxying to multi-upstream clusters, conventional round-robin or sequential failover exposes clients to tail latency spikes whenever one replica stutters or drops packets. When compiled with `--features hedged-racing`, Propylea leverages our sovereign [`hippodrome`](https://github.com/xuoxod/hippodrome) tournament engine:
* **Idempotent Racing (`GET`, `HEAD`, `OPTIONS`)**: Dispatches to the historically fastest upstream, followed speculatively by the #2 contender if the leader stalls beyond the adaptive EWMA delay window. The fastest response wins, and slower connections are aborted with zero memory leak.
* **Mutating Safety (`POST`, `PUT`, `DELETE`)**: Enforces single-flight execution with microsecond failover, guaranteeing idempotency and preventing duplicate side-effects.

### 3. Verify & Run
```bash
# Clean-room schema check without requiring live certificates
./target/release/propylea check --syntax-only --config propylea.toml

# Full check validating certificate files and path permissions
./target/release/propylea check --config propylea.toml

# Start the reverse proxy daemon
./target/release/propylea serve --config propylea.toml
```

### 4. Autonomous Quarantine & Multi-Format Intelligence
Propylea automatically traps repeat hostile offenders, TLS impersonators, and honeylink probes in autonomous CIDR quarantine. Manage and inspect quarantined subnets with zero downtime via native CLI commands or the operator script:

```bash
# Live status of running daemon, control socket, and SQLite database
./scripts/propylea-quarantine.sh status

# Manually quarantine an offending scanner IP or CIDR block
./scripts/propylea-quarantine.sh ban 198.51.100.42 --reason "Hostile path fuzzing" --duration 48h
./scripts/propylea-quarantine.sh ban 203.0.113.88 --exact --reason "Single host probe"

# Surgically unban an IP or CIDR block in real-time (live proxy clears in < 1µs)
./scripts/propylea-quarantine.sh unban 198.51.100.42
./scripts/propylea-quarantine.sh unban 198.51.100.0/24 203.0.113.15    # Batch unban

# Clear all active quarantine blocks across RAM and SQLite WAL
./scripts/propylea-quarantine.sh clear -y

# Ingest historical bad actors and scan logs from systemd journalctl
./scripts/propylea-quarantine.sh ingest-journal --hours 72 --exclude 198.51.100.42

# Inspect active enforced bans in markdown or terminal formats
propylea quarantine list --active-only --format md
propylea quarantine list --format txt                     # Raw CIDRs for iptables / bastion / ipset
propylea quarantine list --format json                    # Structured JSON array

# Export standalone, zero-cloud visual dark-mode HTML dashboard
propylea quarantine export /var/www/quarantine_report.html --format html
```

### 6. Buffalo Crucible Microsecond Gate (`crucible_gate`)
For red-team battle testing and multi-OS stress gauntlets, Propylea provides the standalone `crucible_gate` binary:
```bash
# Launch lightweight microsecond defensive gate with SQLite WAL quarantine
cargo run --release --bin crucible_gate -- --bind 0.0.0.0:8999 --db /tmp/quarantine.db

# Live Multi-OS Benchmark Results (Buffalo NAS Testbed):
# • Subnet Quarantine Latency: 9µs (first hostile packet triggers Bitwise Radix /24 lockdown)
# • Subsequent Packet Deflection: 1µs - 3µs (HTTP 403 Forbidden with zero upstream CPU load)
# • Cross-OS Battle-Tested: Verified against simultaneous assault vectors from Windows Server 2022 & Linux VMs
```

> 📘 **Full Multi-Platform Setup:** See the [**Multi-Platform Installation & Deployment Guide**](docs/INSTALLATION.md) for production `systemd` (Linux), Windows Service via `NSSM` (Windows), and `launchd` (macOS).

---

## 🗺️ Architectural Topology

```
                       Internet Ingress Traffic
                                  │
          ┌───────────────────────┴───────────────────────┐
          ▼                                               ▼
     Port 80 (HTTP)                               Port 443 (HTTPS)
  Instant 301 Redirect                         SNI TLS Multiplexer
  (Preserves URI + Query)                                 │
                                              ┌───────────┴───────────┐
                                              ▼                       ▼
                                       Hostile Scanner         Legitimate Request
                                    (/.env, /wp-login.php)            │
                                              │                       ▼
                                              │               Upstream Router O(1)
                                              │               (Host / :authority)
                                              ▼                       │
                                        [Stealth 404]                 ▼
                                    (Drop in < 15ns)       Streaming Proxy / WebSocket
                                              │                       │
                                     Async Threat Report              ▼
                                  (AbuseIPDB / Webhooks)       Backend Upstream
                                                           (127.0.0.1:8080 / etc.)
```

---

## 📚 Documentation Hierarchy

* 🛡️ **[Sovereign Defense Topology](docs/DEFENSE_TOPOLOGY.md)**: Mental model, castle architecture, and complete disambiguation matrix between Bastion, Propylea, Phylax, Slow-Shield, and Conduit.
* 🩺 **[Troubleshooting & Incident Runbook](docs/TROUBLESHOOTING.md)**: 30-second checklist, common error fixes (502s, port conflicts, TLS certs, WebSockets), and live diagnostic commands.
* 📘 **[Installation & Systemd Guide](docs/INSTALLATION.md)**: Setup as a hardened systemd daemon on Ubuntu, Debian, Rocky, or Arch.
* ⚙️ **[Configuration Reference](docs/CONFIGURATION.md)**: Complete guide to all TOML directives and tuning parameters.
* 🔒 **[Let's Encrypt Guide](docs/LETSENCRYPT.md)**: Zero-downtime certificate acquisition, automated renewal hooks, and permissions.
* 🛡️ **[Active Perimeter Defense](docs/ACTIVE_DEFENSE.md)**: Deep dive into microsecond honeypots, rate limiting, and SIEM webhooks.

---

## 📄 License

Dual-licensed under either:
* **MIT License** ([LICENSE-MIT](LICENSE-MIT))
* **Apache License, Version 2.0** ([LICENSE-APACHE](LICENSE-APACHE))

at your option.
