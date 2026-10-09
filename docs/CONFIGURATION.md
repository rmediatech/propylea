# ⚙️ Propylea Configuration Reference

Propylea uses a single, human-readable TOML configuration file. The configuration is strictly parsed and verified before socket binding, guaranteeing that bad syntax, missing TLS certificates, or unparseable keys fail fast during deployment.

---

## 📄 Complete Example Configuration

```toml
[server]
http_bind = "0.0.0.0:80"
https_bind = "0.0.0.0:443"
# worker_threads = 4  # Optional: defaults to logical CPU cores

[security]
enable_defense = true
abuseipdb_api_key = "YOUR_ABUSEIPDB_API_KEY"
webhook_url = "https://hooks.slack.com/services/T00/B00/X00"
server_banner = "Propylea-Edge-Gateway/1.0"
hsts = true
frame_options = "DENY"

[maintenance]
hygiene_interval_secs = 300
max_telemetry_records = 10000
memory_vacuum = true

[[routes]]
domains = ["example.com", "www.example.com"]
upstream = "127.0.0.1:8080"
cert = "/etc/letsencrypt/live/example.com/fullchain.pem"
key = "/etc/letsencrypt/live/example.com/privkey.pem"
websocket = true

[[routes]]
domains = ["api.example.com"]
upstream = "127.0.0.1:8081"
cert = "/etc/letsencrypt/live/api.example.com/fullchain.pem"
key = "/etc/letsencrypt/live/api.example.com/privkey.pem"
websocket = false
```

---

## 🏷️ Section: `[server]`

Controls network socket binding and Tokio runtime worker distribution.

| Directive | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `http_bind` | `String` (`SocketAddr`) | `"0.0.0.0:80"` | Socket address for the Port 80 HTTP-to-HTTPS 301 redirect engine. |
| `https_bind` | `String` (`SocketAddr`) | `"0.0.0.0:443"` | Socket address for the Port 443 TLS reverse proxy listener. |
| `worker_threads`| `Integer` (Optional) | System CPU count | Tokio runtime worker thread limit. |

---

## 🛡️ Section: `[security]`

Controls the active edge perimeter defense pipeline, automated incident reporting, and downstream client hardening headers.

| Directive | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `enable_defense` | `Boolean` | `true` | Enables the sovereign edge perimeter defense pipeline. Traps automated vulnerability scanners and hostile probes in $<15\text{ns}$. |
| `abuseipdb_api_key` | `String` (Optional) | `None` | AbuseIPDB API v2 reporting key. Automatically dispatches reports for trapped hostile attackers with zero impact on request latency. |
| `webhook_url` | `String` (Optional) | `None` | Generic HTTPS webhook URL (Discord, Slack, Microsoft Teams, SIEM) for incident alerting. |
| `syslog_cef` | `Boolean` | `false` | Enables air-gapped RFC 5424 Syslog / CEF (Common Event Format) logging for enterprise SIEM integration (Wazuh, Splunk) without external HTTP requests. |
| `server_banner` | `String` | `"Propylea-Edge-Gateway/1.0"` | Obfuscated downstream `Server` HTTP header to prevent reconnaissance fingerprinters from discovering your tech stack. |
| `hsts` | `Boolean` | `true` | Injects `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`. |
| `frame_options` | `String` | `"DENY"` | Injects `X-Frame-Options` (`DENY` or `SAMEORIGIN`) to prevent clickjacking. |

---

## 🧹 Section: `[maintenance]`

Governs autonomous self-maintenance, preventing memory leaks, heap fragmentation, and runaway memory usage during long-running production service.

| Directive | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `hygiene_interval_secs` | `Integer` | `300` (5 min) | Frequency in seconds between autonomous memory hygiene passes. |
| `max_telemetry_records` | `Integer` | `10000` | Bounded capacity of the in-memory telemetry ring buffer. Older records are evicted in $O(1)$ time. |
| `memory_vacuum` | `Boolean` | `true` | On Linux, invokes `libc::malloc_trim(0)` during hygiene passes, returning unmapped heap pages directly to the OS kernel. Keeps idle memory footprint $<15\text{MB}$. |

---

## 🔀 Section: `[[routes]]` (Array of Tables)

Defines multi-domain virtual hosts, TLS certificate bindings, and backend upstream destinations. Multiple `[[routes]]` tables can be declared.

| Directive | Type | Required | Description |
| :--- | :--- | :--- | :--- |
| `domains` | `Array<String>` | **Yes** | Hostnames / SNI domain names handled by this route (e.g. `["example.com", "www.example.com"]`). |
| `upstream` | `String` (`SocketAddr`)| **Yes** | Destination backend IP and port (e.g. `"127.0.0.1:8080"`). |
| `cert` | `String` (`Path`) | **Yes** | Absolute or relative path to the PEM-encoded TLS certificate fullchain. |
| `key` | `String` (`Path`) | **Yes** | Absolute or relative path to the PEM-encoded TLS private key (PKCS#8, PKCS#1, or SEC1). |
| `websocket` | `Boolean` | `true` | Enables transparent bi-directional WebSocket upgrade tunneling for real-time protocols. |

---

## 🔍 Validation CLI Command

Test any configuration file before deploying:

```bash
propylea check --config /path/to/propylea.toml
```

If any certificates or private keys are missing, corrupt, or unreadable, Propylea prints an exact diagnostic error and returns exit code 1.
