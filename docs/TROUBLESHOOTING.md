# 🩺 Propylea Troubleshooting, Diagnostics & Incident Runbook

> **The Sovereign Operator's Rapid Triage Field Manual**  
> Written for developers, sysadmins, and systems architects to resolve edge proxy, TLS, routing, and defense issues in seconds.

---

## ⚡ 1. The 30-Second Diagnostic Checklist

When investigating any connectivity or routing issue, run through these 5 rapid checks in order:

```text
[1] Is the Propylea process running?
    systemctl status propylea  (or: pgrep -la propylea)

[2] Are ports 80 and 443 actively bound?
    ss -tulpn | grep -E ':80 |:443 '

[3] Does the configuration pass strict validation?
    propylea check --config /etc/propylea/propylea.toml

[4] Is the upstream application healthy and listening?
    curl -I http://127.0.0.1:<upstream_port>/healthz

[5] What are the live gateway logs saying?
    journalctl -u propylea -n 50 --no-pager -f
```

---

## 🔍 2. Common Scenarios & Immediate Solutions

### Scenario A: `502 Bad Gateway: Upstream Unavailable`
* **Symptoms**: Clients receive a clean `502 Bad Gateway` error page when requesting a domain.
* **Root Cause**: Propylea received the request, matched the domain, but could not establish a TCP connection to the configured upstream IP/port.
* **Immediate Fixes**:
  1. Check your upstream service status (e.g. `systemctl status sovereign-app` or `systemctl status livekit`).
  2. Verify that the port in `/etc/propylea/propylea.toml` matches the port your app is listening on:
     ```bash
     # Check what is actually listening locally
     ss -tulpn | grep 127.0.0.1
     ```
  3. Test direct local connection to the upstream port:
     ```bash
     curl -v http://127.0.0.1:8081/healthz
     ```
  4. Ensure your upstream service is bound to `127.0.0.1` or `0.0.0.0` (not an external interface only).

---

### Scenario B: `Address already in use (os error 98)`
* **Symptoms**: Propylea fails to start with:
  `Error: I/O error: Address already in use (os error 98)`
* **Root Cause**: Another service is already holding port 80 or 443. This commonly happens if Nginx, Caddy, Apache, or Conduit is still running.
* **Immediate Fixes**:
  1. Identify the competing process:
     ```bash
     sudo ss -tulpn | grep -E ':80 |:443 '
     ```
  2. If Nginx is running:
     ```bash
     sudo systemctl stop nginx
     sudo systemctl disable nginx
     ```
  3. If Conduit or Caddy is running on ports 80/443:
     ```bash
     sudo systemctl stop conduit
     sudo systemctl stop caddy
     ```
  4. Start Propylea again:
     ```bash
     sudo systemctl start propylea
     ```

---

### Scenario C: `Permission Denied binding to port 80/443`
* **Symptoms**: Starting Propylea as a non-root user fails with:
  `Permission denied (os error 13)`
* **Root Cause**: Linux restricts ports `< 1024` to `root` by default.
* **Immediate Fixes**:
  Grant Propylea the Linux kernel capability to bind low ports without running as root:
  ```bash
  sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/propylea
  ```
  Verify the capability is set:
  ```bash
  getcap /usr/local/bin/propylea
  # Expected output: /usr/local/bin/propylea cap_net_bind_service=ep
  ```

---

### Scenario D: `TLS Handshake Error / Certificate Mismatch`
* **Symptoms**: Browser reports `SSL_ERROR_BAD_CERT_DOMAIN` or `PR_END_OF_FILE_ERROR`.
* **Root Cause**: Missing certificate file, unreadable file permissions, or the domain requested in the browser does not match any entry in `domains = [...]`.
* **Immediate Fixes**:
  1. Run the strict config check:
     ```bash
     propylea check --config /etc/propylea/propylea.toml
     ```
     This validates whether every certificate and private key file exists, is valid PEM, and can be read by the current user.
  2. Ensure the `propylea` user has read permission on `/etc/letsencrypt/live/...`:
     ```bash
     sudo chmod 755 /etc/letsencrypt/live /etc/letsencrypt/archive
     sudo chmod 644 /etc/letsencrypt/live/*/fullchain.pem
     sudo chmod 640 /etc/letsencrypt/live/*/privkey.pem
     sudo chgrp propylea /etc/letsencrypt/live/*/privkey.pem
     ```
  3. Ensure the domain requested by the client is included in the route's `domains` array.

---

### Scenario E: `WebSocket Connection Drops / 1006 Abnormal Closure`
* **Symptoms**: Real-time apps (LiveKit WebRTC signaling, Matrix sync, chat websockets) fail to connect or disconnect immediately upon connecting.
* **Root Cause**: `websocket = true` is either missing from the route block, or the upstream server does not return `HTTP/1.1 101 Switching Protocols`.
* **Immediate Fixes**:
  1. Inspect `/etc/propylea/propylea.toml` under the relevant route:
     ```toml
     [[routes]]
     domains = ["sfu.example.org"]
     upstream = "127.0.0.1:7880"
     cert = "/etc/letsencrypt/live/sfu.example.org/fullchain.pem"
     key = "/etc/letsencrypt/live/sfu.example.org/privkey.pem"
     websocket = true  # <-- MUST BE TRUE
     ```
  2. Reload Propylea:
     ```bash
     sudo systemctl restart propylea
     ```

---

### Scenario F: `Legitimate Endpoint Returning 404 (Perimeter Trap False Positive)`
* **Symptoms**: A normal user or internal webhook receives a stealth `404 Not Found` even though the upstream application provides that URL.
* **Root Cause**: The URL matches a known scanner decoy pattern in the embedded Phylax threat trie (e.g. `/.env`, `/.git`, `/admin/config.php`, `/wp-login.php`).
* **Immediate Fixes**:
  1. Check the logs to see if the path was intercepted by the defense engine:
     ```bash
     journalctl -u propylea | grep "Hostile reconnaissance scan trapped"
     ```
  2. If an internal tool legitimately requires one of these paths (e.g., `/admin`), change the route path in your upstream application to a sovereign, custom path (e.g., `/dashboard` or `/control`). The decoy trie intentionally prevents access to common default attack vectors.
  3. To temporarily test whether defense is causing the issue, disable defense in `/etc/propylea/propylea.toml`:
     ```toml
     [security]
     enable_defense = false
     ```
     and restart Propylea.

---

### Scenario G: `All Requests from Local IP/Subnet Returning Stealth 404 (CLI Spoofing Friendly Fire)`
* **Symptoms**:
  - Legitimate desktop and mobile browsers (e.g. Google Chrome, Safari, Edge) from a development workstation or local network suddenly receive `404 Not Found` (14-byte response body) for *every* URL on the domain (including root `/`, `/healthz`, and static assets).
  - Upstream backend applications are completely healthy and responsive when tested locally on the server (`curl http://127.0.0.1:<upstream_port>/healthz`).
  - Probes from external networks (e.g., mobile cellular hotspot) connect and load normally.
* **Root Cause**:
  - A developer or automated script on that local network executed an HTTP request with a browser User-Agent header (e.g., `curl -A "Mozilla/5.0 ... Chrome/..." https://example.com/`).
  - Propylea's wire-level TLS engine (`src/tls_fingerprint.rs`) inspected the TLS ClientHello at ingress, detected that OpenSSL or standard CLI libraries lack RFC 8701 GREASE ciphers, and flagged the request as `UserAgentCoherenceVerdict::Spoofed`.
  - Autonomous Subnet Quarantine quarantined the originating public IP in memory for 24 hours. Because all devices in the office or home network share the same public gateway IP via NAT, all subsequent browser requests from that network are immediately deflected at Layer 0 ingress.
* **Immediate Fixes & Runbook**:
  1. Verify the TLS spoofing alarm in gateway logs:
     ```bash
     journalctl -u propylea -n 100 --no-pager | grep -E "PROPYLEA-TLS-SPOOF|quarantined"
     ```
     Expected log output:
     ```text
     WARN [PROPYLEA-TLS-SPOOF] ip=198.51.100.42 ... reason="User-Agent claims modern Chrome/Safari/Edge browser, but TLS ClientHello lacks mandatory RFC 8701 GREASE signatures..."
     WARN [PROPYLEA-EDGE] ip=198.51.100.42 ... reason="Client subnet quarantined due to hostile ingress infractions"
     ```
  2. Unquarantine the IP or Subnet Instantly (Zero Downtime, Zero Restarts):
     Use Propylea's live IPC quarantine unban command:
     ```bash
     propylea quarantine unban 198.51.100.42
     ```
     Or batch unquarantine multiple targets at once:
     ```bash
     propylea quarantine unban 198.51.100.42 198.51.100.0/24
     ```
     *The live proxy receives the command over the local Unix Domain Socket control bridge, instantaneously purges the subnet from RAM fast-path (< 1µs), and marks it inactive in SQLite WAL. Traffic immediately resumes without dropping active connections.*

  3. Alternatively, Clear All Active Bans in One Shot:
     ```bash
     propylea quarantine clear
     ```
     *(Or restart the daemon if preferred: `sudo systemctl restart propylea`).*

  4. Prevent CLI friendly fire going forward:
     - When testing from CLI or automated scripts, do **not** spoof modern browser User-Agents with `curl` or scripting tools. Propylea happily admits honest CLI tools (e.g., standard `curl`, `curl -A "MyScout/1.0"`, etc.); it strictly punishes and quarantines clients attempting to disguise themselves as modern browsers with mismatched TLS ClientHello profiles.
     - For end-to-end browser automation testing, use genuine headless browser engines (such as Playwright or Puppeteer) that utilize authentic Chromium/WebKit TLS network stacks.

---

## 🛠️ 3. Verification & Live Testing Commands

### Test 1: Verify HTTP to HTTPS 301 Redirect
```bash
curl -I http://example.com
```
*Expected Output:*
```http
HTTP/1.1 301 Moved Permanently
location: https://example.com/
server: Propylea-Edge-Gateway/1.0
```

---

### Test 2: Verify Active Defense Decoy Trap
Send a simulated hostile probe:
```bash
curl -I https://example.com/.env
```
*Expected Output:*
```http
HTTP/2 404 Not Found
server: Propylea-Edge-Gateway/1.0
```
*And in the server logs:*
```text
WARN [PROPYLEA-EDGE] Hostile reconnaissance scan trapped at ingress
     ├── Remote IP: <your_ip>
     ├── Target URI: GET /.env
     └── Action: Intercepted in 11ns (stealth 404 returned, 0 bytes proxied upstream)
```

---

### Test 3: Check Memory Footprint (RSS)
```bash
ps -o pid,rss,vsz,comm -p $(pgrep propylea)
```
*Expected Output:*
```text
  PID   RSS    VSZ COMMAND
58059 11420 184500 propylea
```
*RSS should remain `< 15,000 KB` (`< 15 MB`).*

---

### Test 4: Manually Trigger Memory Vacuum
Propylea automatically runs memory hygiene every `hygiene_interval_secs` (default 300s). You can check hygiene passes in the journal:
```bash
journalctl -u propylea | grep "GOVERNOR"
```
*Expected Output:*
```text
DEBUG [GOVERNOR] Executing autonomous resource hygiene pass
      └── Memory Vacuum: malloc_trim(0) returned unmapped pages to kernel
```

---

### Test 5: Inspect and Manage Autonomous Quarantine
Check active defense status, inspect quarantined entities, or surgically unban an IP:

```bash
# 1. Inspect daemon control socket and database
./scripts/propylea-quarantine.sh status

# 2. List currently active bans in markdown or terminal format
./scripts/propylea-quarantine.sh list --active-only

# 3. Surgically unquarantine an operator IP address
./scripts/propylea-quarantine.sh unban 198.51.100.42

# 4. Manually quarantine an offending scanner subnet
./scripts/propylea-quarantine.sh ban 203.0.113.50 --reason "Hostile path fuzzing" --duration 48h

# 5. Ingest past offenders from journalctl into persistent storage
./scripts/propylea-quarantine.sh ingest-journal --hours 72 --exclude 198.51.100.42

# 6. Clear all active bans across RAM and SQLite in an emergency
./scripts/propylea-quarantine.sh clear -y
```

