# 🚀 Propylea Installation & Multi-Platform Deployment Guide

Propylea is engineered with strict **One-Job-Principle (OJP)** boundaries: zero runtime dependencies, static Musl/GNU/Win32 binaries, and an ultra-lean memory footprint (< 15MB RSS). Whether you are an independent developer deploying your first home server or a systems architect securing high-throughput edge nodes, Propylea runs natively across **Linux**, **Windows**, and **macOS**.

---

## 📋 Multi-Platform Requirements & Parity Matrix

| Platform | Target Architecture | Production Init / Daemon | Memory Footprint (RSS) | Asynchronous Engine |
| :--- | :--- | :--- | :--- | :--- |
| **Linux** | `x86_64`, `aarch64` (Musl / Glibc) | `systemd` / `OpenRC` | `< 12 MB` | `epoll` + `malloc_trim` |
| **Windows** | `x86_64` (PE32+ 64-bit) | Windows Service (`NSSM` / `sc.exe`) | `< 18 MB` | Windows IOCP |
| **macOS** | Apple Silicon (`aarch64`), Intel (`x86_64`) | `launchd` daemon | `< 15 MB` | `kqueue` |

* **Privileged Ports**: HTTP (80) and HTTPS (443)
* **RAM**: ~15 MB RSS
* **Rust Toolchain** (if compiling from source): Rust 1.80+ (`stable`)

---

## ⚡ Method 1: Building from Source

### Native Compilation (Linux & macOS)
```bash
git clone https://github.com/rmediatech/propylea.git
cd propylea

# Build optimized release binary
cargo build --release
```
The resulting binary will be located at `target/release/propylea`.

### Native Compilation on Windows (PowerShell)
```powershell
git clone https://github.com/rmediatech/propylea.git
cd propylea
cargo build --release
```
The resulting executable will be located at `target\release\propylea.exe`.

### Cross-Compiling for Windows from Linux
```bash
# Add mingw toolchain and rust target
rustup target add x86_64-pc-windows-gnu
sudo apt-get install -y mingw-w64

# Cross-compile PE32+ 64-bit binary
cargo build --release --target x86_64-pc-windows-gnu
```
The resulting Windows binary is located at `target/x86_64-pc-windows-gnu/release/propylea.exe`.

---

## 🐧 Method 2: Linux Production Deployment (Systemd)

### 1. Install Binary & Create Directories
```bash
# Install binary into /usr/local/bin
sudo install -m 755 target/release/propylea /usr/local/bin/propylea

# Create configuration directory
sudo mkdir -p /etc/propylea

# Copy example configuration
sudo cp propylea.example.toml /etc/propylea/propylea.toml
```

### 2. Grant Non-Root Port Binding Permissions
Propylea does **not** need to run as `root`. Grant it the Linux capability to bind privileged ports 80 and 443:
```bash
sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/propylea
```

### 3. Create Dedicated Service User
```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin propylea
```

### 4. Create the Systemd Unit File (`/etc/systemd/system/propylea.service`)
```ini
[Unit]
Description=Propylea Sovereign L7 Reverse Proxy & Perimeter Defense
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=propylea
Group=propylea
ExecStartPre=/usr/local/bin/propylea check --config /etc/propylea/propylea.toml
ExecStart=/usr/local/bin/propylea serve --config /etc/propylea/propylea.toml
Restart=always
RestartSec=3s

# Security Hardening & Sandboxing
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/etc/propylea
PrivateTmp=true
ProtectKernelTunables=true
ProtectControlGroups=true

# Resource Limits
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
```

### 5. Enable & Start
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now propylea
sudo systemctl status propylea
```

---

## 🪟 Method 3: Windows Production Deployment

Propylea executes natively on Windows 10/11 and Windows Server (2019, 2022, 2025) utilizing the high-performance Windows I/O Completion Ports (IOCP) runtime.

### 1. Directory Structure Setup (Administrative PowerShell)
```powershell
New-Item -ItemType Directory -Path "C:\Program Files\Propylea" -Force
New-Item -ItemType Directory -Path "C:\ProgramData\Propylea" -Force

Copy-Item ".\target\release\propylea.exe" "C:\Program Files\Propylea\propylea.exe"
Copy-Item ".\propylea.example.toml" "C:\ProgramData\Propylea\propylea.toml"
```

### 2. Configure Windows Defender Firewall
Allow inbound HTTP (80) and HTTPS (443) traffic:
```powershell
New-NetFirewallRule -DisplayName "Propylea HTTP (Port 80)" -Direction Inbound -LocalPort 80 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "Propylea HTTPS (Port 443)" -Direction Inbound -LocalPort 443 -Protocol TCP -Action Allow
```

### 3. Verify Configuration Syntax (Win32 Path Verification)
Validate your TOML configuration syntax without binding network ports:
```powershell
& "C:\Program Files\Propylea\propylea.exe" check --syntax-only --config "C:\ProgramData\Propylea\propylea.toml"
```

### 4. Install as a Background Windows Service (Using NSSM)
To run Propylea 24/7 as an autonomous Windows Service with automatic restart:
```powershell
# Using Chocolatey / Scoop to install NSSM (Non-Sucking Service Manager)
choco install nssm -y

# Register and start Propylea Windows Service
nssm install Propylea "C:\Program Files\Propylea\propylea.exe" "serve --config C:\ProgramData\Propylea\propylea.toml"
nssm set Propylea AppStdout "C:\ProgramData\Propylea\propylea.log"
nssm set Propylea AppStderr "C:\ProgramData\Propylea\propylea.err.log"
nssm set Propylea Start SERVICE_AUTO_START

Start-Service Propylea
Get-Service Propylea
```

---

## 🍏 Method 4: macOS Production Deployment (Launchd)

On macOS (both Apple Silicon M-Series and Intel Darwin), Propylea utilizes Apple's native `kqueue` kernel event notification mechanism.

### 1. Install Binary & Configuration
```bash
sudo mkdir -p /usr/local/bin /etc/propylea /var/log/propylea
sudo cp target/release/propylea /usr/local/bin/propylea
sudo cp propylea.example.toml /etc/propylea/propylea.toml
```

### 2. Create Launchd Daemon (`/Library/LaunchDaemons/com.rmediatech.propylea.plist`)
Because ports 80 and 443 are privileged on macOS, manage Propylea as a system-level daemon:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.rmediatech.propylea</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/propylea</string>
        <string>serve</string>
        <string>--config</string>
        <string>/etc/propylea/propylea.toml</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/propylea/output.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/propylea/error.log</string>
    <key>SoftResourceLimits</key>
    <dict>
        <key>NumberOfFiles</key>
        <integer>65535</integer>
    </dict>
</dict>
</plist>
```

### 3. Load & Start Service
```bash
sudo chown root:wheel /Library/LaunchDaemons/com.rmediatech.propylea.plist
sudo launchctl load -w /Library/LaunchDaemons/com.rmediatech.propylea.plist
sudo launchctl list | grep propylea
```

---

## 🔍 Validation & Syntax Testing

Validate configuration files at any time without disturbing active network listeners:

```bash
# Full verification (syntax, TLS certificates existence & validity)
propylea check --config /etc/propylea/propylea.toml

# Clean-room syntax check (validates TOML schema without requiring certificates)
propylea check --syntax-only --config propylea.example.toml
```

Expected Output:
```text
   ____                               __              
  / __ \_________  ____  __  ______  / /__  ____ _    
 / /_/ / ___/ __ \/ __ \/ / / / / _ \/ / _ \/ __ `/    
/ ____/ /  / /_/ / /_/ / /_/ / /  __/ /  __/ /_/ /     
\/    \/   \____/ .___/\__, /_/\___/_/\___/\__,_/      
               /_/    /____/                           
  Sovereign L7 Reverse Proxy & Perimeter Defense Gate

INFO  🔍 Validating Propylea configuration at 'propylea.toml'...
INFO    • HTTP Redirect Bind:  0.0.0.0:80
INFO    • HTTPS Proxy Bind:    0.0.0.0:443
INFO    • Active Defense:      Enabled
INFO    • Memory Vacuum:       Active (malloc_trim)
INFO    • Hygiene Interval:    300s
INFO    • Verifying 2 configured route(s)...

✅ [PROPYLEA] Configuration is valid and verified.
```
