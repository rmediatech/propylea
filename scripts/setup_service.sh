#!/usr/bin/env bash
# ==============================================================================
# Propylea Automated Production Setup & Service Manager
# Standard: AGY-RULE-SOVEREIGN-FLAGSHIP-01
# ==============================================================================
set -euo pipefail

SCRIPT_SOURCE="${BASH_SOURCE[0]-}"
[ -z "$SCRIPT_SOURCE" ] && SCRIPT_SOURCE="$0"
SCRIPT_DIR="$(cd "$(dirname "$SCRIPT_SOURCE")" 2>/dev/null && pwd || echo "$PWD")"
WORKSPACE_ROOT="${SCRIPT_DIR}/.."
BIN_DEST="/usr/local/bin/propylea"
CONF_DIR="/etc/propylea"
CONF_FILE="${CONF_DIR}/propylea.toml"
SERVICE_FILE="/etc/systemd/system/propylea.service"
ACME_DIR="/var/www/letsencrypt/.well-known/acme-challenge"

echo "================================================================================"
echo "  🏛️  PROPYLEA PRODUCTION SETUP & SERVICE ORCHESTRATOR"
echo "================================================================================"

show_help() {
    echo "Usage: ./setup_service.sh [OPTIONS]"
    echo ""
    echo "Automated production installation and systemd registration for Propylea."
    echo ""
    echo "Options:"
    echo "  -n, --dry-run   Simulate actions without executing privileged commands"
    echo "  -h, --help      Display this help menu and exit"
    echo ""
    exit 0
}

DRY_RUN=0
while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help)
            show_help
            ;;
        -n|--dry-run)
            DRY_RUN=1
            shift
            ;;
        *)
            echo "Unknown argument: $1"
            show_help
            ;;
    esac
done

if [ "$DRY_RUN" -eq 1 ]; then
    echo "🔍 [DRY-RUN] Simulating installation steps:"
    echo "   1. Target binary: ${WORKSPACE_ROOT}/target/release/propylea -> ${BIN_DEST}"
    echo "   2. Network capabilities: cap_net_bind_service=+ep on ${BIN_DEST}"
    echo "   3. Config staging: ${WORKSPACE_ROOT}/propylea.example.toml -> ${CONF_FILE}"
    echo "   4. ACME webroot directory: ${ACME_DIR}"
    echo "   5. Systemd unit: ${SERVICE_FILE}"
    echo "✅ Dry-run completed successfully."
    exit 0
fi

# Check for root/sudo
SUDO=""
if [ "$(id -u)" -ne 0 ]; then
    if command -v sudo >/dev/null 2>&1; then
        SUDO="sudo"
    else
        echo "❌ Error: Root or sudo privileges required to install system service."
        exit 1
    fi
fi

# 1. Discover, compile, or fetch release binary
SOURCE_BIN=""
if [ -f "${WORKSPACE_ROOT}/target/release/propylea" ]; then
    SOURCE_BIN="${WORKSPACE_ROOT}/target/release/propylea"
elif [ -f "${WORKSPACE_ROOT}/propylea" ]; then
    SOURCE_BIN="${WORKSPACE_ROOT}/propylea"
elif [ -f "./propylea" ]; then
    SOURCE_BIN="./propylea"
elif [ -f "${WORKSPACE_ROOT}/target/debug/propylea" ]; then
    SOURCE_BIN="${WORKSPACE_ROOT}/target/debug/propylea"
elif command -v cargo >/dev/null 2>&1; then
    echo "🔨 Compiling optimized release binary with cargo..."
    (cd "${WORKSPACE_ROOT}" && cargo build --release)
    SOURCE_BIN="${WORKSPACE_ROOT}/target/release/propylea"
else
    echo "🌐 No local binary or Cargo compiler found. Fetching prebuilt release from GitHub..."
    ARCH="$(uname -m)"
    OS="$(uname -s)"
    if [ "$OS" = "Linux" ] && [ "$ARCH" = "x86_64" ]; then
        TMP_DIR="$(mktemp -d)"
        TAG=$(curl -sSLI -o /dev/null -w '%{url_effective}' https://github.com/rmediatech/propylea/releases/latest 2>/dev/null | awk -F'/' '{print $NF}')
        TAG="${TAG:-v0.2.1}"
        RELEASE_URL="https://github.com/rmediatech/propylea/releases/download/${TAG}/propylea-${TAG}-x86_64-unknown-linux-gnu.tar.gz"
        echo "   Downloading: ${RELEASE_URL}"
        curl -sSLf "${RELEASE_URL}" -o "${TMP_DIR}/propylea.tar.gz"
        tar -xzf "${TMP_DIR}/propylea.tar.gz" -C "${TMP_DIR}"
        SOURCE_BIN="${TMP_DIR}/propylea"
    else
        echo "❌ Error: Could not locate propylea binary and Cargo is not installed."
        exit 1
    fi
fi

# 2. Install binary to system path
echo "📦 Installing binary from ${SOURCE_BIN} to ${BIN_DEST}..."
${SUDO} install -m 755 "${SOURCE_BIN}" "${BIN_DEST}"

# 3. Grant port 80/443 binding capability
echo "🔒 Granting cap_net_bind_service capability..."
if command -v setcap >/dev/null 2>&1; then
    ${SUDO} setcap 'cap_net_bind_service=+ep' "${BIN_DEST}" || true
else
    echo "⚠️  'setcap' not found; service will run with root network binding."
fi

# 4. Create configuration directory & initial template
echo "📁 Setting up configuration directory at ${CONF_DIR}..."
${SUDO} mkdir -p "${CONF_DIR}"
if [ ! -f "${CONF_FILE}" ]; then
    ${SUDO} cp "${WORKSPACE_ROOT}/propylea.example.toml" "${CONF_FILE}"
    echo "📄 Created ${CONF_FILE} from example template."
else
    echo "ℹ️  Existing configuration preserved at ${CONF_FILE}."
fi

# 5. Setup ACME challenge directory
echo "🌐 Ensuring ACME webroot challenge directory exists..."
${SUDO} mkdir -p "${ACME_DIR}"
${SUDO} chmod -R 755 /var/www/letsencrypt || true

# 6. Install systemd service unit
if [ -d "/etc/systemd/system" ]; then
    echo "⚙️  Installing systemd service unit..."
    ${SUDO} bash -c "cat << 'EOF' > ${SERVICE_FILE}
[Unit]
Description=Propylea Sovereign L7 Reverse Proxy & Perimeter Defense
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=${BIN_DEST} serve --config ${CONF_FILE}
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=3
LimitNOFILE=65536
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF"
    ${SUDO} systemctl daemon-reload
    echo "✅ Systemd service registered at ${SERVICE_FILE}."
fi

echo "================================================================================"
echo "🎉 PROPYLEA SETUP COMPLETE!"
echo ""
echo "👉 Quick Verification Commands:"
echo "   1. Validate config:   ${BIN_DEST} check --config ${CONF_FILE}"
echo "   2. Start service:     ${SUDO} systemctl start propylea"
echo "   3. Enable at boot:    ${SUDO} systemctl enable propylea"
echo "   4. View live logs:    ${SUDO} journalctl -u propylea -f"
echo "================================================================================"
