#!/usr/bin/env bash
# ==============================================================================
# Propylea Sovereign Release & Cryptographic Packaging Pipeline
# Standard: AGY-RULE-SOVEREIGN-FLAGSHIP-01 & SOVEREIGN-SIGN-01
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="${SCRIPT_DIR}/.."
DIST_DIR="${WORKSPACE_ROOT}/dist"
KEY_ID="6BC8DA5E7F1B8B49BE5CD70A4E428019A109578B"

mkdir -p "${DIST_DIR}"

echo "================================================================================"
echo "  🏛️  PROPYLEA SOVEREIGN RELEASE & CRYPTOGRAPHIC PACKAGING PIPELINE"
echo "================================================================================"

cd "${WORKSPACE_ROOT}"

# 1. Run full test suite & adversarial TDD
echo "🧪 Running workspace test assertions & red-team attack suite..."
cargo test --quiet

VERSION="$(grep -m1 'version = ' "${WORKSPACE_ROOT}/Cargo.toml" | cut -d'"' -f2)"

# 2. Build Release Targets
echo "🔨 Compiling optimized glibc release binary (x86_64-unknown-linux-gnu)..."
cargo build --release

echo "🔨 Compiling 100% static Musl PIE release binary (x86_64-unknown-linux-musl)..."
cargo build --release --target x86_64-unknown-linux-musl

# 3. Package archives
TARGETS=("x86_64-unknown-linux-gnu" "x86_64-unknown-linux-musl")
ARCHIVES=()

for TARGET in "${TARGETS[@]}"; do
    echo "📦 Packaging distribution archive for ${TARGET}..."
    RELEASE_NAME="propylea-v${VERSION}-${TARGET}"
    ARCHIVE_NAME="${RELEASE_NAME}.tar.gz"
    
    if [ "${TARGET}" = "x86_64-unknown-linux-gnu" ]; then
        BIN_DIR="${WORKSPACE_ROOT}/target/release"
    else
        BIN_DIR="${WORKSPACE_ROOT}/target/${TARGET}/release"
    fi
    
    cd "${BIN_DIR}"
    tar -czvf "${DIST_DIR}/${ARCHIVE_NAME}" propylea
    ARCHIVES+=("${ARCHIVE_NAME}")
done

cd "${DIST_DIR}"

# 4. Generate SHA-256 Checksums
echo "🔐 Computing cryptographic SHA-256 checksums..."
rm -f SHA256SUMS SHA256SUMS.asc

for ARCHIVE in "${ARCHIVES[@]}"; do
    sha256sum "${ARCHIVE}" > "${ARCHIVE}.sha256"
    sha256sum "${ARCHIVE}" >> "SHA256SUMS"
done

# 5. GPG Detached Signatures (SOVEREIGN-SIGN-01)
echo "🖋️  Generating OpenPGP detached signatures with sovereign release key..."
for ARCHIVE in "${ARCHIVES[@]}"; do
    rm -f "${ARCHIVE}.asc"
    gpg --batch --yes --local-user "${KEY_ID}" --armor --detach-sign "${ARCHIVE}"
done

gpg --batch --yes --local-user "${KEY_ID}" --armor --detach-sign "SHA256SUMS"

echo "================================================================================"
echo "🎉 RELEASE ARTIFACTS STAGED SUCCESSFULLY IN: ${DIST_DIR}"
for ARCHIVE in "${ARCHIVES[@]}"; do
    echo "   Archive:   ${DIST_DIR}/${ARCHIVE} ($(du -k "${ARCHIVE}" | cut -f1) KB)"
    echo "   Checksum:  ${DIST_DIR}/${ARCHIVE}.sha256"
    echo "   Signature: ${DIST_DIR}/${ARCHIVE}.asc"
done
echo "   Manifest:  ${DIST_DIR}/SHA256SUMS.asc"
echo "================================================================================"
