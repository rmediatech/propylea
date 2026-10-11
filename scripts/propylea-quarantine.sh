#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# 🛡️ PROPYLEA AUTONOMOUS QUARANTINE OPERATOR CONTROL UTILITY
#
# Radical OJP: Enterprise management, manual banning, unquarantining,
# multi-format threat intelligence export, and historical log ingestion.
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

# ANSI Styling
BOLD=$'\033[1m'
CYAN=$'\033[0;36m'
GREEN=$'\033[0;32m'
YELLOW=$'\033[1;33m'
RED=$'\033[0;31m'
RESET=$'\033[0m'

# Resolve root workspace if available
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." 2>/dev/null && pwd || echo "")"

# Auto-discover propylea binary
discover_bin() {
    if [[ -n "${PROPYLEA_BIN:-}" && -x "${PROPYLEA_BIN}" ]]; then
        echo "${PROPYLEA_BIN}"
        return 0
    fi

    if [[ -x "/usr/local/bin/propylea" ]]; then
        echo "/usr/local/bin/propylea"
        return 0
    fi

    if command -v propylea >/dev/null 2>&1; then
        command -v propylea
        return 0
    fi

    if [[ -n "${REPO_ROOT}" && -x "${REPO_ROOT}/target/release/propylea" ]]; then
        echo "${REPO_ROOT}/target/release/propylea"
        return 0
    fi

    if [[ -n "${REPO_ROOT}" && -x "${REPO_ROOT}/target/debug/propylea" ]]; then
        echo "${REPO_ROOT}/target/debug/propylea"
        return 0
    fi

    echo ""
}

# Auto-discover propylea configuration file
discover_config() {
    if [[ -n "${PROPYLEA_CONFIG:-}" && -f "${PROPYLEA_CONFIG}" ]]; then
        echo "${PROPYLEA_CONFIG}"
        return 0
    fi

    if [[ -f "/etc/propylea/propylea.toml" ]]; then
        echo "/etc/propylea/propylea.toml"
        return 0
    fi

    if [[ -n "${REPO_ROOT}" && -f "${REPO_ROOT}/config/propylea.toml" ]]; then
        echo "${REPO_ROOT}/config/propylea.toml"
        return 0
    fi

    if [[ -f "${HOME}/.config/propylea/propylea.toml" ]]; then
        echo "${HOME}/.config/propylea/propylea.toml"
        return 0
    fi

    echo ""
}

PROPYLEA_EXEC="$(discover_bin)"
CONFIG_FILE="$(discover_config)"

ensure_binary() {
    if [[ -z "${PROPYLEA_EXEC}" ]]; then
        echo -e "${RED}❌ Error: 'propylea' binary not found.${RESET}" >&2
        echo -e "   Please build it ('cargo build --release') or specify PROPYLEA_BIN=/path/to/propylea" >&2
        exit 1
    fi
}

# Build common CLI args
get_cli_prefix() {
    local args=("${PROPYLEA_EXEC}")
    if [[ -n "${CONFIG_FILE}" ]]; then
        args+=("-c" "${CONFIG_FILE}")
    fi
    args+=("quarantine")
    echo "${args[@]}"
}

usage() {
    cat <<EOF
${BOLD}🛡️  Propylea Autonomous Quarantine Control Utility${RESET}

${BOLD}USAGE:${RESET}
  $(basename "$0") <COMMAND> [OPTIONS]

${BOLD}COMMANDS:${RESET}
  ${CYAN}status${RESET}
      Inspect running daemon IPC control socket, active enforced bans, and SQLite store.

  ${CYAN}ban${RESET} <TARGET...> [--reason <REASON>] [--duration <DURATION>] [--exact]
      Quarantine one or more IP addresses or CIDR blocks.
      Default duration: 24h (e.g. 30m, 1h, 24h, 7d).
      Default scope: /24 (IPv4) or /48 (IPv6) subnet. Use --exact for /32 or /128.

  ${CYAN}unban${RESET} <TARGET...>
      Remove quarantine enforcement on one or more IPs or CIDR blocks.
      Instantly clears in-memory firewall and updates persistent SQLite store.

  ${CYAN}clear${RESET} [-y|--yes]
      Clear all active quarantine bans across RAM and persistent SQLite store.

  ${CYAN}list${RESET} [--format <FMT>] [--active-only] [--limit <N>]
      List quarantine records. Formats: md (default), txt, json, jsonl, csv, html.

  ${CYAN}export${RESET} <FILE> [--format <FMT>] [--active-only]
      Export quarantine records and audit intelligence to a file.
      Default format: html (standalone zero-cloud dashboard).

  ${CYAN}ingest-journal${RESET} [--hours <HOURS>] [--unit <UNIT>] [--reason <REASON>] [--duration <DURATION>] [--exclude <IPS...>] [--exact]
      Harvest historical scan probes and TLS spoofing bad actors from systemd journal
      and backfill them into the persistent quarantine store / running daemon.

  ${CYAN}help${RESET}
      Display this usage manual.

${BOLD}ENVIRONMENT VARIABLES:${RESET}
  PROPYLEA_BIN      Explicit path to 'propylea' executable
  PROPYLEA_CONFIG   Explicit path to 'propylea.toml' configuration

${BOLD}EXAMPLES:${RESET}
  # Check live defense and socket status:
  $(basename "$0") status

  # Manually quarantine an offending scanner subnet for 48 hours:
  $(basename "$0") ban 198.51.100.42 --reason "Hostile path fuzzing" --duration 48h

  # Manually quarantine an exact single host IP (/32):
  $(basename "$0") ban 203.0.113.88 --exact --reason "Single host probe"

  # Unban an operator IP or false positive:
  $(basename "$0") unban 198.51.100.42

  # Export standalone dark-mode HTML security dashboard:
  $(basename "$0") export /var/www/reports/quarantine.html --format html

  # Ingest bad actors logged in the past 72 hours from journalctl:
  $(basename "$0") ingest-journal --hours 72 --exclude 198.51.100.42

EOF
}

cmd_status() {
    ensure_binary
    local prefix
    prefix=($(get_cli_prefix))
    "${prefix[@]}" status
}

cmd_ban() {
    ensure_binary
    local targets=()
    local reason="Manual operator ban"
    local duration="24h"
    local exact_flag=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --reason|-r)
                reason="$2"
                shift 2
                ;;
            --duration|-d)
                duration="$2"
                shift 2
                ;;
            --exact|-e)
                exact_flag="--exact"
                shift
                ;;
            *)
                targets+=("$1")
                shift
                ;;
        esac
    done

    if [[ ${#targets[@]} -eq 0 ]]; then
        echo -e "${RED}❌ Error: No target IP or CIDR specified to ban.${RESET}" >&2
        echo "   Usage: $(basename "$0") ban <TARGET...> [--reason <REASON>] [--duration <DURATION>]" >&2
        exit 1
    fi

    local prefix
    prefix=($(get_cli_prefix))
    local cmd_args=("${prefix[@]}" "ban" "${targets[@]}" "--reason" "${reason}" "--duration" "${duration}")
    if [[ -n "${exact_flag}" ]]; then
        cmd_args+=("${exact_flag}")
    fi

    "${cmd_args[@]}"
}

cmd_unban() {
    ensure_binary
    local targets=()

    while [[ $# -gt 0 ]]; do
        targets+=("$1")
        shift
    done

    if [[ ${#targets[@]} -eq 0 ]]; then
        echo -e "${RED}❌ Error: No target IP or CIDR specified to unban.${RESET}" >&2
        echo "   Usage: $(basename "$0") unban <TARGET...>" >&2
        exit 1
    fi

    local prefix
    prefix=($(get_cli_prefix))
    "${prefix[@]}" unban "${targets[@]}"
}

cmd_clear() {
    ensure_binary
    local confirm=false

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -y|--yes|--force)
                confirm=true
                shift
                ;;
            *)
                shift
                ;;
        esac
    done

    if [[ "${confirm}" != "true" ]]; then
        read -r -p "⚠️  Are you sure you want to clear ALL active quarantine bans? [y/N]: " answer
        case "${answer}" in
            [yY][eE][sS]|[yY]) ;;
            *) echo "Aborted."; exit 0 ;;
        esac
    fi

    local prefix
    prefix=($(get_cli_prefix))
    "${prefix[@]}" clear
}

cmd_list() {
    ensure_binary
    local format="md"
    local active_only=""
    local limit="100"

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --format|-f)
                format="$2"
                shift 2
                ;;
            --active-only|-a)
                active_only="--active-only"
                shift
                ;;
            --limit|-l)
                limit="$2"
                shift 2
                ;;
            *)
                format="$1"
                shift
                ;;
        esac
    done

    local prefix
    prefix=($(get_cli_prefix))
    local cmd_args=("${prefix[@]}" "list" "--format" "${format}" "--limit" "${limit}")
    if [[ -n "${active_only}" ]]; then
        cmd_args+=("${active_only}")
    fi

    "${cmd_args[@]}"
}

cmd_export() {
    ensure_binary
    local file=""
    local format="html"
    local active_only=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --format|-f)
                format="$2"
                shift 2
                ;;
            --active-only|-a)
                active_only="--active-only"
                shift
                ;;
            *)
                if [[ -z "${file}" ]]; then
                    file="$1"
                else
                    format="$1"
                fi
                shift
                ;;
        esac
    done

    if [[ -z "${file}" ]]; then
        echo -e "${RED}❌ Error: No output file specified for export.${RESET}" >&2
        echo "   Usage: $(basename "$0") export <FILE> [--format <FMT>] [--active-only]" >&2
        exit 1
    fi

    local prefix
    prefix=($(get_cli_prefix))
    local cmd_args=("${prefix[@]}" "export" "${file}" "--format" "${format}")
    if [[ -n "${active_only}" ]]; then
        cmd_args+=("${active_only}")
    fi

    "${cmd_args[@]}"
}

cmd_ingest_journal() {
    ensure_binary
    local hours="72"
    local unit="propylea"
    local reason="historical_journal_ingest"
    local duration="24h"
    local exact_flag=""
    local excludes=()

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --hours)
                hours="$2"
                shift 2
                ;;
            --unit)
                unit="$2"
                shift 2
                ;;
            --reason|-r)
                reason="$2"
                shift 2
                ;;
            --duration|-d)
                duration="$2"
                shift 2
                ;;
            --exclude|-x)
                excludes+=("$2")
                shift 2
                ;;
            --exact|-e)
                exact_flag="--exact"
                shift
                ;;
            *)
                shift
                ;;
        esac
    done

    echo -e "${CYAN}🛡️  [JOURNAL-HARVEST] Querying systemd journal for '${unit}' (past ${hours} hours)...${RESET}"

    # Build journalctl command
    local journal_cmd=("journalctl" "-u" "${unit}" "--since" "${hours} hours ago" "--no-pager")
    if [[ $(id -u) -ne 0 ]] && ! groups | grep -qE 'adm|systemd-journal'; then
        if command -v sudo >/dev/null 2>&1; then
            journal_cmd=("sudo" "journalctl" "-u" "${unit}" "--since" "${hours} hours ago" "--no-pager")
        fi
    fi

    local prefix
    prefix=($(get_cli_prefix))
    local ingest_args=("${prefix[@]}" "ingest-logs" "--input" "-" "--reason" "${reason}" "--duration" "${duration}")

    for ex in "${excludes[@]}"; do
        ingest_args+=("--exclude" "${ex}")
    done

    if [[ -n "${exact_flag}" ]]; then
        ingest_args+=("${exact_flag}")
    fi

    # Stream logs into propylea ingest-logs
    "${journal_cmd[@]}" | "${ingest_args[@]}"
}

# Entrypoint router
main() {
    if [[ $# -eq 0 ]]; then
        usage
        exit 0
    fi

    local subcmd="$1"
    shift

    case "${subcmd}" in
        status)
            cmd_status "$@"
            ;;
        ban)
            cmd_ban "$@"
            ;;
        unban)
            cmd_unban "$@"
            ;;
        clear)
            cmd_clear "$@"
            ;;
        list)
            cmd_list "$@"
            ;;
        export)
            cmd_export "$@"
            ;;
        ingest-journal)
            cmd_ingest_journal "$@"
            ;;
        help|-h|--help)
            usage
            ;;
        *)
            echo -e "${RED}❌ Unknown command: '${subcmd}'${RESET}" >&2
            echo "   Run '$(basename "$0") help' for available commands." >&2
            exit 1
            ;;
    esac
}

main "$@"
