#!/usr/bin/env bash
# =============================================================================
# binadit-firewall — Single-line installer / uninstaller bootstrap
# =============================================================================
# Copyright (C) 2013-2026 Ronald Jonkers — Binadit BV (binadit.com)
# License: GPL-2.0
#
# Install:
#   curl -sL https://raw.githubusercontent.com/ronaldjonkers/binadit-firewall/master/get.sh | sudo bash
#   wget -qO- https://raw.githubusercontent.com/ronaldjonkers/binadit-firewall/master/get.sh | sudo bash
#
# Unattended install (no questions):
#   curl -sL .../get.sh | sudo bash -s -- --non-interactive
#
# Uninstall:
#   curl -sL .../get.sh | sudo bash -s -- --uninstall
#
# This script downloads the latest binadit-firewall and runs install.sh.
# It cleans up after itself — no leftover files.
# =============================================================================

set -euo pipefail

REPO="ronaldjonkers/binadit-firewall"
BRANCH="master"
TMPDIR_BASE="${TMPDIR:-/tmp}"

# Colors
RED=$'\033[0;31m'
GREEN=$'\033[0;32m'
CYAN=$'\033[0;36m'
BOLD=$'\033[1m'
NC=$'\033[0m'

info()  { echo -e "  ${CYAN}▸${NC} $*"; }
ok()    { echo -e "  ${GREEN}✓${NC} $*"; }
fail()  { echo -e "  ${RED}✗${NC} $*" >&2; exit 1; }

main() {
    # Detect mode (install vs uninstall)
    local action="install" arg
    for arg in "$@"; do
        case "$arg" in
            --uninstall|uninstall) action="uninstall" ;;
        esac
    done

    if (( BASH_VERSINFO[0] < 4 )); then
        fail "bash 4 or newer is required."
    fi

    # Must be root
    if [[ $EUID -ne 0 ]]; then
        fail "This script must be run as root. Use: curl -sL ... | ${BOLD}sudo${NC} bash"
    fi

    command -v tar &>/dev/null || fail "tar is required. Install it and try again."

    echo ""
    if [[ "$action" == "uninstall" ]]; then
        echo -e "  ${BOLD}${RED}binadit-firewall${NC} — Uninstaller"
        echo -e "  ${RED}─────────────────────────────────${NC}"
    else
        echo -e "  ${BOLD}${CYAN}binadit-firewall${NC} — Quick Installer"
        echo -e "  ${CYAN}─────────────────────────────────────${NC}"
    fi
    echo ""

    # Create temp directory
    INSTALL_TMP=$(mktemp -d "${TMPDIR_BASE}/binadit-firewall-install.XXXXXX")
    trap 'rm -rf "$INSTALL_TMP"' EXIT

    info "Downloading binadit-firewall..."

    local url="https://github.com/${REPO}/archive/refs/heads/${BRANCH}.tar.gz"
    local archive="$INSTALL_TMP/src.tar.gz"
    if command -v curl &>/dev/null; then
        curl -fsSL "$url" -o "$archive" || fail "Download failed (${url}). Check the internet connection."
    elif command -v wget &>/dev/null; then
        wget -qO "$archive" "$url" || fail "Download failed (${url}). Check the internet connection."
    else
        fail "curl or wget is required. Install one and try again."
    fi

    tar -xzf "$archive" -C "$INSTALL_TMP" || fail "Downloaded archive is corrupt."
    local src
    src=$(find "$INSTALL_TMP" -mindepth 1 -maxdepth 1 -type d | head -1)
    [[ -n "$src" && -f "$src/install.sh" ]] || fail "Downloaded archive is incomplete."
    ok "Downloaded"

    if [[ "$action" == "uninstall" ]]; then
        info "Starting uninstaller..."
    else
        info "Starting installer..."
    fi
    echo ""

    cd "$src"

    # With "curl | bash" stdin is the script itself, not the keyboard. Use the
    # terminal for the installer's questions when there is one; otherwise the
    # installer runs unattended with safe defaults.
    if { : < /dev/tty; } 2>/dev/null; then
        bash install.sh "$@" < /dev/tty
    else
        bash install.sh "$@" < /dev/null
    fi
}

# Wrapped in a function so a partially downloaded script can never run
main "$@"
