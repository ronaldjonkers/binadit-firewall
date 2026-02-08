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
# Uninstall:
#   curl -sL https://raw.githubusercontent.com/ronaldjonkers/binadit-firewall/master/get.sh | sudo bash -s -- --uninstall
#   wget -qO- https://raw.githubusercontent.com/ronaldjonkers/binadit-firewall/master/get.sh | sudo bash -s -- --uninstall
#
# This script downloads the latest binadit-firewall release and runs install.sh.
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
fail()  { echo -e "  ${RED}✗${NC} $*"; exit 1; }

# Detect mode (install vs uninstall)
ACTION="install"
for arg in "$@"; do
    case "$arg" in
        --uninstall|uninstall) ACTION="uninstall" ;;
    esac
done

# Must be root
if [[ $EUID -ne 0 ]]; then
    fail "This script must be run as root. Use: curl -sL ... | ${BOLD}sudo${NC} bash"
fi

# Need curl or wget
if command -v curl &>/dev/null; then
    FETCH="curl -fsSL"
elif command -v wget &>/dev/null; then
    FETCH="wget -qO-"
else
    fail "curl or wget is required. Install one and try again."
fi

# Need tar or git
HAS_GIT=false
HAS_TAR=false
command -v git &>/dev/null && HAS_GIT=true
command -v tar &>/dev/null && HAS_TAR=true

echo ""
if [[ "$ACTION" == "uninstall" ]]; then
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

if [[ "$HAS_GIT" == "true" ]]; then
    git clone --depth 1 -b "$BRANCH" "https://github.com/${REPO}.git" "$INSTALL_TMP/binadit-firewall" 2>/dev/null
    ok "Downloaded via git"
elif [[ "$HAS_TAR" == "true" ]]; then
    $FETCH "https://github.com/${REPO}/archive/refs/heads/${BRANCH}.tar.gz" | tar -xz -C "$INSTALL_TMP"
    # GitHub extracts to repo-branch/
    mv "$INSTALL_TMP"/binadit-firewall-* "$INSTALL_TMP/binadit-firewall"
    ok "Downloaded via tarball"
else
    fail "git or tar is required to download the installer."
fi

# Run the installer / uninstaller
if [[ "$ACTION" == "uninstall" ]]; then
    info "Starting uninstaller..."
else
    info "Starting installer..."
fi
echo ""

cd "$INSTALL_TMP/binadit-firewall"

# Pass through any arguments (e.g., --non-interactive, --uninstall)
# Redirect /dev/tty as stdin so interactive prompts work even when piped (curl | bash)
if [[ -t 1 ]] && [[ -e /dev/tty ]]; then
    bash install.sh "$@" < /dev/tty
else
    bash install.sh "$@"
fi
