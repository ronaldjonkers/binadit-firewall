#!/usr/bin/env bash
# =============================================================================
# binadit-firewall - Common utility functions
# =============================================================================
# Shared functions used across all binadit-firewall components.
# This file is sourced by other scripts and should not be executed directly.
# =============================================================================

set -euo pipefail

# Guard against re-sourcing (readonly can only be set once)
if [[ -z "${_BINADIT_COMMON_LOADED:-}" ]]; then
    readonly _BINADIT_COMMON_LOADED=1
    readonly BINADIT_VERSION="2.0.0"
    readonly RED='\033[0;31m'
    readonly GREEN='\033[0;32m'
    readonly YELLOW='\033[1;33m'
    readonly BLUE='\033[0;34m'
    readonly CYAN='\033[0;36m'
    readonly BOLD='\033[1m'
    readonly NC='\033[0m' # No Color
fi

# Logging functions
log_info()    { echo -e "${GREEN}[INFO]${NC}    $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC}    $*" >&2; }
log_error()   { echo -e "${RED}[ERROR]${NC}   $*" >&2; }
log_success() { echo -e "${GREEN}[OK]${NC}      $*"; }
log_header()  { echo -e "\n${BOLD}${CYAN}=== $* ===${NC}\n"; }
log_debug()   {
    if [[ "${BINADIT_DEBUG:-false}" == "true" ]]; then
        echo -e "${BLUE}[DEBUG]${NC}   $*" >&2
    fi
}

# Check if running as root
require_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# Validate an IPv4 address
is_valid_ipv4() {
    local ip="$1"
    local IFS='.'
    local -a octets
    read -ra octets <<< "$ip"

    [[ ${#octets[@]} -eq 4 ]] || return 1

    for octet in "${octets[@]}"; do
        [[ "$octet" =~ ^[0-9]+$ ]] || return 1
        (( octet >= 0 && octet <= 255 )) || return 1
    done
    return 0
}

# Validate an IPv6 address (basic check - must contain at least one colon)
is_valid_ipv6() {
    local ip="$1"
    # Must contain at least one colon to be IPv6
    [[ "$ip" == *:* ]] || return 1
    [[ "$ip" =~ ^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$ ]] || \
    [[ "$ip" =~ ^::$ ]] || \
    [[ "$ip" =~ ^::1$ ]] || \
    [[ "$ip" =~ ^[0-9a-fA-F]*:[0-9a-fA-F:]+$ ]]
}

# Validate CIDR notation (IPv4 or IPv6)
is_valid_cidr() {
    local cidr="$1"
    local ip prefix

    if [[ "$cidr" =~ / ]]; then
        ip="${cidr%/*}"
        prefix="${cidr#*/}"
    else
        return 1
    fi

    if is_valid_ipv4 "$ip"; then
        [[ "$prefix" =~ ^[0-9]+$ ]] && (( prefix >= 0 && prefix <= 32 ))
    elif is_valid_ipv6 "$ip"; then
        [[ "$prefix" =~ ^[0-9]+$ ]] && (( prefix >= 0 && prefix <= 128 ))
    else
        return 1
    fi
}

# Validate a port number or port range (e.g., 80 or 8000:9000)
is_valid_port() {
    local port="$1"

    if [[ "$port" =~ ^([0-9]+):([0-9]+)$ ]]; then
        local start="${BASH_REMATCH[1]}"
        local end="${BASH_REMATCH[2]}"
        (( start >= 1 && start <= 65535 && end >= 1 && end <= 65535 && start <= end ))
    elif [[ "$port" =~ ^[0-9]+$ ]]; then
        (( port >= 1 && port <= 65535 ))
    else
        return 1
    fi
}

# Validate an IP address (v4 or v6), CIDR, or hostname
is_valid_host() {
    local host="$1"

    # Check for CIDR
    if [[ "$host" =~ / ]]; then
        is_valid_cidr "$host" && return 0
    fi

    # Check for IP range (dash-separated)
    if [[ "$host" =~ - ]]; then
        return 0  # Accept ranges
    fi

    # Check IPv4
    is_valid_ipv4 "$host" && return 0

    # Check IPv6
    is_valid_ipv6 "$host" && return 0

    # Check hostname (basic)
    [[ "$host" =~ ^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$ ]] && return 0

    return 1
}

# Resolve hostname to IP address
resolve_hostname() {
    local hostname="$1"

    if is_valid_ipv4 "$hostname" || is_valid_ipv6 "$hostname" || [[ "$hostname" =~ / ]]; then
        echo "$hostname"
        return 0
    fi

    local resolved
    if command -v dig &>/dev/null; then
        resolved=$(dig +short "$hostname" A 2>/dev/null | head -1)
    elif command -v getent &>/dev/null; then
        resolved=$(getent ahosts "$hostname" 2>/dev/null | awk 'NR==1{print $1}')
    elif command -v host &>/dev/null; then
        resolved=$(host "$hostname" 2>/dev/null | awk '/has address/{print $4; exit}')
    fi

    if [[ -n "${resolved:-}" ]]; then
        echo "$resolved"
        return 0
    fi

    log_warn "Could not resolve hostname: $hostname"
    return 1
}

# Detect the current SSH port from sshd_config
detect_ssh_port() {
    local ssh_port="22"

    if [[ -f /etc/ssh/sshd_config ]]; then
        local configured_port
        configured_port=$(grep -E "^Port " /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | head -1)
        if [[ -n "${configured_port:-}" ]] && is_valid_port "$configured_port"; then
            ssh_port="$configured_port"
        fi
    fi

    echo "$ssh_port"
}

# Create a backup of the current firewall rules
backup_rules() {
    local backup_dir="/etc/binadit-firewall/backups"
    local timestamp
    timestamp=$(date +%Y%m%d_%H%M%S)

    mkdir -p "$backup_dir"

    if command -v iptables-save &>/dev/null; then
        iptables-save > "$backup_dir/iptables_${timestamp}.bak" 2>/dev/null || true
    fi
    if command -v ip6tables-save &>/dev/null; then
        ip6tables-save > "$backup_dir/ip6tables_${timestamp}.bak" 2>/dev/null || true
    fi
    if command -v nft &>/dev/null; then
        nft list ruleset > "$backup_dir/nftables_${timestamp}.bak" 2>/dev/null || true
    fi

    # Keep only last 10 backups
    local count
    count=$(find "$backup_dir" -name "*.bak" -type f | wc -l)
    if (( count > 30 )); then
        find "$backup_dir" -name "*.bak" -type f | sort | head -n "$(( count - 30 ))" | xargs rm -f
    fi

    log_debug "Backup saved to $backup_dir/*_${timestamp}.bak"
}
