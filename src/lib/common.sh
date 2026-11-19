#!/usr/bin/env bash
# =============================================================================
# binadit-firewall - Common utility functions
# =============================================================================
# Copyright (C) 2013-2026 Ronald Jonkers — Binadit BV (binadit.com)
# License: GPL-2.0
#
# Shared functions used across all binadit-firewall components.
# This file is sourced by other scripts and should not be executed directly.
# =============================================================================

set -euo pipefail

# Guard against re-sourcing (readonly can only be set once)
if [[ -z "${_BINADIT_COMMON_LOADED:-}" ]]; then
    readonly _BINADIT_COMMON_LOADED=1
    readonly BINADIT_VERSION="3.1.1"
    readonly RED=$'\033[0;31m'
    readonly GREEN=$'\033[0;32m'
    readonly YELLOW=$'\033[1;33m'
    readonly BLUE=$'\033[0;34m'
    readonly CYAN=$'\033[0;36m'
    readonly BOLD=$'\033[1m'
    readonly NC=$'\033[0m' # No Color
fi

# Logging functions
log_info()    { echo -e "  ${GREEN}▸${NC} $*"; }
log_warn()    { echo -e "  ${YELLOW}⚠${NC} $*" >&2; }
log_error()   { echo -e "  ${RED}✗${NC} $*" >&2; }
log_success() { echo -e "  ${GREEN}✓${NC} $*"; }
log_header()  { echo -e "\n  ${BOLD}${CYAN}━━━ $* ━━━${NC}\n"; }
log_rule()    { echo -e "  ${BLUE}│${NC} $*"; }
log_debug()   {
    if [[ "${BINADIT_DEBUG:-false}" == "true" ]]; then
        echo -e "  ${BLUE}⊡${NC} $*" >&2
    fi
}

# Show the binadit-firewall ASCII art banner
show_banner() {
    echo -e "${CYAN}"
    cat <<'BANNER'
    ╔═══════════════════════════════════════════════════════════════════════════╗
    ║                                                                           ║
    ║   _     _                 _ _ _         __ _                        _ _   ║
    ║  | |__ (_)_ __   __ _  __| (_) |_      / _(_)_ __ _____      ____ _| | |  ║
    ║  | '_ \| | '_ \ / _` |/ _` | | __|____| |_| | '__/ _ \ \ /\ / / _` | | |  ║
    ║  | |_) | | | | | (_| | (_| | | ||_____|  _| | | |  __/\ V  V / (_| | | |  ║
    ║  |_.__/|_|_| |_|\__,_|\__,_|_|\__|    |_| |_|_|  \___| \_/\_/ \__,_|_|_|  ║
    ║                                                                           ║
BANNER
    echo -e "    ║                       ${BOLD}Simple Linux Firewall Manager${NC}${CYAN}                       ║"
    local ver_text="v${BINADIT_VERSION}"
    local ver_len=${#ver_text}
    local total_pad=$((75 - ver_len))
    local left_pad=$((total_pad / 2))
    local right_pad=$((total_pad - left_pad))
    printf "    ║%*s%s%*s║\n" "$left_pad" "" "$ver_text" "$right_pad" ""
    echo    "    ║                                                                           ║"
    echo    "    ║              © Ronald Jonkers — Binadit BV — binadit.com                  ║"
    echo    "    ║                                                                           ║"
    echo    "    ╚═══════════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Show protection active banner
show_protected() {
    echo ""
    echo -e "${GREEN}${BOLD}"
    cat <<'BANNER'
    ╔═══════════════════════════════════════════════════════════════════════════╗
    ║                                                                           ║
    ║              🛡️  YOUR SERVER IS NOW PROTECTED  🛡️                         ║
    ║                                                                           ║
    ║      ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░    ║
    ║      ░   binadit-firewall is actively filtering traffic              ░    ║
    ║      ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░    ║
    ║                                                                           ║
    ╚═══════════════════════════════════════════════════════════════════════════╝
BANNER
    echo -e "${NC}"
}

# Show firewall stopped banner
show_unprotected() {
    echo ""
    echo -e "${RED}${BOLD}"
    cat <<'BANNER'
    ╔═══════════════════════════════════════════════════════════════════════════╗
    ║                                                                           ║
    ║              ⚠️  FIREWALL DISABLED - SERVER EXPOSED  ⚠️                   ║
    ║                                                                           ║
    ║      All traffic is currently allowed. Run:                               ║
    ║        binadit-firewall start                                             ║
    ║      to re-enable protection.                                             ║
    ║                                                                           ║
    ╚═══════════════════════════════════════════════════════════════════════════╝
BANNER
    echo -e "${NC}"
}

# =============================================================================
# Paths and state
# =============================================================================

# Directory holding runtime state (applied config copy, DNS cache, ...)
state_dir() {
    echo "${CONFIG_DIR:-/etc/binadit-firewall}/state"
}

ensure_state_dir() {
    local d
    d=$(state_dir)
    mkdir -p "$d" 2>/dev/null || return 1
    chmod 700 "$d" 2>/dev/null || true
}

# World-readable marker so non-root logins can show the firewall state
run_state_file() {
    if [[ -d /run ]]; then
        echo "/run/binadit-firewall.active"
    else
        echo "/var/run/binadit-firewall.active"
    fi
}

# Check if running as root
require_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This command must be run as root (use sudo)"
        exit 1
    fi
}

# Ask a question. Falls back to the default when there is no terminal,
# when NON_INTERACTIVE=true, or when the user just presses Enter.
# Usage: ask VARNAME "prompt" "default"
ask() {
    local __var="$1" __prompt="$2" __default="${3:-}" __reply=""
    if [[ "${NON_INTERACTIVE:-false}" == "true" ]]; then
        __reply="$__default"
    elif ! read -rp "$__prompt" __reply; then
        __reply="$__default"
        echo ""
    fi
    [[ -z "$__reply" ]] && __reply="$__default"
    printf -v "$__var" '%s' "$__reply"
}

# =============================================================================
# Configuration loading
# =============================================================================

# Every supported configuration key
ALL_CONFIG_KEYS="TCP_PORTS TCP_PORTS_INPUT TCP_PORTS_OUTPUT UDP_PORTS \
BLOCKED_TCP_PORTS BLOCKED_UDP_PORTS BLOCKED_TCP_PORTS_OUTPUT BLOCKED_UDP_PORTS_OUTPUT \
SSH_PORT SSH_ALLOWED_IPS SSH_ALLOWED_IPS_IPV6 \
TRUSTED_IPS TRUSTED_IPS_IPV6 TRUSTED_RANGES TRUSTED_RANGES_IPV6 \
BLACKLIST BLACKLIST_IPV6 BLOCKED_RANGES BLOCKED_RANGES_IPV6 \
PORT_IP_RULES DNS_REFRESH_INTERVAL ICMP_ENABLE MULTICAST_ENABLE SMTP_ENABLE RATE_LIMIT_ENABLE \
RATE_LIMIT_RATE RATE_LIMIT_BURST LOG_DROPPED NAT_ENABLE NAT_EXTERNAL_IFACE \
NAT_INTERNAL_IFACE SYN_FLOOD_PROTECT CONN_LIMIT_ENABLE CONN_LIMIT_PER_IP \
CONN_RATE_PER_IP DROP_INVALID BLOCK_COMMON_ATTACKS PORT_FORWARD_RULES \
CUSTOM_RULES_FILE BINADIT_DEBUG"

# Keys holding a space-separated list of ports
PORT_LIST_KEYS="TCP_PORTS TCP_PORTS_INPUT TCP_PORTS_OUTPUT UDP_PORTS \
BLOCKED_TCP_PORTS BLOCKED_UDP_PORTS BLOCKED_TCP_PORTS_OUTPUT BLOCKED_UDP_PORTS_OUTPUT SSH_PORT"

# Keys holding a space-separated list of addresses
ADDR_LIST_KEYS="SSH_ALLOWED_IPS SSH_ALLOWED_IPS_IPV6 \
TRUSTED_IPS TRUSTED_IPS_IPV6 TRUSTED_RANGES TRUSTED_RANGES_IPV6 \
BLACKLIST BLACKLIST_IPV6 BLOCKED_RANGES BLOCKED_RANGES_IPV6"

# Keys that must be "true" or "false"
BOOL_KEYS="ICMP_ENABLE MULTICAST_ENABLE SMTP_ENABLE RATE_LIMIT_ENABLE LOG_DROPPED \
NAT_ENABLE SYN_FLOOD_PROTECT CONN_LIMIT_ENABLE DROP_INVALID BLOCK_COMMON_ATTACKS BINADIT_DEBUG"

# Set every key to its default. A config file written for an older version
# may not contain newer keys; this guarantees they are always defined.
config_defaults() {
    TCP_PORTS=""; TCP_PORTS_INPUT=""; TCP_PORTS_OUTPUT=""; UDP_PORTS=""
    BLOCKED_TCP_PORTS=""; BLOCKED_UDP_PORTS=""
    BLOCKED_TCP_PORTS_OUTPUT=""; BLOCKED_UDP_PORTS_OUTPUT=""
    SSH_PORT=""; SSH_ALLOWED_IPS=""; SSH_ALLOWED_IPS_IPV6=""
    TRUSTED_IPS=""; TRUSTED_IPS_IPV6=""; TRUSTED_RANGES=""; TRUSTED_RANGES_IPV6=""
    BLACKLIST=""; BLACKLIST_IPV6=""; BLOCKED_RANGES=""; BLOCKED_RANGES_IPV6=""
    PORT_IP_RULES=""; DNS_REFRESH_INTERVAL="5"
    ICMP_ENABLE="true"; MULTICAST_ENABLE="false"; SMTP_ENABLE="true"
    RATE_LIMIT_ENABLE="true"; RATE_LIMIT_RATE="25"; RATE_LIMIT_BURST="100"
    LOG_DROPPED="true"
    NAT_ENABLE="false"; NAT_EXTERNAL_IFACE="eth0"; NAT_INTERNAL_IFACE="eth1"
    SYN_FLOOD_PROTECT="true"; CONN_LIMIT_ENABLE="false"; CONN_LIMIT_PER_IP="50"
    CONN_RATE_PER_IP="0"; DROP_INVALID="true"; BLOCK_COMMON_ATTACKS="true"
    PORT_FORWARD_RULES=""; CUSTOM_RULES_FILE=""
    BINADIT_DEBUG="${BINADIT_DEBUG:-false}"
}

# Load a configuration file on top of the defaults
load_config() {
    local config_file="$1"
    config_defaults
    # shellcheck source=/dev/null
    source "$config_file"
    # The SSH port(s) to protect: explicit SSH_PORT wins, otherwise auto-detect
    if [[ -n "${SSH_PORT:-}" ]]; then
        SSH_PORTS="$SSH_PORT"
    else
        SSH_PORTS=$(detect_ssh_ports)
    fi
}

# Safely write KEY="value" into a config file.
# - replaces an existing assignment (including multi-line quoted values)
# - appends the key when it is missing (configs from older versions)
# - never interprets the value (no sed/regex injection)
config_set_value() {
    local file="$1" key="$2" value="$3" tmp
    case "$value" in
        *'"'*|*'$'*|*'`'*|*'\'*)
            log_error "Value for ${key} may not contain \" \$ \` or \\ characters"
            return 1 ;;
    esac
    tmp=$(mktemp "${file}.XXXXXX") || return 1
    if ! KEY="$key" VALUE="$value" awk '
        BEGIN { key = ENVIRON["KEY"]; val = ENVIRON["VALUE"]; done = 0; skip = 0 }
        skip { if ($0 ~ /"/) skip = 0; next }
        index($0, key "=") == 1 {
            if (!done) { print key "=\"" val "\""; done = 1 }
            rest = substr($0, length(key) + 2)
            # opening quote without a closing quote on the same line = multi-line value
            if (rest ~ /^"/ && rest !~ /^"[^"]*"/) skip = 1
            next
        }
        { print }
        END { if (!done) print key "=\"" val "\"" }
    ' "$file" > "$tmp"; then
        rm -f "$tmp"
        return 1
    fi
    # Overwrite in place so ownership and permissions are preserved
    cat "$tmp" > "$file"
    rm -f "$tmp"
}

# =============================================================================
# Validation helpers
# =============================================================================

# Validate an IPv4 address
is_valid_ipv4() {
    [[ "${1:-}" =~ ^(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})$ ]] || return 1
    local i
    for i in 1 2 3 4; do
        (( 10#${BASH_REMATCH[$i]} <= 255 )) || return 1
    done
    return 0
}

# Validate an IPv6 address
is_valid_ipv6() {
    local ip="${1:-}"
    [[ "$ip" =~ ^[0-9a-fA-F:]+$ && "$ip" == *:* ]] || return 1
    [[ "$ip" == *:::* ]] && return 1
    local compressed=false
    if [[ "$ip" == *::* ]]; then
        compressed=true
        local rest="${ip/::/}"
        [[ "$rest" == *::* ]] && return 1
    fi
    # A single leading or trailing colon is not allowed
    [[ "$ip" == :* && "$ip" != ::* ]] && return 1
    [[ "$ip" == *: && "$ip" != *:: ]] && return 1

    local IFS=':'
    local -a groups
    read -ra groups <<< "$ip"
    local g count=0
    for g in ${groups[@]+"${groups[@]}"}; do
        [[ -z "$g" ]] && continue
        (( ${#g} <= 4 )) || return 1
        count=$((count + 1))
    done
    if [[ "$compressed" == "true" ]]; then
        (( count <= 7 ))
    else
        (( count == 8 ))
    fi
}

# Validate CIDR notation (IPv4 or IPv6)
is_valid_cidr() {
    local cidr="${1:-}"
    [[ "$cidr" == */* ]] || return 1
    local ip="${cidr%/*}" prefix="${cidr##*/}"
    [[ "$prefix" =~ ^[0-9]{1,3}$ ]] || return 1
    if is_valid_ipv4 "$ip"; then
        (( 10#$prefix <= 32 ))
    elif is_valid_ipv6 "$ip"; then
        (( 10#$prefix <= 128 ))
    else
        return 1
    fi
}

# Validate a port number or port range (e.g., 80 or 8000:9000)
is_valid_port() {
    local port="${1:-}"
    if [[ "$port" =~ ^([0-9]{1,5}):([0-9]{1,5})$ ]]; then
        local start=$((10#${BASH_REMATCH[1]})) end=$((10#${BASH_REMATCH[2]}))
        (( start >= 1 && start <= 65535 && end >= 1 && end <= 65535 && start <= end ))
    elif [[ "$port" =~ ^[0-9]{1,5}$ ]]; then
        (( 10#$port >= 1 && 10#$port <= 65535 ))
    else
        return 1
    fi
}

# Validate a hostname (must contain at least one letter, so that a mistyped
# IP address such as 300.1.1.1 is not silently treated as a hostname)
is_valid_hostname() {
    local h="${1:-}"
    (( ${#h} >= 1 && ${#h} <= 253 )) || return 1
    [[ "$h" =~ [a-zA-Z] ]] || return 1
    [[ "$h" =~ ^[a-zA-Z0-9_]([a-zA-Z0-9_-]*[a-zA-Z0-9_])?(\.[a-zA-Z0-9_]([a-zA-Z0-9_-]*[a-zA-Z0-9_])?)*$ ]]
}

_ipv4_to_int() {
    local IFS='.'
    local -a o
    read -ra o <<< "$1"
    echo $(( (10#${o[0]} << 24) + (10#${o[1]} << 16) + (10#${o[2]} << 8) + 10#${o[3]} ))
}

# Classify an address token. Sets ADDR_KIND to one of:
#   v4 (address or CIDR), v4range (a-b), v6 (address or CIDR), v6range, host
# Returns 1 when the token is not valid.
classify_addr() {
    local a="${1:-}"
    ADDR_KIND=""
    [[ -n "$a" ]] || return 1
    if [[ "$a" == */* ]]; then
        is_valid_cidr "$a" || return 1
        if [[ "$a" == *:* ]]; then ADDR_KIND="v6"; else ADDR_KIND="v4"; fi
        return 0
    fi
    if is_valid_ipv4 "$a"; then ADDR_KIND="v4"; return 0; fi
    if is_valid_ipv6 "$a"; then ADDR_KIND="v6"; return 0; fi
    if [[ "$a" == *-* ]]; then
        local lo="${a%%-*}" hi="${a#*-}"
        if is_valid_ipv4 "$lo" && is_valid_ipv4 "$hi"; then
            (( $(_ipv4_to_int "$lo") <= $(_ipv4_to_int "$hi") )) || return 1
            ADDR_KIND="v4range"; return 0
        fi
        if is_valid_ipv6 "$lo" && is_valid_ipv6 "$hi"; then
            ADDR_KIND="v6range"; return 0
        fi
    fi
    if is_valid_hostname "$a"; then ADDR_KIND="host"; return 0; fi
    return 1
}

# Validate an IP address (v4 or v6), CIDR, range, or hostname
is_valid_host() {
    classify_addr "${1:-}"
}

# Validate a rate such as "25", "25/second" or "600/minute"
is_valid_rate() {
    [[ "${1:-}" =~ ^[1-9][0-9]{0,5}(/(second|minute|hour|day))?$ ]]
}

# Validate a network interface name
is_valid_iface() {
    [[ "${1:-}" =~ ^[a-zA-Z0-9_.@-]{1,15}$ ]]
}

# Trim whitespace; result in REPLY (no subshell)
_trim() {
    local s="${1:-}"
    s="${s#"${s%%[![:space:]]*}"}"
    s="${s%"${s##*[![:space:]]}"}"
    REPLY="$s"
}

# Split a "a|b|c" rule line into R1 R2 R3 (trimmed) and RULE_NF (field count)
split_rule() {
    local line="$1"
    local IFS='|'
    local -a f
    read -ra f <<< "$line"
    RULE_NF=${#f[@]}
    _trim "${f[0]:-}"; R1="$REPLY"
    _trim "${f[1]:-}"; R2="$REPLY"
    _trim "${f[2]:-}"; R3="$REPLY"
}

# =============================================================================
# SSH port detection
# =============================================================================

# Print every port sshd listens on (space-separated). Falls back to 22.
detect_ssh_ports() {
    local raw="" ports="" p

    # 1. Effective sshd configuration (includes sshd_config.d and defaults)
    local sshd_bin=""
    if command -v sshd &>/dev/null; then
        sshd_bin=$(command -v sshd)
    elif [[ -x /usr/sbin/sshd ]]; then
        sshd_bin="/usr/sbin/sshd"
    fi
    if [[ -n "$sshd_bin" && $EUID -eq 0 ]]; then
        raw=$("$sshd_bin" -T 2>/dev/null | awk 'tolower($1) == "port" { print $2 }') || true
    fi

    # 2. Config files
    if [[ -z "$raw" ]] && [[ -r /etc/ssh/sshd_config ]]; then
        raw=$(cat /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null \
            | awk 'tolower($1) == "port" { print $2 }') || true
    fi

    # 3. Ports a running sshd is actually listening on
    if command -v ss &>/dev/null; then
        raw+=" $(ss -H -tlnp 2>/dev/null | awk '/"sshd"/ { n = split($4, a, ":"); print a[n] }')" || true
    fi

    for p in $raw; do
        [[ "$p" =~ ^[0-9]+$ ]] && is_valid_port "$p" || continue
        [[ " $ports " == *" $p "* ]] && continue
        ports="${ports:+$ports }$p"
    done

    echo "${ports:-22}"
}

# First SSH port (kept for display purposes)
detect_ssh_port() {
    local ports
    ports=$(detect_ssh_ports)
    echo "${ports%% *}"
}

# =============================================================================
# Hostname resolution (with on-disk cache)
# =============================================================================
# Hostnames in the configuration are resolved to their A and AAAA records
# every time rules are built. The result is cached on disk so that:
#   - the firewall can start at boot before DNS is available
#   - a temporary DNS failure never removes an admin's access
#   - "dns-refresh" can detect that an address changed and reload the rules

declare -A _DNS_V4=() _DNS_V6=() _DNS_CACHE_V4=() _DNS_CACHE_V6=()
_DNS_UNRESOLVED=""
_DNS_STALE=""

dns_cache_file() {
    echo "$(state_dir)/dns-cache"
}

# Resolve one hostname for one address family (4 or 6).
# Prints a sorted, space-separated list of addresses (empty when none).
_dns_lookup() {
    local host="$1" fam="$2" out="" line result=""
    local -a tmo=()
    command -v timeout &>/dev/null && tmo=(timeout 4)

    if command -v getent &>/dev/null; then
        out=$(${tmo[@]+"${tmo[@]}"} getent "ahostsv${fam}" "$host" 2>/dev/null | awk '{ print $1 }') || true
    fi
    if [[ -z "$out" ]] && command -v dig &>/dev/null; then
        local rr="A"
        [[ "$fam" == "6" ]] && rr="AAAA"
        out=$(${tmo[@]+"${tmo[@]}"} dig +short +time=2 +tries=1 "$host" "$rr" 2>/dev/null) || true
    fi
    if [[ -z "$out" ]] && command -v host &>/dev/null; then
        local rr="A"
        [[ "$fam" == "6" ]] && rr="AAAA"
        out=$(${tmo[@]+"${tmo[@]}"} host -W 2 -t "$rr" "$host" 2>/dev/null | awk '/has (IPv6 )?address/ { print $NF }') || true
    fi

    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        if [[ "$fam" == "4" ]]; then
            is_valid_ipv4 "$line" || continue
        else
            is_valid_ipv6 "$line" || continue
        fi
        result+="$line"$'\n'
    done <<< "$out"

    printf '%s' "$result" | sort -u | tr '\n' ' ' | sed 's/ $//'
}

# Print every unique hostname used in the loaded configuration (lowercase)
config_hostnames() {
    local key tok line seen=" "
    local -a toks=()
    for key in $ADDR_LIST_KEYS; do
        for tok in ${!key:-}; do
            toks+=("$tok")
        done
    done
    while IFS= read -r line; do
        [[ -z "${line// /}" || "$line" == \#* ]] && continue
        split_rule "$line"
        [[ -n "$R3" ]] && toks+=("$R3")
    done <<< "${PORT_IP_RULES:-}"

    for tok in ${toks[@]+"${toks[@]}"}; do
        classify_addr "$tok" || continue
        [[ "$ADDR_KIND" == "host" ]] || continue
        tok="${tok,,}"
        [[ "$seen" == *" $tok "* ]] && continue
        seen+="$tok "
        echo "$tok"
    done
}

# Load the on-disk DNS cache into _DNS_CACHE_V4 / _DNS_CACHE_V6
dns_cache_load() {
    _DNS_CACHE_V4=(); _DNS_CACHE_V6=()
    local f host v4 v6
    f=$(dns_cache_file)
    [[ -r "$f" ]] || return 0
    while IFS='|' read -r host v4 v6; do
        [[ -z "$host" ]] && continue
        _DNS_CACHE_V4[$host]="$v4"
        _DNS_CACHE_V6[$host]="$v6"
    done < "$f"
}

# Render the current resolution result in cache-file format (sorted)
dns_cache_render() {
    local host
    for host in $(config_hostnames | sort); do
        echo "${host}|${_DNS_V4[$host]:-}|${_DNS_V6[$host]:-}"
    done
}

# Persist the current resolution result
dns_cache_save() {
    ensure_state_dir || return 0
    local f
    f=$(dns_cache_file)
    dns_cache_render > "${f}.tmp" 2>/dev/null && mv -f "${f}.tmp" "$f" 2>/dev/null || true
}

# Resolve every hostname in the loaded configuration.
# Unresolvable hostnames fall back to the cached addresses.
resolve_config_hosts() {
    _DNS_V4=(); _DNS_V6=()
    _DNS_UNRESOLVED=""; _DNS_STALE=""
    dns_cache_load

    local host v4 v6 cached streak=0
    for host in $(config_hostnames); do
        v4=""; v6=""
        cached="${_DNS_CACHE_V4[$host]:-}${_DNS_CACHE_V6[$host]:-}"
        # After two consecutive failures DNS is evidently unavailable (e.g.
        # early boot): stop waiting on lookups for hosts we have cached.
        if (( streak < 2 )) || [[ -z "$cached" ]]; then
            v4=$(_dns_lookup "$host" 4)
            v6=$(_dns_lookup "$host" 6)
        fi
        if [[ -z "${v4}${v6}" ]]; then
            streak=$((streak + 1))
            if [[ -n "$cached" ]]; then
                v4="${_DNS_CACHE_V4[$host]:-}"
                v6="${_DNS_CACHE_V6[$host]:-}"
                _DNS_STALE+=" $host"
                log_debug "Could not resolve ${host} — using cached address(es): ${v4} ${v6}"
            else
                _DNS_UNRESOLVED+=" $host"
                log_warn "Could not resolve hostname: ${host} (no cached address — rules for it are skipped)"
            fi
        else
            streak=0
        fi
        _DNS_V4[$host]="$v4"
        _DNS_V6[$host]="$v6"
    done
}

# Kept for backwards compatibility: resolve a single host to IPv4 address(es)
resolve_hostname() {
    local hostname="$1"
    if classify_addr "$hostname" && [[ "$ADDR_KIND" != "host" ]]; then
        echo "$hostname"
        return 0
    fi
    local resolved
    resolved=$(_dns_lookup "$hostname" 4)
    if [[ -n "$resolved" ]]; then
        echo "$resolved"
        return 0
    fi
    log_warn "Could not resolve hostname: $hostname"
    return 1
}

# Sort address tokens into ADDR4 / ADDR6 arrays. Hostnames are replaced by
# their resolved addresses (resolve_config_hosts must have run).
collect_addrs() {
    ADDR4=(); ADDR6=()
    local tok ip seen4=" " seen6=" "
    for tok in "$@"; do
        if ! classify_addr "$tok"; then
            log_warn "Ignoring invalid address: $tok"
            continue
        fi
        case "$ADDR_KIND" in
            v4|v4range)
                [[ "$seen4" == *" $tok "* ]] || { ADDR4+=("$tok"); seen4+="$tok "; } ;;
            v6|v6range)
                [[ "$seen6" == *" $tok "* ]] || { ADDR6+=("$tok"); seen6+="$tok "; } ;;
            host)
                tok="${tok,,}"
                for ip in ${_DNS_V4[$tok]:-}; do
                    [[ "$seen4" == *" $ip "* ]] || { ADDR4+=("$ip"); seen4+="$ip "; }
                done
                for ip in ${_DNS_V6[$tok]:-}; do
                    [[ "$seen6" == *" $ip "* ]] || { ADDR6+=("$ip"); seen6+="$ip "; }
                done ;;
        esac
    done
}

# Join arguments with ", "
join_comma() {
    local out="" item
    for item in "$@"; do
        out+="${out:+, }$item"
    done
    echo "$out"
}

# True when SSH is restricted to an allow-list
ssh_is_restricted() {
    [[ -n "${SSH_ALLOWED_IPS// /}${SSH_ALLOWED_IPS_IPV6// /}" ]]
}

# Print the publicly open TCP ports. When SSH is restricted, the SSH port(s)
# are left out: access to them is decided by the allow-list only.
public_tcp_ports() {
    local p out=""
    for p in $TCP_PORTS $TCP_PORTS_INPUT; do
        if ssh_is_restricted && [[ " $SSH_PORTS " == *" $p "* ]]; then
            continue
        fi
        out+="${out:+ }$p"
    done
    echo "$out"
}

# =============================================================================
# Rule summary
# =============================================================================

print_rule_summary() {
    local config_file="$1"
    load_config "$config_file"

    local row="  ${CYAN}│${NC}"
    echo ""
    echo -e "  ${BOLD}${CYAN}┌─────────────────────────────────────────────────────┐${NC}"
    echo -e "  ${BOLD}${CYAN}│${NC}  ${BOLD}Firewall Rule Summary${NC}                               ${BOLD}${CYAN}│${NC}"
    echo -e "  ${BOLD}${CYAN}├─────────────────────────────────────────────────────┤${NC}"

    [[ -n "$TCP_PORTS" ]]       && echo -e "$row  ${GREEN}TCP open:${NC}        $TCP_PORTS"
    [[ -n "$TCP_PORTS_INPUT" ]] && echo -e "$row  ${GREEN}TCP open:${NC}        $TCP_PORTS_INPUT"
    [[ -n "$UDP_PORTS" ]]       && echo -e "$row  ${GREEN}UDP open:${NC}        $UDP_PORTS"
    [[ -z "${TCP_PORTS}${TCP_PORTS_INPUT}${UDP_PORTS}" ]] && echo -e "$row  ${YELLOW}No public ports open${NC}"
    echo -e "$row  ${GREEN}Outgoing:${NC}        all allowed (except blocked below)"

    [[ -n "$BLOCKED_TCP_PORTS" ]]        && echo -e "$row  ${RED}TCP blocked:${NC}     $BLOCKED_TCP_PORTS (in + out)"
    [[ -n "$BLOCKED_UDP_PORTS" ]]        && echo -e "$row  ${RED}UDP blocked:${NC}     $BLOCKED_UDP_PORTS (in + out)"
    [[ -n "$BLOCKED_TCP_PORTS_OUTPUT" ]] && echo -e "$row  ${RED}TCP out block:${NC}   $BLOCKED_TCP_PORTS_OUTPUT"
    [[ -n "$BLOCKED_UDP_PORTS_OUTPUT" ]] && echo -e "$row  ${RED}UDP out block:${NC}   $BLOCKED_UDP_PORTS_OUTPUT"

    echo -e "  ${CYAN}├─────────────────────────────────────────────────────┤${NC}"

    if ssh_is_restricted; then
        echo -e "$row  ${YELLOW}SSH (${SSH_PORTS}):${NC}       restricted to: ${SSH_ALLOWED_IPS} ${SSH_ALLOWED_IPS_IPV6}"
    else
        echo -e "$row  ${YELLOW}SSH (${SSH_PORTS}):${NC}       open to everyone"
    fi

    [[ -n "${TRUSTED_IPS}${TRUSTED_IPS_IPV6}" ]]       && echo -e "$row  ${GREEN}Trusted IPs:${NC}     $TRUSTED_IPS $TRUSTED_IPS_IPV6"
    [[ -n "${TRUSTED_RANGES}${TRUSTED_RANGES_IPV6}" ]] && echo -e "$row  ${GREEN}Trusted ranges:${NC}  $TRUSTED_RANGES $TRUSTED_RANGES_IPV6"
    [[ -n "${BLACKLIST}${BLACKLIST_IPV6}" ]]           && echo -e "$row  ${RED}Blacklisted:${NC}     $BLACKLIST $BLACKLIST_IPV6"
    [[ -n "${BLOCKED_RANGES}${BLOCKED_RANGES_IPV6}" ]] && echo -e "$row  ${RED}Blocked ranges:${NC}  $BLOCKED_RANGES $BLOCKED_RANGES_IPV6"

    if [[ -n "${PORT_IP_RULES// /}" ]]; then
        local line
        while IFS= read -r line; do
            [[ -z "${line// /}" ]] && continue
            echo -e "$row  ${BLUE}Port-IP rule:${NC}    $line"
        done <<< "$PORT_IP_RULES"
    fi
    if [[ -n "${PORT_FORWARD_RULES// /}" ]]; then
        if [[ "$NAT_ENABLE" == "true" ]]; then
            echo -e "$row  ${BLUE}Port forwards:${NC}   active"
        else
            echo -e "$row  ${YELLOW}Port forwards:${NC}   NOT active (NAT_ENABLE is false)"
        fi
    fi

    local hosts
    hosts=$(config_hostnames | tr '\n' ' ')
    if [[ -n "${hosts// /}" ]]; then
        if [[ "${DNS_REFRESH_INTERVAL:-5}" != "0" ]]; then
            echo -e "$row  ${BLUE}Hostnames:${NC}       re-checked every ${DNS_REFRESH_INTERVAL} min (auto-reload on change)"
        else
            echo -e "$row  ${YELLOW}Hostnames:${NC}       resolved at start only (DNS_REFRESH_INTERVAL=0)"
        fi
    fi

    echo -e "  ${CYAN}├─────────────────────────────────────────────────────┤${NC}"

    local features=""
    if [[ "$ICMP_ENABLE" == "true" ]]; then features+="${GREEN}ping${NC} "; else features+="${RED}no-ping${NC} "; fi
    [[ "$MULTICAST_ENABLE" == "true" ]]  && features+="${GREEN}multicast${NC} "
    [[ "$RATE_LIMIT_ENABLE" == "true" ]] && features+="${GREEN}rate-limit${NC} "
    [[ "$LOG_DROPPED" == "true" ]]       && features+="${GREEN}logging${NC} "
    [[ "$NAT_ENABLE" == "true" ]]        && features+="${GREEN}nat${NC} "
    [[ "$SYN_FLOOD_PROTECT" == "true" ]] && features+="${GREEN}syn-protect${NC} "
    [[ "$CONN_LIMIT_ENABLE" == "true" ]] && features+="${GREEN}conn-limit${NC} "
    [[ "${CONN_RATE_PER_IP:-0}" != "0" ]] && features+="${GREEN}conn-rate${NC} "
    echo -e "$row  ${BOLD}Features:${NC}        $features"

    echo -e "  ${CYAN}└─────────────────────────────────────────────────────┘${NC}"
    echo ""
}

# =============================================================================
# Configuration validation
# =============================================================================

CT_ERRORS=()
CT_WARNINGS=()
CT_OK=()

_ct_err()  { CT_ERRORS+=("$1"); }
_ct_warn() { CT_WARNINGS+=("$1"); }
_ct_ok()   { CT_OK+=("$1"); }

# Validate the currently loaded configuration values.
# Fills CT_ERRORS / CT_WARNINGS / CT_OK. Returns 1 when there are errors.
config_validate() {
    CT_ERRORS=(); CT_WARNINGS=(); CT_OK=()
    local key tok bad count line n

    # --- Port lists ---
    for key in $PORT_LIST_KEYS; do
        [[ -z "${!key// /}" ]] && continue
        bad=""; count=0
        for tok in ${!key}; do
            count=$((count + 1))
            is_valid_port "$tok" || { bad="$tok"; break; }
        done
        if [[ -n "$bad" ]]; then
            _ct_err "${key}: invalid port '${bad}' (use 1-65535 or a range like 8000:9000)"
        else
            _ct_ok "${key}: ${count} port(s)"
        fi
    done

    # --- Address lists ---
    for key in $ADDR_LIST_KEYS; do
        [[ -z "${!key// /}" ]] && continue
        bad=""; count=0
        for tok in ${!key}; do
            count=$((count + 1))
            classify_addr "$tok" || { bad="$tok"; break; }
        done
        if [[ -n "$bad" ]]; then
            _ct_err "${key}: invalid entry '${bad}' (use an IP, CIDR, range a-b, or hostname)"
        else
            _ct_ok "${key}: ${count} entry(s)"
        fi
    done

    # --- PORT_IP_RULES ---
    if [[ -n "${PORT_IP_RULES// /}" ]]; then
        n=0; bad=0
        while IFS= read -r line; do
            [[ -z "${line// /}" ]] && continue
            n=$((n + 1))
            split_rule "$line"
            if (( RULE_NF != 3 )); then
                _ct_err "PORT_IP_RULES: rule #${n} '${line}' must be protocol|port|address"; bad=1; continue
            fi
            [[ "$R1" == "tcp" || "$R1" == "udp" ]] || { _ct_err "PORT_IP_RULES: rule #${n}: protocol '${R1}' invalid (use tcp or udp)"; bad=1; }
            is_valid_port "$R2" || { _ct_err "PORT_IP_RULES: rule #${n}: port '${R2}' invalid"; bad=1; }
            classify_addr "$R3" || { _ct_err "PORT_IP_RULES: rule #${n}: address '${R3}' invalid"; bad=1; }
        done <<< "$PORT_IP_RULES"
        [[ "$bad" == "0" ]] && _ct_ok "PORT_IP_RULES: ${n} rule(s)"
    fi

    # --- PORT_FORWARD_RULES ---
    if [[ -n "${PORT_FORWARD_RULES// /}" ]]; then
        n=0; bad=0
        while IFS= read -r line; do
            [[ -z "${line// /}" ]] && continue
            n=$((n + 1))
            split_rule "$line"
            if (( RULE_NF != 3 )); then
                _ct_err "PORT_FORWARD_RULES: rule #${n} '${line}' must be protocol|port|ip:port"; bad=1; continue
            fi
            [[ "$R1" == "tcp" || "$R1" == "udp" ]] || { _ct_err "PORT_FORWARD_RULES: rule #${n}: protocol '${R1}' invalid (use tcp or udp)"; bad=1; }
            is_valid_port "$R2" || { _ct_err "PORT_FORWARD_RULES: rule #${n}: port '${R2}' invalid"; bad=1; }
            local dip="${R3%%:*}" dport=""
            [[ "$R3" == *:* ]] && dport="${R3#*:}"
            if ! is_valid_ipv4 "$dip"; then
                _ct_err "PORT_FORWARD_RULES: rule #${n}: destination '${R3}' must be an IPv4 address with optional :port"; bad=1
            elif [[ -n "$dport" ]] && ! [[ "$dport" =~ ^[0-9]+$ && "$dport" -ge 1 && "$dport" -le 65535 ]]; then
                _ct_err "PORT_FORWARD_RULES: rule #${n}: destination port '${dport}' invalid"; bad=1
            fi
        done <<< "$PORT_FORWARD_RULES"
        [[ "$bad" == "0" ]] && _ct_ok "PORT_FORWARD_RULES: ${n} rule(s)"
        if [[ "$NAT_ENABLE" != "true" ]]; then
            _ct_warn "PORT_FORWARD_RULES is set but NAT_ENABLE is not 'true' — port forwarding is NOT active"
        fi
    fi

    # --- Booleans ---
    for key in $BOOL_KEYS; do
        if [[ "${!key}" != "true" && "${!key}" != "false" ]]; then
            _ct_err "${key}: '${!key}' is not valid (use true or false)"
        fi
    done

    # --- Numbers ---
    for key in CONN_LIMIT_PER_IP CONN_RATE_PER_IP RATE_LIMIT_BURST DNS_REFRESH_INTERVAL; do
        if ! [[ "${!key}" =~ ^[0-9]{1,5}$ ]]; then
            _ct_err "${key}: '${!key}' is not a number"
        fi
    done
    if [[ "$CONN_LIMIT_ENABLE" == "true" && "$CONN_LIMIT_PER_IP" =~ ^0*$ ]]; then
        _ct_err "CONN_LIMIT_PER_IP: must be at least 1 when CONN_LIMIT_ENABLE=true"
    fi
    if [[ "$RATE_LIMIT_ENABLE" == "true" ]]; then
        is_valid_rate "$RATE_LIMIT_RATE" || _ct_err "RATE_LIMIT_RATE: '${RATE_LIMIT_RATE}' is not valid (use e.g. 25, 25/second or 600/minute)"
        [[ "$RATE_LIMIT_BURST" =~ ^0*$ ]] && _ct_err "RATE_LIMIT_BURST: must be at least 1"
    fi

    # --- NAT ---
    if [[ "$NAT_ENABLE" == "true" ]]; then
        is_valid_iface "$NAT_EXTERNAL_IFACE" || _ct_err "NAT_EXTERNAL_IFACE: '${NAT_EXTERNAL_IFACE}' is not a valid interface name (required when NAT_ENABLE=true)"
        is_valid_iface "$NAT_INTERNAL_IFACE" || _ct_err "NAT_INTERNAL_IFACE: '${NAT_INTERNAL_IFACE}' is not a valid interface name (required when NAT_ENABLE=true)"
    fi

    # --- Custom rules file ---
    if [[ -n "$CUSTOM_RULES_FILE" ]] && [[ ! -f "$CUSTOM_RULES_FILE" ]]; then
        _ct_warn "CUSTOM_RULES_FILE: '${CUSTOM_RULES_FILE}' does not exist (will be skipped)"
    fi

    # --- Things that do not do what one might expect ---
    if [[ -n "${TCP_PORTS_OUTPUT// /}" ]]; then
        _ct_warn "TCP_PORTS_OUTPUT has no effect: all outgoing traffic is allowed (use BLOCKED_TCP_PORTS_OUTPUT to block)"
    fi
    if [[ "$SMTP_ENABLE" == "false" ]]; then
        _ct_warn "SMTP_ENABLE=false has no effect: outgoing mail is NOT blocked (use BLOCKED_TCP_PORTS_OUTPUT=\"25 465 587\")"
    fi

    if ssh_is_restricted; then
        local p
        for p in $SSH_PORTS; do
            if [[ " ${TCP_PORTS} ${TCP_PORTS_INPUT} " == *" $p "* ]]; then
                _ct_warn "SSH port ${p} is listed in TCP_PORTS but SSH_ALLOWED_IPS is set — the restriction wins, SSH stays limited to the allowed IPs"
            fi
        done
        _ct_ok "SSH (${SSH_PORTS}): restricted to allowed IPs"
    else
        _ct_ok "SSH (${SSH_PORTS}): open to everyone (always kept reachable)"
    fi

    if [[ -z "${TCP_PORTS// /}${TCP_PORTS_INPUT// /}${UDP_PORTS// /}" ]]; then
        _ct_warn "No open ports defined — only SSH and established connections will work"
    fi

    (( ${#CT_ERRORS[@]} == 0 ))
}

# Configuration test with formatted output.
# Returns 0 on success, 1 on error. Warnings are non-fatal.
configtest() {
    local config_file="$1"
    local row="  ${CYAN}│${NC}"
    local bottom="  ${CYAN}└─────────────────────────────────────────────────────┘${NC}"

    echo ""
    echo -e "  ${BOLD}${CYAN}┌─────────────────────────────────────────────────────┐${NC}"
    echo -e "  ${BOLD}${CYAN}│${NC}  ${BOLD}Configuration Test${NC}                                  ${BOLD}${CYAN}│${NC}"
    echo -e "  ${BOLD}${CYAN}├─────────────────────────────────────────────────────┤${NC}"

    if [[ ! -f "$config_file" ]]; then
        echo -e "$row  ${RED}✗ Config file not found:${NC} $config_file"
        echo -e "$row    Run: ${BOLD}binadit-firewall setup${NC}"
        echo -e "$bottom"
        return 1
    fi
    if [[ ! -r "$config_file" ]]; then
        echo -e "$row  ${RED}✗ Config file not readable${NC} (check permissions)"
        echo -e "$bottom"
        return 1
    fi

    local syntax_err
    syntax_err=$(bash -n "$config_file" 2>&1) || true
    if [[ -n "$syntax_err" ]]; then
        echo -e "$row  ${RED}✗ Bash syntax error in config:${NC}"
        echo -e "$row    $syntax_err"
        echo -e "$bottom"
        return 1
    fi
    echo -e "$row  ${GREEN}✓${NC} Config syntax valid"

    load_config "$config_file"
    config_validate || true

    local msg
    for msg in ${CT_OK[@]+"${CT_OK[@]}"}; do
        echo -e "$row  ${GREEN}✓${NC} $msg"
    done
    for msg in ${CT_ERRORS[@]+"${CT_ERRORS[@]}"}; do
        echo -e "$row  ${RED}✗${NC} $msg"
    done
    for msg in ${CT_WARNINGS[@]+"${CT_WARNINGS[@]}"}; do
        echo -e "$row  ${YELLOW}⚠${NC} $msg"
    done

    local errors=${#CT_ERRORS[@]} warnings=${#CT_WARNINGS[@]}
    echo -e "  ${CYAN}├─────────────────────────────────────────────────────┤${NC}"
    if (( errors > 0 )); then
        echo -e "$row  ${RED}${BOLD}FAILED${NC} — ${errors} error(s), ${warnings} warning(s)"
        echo -e "$row  Fix the errors above and try again."
        echo -e "$bottom"
        echo ""
        return 1
    elif (( warnings > 0 )); then
        echo -e "$row  ${YELLOW}${BOLD}PASSED with warnings${NC} — ${warnings} warning(s)"
    else
        echo -e "$row  ${GREEN}${BOLD}ALL CHECKS PASSED${NC}"
    fi
    echo -e "$bottom"
    echo ""
    return 0
}

# =============================================================================
# Backups
# =============================================================================

# Create a backup of the current firewall rules (keeps the 30 newest files)
backup_rules() {
    local backup_dir="${CONFIG_DIR:-/etc/binadit-firewall}/backups"
    local timestamp
    timestamp=$(date +%Y%m%d_%H%M%S)

    mkdir -p "$backup_dir" 2>/dev/null || return 0

    if command -v nft &>/dev/null; then
        nft list ruleset > "$backup_dir/nftables_${timestamp}.bak" 2>/dev/null || true
    fi
    if command -v iptables-save &>/dev/null; then
        iptables-save > "$backup_dir/iptables_${timestamp}.bak" 2>/dev/null || true
    fi
    if command -v ip6tables-save &>/dev/null; then
        ip6tables-save > "$backup_dir/ip6tables_${timestamp}.bak" 2>/dev/null || true
    fi
    # Empty backups (backend not in use) are just noise
    find "$backup_dir" -name "*_${timestamp}.bak" -type f -size 0 -delete 2>/dev/null || true

    local count
    count=$(find "$backup_dir" -name "*.bak" -type f | wc -l)
    if (( count > 30 )); then
        find "$backup_dir" -name "*.bak" -type f | sort | head -n "$(( count - 30 ))" | xargs rm -f
    fi

    log_debug "Backup saved to $backup_dir/*_${timestamp}.bak"
}

# =============================================================================
# Migration from binadit-firewall v1.x (2013)
# =============================================================================

# True when port $1 is covered by the port list $2 (single ports and ranges)
port_in_list() {
    local port="$1" entry
    for entry in $2; do
        if [[ "$entry" =~ ^([0-9]+)[:-]([0-9]+)$ ]]; then
            (( port >= BASH_REMATCH[1] && port <= BASH_REMATCH[2] )) && return 0
        elif [[ "$entry" == "$port" ]]; then
            return 0
        fi
    done
    return 1
}

# Migrate /etc/firewall.d/host.conf into a new-style config file.
# $1 old config, $2 new config, $3 example config to start from
migrate_v1_config() {
    local old_config="$1" new_conf="$2" example="$3"

    if [[ -f "$new_conf" ]]; then
        log_warn "Not migrating ${old_config}: ${new_conf} already exists"
        return 0
    fi
    [[ -f "$example" ]] || { log_error "Example config not found: $example"; return 1; }

    # Read the old values in a subshell so they cannot leak into this script
    local dump
    dump=$(
        set +u
        # shellcheck source=/dev/null
        source "$old_config" >/dev/null 2>&1
        printf 'TCP_PORTS=%s\n'            "$TCPPORTS"
        printf 'TCP_PORTS_INPUT=%s\n'      "$TCPPORTS_INPUT"
        printf 'UDP_PORTS=%s\n'            "$UDPPORTS"
        printf 'TRUSTED_IPS=%s\n'          "$DMZS"
        printf 'TRUSTED_IPS_IPV6=%s\n'     "$DMZS_IPv6"
        # v1 allowed SSH from SSHACCESS and from everything with full access
        # (DMZS, DMZRANGE). In v3 an empty SSH_ALLOWED_IPS means "open to
        # everyone", so the full-access entries are carried over as well.
        printf 'SSH_ALLOWED_IPS=%s\n'      "$SSHACCESS $DMZS $DMZRANGE"
        printf 'SSH_ALLOWED_IPS_IPV6=%s\n' "$SSHACCESS_IPv6 $DMZS_IPv6"
        printf 'TRUSTED_RANGES=%s\n'       "$DMZRANGE"
        printf 'BLACKLIST=%s\n'            "$BLACKLIST"
        printf 'BLACKLIST_IPV6=%s\n'       "$BLACKLIST_IPv6"
        printf 'BLOCKED_RANGES=%s\n'       "$BLOCKRANGE"
        [[ "$MULTICAST_ENABLE" == "TRUE" ]] && printf 'MULTICAST_ENABLE=true\n'
        [[ "$NATROUTER_ENABLE" == "TRUE" ]] && printf 'NAT_ENABLE=true\n'
        true
    ) || { log_error "Could not read ${old_config}"; return 1; }

    mkdir -p "$(dirname "$new_conf")"
    cp "$example" "$new_conf"

    local key value v1_tcp="" v1_ssh=""
    while IFS='=' read -r key value; do
        [[ -z "$key" ]] && continue
        # v1 always had explicit port lists: an empty list there means "none"
        if [[ -z "$value" && "$key" != "TCP_PORTS" ]]; then
            continue
        fi
        value=$(echo "$value" | xargs)
        case "$key" in
            TCP_PORTS)            v1_tcp="$value" ;;
            TCP_PORTS_INPUT)      v1_tcp+=" $value" ;;
            SSH_ALLOWED_IPS)      v1_ssh="$value" ;;
            SSH_ALLOWED_IPS_IPV6) v1_ssh+=" $value" ;;
        esac
        # Decided below, once the whole v1 config is known
        [[ "$key" == SSH_ALLOWED_IPS* ]] && continue
        config_set_value "$new_conf" "$key" "$value" || return 1
    done <<< "$dump"

    # SSH: keep exactly who could reach it under v1
    local ssh_ports ssh_public="false" p
    ssh_ports="${BINADIT_V1_SSH_PORTS:-$(detect_ssh_ports)}"
    for p in $ssh_ports; do
        port_in_list "$p" "$v1_tcp" && ssh_public="true"
    done
    if [[ "$ssh_public" == "true" ]]; then
        log_info "SSH port (${ssh_ports}) was open to everyone in v1 (listed in TCPPORTS) — kept that way"
    elif [[ -n "${v1_ssh// /}" ]]; then
        local val
        for key in SSH_ALLOWED_IPS SSH_ALLOWED_IPS_IPV6; do
            val=$(sed -n "s/^${key}=//p" <<< "$dump" | xargs)
            [[ -n "$val" ]] && { config_set_value "$new_conf" "$key" "$val" || return 1; }
        done
        log_success "SSH stays restricted to the v1 addresses (SSHACCESS, DMZS, DMZRANGE)"
    else
        log_warn "v1 allowed SSH from nobody (no SSHACCESS/DMZS and the SSH port was not in TCPPORTS)."
        log_warn "binadit-firewall never closes SSH completely: SSH is now OPEN TO EVERYONE."
        log_warn "Restrict it with: binadit-firewall config set SSH_ALLOWED_IPS \"<your-ip>\""
    fi

    mv "$old_config" "${old_config}.migrated.$(date +%Y%m%d)"
    log_success "Config migrated: ${old_config} -> ${new_conf}"
    log_info "Old config kept as: ${old_config}.migrated.*"
    log_info "Note: outgoing traffic is no longer filtered per port (v1 TCPPORTS_OUTPUT is not needed anymore)"

    # Retire the old init script so it cannot load the old rules at boot
    if [[ -f /etc/init.d/firewall ]]; then
        if command -v update-rc.d &>/dev/null; then
            update-rc.d -f firewall remove &>/dev/null || true
        elif command -v chkconfig &>/dev/null; then
            chkconfig --del firewall &>/dev/null || true
        fi
        mv /etc/init.d/firewall /etc/init.d/firewall.v1.bak
        chmod -x /etc/init.d/firewall.v1.bak 2>/dev/null || true
        log_info "Old init script retired: /etc/init.d/firewall.v1.bak"
    fi
}
