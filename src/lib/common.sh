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
    readonly BINADIT_VERSION="2.2.0"
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

# Print a summary of the applied rules
print_rule_summary() {
    local config_file="$1"
    # shellcheck source=/dev/null
    source "$config_file"

    local ssh_port
    ssh_port=$(detect_ssh_port)

    echo ""
    echo -e "  ${BOLD}${CYAN}┌─────────────────────────────────────────────────────┐${NC}"
    echo -e "  ${BOLD}${CYAN}│${NC}  ${BOLD}Firewall Rule Summary${NC}                               ${BOLD}${CYAN}│${NC}"
    echo -e "  ${BOLD}${CYAN}├─────────────────────────────────────────────────────┤${NC}"

    # TCP Ports
    if [[ -n "${TCP_PORTS:-}" ]]; then
        echo -e "  ${CYAN}│${NC}  ${GREEN}TCP open:${NC}        $TCP_PORTS"
    fi
    if [[ -n "${TCP_PORTS_INPUT:-}" ]]; then
        echo -e "  ${CYAN}│${NC}  ${GREEN}TCP in-only:${NC}     $TCP_PORTS_INPUT"
    fi
    if [[ -n "${TCP_PORTS_OUTPUT:-}" ]]; then
        echo -e "  ${CYAN}│${NC}  ${GREEN}TCP out-only:${NC}    $TCP_PORTS_OUTPUT"
    fi
    if [[ -n "${UDP_PORTS:-}" ]]; then
        echo -e "  ${CYAN}│${NC}  ${GREEN}UDP open:${NC}        $UDP_PORTS"
    fi

    # Blocked
    if [[ -n "${BLOCKED_TCP_PORTS:-}" ]]; then
        echo -e "  ${CYAN}│${NC}  ${RED}TCP blocked:${NC}     $BLOCKED_TCP_PORTS"
    fi
    if [[ -n "${BLOCKED_UDP_PORTS:-}" ]]; then
        echo -e "  ${CYAN}│${NC}  ${RED}UDP blocked:${NC}     $BLOCKED_UDP_PORTS"
    fi
    if [[ -n "${BLOCKED_TCP_PORTS_OUTPUT:-}" ]]; then
        echo -e "  ${CYAN}│${NC}  ${RED}TCP out block:${NC}   $BLOCKED_TCP_PORTS_OUTPUT"
    fi
    if [[ -n "${BLOCKED_UDP_PORTS_OUTPUT:-}" ]]; then
        echo -e "  ${CYAN}│${NC}  ${RED}UDP out block:${NC}   $BLOCKED_UDP_PORTS_OUTPUT"
    fi

    echo -e "  ${CYAN}├─────────────────────────────────────────────────────┤${NC}"

    # SSH
    if [[ -n "${SSH_ALLOWED_IPS:-}" ]]; then
        echo -e "  ${CYAN}│${NC}  ${YELLOW}SSH (${ssh_port}):${NC}       restricted to: ${SSH_ALLOWED_IPS}"
    else
        echo -e "  ${CYAN}│${NC}  ${YELLOW}SSH (${ssh_port}):${NC}       open (via TCP_PORTS or unrestricted)"
    fi

    # Trusted
    if [[ -n "${TRUSTED_IPS:-}" ]]; then
        echo -e "  ${CYAN}│${NC}  ${GREEN}Trusted IPs:${NC}     $TRUSTED_IPS"
    fi
    if [[ -n "${TRUSTED_RANGES:-}" ]]; then
        echo -e "  ${CYAN}│${NC}  ${GREEN}Trusted ranges:${NC}  $TRUSTED_RANGES"
    fi

    # Blacklist
    if [[ -n "${BLACKLIST:-}" ]]; then
        echo -e "  ${CYAN}│${NC}  ${RED}Blacklisted:${NC}     $BLACKLIST"
    fi
    if [[ -n "${BLOCKED_RANGES:-}" ]]; then
        echo -e "  ${CYAN}│${NC}  ${RED}Blocked ranges:${NC}  $BLOCKED_RANGES"
    fi

    # Port-IP rules
    if [[ -n "${PORT_IP_RULES:-}" ]]; then
        echo -e "  ${CYAN}│${NC}  ${BLUE}Port-IP rules:${NC}   (custom rules active)"
    fi

    # Port forwarding
    if [[ -n "${PORT_FORWARD_RULES:-}" ]]; then
        echo -e "  ${CYAN}│${NC}  ${BLUE}Port forwards:${NC}   (active)"
    fi

    echo -e "  ${CYAN}├─────────────────────────────────────────────────────┤${NC}"

    # Features
    local features=""
    [[ "${ICMP_ENABLE:-true}" == "true" ]] && features+="${GREEN}ping${NC} "
    [[ "${ICMP_ENABLE:-true}" != "true" ]] && features+="${RED}no-ping${NC} "
    [[ "${MULTICAST_ENABLE:-false}" == "true" ]] && features+="${GREEN}multicast${NC} "
    [[ "${RATE_LIMIT_ENABLE:-true}" == "true" ]] && features+="${GREEN}rate-limit${NC} "
    [[ "${LOG_DROPPED:-true}" == "true" ]] && features+="${GREEN}logging${NC} "
    [[ "${NAT_ENABLE:-false}" == "true" ]] && features+="${GREEN}nat${NC} "
    [[ "${SYN_FLOOD_PROTECT:-true}" == "true" ]] && features+="${GREEN}syn-protect${NC} "
    [[ "${CONN_LIMIT_ENABLE:-false}" == "true" ]] && features+="${GREEN}conn-limit${NC} "
    echo -e "  ${CYAN}│${NC}  ${BOLD}Features:${NC}        $features"

    echo -e "  ${CYAN}└─────────────────────────────────────────────────────┘${NC}"
    echo ""
}

# =============================================================================
# Configuration test — validates every setting with clear feedback
# Returns 0 on success, 1 on error. Prints warnings for non-fatal issues.
# =============================================================================
configtest() {
    local config_file="$1"
    local errors=0
    local warnings=0

    echo ""
    echo -e "  ${BOLD}${CYAN}┌─────────────────────────────────────────────────────┐${NC}"
    echo -e "  ${BOLD}${CYAN}│${NC}  ${BOLD}Configuration Test${NC}                                  ${BOLD}${CYAN}│${NC}"
    echo -e "  ${BOLD}${CYAN}├─────────────────────────────────────────────────────┤${NC}"

    # --- File checks ---
    if [[ ! -f "$config_file" ]]; then
        echo -e "  ${CYAN}│${NC}  ${RED}✗ Config file not found:${NC} $config_file"
        echo -e "  ${CYAN}│${NC}    Run: ${BOLD}binadit-firewall setup${NC}"
        echo -e "  ${CYAN}│${NC}    Or:  ${BOLD}cp ${config_file}.example ${config_file}${NC}"
        echo -e "  ${CYAN}└─────────────────────────────────────────────────────┘${NC}"
        return 1
    fi

    if [[ ! -r "$config_file" ]]; then
        echo -e "  ${CYAN}│${NC}  ${RED}✗ Config file not readable${NC} (check permissions)"
        echo -e "  ${CYAN}└─────────────────────────────────────────────────────┘${NC}"
        return 1
    fi

    # Bash syntax check
    local syntax_err
    syntax_err=$(bash -n "$config_file" 2>&1) || true
    if [[ -n "$syntax_err" ]]; then
        echo -e "  ${CYAN}│${NC}  ${RED}✗ Bash syntax error in config:${NC}"
        echo -e "  ${CYAN}│${NC}    $syntax_err"
        echo -e "  ${CYAN}└─────────────────────────────────────────────────────┘${NC}"
        return 1
    fi
    echo -e "  ${CYAN}│${NC}  ${GREEN}✓${NC} Config syntax valid"

    # Source config
    # shellcheck source=/dev/null
    source "$config_file"

    # --- Helper: validate a space-separated list of ports ---
    _ct_check_ports() {
        local label="$1" value="$2"
        if [[ -z "$value" ]]; then return 0; fi
        for p in $value; do
            if ! is_valid_port "$p"; then
                echo -e "  ${CYAN}│${NC}  ${RED}✗ ${label}:${NC} invalid port '${BOLD}$p${NC}' (use 1-65535 or range like 8000:9000)"
                errors=$((errors + 1))
                return 1
            fi
        done
        local count
        count=$(echo "$value" | wc -w | tr -d ' ')
        echo -e "  ${CYAN}│${NC}  ${GREEN}✓${NC} ${label}: ${count} port(s)"
        return 0
    }

    # --- Helper: validate a space-separated list of hosts/IPs ---
    _ct_check_hosts() {
        local label="$1" value="$2"
        if [[ -z "$value" ]]; then return 0; fi
        for h in $value; do
            if ! is_valid_host "$h"; then
                echo -e "  ${CYAN}│${NC}  ${RED}✗ ${label}:${NC} invalid host '${BOLD}$h${NC}' (use IP, CIDR, or hostname)"
                errors=$((errors + 1))
                return 1
            fi
        done
        local count
        count=$(echo "$value" | wc -w | tr -d ' ')
        echo -e "  ${CYAN}│${NC}  ${GREEN}✓${NC} ${label}: ${count} host(s)"
        return 0
    }

    # --- Helper: validate boolean ---
    _ct_check_bool() {
        local label="$1" value="$2"
        if [[ "$value" != "true" && "$value" != "false" ]]; then
            echo -e "  ${CYAN}│${NC}  ${RED}✗ ${label}:${NC} '${BOLD}$value${NC}' is not valid (use ${GREEN}true${NC} or ${GREEN}false${NC})"
            errors=$((errors + 1))
            return 1
        fi
        return 0
    }

    # --- Port validation ---
    _ct_check_ports "TCP_PORTS"        "${TCP_PORTS:-}"
    _ct_check_ports "TCP_PORTS_INPUT"  "${TCP_PORTS_INPUT:-}"
    _ct_check_ports "TCP_PORTS_OUTPUT" "${TCP_PORTS_OUTPUT:-}"
    _ct_check_ports "UDP_PORTS"        "${UDP_PORTS:-}"
    _ct_check_ports "BLOCKED_TCP_PORTS" "${BLOCKED_TCP_PORTS:-}"
    _ct_check_ports "BLOCKED_UDP_PORTS" "${BLOCKED_UDP_PORTS:-}"
    _ct_check_ports "BLOCKED_TCP_PORTS_OUTPUT" "${BLOCKED_TCP_PORTS_OUTPUT:-}"
    _ct_check_ports "BLOCKED_UDP_PORTS_OUTPUT" "${BLOCKED_UDP_PORTS_OUTPUT:-}"

    # --- Host/IP validation ---
    _ct_check_hosts "SSH_ALLOWED_IPS"  "${SSH_ALLOWED_IPS:-}"
    _ct_check_hosts "TRUSTED_IPS"      "${TRUSTED_IPS:-}"
    _ct_check_hosts "TRUSTED_RANGES"   "${TRUSTED_RANGES:-}"
    _ct_check_hosts "BLACKLIST"        "${BLACKLIST:-}"
    _ct_check_hosts "BLOCKED_RANGES"   "${BLOCKED_RANGES:-}"

    # --- PORT_IP_RULES validation ---
    if [[ -n "${PORT_IP_RULES:-}" ]]; then
        local rule_count=0 rule_errors=0
        local IFS_OLD="$IFS"
        IFS=$'\n'
        for rule in $PORT_IP_RULES; do
            IFS="$IFS_OLD"
            rule_count=$((rule_count + 1))
            local proto rport rip
            proto=$(echo "$rule" | awk -F'|' '{print $1}' | xargs)
            rport=$(echo "$rule" | awk -F'|' '{print $2}' | xargs)
            rip=$(echo "$rule" | awk -F'|' '{print $3}' | xargs)
            if [[ "$proto" != "tcp" && "$proto" != "udp" ]]; then
                echo -e "  ${CYAN}│${NC}  ${RED}✗ PORT_IP_RULES:${NC} rule #${rule_count}: protocol '${BOLD}$proto${NC}' invalid (use tcp or udp)"
                errors=$((errors + 1)); rule_errors=$((rule_errors + 1))
            fi
            if [[ -n "$rport" ]] && ! is_valid_port "$rport"; then
                echo -e "  ${CYAN}│${NC}  ${RED}✗ PORT_IP_RULES:${NC} rule #${rule_count}: port '${BOLD}$rport${NC}' invalid"
                errors=$((errors + 1)); rule_errors=$((rule_errors + 1))
            fi
            if [[ -n "$rip" ]] && ! is_valid_host "$rip"; then
                echo -e "  ${CYAN}│${NC}  ${RED}✗ PORT_IP_RULES:${NC} rule #${rule_count}: host '${BOLD}$rip${NC}' invalid"
                errors=$((errors + 1)); rule_errors=$((rule_errors + 1))
            fi
            IFS=$'\n'
        done
        IFS="$IFS_OLD"
        if [[ $rule_errors -eq 0 ]]; then
            echo -e "  ${CYAN}│${NC}  ${GREEN}✓${NC} PORT_IP_RULES: ${rule_count} rule(s)"
        fi
    fi

    # --- PORT_FORWARD_RULES validation ---
    if [[ -n "${PORT_FORWARD_RULES:-}" ]]; then
        local fwd_count=0 fwd_errors=0
        local IFS_OLD="$IFS"
        IFS=$'\n'
        for rule in $PORT_FORWARD_RULES; do
            IFS="$IFS_OLD"
            fwd_count=$((fwd_count + 1))
            local proto ext_port int_dest
            proto=$(echo "$rule" | awk -F'|' '{print $1}' | xargs)
            ext_port=$(echo "$rule" | awk -F'|' '{print $2}' | xargs)
            int_dest=$(echo "$rule" | awk -F'|' '{print $3}' | xargs)
            if [[ "$proto" != "tcp" && "$proto" != "udp" ]]; then
                echo -e "  ${CYAN}│${NC}  ${RED}✗ PORT_FORWARD_RULES:${NC} rule #${fwd_count}: protocol '${BOLD}$proto${NC}' invalid"
                errors=$((errors + 1)); fwd_errors=$((fwd_errors + 1))
            fi
            if [[ -n "$ext_port" ]] && ! is_valid_port "$ext_port"; then
                echo -e "  ${CYAN}│${NC}  ${RED}✗ PORT_FORWARD_RULES:${NC} rule #${fwd_count}: port '${BOLD}$ext_port${NC}' invalid"
                errors=$((errors + 1)); fwd_errors=$((fwd_errors + 1))
            fi
            if [[ -z "$int_dest" ]]; then
                echo -e "  ${CYAN}│${NC}  ${RED}✗ PORT_FORWARD_RULES:${NC} rule #${fwd_count}: missing destination (ip:port)"
                errors=$((errors + 1)); fwd_errors=$((fwd_errors + 1))
            fi
            IFS=$'\n'
        done
        IFS="$IFS_OLD"
        if [[ $fwd_errors -eq 0 ]]; then
            echo -e "  ${CYAN}│${NC}  ${GREEN}✓${NC} PORT_FORWARD_RULES: ${fwd_count} rule(s)"
        fi

        # Port forwarding requires NAT
        if [[ "${NAT_ENABLE:-false}" != "true" ]]; then
            echo -e "  ${CYAN}│${NC}  ${YELLOW}⚠${NC} PORT_FORWARD_RULES set but NAT_ENABLE is not 'true' — forwarding won't work"
            warnings=$((warnings + 1))
        fi
    fi

    # --- Boolean options ---
    _ct_check_bool "ICMP_ENABLE"         "${ICMP_ENABLE:-true}"
    _ct_check_bool "MULTICAST_ENABLE"    "${MULTICAST_ENABLE:-false}"
    _ct_check_bool "SMTP_ENABLE"         "${SMTP_ENABLE:-true}"
    _ct_check_bool "RATE_LIMIT_ENABLE"   "${RATE_LIMIT_ENABLE:-true}"
    _ct_check_bool "LOG_DROPPED"         "${LOG_DROPPED:-true}"
    _ct_check_bool "NAT_ENABLE"          "${NAT_ENABLE:-false}"
    _ct_check_bool "SYN_FLOOD_PROTECT"   "${SYN_FLOOD_PROTECT:-true}"
    _ct_check_bool "CONN_LIMIT_ENABLE"   "${CONN_LIMIT_ENABLE:-false}"
    _ct_check_bool "DROP_INVALID"        "${DROP_INVALID:-true}"
    _ct_check_bool "BLOCK_COMMON_ATTACKS" "${BLOCK_COMMON_ATTACKS:-true}"

    # --- Numeric options ---
    if [[ -n "${CONN_LIMIT_PER_IP:-}" ]] && ! [[ "${CONN_LIMIT_PER_IP}" =~ ^[0-9]+$ ]]; then
        echo -e "  ${CYAN}│${NC}  ${RED}✗ CONN_LIMIT_PER_IP:${NC} '${BOLD}${CONN_LIMIT_PER_IP}${NC}' is not a number"
        errors=$((errors + 1))
    fi
    if [[ -n "${CONN_RATE_PER_IP:-}" ]] && ! [[ "${CONN_RATE_PER_IP}" =~ ^[0-9]+$ ]]; then
        echo -e "  ${CYAN}│${NC}  ${RED}✗ CONN_RATE_PER_IP:${NC} '${BOLD}${CONN_RATE_PER_IP}${NC}' is not a number"
        errors=$((errors + 1))
    fi
    if [[ -n "${RATE_LIMIT_BURST:-}" ]] && ! [[ "${RATE_LIMIT_BURST}" =~ ^[0-9]+$ ]]; then
        echo -e "  ${CYAN}│${NC}  ${RED}✗ RATE_LIMIT_BURST:${NC} '${BOLD}${RATE_LIMIT_BURST}${NC}' is not a number"
        errors=$((errors + 1))
    fi

    # --- NAT interface check ---
    if [[ "${NAT_ENABLE:-false}" == "true" ]]; then
        if [[ -z "${NAT_EXTERNAL_IFACE:-}" ]]; then
            echo -e "  ${CYAN}│${NC}  ${RED}✗ NAT_EXTERNAL_IFACE:${NC} required when NAT_ENABLE=true"
            errors=$((errors + 1))
        fi
        if [[ -z "${NAT_INTERNAL_IFACE:-}" ]]; then
            echo -e "  ${CYAN}│${NC}  ${RED}✗ NAT_INTERNAL_IFACE:${NC} required when NAT_ENABLE=true"
            errors=$((errors + 1))
        fi
    fi

    # --- Custom rules file ---
    if [[ -n "${CUSTOM_RULES_FILE:-}" ]] && [[ ! -f "${CUSTOM_RULES_FILE}" ]]; then
        echo -e "  ${CYAN}│${NC}  ${YELLOW}⚠${NC} CUSTOM_RULES_FILE: '${CUSTOM_RULES_FILE}' does not exist (will be skipped)"
        warnings=$((warnings + 1))
    fi

    # --- Warnings (non-fatal) ---
    if [[ -z "${TCP_PORTS:-}" && -z "${TCP_PORTS_INPUT:-}" && -z "${UDP_PORTS:-}" ]]; then
        echo -e "  ${CYAN}│${NC}  ${YELLOW}⚠${NC} No open ports defined — only SSH and established connections will work"
        warnings=$((warnings + 1))
    fi

    local ssh_port
    ssh_port=$(detect_ssh_port)
    if [[ -n "${TCP_PORTS:-}" ]] && [[ " ${TCP_PORTS} " != *" ${ssh_port} "* ]] && [[ -z "${SSH_ALLOWED_IPS:-}" ]]; then
        echo -e "  ${CYAN}│${NC}  ${YELLOW}⚠${NC} SSH port ${ssh_port} not in TCP_PORTS and no SSH_ALLOWED_IPS set"
        echo -e "  ${CYAN}│${NC}    You may lose SSH access! Add ${ssh_port} to TCP_PORTS or set SSH_ALLOWED_IPS"
        warnings=$((warnings + 1))
    fi

    # --- Summary ---
    echo -e "  ${CYAN}├─────────────────────────────────────────────────────┤${NC}"
    if [[ $errors -gt 0 ]]; then
        echo -e "  ${CYAN}│${NC}  ${RED}${BOLD}FAILED${NC} — ${errors} error(s), ${warnings} warning(s)"
        echo -e "  ${CYAN}│${NC}  Fix the errors above and try again."
        echo -e "  ${CYAN}└─────────────────────────────────────────────────────┘${NC}"
        echo ""
        return 1
    elif [[ $warnings -gt 0 ]]; then
        echo -e "  ${CYAN}│${NC}  ${YELLOW}${BOLD}PASSED with warnings${NC} — ${warnings} warning(s)"
        echo -e "  ${CYAN}└─────────────────────────────────────────────────────┘${NC}"
        echo ""
        return 0
    else
        echo -e "  ${CYAN}│${NC}  ${GREEN}${BOLD}ALL CHECKS PASSED${NC}"
        echo -e "  ${CYAN}└─────────────────────────────────────────────────────┘${NC}"
        echo ""
        return 0
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
