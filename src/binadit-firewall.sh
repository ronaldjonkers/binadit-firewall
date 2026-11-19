#!/usr/bin/env bash
# =============================================================================
# binadit-firewall v3.1.0
# =============================================================================
# A modern, easy-to-use Linux firewall manager with support for both
# nftables and iptables backends.
#
# Copyright (C) 2013-2026 Ronald Jonkers — Binadit BV (binadit.com)
# License: GPL-2.0
#
# Usage: binadit-firewall {start|stop|restart|reload|status|config|configtest|
#                          dns-refresh|setup|features|update|auto-update|upgrade|
#                          backup|motd-on|motd-off|prompt-on|prompt-off|version|help}
# =============================================================================

set -euo pipefail

if (( BASH_VERSINFO[0] < 4 )); then
    echo "binadit-firewall requires bash 4 or newer" >&2
    exit 1
fi

# Determine script directory for sourcing libraries (resolve symlinks)
SCRIPT_SOURCE="${BASH_SOURCE[0]}"
while [[ -L "$SCRIPT_SOURCE" ]]; do
    SCRIPT_DIR="$(cd "$(dirname "$SCRIPT_SOURCE")" && pwd)"
    SCRIPT_SOURCE="$(readlink "$SCRIPT_SOURCE")"
    [[ "$SCRIPT_SOURCE" != /* ]] && SCRIPT_SOURCE="$SCRIPT_DIR/$SCRIPT_SOURCE"
done
SCRIPT_DIR="$(cd "$(dirname "$SCRIPT_SOURCE")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/lib"

# Default config location (can be overridden via environment)
CONFIG_DIR="${BINADIT_CONFIG_DIR:-/etc/binadit-firewall}"
CONFIG_FILE="${CONFIG_DIR}/firewall.conf"

# Installation paths
INSTALL_DIR="/usr/local/share/binadit-firewall"
SBIN_LINK="/usr/local/sbin/binadit-firewall"

# Source libraries
source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/backend.sh"
source "${LIB_DIR}/backend_nftables.sh"
source "${LIB_DIR}/backend_iptables.sh"

# The command other tools (timers, cron) should call
if [[ -x "$SBIN_LINK" ]]; then
    SELF_CMD="$SBIN_LINK"
else
    SELF_CMD="${SCRIPT_DIR}/binadit-firewall.sh"
fi

# =============================================================================
# Backend helpers
# =============================================================================

# True when our rules are loaded in the kernel
backend_is_active() {
    local backend
    backend=$(detect_backend 2>/dev/null) || return 1
    case "$backend" in
        nftables) nft_is_active ;;
        *)        ipt_is_active ;;
    esac
}

# Generate the ruleset for the loaded config and let the kernel verify it,
# without applying anything.
backend_dry_run() {
    local backend rc=0
    backend=$(detect_backend 2>/dev/null) || return 0
    resolve_config_hosts
    case "$backend" in
        nftables)
            local tmp
            tmp=$(mktemp)
            nft_check "$tmp" || rc=1
            rm -f "$tmp"
            ;;
        *)
            ipt_check || rc=1
            rm -f "${CONFIG_DIR}/rules.v4.new" "${CONFIG_DIR}/rules.v6.new"
            ;;
    esac
    return $rc
}

# Serialize operations that change the ruleset (manual reload vs. dns-refresh)
fw_lock() {
    command -v flock &>/dev/null || return 0
    local lock_file="/run/binadit-firewall.lock"
    [[ -d /run ]] || lock_file="/tmp/binadit-firewall.lock"
    ( : >> "$lock_file" ) 2>/dev/null || return 0
    exec 9>>"$lock_file"
    if ! flock -w 60 9; then
        log_error "Another binadit-firewall operation is still running"
        exit 1
    fi
}

# The configuration that is currently loaded in the kernel (a copy made at
# the last successful apply). Automatic reloads use this copy, so a half
# finished edit of firewall.conf is never applied behind the admin's back.
applied_config_file() {
    echo "$(state_dir)/applied.conf"
}

_sysctl_set() {
    [[ -w "$1" ]] || return 0
    echo "$2" > "$1" 2>/dev/null || true
}

# =============================================================================
# Hostname re-check schedule
# =============================================================================

DNS_TIMER_UNIT="/etc/systemd/system/binadit-firewall-dns.timer"
DNS_SERVICE_UNIT="/etc/systemd/system/binadit-firewall-dns.service"
DNS_CRON_FILE="/etc/cron.d/binadit-firewall-dns"
DNS_PERIODIC_FILE="/etc/periodic/15min/binadit-firewall-dns"   # Alpine (busybox crond)

_has_systemd() {
    command -v systemctl &>/dev/null && [[ -d /run/systemd/system ]]
}

# Write a file only when its content changed. Returns 0 when it was written.
_write_if_changed() {
    local file="$1" content="$2"
    if [[ -f "$file" ]] && [[ "$(cat "$file")" == "$content" ]]; then
        return 1
    fi
    printf '%s\n' "$content" > "$file"
}

dns_schedule_remove() {
    if [[ -f "$DNS_TIMER_UNIT" || -f "$DNS_SERVICE_UNIT" ]]; then
        if _has_systemd; then
            systemctl disable --now binadit-firewall-dns.timer &>/dev/null || true
        fi
        rm -f "$DNS_TIMER_UNIT" "$DNS_SERVICE_UNIT"
        _has_systemd && systemctl daemon-reload &>/dev/null || true
    fi
    rm -f "$DNS_CRON_FILE" "$DNS_PERIODIC_FILE"
}

# Install, update or remove the periodic hostname check so that it matches
# the loaded configuration.
dns_schedule_sync() {
    local interval="${DNS_REFRESH_INTERVAL:-5}" hosts
    hosts=$(config_hostnames)

    if [[ -z "$hosts" || ! "$interval" =~ ^[0-9]+$ || "$interval" =~ ^0*$ ]]; then
        dns_schedule_remove
        return 0
    fi
    interval=$((10#$interval))

    if _has_systemd; then
        local service_content timer_content changed=false
        service_content="[Unit]
Description=binadit-firewall - re-check hostnames and reload on change
Documentation=https://github.com/ronaldjonkers/binadit-firewall

[Service]
Type=oneshot
ExecStart=${SELF_CMD} dns-refresh"
        timer_content="[Unit]
Description=binadit-firewall - periodic hostname re-check
Documentation=https://github.com/ronaldjonkers/binadit-firewall

[Timer]
OnBootSec=1min
OnUnitActiveSec=${interval}min
AccuracySec=10s

[Install]
WantedBy=timers.target"
        _write_if_changed "$DNS_SERVICE_UNIT" "$service_content" && changed=true
        _write_if_changed "$DNS_TIMER_UNIT" "$timer_content" && changed=true
        if [[ "$changed" == "true" ]]; then
            systemctl daemon-reload &>/dev/null || true
            systemctl enable binadit-firewall-dns.timer &>/dev/null || true
            systemctl --no-block restart binadit-firewall-dns.timer &>/dev/null || true
        elif ! systemctl is-enabled binadit-firewall-dns.timer &>/dev/null; then
            systemctl enable binadit-firewall-dns.timer &>/dev/null || true
            systemctl --no-block start binadit-firewall-dns.timer &>/dev/null || true
        fi
        rm -f "$DNS_CRON_FILE"
    elif [[ -d /etc/cron.d ]]; then
        local schedule="*/${interval} * * * *"
        (( interval >= 60 )) && schedule="0 * * * *"
        _write_if_changed "$DNS_CRON_FILE" "# binadit-firewall: re-check hostnames and reload when an address changed
${schedule} root ${SELF_CMD} dns-refresh >/dev/null 2>&1" || true
        chmod 644 "$DNS_CRON_FILE" 2>/dev/null || true
    elif [[ -d /etc/periodic/15min ]]; then
        # Alpine: busybox crond runs /etc/periodic/15min (fixed 15 minute interval)
        _write_if_changed "$DNS_PERIODIC_FILE" "#!/bin/sh
# binadit-firewall: re-check hostnames and reload when an address changed
exec ${SELF_CMD} dns-refresh >/dev/null 2>&1" || true
        chmod 755 "$DNS_PERIODIC_FILE" 2>/dev/null || true
    else
        log_warn "No systemd or cron directory found — hostnames are only re-checked on (re)start"
    fi
}

# =============================================================================
# Applying rules
# =============================================================================

# Apply a configuration file. Atomic: on any error the previous rules stay.
# $1 config file, $2 "resolved" when resolve_config_hosts already ran
fw_apply() {
    local config_file="$1" backend
    backend=$(detect_backend) || return 1

    if [[ "${2:-}" != "resolved" ]]; then
        load_config "$config_file"
        resolve_config_hosts
    fi

    if [[ -n "${_DNS_STALE// /}" ]]; then
        log_warn "DNS lookup failed for:${_DNS_STALE} — using the last known address(es)"
    fi
    if ssh_is_restricted; then
        collect_addrs $SSH_ALLOWED_IPS $SSH_ALLOWED_IPS_IPV6
        if (( ${#ADDR4[@]} + ${#ADDR6[@]} == 0 )); then
            log_warn "SSH_ALLOWED_IPS is set but none of its entries resolve to an address:"
            log_warn "SSH will only be reachable from trusted IPs!"
        fi
    fi

    log_info "Using firewall backend: ${BOLD}${backend}${NC}"
    case "$backend" in
        nftables)
            nft_apply || return 1 ;;
        iptables-nft|iptables-legacy)
            ipt_apply || return 1 ;;
        *)
            log_error "Unsupported backend: $backend"
            return 1 ;;
    esac

    # Kernel settings that belong to the enabled features
    if [[ "$SYN_FLOOD_PROTECT" == "true" ]]; then
        _sysctl_set /proc/sys/net/ipv4/tcp_syncookies 1
    fi
    if [[ "$NAT_ENABLE" == "true" ]]; then
        _sysctl_set /proc/sys/net/ipv4/ip_forward 1
        log_info "NAT routing enabled (${NAT_INTERNAL_IFACE} -> ${NAT_EXTERNAL_IFACE})"
    fi

    # Remember what is loaded
    if ensure_state_dir; then
        local applied
        applied=$(applied_config_file)
        if [[ "$config_file" != "$applied" ]]; then
            cp -f "$config_file" "$applied"
            chmod 600 "$applied" 2>/dev/null || true
        fi
        dns_cache_save
    fi
    : > "$(run_state_file)" 2>/dev/null || true
    chmod 644 "$(run_state_file)" 2>/dev/null || true

    # System integration (skipped for throw-away instances, e.g. the test suite)
    if [[ "${BINADIT_SKIP_SYSTEM_HOOKS:-false}" != "true" ]]; then
        dns_schedule_sync
        refresh_integrations
    fi
    return 0
}

# Validate the configuration file — runs the full configtest plus a kernel
# dry-run. On error: prints detailed feedback and aborts (rules unchanged).
validate_config() {
    if ! configtest "$CONFIG_FILE"; then
        log_error "Configuration test failed — firewall rules NOT changed"
        exit 1
    fi
}

# Run configtest standalone
fw_configtest() {
    configtest "$CONFIG_FILE" || exit 1
    if [[ $EUID -eq 0 ]] && detect_backend &>/dev/null; then
        if backend_dry_run; then
            log_success "Generated ruleset verified by the kernel ($(detect_backend)) — safe to apply"
            echo ""
        else
            log_error "The configuration is valid but the generated ruleset was rejected (see above)"
            exit 1
        fi
    else
        log_info "Run as root to also verify the generated ruleset against the kernel"
        echo ""
    fi
}

# Start the firewall (also used for reload and restart)
fw_start() {
    require_root
    validate_config

    show_banner
    fw_lock

    # Backup current rules before making changes
    backup_rules

    if ! fw_apply "$CONFIG_FILE"; then
        if backend_is_active; then
            log_error "New rules were NOT applied — the previously loaded rules are still active"
        else
            log_error "Firewall could not be started — the server is NOT protected"
        fi
        exit 1
    fi

    print_rule_summary "$CONFIG_FILE"
    show_protected
}

# Stop the firewall (remove all rules, allow all traffic)
fw_stop() {
    require_root

    log_header "Stopping binadit-firewall"
    fw_lock

    # Backup before flushing
    backup_rules

    local backend
    backend=$(detect_backend)

    case "$backend" in
        nftables)
            nft_flush
            ;;
        iptables-nft|iptables-legacy)
            ipt_flush
            ;;
    esac
    rm -f "$(run_state_file)" 2>/dev/null || true

    show_unprotected
}

# Show firewall status. Exit code: 0 = active, 3 = not active.
fw_status() {
    show_banner

    if [[ -f "$CONFIG_FILE" ]]; then
        print_rule_summary "$CONFIG_FILE"
    fi

    local backend
    backend=$(detect_backend)

    if [[ $EUID -ne 0 ]]; then
        log_warn "Run as root to see the live firewall state and rules"
        return 0
    fi

    if ! backend_is_active; then
        log_error "Status: ${RED}${BOLD}NOT ACTIVE${NC} — no binadit-firewall rules are loaded"
        log_info "Start with: ${BOLD}binadit-firewall start${NC}"
        echo ""
        exit 3
    fi

    log_success "Status: ${GREEN}${BOLD}ACTIVE${NC} (backend: ${backend})"
    local applied
    applied=$(applied_config_file)
    if [[ -f "$applied" && -f "$CONFIG_FILE" ]] && [[ "$(cat "$applied")" != "$(cat "$CONFIG_FILE")" ]]; then
        log_warn "firewall.conf changed since the rules were loaded — run ${BOLD}binadit-firewall reload${NC} to apply"
    fi

    log_header "Active Rules ($(echo "$backend" | tr '[:lower:]' '[:upper:]'))"
    case "$backend" in
        nftables)
            nft_status
            ;;
        iptables-nft|iptables-legacy)
            ipt_status
            ;;
    esac
}

# Re-resolve all hostnames; reload the rules when an address changed.
# Runs from a timer/cron job, safe to run by hand.
fw_dns_refresh() {
    require_root

    if ! backend_is_active; then
        log_info "Firewall is not active — nothing to refresh"
        return 0
    fi

    local cfg
    cfg=$(applied_config_file)
    [[ -f "$cfg" ]] || cfg="$CONFIG_FILE"
    if [[ ! -f "$cfg" ]]; then
        log_error "Configuration file not found: $CONFIG_FILE"
        exit 1
    fi

    load_config "$cfg"
    if [[ -z "$(config_hostnames)" ]]; then
        log_info "No hostnames in the configuration — nothing to refresh"
        return 0
    fi

    fw_lock
    resolve_config_hosts

    local new old="" cache
    cache=$(dns_cache_file)
    new=$(dns_cache_render)
    [[ -f "$cache" ]] && old=$(cat "$cache")

    if [[ "$new" == "$old" ]]; then
        log_success "Hostnames checked — no address changes"
        return 0
    fi

    # Describe what changed
    local host v4 v6 changes=""
    while IFS='|' read -r host v4 v6; do
        [[ -z "$host" ]] && continue
        local before="${_DNS_CACHE_V4[$host]:-} ${_DNS_CACHE_V6[$host]:-}"
        local after="${v4} ${v6}"
        if [[ "$before" != "$after" ]]; then
            _trim "$before"; before="${REPLY:-(none)}"
            _trim "$after";  after="${REPLY:-(none)}"
            changes+="${host}: ${before} -> ${after}; "
            log_info "Address change: ${BOLD}${host}${NC}: ${before} → ${after}"
        fi
    done <<< "$new"

    if ! fw_apply "$cfg" resolved >/dev/null; then
        log_error "Hostname addresses changed but the reload failed — previous rules are still active"
        command -v logger &>/dev/null && logger -t binadit-firewall -p daemon.err "hostname change detected (${changes}) but reload FAILED" || true
        exit 1
    fi

    log_success "Hostname addresses changed — firewall rules reloaded"
    command -v logger &>/dev/null && logger -t binadit-firewall "hostname change detected (${changes}) rules reloaded" || true
}

# =============================================================================
# Login / prompt indicators
# =============================================================================

readonly PROFILE_MARKER="binadit-firewall-profile-v2"
MOTD_SCRIPT="/etc/profile.d/binadit-firewall-status.sh"
PROMPT_SCRIPT="/etc/profile.d/binadit-firewall-prompt.sh"

_write_motd_script() {
    cat > "$MOTD_SCRIPT" <<'MOTD_EOF'
#!/bin/sh
# binadit-firewall login status indicator (binadit-firewall-profile-v2)
# Shows a one-line status on login so admins know if the firewall is active.
# Remove with: binadit-firewall motd-off

if [ "$(id -u)" = "0" ] || id -nG 2>/dev/null | grep -qwE 'sudo|wheel'; then
    _bf_active=0
    if [ "$(id -u)" = "0" ]; then
        # root: ask the kernel whether the binadit-firewall rules are loaded
        if command -v nft >/dev/null 2>&1 && nft list chain inet binadit input >/dev/null 2>&1; then
            _bf_active=1
        elif command -v iptables >/dev/null 2>&1 && iptables -S binadit-firewall >/dev/null 2>&1; then
            _bf_active=1
        fi
    elif [ -e /run/binadit-firewall.active ] || [ -e /var/run/binadit-firewall.active ]; then
        # non-root cannot read the ruleset: use the state marker
        _bf_active=1
    fi
    if [ "$_bf_active" = "1" ]; then
        printf '\033[0;32m  \342\226\270 binadit-firewall: active\033[0m\n'
    else
        printf '\033[0;31m  \342\232\240 binadit-firewall: NOT ACTIVE \342\200\224 run: binadit-firewall start\033[0m\n'
    fi
    unset _bf_active
fi
MOTD_EOF
    chmod 644 "$MOTD_SCRIPT"
}

_write_prompt_script() {
    cat > "$PROMPT_SCRIPT" <<'PROMPT_EOF'
#!/bin/bash
# binadit-firewall prompt indicator (binadit-firewall-profile-v2)
# Shows 🟢 (active) or 🔴 (inactive) before your prompt.
# Remove with: binadit-firewall prompt-off

if [ -n "${BASH_VERSION:-}" ]; then
    case "$-" in
        *i*)
            if [ "$(id -u)" = "0" ] || id -nG 2>/dev/null | grep -qwE 'sudo|wheel'; then
                __binadit_fw_prompt() {
                    local __s='🔴'
                    if [ "$EUID" = "0" ]; then
                        if command -v nft >/dev/null 2>&1 && nft list chain inet binadit input >/dev/null 2>&1; then
                            __s='🟢'
                        elif command -v iptables >/dev/null 2>&1 && iptables -S binadit-firewall >/dev/null 2>&1; then
                            __s='🟢'
                        fi
                    elif [ -e /run/binadit-firewall.active ] || [ -e /var/run/binadit-firewall.active ]; then
                        __s='🟢'
                    fi
                    PS1="${PS1#🟢 }"
                    PS1="${PS1#🔴 }"
                    PS1="${__s} ${PS1}"
                }
                case ";${PROMPT_COMMAND:-};" in
                    *";__binadit_fw_prompt;"*) ;;
                    *) PROMPT_COMMAND="__binadit_fw_prompt${PROMPT_COMMAND:+;$PROMPT_COMMAND}" ;;
                esac
            fi
            ;;
    esac
fi
PROMPT_EOF
    chmod 644 "$PROMPT_SCRIPT"
}

# Rewrite indicator scripts installed by an older version
refresh_integrations() {
    if [[ -f "$MOTD_SCRIPT" ]] && ! grep -q "$PROFILE_MARKER" "$MOTD_SCRIPT" 2>/dev/null; then
        _write_motd_script 2>/dev/null || true
    fi
    if [[ -f "$PROMPT_SCRIPT" ]] && ! grep -q "$PROFILE_MARKER" "$PROMPT_SCRIPT" 2>/dev/null; then
        _write_prompt_script 2>/dev/null || true
    fi
    return 0
}

fw_install_motd() {
    require_root
    if [[ ! -d /etc/profile.d ]]; then
        log_error "/etc/profile.d does not exist on this system"
        exit 1
    fi
    _write_motd_script
    log_success "Login status indicator installed: ${MOTD_SCRIPT}"
    log_info "Admins will see firewall status on every login"
    log_info "Remove with: ${BOLD}binadit-firewall motd-off${NC}"
}

fw_remove_motd() {
    require_root
    if [[ -f "$MOTD_SCRIPT" ]]; then
        rm -f "$MOTD_SCRIPT"
        log_success "Login status indicator removed"
    else
        log_info "Login status indicator was not installed"
    fi
}

fw_install_prompt() {
    require_root
    if [[ ! -d /etc/profile.d ]]; then
        log_error "/etc/profile.d does not exist on this system"
        exit 1
    fi
    _write_prompt_script
    log_success "Prompt indicator installed: ${PROMPT_SCRIPT}"
    log_info "🟢 = firewall active, 🔴 = firewall inactive"
    log_info "Remove with: ${BOLD}binadit-firewall prompt-off${NC}"
    log_info "Takes effect on next login (bash)"
}

fw_remove_prompt() {
    require_root
    if [[ -f "$PROMPT_SCRIPT" ]]; then
        rm -f "$PROMPT_SCRIPT"
        log_success "Prompt indicator removed"
        log_info "Takes effect on next login"
    else
        log_info "Prompt indicator was not installed"
    fi
}

# Show version
fw_version() {
    show_banner
    echo -e "  ${BOLD}Version:${NC}  ${BINADIT_VERSION}"
    echo -e "  ${BOLD}Backend:${NC}  $(detect_backend 2>/dev/null || echo "none found")"
    echo -e "  ${BOLD}Config:${NC}   ${CONFIG_FILE}"
    echo -e "  ${BOLD}OS:${NC}       $(detect_distro) ($(detect_distro_family))"
    if [[ -f "$CONFIG_FILE" ]]; then
        echo -e "  ${BOLD}Status:${NC}   ${GREEN}configured${NC}"
    else
        echo -e "  ${BOLD}Status:${NC}   ${YELLOW}not configured${NC}"
    fi
    echo ""
}

# Locate the example configuration
_example_config() {
    local candidate
    for candidate in "${CONFIG_DIR}/firewall.conf.example" "${SCRIPT_DIR}/../config/firewall.conf.example"; do
        if [[ -f "$candidate" ]]; then
            echo "$candidate"
            return 0
        fi
    done
    return 1
}

# Upgrade: migrate a v1.x (2013) installation, then update to the latest version
fw_upgrade() {
    require_root

    show_banner
    log_header "Upgrade"

    local old_v1_config="/etc/firewall.d/host.conf"
    if [[ -f "$old_v1_config" ]]; then
        log_warn "Found binadit-firewall v1.x configuration: ${old_v1_config}"
        local do_migrate
        ask do_migrate "  Migrate it to ${CONFIG_FILE}? [Y/n]: " "y"
        if [[ "${do_migrate,,}" != "n" ]]; then
            local example
            example=$(_example_config) || { log_error "Example config not found"; exit 1; }
            migrate_v1_config "$old_v1_config" "$CONFIG_FILE" "$example"
            log_info "Review it with: ${BOLD}binadit-firewall config show${NC}"
        fi
    else
        log_info "No v1.x configuration found — nothing to migrate"
    fi

    if [[ -d "$INSTALL_DIR" ]]; then
        fw_update "$@"
    else
        log_info "binadit-firewall is not installed yet — run ${BOLD}install.sh${NC} to install it"
    fi
}

# Interactive setup wizard
fw_setup() {
    require_root

    log_header "binadit-firewall Setup Wizard"

    mkdir -p "$CONFIG_DIR"

    local example_config
    example_config=$(_example_config) || { log_error "Example config not found"; exit 1; }

    if [[ -f "$CONFIG_FILE" ]]; then
        log_warn "Configuration already exists: $CONFIG_FILE"
        local overwrite
        ask overwrite "  Overwrite? [y/N]: " "n"
        if [[ "${overwrite,,}" != "y" ]]; then
            log_info "Setup cancelled"
            return 0
        fi
        local backup="${CONFIG_FILE}.bak.$(date +%Y%m%d_%H%M%S)"
        cp "$CONFIG_FILE" "$backup"
        log_info "Previous configuration saved as: $backup"
    fi

    # Work on a draft so an aborted wizard never leaves a half-written config
    local draft="${CONFIG_FILE}.setup.$$"
    cp "$example_config" "$draft"

    local ssh_ports tcp_ports=""
    ssh_ports=$(detect_ssh_ports)
    log_info "Detected SSH port(s): ${ssh_ports} — SSH is always kept reachable"

    echo ""
    echo -e "  ${BOLD}Which ports would you like to open?${NC}"
    echo ""

    local answer
    ask answer "  Open HTTP (80) and HTTPS (443)? [Y/n]: " "y"
    [[ "${answer,,}" != "n" ]] && tcp_ports="80 443"

    ask answer "  Is this a mail server? (opens 25, 465, 587, 993, 995) [y/N]: " "n"
    [[ "${answer,,}" == "y" ]] && tcp_ports+=" 25 465 587 993 995"

    while true; do
        ask answer "  Additional TCP ports to open (space-separated, ranges as 8000:9000, or empty): " ""
        local bad="" p
        for p in $answer; do
            is_valid_port "$p" || { bad="$p"; break; }
        done
        if [[ -n "$bad" ]]; then
            log_warn "'${bad}' is not a valid port — try again"
            continue
        fi
        tcp_ports+=" $answer"
        break
    done

    # Remove duplicates
    local unique="" p
    for p in $tcp_ports; do
        [[ " $unique " == *" $p "* ]] || unique+="${unique:+ }$p"
    done
    config_set_value "$draft" TCP_PORTS "$unique"

    while true; do
        ask answer "  UDP ports to open (space-separated, or empty): " ""
        local bad=""
        for p in $answer; do
            is_valid_port "$p" || { bad="$p"; break; }
        done
        if [[ -n "$bad" ]]; then
            log_warn "'${bad}' is not a valid port — try again"
            continue
        fi
        config_set_value "$draft" UDP_PORTS "$(echo "$answer" | xargs)"
        break
    done

    ask answer "  Restrict SSH (${ssh_ports}) to specific IPs/hostnames? [y/N]: " "n"
    if [[ "${answer,,}" == "y" ]]; then
        while true; do
            ask answer "  Allowed SSH IPs/hostnames (space-separated, empty = no restriction): " ""
            local bad=""
            for p in $answer; do
                classify_addr "$p" || { bad="$p"; break; }
            done
            if [[ -n "$bad" ]]; then
                log_warn "'${bad}' is not a valid IP, CIDR or hostname — try again"
                continue
            fi
            config_set_value "$draft" SSH_ALLOWED_IPS "$(echo "$answer" | xargs)"
            [[ -n "${answer// /}" ]] && log_warn "Make sure your own address is in this list, or you will lose SSH access"
            break
        done
    fi

    ask answer "  Allow ping (ICMP)? [Y/n]: " "y"
    if [[ "${answer,,}" == "n" ]]; then
        config_set_value "$draft" ICMP_ENABLE "false"
    fi

    cat "$draft" > "$CONFIG_FILE"
    rm -f "$draft"

    echo ""
    log_success "Configuration saved to: $CONFIG_FILE"
    log_info "Review and edit: ${BOLD}binadit-firewall config show${NC}"
    echo ""

    ask answer "  Apply firewall rules now? [Y/n]: " "y"
    if [[ "${answer,,}" != "n" ]]; then
        fw_start
    fi
}

# =============================================================================
# Features overview
# =============================================================================

fw_features() {
    show_banner
    cat <<EOF

  ${BOLD}${CYAN}━━━ FEATURE OVERVIEW ━━━${NC}

  ${BOLD}HOW TRAFFIC IS HANDLED${NC}
  Incoming   Everything is dropped unless a rule below allows it.
  Outgoing   Everything is allowed unless you block specific ports.
  Forwarded  Dropped, unless NAT routing is enabled.

  ${BOLD}FIREWALL CONTROL${NC}
  ${GREEN}start${NC}           Validate the config and apply all rules. The new ruleset is
                  loaded in one transaction: on any error the old rules stay.
  ${GREEN}stop${NC}            Remove all rules and allow all traffic (emergencies).
  ${GREEN}restart${NC}         Same as start: rules are replaced atomically, so there is
  ${GREEN}reload${NC}          never a moment without a firewall. Connections stay open.
  ${GREEN}status${NC}          Show whether the firewall is active, the rule summary and
                  the live rules. Exit code 0 = active, 3 = not active.

  ${BOLD}CONFIGURATION MANAGEMENT${NC}
  ${GREEN}config show${NC}     Display all current settings.
  ${GREEN}config get${NC}      Get the value of a single setting.
  ${GREEN}config set${NC}      Set a value (validated; an invalid value is refused).
                  Example: ${BOLD}binadit-firewall config set TCP_PORTS "80 443 8080"${NC}
  ${GREEN}config add${NC}      Add a value to a list setting.
                  Example: ${BOLD}binadit-firewall config add TCP_PORTS 8080${NC}
  ${GREEN}config remove${NC}   Remove a value from a list setting.
  ${GREEN}configtest${NC}      Validate every setting. As root it also generates the
                  ruleset and lets the kernel verify it, without applying.
  ${GREEN}setup${NC}           Interactive setup wizard.
                  Config changes take effect after: ${BOLD}binadit-firewall reload${NC}

  ${BOLD}PORT SETTINGS${NC}
  ${GREEN}TCP_PORTS${NC}               Incoming TCP ports open to everyone.
                          Example: "80 443 8080 20000:25000"
  ${GREEN}TCP_PORTS_INPUT${NC}         Same as TCP_PORTS (kept for compatibility).
  ${GREEN}UDP_PORTS${NC}               Incoming UDP ports open to everyone.
  ${GREEN}BLOCKED_TCP_PORTS${NC}       TCP ports blocked in BOTH directions. Wins over every
                          allow rule, including trusted IPs.
  ${GREEN}BLOCKED_UDP_PORTS${NC}       UDP ports blocked in BOTH directions.
  ${GREEN}BLOCKED_TCP_PORTS_OUTPUT${NC} TCP ports blocked for outgoing traffic only.
                          Example: "25 465 587" to stop the server sending mail.
  ${GREEN}BLOCKED_UDP_PORTS_OUTPUT${NC} UDP ports blocked for outgoing traffic only.
  ${GREEN}TCP_PORTS_OUTPUT${NC}        No effect (outgoing traffic is always allowed).

  ${BOLD}ACCESS CONTROL${NC}
  ${GREEN}SSH_PORT${NC}                SSH port(s). Empty = detected automatically from sshd.
  ${GREEN}SSH_ALLOWED_IPS${NC}         Restrict SSH to these IPs/CIDRs/hostnames.
                          Empty = SSH is open to everyone (never locked out).
                          When set, SSH is closed for everyone else, even if
                          the SSH port is also listed in TCP_PORTS.
  ${GREEN}TRUSTED_IPS${NC}             Full access to every port, exempt from rate limits.
  ${GREEN}TRUSTED_RANGES${NC}          Same, for ranges (CIDR or 1.2.3.4-1.2.3.9).
  ${GREEN}BLACKLIST${NC}               Blocked completely, incoming and outgoing.
  ${GREEN}BLOCKED_RANGES${NC}          Same, for ranges.
  ${GREEN}PORT_IP_RULES${NC}           Open a port for specific addresses only.
                          Format: "proto|port|address" (one per line).
                          Example: "tcp|3306|10.0.0.5"
  All address settings accept IPv4, IPv6, CIDR, ranges and hostnames.
  Kept for compatibility, identical to the setting without the suffix:
  SSH_ALLOWED_IPS_IPV6, TRUSTED_IPS_IPV6, TRUSTED_RANGES_IPV6,
  BLACKLIST_IPV6, BLOCKED_RANGES_IPV6.

  ${BOLD}HOSTNAMES${NC}
  Hostnames are resolved to their A and AAAA records when rules are loaded.
  ${GREEN}DNS_REFRESH_INTERVAL${NC}    Minutes between re-checks (default 5, 0 = off).
                          When an address behind a hostname changed, the rules
                          are reloaded automatically.
  ${GREEN}dns-refresh${NC}             Run the re-check now.
  Resolved addresses are cached: if DNS is down (or not up yet at boot) the
  last known addresses keep working.

  ${BOLD}SECURITY FEATURES${NC}
  ${GREEN}RATE_LIMIT_ENABLE${NC}       Limit new TCP connections per source IP.
  ${GREEN}RATE_LIMIT_RATE${NC}         Sustained rate per IP. Default: 25 (per second).
                          Also accepts e.g. "600/minute".
  ${GREEN}RATE_LIMIT_BURST${NC}        Extra connections an IP may open in a burst. Default: 100.
  ${GREEN}CONN_RATE_PER_IP${NC}        Optional hard cap on new TCP connections per second
                          per IP, without burst allowance. 0 = off (default).
  ${GREEN}CONN_LIMIT_ENABLE${NC}       Limit concurrent TCP connections per source IP.
  ${GREEN}CONN_LIMIT_PER_IP${NC}       Max simultaneous connections per IP. Default: 50.
  ${GREEN}SYN_FLOOD_PROTECT${NC}       Enables kernel SYN cookies and drops TCP packets with
                          impossible flag combinations. Default: true.
  ${GREEN}DROP_INVALID${NC}            Drop packets in INVALID state. Default: true.
  ${GREEN}BLOCK_COMMON_ATTACKS${NC}    Silently drop telnet/netbios/SMB/SSDP probes (ports 23,
                          135, 137-139, 445, 1900) so they stay out of the log.
                          A port you open explicitly stays open.
  Limits never apply to trusted IPs or to the SSH allow-list.
  For IPv6 the limits count per /64 network.

  ${BOLD}NETWORK FEATURES${NC}
  ${GREEN}ICMP_ENABLE${NC}             Answer ping (IPv4 and IPv6). Default: true.
                          ICMPv6 needed for IPv6 itself is always allowed.
  ${GREEN}MULTICAST_ENABLE${NC}        Accept multicast/broadcast (clusters, VRRP). Default: false.
  ${GREEN}NAT_ENABLE${NC}              Act as NAT router for a LAN. Default: false.
  ${GREEN}NAT_EXTERNAL_IFACE${NC}      Internet-facing interface (e.g., eth0).
  ${GREEN}NAT_INTERNAL_IFACE${NC}      LAN-facing interface (e.g., eth1).
  ${GREEN}PORT_FORWARD_RULES${NC}      Forward ports arriving on the external interface.
                          Format: "proto|ext_port|int_ip:int_port". Needs NAT_ENABLE.
  ${GREEN}SMTP_ENABLE${NC}             Deprecated, no effect. To block outgoing mail use
                          BLOCKED_TCP_PORTS_OUTPUT="25 465 587".

  ${BOLD}MONITORING & MAINTENANCE${NC}
  ${GREEN}LOG_DROPPED${NC}     Log dropped packets (max 5/minute). Default: true.
                  View: ${BOLD}journalctl -k | grep binadit-drop${NC}
  ${GREEN}backup${NC}          Save the currently loaded rules to ${CONFIG_DIR}/backups/.
                  Also happens automatically before every start/stop.
  ${GREEN}motd-on${NC}         Show one-line firewall status on every login.
  ${GREEN}motd-off${NC}        Remove the login status indicator.
  ${GREEN}prompt-on${NC}       Show 🟢/🔴 before your bash prompt, checked on every prompt.
  ${GREEN}prompt-off${NC}      Remove the prompt indicator.

  ${BOLD}UPDATES & VERSIONING${NC}
  ${GREEN}update${NC}          Download and install the latest version from GitHub.
                  Configuration is preserved. If the firewall is active, the
                  rules are reloaded with the new version (atomically).
  ${GREEN}auto-update on${NC}  Enable weekly automatic updates (cron or systemd timer).
  ${GREEN}auto-update off${NC} Disable automatic updates.
  ${GREEN}upgrade${NC}         Migrate a v1.x (2013) config, then update.
  ${GREEN}version${NC}         Show version, backend, OS, and config status.

  ${BOLD}ADVANCED${NC}
  ${GREEN}CUSTOM_RULES_FILE${NC}       File with extra rules, loaded after the managed rules.
                          nftables backend: nft syntax. iptables backend:
                          iptables-restore syntax.
  ${GREEN}BINADIT_DEBUG${NC}           Debug logging. Also: BINADIT_DEBUG=true binadit-firewall start

EOF
}

# =============================================================================
# CLI config management
# =============================================================================

VALID_CONFIG_KEYS="$ALL_CONFIG_KEYS"

# List-type keys (space-separated values that support add/remove)
LIST_CONFIG_KEYS="$PORT_LIST_KEYS $ADDR_LIST_KEYS"

_config_key_valid() {
    local key="$1"
    [[ " $VALID_CONFIG_KEYS " == *" $key "* ]]
}

_config_key_is_list() {
    local key="$1"
    [[ " $LIST_CONFIG_KEYS " == *" $key "* ]]
}

_ensure_config() {
    if [[ ! -f "$CONFIG_FILE" ]]; then
        log_error "Configuration file not found: $CONFIG_FILE"
        log_info "Run: ${BOLD}binadit-firewall setup${NC}"
        exit 1
    fi
}

# Write a value, then validate the complete configuration. An invalid result
# is rolled back so the config file is never left in a broken state.
_config_write_validated() {
    local key="$1" value="$2" backup
    backup=$(mktemp)
    cat "$CONFIG_FILE" > "$backup"

    if ! config_set_value "$CONFIG_FILE" "$key" "$value"; then
        rm -f "$backup"
        exit 1
    fi

    load_config "$CONFIG_FILE"
    if ! config_validate; then
        cat "$backup" > "$CONFIG_FILE"
        rm -f "$backup"
        log_error "Not saved — this would make the configuration invalid:"
        local msg
        for msg in "${CT_ERRORS[@]}"; do
            log_error "  $msg"
        done
        exit 1
    fi
    rm -f "$backup"
}

fw_config() {
    local subcmd="${1:-show}"
    shift || true

    case "$subcmd" in
        show)
            fw_config_show
            ;;
        get)
            fw_config_get "$@"
            ;;
        set)
            fw_config_set "$@"
            ;;
        add)
            fw_config_add "$@"
            ;;
        remove|rm|del)
            fw_config_remove "$@"
            ;;
        *)
            log_error "Unknown config command: $subcmd"
            echo ""
            echo -e "  ${BOLD}Usage:${NC}"
            echo -e "    binadit-firewall config show                    ${GREEN}# Show all settings${NC}"
            echo -e "    binadit-firewall config get KEY                 ${GREEN}# Get a setting${NC}"
            echo -e "    binadit-firewall config set KEY VALUE           ${GREEN}# Set a setting${NC}"
            echo -e "    binadit-firewall config add KEY VALUE           ${GREEN}# Add to a list setting${NC}"
            echo -e "    binadit-firewall config remove KEY VALUE        ${GREEN}# Remove from a list setting${NC}"
            echo ""
            exit 1
            ;;
    esac
}

fw_config_show() {
    _ensure_config
    load_config "$CONFIG_FILE"

    _show_group() {
        local title="$1" key val
        shift
        echo ""
        echo -e "  ${BOLD}${title}${NC}"
        for key in "$@"; do
            val="${!key:-}"
            if [[ -z "$val" ]]; then
                printf "  ${CYAN}│${NC} %-26s = ${YELLOW}(empty)${NC}\n" "$key"
            elif [[ "$val" == "true" ]]; then
                printf "  ${CYAN}│${NC} %-26s = ${GREEN}${BOLD}%s${NC}\n" "$key" "$val"
            elif [[ "$val" == "false" ]]; then
                printf "  ${CYAN}│${NC} %-26s = ${RED}${BOLD}%s${NC}\n" "$key" "$val"
            elif [[ "$val" == *$'\n'* ]]; then
                printf "  ${CYAN}│${NC} %-26s =\n" "$key"
                local line
                while IFS= read -r line; do
                    [[ -z "${line// /}" ]] && continue
                    printf "  ${CYAN}│${NC}     ${BOLD}%s${NC}\n" "$line"
                done <<< "$val"
            else
                printf "  ${CYAN}│${NC} %-26s = ${BOLD}%s${NC}\n" "$key" "$val"
            fi
        done
    }

    echo ""
    echo -e "  ${BOLD}${CYAN}━━━ Current Configuration ━━━${NC}"
    echo -e "  ${CYAN}File: ${NC}${CONFIG_FILE}"

    _show_group "OPEN PORTS (incoming)" TCP_PORTS TCP_PORTS_INPUT UDP_PORTS
    _show_group "BLOCKED PORTS" BLOCKED_TCP_PORTS BLOCKED_UDP_PORTS BLOCKED_TCP_PORTS_OUTPUT BLOCKED_UDP_PORTS_OUTPUT
    _show_group "SSH" SSH_PORT SSH_ALLOWED_IPS SSH_ALLOWED_IPS_IPV6
    [[ -z "$SSH_PORT" ]] && echo -e "  ${CYAN}│${NC}   (SSH port auto-detected: ${SSH_PORTS})"
    _show_group "ACCESS CONTROL" TRUSTED_IPS TRUSTED_IPS_IPV6 TRUSTED_RANGES TRUSTED_RANGES_IPV6 \
        BLACKLIST BLACKLIST_IPV6 BLOCKED_RANGES BLOCKED_RANGES_IPV6 PORT_IP_RULES DNS_REFRESH_INTERVAL
    _show_group "SECURITY" RATE_LIMIT_ENABLE RATE_LIMIT_RATE RATE_LIMIT_BURST CONN_RATE_PER_IP \
        CONN_LIMIT_ENABLE CONN_LIMIT_PER_IP SYN_FLOOD_PROTECT DROP_INVALID BLOCK_COMMON_ATTACKS
    _show_group "NETWORK" ICMP_ENABLE MULTICAST_ENABLE LOG_DROPPED NAT_ENABLE NAT_EXTERNAL_IFACE \
        NAT_INTERNAL_IFACE PORT_FORWARD_RULES
    _show_group "ADVANCED" CUSTOM_RULES_FILE BINADIT_DEBUG
    _show_group "NO EFFECT (deprecated)" TCP_PORTS_OUTPUT SMTP_ENABLE
    echo ""
}

fw_config_get() {
    local key="${1:-}"
    if [[ -z "$key" ]]; then
        log_error "Usage: binadit-firewall config get KEY"
        exit 1
    fi
    if ! _config_key_valid "$key"; then
        log_error "Unknown config key: $key"
        log_info "Run ${BOLD}binadit-firewall features${NC} to see all valid keys"
        exit 1
    fi
    _ensure_config
    load_config "$CONFIG_FILE"
    echo "${!key:-}"
}

fw_config_set() {
    local key="${1:-}"
    if [[ -z "$key" || $# -lt 2 ]]; then
        log_error "Usage: binadit-firewall config set KEY VALUE"
        exit 1
    fi
    local value="$2"
    if ! _config_key_valid "$key"; then
        log_error "Unknown config key: $key"
        log_info "Run ${BOLD}binadit-firewall features${NC} to see all valid keys"
        exit 1
    fi
    require_root
    _ensure_config

    _config_write_validated "$key" "$value"

    log_success "${key} = \"${value}\""
    log_info "Run ${BOLD}binadit-firewall reload${NC} to apply"
}

fw_config_add() {
    local key="${1:-}"
    local value="${2:-}"
    if [[ -z "$key" || -z "$value" ]]; then
        log_error "Usage: binadit-firewall config add KEY VALUE"
        exit 1
    fi
    if ! _config_key_valid "$key"; then
        log_error "Unknown config key: $key"
        exit 1
    fi
    if ! _config_key_is_list "$key"; then
        log_error "${key} is not a list setting. Use 'config set' instead."
        exit 1
    fi
    require_root
    _ensure_config

    load_config "$CONFIG_FILE"
    local current="${!key:-}" new_value="" item added=""
    current=$(echo "$current" | xargs)
    new_value="$current"

    for item in $value; do
        if [[ " $new_value " == *" $item "* ]]; then
            log_warn "$item is already in $key"
            continue
        fi
        new_value="${new_value:+$new_value }$item"
        added+="${added:+ }$item"
    done
    [[ -z "$added" ]] && return 0

    _config_write_validated "$key" "$new_value"

    log_success "Added ${added} to ${key}"
    log_info "${key} = \"${new_value}\""
    log_info "Run ${BOLD}binadit-firewall reload${NC} to apply"
}

fw_config_remove() {
    local key="${1:-}"
    local value="${2:-}"
    if [[ -z "$key" || -z "$value" ]]; then
        log_error "Usage: binadit-firewall config remove KEY VALUE"
        exit 1
    fi
    if ! _config_key_valid "$key"; then
        log_error "Unknown config key: $key"
        exit 1
    fi
    if ! _config_key_is_list "$key"; then
        log_error "${key} is not a list setting. Use 'config set' instead."
        exit 1
    fi
    require_root
    _ensure_config

    load_config "$CONFIG_FILE"
    local current="${!key:-}" new_value="" item removed=""

    for item in $current; do
        if [[ " $value " == *" $item "* ]]; then
            removed+="${removed:+ }$item"
        else
            new_value="${new_value:+$new_value }$item"
        fi
    done

    if [[ -z "$removed" ]]; then
        log_warn "$value is not in $key"
        return 0
    fi

    _config_write_validated "$key" "$new_value"

    log_success "Removed ${removed} from ${key}"
    log_info "${key} = \"${new_value}\""
    log_info "Run ${BOLD}binadit-firewall reload${NC} to apply"
}

# =============================================================================
# Self-update from GitHub
# =============================================================================

REPO_URL="${BINADIT_REPO_URL:-https://github.com/ronaldjonkers/binadit-firewall}"
REPO_RAW="${BINADIT_REPO_RAW:-https://raw.githubusercontent.com/ronaldjonkers/binadit-firewall/master}"

_version_from_file() {
    grep 'BINADIT_VERSION=' "$1" 2>/dev/null | head -1 | sed 's/.*"\([0-9.]*\)".*/\1/'
}

fw_update() {
    require_root

    local assume_yes=false force=false arg
    for arg in "$@"; do
        case "$arg" in
            --yes|-y) assume_yes=true ;;
            --force)  force=true ;;
        esac
    done

    show_banner
    log_header "Checking for updates"

    if [[ ! -d "$INSTALL_DIR" ]]; then
        log_error "binadit-firewall is not installed in ${INSTALL_DIR}"
        log_info "Install it first with install.sh (see the README)"
        exit 1
    fi

    # Determine download tool
    local -a fetch
    if command -v curl &>/dev/null; then
        fetch=(curl -fsSL)
    elif command -v wget &>/dev/null; then
        fetch=(wget -qO-)
    else
        log_error "curl or wget is required for updates"
        exit 1
    fi
    if ! command -v tar &>/dev/null; then
        log_error "tar is required for updates"
        exit 1
    fi

    # Get remote version
    local remote_version
    remote_version=$("${fetch[@]}" "${REPO_RAW}/src/lib/common.sh" 2>/dev/null | grep 'BINADIT_VERSION=' | head -1 | sed 's/.*"\([0-9.]*\)".*/\1/') || true

    if [[ -z "$remote_version" ]]; then
        log_error "Could not check remote version. Check your internet connection."
        exit 1
    fi

    log_info "Installed version: ${BOLD}v${BINADIT_VERSION}${NC}"
    log_info "Latest version:    ${BOLD}v${remote_version}${NC}"

    # Compare versions using sort -V (version sort)
    local higher
    higher=$(printf '%s\n%s' "$BINADIT_VERSION" "$remote_version" | sort -V | tail -1)

    if [[ "$force" != "true" ]]; then
        if [[ "$BINADIT_VERSION" == "$remote_version" ]]; then
            log_success "Already up to date!"
            return 0
        elif [[ "$higher" == "$BINADIT_VERSION" ]]; then
            log_success "Installed version is newer than remote (v${remote_version}) — no update needed"
            return 0
        fi
        log_info "Update available: ${BOLD}v${BINADIT_VERSION}${NC} → ${BOLD}v${remote_version}${NC}"
    else
        log_info "Reinstalling (--force)"
    fi

    if [[ "$assume_yes" != "true" ]]; then
        echo ""
        local do_update
        ask do_update "  Install update? [Y/n]: " "y"
        if [[ "${do_update,,}" == "n" ]]; then
            log_info "Update cancelled"
            return 0
        fi
    fi

    # Download
    local tmpdir
    tmpdir=$(mktemp -d /tmp/binadit-firewall-update.XXXXXX)
    # shellcheck disable=SC2064
    trap "rm -rf '$tmpdir'" EXIT

    log_info "Downloading..."
    if ! "${fetch[@]}" "${REPO_URL}/archive/refs/heads/master.tar.gz" > "$tmpdir/src.tar.gz" 2>/dev/null \
        || ! tar -xzf "$tmpdir/src.tar.gz" -C "$tmpdir" 2>/dev/null; then
        log_error "Download failed — nothing was changed"
        exit 1
    fi

    local update_src
    update_src=$(find "$tmpdir" -mindepth 1 -maxdepth 1 -type d | head -1)
    if [[ -z "$update_src" || ! -f "$update_src/install.sh" || ! -f "$update_src/src/binadit-firewall.sh" ]]; then
        log_error "Downloaded archive is incomplete — nothing was changed"
        exit 1
    fi

    # Verify the download before installing anything
    local f
    while IFS= read -r f; do
        if ! bash -n "$f" 2>/dev/null; then
            log_error "Downloaded file is corrupt (${f##*/}) — nothing was changed"
            exit 1
        fi
    done < <(find "$update_src" -name '*.sh' -type f)

    local new_version
    new_version=$(_version_from_file "$update_src/src/lib/common.sh")
    if [[ "$force" != "true" ]]; then
        higher=$(printf '%s\n%s' "$BINADIT_VERSION" "$new_version" | sort -V | tail -1)
        if [[ -z "$new_version" || "$new_version" == "$BINADIT_VERSION" || "$higher" == "$BINADIT_VERSION" ]]; then
            log_warn "Downloaded version (v${new_version:-unknown}) is not newer than v${BINADIT_VERSION} — skipping (try again later)"
            return 0
        fi
    fi

    # Let the new version install itself (program files, service, reload)
    log_info "Installing v${new_version}..."
    if ! bash "$update_src/install.sh" --update; then
        log_error "Update failed"
        exit 1
    fi

    echo ""
    log_success "Updated to v${new_version}"
    log_info "Configuration preserved: ${CONFIG_FILE}"

    # This script file has been replaced: stop here instead of reading on
    exit 0
}

# Finish an update (called by the installer of the NEW version)
fw_post_update() {
    require_root
    refresh_integrations

    if ! backend_is_active; then
        log_info "Firewall is not active — start it with: ${BOLD}binadit-firewall start${NC}"
        return 0
    fi

    # Reload with the configuration that is currently in effect
    local cfg
    cfg=$(applied_config_file)
    [[ -f "$cfg" ]] || cfg="$CONFIG_FILE"
    if [[ ! -f "$cfg" ]]; then
        return 0
    fi

    load_config "$cfg"
    if ! config_validate; then
        log_warn "Configuration has errors — the currently loaded rules were left untouched"
        log_warn "Run ${BOLD}binadit-firewall configtest${NC} and then ${BOLD}binadit-firewall reload${NC}"
        return 0
    fi

    fw_lock
    backup_rules
    if fw_apply "$cfg" >/dev/null; then
        log_success "Firewall rules reloaded with the new version"
    else
        log_warn "Reload failed — the previously loaded rules are still active"
        log_warn "Run ${BOLD}binadit-firewall configtest${NC} to see why"
    fi
}

# =============================================================================
# Auto-update management
# =============================================================================

CRON_SCRIPT="/etc/cron.weekly/binadit-firewall-update"
[[ ! -d /etc/cron.weekly && -d /etc/periodic/weekly ]] && CRON_SCRIPT="/etc/periodic/weekly/binadit-firewall-update"
UPDATE_TIMER_UNIT="/etc/systemd/system/binadit-firewall-update.timer"
UPDATE_SERVICE_UNIT="/etc/systemd/system/binadit-firewall-update.service"
UPDATE_LOG="/var/log/binadit-firewall-update.log"

fw_auto_update() {
    local action="${1:-}"

    case "$action" in
        on|enable)
            require_root
            if [[ -d "$(dirname "$CRON_SCRIPT")" ]]; then
                cat > "$CRON_SCRIPT" <<'CRONEOF'
#!/bin/bash
# binadit-firewall weekly auto-update
# Installed by: binadit-firewall auto-update on
# Remove with:  binadit-firewall auto-update off

LOG="/var/log/binadit-firewall-update.log"

{
    echo "=== binadit-firewall auto-update: $(date) ==="
    /usr/local/sbin/binadit-firewall update --yes 2>&1
    echo "=== Update completed: $(date) ==="
    echo ""
} >> "$LOG" 2>&1

# Keep log file reasonable (last 500 lines)
if [ -f "$LOG" ]; then
    tail -500 "$LOG" > "${LOG}.tmp" && mv "${LOG}.tmp" "$LOG"
fi
CRONEOF
                chmod 755 "$CRON_SCRIPT"
                log_success "Weekly auto-update enabled (cron)"
                log_info "Cron script: ${CRON_SCRIPT}"
            elif _has_systemd; then
                cat > "$UPDATE_SERVICE_UNIT" <<UNITEOF
[Unit]
Description=binadit-firewall - weekly auto-update
Documentation=https://github.com/ronaldjonkers/binadit-firewall
After=network-online.target

[Service]
Type=oneshot
ExecStart=/bin/sh -c '{ echo "=== binadit-firewall auto-update: \$(date) ==="; ${SBIN_LINK} update --yes; echo; } >> ${UPDATE_LOG} 2>&1'
UNITEOF
                cat > "$UPDATE_TIMER_UNIT" <<'UNITEOF'
[Unit]
Description=binadit-firewall - weekly auto-update

[Timer]
OnCalendar=weekly
RandomizedDelaySec=6h
Persistent=true

[Install]
WantedBy=timers.target
UNITEOF
                systemctl daemon-reload
                systemctl enable --now binadit-firewall-update.timer &>/dev/null
                log_success "Weekly auto-update enabled (systemd timer)"
                log_info "Timer: binadit-firewall-update.timer"
            else
                log_error "Cannot enable auto-update: no weekly cron directory and no systemd available"
                exit 1
            fi
            log_info "Update log:  ${UPDATE_LOG}"
            log_info "Disable with: ${BOLD}binadit-firewall auto-update off${NC}"
            ;;
        off|disable)
            require_root
            local was_enabled=false
            if [[ -f "$CRON_SCRIPT" ]]; then
                rm -f "$CRON_SCRIPT"
                was_enabled=true
            fi
            if [[ -f "$UPDATE_TIMER_UNIT" ]]; then
                systemctl disable --now binadit-firewall-update.timer &>/dev/null || true
                rm -f "$UPDATE_TIMER_UNIT" "$UPDATE_SERVICE_UNIT"
                systemctl daemon-reload &>/dev/null || true
                was_enabled=true
            fi
            if [[ "$was_enabled" == "true" ]]; then
                log_success "Auto-update disabled"
            else
                log_info "Auto-update was not enabled"
            fi
            ;;
        status)
            if [[ -f "$CRON_SCRIPT" || -f "$UPDATE_TIMER_UNIT" ]]; then
                log_success "Auto-update is ${GREEN}${BOLD}enabled${NC}"
                [[ -f "$CRON_SCRIPT" ]] && log_info "Cron script: ${CRON_SCRIPT}"
                [[ -f "$UPDATE_TIMER_UNIT" ]] && log_info "Timer: binadit-firewall-update.timer"
                if [[ -f "$UPDATE_LOG" ]]; then
                    echo ""
                    echo -e "  ${BOLD}Last update log entries:${NC}"
                    tail -5 "$UPDATE_LOG" 2>/dev/null | while IFS= read -r line; do
                        echo -e "  ${CYAN}│${NC} $line"
                    done
                fi
            else
                log_info "Auto-update is ${RED}${BOLD}disabled${NC}"
                log_info "Enable with: ${BOLD}binadit-firewall auto-update on${NC}"
            fi
            ;;
        *)
            echo -e "  ${BOLD}Usage:${NC} binadit-firewall auto-update {on|off|status}"
            echo ""
            echo -e "  ${GREEN}on${NC}      Enable weekly automatic updates"
            echo -e "  ${GREEN}off${NC}     Disable automatic updates"
            echo -e "  ${GREEN}status${NC}  Show auto-update status and recent log"
            echo ""
            exit 1
            ;;
    esac
}

# Show help
fw_help() {
    show_banner
    cat <<EOF
  ${BOLD}USAGE:${NC}
      binadit-firewall <command> [options]

  ${BOLD}FIREWALL:${NC}
      ${GREEN}start${NC}               Apply firewall rules from configuration
      ${GREEN}stop${NC}                Remove all rules (allow all traffic)
      ${GREEN}restart${NC} | ${GREEN}reload${NC}    Re-read the config and replace the rules atomically
      ${GREEN}status${NC}              Show whether the firewall is active + rules

  ${BOLD}CONFIGURATION:${NC}
      ${GREEN}config show${NC}         Show all current settings
      ${GREEN}config get${NC} KEY      Get a setting value
      ${GREEN}config set${NC} KEY VAL  Set a setting value
      ${GREEN}config add${NC} KEY VAL  Add value to a list setting
      ${GREEN}config remove${NC} K V   Remove value from a list setting
      ${GREEN}configtest${NC}          Validate config without applying
      ${GREEN}dns-refresh${NC}         Re-check hostnames now, reload if an IP changed
      ${GREEN}setup${NC}               Interactive setup wizard
      ${GREEN}features${NC}            Show all features with detailed explanations

  ${BOLD}UPDATES:${NC}
      ${GREEN}update${NC}              Download and install latest version
      ${GREEN}auto-update${NC} on|off  Enable/disable weekly auto-updates
      ${GREEN}upgrade${NC}             Migrate a v1.x (2013) config, then update

  ${BOLD}SYSTEM:${NC}
      ${GREEN}backup${NC}              Create a backup of current rules
      ${GREEN}motd-on${NC}             Show firewall status on every login
      ${GREEN}motd-off${NC}            Remove login status indicator
      ${GREEN}prompt-on${NC}           Show 🟢/🔴 emoji before prompt
      ${GREEN}prompt-off${NC}          Remove prompt indicator
      ${GREEN}version${NC}             Show version and system info
      ${GREEN}help${NC}                Show this help message

  ${BOLD}EXAMPLES:${NC}
      binadit-firewall config show                  # View all settings
      binadit-firewall config set TCP_PORTS "80 443" # Set open ports
      binadit-firewall config add TCP_PORTS 8080     # Add a port
      binadit-firewall config remove BLACKLIST 1.2.3.4
      binadit-firewall configtest                    # Validate config
      binadit-firewall reload                        # Apply changes
      binadit-firewall update                        # Get latest version
      binadit-firewall features                      # Full feature docs

EOF
}

# =============================================================================
# Main entry point
# =============================================================================

case "${1:-help}" in
    start|restart|reload)
        fw_start
        ;;
    stop)
        fw_stop
        ;;
    status)
        fw_status
        ;;
    config)
        shift
        fw_config "$@"
        ;;
    configtest|test)
        fw_configtest
        ;;
    dns-refresh)
        fw_dns_refresh
        ;;
    setup)
        fw_setup
        ;;
    features)
        fw_features
        ;;
    update)
        shift
        fw_update "$@"
        ;;
    post-update)
        fw_post_update
        ;;
    auto-update)
        shift
        fw_auto_update "$@"
        ;;
    upgrade)
        shift
        fw_upgrade "$@"
        ;;
    motd-on)
        fw_install_motd
        ;;
    motd-off)
        fw_remove_motd
        ;;
    prompt-on)
        fw_install_prompt
        ;;
    prompt-off)
        fw_remove_prompt
        ;;
    backup)
        require_root
        backup_rules
        log_success "Backup created in ${CONFIG_DIR}/backups/"
        ;;
    version|--version|-v)
        fw_version
        ;;
    help|--help|-h)
        fw_help
        ;;
    *)
        log_error "Unknown command: $1"
        fw_help
        exit 1
        ;;
esac
