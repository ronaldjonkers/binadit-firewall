#!/usr/bin/env bash
# =============================================================================
# binadit-firewall v2.1.2
# =============================================================================
# A modern, easy-to-use Linux firewall manager with support for both
# nftables and iptables backends.
#
# Copyright (C) 2013-2026 Ronald Jonkers — Binadit BV (binadit.com)
# License: GPL-2.0
#
# Usage: binadit-firewall {start|stop|restart|status|reload|config|configtest|setup|features|update|auto-update|upgrade|backup|motd-on|motd-off|prompt-on|prompt-off|version|help}
# =============================================================================

set -euo pipefail

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

# Source libraries
source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/backend.sh"
source "${LIB_DIR}/backend_nftables.sh"
source "${LIB_DIR}/backend_iptables.sh"

# =============================================================================
# Main functions
# =============================================================================

# Validate the configuration file — runs full configtest
# On error: prints detailed feedback and aborts (firewall stays unchanged)
validate_config() {
    if ! configtest "$CONFIG_FILE"; then
        log_error "Configuration test failed — firewall rules NOT changed"
        exit 1
    fi
}

# Detect and use the appropriate backend
get_backend() {
    detect_backend
}

# Run configtest standalone
fw_configtest() {
    if [[ ! -f "$CONFIG_FILE" ]]; then
        log_error "Configuration file not found: $CONFIG_FILE"
        log_info "Run 'binadit-firewall setup' or copy the example config:"
        log_info "  cp ${CONFIG_DIR}/firewall.conf.example ${CONFIG_FILE}"
        exit 1
    fi
    configtest "$CONFIG_FILE"
}

# Start the firewall
fw_start() {
    require_root
    validate_config

    show_banner

    local backend
    backend=$(get_backend)
    log_info "Using firewall backend: ${BOLD}${backend}${NC}"

    # Backup current rules before making changes
    backup_rules

    case "$backend" in
        nftables)
            nft_apply "$CONFIG_FILE"
            ;;
        iptables-nft|iptables-legacy)
            ipt_flush
            ipt_apply "$CONFIG_FILE"
            ;;
        *)
            log_error "Unsupported backend: $backend"
            exit 1
            ;;
    esac

    print_rule_summary "$CONFIG_FILE"
    show_protected
}

# Stop the firewall (flush all rules, allow all traffic)
fw_stop() {
    require_root

    log_header "Stopping binadit-firewall"

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

    show_unprotected
}

# Show firewall status
fw_status() {
    show_banner

    if [[ -f "$CONFIG_FILE" ]]; then
        print_rule_summary "$CONFIG_FILE"
    fi

    local backend
    backend=$(detect_backend)

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

# Reload configuration
fw_reload() {
    log_info "Reloading configuration..."
    fw_start
}

# Install MOTD script that shows firewall status on login
fw_install_motd() {
    require_root

    local motd_script="/etc/profile.d/binadit-firewall-status.sh"

    cat > "$motd_script" <<'MOTD_EOF'
#!/bin/sh
# binadit-firewall login status indicator
# Shows a subtle one-line status on login so admins know if the firewall is active.
# Remove with: binadit-firewall motd-off

if [ "$(id -u)" = "0" ] || id -nG 2>/dev/null | grep -qw sudo; then
    _bf_active=0
    _bf_detail=""
    if command -v nft >/dev/null 2>&1; then
        _bf_chains=$(nft list ruleset 2>/dev/null | grep -c "^[[:space:]]*chain " || true)
        _bf_chains=$(echo "$_bf_chains" | head -1 | tr -d '[:space:]')
        [ -z "$_bf_chains" ] && _bf_chains=0
        if [ "$_bf_chains" -gt 0 ] 2>/dev/null; then
            _bf_active=1
            _bf_detail="$_bf_chains chains"
        fi
    elif command -v iptables >/dev/null 2>&1; then
        _bf_rules=$(iptables -S 2>/dev/null | grep -cv '^\-P' || true)
        _bf_rules=$(echo "$_bf_rules" | head -1 | tr -d '[:space:]')
        [ -z "$_bf_rules" ] && _bf_rules=0
        if [ "$_bf_rules" -gt 2 ] 2>/dev/null; then
            _bf_active=1
            _bf_detail="$_bf_rules rules"
        fi
    fi
    if [ "$_bf_active" = "1" ]; then
        printf '\033[0;32m  \xE2\x96\xB8 binadit-firewall: active (%s)\033[0m\n' "$_bf_detail"
    else
        printf '\033[0;31m  \xE2\x9A\xA0 binadit-firewall: NOT ACTIVE \xe2\x80\x94 run: binadit-firewall start\033[0m\n'
    fi
    unset _bf_active _bf_detail _bf_chains _bf_rules
fi
MOTD_EOF

    chmod 644 "$motd_script"
    log_success "Login status indicator installed: ${motd_script}"
    log_info "Admins will see firewall status on every login"
    log_info "Remove with: ${BOLD}binadit-firewall motd-off${NC}"
}

# Remove MOTD script
fw_remove_motd() {
    require_root

    local motd_script="/etc/profile.d/binadit-firewall-status.sh"
    if [[ -f "$motd_script" ]]; then
        rm -f "$motd_script"
        log_success "Login status indicator removed"
    else
        log_info "Login status indicator was not installed"
    fi
}

# Install PS1 prompt indicator (🟢/🔴 before prompt)
fw_install_prompt() {
    require_root

    local prompt_script="/etc/profile.d/binadit-firewall-prompt.sh"

    cat > "$prompt_script" <<'PROMPT_EOF'
#!/bin/bash
# binadit-firewall PS1 prompt indicator
# Shows 🟢 (active) or 🔴 (inactive) before your prompt
# Remove with: binadit-firewall prompt-off

__binadit_fw_status() {
    if command -v nft >/dev/null 2>&1; then
        local _c
        _c=$(nft list ruleset 2>/dev/null | grep -c "^[[:space:]]*chain " 2>/dev/null || true)
        _c=$(echo "$_c" | head -1 | tr -d '[:space:]')
        [ -n "$_c" ] && [ "$_c" -gt 0 ] 2>/dev/null && printf '🟢' && return
    elif command -v iptables >/dev/null 2>&1; then
        local _r
        _r=$(iptables -S 2>/dev/null | grep -cv '^\-P' 2>/dev/null || true)
        _r=$(echo "$_r" | head -1 | tr -d '[:space:]')
        [ -n "$_r" ] && [ "$_r" -gt 2 ] 2>/dev/null && printf '🟢' && return
    fi
    printf '🔴'
}

if [ "$(id -u)" = "0" ] || id -nG 2>/dev/null | grep -qw sudo 2>/dev/null; then
    if [ -n "$BASH_VERSION" ]; then
        PROMPT_COMMAND='__binadit_fw_ps1=$(__binadit_fw_status)'${PROMPT_COMMAND:+";$PROMPT_COMMAND"}
        PS1='${__binadit_fw_ps1} '"$PS1"
    fi
fi
PROMPT_EOF

    chmod 644 "$prompt_script"
    log_success "Prompt indicator installed: ${prompt_script}"
    log_info "🟢 = firewall active, 🔴 = firewall inactive"
    log_info "Remove with: ${BOLD}binadit-firewall prompt-off${NC}"
    log_info "Takes effect on next login"
}

# Remove PS1 prompt indicator
fw_remove_prompt() {
    require_root

    local prompt_script="/etc/profile.d/binadit-firewall-prompt.sh"
    if [[ -f "$prompt_script" ]]; then
        rm -f "$prompt_script"
        log_success "Prompt indicator removed"
        log_info "Takes effect on next login"
    else
        log_info "Prompt indicator was not installed"
    fi
}

# Show version
fw_version() {
    show_banner
    echo -e "  ${BOLD}Backend:${NC}  $(detect_backend)"
    echo -e "  ${BOLD}Config:${NC}   ${CONFIG_FILE}"
    echo -e "  ${BOLD}OS:${NC}       $(detect_distro) ($(detect_distro_family))"
    if [[ -f "$CONFIG_FILE" ]]; then
        echo -e "  ${BOLD}Status:${NC}   ${GREEN}configured${NC}"
    else
        echo -e "  ${BOLD}Status:${NC}   ${YELLOW}not configured${NC}"
    fi
    echo ""
}

# Upgrade from v1.x or older v2.x (preserves config)
fw_upgrade() {
    require_root

    show_banner
    log_header "Upgrade Check"

    local needs_upgrade=false
    local old_v1_config="/etc/firewall.d/host.conf"
    local old_v1_script="/etc/init.d/firewall"

    # Check for v1.x installation
    if [[ -f "$old_v1_config" ]] || [[ -f "$old_v1_script" ]]; then
        log_warn "Found binadit-firewall v1.x installation"
        needs_upgrade=true

        echo ""
        echo -e "  ${BOLD}Migration plan:${NC}"
        echo -e "  ${CYAN}│${NC} 1. Migrate config from ${old_v1_config}"
        echo -e "  ${CYAN}│${NC} 2. Preserve all port/IP settings"
        echo -e "  ${CYAN}│${NC} 3. Install new v${BINADIT_VERSION} files"
        echo -e "  ${CYAN}│${NC} 4. Setup systemd/init.d service"
        echo -e "  ${CYAN}│${NC} 5. Backup and remove old files"
        echo ""

        read -rp "  Proceed with upgrade? [Y/n]: " do_upgrade
        if [[ "${do_upgrade,,}" == "n" ]]; then
            log_info "Upgrade cancelled"
            return 0
        fi

        # Migrate the config
        if [[ -f "$old_v1_config" ]]; then
            log_info "Migrating v1.x configuration..."
            mkdir -p "$CONFIG_DIR"

            # Source old config
            # shellcheck source=/dev/null
            source "$old_v1_config"

            # Create new config from example
            local example="${SCRIPT_DIR}/../config/firewall.conf.example"
            [[ ! -f "$example" ]] && example="${CONFIG_DIR}/firewall.conf.example"
            cp "$example" "${CONFIG_DIR}/firewall.conf"
            local new_conf="${CONFIG_DIR}/firewall.conf"

            # Map old variables to new
            [[ -n "${TCPPORTS:-}" ]] && sed -i "s/^TCP_PORTS=.*/TCP_PORTS=\"${TCPPORTS}\"/" "$new_conf"
            [[ -n "${TCPPORTS_INPUT:-}" ]] && sed -i "s/^TCP_PORTS_INPUT=.*/TCP_PORTS_INPUT=\"${TCPPORTS_INPUT}\"/" "$new_conf"
            [[ -n "${TCPPORTS_OUTPUT:-}" ]] && sed -i "s/^TCP_PORTS_OUTPUT=.*/TCP_PORTS_OUTPUT=\"${TCPPORTS_OUTPUT}\"/" "$new_conf"
            [[ -n "${UDPPORTS:-}" ]] && sed -i "s/^UDP_PORTS=.*/UDP_PORTS=\"${UDPPORTS}\"/" "$new_conf"
            [[ -n "${DMZS:-}" ]] && sed -i "s/^TRUSTED_IPS=.*/TRUSTED_IPS=\"${DMZS}\"/" "$new_conf"
            [[ -n "${SSHACCESS:-}" ]] && sed -i "s/^SSH_ALLOWED_IPS=.*/SSH_ALLOWED_IPS=\"${SSHACCESS}\"/" "$new_conf"
            [[ -n "${SSHACCESS_IPv6:-}" ]] && sed -i "s/^SSH_ALLOWED_IPS_IPV6=.*/SSH_ALLOWED_IPS_IPV6=\"${SSHACCESS_IPv6}\"/" "$new_conf"
            [[ -n "${DMZRANGE:-}" ]] && sed -i "s/^TRUSTED_RANGES=.*/TRUSTED_RANGES=\"${DMZRANGE}\"/" "$new_conf"
            [[ -n "${BLACKLIST:-}" ]] && sed -i "s/^BLACKLIST=.*/BLACKLIST=\"${BLACKLIST}\"/" "$new_conf"
            [[ -n "${BLOCKRANGE:-}" ]] && sed -i "s/^BLOCKED_RANGES=.*/BLOCKED_RANGES=\"${BLOCKRANGE}\"/" "$new_conf"
            [[ -n "${DMZS_IPv6:-}" ]] && sed -i "s/^TRUSTED_IPS_IPV6=.*/TRUSTED_IPS_IPV6=\"${DMZS_IPv6}\"/" "$new_conf"
            [[ -n "${BLACKLIST_IPv6:-}" ]] && sed -i "s/^BLACKLIST_IPV6=.*/BLACKLIST_IPV6=\"${BLACKLIST_IPv6}\"/" "$new_conf"
            [[ "${MULTICAST_ENABLE:-}" == "TRUE" ]] && sed -i 's/^MULTICAST_ENABLE=.*/MULTICAST_ENABLE="true"/' "$new_conf"
            [[ "${NATROUTER_ENABLE:-}" == "TRUE" ]] && sed -i 's/^NAT_ENABLE=.*/NAT_ENABLE="true"/' "$new_conf"

            # Backup old files
            mv "$old_v1_config" "${old_v1_config}.migrated.$(date +%Y%m%d)"
            log_success "Config migrated: ${old_v1_config} -> ${new_conf}"
        fi

        # Remove old init.d script
        if [[ -f "$old_v1_script" ]]; then
            mv "$old_v1_script" "${old_v1_script}.v1.bak"
            log_success "Old init script backed up: ${old_v1_script}.v1.bak"
        fi
    fi

    # Check for existing v2.x that needs file update
    if [[ -f "/usr/local/share/binadit-firewall/binadit-firewall.sh" ]]; then
        local installed_version
        installed_version=$(grep "BINADIT_VERSION=" /usr/local/share/binadit-firewall/lib/common.sh 2>/dev/null | head -1 | sed 's/.*"\([0-9.]*\)".*/\1/' || echo "unknown")

        if [[ "$installed_version" != "$BINADIT_VERSION" ]]; then
            log_info "Installed version: ${BOLD}${installed_version}${NC}"
            log_info "Available version: ${BOLD}${BINADIT_VERSION}${NC}"
            needs_upgrade=true

            read -rp "  Upgrade to v${BINADIT_VERSION}? (config will be preserved) [Y/n]: " do_upgrade
            if [[ "${do_upgrade,,}" == "n" ]]; then
                log_info "Upgrade cancelled"
                return 0
            fi

            # Update program files only (preserve config)
            log_info "Updating program files..."
            cp -r "${SCRIPT_DIR}/"* /usr/local/share/binadit-firewall/
            cp "${SCRIPT_DIR}/../config/firewall.conf.example" "${CONFIG_DIR}/firewall.conf.example"
            chmod 755 /usr/local/share/binadit-firewall/binadit-firewall.sh
            chmod 644 /usr/local/share/binadit-firewall/lib/*.sh
            log_success "Program files updated to v${BINADIT_VERSION}"
            log_success "Configuration preserved: ${CONFIG_FILE}"
        else
            log_success "Already running v${BINADIT_VERSION} - no upgrade needed"
            return 0
        fi
    fi

    if [[ "$needs_upgrade" == "false" ]]; then
        log_success "No previous installation found. Run 'install.sh' for fresh install."
        return 0
    fi

    # Restart with new version
    echo ""
    read -rp "  Restart firewall with new version? [Y/n]: " do_restart
    if [[ "${do_restart,,}" != "n" ]]; then
        fw_start
    fi
}

# Interactive setup wizard
fw_setup() {
    require_root

    log_header "binadit-firewall Setup Wizard"

    mkdir -p "$CONFIG_DIR"

    if [[ -f "$CONFIG_FILE" ]]; then
        log_warn "Configuration already exists: $CONFIG_FILE"
        read -rp "Overwrite? [y/N]: " overwrite
        if [[ "${overwrite,,}" != "y" ]]; then
            log_info "Setup cancelled"
            return 0
        fi
        cp "$CONFIG_FILE" "${CONFIG_FILE}.bak.$(date +%Y%m%d_%H%M%S)"
    fi

    # Copy example config
    local example_config="${CONFIG_DIR}/firewall.conf.example"
    if [[ ! -f "$example_config" ]]; then
        example_config="${SCRIPT_DIR}/../config/firewall.conf.example"
    fi

    if [[ -f "$example_config" ]]; then
        cp "$example_config" "$CONFIG_FILE"
    else
        log_error "Example config not found"
        return 1
    fi

    local ssh_port
    ssh_port=$(detect_ssh_port)
    log_info "Detected SSH port: $ssh_port"

    echo ""
    echo -e "${BOLD}Which ports would you like to open?${NC}"
    echo ""

    # Web server ports
    read -rp "Open HTTP (80) and HTTPS (443)? [Y/n]: " open_web
    if [[ "${open_web,,}" != "n" ]]; then
        sed -i "s/^TCP_PORTS=.*/TCP_PORTS=\"80 443\"/" "$CONFIG_FILE"
    fi

    # SSH port
    read -rp "Restrict SSH ($ssh_port) to specific IPs? [y/N]: " restrict_ssh
    if [[ "${restrict_ssh,,}" == "y" ]]; then
        read -rp "Enter allowed SSH IPs (space-separated): " ssh_ips
        sed -i "s/^SSH_ALLOWED_IPS=.*/SSH_ALLOWED_IPS=\"${ssh_ips}\"/" "$CONFIG_FILE"
    fi

    # Additional TCP ports
    read -rp "Additional TCP ports to open (space-separated, or empty): " extra_tcp
    if [[ -n "$extra_tcp" ]]; then
        local current_tcp
        current_tcp=$(grep "^TCP_PORTS=" "$CONFIG_FILE" | cut -d'"' -f2)
        sed -i "s/^TCP_PORTS=.*/TCP_PORTS=\"${current_tcp} ${extra_tcp}\"/" "$CONFIG_FILE"
    fi

    # Mail server
    read -rp "Is this a mail server? (opens 25, 587, 993, 995) [y/N]: " is_mail
    if [[ "${is_mail,,}" == "y" ]]; then
        local current_tcp
        current_tcp=$(grep "^TCP_PORTS=" "$CONFIG_FILE" | cut -d'"' -f2)
        sed -i "s/^TCP_PORTS=.*/TCP_PORTS=\"${current_tcp} 25 587 993 995\"/" "$CONFIG_FILE"
    fi

    # Database ports
    read -rp "Open database ports? (MySQL 3306, PostgreSQL 5432, Redis 6379) [y/N]: " open_db
    if [[ "${open_db,,}" == "y" ]]; then
        read -rp "Which? [mysql/postgres/redis/all]: " db_choice
        local db_ports=""
        case "$db_choice" in
            mysql)    db_ports="3306" ;;
            postgres) db_ports="5432" ;;
            redis)    db_ports="6379" ;;
            all)      db_ports="3306 5432 6379" ;;
        esac
        if [[ -n "$db_ports" ]]; then
            local current_tcp
            current_tcp=$(grep "^TCP_PORTS=" "$CONFIG_FILE" | cut -d'"' -f2)
            sed -i "s/^TCP_PORTS=.*/TCP_PORTS=\"${current_tcp} ${db_ports}\"/" "$CONFIG_FILE"
            log_warn "Consider restricting database ports to specific IPs using PORT_IP_RULES"
        fi
    fi

    # ICMP
    read -rp "Allow ping (ICMP)? [Y/n]: " allow_ping
    if [[ "${allow_ping,,}" == "n" ]]; then
        sed -i "s/^ICMP_ENABLE=.*/ICMP_ENABLE=\"false\"/" "$CONFIG_FILE"
    fi

    echo ""
    log_success "Configuration saved to: $CONFIG_FILE"
    log_info "Review and edit: nano $CONFIG_FILE"
    echo ""

    read -rp "Apply firewall rules now? [Y/n]: " apply_now
    if [[ "${apply_now,,}" != "n" ]]; then
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

  ${BOLD}FIREWALL CONTROL${NC}
  ${GREEN}start${NC}           Apply all firewall rules from config. Backs up current
                  rules first, then applies nftables or iptables rules.
  ${GREEN}stop${NC}            Flush all rules and allow all traffic. Use in emergencies
                  if you get locked out. Rules are backed up before flushing.
  ${GREEN}restart${NC}         Full stop + start cycle. Ensures clean rule application.
  ${GREEN}reload${NC}          Alias for start. Re-reads config and applies rules.

  ${BOLD}CONFIGURATION MANAGEMENT${NC}
  ${GREEN}config show${NC}     Display all current firewall settings in a readable table.
  ${GREEN}config get${NC}      Get the value of a single setting.
                  Example: ${BOLD}binadit-firewall config get TCP_PORTS${NC}
  ${GREEN}config set${NC}      Set the value of a setting.
                  Example: ${BOLD}binadit-firewall config set TCP_PORTS "80 443 8080"${NC}
  ${GREEN}config add${NC}      Add a value to a space-separated list setting.
                  Example: ${BOLD}binadit-firewall config add TCP_PORTS 8080${NC}
  ${GREEN}config remove${NC}   Remove a value from a space-separated list setting.
                  Example: ${BOLD}binadit-firewall config remove TCP_PORTS 8080${NC}
  ${GREEN}configtest${NC}      Validate the entire config without applying. Shows errors
                  and warnings for every setting. Run before applying changes.
  ${GREEN}setup${NC}           Interactive setup wizard. Walks through common settings
                  step by step (ports, SSH, ICMP, etc.).

  ${BOLD}PORT SETTINGS${NC}
  ${GREEN}TCP_PORTS${NC}               Ports open for both incoming and outgoing TCP.
                          Example: "80 443 8080 20000:25000"
  ${GREEN}TCP_PORTS_INPUT${NC}         Ports open for incoming TCP only.
  ${GREEN}TCP_PORTS_OUTPUT${NC}        Ports open for outgoing TCP only.
  ${GREEN}UDP_PORTS${NC}               Ports open for both incoming and outgoing UDP.
                          Example: "53 51820"
  ${GREEN}BLOCKED_TCP_PORTS${NC}       TCP ports to block in BOTH directions (overrides other rules).
  ${GREEN}BLOCKED_UDP_PORTS${NC}       UDP ports to block in BOTH directions.
  ${GREEN}BLOCKED_TCP_PORTS_OUTPUT${NC} TCP ports to block outgoing only.
                          Example: "25 587" to block outgoing SMTP/email.
  ${GREEN}BLOCKED_UDP_PORTS_OUTPUT${NC} UDP ports to block outgoing only.

  ${BOLD}ACCESS CONTROL${NC}
  ${GREEN}SSH_ALLOWED_IPS${NC}         Restrict SSH to specific IPs/hostnames/CIDRs.
                          Leave empty = SSH handled by TCP_PORTS.
  ${GREEN}TRUSTED_IPS${NC}             IPs with full server access (bypass all rules).
  ${GREEN}TRUSTED_RANGES${NC}          Trusted IP ranges (CIDR or dash notation).
  ${GREEN}BLACKLIST${NC}               IPs to completely block.
  ${GREEN}BLOCKED_RANGES${NC}          IP ranges to block.
  ${GREEN}PORT_IP_RULES${NC}           Allow specific IPs for specific ports.
                          Format: "proto|port|ip" (one per line).
                          Example: "tcp|3306|10.0.0.5"

  ${BOLD}SECURITY FEATURES${NC}
  ${GREEN}SYN_FLOOD_PROTECT${NC}       SYN flood mitigation (true/false). Default: true.
  ${GREEN}RATE_LIMIT_ENABLE${NC}       DDoS protection via connection rate limiting.
  ${GREEN}RATE_LIMIT_RATE${NC}         Connections per second. Default: 25.
  ${GREEN}RATE_LIMIT_BURST${NC}        Burst tolerance. Default: 100.
  ${GREEN}CONN_LIMIT_ENABLE${NC}       Per-IP concurrent connection limit.
  ${GREEN}CONN_LIMIT_PER_IP${NC}       Max simultaneous connections per IP. Default: 50.
  ${GREEN}CONN_RATE_PER_IP${NC}        New connections/sec per IP. Default: 15.
  ${GREEN}DROP_INVALID${NC}            Drop packets in INVALID state. Default: true.
  ${GREEN}BLOCK_COMMON_ATTACKS${NC}    Auto-block telnet, netbios, etc. Default: true.

  ${BOLD}NETWORK FEATURES${NC}
  ${GREEN}ICMP_ENABLE${NC}             Allow ping. Default: true.
  ${GREEN}MULTICAST_ENABLE${NC}        For clusters/load balancers. Default: false.
  ${GREEN}SMTP_ENABLE${NC}             Deprecated — outgoing is open by default.
                          To block outgoing mail, use BLOCKED_TCP_PORTS_OUTPUT="25 587".
  ${GREEN}NAT_ENABLE${NC}              Enable NAT routing (gateway setups). Default: false.
  ${GREEN}NAT_EXTERNAL_IFACE${NC}      Internet-facing interface (e.g., eth0).
  ${GREEN}NAT_INTERNAL_IFACE${NC}      LAN-facing interface (e.g., eth1).
  ${GREEN}PORT_FORWARD_RULES${NC}      DNAT rules. Format: "proto|ext_port|int_ip:int_port".

  ${BOLD}MONITORING & MAINTENANCE${NC}
  ${GREEN}status${NC}          Show rule summary + active rules from the backend.
  ${GREEN}backup${NC}          Manually create a backup of current rules.
  ${GREEN}motd-on${NC}         Show one-line firewall status on every SSH login.
  ${GREEN}motd-off${NC}        Remove the login status indicator.
  ${GREEN}prompt-on${NC}       Show 🟢/🔴 emoji before your shell prompt.
                  🟢 = firewall active, 🔴 = firewall inactive.
                  Updates on every command. Works in bash.
  ${GREEN}prompt-off${NC}      Remove the prompt indicator.
  ${GREEN}LOG_DROPPED${NC}     Log dropped packets to syslog. Default: true.
                  View logs: ${BOLD}journalctl -k | grep binadit-drop${NC}

  ${BOLD}UPDATES & VERSIONING${NC}
  ${GREEN}update${NC}          Download and install the latest version from GitHub.
                  Configuration is always preserved.
  ${GREEN}auto-update on${NC}  Enable weekly automatic updates via cron.
  ${GREEN}auto-update off${NC} Disable automatic updates.
  ${GREEN}version${NC}         Show version, backend, OS, and config status.

  ${BOLD}ADVANCED${NC}
  ${GREEN}CUSTOM_RULES_FILE${NC}       Path to a file with raw iptables/nft rules.
                          These are appended after all managed rules.
  ${GREEN}BINADIT_DEBUG${NC}           Enable debug logging. Also: BINADIT_DEBUG=true binadit-firewall start

EOF
}

# =============================================================================
# CLI config management
# =============================================================================

# Valid config keys (for validation)
VALID_CONFIG_KEYS="TCP_PORTS TCP_PORTS_INPUT TCP_PORTS_OUTPUT UDP_PORTS \
BLOCKED_TCP_PORTS BLOCKED_UDP_PORTS BLOCKED_TCP_PORTS_OUTPUT BLOCKED_UDP_PORTS_OUTPUT \
SSH_ALLOWED_IPS SSH_ALLOWED_IPS_IPV6 \
TRUSTED_IPS TRUSTED_IPS_IPV6 TRUSTED_RANGES TRUSTED_RANGES_IPV6 \
BLACKLIST BLACKLIST_IPV6 BLOCKED_RANGES BLOCKED_RANGES_IPV6 \
PORT_IP_RULES ICMP_ENABLE MULTICAST_ENABLE SMTP_ENABLE RATE_LIMIT_ENABLE \
RATE_LIMIT_RATE RATE_LIMIT_BURST LOG_DROPPED NAT_ENABLE NAT_EXTERNAL_IFACE \
NAT_INTERNAL_IFACE SYN_FLOOD_PROTECT CONN_LIMIT_ENABLE CONN_LIMIT_PER_IP \
CONN_RATE_PER_IP DROP_INVALID BLOCK_COMMON_ATTACKS PORT_FORWARD_RULES \
CUSTOM_RULES_FILE BINADIT_DEBUG"

# List-type keys (space-separated values that support add/remove)
LIST_CONFIG_KEYS="TCP_PORTS TCP_PORTS_INPUT TCP_PORTS_OUTPUT UDP_PORTS \
BLOCKED_TCP_PORTS BLOCKED_UDP_PORTS BLOCKED_TCP_PORTS_OUTPUT BLOCKED_UDP_PORTS_OUTPUT \
SSH_ALLOWED_IPS SSH_ALLOWED_IPS_IPV6 \
TRUSTED_IPS TRUSTED_IPS_IPV6 TRUSTED_RANGES TRUSTED_RANGES_IPV6 \
BLACKLIST BLACKLIST_IPV6 BLOCKED_RANGES BLOCKED_RANGES_IPV6"

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
    # shellcheck source=/dev/null
    source "$CONFIG_FILE"

    echo ""
    echo -e "  ${BOLD}${CYAN}━━━ Current Configuration ━━━${NC}"
    echo -e "  ${CYAN}File: ${NC}${CONFIG_FILE}"
    echo ""

    echo -e "  ${BOLD}PORT SETTINGS${NC}"
    echo -e "  ${CYAN}├${NC} TCP_PORTS            = ${BOLD}${TCP_PORTS:-${YELLOW}(empty)${NC}}${NC}"
    echo -e "  ${CYAN}├${NC} TCP_PORTS_INPUT      = ${BOLD}${TCP_PORTS_INPUT:-${YELLOW}(empty)${NC}}${NC}"
    echo -e "  ${CYAN}├${NC} TCP_PORTS_OUTPUT     = ${BOLD}${TCP_PORTS_OUTPUT:-${YELLOW}(empty)${NC}}${NC}"
    echo -e "  ${CYAN}├${NC} UDP_PORTS            = ${BOLD}${UDP_PORTS:-${YELLOW}(empty)${NC}}${NC}"
    echo -e "  ${CYAN}├${NC} BLOCKED_TCP_PORTS    = ${BOLD}${BLOCKED_TCP_PORTS:-${YELLOW}(empty)${NC}}${NC}"
    echo -e "  ${CYAN}└${NC} BLOCKED_UDP_PORTS    = ${BOLD}${BLOCKED_UDP_PORTS:-${YELLOW}(empty)${NC}}${NC}"

    echo ""
    echo -e "  ${BOLD}ACCESS CONTROL${NC}"
    echo -e "  ${CYAN}├${NC} SSH_ALLOWED_IPS      = ${BOLD}${SSH_ALLOWED_IPS:-${YELLOW}(empty)${NC}}${NC}"
    echo -e "  ${CYAN}├${NC} TRUSTED_IPS          = ${BOLD}${TRUSTED_IPS:-${YELLOW}(empty)${NC}}${NC}"
    echo -e "  ${CYAN}├${NC} TRUSTED_RANGES       = ${BOLD}${TRUSTED_RANGES:-${YELLOW}(empty)${NC}}${NC}"
    echo -e "  ${CYAN}├${NC} BLACKLIST            = ${BOLD}${BLACKLIST:-${YELLOW}(empty)${NC}}${NC}"
    echo -e "  ${CYAN}└${NC} BLOCKED_RANGES       = ${BOLD}${BLOCKED_RANGES:-${YELLOW}(empty)${NC}}${NC}"

    echo ""
    echo -e "  ${BOLD}SECURITY${NC}"
    local _bool_color
    for key in SYN_FLOOD_PROTECT RATE_LIMIT_ENABLE CONN_LIMIT_ENABLE DROP_INVALID BLOCK_COMMON_ATTACKS; do
        local val="${!key:-}"
        [[ "$val" == "true" ]] && _bool_color="${GREEN}" || _bool_color="${RED}"
        printf "  ${CYAN}├${NC} %-22s = ${_bool_color}${BOLD}%s${NC}\n" "$key" "$val"
    done
    echo -e "  ${CYAN}├${NC} RATE_LIMIT_RATE      = ${BOLD}${RATE_LIMIT_RATE:-25}${NC}"
    echo -e "  ${CYAN}├${NC} RATE_LIMIT_BURST     = ${BOLD}${RATE_LIMIT_BURST:-100}${NC}"
    echo -e "  ${CYAN}├${NC} CONN_LIMIT_PER_IP    = ${BOLD}${CONN_LIMIT_PER_IP:-50}${NC}"
    echo -e "  ${CYAN}└${NC} CONN_RATE_PER_IP     = ${BOLD}${CONN_RATE_PER_IP:-15}${NC}"

    echo ""
    echo -e "  ${BOLD}NETWORK FEATURES${NC}"
    for key in ICMP_ENABLE MULTICAST_ENABLE SMTP_ENABLE NAT_ENABLE LOG_DROPPED; do
        local val="${!key:-}"
        [[ "$val" == "true" ]] && _bool_color="${GREEN}" || _bool_color="${RED}"
        printf "  ${CYAN}├${NC} %-22s = ${_bool_color}${BOLD}%s${NC}\n" "$key" "$val"
    done
    if [[ "${NAT_ENABLE:-false}" == "true" ]]; then
        echo -e "  ${CYAN}├${NC} NAT_EXTERNAL_IFACE  = ${BOLD}${NAT_EXTERNAL_IFACE:-}${NC}"
        echo -e "  ${CYAN}└${NC} NAT_INTERNAL_IFACE  = ${BOLD}${NAT_INTERNAL_IFACE:-}${NC}"
    fi

    if [[ -n "${PORT_IP_RULES:-}" ]]; then
        echo ""
        echo -e "  ${BOLD}PORT-IP RULES${NC}"
        local IFS_OLD="$IFS"
        IFS=$'\n'
        for rule in $PORT_IP_RULES; do
            IFS="$IFS_OLD"
            echo -e "  ${CYAN}├${NC} $rule"
            IFS=$'\n'
        done
        IFS="$IFS_OLD"
    fi

    if [[ -n "${PORT_FORWARD_RULES:-}" ]]; then
        echo ""
        echo -e "  ${BOLD}PORT FORWARDING${NC}"
        local IFS_OLD="$IFS"
        IFS=$'\n'
        for rule in $PORT_FORWARD_RULES; do
            IFS="$IFS_OLD"
            echo -e "  ${CYAN}├${NC} $rule"
            IFS=$'\n'
        done
        IFS="$IFS_OLD"
    fi

    if [[ -n "${CUSTOM_RULES_FILE:-}" ]]; then
        echo ""
        echo -e "  ${BOLD}CUSTOM RULES${NC}"
        echo -e "  ${CYAN}└${NC} ${CUSTOM_RULES_FILE}"
    fi
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
    # shellcheck source=/dev/null
    source "$CONFIG_FILE"
    echo "${!key:-}"
}

fw_config_set() {
    local key="${1:-}"
    local value="${2:-}"
    if [[ -z "$key" ]]; then
        log_error "Usage: binadit-firewall config set KEY VALUE"
        exit 1
    fi
    if ! _config_key_valid "$key"; then
        log_error "Unknown config key: $key"
        exit 1
    fi
    require_root
    _ensure_config

    # Escape special sed characters in value
    local escaped_value
    escaped_value=$(printf '%s' "$value" | sed 's/[&/\]/\\&/g')

    if grep -q "^${key}=" "$CONFIG_FILE"; then
        sed -i "s/^${key}=.*/${key}=\"${escaped_value}\"/" "$CONFIG_FILE"
    else
        echo "${key}=\"${value}\"" >> "$CONFIG_FILE"
    fi

    log_success "${key} = \"${value}\""
    log_info "Run ${BOLD}binadit-firewall configtest${NC} to validate, then ${BOLD}binadit-firewall restart${NC} to apply"
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

    # shellcheck source=/dev/null
    source "$CONFIG_FILE"
    local current="${!key:-}"

    # Check if already present
    if [[ " $current " == *" $value "* ]]; then
        log_warn "$value is already in $key"
        return 0
    fi

    local new_value="${current:+$current }$value"
    local escaped_value
    escaped_value=$(printf '%s' "$new_value" | sed 's/[&/\]/\\&/g')
    sed -i "s/^${key}=.*/${key}=\"${escaped_value}\"/" "$CONFIG_FILE"

    log_success "Added $value to $key"
    log_info "${key} = \"${new_value}\""
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

    # shellcheck source=/dev/null
    source "$CONFIG_FILE"
    local current="${!key:-}"

    if [[ " $current " != *" $value "* ]]; then
        log_warn "$value is not in $key"
        return 0
    fi

    # Remove the value (handle leading/trailing/double spaces)
    local new_value
    new_value=$(echo " $current " | sed "s/ ${value} / /g" | xargs)
    local escaped_value
    escaped_value=$(printf '%s' "$new_value" | sed 's/[&/\]/\\&/g')
    sed -i "s/^${key}=.*/${key}=\"${escaped_value}\"/" "$CONFIG_FILE"

    log_success "Removed $value from $key"
    log_info "${key} = \"${new_value}\""
}

# =============================================================================
# Self-update from GitHub
# =============================================================================

REPO_URL="https://github.com/ronaldjonkers/binadit-firewall"
REPO_RAW="https://raw.githubusercontent.com/ronaldjonkers/binadit-firewall/master"

fw_update() {
    require_root

    show_banner
    log_header "Checking for updates"

    # Determine download tool
    local fetch
    if command -v curl &>/dev/null; then
        fetch="curl -fsSL"
    elif command -v wget &>/dev/null; then
        fetch="wget -qO-"
    else
        log_error "curl or wget is required for updates"
        exit 1
    fi

    # Get remote version
    local remote_version
    remote_version=$($fetch "${REPO_RAW}/src/lib/common.sh" 2>/dev/null | grep 'BINADIT_VERSION=' | head -1 | sed 's/.*"\([0-9.]*\)".*/\1/') || true

    if [[ -z "$remote_version" ]]; then
        log_error "Could not check remote version. Check your internet connection."
        exit 1
    fi

    log_info "Installed version: ${BOLD}v${BINADIT_VERSION}${NC}"
    log_info "Latest version:    ${BOLD}v${remote_version}${NC}"

    if [[ "$BINADIT_VERSION" == "$remote_version" ]]; then
        log_success "Already up to date!"
        return 0
    fi

    log_info "Update available: ${BOLD}v${BINADIT_VERSION}${NC} → ${BOLD}v${remote_version}${NC}"

    # Unless called with --yes, ask for confirmation
    if [[ "${1:-}" != "--yes" && "${1:-}" != "-y" ]]; then
        echo ""
        read -rp "  Install update? [Y/n]: " do_update
        if [[ "${do_update,,}" == "n" ]]; then
            log_info "Update cancelled"
            return 0
        fi
    fi

    # Download and install
    local tmpdir
    tmpdir=$(mktemp -d /tmp/binadit-firewall-update.XXXXXX)
    trap "rm -rf '$tmpdir'" RETURN

    log_info "Downloading v${remote_version}..."

    if command -v tar &>/dev/null; then
        $fetch "${REPO_URL}/archive/refs/heads/master.tar.gz" | tar -xz -C "$tmpdir"
        mv "$tmpdir"/binadit-firewall-* "$tmpdir/binadit-firewall"
    elif command -v git &>/dev/null; then
        git clone --depth 1 "${REPO_URL}.git" "$tmpdir/binadit-firewall" 2>/dev/null
    else
        log_error "tar or git is required for updates"
        exit 1
    fi

    local update_src="$tmpdir/binadit-firewall"

    # Update program files (preserve config)
    log_info "Installing update..."
    cp -r "${update_src}/src/"* /usr/local/share/binadit-firewall/
    cp "${update_src}/config/firewall.conf.example" "${CONFIG_DIR}/firewall.conf.example"
    chmod 755 /usr/local/share/binadit-firewall/binadit-firewall.sh
    chmod 644 /usr/local/share/binadit-firewall/lib/*.sh

    # Update systemd service if present
    if [[ -f /etc/systemd/system/binadit-firewall.service ]]; then
        cp "${update_src}/config/binadit-firewall.service" /etc/systemd/system/binadit-firewall.service
        systemctl daemon-reload 2>/dev/null || true
    fi

    echo ""
    log_success "Updated to v${remote_version}"
    log_info "Configuration preserved: ${CONFIG_FILE}"
    log_info "Run ${BOLD}binadit-firewall restart${NC} to apply with the new version"
}

# =============================================================================
# Auto-update cronjob management
# =============================================================================

CRON_SCRIPT="/etc/cron.weekly/binadit-firewall-update"

fw_auto_update() {
    local action="${1:-}"

    case "$action" in
        on|enable)
            require_root
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
            log_success "Weekly auto-update enabled"
            log_info "Cron script: ${CRON_SCRIPT}"
            log_info "Update log:  /var/log/binadit-firewall-update.log"
            log_info "Disable with: ${BOLD}binadit-firewall auto-update off${NC}"
            ;;
        off|disable)
            require_root
            if [[ -f "$CRON_SCRIPT" ]]; then
                rm -f "$CRON_SCRIPT"
                log_success "Auto-update disabled"
            else
                log_info "Auto-update was not enabled"
            fi
            ;;
        status)
            if [[ -f "$CRON_SCRIPT" ]]; then
                log_success "Auto-update is ${GREEN}${BOLD}enabled${NC}"
                log_info "Cron script: ${CRON_SCRIPT}"
                if [[ -f /var/log/binadit-firewall-update.log ]]; then
                    echo ""
                    echo -e "  ${BOLD}Last update log entries:${NC}"
                    tail -5 /var/log/binadit-firewall-update.log 2>/dev/null | while IFS= read -r line; do
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
            echo -e "  ${GREEN}on${NC}      Enable weekly automatic updates via cron"
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
      ${GREEN}restart${NC}             Stop and start the firewall
      ${GREEN}reload${NC}              Reload configuration (same as start)
      ${GREEN}status${NC}              Show current firewall rules and summary

  ${BOLD}CONFIGURATION:${NC}
      ${GREEN}config show${NC}         Show all current settings
      ${GREEN}config get${NC} KEY      Get a setting value
      ${GREEN}config set${NC} KEY VAL  Set a setting value
      ${GREEN}config add${NC} KEY VAL  Add value to a list setting
      ${GREEN}config remove${NC} K V   Remove value from a list setting
      ${GREEN}configtest${NC}          Validate config without applying
      ${GREEN}setup${NC}               Interactive setup wizard
      ${GREEN}features${NC}            Show all features with detailed explanations

  ${BOLD}UPDATES:${NC}
      ${GREEN}update${NC}              Download and install latest version
      ${GREEN}auto-update${NC} on|off  Enable/disable weekly auto-updates
      ${GREEN}upgrade${NC}             Upgrade from v1.x or older v2.x

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
      binadit-firewall restart                       # Apply changes
      binadit-firewall update                        # Get latest version
      binadit-firewall auto-update on                # Enable weekly updates
      binadit-firewall features                      # Full feature docs

EOF
}

# =============================================================================
# Main entry point
# =============================================================================

case "${1:-help}" in
    start)
        fw_start
        ;;
    stop)
        fw_stop
        ;;
    restart)
        fw_stop
        fw_start
        ;;
    reload)
        fw_reload
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
    auto-update)
        shift
        fw_auto_update "$@"
        ;;
    upgrade)
        fw_upgrade
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
        log_success "Backup created in /etc/binadit-firewall/backups/"
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
