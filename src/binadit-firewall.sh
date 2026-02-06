#!/usr/bin/env bash
# =============================================================================
# binadit-firewall v2.1.0
# =============================================================================
# A modern, easy-to-use Linux firewall manager with support for both
# nftables and iptables backends.
#
# Copyright (C) 2013-2026 Ronald Jonkers - binadit
# License: GPL-2.0
#
# Usage: binadit-firewall {start|stop|restart|status|reload|backup|upgrade|version}
# =============================================================================

set -euo pipefail

# Determine script directory for sourcing libraries
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
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

# Validate the configuration file exists and is readable
validate_config() {
    if [[ ! -f "$CONFIG_FILE" ]]; then
        log_error "Configuration file not found: $CONFIG_FILE"
        log_info "Run 'binadit-firewall setup' or copy the example config:"
        log_info "  cp ${CONFIG_DIR}/firewall.conf.example ${CONFIG_FILE}"
        exit 1
    fi

    if [[ ! -r "$CONFIG_FILE" ]]; then
        log_error "Configuration file not readable: $CONFIG_FILE"
        exit 1
    fi

    # Basic syntax check
    if ! bash -n "$CONFIG_FILE" 2>/dev/null; then
        log_error "Configuration file has syntax errors: $CONFIG_FILE"
        exit 1
    fi

    log_debug "Configuration validated: $CONFIG_FILE"
}

# Detect and use the appropriate backend
get_backend() {
    local backend
    backend=$(detect_backend)
    log_info "Using firewall backend: ${BOLD}${backend}${NC}"
    echo "$backend"
}

# Start the firewall
fw_start() {
    require_root
    validate_config

    show_banner

    local backend
    backend=$(get_backend)

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

# Show help
fw_help() {
    show_banner
    cat <<EOF
  ${BOLD}USAGE:${NC}
      binadit-firewall <command>

  ${BOLD}COMMANDS:${NC}
      ${GREEN}start${NC}       Apply firewall rules from configuration
      ${GREEN}stop${NC}        Remove all rules (allow all traffic)
      ${GREEN}restart${NC}     Stop and start the firewall
      ${GREEN}reload${NC}      Reload configuration (same as start)
      ${GREEN}status${NC}      Show current firewall rules and summary
      ${GREEN}setup${NC}       Interactive setup wizard
      ${GREEN}upgrade${NC}     Upgrade from v1.x or update v2.x in-place
      ${GREEN}backup${NC}      Create a backup of current rules
      ${GREEN}version${NC}     Show version and system info
      ${GREEN}help${NC}        Show this help message

  ${BOLD}CONFIGURATION:${NC}
      ${CONFIG_FILE}

  ${BOLD}EXAMPLES:${NC}
      binadit-firewall start          # Apply firewall rules
      binadit-firewall status         # View active rules and summary
      binadit-firewall setup          # Run setup wizard
      binadit-firewall upgrade        # Upgrade from older version

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
    setup)
        fw_setup
        ;;
    upgrade)
        fw_upgrade
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
