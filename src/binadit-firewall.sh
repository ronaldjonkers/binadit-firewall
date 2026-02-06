#!/usr/bin/env bash
# =============================================================================
# binadit-firewall v2.0.0
# =============================================================================
# A modern, easy-to-use Linux firewall manager with support for both
# nftables and iptables backends.
#
# Copyright (C) 2013-2026 Ronald Jonkers - binadit
# License: GPL-2.0
#
# Usage: binadit-firewall {start|stop|restart|status|reload|backup|version}
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

    log_header "Starting binadit-firewall v${BINADIT_VERSION}"

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

    log_success "binadit-firewall is active"
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

    log_success "binadit-firewall stopped - all traffic allowed"
}

# Show firewall status
fw_status() {
    local backend
    backend=$(detect_backend)

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
    echo -e "${BOLD}binadit-firewall${NC} v${BINADIT_VERSION}"
    echo "Backend: $(detect_backend)"
    echo "Config:  ${CONFIG_FILE}"
    echo "OS:      $(detect_distro) ($(detect_distro_family))"
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
    cat <<EOF

${BOLD}binadit-firewall${NC} v${BINADIT_VERSION} - Simple Linux Firewall Manager

${BOLD}USAGE:${NC}
    binadit-firewall <command>

${BOLD}COMMANDS:${NC}
    ${GREEN}start${NC}       Apply firewall rules from configuration
    ${GREEN}stop${NC}        Remove all rules (allow all traffic)
    ${GREEN}restart${NC}     Stop and start the firewall
    ${GREEN}reload${NC}      Reload configuration (same as start)
    ${GREEN}status${NC}      Show current firewall rules
    ${GREEN}setup${NC}       Interactive setup wizard
    ${GREEN}backup${NC}      Create a backup of current rules
    ${GREEN}version${NC}     Show version and system info
    ${GREEN}help${NC}        Show this help message

${BOLD}CONFIGURATION:${NC}
    ${CONFIG_FILE}

${BOLD}EXAMPLES:${NC}
    binadit-firewall start          # Apply firewall rules
    binadit-firewall status         # View active rules
    binadit-firewall setup          # Run setup wizard

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
