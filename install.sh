#!/usr/bin/env bash
# =============================================================================
# binadit-firewall v2.1.2 - Installer
# =============================================================================
# Copyright (C) 2013-2026 Ronald Jonkers — Binadit BV (binadit.com)
# License: GPL-2.0
#
# Universal installer for Linux systems.
# Supports: Debian/Ubuntu, CentOS/RHEL/Rocky/Alma, Fedora, Arch, Alpine, SUSE
#
# Features:
#   - Detects and disables competing firewalls (firewalld, ufw, iptables-services)
#   - Installs required dependencies (nftables or iptables)
#   - Sets up systemd service for boot persistence
#   - Interactive setup wizard for common port configurations
#   - Idempotent: safe to run multiple times
#
# Usage: sudo bash install.sh [--uninstall] [--non-interactive]
# =============================================================================

set -euo pipefail

# Script directory
INSTALLER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Installation paths
INSTALL_DIR="/usr/local/share/binadit-firewall"
SBIN_LINK="/usr/local/sbin/binadit-firewall"
CONFIG_DIR="/etc/binadit-firewall"
SYSTEMD_DIR="/etc/systemd/system"
BACKUP_DIR="${CONFIG_DIR}/backups"

# Source common library for colors and logging
source "${INSTALLER_DIR}/src/lib/common.sh"
source "${INSTALLER_DIR}/src/lib/backend.sh"

# =============================================================================
# Helper functions
# =============================================================================

# Check if a systemd service exists and is active
service_is_active() {
    systemctl is-active "$1" &>/dev/null 2>&1
}

# Check if a systemd service exists
service_exists() {
    systemctl list-unit-files "$1.service" &>/dev/null 2>&1
}

# Disable and stop a service
disable_service() {
    local svc="$1"
    if service_exists "$svc"; then
        if service_is_active "$svc"; then
            log_info "Stopping $svc..."
            systemctl stop "$svc" 2>/dev/null || true
        fi
        log_info "Disabling $svc..."
        systemctl disable "$svc" 2>/dev/null || true
        systemctl mask "$svc" 2>/dev/null || true
        log_success "$svc disabled and masked"
    fi
}

# Detect package manager
detect_pkg_manager() {
    if command -v apt-get &>/dev/null; then
        echo "apt"
    elif command -v dnf &>/dev/null; then
        echo "dnf"
    elif command -v yum &>/dev/null; then
        echo "yum"
    elif command -v pacman &>/dev/null; then
        echo "pacman"
    elif command -v apk &>/dev/null; then
        echo "apk"
    elif command -v zypper &>/dev/null; then
        echo "zypper"
    else
        echo "unknown"
    fi
}

# Install a package
install_package() {
    local pkg="$1"
    local pkg_mgr
    pkg_mgr=$(detect_pkg_manager)

    log_info "Installing $pkg..."

    case "$pkg_mgr" in
        apt)
            DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg" ;;
        dnf)
            dnf install -y "$pkg" ;;
        yum)
            yum install -y "$pkg" ;;
        pacman)
            pacman -S --noconfirm "$pkg" ;;
        apk)
            apk add "$pkg" ;;
        zypper)
            zypper install -y "$pkg" ;;
        *)
            log_error "Unknown package manager. Please install '$pkg' manually."
            return 1 ;;
    esac
}

# Update package cache
update_pkg_cache() {
    local pkg_mgr
    pkg_mgr=$(detect_pkg_manager)

    case "$pkg_mgr" in
        apt)    apt-get update -qq ;;
        dnf)    dnf makecache -q 2>/dev/null || true ;;
        yum)    yum makecache -q 2>/dev/null || true ;;
        pacman) pacman -Sy --noconfirm ;;
        apk)    apk update ;;
        zypper) zypper refresh -q ;;
    esac
}

# =============================================================================
# Disable competing firewalls
# =============================================================================

disable_competing_firewalls() {
    log_header "Checking for competing firewalls"

    local found_competing=false

    # firewalld (RHEL/CentOS/Fedora default)
    if service_exists "firewalld"; then
        log_warn "Found firewalld - will disable"
        found_competing=true
        if [[ "$NON_INTERACTIVE" != "true" ]]; then
            read -rp "Disable firewalld? [Y/n]: " disable_fwd
            if [[ "${disable_fwd,,}" == "n" ]]; then
                log_error "Cannot install binadit-firewall while firewalld is active"
                exit 1
            fi
        fi
        disable_service "firewalld"
    fi

    # ufw (Ubuntu/Debian default)
    if command -v ufw &>/dev/null; then
        local ufw_status
        ufw_status=$(ufw status 2>/dev/null | head -1 || echo "inactive")
        if [[ "$ufw_status" == *"active"* ]]; then
            log_warn "Found ufw (active) - will disable"
            found_competing=true
            if [[ "$NON_INTERACTIVE" != "true" ]]; then
                read -rp "Disable ufw? [Y/n]: " disable_ufw
                if [[ "${disable_ufw,,}" == "n" ]]; then
                    log_error "Cannot install binadit-firewall while ufw is active"
                    exit 1
                fi
            fi
            ufw disable 2>/dev/null || true
            disable_service "ufw"
        fi
    fi

    # iptables-services (RHEL/CentOS)
    if service_exists "iptables"; then
        if service_is_active "iptables"; then
            log_warn "Found iptables service (active) - will disable"
            found_competing=true
            disable_service "iptables"
        fi
    fi
    if service_exists "ip6tables"; then
        disable_service "ip6tables"
    fi

    # nftables system service (we manage nftables ourselves)
    if service_exists "nftables"; then
        if service_is_active "nftables"; then
            log_warn "Found nftables service (active) - will disable (binadit-firewall manages nftables directly)"
            found_competing=true
            disable_service "nftables"
        fi
    fi

    if [[ "$found_competing" == "false" ]]; then
        log_success "No competing firewalls found"
    fi
}

# =============================================================================
# Service detection and interactive configuration
# =============================================================================

# Known port-to-service name mappings
declare -A PORT_SERVICE_NAMES=(
    [22]="SSH"
    [25]="SMTP"
    [53]="DNS"
    [80]="HTTP"
    [443]="HTTPS"
    [110]="POP3"
    [143]="IMAP"
    [465]="SMTPS"
    [587]="Mail Submission"
    [993]="IMAPS"
    [995]="POP3S"
    [3306]="MySQL"
    [5432]="PostgreSQL"
    [6379]="Redis"
    [8080]="HTTP Alt"
    [8443]="HTTPS Alt"
    [27017]="MongoDB"
    [9090]="Prometheus"
    [9100]="Node Exporter"
    [3000]="Grafana"
    [9200]="Elasticsearch"
    [5601]="Kibana"
    [8888]="HTTP Proxy"
    [2375]="Docker API"
    [2376]="Docker TLS"
    [6443]="Kubernetes API"
    [10250]="Kubelet"
    [51820]="WireGuard"
    [1194]="OpenVPN"
    [1723]="PPTP"
    [21]="FTP"
    [873]="rsync"
    [1433]="MSSQL"
    [5900]="VNC"
    [3389]="RDP"
    [11211]="Memcached"
    [5672]="RabbitMQ"
    [15672]="RabbitMQ Mgmt"
    [4369]="EPMD"
    [6660]="IRC"
    [8081]="HTTP Alt"
    [9092]="Kafka"
    [2181]="ZooKeeper"
    [8500]="Consul"
    [4443]="HTTPS Alt"
)

# Services that are safe to expose by default
SAFE_DEFAULT_PORTS="22 80 443 53"

# Detect running services by scanning listening ports
detect_running_services() {
    local -n _tcp_ports=$1
    local -n _udp_ports=$2
    local -n _tcp_procs=$3
    local -n _udp_procs=$4

    _tcp_ports=()
    _udp_ports=()
    _tcp_procs=()
    _udp_procs=()

    local ss_output

    # TCP listeners
    if command -v ss &>/dev/null; then
        ss_output=$(ss -tlnp 2>/dev/null | tail -n +2 || true)
    elif command -v netstat &>/dev/null; then
        ss_output=$(netstat -tlnp 2>/dev/null | tail -n +2 || true)
    else
        return 1
    fi

    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        local port proc_name

        # Extract port from Local Address column (format: *:port or 0.0.0.0:port or :::port)
        port=$(echo "$line" | awk '{print $4}' | rev | cut -d: -f1 | rev)
        # Extract process name
        proc_name=$(echo "$line" | grep -oP 'users:\(\("\K[^"]+' 2>/dev/null || \
                    echo "$line" | grep -oP '(?<=\/)[^ ]+' 2>/dev/null || \
                    echo "unknown")

        # Skip non-numeric ports and duplicates
        [[ ! "$port" =~ ^[0-9]+$ ]] && continue
        local already=false
        for existing in "${_tcp_ports[@]+"${_tcp_ports[@]}"}"; do
            [[ "$existing" == "$port" ]] && already=true && break
        done
        [[ "$already" == "true" ]] && continue

        _tcp_ports+=("$port")
        _tcp_procs+=("$proc_name")
    done <<< "$ss_output"

    # UDP listeners
    if command -v ss &>/dev/null; then
        ss_output=$(ss -ulnp 2>/dev/null | tail -n +2 || true)
    elif command -v netstat &>/dev/null; then
        ss_output=$(netstat -ulnp 2>/dev/null | tail -n +2 || true)
    fi

    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        local port proc_name

        port=$(echo "$line" | awk '{print $4}' | rev | cut -d: -f1 | rev)
        proc_name=$(echo "$line" | grep -oP 'users:\(\("\K[^"]+' 2>/dev/null || \
                    echo "$line" | grep -oP '(?<=\/)[^ ]+' 2>/dev/null || \
                    echo "unknown")

        [[ ! "$port" =~ ^[0-9]+$ ]] && continue
        local already=false
        for existing in "${_udp_ports[@]+"${_udp_ports[@]}"}"; do
            [[ "$existing" == "$port" ]] && already=true && break
        done
        [[ "$already" == "true" ]] && continue

        _udp_ports+=("$port")
        _udp_procs+=("$proc_name")
    done <<< "$ss_output"
}

# Get a friendly service name for a port
get_service_name() {
    local port="$1"
    local proc_name="${2:-}"

    if [[ -n "${PORT_SERVICE_NAMES[$port]+x}" ]]; then
        echo "${PORT_SERVICE_NAMES[$port]}"
    elif [[ -n "$proc_name" && "$proc_name" != "unknown" ]]; then
        echo "$proc_name"
    else
        echo "Port $port"
    fi
}

# Interactive service selection menu during install
service_selection_menu() {
    local config_file="$1"

    log_header "Detected Running Services"

    local tcp_ports=() udp_ports=() tcp_procs=() udp_procs=()
    if ! detect_running_services tcp_ports udp_ports tcp_procs udp_procs; then
        log_warn "Could not detect running services (ss/netstat not found)"
        return 1
    fi

    local total=$(( ${#tcp_ports[@]} + ${#udp_ports[@]} ))
    if [[ "$total" -eq 0 ]]; then
        log_info "No listening services detected"
        return 0
    fi

    # Build the menu items: index, proto, port, process, service_name, enabled
    local -a menu_proto=() menu_port=() menu_proc=() menu_name=() menu_enabled=()
    local idx=0

    for i in "${!tcp_ports[@]}"; do
        local port="${tcp_ports[$i]}"
        local proc="${tcp_procs[$i]}"
        local name
        name=$(get_service_name "$port" "$proc")
        menu_proto+=("TCP")
        menu_port+=("$port")
        menu_proc+=("$proc")
        menu_name+=("$name")
        # Default: enable SSH, HTTP, HTTPS; disable others
        if [[ " $SAFE_DEFAULT_PORTS " == *" $port "* ]]; then
            menu_enabled+=("true")
        else
            menu_enabled+=("false")
        fi
        idx=$((idx + 1))
    done

    for i in "${!udp_ports[@]}"; do
        local port="${udp_ports[$i]}"
        local proc="${udp_procs[$i]}"
        local name
        name=$(get_service_name "$port" "$proc")
        menu_proto+=("UDP")
        menu_port+=("$port")
        menu_proc+=("$proc")
        menu_name+=("$name")
        if [[ " $SAFE_DEFAULT_PORTS " == *" $port "* ]]; then
            menu_enabled+=("true")
        else
            menu_enabled+=("false")
        fi
        idx=$((idx + 1))
    done

    # Sort by port number (build index array sorted by port)
    local -a sorted_indices
    sorted_indices=($(for i in "${!menu_port[@]}"; do echo "$i ${menu_port[$i]}"; done | sort -k2 -n | awk '{print $1}'))

    # Display function
    _display_menu() {
        echo ""
        echo -e "  ${BOLD}${CYAN}┌────┬──────────────────────┬────────┬───────┬──────────────────┐${NC}"
        echo -e "  ${BOLD}${CYAN}│${NC} ${BOLD} #  ${CYAN}│${NC} ${BOLD}Service              ${CYAN}│${NC} ${BOLD}Port   ${CYAN}│${NC} ${BOLD}Proto ${CYAN}│${NC} ${BOLD}Firewall         ${CYAN}│${NC}"
        echo -e "  ${BOLD}${CYAN}├────┼──────────────────────┼────────┼───────┼──────────────────┤${NC}"

        local display_num=1
        for si in "${sorted_indices[@]}"; do
            local name="${menu_name[$si]}"
            local port="${menu_port[$si]}"
            local proto="${menu_proto[$si]}"
            local enabled="${menu_enabled[$si]}"
            local proc="${menu_proc[$si]}"

            # Truncate name to 20 chars
            local display_name
            if [[ ${#name} -gt 20 ]]; then
                display_name="${name:0:17}..."
            else
                display_name="$name"
            fi

            # Format columns
            local status_text
            if [[ "$enabled" == "true" ]]; then
                status_text="${GREEN}✓ ALLOW${NC}"
            else
                status_text="${RED}✗ BLOCK${NC}"
            fi

            printf "  ${CYAN}│${NC} %-2s ${CYAN}│${NC} %-20s ${CYAN}│${NC} %-6s ${CYAN}│${NC} %-5s ${CYAN}│${NC} %b          ${CYAN}│${NC}\n" \
                "$display_num" "$display_name" "$port" "$proto" "$status_text"

            display_num=$((display_num + 1))
        done

        echo -e "  ${BOLD}${CYAN}└────┴──────────────────────┴────────┴───────┴──────────────────┘${NC}"
        echo ""
    }

    # Show menu and handle input
    while true; do
        _display_menu

        echo -e "  ${BOLD}Toggle:${NC} enter number(s) to toggle (e.g., ${BOLD}3 5${NC})"
        echo -e "  ${BOLD}Shortcuts:${NC} ${GREEN}a${NC}=allow all  ${RED}n${NC}=block all  ${BOLD}d${NC}=done"
        echo ""
        read -rp "  > " user_input

        # Handle shortcuts
        case "${user_input,,}" in
            d|done|"")
                break
                ;;
            a|all)
                for i in "${!menu_enabled[@]}"; do
                    menu_enabled[$i]="true"
                done
                continue
                ;;
            n|none)
                for i in "${!menu_enabled[@]}"; do
                    menu_enabled[$i]="false"
                done
                # Always keep SSH allowed
                for i in "${!menu_port[@]}"; do
                    if [[ "${menu_port[$i]}" == "22" ]]; then
                        menu_enabled[$i]="true"
                    fi
                done
                continue
                ;;
        esac

        # Toggle specific numbers
        for num in $user_input; do
            if [[ "$num" =~ ^[0-9]+$ ]] && (( num >= 1 && num <= ${#sorted_indices[@]} )); then
                local si="${sorted_indices[$((num - 1))]}"
                if [[ "${menu_enabled[$si]}" == "true" ]]; then
                    menu_enabled[$si]="false"
                else
                    menu_enabled[$si]="true"
                fi
            else
                log_warn "Invalid selection: $num"
            fi
        done
    done

    # Build port lists from selections
    local selected_tcp="" selected_udp=""
    for i in "${!menu_enabled[@]}"; do
        if [[ "${menu_enabled[$i]}" == "true" ]]; then
            local port="${menu_port[$i]}"
            local proto="${menu_proto[$i]}"
            # Don't add SSH port to TCP_PORTS (it's handled separately)
            if [[ "$port" == "$(detect_ssh_port)" && "$proto" == "TCP" ]]; then
                continue
            fi
            if [[ "$proto" == "TCP" ]]; then
                selected_tcp="${selected_tcp:+$selected_tcp }$port"
            else
                selected_udp="${selected_udp:+$selected_udp }$port"
            fi
        fi
    done

    # Apply to config
    sed -i "s/^TCP_PORTS=.*/TCP_PORTS=\"${selected_tcp}\"/" "$config_file"
    sed -i "s/^UDP_PORTS=.*/UDP_PORTS=\"${selected_udp}\"/" "$config_file"

    echo ""
    log_success "Firewall configured based on service selection"
    if [[ -n "$selected_tcp" ]]; then
        log_info "TCP ports: ${BOLD}${selected_tcp}${NC}"
    fi
    if [[ -n "$selected_udp" ]]; then
        log_info "UDP ports: ${BOLD}${selected_udp}${NC}"
    fi
    log_info "SSH is always allowed (managed separately)"
}

# =============================================================================
# Install dependencies
# =============================================================================

install_dependencies() {
    log_header "Installing dependencies"

    local distro_family
    distro_family=$(detect_distro_family)

    # Update package cache
    log_info "Updating package cache..."
    update_pkg_cache

    # Ensure we have a firewall backend
    if ! command -v nft &>/dev/null && ! command -v iptables &>/dev/null; then
        log_info "No firewall backend found, installing..."

        case "$distro_family" in
            debian)
                install_package "nftables"
                install_package "iptables"  # Fallback
                ;;
            rhel)
                install_package "nftables"
                install_package "iptables-nft" 2>/dev/null || install_package "iptables" || true
                ;;
            arch)
                install_package "nftables"
                install_package "iptables-nft"
                ;;
            alpine)
                install_package "nftables"
                install_package "iptables"
                ;;
            suse)
                install_package "nftables"
                install_package "iptables"
                ;;
            *)
                log_warn "Unknown distro family. Attempting to install nftables..."
                install_package "nftables" || install_package "iptables" || true
                ;;
        esac
    fi

    # Ensure we have conntrack tools
    if ! command -v conntrack &>/dev/null; then
        case "$distro_family" in
            debian)  install_package "conntrack" 2>/dev/null || true ;;
            rhel)    install_package "conntrack-tools" 2>/dev/null || true ;;
            arch)    install_package "conntrack-tools" 2>/dev/null || true ;;
            alpine)  install_package "conntrack-tools" 2>/dev/null || true ;;
            suse)    install_package "conntrack-tools" 2>/dev/null || true ;;
        esac
    fi

    # Ensure we have dig for hostname resolution
    if ! command -v dig &>/dev/null; then
        case "$distro_family" in
            debian)  install_package "dnsutils" 2>/dev/null || true ;;
            rhel)    install_package "bind-utils" 2>/dev/null || true ;;
            arch)    install_package "bind" 2>/dev/null || true ;;
            alpine)  install_package "bind-tools" 2>/dev/null || true ;;
            suse)    install_package "bind-utils" 2>/dev/null || true ;;
        esac
    fi

    # Verify we have at least one backend
    if command -v nft &>/dev/null; then
        log_success "nftables available: $(nft --version 2>/dev/null || echo 'installed')"
    fi
    if command -v iptables &>/dev/null; then
        log_success "iptables available: $(iptables --version 2>/dev/null || echo 'installed')"
    fi

    if ! command -v nft &>/dev/null && ! command -v iptables &>/dev/null; then
        log_error "Failed to install any firewall backend"
        exit 1
    fi
}

# =============================================================================
# Detect existing installation (upgrade path: v1.x, v2.x → v3.x)
# =============================================================================

detect_existing_install() {
    if [[ -f "$SBIN_LINK" ]] || [[ -d "$INSTALL_DIR" ]]; then
        local installed_version="unknown"
        if [[ -f "$INSTALL_DIR/lib/common.sh" ]]; then
            installed_version=$(grep "BINADIT_VERSION=" "$INSTALL_DIR/lib/common.sh" 2>/dev/null | head -1 | sed 's/.*"\([0-9.]*\)".*/\1/' || echo "unknown")
        fi

        log_header "Existing Installation Detected"
        log_info "Installed version: ${BOLD}v${installed_version}${NC}"
        log_info "New version:       ${BOLD}v${BINADIT_VERSION}${NC}"

        if [[ -f "${CONFIG_DIR}/firewall.conf" ]]; then
            log_success "Existing configuration found - will be ${BOLD}preserved${NC}"
        fi

        if [[ "$NON_INTERACTIVE" != "true" ]]; then
            echo ""
            read -rp "  Upgrade to v${BINADIT_VERSION}? [Y/n]: " do_upgrade
            if [[ "${do_upgrade,,}" == "n" ]]; then
                log_info "Upgrade cancelled"
                exit 0
            fi
        fi

        log_info "Upgrading binadit-firewall (config preserved)..."
    fi
}

# =============================================================================
# Install binadit-firewall files
# =============================================================================

install_files() {
    log_header "Installing binadit-firewall"

    # Create directories
    mkdir -p "$INSTALL_DIR"
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$BACKUP_DIR"

    # Copy source files
    log_info "Copying files to $INSTALL_DIR..."
    cp -r "${INSTALLER_DIR}/src/"* "$INSTALL_DIR/"

    # Set permissions
    chmod 755 "$INSTALL_DIR/binadit-firewall.sh"
    chmod 644 "$INSTALL_DIR/lib/"*.sh

    # Create symlink for easy access
    ln -sf "$INSTALL_DIR/binadit-firewall.sh" "$SBIN_LINK"
    log_success "Command available: binadit-firewall"

    # Copy example config
    cp "${INSTALLER_DIR}/config/firewall.conf.example" "${CONFIG_DIR}/firewall.conf.example"
    log_success "Example config: ${CONFIG_DIR}/firewall.conf.example"

    # Install service for boot persistence
    if command -v systemctl &>/dev/null; then
        # systemd (Debian 8+, Ubuntu 15+, CentOS 7+, Fedora 15+, Arch, SUSE 12+)
        cp "${INSTALLER_DIR}/config/binadit-firewall.service" "${SYSTEMD_DIR}/binadit-firewall.service"
        systemctl daemon-reload
        systemctl enable binadit-firewall.service
        log_success "Systemd service installed and enabled"
    elif command -v rc-service &>/dev/null; then
        # OpenRC (Alpine Linux, Gentoo)
        log_info "OpenRC detected - installing OpenRC service"
        cat > /etc/init.d/binadit-firewall <<'OPENRC_EOF'
#!/sbin/openrc-run
# binadit-firewall OpenRC service

description="binadit-firewall - Simple Linux Firewall Manager"

depend() {
    need net
    before firewall
    after networking
}

start() {
    ebegin "Starting binadit-firewall"
    /usr/local/sbin/binadit-firewall start
    eend $?
}

stop() {
    ebegin "Stopping binadit-firewall"
    /usr/local/sbin/binadit-firewall stop
    eend $?
}

restart() {
    ebegin "Restarting binadit-firewall"
    /usr/local/sbin/binadit-firewall restart
    eend $?
}

status() {
    /usr/local/sbin/binadit-firewall status
}
OPENRC_EOF
        chmod 755 /etc/init.d/binadit-firewall
        rc-update add binadit-firewall default 2>/dev/null || true
        log_success "OpenRC service installed and enabled"
    else
        # SysVinit fallback (CentOS 6, Debian 7, older systems)
        log_info "No systemd/OpenRC found - installing SysVinit script"
        cat > /etc/init.d/binadit-firewall <<'INITEOF'
#!/bin/bash
### BEGIN INIT INFO
# Provides:          binadit-firewall
# Required-Start:    $network $local_fs
# Required-Stop:     $network $local_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: binadit-firewall
# Description:       Simple Linux Firewall Manager
### END INIT INFO
exec /usr/local/sbin/binadit-firewall "$@"
INITEOF
        chmod 755 /etc/init.d/binadit-firewall

        # Enable on boot
        if command -v update-rc.d &>/dev/null; then
            update-rc.d binadit-firewall defaults
        elif command -v chkconfig &>/dev/null; then
            chkconfig binadit-firewall on
        fi
        log_success "SysVinit service installed"
    fi
}

# =============================================================================
# Migrate from old binadit-firewall
# =============================================================================

migrate_old_config() {
    local old_config="/etc/firewall.d/host.conf"

    if [[ ! -f "$old_config" ]]; then
        return 0
    fi

    log_header "Migrating from old binadit-firewall"
    log_info "Found old config: $old_config"

    # Source old config
    # shellcheck source=/dev/null
    source "$old_config"

    # Create new config from example
    cp "${CONFIG_DIR}/firewall.conf.example" "${CONFIG_DIR}/firewall.conf"

    # Migrate values
    local new_conf="${CONFIG_DIR}/firewall.conf"

    [[ -n "${TCPPORTS:-}" ]] && \
        sed -i "s/^TCP_PORTS=.*/TCP_PORTS=\"${TCPPORTS}\"/" "$new_conf"
    [[ -n "${TCPPORTS_INPUT:-}" ]] && \
        sed -i "s/^TCP_PORTS_INPUT=.*/TCP_PORTS_INPUT=\"${TCPPORTS_INPUT}\"/" "$new_conf"
    [[ -n "${TCPPORTS_OUTPUT:-}" ]] && \
        sed -i "s/^TCP_PORTS_OUTPUT=.*/TCP_PORTS_OUTPUT=\"${TCPPORTS_OUTPUT}\"/" "$new_conf"
    [[ -n "${UDPPORTS:-}" ]] && \
        sed -i "s/^UDP_PORTS=.*/UDP_PORTS=\"${UDPPORTS}\"/" "$new_conf"
    [[ -n "${DMZS:-}" ]] && \
        sed -i "s/^TRUSTED_IPS=.*/TRUSTED_IPS=\"${DMZS}\"/" "$new_conf"
    [[ -n "${SSHACCESS:-}" ]] && \
        sed -i "s/^SSH_ALLOWED_IPS=.*/SSH_ALLOWED_IPS=\"${SSHACCESS}\"/" "$new_conf"
    [[ -n "${SSHACCESS_IPv6:-}" ]] && \
        sed -i "s/^SSH_ALLOWED_IPS_IPV6=.*/SSH_ALLOWED_IPS_IPV6=\"${SSHACCESS_IPv6}\"/" "$new_conf"
    [[ -n "${DMZRANGE:-}" ]] && \
        sed -i "s/^TRUSTED_RANGES=.*/TRUSTED_RANGES=\"${DMZRANGE}\"/" "$new_conf"
    [[ -n "${BLACKLIST:-}" ]] && \
        sed -i "s/^BLACKLIST=.*/BLACKLIST=\"${BLACKLIST}\"/" "$new_conf"
    [[ -n "${BLOCKRANGE:-}" ]] && \
        sed -i "s/^BLOCKED_RANGES=.*/BLOCKED_RANGES=\"${BLOCKRANGE}\"/" "$new_conf"
    [[ -n "${DMZS_IPv6:-}" ]] && \
        sed -i "s/^TRUSTED_IPS_IPV6=.*/TRUSTED_IPS_IPV6=\"${DMZS_IPv6}\"/" "$new_conf"
    [[ -n "${BLACKLIST_IPv6:-}" ]] && \
        sed -i "s/^BLACKLIST_IPV6=.*/BLACKLIST_IPV6=\"${BLACKLIST_IPv6}\"/" "$new_conf"

    if [[ "${MULTICAST_ENABLE:-}" == "TRUE" ]]; then
        sed -i 's/^MULTICAST_ENABLE=.*/MULTICAST_ENABLE="true"/' "$new_conf"
    fi
    if [[ "${NATROUTER_ENABLE:-}" == "TRUE" ]]; then
        sed -i 's/^NAT_ENABLE=.*/NAT_ENABLE="true"/' "$new_conf"
    fi

    # Backup old config
    mv "$old_config" "${old_config}.migrated.$(date +%Y%m%d)"
    log_success "Old config migrated to: $new_conf"
    log_info "Old config backed up to: ${old_config}.migrated.*"

    # Remove old init.d script if present
    if [[ -f /etc/init.d/firewall ]]; then
        mv /etc/init.d/firewall /etc/init.d/firewall.old.bak
        log_info "Old /etc/init.d/firewall backed up"
    fi
}

# =============================================================================
# Uninstall
# =============================================================================

uninstall() {
    require_root

    log_header "Uninstalling binadit-firewall"

    # Stop and disable service
    if command -v systemctl &>/dev/null; then
        systemctl stop binadit-firewall 2>/dev/null || true
        systemctl disable binadit-firewall 2>/dev/null || true
        rm -f "${SYSTEMD_DIR}/binadit-firewall.service"
        systemctl daemon-reload
    fi

    # Remove init.d script
    rm -f /etc/init.d/binadit-firewall

    # Flush rules
    "${SBIN_LINK}" stop 2>/dev/null || true

    # Remove MOTD login status indicator
    rm -f /etc/profile.d/binadit-firewall-status.sh
    log_info "Removed login status indicator"

    # Remove prompt indicator (🟢/🔴)
    rm -f /etc/profile.d/binadit-firewall-prompt.sh
    log_info "Removed prompt indicator"

    # Remove auto-update cron job
    rm -f /etc/cron.weekly/binadit-firewall-update
    log_info "Removed auto-update cron job"

    # Remove program files
    rm -f "$SBIN_LINK"
    rm -rf "$INSTALL_DIR"

    log_success "binadit-firewall uninstalled"

    # Ask about config removal
    if [[ -d "$CONFIG_DIR" ]]; then
        if [[ "$NON_INTERACTIVE" == "true" ]]; then
            log_info "Configuration preserved in: $CONFIG_DIR"
            log_info "To remove config: rm -rf $CONFIG_DIR"
        else
            echo ""
            read -rp "  Remove configuration ($CONFIG_DIR)? [y/N]: " remove_config
            if [[ "${remove_config,,}" == "y" ]]; then
                rm -rf "$CONFIG_DIR"
                log_success "Configuration removed"
            else
                log_info "Configuration preserved in: $CONFIG_DIR"
            fi
        fi
    fi
}

# =============================================================================
# Main installer
# =============================================================================

main() {
    # Parse arguments
    NON_INTERACTIVE="false"
    local action="install"

    for arg in "$@"; do
        case "$arg" in
            --uninstall|uninstall)
                action="uninstall" ;;
            --non-interactive|-y)
                NON_INTERACTIVE="true" ;;
            --help|-h)
                echo "Usage: sudo bash install.sh [--uninstall] [--non-interactive]"
                exit 0 ;;
        esac
    done

    # Auto-detect non-interactive mode
    # When piped via get.sh, stdin is redirected from /dev/tty so -t 0 will be true.
    # Only force non-interactive if there is truly no terminal available.
    if [[ ! -t 0 ]] && [[ ! -e /dev/tty ]]; then
        NON_INTERACTIVE="true"
    fi

    if [[ "$action" == "uninstall" ]]; then
        uninstall
        exit 0
    fi

    require_root

    show_banner

    local distro distro_family
    distro=$(detect_distro)
    distro_family=$(detect_distro_family)
    log_info "Detected OS: ${BOLD}${distro}${NC} (family: ${distro_family})"

    # Step 0: Check for existing v2.x installation (upgrade path)
    detect_existing_install

    # Step 1: Disable competing firewalls
    disable_competing_firewalls

    # Step 2: Install dependencies
    install_dependencies

    # Step 3: Migrate old config if present
    migrate_old_config

    # Step 4: Install files
    install_files

    # Step 5: Setup configuration
    local run_service_detection=false

    if [[ ! -f "${CONFIG_DIR}/firewall.conf" ]]; then
        # Fresh install: start with example config
        cp "${CONFIG_DIR}/firewall.conf.example" "${CONFIG_DIR}/firewall.conf"
        log_info "Default configuration installed"
        run_service_detection=true
    else
        # Re-install: offer to reconfigure
        log_info "Existing configuration found: ${CONFIG_DIR}/firewall.conf"
        if [[ "$NON_INTERACTIVE" != "true" ]]; then
            echo ""
            read -rp "  Configure firewall ports based on detected services? [Y/n]: " reconfig
            if [[ "${reconfig,,}" != "n" ]]; then
                run_service_detection=true
            fi
        fi
    fi

    if [[ "$run_service_detection" == "true" && "$NON_INTERACTIVE" != "true" ]]; then
        # Detect running services and offer interactive selection
        service_selection_menu "${CONFIG_DIR}/firewall.conf" || true

        # Offer SSH restriction
        local ssh_port
        ssh_port=$(detect_ssh_port)
        echo ""
        read -rp "  Restrict SSH ($ssh_port) to specific IPs? [y/N]: " restrict_ssh
        if [[ "${restrict_ssh,,}" == "y" ]]; then
            read -rp "  Enter allowed SSH IPs (space-separated): " ssh_ips
            if [[ -n "$ssh_ips" ]]; then
                sed -i "s/^SSH_ALLOWED_IPS=.*/SSH_ALLOWED_IPS=\"${ssh_ips}\"/" "${CONFIG_DIR}/firewall.conf"
                log_success "SSH restricted to: $ssh_ips"
            fi
        fi

        # Allow ping?
        echo ""
        read -rp "  Allow ping (ICMP)? [Y/n]: " allow_ping
        if [[ "${allow_ping,,}" == "n" ]]; then
            sed -i "s/^ICMP_ENABLE=.*/ICMP_ENABLE=\"false\"/" "${CONFIG_DIR}/firewall.conf"
        fi

        echo ""
        log_success "Configuration saved: ${CONFIG_DIR}/firewall.conf"
        log_info "Edit anytime: nano ${CONFIG_DIR}/firewall.conf"
        log_info "Or use: binadit-firewall config show"
    fi

    # Step 6: Start firewall
    echo ""
    log_header "Starting firewall"
    "$SBIN_LINK" start || log_warn "Firewall start failed — run 'binadit-firewall start' manually"

    # Done
    echo ""
    echo -e "${GREEN}${BOLD}"
    cat <<'COMPLETE'
    ╔═══════════════════════════════════════════════════════════════════════════╗
    ║                                                                           ║
    ║                         ✅  INSTALLATION COMPLETE                          ║
    ║                                                                           ║
    ╚═══════════════════════════════════════════════════════════════════════════╝
COMPLETE
    echo -e "${NC}"
    # Offer weekly auto-updates
    if [[ "$NON_INTERACTIVE" != "true" ]]; then
        echo ""
        read -rp "  Enable weekly automatic updates? [Y/n]: " enable_autoupdate
        if [[ "${enable_autoupdate,,}" != "n" ]]; then
            # Write cron script directly (don't rely on freshly installed binary)
            local cron_script="/etc/cron.weekly/binadit-firewall-update"
            if [[ -d /etc/cron.weekly ]]; then
                cat > "$cron_script" <<'CRONEOF'
#!/bin/bash
# binadit-firewall weekly auto-update
# Installed by: binadit-firewall installer
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
                chmod 755 "$cron_script"
                log_success "Weekly auto-update enabled"
                log_info "Cron script: ${cron_script}"
                log_info "Disable with: ${BOLD}binadit-firewall auto-update off${NC}"
            else
                # No /etc/cron.weekly — try via binadit-firewall command
                "$SBIN_LINK" auto-update on 2>/dev/null || log_warn "Could not enable auto-update (no /etc/cron.weekly/)"
            fi
        fi
    fi

    # Offer MOTD login banner
    if [[ "$NON_INTERACTIVE" != "true" ]]; then
        echo ""
        read -rp "  Show firewall status on every login (motd)? [Y/n]: " install_motd
        if [[ "${install_motd,,}" != "n" ]]; then
            "$SBIN_LINK" motd-on 2>/dev/null || log_warn "Could not install MOTD script"
        fi
    fi

    # Offer prompt indicator (🟢/🔴)
    if [[ "$NON_INTERACTIVE" != "true" ]]; then
        echo ""
        read -rp "  Show 🟢/🔴 firewall status emoji in your prompt? [Y/n]: " install_prompt
        if [[ "${install_prompt,,}" != "n" ]]; then
            "$SBIN_LINK" prompt-on 2>/dev/null || log_warn "Could not install prompt indicator"
        fi
    fi

    echo ""
    echo -e "  ${BOLD}Commands:${NC}"
    echo -e "    binadit-firewall start        ${GREEN}# Apply firewall rules${NC}"
    echo -e "    binadit-firewall stop         ${GREEN}# Disable firewall${NC}"
    echo -e "    binadit-firewall status       ${GREEN}# Show active rules & summary${NC}"
    echo -e "    binadit-firewall config show  ${GREEN}# View all settings${NC}"
    echo -e "    binadit-firewall config set   ${GREEN}# Change a setting via CLI${NC}"
    echo -e "    binadit-firewall configtest   ${GREEN}# Validate config${NC}"
    echo -e "    binadit-firewall update       ${GREEN}# Download latest version${NC}"
    echo -e "    binadit-firewall features     ${GREEN}# Full feature documentation${NC}"
    echo -e "    binadit-firewall help         ${GREEN}# All commands${NC}"
    echo ""
    echo -e "  ${BOLD}Configuration:${NC}"
    echo -e "    ${CONFIG_DIR}/firewall.conf"
    echo ""
    echo -e "  ${BOLD}Service management:${NC}"
    if command -v systemctl &>/dev/null; then
        echo -e "    systemctl status binadit-firewall"
        echo -e "    systemctl restart binadit-firewall"
    elif command -v rc-service &>/dev/null; then
        echo -e "    rc-service binadit-firewall status"
    else
        echo -e "    service binadit-firewall status"
    fi
    echo ""
}

main "$@"
