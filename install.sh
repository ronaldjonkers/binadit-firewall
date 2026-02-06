#!/usr/bin/env bash
# =============================================================================
# binadit-firewall v2.0.0 - Installer
# =============================================================================
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

    # Install systemd service (if systemd is available)
    if command -v systemctl &>/dev/null; then
        cp "${INSTALLER_DIR}/config/binadit-firewall.service" "${SYSTEMD_DIR}/binadit-firewall.service"
        systemctl daemon-reload
        systemctl enable binadit-firewall.service
        log_success "Systemd service installed and enabled"
    else
        # Fallback: install as init.d script for older systems
        log_warn "systemd not found - creating init.d wrapper"
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
        log_success "Init.d service installed"
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

    # Remove files
    rm -f "$SBIN_LINK"
    rm -rf "$INSTALL_DIR"

    log_success "binadit-firewall uninstalled"
    log_info "Configuration preserved in: $CONFIG_DIR"
    log_info "To remove config: rm -rf $CONFIG_DIR"
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

    if [[ "$action" == "uninstall" ]]; then
        uninstall
        exit 0
    fi

    require_root

    echo ""
    echo -e "${BOLD}${CYAN}"
    echo "  ╔══════════════════════════════════════════════╗"
    echo "  ║         binadit-firewall v${BINADIT_VERSION}            ║"
    echo "  ║       Simple Linux Firewall Manager          ║"
    echo "  ╚══════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo ""

    local distro distro_family
    distro=$(detect_distro)
    distro_family=$(detect_distro_family)
    log_info "Detected OS: ${BOLD}${distro}${NC} (family: ${distro_family})"

    # Step 1: Disable competing firewalls
    disable_competing_firewalls

    # Step 2: Install dependencies
    install_dependencies

    # Step 3: Migrate old config if present
    migrate_old_config

    # Step 4: Install files
    install_files

    # Step 5: Setup configuration
    if [[ ! -f "${CONFIG_DIR}/firewall.conf" ]]; then
        if [[ "$NON_INTERACTIVE" == "true" ]]; then
            # Non-interactive: use example config with sensible defaults
            cp "${CONFIG_DIR}/firewall.conf.example" "${CONFIG_DIR}/firewall.conf"
            log_info "Default configuration installed"
        else
            # Interactive setup wizard
            echo ""
            read -rp "Run interactive setup wizard? [Y/n]: " run_wizard
            if [[ "${run_wizard,,}" != "n" ]]; then
                "$SBIN_LINK" setup
            else
                cp "${CONFIG_DIR}/firewall.conf.example" "${CONFIG_DIR}/firewall.conf"
                log_info "Default configuration installed"
                log_info "Edit config: nano ${CONFIG_DIR}/firewall.conf"
            fi
        fi
    else
        log_info "Existing configuration preserved: ${CONFIG_DIR}/firewall.conf"
    fi

    # Step 6: Start firewall
    echo ""
    if [[ "$NON_INTERACTIVE" == "true" ]]; then
        "$SBIN_LINK" start
    else
        read -rp "Start firewall now? [Y/n]: " start_now
        if [[ "${start_now,,}" != "n" ]]; then
            "$SBIN_LINK" start
        fi
    fi

    # Done
    echo ""
    log_header "Installation Complete"
    echo -e "  ${BOLD}Commands:${NC}"
    echo -e "    binadit-firewall start     ${GREEN}# Apply firewall rules${NC}"
    echo -e "    binadit-firewall stop      ${GREEN}# Disable firewall${NC}"
    echo -e "    binadit-firewall restart   ${GREEN}# Restart firewall${NC}"
    echo -e "    binadit-firewall status    ${GREEN}# Show active rules${NC}"
    echo -e "    binadit-firewall setup     ${GREEN}# Run setup wizard${NC}"
    echo ""
    echo -e "  ${BOLD}Configuration:${NC}"
    echo -e "    ${CONFIG_DIR}/firewall.conf"
    echo ""
    echo -e "  ${BOLD}Service:${NC}"
    echo -e "    systemctl status binadit-firewall"
    echo ""
}

main "$@"
