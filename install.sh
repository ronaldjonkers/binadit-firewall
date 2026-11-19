#!/usr/bin/env bash
# =============================================================================
# binadit-firewall v3.1.1 - Installer
# =============================================================================
# Copyright (C) 2013-2026 Ronald Jonkers — Binadit BV (binadit.com)
# License: GPL-2.0
#
# Universal installer for Linux systems.
# Supports: Debian/Ubuntu, CentOS/RHEL/Rocky/Alma, Fedora, Arch, Alpine, SUSE
#
# What it does, in this order:
#   1. Installs a firewall backend if none is present (nftables or iptables)
#   2. Installs the program files and the boot service
#   3. Creates the configuration (new installs) or keeps yours (upgrades)
#   4. Validates the configuration
#   5. Only then disables competing firewalls (firewalld, ufw, ...) and starts
#      binadit-firewall — the server is never left without a firewall
#
# Safe to run multiple times.
#
# Usage: sudo bash install.sh [--non-interactive] [--uninstall] [--update]
#   --non-interactive   never ask questions (use defaults, keep existing config)
#   --uninstall         remove binadit-firewall
#   --update            only replace program files (used by "binadit-firewall update")
# =============================================================================

set -euo pipefail

if (( BASH_VERSINFO[0] < 4 )); then
    echo "binadit-firewall requires bash 4 or newer" >&2
    exit 1
fi

# Script directory
INSTALLER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Installation paths
INSTALL_DIR="/usr/local/share/binadit-firewall"
SBIN_LINK="/usr/local/sbin/binadit-firewall"
SYSTEM_LINK="/usr/sbin/binadit-firewall"
CONFIG_DIR="/etc/binadit-firewall"
SYSTEMD_DIR="/etc/systemd/system"
BACKUP_DIR="${CONFIG_DIR}/backups"

NON_INTERACTIVE="false"

# Source common library for colors and logging
source "${INSTALLER_DIR}/src/lib/common.sh"
source "${INSTALLER_DIR}/src/lib/backend.sh"

# =============================================================================
# Helper functions
# =============================================================================

has_systemctl() {
    command -v systemctl &>/dev/null
}

systemd_running() {
    has_systemctl && [[ -d /run/systemd/system ]]
}

# Check if a systemd service is active
service_is_active() {
    has_systemctl && systemctl is-active "$1" &>/dev/null
}

# Check if a systemd unit file really exists
service_exists() {
    has_systemctl || return 1
    systemctl list-unit-files "$1.service" 2>/dev/null | grep -q "^$1\.service"
}

service_is_enabled() {
    has_systemctl && systemctl is-enabled "$1" &>/dev/null
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
            zypper --non-interactive install "$pkg" ;;
        *)
            log_error "Unknown package manager. Please install '$pkg' manually."
            return 1 ;;
    esac
}

# Update package cache (failures are not fatal: the install step will tell)
update_pkg_cache() {
    local pkg_mgr
    pkg_mgr=$(detect_pkg_manager)

    case "$pkg_mgr" in
        apt)    apt-get update -qq || true ;;
        dnf)    dnf makecache -q 2>/dev/null || true ;;
        yum)    yum makecache -q 2>/dev/null || true ;;
        pacman) pacman -Sy --noconfirm || true ;;
        apk)    apk update || true ;;
        zypper) zypper --non-interactive refresh -q || true ;;
    esac
}

# =============================================================================
# Competing firewalls
# =============================================================================
# Detection (and the question) happens early; the actual disabling happens
# only when binadit-firewall is installed, configured and validated.

COMPETING=()

check_competing_firewalls() {
    log_header "Checking for other firewalls"

    COMPETING=()
    local svc

    if service_exists "firewalld" && { service_is_active "firewalld" || service_is_enabled "firewalld"; }; then
        COMPETING+=("firewalld")
    fi

    if command -v ufw &>/dev/null; then
        local ufw_status
        ufw_status=$(ufw status 2>/dev/null | head -1 || true)
        if [[ "$ufw_status" == *"Status: active"* ]]; then
            COMPETING+=("ufw")
        fi
    fi

    # Services that restore their own saved rules at boot
    for svc in iptables ip6tables nftables netfilter-persistent; do
        if service_exists "$svc" && { service_is_active "$svc" || service_is_enabled "$svc"; }; then
            COMPETING+=("$svc")
        fi
    done

    if (( ${#COMPETING[@]} == 0 )); then
        log_success "No other active firewalls found"
        return 0
    fi

    log_warn "Found: ${BOLD}${COMPETING[*]}${NC}"
    log_info "These will be stopped and disabled right before binadit-firewall starts"
    local answer
    ask answer "  Continue? [Y/n]: " "y"
    if [[ "${answer,,}" == "n" ]]; then
        log_error "Installation cancelled — nothing was changed"
        exit 1
    fi
}

disable_competing_firewalls() {
    (( ${#COMPETING[@]} == 0 )) && return 0

    log_header "Disabling other firewalls"
    ensure_state_dir || true
    local record svc
    record="$(state_dir)/disabled-services"

    for svc in "${COMPETING[@]}"; do
        if [[ "$svc" == "ufw" ]]; then
            ufw disable &>/dev/null || true
        fi
        if service_exists "$svc"; then
            systemctl stop "$svc" 2>/dev/null || true
            systemctl disable "$svc" 2>/dev/null || true
            systemctl mask "$svc" 2>/dev/null || true
        fi
        grep -qx "$svc" "$record" 2>/dev/null || echo "$svc" >> "$record"
        log_success "$svc stopped and disabled"
    done
}

# =============================================================================
# Service detection and interactive configuration
# =============================================================================

# Known port-to-service name mappings
declare -A PORT_SERVICE_NAMES=(
    [21]="FTP"
    [22]="SSH"
    [25]="SMTP"
    [53]="DNS"
    [80]="HTTP"
    [110]="POP3"
    [143]="IMAP"
    [443]="HTTPS"
    [465]="SMTPS"
    [587]="Mail Submission"
    [873]="rsync"
    [993]="IMAPS"
    [995]="POP3S"
    [1194]="OpenVPN"
    [1433]="MSSQL"
    [1723]="PPTP"
    [2181]="ZooKeeper"
    [2375]="Docker API"
    [2376]="Docker TLS"
    [3000]="Grafana"
    [3306]="MySQL"
    [3389]="RDP"
    [4369]="EPMD"
    [4443]="HTTPS Alt"
    [5432]="PostgreSQL"
    [5601]="Kibana"
    [5672]="RabbitMQ"
    [5900]="VNC"
    [6379]="Redis"
    [6443]="Kubernetes API"
    [6660]="IRC"
    [8080]="HTTP Alt"
    [8081]="HTTP Alt"
    [8443]="HTTPS Alt"
    [8500]="Consul"
    [8888]="HTTP Proxy"
    [9090]="Prometheus"
    [9092]="Kafka"
    [9100]="Node Exporter"
    [9200]="Elasticsearch"
    [10250]="Kubelet"
    [11211]="Memcached"
    [15672]="RabbitMQ Mgmt"
    [27017]="MongoDB"
    [51820]="WireGuard"
)

# Ports that are pre-selected on a fresh install
SAFE_DEFAULT_PORTS="80 443 53"

# Results of detect_running_services
DET_TCP_PORTS=(); DET_TCP_PROCS=(); DET_UDP_PORTS=(); DET_UDP_PROCS=()

# Parse "ss -lnp" / "netstat -lnp" output: prints "port process" for every
# listener that is reachable from outside (loopback-only listeners are skipped)
_parse_listeners() {
    local line addr port proc
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        addr=$(echo "$line" | awk '{ print $4 }')
        port="${addr##*:}"
        addr="${addr%:*}"
        [[ "$port" =~ ^[0-9]+$ ]] || continue
        case "$addr" in
            127.*|"[::1]"|::1|localhost) continue ;;
        esac
        proc=$(echo "$line" | sed -n 's/.*users:(("\([^"]*\)".*/\1/p')
        if [[ -z "$proc" ]]; then
            # netstat format: last column is "pid/program"
            proc=$(echo "$line" | awk '{ print $NF }')
            if [[ "$proc" == */* ]]; then proc="${proc#*/}"; else proc=""; fi
        fi
        echo "$port ${proc:-unknown}"
    done
}

# Detect running services by scanning listening ports
detect_running_services() {
    DET_TCP_PORTS=(); DET_TCP_PROCS=(); DET_UDP_PORTS=(); DET_UDP_PROCS=()
    local tool port proc

    if command -v ss &>/dev/null; then
        tool="ss"
    elif command -v netstat &>/dev/null; then
        tool="netstat"
    else
        return 1
    fi

    while read -r port proc; do
        [[ -z "$port" ]] && continue
        [[ " ${DET_TCP_PORTS[*]:-} " == *" $port "* ]] && continue
        DET_TCP_PORTS+=("$port"); DET_TCP_PROCS+=("$proc")
    done < <("$tool" -tlnp 2>/dev/null | tail -n +2 | _parse_listeners)

    while read -r port proc; do
        [[ -z "$port" ]] && continue
        [[ " ${DET_UDP_PORTS[*]:-} " == *" $port "* ]] && continue
        DET_UDP_PORTS+=("$port"); DET_UDP_PROCS+=("$proc")
    done < <("$tool" -ulnp 2>/dev/null | tail -n +2 | _parse_listeners)

    return 0
}

# Get a friendly service name for a port
get_service_name() {
    local port="$1"
    local proc_name="${2:-}"

    if [[ -n "${PORT_SERVICE_NAMES[$port]+x}" ]]; then
        echo "${PORT_SERVICE_NAMES[$port]}"
    elif [[ -n "$proc_name" && "$proc_name" != "unknown" && "$proc_name" != "-" ]]; then
        echo "$proc_name"
    else
        echo "Port $port"
    fi
}

# Interactive service selection menu.
# $1 config file, $2 "fresh" (pre-select safe defaults) or "existing"
# (pre-select exactly what the config already opens).
service_selection_menu() {
    local config_file="$1" mode="${2:-fresh}"

    log_header "Which services should be reachable from outside?"

    if ! detect_running_services; then
        log_warn "Could not detect running services (ss/netstat not found) — keeping current port settings"
        return 0
    fi

    load_config "$config_file"
    local ssh_ports="$SSH_PORTS"
    local cur_tcp="$TCP_PORTS" cur_udp="$UDP_PORTS"

    local -a menu_proto=() menu_port=() menu_name=() menu_note=() menu_enabled=()
    local keep_tcp="" keep_udp="" i port proc tok

    _menu_add() {
        local proto="$1" port="$2" proc="$3" enabled="false" current="$cur_tcp"
        [[ "$proto" == "UDP" ]] && current="$cur_udp"
        # SSH is never part of the menu: it is always kept reachable
        if [[ "$proto" == "TCP" && " $ssh_ports " == *" $port "* ]]; then
            return 0
        fi
        local j
        for j in "${!menu_port[@]}"; do
            [[ "${menu_port[$j]}" == "$port" && "${menu_proto[$j]}" == "$proto" ]] && return 0
        done
        if [[ "$mode" == "existing" ]]; then
            [[ " $current " == *" $port "* ]] && enabled="true"
        else
            [[ "$proto" == "TCP" || "$port" == "53" ]] && [[ " $SAFE_DEFAULT_PORTS " == *" $port "* ]] && enabled="true"
        fi
        menu_proto+=("$proto"); menu_port+=("$port")
        menu_name+=("$(get_service_name "$port" "$proc")")
        if [[ "$proc" == "-" ]]; then menu_note+=("not running"); else menu_note+=("listening"); fi
        menu_enabled+=("$enabled")
    }

    for i in "${!DET_TCP_PORTS[@]}"; do
        _menu_add TCP "${DET_TCP_PORTS[$i]}" "${DET_TCP_PROCS[$i]}"
    done
    for i in "${!DET_UDP_PORTS[@]}"; do
        _menu_add UDP "${DET_UDP_PORTS[$i]}" "${DET_UDP_PROCS[$i]}"
    done
    # Always offer HTTP and HTTPS
    _menu_add TCP 80 "-"
    _menu_add TCP 443 "-"
    # Ports the configuration already opens stay visible (and selected);
    # port ranges cannot be toggled and are simply kept
    if [[ "$mode" == "existing" ]]; then
        for tok in $cur_tcp; do
            if [[ "$tok" == *:* ]]; then keep_tcp+="${keep_tcp:+ }$tok"; else _menu_add TCP "$tok" "-"; fi
        done
        for tok in $cur_udp; do
            if [[ "$tok" == *:* ]]; then keep_udp+="${keep_udp:+ }$tok"; else _menu_add UDP "$tok" "-"; fi
        done
    fi

    # Sort by port number
    local -a sorted_indices=()
    while read -r i; do
        [[ -n "$i" ]] && sorted_indices+=("$i")
    done < <(for i in "${!menu_port[@]}"; do echo "$i ${menu_port[$i]}"; done | sort -k2 -n | awk '{ print $1 }')

    _display_menu() {
        echo ""
        echo -e "  ${BOLD}${CYAN}┌────┬──────────────────────┬────────┬───────┬─────────────┬─────────┐${NC}"
        echo -e "  ${BOLD}${CYAN}│${NC} ${BOLD}#  ${CYAN}│${NC} ${BOLD}Service              ${CYAN}│${NC} ${BOLD}Port   ${CYAN}│${NC} ${BOLD}Proto ${CYAN}│${NC} ${BOLD}State       ${CYAN}│${NC} ${BOLD}Access  ${CYAN}│${NC}"
        echo -e "  ${BOLD}${CYAN}├────┼──────────────────────┼────────┼───────┼─────────────┼─────────┤${NC}"

        local display_num=1 si name status_text
        for si in "${sorted_indices[@]}"; do
            name="${menu_name[$si]}"
            (( ${#name} > 20 )) && name="${name:0:17}..."
            if [[ "${menu_enabled[$si]}" == "true" ]]; then
                status_text="${GREEN}✓ ALLOW${NC}"
            else
                status_text="${RED}✗ BLOCK${NC}"
            fi
            printf "  ${CYAN}│${NC} %-2s ${CYAN}│${NC} %-20s ${CYAN}│${NC} %-6s ${CYAN}│${NC} %-5s ${CYAN}│${NC} %-11s ${CYAN}│${NC} %b ${CYAN}│${NC}\n" \
                "$display_num" "$name" "${menu_port[$si]}" "${menu_proto[$si]}" "${menu_note[$si]}" "$status_text"
            display_num=$((display_num + 1))
        done

        echo -e "  ${BOLD}${CYAN}└────┴──────────────────────┴────────┴───────┴─────────────┴─────────┘${NC}"
        echo -e "  SSH (port ${ssh_ports}) is always kept reachable and is not listed."
        [[ -n "${keep_tcp}${keep_udp}" ]] && echo -e "  Port ranges from your config are kept: ${keep_tcp} ${keep_udp}"
        echo ""
    }

    local user_input num si
    while true; do
        _display_menu

        echo -e "  ${BOLD}Toggle:${NC} enter number(s) to toggle (e.g., ${BOLD}3 5${NC})"
        echo -e "  ${BOLD}Shortcuts:${NC} ${GREEN}a${NC}=allow all  ${RED}n${NC}=block all  ${BOLD}d${NC}=done (or just Enter)"
        echo ""
        ask user_input "  > " "d"

        case "${user_input,,}" in
            d|done)
                break ;;
            a|all)
                for i in "${!menu_enabled[@]}"; do menu_enabled[$i]="true"; done
                continue ;;
            n|none)
                for i in "${!menu_enabled[@]}"; do menu_enabled[$i]="false"; done
                continue ;;
        esac

        for num in $user_input; do
            if [[ "$num" =~ ^[0-9]+$ ]] && (( num >= 1 && num <= ${#sorted_indices[@]} )); then
                si="${sorted_indices[$((num - 1))]}"
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

    # Build port lists from selections (in port order)
    local selected_tcp="" selected_udp=""
    for si in ${sorted_indices[@]+"${sorted_indices[@]}"}; do
        [[ "${menu_enabled[$si]}" == "true" ]] || continue
        if [[ "${menu_proto[$si]}" == "TCP" ]]; then
            selected_tcp+="${selected_tcp:+ }${menu_port[$si]}"
        else
            selected_udp+="${selected_udp:+ }${menu_port[$si]}"
        fi
    done
    [[ -n "$keep_tcp" ]] && selected_tcp+="${selected_tcp:+ }$keep_tcp"
    [[ -n "$keep_udp" ]] && selected_udp+="${selected_udp:+ }$keep_udp"

    config_set_value "$config_file" TCP_PORTS "$selected_tcp"
    config_set_value "$config_file" UDP_PORTS "$selected_udp"

    echo ""
    log_success "Open TCP ports: ${BOLD}${selected_tcp:-none}${NC}"
    log_success "Open UDP ports: ${BOLD}${selected_udp:-none}${NC}"
    log_info "SSH (${ssh_ports}) stays reachable"
}

# Ask the remaining configuration questions
configure_interactively() {
    local config_file="$1" mode="$2" answer tok bad

    service_selection_menu "$config_file" "$mode"

    load_config "$config_file"
    echo ""
    if ssh_is_restricted; then
        log_info "SSH is restricted to: ${SSH_ALLOWED_IPS} ${SSH_ALLOWED_IPS_IPV6} (unchanged)"
    else
        ask answer "  Restrict SSH (${SSH_PORTS}) to specific IPs/hostnames? [y/N]: " "n"
        if [[ "${answer,,}" == "y" ]]; then
            while true; do
                ask answer "  Allowed SSH IPs/hostnames (space-separated, empty = no restriction): " ""
                bad=""
                for tok in $answer; do
                    classify_addr "$tok" || { bad="$tok"; break; }
                done
                if [[ -n "$bad" ]]; then
                    log_warn "'${bad}' is not a valid IP, CIDR or hostname — try again"
                    continue
                fi
                if [[ -n "${answer// /}" ]]; then
                    config_set_value "$config_file" SSH_ALLOWED_IPS "$(echo "$answer" | xargs)"
                    log_success "SSH restricted to: $answer"
                    log_warn "Make sure your own address is in this list, or you will lose SSH access"
                fi
                break
            done
        fi
    fi

    if [[ "$mode" == "fresh" ]]; then
        echo ""
        ask answer "  Allow ping (ICMP)? [Y/n]: " "y"
        if [[ "${answer,,}" == "n" ]]; then
            config_set_value "$config_file" ICMP_ENABLE "false"
        fi
    fi

    echo ""
    log_success "Configuration saved: ${config_file}"
}

# =============================================================================
# Install dependencies
# =============================================================================

install_dependencies() {
    log_header "Checking dependencies"

    local distro_family
    distro_family=$(detect_distro_family)

    # A kernel that already runs iptables through nf_tables (iptables-nft) is
    # an nftables system: install the native tool, so the same distribution
    # always ends up on the same backend. Legacy-iptables systems are left alone.
    if ! command -v nft &>/dev/null && [[ "$(iptables --version 2>/dev/null || true)" == *"nf_tables"* ]]; then
        log_info "This system uses nf_tables but the nft tool is missing, installing nftables..."
        update_pkg_cache
        install_package "nftables" || true
        if ! command -v nft &>/dev/null; then
            log_warn "nftables could not be installed — continuing with the iptables backend"
        fi
    fi

    if command -v nft &>/dev/null || command -v iptables &>/dev/null; then
        command -v nft &>/dev/null && log_success "nftables available: $(nft --version 2>/dev/null || echo 'installed')"
        command -v iptables &>/dev/null && log_success "iptables available: $(iptables --version 2>/dev/null || echo 'installed')"
    else
        log_info "No firewall backend found, installing nftables..."
        update_pkg_cache
        install_package "nftables" || true
        if ! command -v nft &>/dev/null; then
            log_warn "nftables could not be installed, trying iptables..."
            install_package "iptables" || true
        fi
    fi

    if ! command -v nft &>/dev/null && ! command -v iptables &>/dev/null; then
        log_error "No firewall backend available. Install 'nftables' or 'iptables' and run the installer again."
        exit 1
    fi

    if ! detect_backend &>/dev/null; then
        log_error "A firewall backend is installed but not usable (missing kernel support or permissions)"
        exit 1
    fi
    log_success "Backend in use: $(detect_backend)"

    # Hostname resolution works with getent (always present on glibc systems);
    # only install DNS tools when no resolver command exists at all.
    if ! command -v getent &>/dev/null && ! command -v dig &>/dev/null && ! command -v host &>/dev/null; then
        case "$distro_family" in
            debian)  install_package "dnsutils" || true ;;
            rhel)    install_package "bind-utils" || true ;;
            arch)    install_package "bind" || true ;;
            alpine)  install_package "bind-tools" || true ;;
            suse)    install_package "bind-utils" || true ;;
        esac
    fi
}

# =============================================================================
# Detect existing installation (upgrade path: v1.x, v2.x → v3.x)
# =============================================================================

EXISTING_INSTALL="false"

detect_existing_install() {
    if [[ -e "$SBIN_LINK" ]] || [[ -d "$INSTALL_DIR" ]]; then
        EXISTING_INSTALL="true"
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

        local do_upgrade
        echo ""
        ask do_upgrade "  Install v${BINADIT_VERSION} over it? [Y/n]: " "y"
        if [[ "${do_upgrade,,}" == "n" ]]; then
            log_info "Cancelled — nothing was changed"
            exit 0
        fi
    fi
}

# =============================================================================
# Install binadit-firewall files
# =============================================================================

# /usr/local/sbin is not in sudo's secure_path on RHEL-like systems, so
# "sudo binadit-firewall" would not be found there. Link the command into
# /usr/sbin as well (never over a file that is not ours).
link_into_system_path() {
    local link="$SYSTEM_LINK"
    [[ -d "$(dirname "$link")" ]] || return 0
    [[ "$(readlink -f "$(dirname "$link")")" == "$(readlink -f "$(dirname "$SBIN_LINK")")" ]] && return 0
    if [[ -L "$link" ]] || [[ ! -e "$link" ]]; then
        ln -sfn "$SBIN_LINK" "$link" 2>/dev/null || true
    fi
}

install_program_files() {
    mkdir -p "$CONFIG_DIR" "$BACKUP_DIR"
    mkdir -p "$(dirname "$INSTALL_DIR")" "$(dirname "$SBIN_LINK")"

    # Build the new program directory next to the old one and swap it in, so
    # a running binadit-firewall process never sees half-written files
    local staging="${INSTALL_DIR}.new.$$"
    rm -rf "$staging"
    mkdir -p "$staging"
    cp -r "${INSTALLER_DIR}/src/"* "$staging/"
    chmod 755 "$staging" "$staging/lib"
    chmod 755 "$staging/binadit-firewall.sh"
    chmod 644 "$staging/lib/"*.sh

    if [[ -d "$INSTALL_DIR" ]]; then
        rm -rf "${INSTALL_DIR}.old"
        mv "$INSTALL_DIR" "${INSTALL_DIR}.old"
    fi
    mv "$staging" "$INSTALL_DIR"
    rm -rf "${INSTALL_DIR}.old"

    ln -sf "$INSTALL_DIR/binadit-firewall.sh" "$SBIN_LINK"
    link_into_system_path

    cp "${INSTALLER_DIR}/config/firewall.conf.example" "${CONFIG_DIR}/firewall.conf.example"
}

install_boot_service() {
    if has_systemctl; then
        # systemd
        mkdir -p "$SYSTEMD_DIR"
        cp "${INSTALLER_DIR}/config/binadit-firewall.service" "${SYSTEMD_DIR}/binadit-firewall.service"
        chmod 644 "${SYSTEMD_DIR}/binadit-firewall.service"
        systemctl daemon-reload 2>/dev/null || true
        if systemctl enable binadit-firewall.service &>/dev/null; then
            log_success "Systemd service installed and enabled (starts at boot)"
        else
            log_warn "Could not enable the systemd service — run: systemctl enable binadit-firewall"
        fi
    elif command -v rc-service &>/dev/null; then
        # OpenRC (Alpine Linux, Gentoo)
        cat > /etc/init.d/binadit-firewall <<'OPENRC_EOF'
#!/sbin/openrc-run
# binadit-firewall OpenRC service

description="binadit-firewall - Simple Linux Firewall Manager"
extra_started_commands="reload"

depend() {
    need localmount
    before net
}

start() {
    ebegin "Starting binadit-firewall"
    /usr/local/sbin/binadit-firewall start >/dev/null
    eend $?
}

stop() {
    ebegin "Stopping binadit-firewall"
    /usr/local/sbin/binadit-firewall stop >/dev/null
    eend $?
}

reload() {
    ebegin "Reloading binadit-firewall"
    /usr/local/sbin/binadit-firewall reload >/dev/null
    eend $?
}
OPENRC_EOF
        chmod 755 /etc/init.d/binadit-firewall
        rc-update add binadit-firewall default &>/dev/null || true
        log_success "OpenRC service installed and enabled (starts at boot)"
    else
        # SysVinit fallback
        cat > /etc/init.d/binadit-firewall <<'INITEOF'
#!/bin/bash
### BEGIN INIT INFO
# Provides:          binadit-firewall
# Required-Start:    $local_fs
# Required-Stop:     $local_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: binadit-firewall
# Description:       Simple Linux Firewall Manager
### END INIT INFO
exec /usr/local/sbin/binadit-firewall "$@"
INITEOF
        chmod 755 /etc/init.d/binadit-firewall

        if command -v update-rc.d &>/dev/null; then
            update-rc.d binadit-firewall defaults &>/dev/null || true
        elif command -v chkconfig &>/dev/null; then
            chkconfig --add binadit-firewall &>/dev/null || true
            chkconfig binadit-firewall on &>/dev/null || true
        fi
        log_success "SysVinit service installed (starts at boot)"
    fi
}

install_files() {
    log_header "Installing binadit-firewall"
    install_program_files
    log_success "Program files installed: ${INSTALL_DIR}"
    log_success "Command available: binadit-firewall"
    install_boot_service
}

# =============================================================================
# Migrate from old binadit-firewall v1.x
# =============================================================================

migrate_old_config() {
    local old_config="/etc/firewall.d/host.conf"
    [[ -f "$old_config" ]] || return 0

    log_header "Migrating from binadit-firewall v1.x"
    log_info "Found old config: $old_config"
    migrate_v1_config "$old_config" "${CONFIG_DIR}/firewall.conf" "${INSTALLER_DIR}/config/firewall.conf.example"
}

# =============================================================================
# Update mode (called by "binadit-firewall update")
# =============================================================================

update_only() {
    require_root
    install_program_files
    log_success "Program files updated to v${BINADIT_VERSION}"

    # Refresh the boot service definition if one is installed
    if [[ -f "${SYSTEMD_DIR}/binadit-firewall.service" ]] && has_systemctl; then
        cp "${INSTALLER_DIR}/config/binadit-firewall.service" "${SYSTEMD_DIR}/binadit-firewall.service"
        systemctl daemon-reload 2>/dev/null || true
    fi

    # Let the new version finish the job (reload rules, refresh helpers)
    "$SBIN_LINK" post-update
}

# =============================================================================
# Uninstall
# =============================================================================

uninstall() {
    require_root

    log_header "Uninstalling binadit-firewall"

    # Remove the rules while the program is still installed
    if [[ -x "$SBIN_LINK" ]]; then
        "$SBIN_LINK" stop >/dev/null 2>&1 || true
    fi

    # Boot service
    if has_systemctl; then
        systemctl disable --now binadit-firewall-dns.timer &>/dev/null || true
        systemctl disable --now binadit-firewall-update.timer &>/dev/null || true
        systemctl disable binadit-firewall.service &>/dev/null || true
        rm -f "${SYSTEMD_DIR}/binadit-firewall.service" \
              "${SYSTEMD_DIR}/binadit-firewall-dns.service" "${SYSTEMD_DIR}/binadit-firewall-dns.timer" \
              "${SYSTEMD_DIR}/binadit-firewall-update.service" "${SYSTEMD_DIR}/binadit-firewall-update.timer"
        systemctl daemon-reload &>/dev/null || true
        systemctl reset-failed 'binadit-firewall*' &>/dev/null || true
    fi
    if [[ -f /etc/init.d/binadit-firewall ]]; then
        if command -v rc-update &>/dev/null; then
            rc-update del binadit-firewall default &>/dev/null || true
        elif command -v update-rc.d &>/dev/null; then
            update-rc.d -f binadit-firewall remove &>/dev/null || true
        elif command -v chkconfig &>/dev/null; then
            chkconfig --del binadit-firewall &>/dev/null || true
        fi
        rm -f /etc/init.d/binadit-firewall
    fi
    log_info "Removed boot service"

    # Helpers
    rm -f /etc/profile.d/binadit-firewall-status.sh /etc/profile.d/binadit-firewall-prompt.sh
    rm -f /etc/cron.weekly/binadit-firewall-update /etc/cron.d/binadit-firewall-dns
    rm -f /etc/periodic/weekly/binadit-firewall-update /etc/periodic/15min/binadit-firewall-dns
    rm -f /run/binadit-firewall.active /var/run/binadit-firewall.active /run/binadit-firewall.lock
    log_info "Removed login indicators and scheduled jobs"

    # Program files
    rm -f "$SBIN_LINK"
    if [[ -L "$SYSTEM_LINK" && "$(readlink "$SYSTEM_LINK")" == "$SBIN_LINK" ]]; then
        rm -f "$SYSTEM_LINK"
    fi
    rm -rf "$INSTALL_DIR" "${INSTALL_DIR}.old"

    # Firewalls the installer disabled: make them usable again (not started)
    local record="${CONFIG_DIR}/state/disabled-services" svc restored=""
    if [[ -f "$record" ]] && has_systemctl; then
        while IFS= read -r svc; do
            [[ -z "$svc" ]] && continue
            systemctl unmask "$svc" &>/dev/null || true
            restored+="${restored:+ }$svc"
        done < "$record"
        rm -f "$record"
    fi

    log_success "binadit-firewall uninstalled — all its firewall rules are removed"
    log_warn "This server now has NO firewall"
    if [[ -n "$restored" ]]; then
        log_info "Previously disabled by the installer and now available again: ${BOLD}${restored}${NC}"
        log_info "Re-enable with e.g.: systemctl enable --now ${restored%% *}"
    fi

    # Configuration
    if [[ -d "$CONFIG_DIR" ]]; then
        local remove_config
        echo ""
        ask remove_config "  Remove configuration and backups (${CONFIG_DIR})? [y/N]: " "n"
        if [[ "${remove_config,,}" == "y" ]]; then
            rm -rf "$CONFIG_DIR"
            log_success "Configuration removed"
        else
            log_info "Configuration preserved in: $CONFIG_DIR"
            log_info "To remove it: rm -rf $CONFIG_DIR"
        fi
    fi
}

# =============================================================================
# Main installer
# =============================================================================

main() {
    local action="install" arg

    for arg in "$@"; do
        case "$arg" in
            --uninstall|uninstall)
                action="uninstall" ;;
            --update)
                action="update"; NON_INTERACTIVE="true" ;;
            --non-interactive|-y)
                NON_INTERACTIVE="true" ;;
            --help|-h)
                echo "Usage: sudo bash install.sh [--non-interactive] [--uninstall] [--update]"
                exit 0 ;;
            *)
                log_error "Unknown option: $arg"
                echo "Usage: sudo bash install.sh [--non-interactive] [--uninstall] [--update]"
                exit 1 ;;
        esac
    done

    # Without a terminal on stdin nobody can answer questions
    if [[ ! -t 0 ]]; then
        NON_INTERACTIVE="true"
    fi

    case "$action" in
        uninstall) uninstall; exit 0 ;;
        update)    update_only; exit 0 ;;
    esac

    require_root

    show_banner

    local distro distro_family
    distro=$(detect_distro)
    distro_family=$(detect_distro_family)
    log_info "Detected OS: ${BOLD}${distro}${NC} (family: ${distro_family})"
    [[ "$NON_INTERACTIVE" == "true" ]] && log_info "Running non-interactive: using defaults, keeping existing configuration"

    # Step 1: existing installation? other firewalls? (questions only)
    detect_existing_install
    check_competing_firewalls

    # Step 2: dependencies
    install_dependencies

    # Step 3: migrate a v1.x config if present
    migrate_old_config

    # Step 4: program files + boot service
    install_files

    # Step 5: configuration
    local config_file="${CONFIG_DIR}/firewall.conf"
    if [[ ! -f "$config_file" ]]; then
        cp "${CONFIG_DIR}/firewall.conf.example" "$config_file"
        log_info "Default configuration installed (HTTP, HTTPS and SSH open)"
        if [[ "$NON_INTERACTIVE" != "true" ]]; then
            configure_interactively "$config_file" "fresh"
        fi
    else
        log_success "Keeping existing configuration: ${config_file}"
        if [[ "$NON_INTERACTIVE" != "true" ]]; then
            local reconfig
            echo ""
            ask reconfig "  Review which ports are open? (your current choices are pre-selected) [y/N]: " "n"
            if [[ "${reconfig,,}" == "y" ]]; then
                configure_interactively "$config_file" "existing"
            fi
        fi
    fi

    # Step 6: validate before touching the running system
    if ! "$SBIN_LINK" configtest; then
        echo ""
        log_error "The configuration has errors, so the firewall was NOT started and nothing else was changed."
        log_info "Fix ${config_file} and run: ${BOLD}binadit-firewall start${NC}"
        exit 1
    fi

    # Step 7: switch over
    disable_competing_firewalls

    log_header "Starting firewall"
    local started="false"
    if systemd_running; then
        # Start through systemd so "systemctl status" reflects reality
        if systemctl restart binadit-firewall.service; then
            started="true"
            "$SBIN_LINK" status 2>/dev/null | sed -n '/Firewall Rule Summary/,/└/p' || true
        fi
    elif "$SBIN_LINK" start; then
        started="true"
    fi

    echo ""
    if [[ "$started" == "true" ]]; then
        echo -e "${GREEN}${BOLD}"
        cat <<'COMPLETE'
    ╔═══════════════════════════════════════════════════════════════════════════╗
    ║                                                                           ║
    ║              ✅  INSTALLATION COMPLETE — FIREWALL IS ACTIVE               ║
    ║                                                                           ║
    ╚═══════════════════════════════════════════════════════════════════════════╝
COMPLETE
        echo -e "${NC}"
    else
        echo -e "${RED}${BOLD}"
        cat <<'FAILED'
    ╔═══════════════════════════════════════════════════════════════════════════╗
    ║                                                                           ║
    ║        ⚠️  INSTALLED, BUT THE FIREWALL COULD NOT BE STARTED               ║
    ║                                                                           ║
    ╚═══════════════════════════════════════════════════════════════════════════╝
FAILED
        echo -e "${NC}"
        log_error "The server is NOT protected by binadit-firewall right now."
        log_info "See what is wrong with: ${BOLD}binadit-firewall start${NC}"
    fi

    # Optional extras (interactive only)
    if [[ "$NON_INTERACTIVE" != "true" ]]; then
        local answer
        if [[ ! -f /etc/cron.weekly/binadit-firewall-update && ! -f /etc/periodic/weekly/binadit-firewall-update \
              && ! -f "${SYSTEMD_DIR}/binadit-firewall-update.timer" ]]; then
            ask answer "  Enable weekly automatic updates? [Y/n]: " "y"
            if [[ "${answer,,}" != "n" ]]; then
                "$SBIN_LINK" auto-update on || log_warn "Could not enable auto-update"
            fi
        fi

        if [[ -d /etc/profile.d ]]; then
            if [[ ! -f /etc/profile.d/binadit-firewall-status.sh ]]; then
                echo ""
                ask answer "  Show firewall status on every login (motd)? [Y/n]: " "y"
                if [[ "${answer,,}" != "n" ]]; then
                    "$SBIN_LINK" motd-on || log_warn "Could not install login status"
                fi
            fi
            if [[ ! -f /etc/profile.d/binadit-firewall-prompt.sh ]]; then
                echo ""
                ask answer "  Show 🟢/🔴 firewall status emoji in your prompt? [Y/n]: " "y"
                if [[ "${answer,,}" != "n" ]]; then
                    "$SBIN_LINK" prompt-on || log_warn "Could not install prompt indicator"
                fi
            fi
        fi
    fi

    echo ""
    echo -e "  ${BOLD}Commands:${NC}"
    echo -e "    binadit-firewall status       ${GREEN}# Is it active? Which rules?${NC}"
    echo -e "    binadit-firewall config show  ${GREEN}# View all settings${NC}"
    echo -e "    binadit-firewall config add TCP_PORTS 8080  ${GREEN}# Change a setting${NC}"
    echo -e "    binadit-firewall reload       ${GREEN}# Apply configuration changes${NC}"
    echo -e "    binadit-firewall stop         ${GREEN}# Disable firewall${NC}"
    echo -e "    binadit-firewall update       ${GREEN}# Download latest version${NC}"
    echo -e "    binadit-firewall features     ${GREEN}# Full feature documentation${NC}"
    echo ""
    echo -e "  ${BOLD}Configuration:${NC}"
    echo -e "    ${CONFIG_DIR}/firewall.conf"
    echo ""

    [[ "$started" == "true" ]] || exit 1
}

main "$@"
