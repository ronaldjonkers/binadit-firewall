#!/usr/bin/env bash
# =============================================================================
# binadit-firewall - Backend detection and abstraction
# =============================================================================
# Detects whether to use nftables or iptables and provides a unified interface.
# =============================================================================

# Detect the best available firewall backend
# Priority: nftables > iptables-nft > iptables-legacy
detect_backend() {
    # Check for nftables (native)
    if command -v nft &>/dev/null; then
        # Verify nft actually works
        if nft list ruleset &>/dev/null 2>&1; then
            echo "nftables"
            return 0
        fi
    fi

    # Check for iptables (could be iptables-nft or iptables-legacy)
    if command -v iptables &>/dev/null; then
        local iptables_version
        iptables_version=$(iptables --version 2>/dev/null || true)

        if [[ "$iptables_version" == *"nf_tables"* ]]; then
            echo "iptables-nft"
        else
            echo "iptables-legacy"
        fi
        return 0
    fi

    log_error "No supported firewall backend found (nftables or iptables required)"
    return 1
}

# Get the iptables binary path (handles legacy vs nft variants)
get_iptables_cmd() {
    if command -v iptables &>/dev/null; then
        command -v iptables
    elif command -v /usr/sbin/iptables &>/dev/null; then
        echo "/usr/sbin/iptables"
    else
        return 1
    fi
}

get_ip6tables_cmd() {
    if command -v ip6tables &>/dev/null; then
        command -v ip6tables
    elif command -v /usr/sbin/ip6tables &>/dev/null; then
        echo "/usr/sbin/ip6tables"
    else
        return 1
    fi
}

get_iptables_save_cmd() {
    if command -v iptables-save &>/dev/null; then
        command -v iptables-save
    elif command -v /usr/sbin/iptables-save &>/dev/null; then
        echo "/usr/sbin/iptables-save"
    else
        return 1
    fi
}

get_ip6tables_save_cmd() {
    if command -v ip6tables-save &>/dev/null; then
        command -v ip6tables-save
    elif command -v /usr/sbin/ip6tables-save &>/dev/null; then
        echo "/usr/sbin/ip6tables-save"
    else
        return 1
    fi
}

get_iptables_restore_cmd() {
    if command -v iptables-restore &>/dev/null; then
        command -v iptables-restore
    elif command -v /usr/sbin/iptables-restore &>/dev/null; then
        echo "/usr/sbin/iptables-restore"
    else
        return 1
    fi
}

get_ip6tables_restore_cmd() {
    if command -v ip6tables-restore &>/dev/null; then
        command -v ip6tables-restore
    elif command -v /usr/sbin/ip6tables-restore &>/dev/null; then
        echo "/usr/sbin/ip6tables-restore"
    else
        return 1
    fi
}

# Detect the Linux distribution
detect_distro() {
    local distro="unknown"

    if [[ -f /etc/os-release ]]; then
        # shellcheck source=/dev/null
        source /etc/os-release
        distro="${ID:-unknown}"
    elif [[ -f /etc/redhat-release ]]; then
        distro="rhel"
    elif [[ -f /etc/debian_version ]]; then
        distro="debian"
    elif [[ -f /etc/alpine-release ]]; then
        distro="alpine"
    elif [[ -f /etc/arch-release ]]; then
        distro="arch"
    fi

    echo "$distro"
}

# Detect the distro family (debian, rhel, suse, arch, alpine)
detect_distro_family() {
    local distro
    distro=$(detect_distro)

    case "$distro" in
        ubuntu|debian|linuxmint|pop|elementary|kali|raspbian)
            echo "debian" ;;
        centos|rhel|fedora|rocky|almalinux|ol|amzn|amazon)
            echo "rhel" ;;
        opensuse*|sles|suse)
            echo "suse" ;;
        arch|manjaro|endeavouros|garuda)
            echo "arch" ;;
        alpine)
            echo "alpine" ;;
        *)
            echo "unknown" ;;
    esac
}
