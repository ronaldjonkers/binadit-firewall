#!/usr/bin/env bash
# =============================================================================
# binadit-firewall - iptables backend implementation
# =============================================================================
# All firewall operations using iptables/ip6tables commands.
# Supports both iptables-legacy and iptables-nft variants.
# =============================================================================

# Flush all iptables rules
ipt_flush() {
    log_info "Flushing iptables rules..."

    local ipt ipt6
    ipt=$(get_iptables_cmd) || { log_error "iptables not found"; return 1; }
    ipt6=$(get_ip6tables_cmd) || { log_warn "ip6tables not found, skipping IPv6"; }

    # IPv4
    $ipt -F 2>/dev/null || true
    $ipt -X 2>/dev/null || true
    $ipt -Z 2>/dev/null || true
    $ipt -t nat -F 2>/dev/null || true
    $ipt -t nat -X 2>/dev/null || true
    $ipt -t mangle -F 2>/dev/null || true
    $ipt -t mangle -X 2>/dev/null || true
    $ipt -P INPUT ACCEPT
    $ipt -P OUTPUT ACCEPT
    $ipt -P FORWARD ACCEPT

    # IPv6
    if [[ -n "${ipt6:-}" ]]; then
        $ipt6 -F 2>/dev/null || true
        $ipt6 -X 2>/dev/null || true
        $ipt6 -Z 2>/dev/null || true
        $ipt6 -P INPUT ACCEPT
        $ipt6 -P OUTPUT ACCEPT
        $ipt6 -P FORWARD ACCEPT
    fi

    log_success "iptables rules flushed"
}

# Build and apply iptables rules from config
ipt_apply() {
    local config_file="$1"
    local ssh_port
    ssh_port=$(detect_ssh_port)

    # Source config
    # shellcheck source=/dev/null
    source "$config_file"

    local ipt ipt6
    ipt=$(get_iptables_cmd) || { log_error "iptables not found"; return 1; }
    ipt6=$(get_ip6tables_cmd) || { log_warn "ip6tables not found, skipping IPv6"; ipt6=""; }

    log_info "Applying iptables rules..."

    # Load conntrack modules
    modprobe ip_conntrack 2>/dev/null || modprobe nf_conntrack 2>/dev/null || true
    modprobe ip_conntrack_ftp 2>/dev/null || modprobe nf_conntrack_ftp 2>/dev/null || true

    # =========================================================================
    # IPv4 RULES
    # =========================================================================

    # Default policies
    $ipt -P INPUT DROP
    $ipt -P FORWARD DROP
    $ipt -P OUTPUT DROP

    # Loopback
    $ipt -A INPUT -i lo -j ACCEPT
    $ipt -A OUTPUT -o lo -j ACCEPT

    # Connection tracking
    $ipt -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    $ipt -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    $ipt -A INPUT -m conntrack --ctstate INVALID -j DROP

    # Blacklist (inserted at top, before other rules)
    for ip in $BLACKLIST; do
        $ipt -I INPUT 1 -s "$ip" -j DROP
        $ipt -I OUTPUT 1 -d "$ip" -j DROP
    done

    # Blocked ranges
    if [[ -n "${BLOCKED_RANGES:-}" ]]; then
        for range in $BLOCKED_RANGES; do
            if [[ "$range" =~ - ]]; then
                $ipt -I INPUT 1 -m iprange --src-range "$range" -j DROP
                $ipt -I OUTPUT 1 -m iprange --dst-range "$range" -j DROP
            else
                $ipt -I INPUT 1 -s "$range" -j DROP
                $ipt -I OUTPUT 1 -d "$range" -j DROP
            fi
        done
    fi

    # Blocked ports
    if [[ -n "${BLOCKED_TCP_PORTS:-}" ]]; then
        for port in $BLOCKED_TCP_PORTS; do
            $ipt -A INPUT -p tcp --dport "$port" -j DROP
            $ipt -A OUTPUT -p tcp --dport "$port" -j DROP
        done
    fi
    if [[ -n "${BLOCKED_UDP_PORTS:-}" ]]; then
        for port in $BLOCKED_UDP_PORTS; do
            $ipt -A INPUT -p udp --dport "$port" -j DROP
            $ipt -A OUTPUT -p udp --dport "$port" -j DROP
        done
    fi

    # DNS (always allowed outgoing)
    $ipt -A OUTPUT -p udp --dport 53 -j ACCEPT
    $ipt -A OUTPUT -p tcp --dport 53 -j ACCEPT

    # NTP
    $ipt -A OUTPUT -p udp --dport 123 -j ACCEPT

    # SSH access restrictions
    if [[ -n "${SSH_ALLOWED_IPS:-}" ]]; then
        for ip in $SSH_ALLOWED_IPS; do
            local resolved
            resolved=$(resolve_hostname "$ip" 2>/dev/null) || continue
            $ipt -A INPUT -p tcp --dport "$ssh_port" -s "$resolved" -j ACCEPT
            $ipt -A OUTPUT -p tcp --sport "$ssh_port" -d "$resolved" -j ACCEPT
        done
    fi

    # Port-specific IP restrictions
    if [[ -n "${PORT_IP_RULES:-}" ]]; then
        local IFS_OLD="$IFS"
        IFS=$'\n'
        for rule in $PORT_IP_RULES; do
            IFS="$IFS_OLD"
            local proto port_num ip_addr
            proto=$(echo "$rule" | awk -F'|' '{print $1}' | xargs)
            port_num=$(echo "$rule" | awk -F'|' '{print $2}' | xargs)
            ip_addr=$(echo "$rule" | awk -F'|' '{print $3}' | xargs)
            if [[ -n "$proto" && -n "$port_num" && -n "$ip_addr" ]]; then
                local resolved
                resolved=$(resolve_hostname "$ip_addr" 2>/dev/null) || resolved="$ip_addr"
                $ipt -A INPUT -p "$proto" --dport "$port_num" -s "$resolved" -j ACCEPT
                $ipt -A OUTPUT -p "$proto" --sport "$port_num" -d "$resolved" -j ACCEPT
            fi
            IFS=$'\n'
        done
        IFS="$IFS_OLD"
    fi

    # TCP ports (bidirectional)
    for port in $TCP_PORTS; do
        $ipt -A INPUT -p tcp --dport "$port" -j ACCEPT
        $ipt -A OUTPUT -p tcp --dport "$port" -j ACCEPT
    done

    # TCP input-only ports
    if [[ -n "${TCP_PORTS_INPUT:-}" ]]; then
        for port in $TCP_PORTS_INPUT; do
            $ipt -A INPUT -p tcp --dport "$port" -j ACCEPT
            $ipt -A OUTPUT -p tcp --dport "$port" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
        done
    fi

    # TCP output-only ports
    if [[ -n "${TCP_PORTS_OUTPUT:-}" ]]; then
        for port in $TCP_PORTS_OUTPUT; do
            $ipt -A OUTPUT -p tcp --dport "$port" -j ACCEPT
            $ipt -A INPUT -p tcp --dport "$port" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
        done
    fi

    # UDP ports
    for port in $UDP_PORTS; do
        $ipt -A INPUT -p udp --dport "$port" -j ACCEPT
        $ipt -A OUTPUT -p udp --dport "$port" -j ACCEPT
    done

    # Trusted IPs (full access)
    for entry in $TRUSTED_IPS; do
        local resolved
        resolved=$(resolve_hostname "$entry" 2>/dev/null) || continue
        $ipt -A INPUT -s "$resolved" -j ACCEPT
        $ipt -A OUTPUT -d "$resolved" -j ACCEPT
    done

    # Trusted ranges
    if [[ -n "${TRUSTED_RANGES:-}" ]]; then
        for range in $TRUSTED_RANGES; do
            if [[ "$range" =~ - ]]; then
                $ipt -A INPUT -m iprange --src-range "$range" -j ACCEPT
                $ipt -A OUTPUT -m iprange --dst-range "$range" -j ACCEPT
            else
                $ipt -A INPUT -s "$range" -j ACCEPT
                $ipt -A OUTPUT -d "$range" -j ACCEPT
            fi
        done
    fi

    # Multicast
    if [[ "${MULTICAST_ENABLE:-false}" == "true" ]]; then
        $ipt -A INPUT -d 224.0.0.0/4 -j ACCEPT
        $ipt -A OUTPUT -d 224.0.0.0/4 -j ACCEPT
        $ipt -A INPUT -m pkttype --pkt-type multicast -j ACCEPT
        $ipt -A INPUT -m pkttype --pkt-type broadcast -j ACCEPT
        $ipt -A OUTPUT -m pkttype --pkt-type multicast -j ACCEPT
        $ipt -A OUTPUT -m pkttype --pkt-type broadcast -j ACCEPT
    fi

    # SMTP
    if [[ "${SMTP_ENABLE:-true}" == "true" ]]; then
        $ipt -A OUTPUT -p tcp --dport 25 -j ACCEPT
        $ipt -A OUTPUT -p tcp --dport 587 -j ACCEPT
    fi

    # ICMP
    if [[ "${ICMP_ENABLE:-true}" == "true" ]]; then
        $ipt -A INPUT -p icmp --icmp-type destination-unreachable -j ACCEPT
        $ipt -A INPUT -p icmp --icmp-type time-exceeded -j ACCEPT
        $ipt -A INPUT -p icmp --icmp-type echo-request -j ACCEPT
        $ipt -A INPUT -p icmp --icmp-type echo-reply -j ACCEPT
        $ipt -A INPUT -p icmp --icmp-type fragmentation-needed -j ACCEPT
        $ipt -A OUTPUT -p icmp --icmp-type echo-request -j ACCEPT
        $ipt -A OUTPUT -p icmp --icmp-type echo-reply -j ACCEPT
    fi

    # SYN flood protection
    if [[ "${SYN_FLOOD_PROTECT:-true}" == "true" ]]; then
        $ipt -A INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 3 -j ACCEPT
        $ipt -A INPUT -p tcp --syn -j DROP
        log_debug "SYN flood protection enabled"
    fi

    # Connection limit per IP
    if [[ "${CONN_LIMIT_ENABLE:-false}" == "true" ]]; then
        local conn_limit="${CONN_LIMIT_PER_IP:-50}"
        $ipt -A INPUT -p tcp -m connlimit --connlimit-above "$conn_limit" --connlimit-mask 32 -j DROP
        log_debug "Connection limit: $conn_limit per IP"
    fi

    # Connection rate per IP
    if [[ -n "${CONN_RATE_PER_IP:-}" ]] && [[ "${CONN_RATE_PER_IP:-0}" != "0" ]]; then
        $ipt -A INPUT -p tcp -m conntrack --ctstate NEW -m recent --set --name CONNRATE
        $ipt -A INPUT -p tcp -m conntrack --ctstate NEW -m recent --update --seconds 1 --hitcount "${CONN_RATE_PER_IP}" --name CONNRATE -j DROP
        log_debug "Connection rate limit: ${CONN_RATE_PER_IP}/s per IP"
    fi

    # Block common attack ports
    if [[ "${BLOCK_COMMON_ATTACKS:-true}" == "true" ]]; then
        for aport in 23 135 137 138 139 445 1900; do
            $ipt -A INPUT -p tcp --dport "$aport" -j DROP 2>/dev/null || true
            $ipt -A INPUT -p udp --dport "$aport" -j DROP 2>/dev/null || true
        done
        log_debug "Common attack ports blocked"
    fi

    # Rate limiting
    if [[ "${RATE_LIMIT_ENABLE:-true}" == "true" ]]; then
        local rate="${RATE_LIMIT_RATE:-25}"
        local burst="${RATE_LIMIT_BURST:-100}"
        $ipt -A INPUT -p tcp -m conntrack --ctstate NEW -m limit --limit "${rate}/s" --limit-burst "$burst" -j ACCEPT
    fi

    # Logging
    if [[ "${LOG_DROPPED:-true}" == "true" ]]; then
        $ipt -N LOGGING 2>/dev/null || true
        $ipt -A INPUT -j LOGGING
        $ipt -A LOGGING -m limit --limit 5/min -j LOG --log-prefix "binadit-drop: " --log-level 4
        $ipt -A LOGGING -j DROP
    fi

    # NAT
    if [[ "${NAT_ENABLE:-false}" == "true" ]]; then
        echo 1 > /proc/sys/net/ipv4/ip_forward
        local ext_iface="${NAT_EXTERNAL_IFACE:-eth0}"
        local int_iface="${NAT_INTERNAL_IFACE:-eth1}"
        $ipt -t nat -A POSTROUTING -o "$ext_iface" -j MASQUERADE
        $ipt -A FORWARD -i "$int_iface" -j ACCEPT
        $ipt -A FORWARD -o "$int_iface" -j ACCEPT
        log_info "NAT routing enabled ($int_iface -> $ext_iface)"

        # Port forwarding (DNAT)
        if [[ -n "${PORT_FORWARD_RULES:-}" ]]; then
            local IFS_OLD="$IFS"
            IFS=$'\n'
            for rule in $PORT_FORWARD_RULES; do
                IFS="$IFS_OLD"
                local proto ext_port int_dest
                proto=$(echo "$rule" | awk -F'|' '{print $1}' | xargs)
                ext_port=$(echo "$rule" | awk -F'|' '{print $2}' | xargs)
                int_dest=$(echo "$rule" | awk -F'|' '{print $3}' | xargs)
                if [[ -n "$proto" && -n "$ext_port" && -n "$int_dest" ]]; then
                    $ipt -t nat -A PREROUTING -p "$proto" --dport "$ext_port" -j DNAT --to-destination "$int_dest"
                    local int_ip="${int_dest%%:*}"
                    local int_port="${int_dest##*:}"
                    $ipt -A FORWARD -p "$proto" -d "$int_ip" --dport "$int_port" -j ACCEPT
                    log_debug "Port forward: $proto/$ext_port -> $int_dest"
                fi
                IFS=$'\n'
            done
            IFS="$IFS_OLD"
        fi
    fi

    # Custom rules file
    if [[ -n "${CUSTOM_RULES_FILE:-}" ]] && [[ -f "${CUSTOM_RULES_FILE}" ]]; then
        log_info "Loading custom rules from ${CUSTOM_RULES_FILE}..."
        local ipt_restore
        ipt_restore=$(get_iptables_restore_cmd) || true
        if [[ -n "${ipt_restore:-}" ]]; then
            $ipt_restore --noflush < "${CUSTOM_RULES_FILE}" 2>/dev/null || \
                log_warn "Failed to load custom rules (iptables-restore format)"
        else
            # Try sourcing as shell commands
            # shellcheck source=/dev/null
            source "${CUSTOM_RULES_FILE}" 2>/dev/null || \
                log_warn "Failed to load custom rules"
        fi
    fi

    # Save IPv4 rules
    local ipt_save
    ipt_save=$(get_iptables_save_cmd) || true
    if [[ -n "${ipt_save:-}" ]]; then
        mkdir -p /etc/binadit-firewall
        $ipt_save > /etc/binadit-firewall/rules.v4
    fi

    # =========================================================================
    # IPv6 RULES
    # =========================================================================
    if [[ -n "${ipt6:-}" ]]; then
        # Default policies
        $ipt6 -P INPUT DROP
        $ipt6 -P FORWARD DROP
        $ipt6 -P OUTPUT DROP

        # Loopback
        $ipt6 -A INPUT -i lo -j ACCEPT
        $ipt6 -A OUTPUT -o lo -j ACCEPT

        # Connection tracking
        $ipt6 -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
        $ipt6 -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
        $ipt6 -A INPUT -m conntrack --ctstate INVALID -j DROP

        # Blacklist IPv6
        for ip in $BLACKLIST_IPV6; do
            $ipt6 -I INPUT 1 -s "$ip" -j DROP
            $ipt6 -I OUTPUT 1 -d "$ip" -j DROP
        done

        # Blocked ranges IPv6
        if [[ -n "${BLOCKED_RANGES_IPV6:-}" ]]; then
            for range in $BLOCKED_RANGES_IPV6; do
                $ipt6 -I INPUT 1 -s "$range" -j DROP
                $ipt6 -I OUTPUT 1 -d "$range" -j DROP
            done
        fi

        # DNS
        $ipt6 -A OUTPUT -p udp --dport 53 -j ACCEPT
        $ipt6 -A OUTPUT -p tcp --dport 53 -j ACCEPT

        # NTP
        $ipt6 -A OUTPUT -p udp --dport 123 -j ACCEPT

        # SSH access IPv6
        if [[ -n "${SSH_ALLOWED_IPS_IPV6:-}" ]]; then
            for ip in $SSH_ALLOWED_IPS_IPV6; do
                $ipt6 -A INPUT -p tcp --dport "$ssh_port" -s "$ip" -j ACCEPT
                $ipt6 -A OUTPUT -p tcp --sport "$ssh_port" -d "$ip" -j ACCEPT
            done
        fi

        # TCP ports
        for port in $TCP_PORTS; do
            $ipt6 -A INPUT -p tcp --dport "$port" -j ACCEPT
            $ipt6 -A OUTPUT -p tcp --dport "$port" -j ACCEPT
        done

        # TCP input-only
        if [[ -n "${TCP_PORTS_INPUT:-}" ]]; then
            for port in $TCP_PORTS_INPUT; do
                $ipt6 -A INPUT -p tcp --dport "$port" -j ACCEPT
                $ipt6 -A OUTPUT -p tcp --dport "$port" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
            done
        fi

        # TCP output-only
        if [[ -n "${TCP_PORTS_OUTPUT:-}" ]]; then
            for port in $TCP_PORTS_OUTPUT; do
                $ipt6 -A OUTPUT -p tcp --dport "$port" -j ACCEPT
                $ipt6 -A INPUT -p tcp --dport "$port" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
            done
        fi

        # UDP ports
        for port in $UDP_PORTS; do
            $ipt6 -A INPUT -p udp --dport "$port" -j ACCEPT
            $ipt6 -A OUTPUT -p udp --dport "$port" -j ACCEPT
        done

        # Trusted IPv6
        if [[ -n "${TRUSTED_IPS_IPV6:-}" ]]; then
            for ip in $TRUSTED_IPS_IPV6; do
                $ipt6 -A INPUT -s "$ip" -j ACCEPT
                $ipt6 -A OUTPUT -d "$ip" -j ACCEPT
            done
        fi

        # Trusted ranges IPv6
        if [[ -n "${TRUSTED_RANGES_IPV6:-}" ]]; then
            for range in $TRUSTED_RANGES_IPV6; do
                $ipt6 -A INPUT -s "$range" -j ACCEPT
                $ipt6 -A OUTPUT -d "$range" -j ACCEPT
            done
        fi

        # Multicast IPv6
        if [[ "${MULTICAST_ENABLE:-false}" == "true" ]]; then
            $ipt6 -A INPUT -d ff00::/8 -j ACCEPT
            $ipt6 -A OUTPUT -d ff00::/8 -j ACCEPT
            $ipt6 -A INPUT -m pkttype --pkt-type multicast -j ACCEPT
            $ipt6 -A INPUT -m pkttype --pkt-type broadcast -j ACCEPT
            $ipt6 -A OUTPUT -m pkttype --pkt-type multicast -j ACCEPT
            $ipt6 -A OUTPUT -m pkttype --pkt-type broadcast -j ACCEPT
        fi

        # SMTP IPv6
        if [[ "${SMTP_ENABLE:-true}" == "true" ]]; then
            $ipt6 -A OUTPUT -p tcp --dport 25 -j ACCEPT
            $ipt6 -A OUTPUT -p tcp --dport 587 -j ACCEPT
        fi

        # ICMPv6 (essential for IPv6 operation)
        $ipt6 -A INPUT -p ipv6-icmp -j ACCEPT
        $ipt6 -A OUTPUT -p ipv6-icmp -j ACCEPT

        # Logging IPv6
        if [[ "${LOG_DROPPED:-true}" == "true" ]]; then
            $ipt6 -N LOGGING 2>/dev/null || true
            $ipt6 -A INPUT -j LOGGING
            $ipt6 -A LOGGING -m limit --limit 5/min -j LOG --log-prefix "binadit-drop6: " --log-level 4
            $ipt6 -A LOGGING -j DROP
        fi

        # Save IPv6 rules
        local ipt6_save
        ipt6_save=$(get_ip6tables_save_cmd) || true
        if [[ -n "${ipt6_save:-}" ]]; then
            $ipt6_save > /etc/binadit-firewall/rules.v6
        fi
    fi

    log_success "iptables rules applied successfully"
}

# Show current iptables status
ipt_status() {
    local ipt ipt6
    ipt=$(get_iptables_cmd) || { log_error "iptables not found"; return 1; }
    ipt6=$(get_ip6tables_cmd) || true

    log_header "IPv4 Firewall Rules"
    $ipt -n -L -v --line-numbers 2>/dev/null || $ipt -n -L

    if [[ -n "${ipt6:-}" ]]; then
        log_header "IPv6 Firewall Rules"
        $ipt6 -n -L -v --line-numbers 2>/dev/null || $ipt6 -n -L
    fi
}
