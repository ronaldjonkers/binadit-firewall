#!/usr/bin/env bash
# =============================================================================
# binadit-firewall - nftables backend implementation
# =============================================================================
# All firewall operations using native nftables (nft) commands.
# =============================================================================

readonly NFT_TABLE_NAME="binadit"

# Flush all nftables rules managed by binadit
nft_flush() {
    log_info "Flushing nftables rules..."
    nft delete table inet "$NFT_TABLE_NAME" 2>/dev/null || true
    log_success "nftables rules flushed"
}

# Build and apply the nftables ruleset from config
nft_apply() {
    local config_file="$1"
    local ssh_port
    ssh_port=$(detect_ssh_port)

    # Source config
    # shellcheck source=/dev/null
    source "$config_file"

    log_info "Building nftables ruleset..."

    # Start building the ruleset
    local ruleset=""
    ruleset+="#!/usr/sbin/nft -f\n"
    ruleset+="\n"
    ruleset+="# binadit-firewall v${BINADIT_VERSION} - Generated $(date '+%Y-%m-%d %H:%M:%S')\n"
    ruleset+="# Do not edit manually - managed by binadit-firewall\n"
    ruleset+="\n"

    # Delete existing table if present
    ruleset+="delete table inet ${NFT_TABLE_NAME} 2>/dev/null || true\n"
    ruleset+="\n"

    # Create table
    ruleset+="table inet ${NFT_TABLE_NAME} {\n"

    # --- Blacklist set ---
    ruleset+="    set blacklist_v4 {\n"
    ruleset+="        type ipv4_addr\n"
    ruleset+="        flags interval\n"
    local bl_elements=""
    for ip in $BLACKLIST; do
        [[ -n "$bl_elements" ]] && bl_elements+=", "
        bl_elements+="$ip"
    done
    if [[ -n "$bl_elements" ]]; then
        ruleset+="        elements = { ${bl_elements} }\n"
    fi
    ruleset+="    }\n\n"

    ruleset+="    set blacklist_v6 {\n"
    ruleset+="        type ipv6_addr\n"
    ruleset+="        flags interval\n"
    local bl6_elements=""
    for ip in $BLACKLIST_IPV6; do
        [[ -n "$bl6_elements" ]] && bl6_elements+=", "
        bl6_elements+="$ip"
    done
    if [[ -n "$bl6_elements" ]]; then
        ruleset+="        elements = { ${bl6_elements} }\n"
    fi
    ruleset+="    }\n\n"

    # --- DMZ / Trusted set ---
    ruleset+="    set trusted_v4 {\n"
    ruleset+="        type ipv4_addr\n"
    ruleset+="        flags interval\n"
    local dmz_elements=""
    for entry in $TRUSTED_IPS; do
        local resolved
        resolved=$(resolve_hostname "$entry" 2>/dev/null) || continue
        [[ -n "$dmz_elements" ]] && dmz_elements+=", "
        dmz_elements+="$resolved"
    done
    if [[ -n "$dmz_elements" ]]; then
        ruleset+="        elements = { ${dmz_elements} }\n"
    fi
    ruleset+="    }\n\n"

    ruleset+="    set trusted_v6 {\n"
    ruleset+="        type ipv6_addr\n"
    ruleset+="        flags interval\n"
    local dmz6_elements=""
    for ip in $TRUSTED_IPS_IPV6; do
        [[ -n "$dmz6_elements" ]] && dmz6_elements+=", "
        dmz6_elements+="$ip"
    done
    if [[ -n "$dmz6_elements" ]]; then
        ruleset+="        elements = { ${dmz6_elements} }\n"
    fi
    ruleset+="    }\n\n"

    # --- INPUT chain ---
    ruleset+="    chain input {\n"
    ruleset+="        type filter hook input priority 0; policy drop;\n"
    ruleset+="\n"
    ruleset+="        # Loopback\n"
    ruleset+="        iif lo accept\n"
    ruleset+="\n"
    ruleset+="        # Connection tracking\n"
    ruleset+="        ct state established,related accept\n"
    ruleset+="        ct state invalid drop\n"
    ruleset+="\n"
    ruleset+="        # Blacklists\n"
    ruleset+="        ip saddr @blacklist_v4 drop\n"
    ruleset+="        ip6 saddr @blacklist_v6 drop\n"
    ruleset+="\n"

    # Blocked port ranges
    if [[ -n "${BLOCKED_TCP_PORTS:-}" ]]; then
        for port in $BLOCKED_TCP_PORTS; do
            ruleset+="        tcp dport ${port} drop\n"
        done
    fi
    if [[ -n "${BLOCKED_UDP_PORTS:-}" ]]; then
        for port in $BLOCKED_UDP_PORTS; do
            ruleset+="        udp dport ${port} drop\n"
        done
    fi

    ruleset+="\n"
    ruleset+="        # Trusted IPs - full access\n"
    ruleset+="        ip saddr @trusted_v4 accept\n"
    ruleset+="        ip6 saddr @trusted_v6 accept\n"
    ruleset+="\n"

    # Trusted IP ranges
    if [[ -n "${TRUSTED_RANGES:-}" ]]; then
        for range in $TRUSTED_RANGES; do
            ruleset+="        ip saddr ${range} accept\n"
        done
    fi
    if [[ -n "${TRUSTED_RANGES_IPV6:-}" ]]; then
        for range in $TRUSTED_RANGES_IPV6; do
            ruleset+="        ip6 saddr ${range} accept\n"
        done
    fi

    # Blocked ranges
    if [[ -n "${BLOCKED_RANGES:-}" ]]; then
        for range in $BLOCKED_RANGES; do
            ruleset+="        ip saddr ${range} drop\n"
        done
    fi
    if [[ -n "${BLOCKED_RANGES_IPV6:-}" ]]; then
        for range in $BLOCKED_RANGES_IPV6; do
            ruleset+="        ip6 saddr ${range} drop\n"
        done
    fi

    ruleset+="\n"

    # SSH access restrictions
    if [[ -n "${SSH_ALLOWED_IPS:-}" ]]; then
        ruleset+="        # SSH access (restricted)\n"
        for ip in $SSH_ALLOWED_IPS; do
            local resolved
            resolved=$(resolve_hostname "$ip" 2>/dev/null) || continue
            ruleset+="        ip saddr ${resolved} tcp dport ${ssh_port} accept\n"
        done
    fi
    if [[ -n "${SSH_ALLOWED_IPS_IPV6:-}" ]]; then
        for ip in $SSH_ALLOWED_IPS_IPV6; do
            ruleset+="        ip6 saddr ${ip} tcp dport ${ssh_port} accept\n"
        done
    fi

    # Port-specific IP restrictions
    if [[ -n "${PORT_IP_RULES:-}" ]]; then
        ruleset+="\n        # Port-specific IP access rules\n"
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
                if is_valid_ipv6 "$resolved"; then
                    ruleset+="        ip6 saddr ${resolved} ${proto} dport ${port_num} accept\n"
                else
                    ruleset+="        ip saddr ${resolved} ${proto} dport ${port_num} accept\n"
                fi
            fi
            IFS=$'\n'
        done
        IFS="$IFS_OLD"
    fi

    # TCP ports (bidirectional)
    if [[ -n "${TCP_PORTS:-}" ]]; then
        local tcp_list
        tcp_list=$(echo "$TCP_PORTS" | tr ' ' ',')
        ruleset+="\n        # Open TCP ports\n"
        ruleset+="        tcp dport { ${tcp_list} } accept\n"
    fi

    # TCP input-only ports
    if [[ -n "${TCP_PORTS_INPUT:-}" ]]; then
        local tcp_in_list
        tcp_in_list=$(echo "$TCP_PORTS_INPUT" | tr ' ' ',')
        ruleset+="        tcp dport { ${tcp_in_list} } accept\n"
    fi

    # UDP ports
    if [[ -n "${UDP_PORTS:-}" ]]; then
        local udp_list
        udp_list=$(echo "$UDP_PORTS" | tr ' ' ',')
        ruleset+="\n        # Open UDP ports\n"
        ruleset+="        udp dport { ${udp_list} } accept\n"
    fi

    # ICMP
    if [[ "${ICMP_ENABLE:-true}" == "true" ]]; then
        ruleset+="\n        # ICMP (IPv4)\n"
        ruleset+="        ip protocol icmp icmp type { echo-reply, destination-unreachable, echo-request, time-exceeded, parameter-problem } accept\n"
        ruleset+="\n        # ICMPv6 (required for IPv6 to function)\n"
        ruleset+="        ip6 nexthdr icmpv6 icmpv6 type { echo-reply, echo-request, destination-unreachable, packet-too-big, time-exceeded, parameter-problem, nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept\n"
    fi

    # Multicast
    if [[ "${MULTICAST_ENABLE:-false}" == "true" ]]; then
        ruleset+="\n        # Multicast\n"
        ruleset+="        pkttype multicast accept\n"
        ruleset+="        pkttype broadcast accept\n"
        ruleset+="        ip daddr 224.0.0.0/4 accept\n"
        ruleset+="        ip6 daddr ff00::/8 accept\n"
    fi

    # SYN flood protection
    if [[ "${SYN_FLOOD_PROTECT:-true}" == "true" ]]; then
        ruleset+="\n        # SYN flood protection\n"
        ruleset+="        tcp flags syn limit rate 1/second burst 3 accept\n"
    fi

    # Connection limit per IP
    if [[ "${CONN_LIMIT_ENABLE:-false}" == "true" ]]; then
        local conn_limit="${CONN_LIMIT_PER_IP:-50}"
        ruleset+="\n        # Connection limit per IP\n"
        ruleset+="        ct state new tcp flags syn ct count over ${conn_limit} drop\n"
    fi

    # Block common attack ports
    if [[ "${BLOCK_COMMON_ATTACKS:-true}" == "true" ]]; then
        ruleset+="\n        # Block common attack ports\n"
        ruleset+="        tcp dport { 23, 135, 137-139, 445, 1900 } drop\n"
        ruleset+="        udp dport { 23, 135, 137-139, 445, 1900 } drop\n"
    fi

    # Rate limiting (DDoS protection)
    if [[ "${RATE_LIMIT_ENABLE:-true}" == "true" ]]; then
        local rate="${RATE_LIMIT_RATE:-25/second}"
        local burst="${RATE_LIMIT_BURST:-100}"
        ruleset+="\n        # Rate limiting for new connections\n"
        ruleset+="        ct state new limit rate ${rate} burst ${burst} packets accept\n"
    fi

    # Logging
    if [[ "${LOG_DROPPED:-true}" == "true" ]]; then
        ruleset+="\n        # Log dropped packets\n"
        ruleset+="        limit rate 5/minute burst 10 packets log prefix \"binadit-drop: \" level warn\n"
    fi

    ruleset+="    }\n\n"

    # --- OUTPUT chain ---
    ruleset+="    chain output {\n"
    ruleset+="        type filter hook output priority 0; policy drop;\n"
    ruleset+="\n"
    ruleset+="        # Loopback\n"
    ruleset+="        oif lo accept\n"
    ruleset+="\n"
    ruleset+="        # Connection tracking\n"
    ruleset+="        ct state established,related accept\n"
    ruleset+="\n"
    ruleset+="        # DNS\n"
    ruleset+="        tcp dport 53 accept\n"
    ruleset+="        udp dport 53 accept\n"
    ruleset+="\n"

    # NTP
    ruleset+="        # NTP\n"
    ruleset+="        udp dport 123 accept\n"
    ruleset+="\n"

    # SSH outgoing for restricted IPs
    if [[ -n "${SSH_ALLOWED_IPS:-}" || -n "${SSH_ALLOWED_IPS_IPV6:-}" ]]; then
        ruleset+="        # SSH\n"
        ruleset+="        tcp dport ${ssh_port} accept\n"
    fi

    # TCP ports (bidirectional)
    if [[ -n "${TCP_PORTS:-}" ]]; then
        local tcp_list
        tcp_list=$(echo "$TCP_PORTS" | tr ' ' ',')
        ruleset+="        tcp dport { ${tcp_list} } accept\n"
        ruleset+="        tcp sport { ${tcp_list} } accept\n"
    fi

    # TCP output-only ports
    if [[ -n "${TCP_PORTS_OUTPUT:-}" ]]; then
        local tcp_out_list
        tcp_out_list=$(echo "$TCP_PORTS_OUTPUT" | tr ' ' ',')
        ruleset+="        tcp dport { ${tcp_out_list} } accept\n"
    fi

    # UDP ports
    if [[ -n "${UDP_PORTS:-}" ]]; then
        local udp_list
        udp_list=$(echo "$UDP_PORTS" | tr ' ' ',')
        ruleset+="        udp dport { ${udp_list} } accept\n"
        ruleset+="        udp sport { ${udp_list} } accept\n"
    fi

    # Trusted IPs output
    ruleset+="\n        # Trusted IPs\n"
    ruleset+="        ip daddr @trusted_v4 accept\n"
    ruleset+="        ip6 daddr @trusted_v6 accept\n"

    # Trusted ranges output
    if [[ -n "${TRUSTED_RANGES:-}" ]]; then
        for range in $TRUSTED_RANGES; do
            ruleset+="        ip daddr ${range} accept\n"
        done
    fi
    if [[ -n "${TRUSTED_RANGES_IPV6:-}" ]]; then
        for range in $TRUSTED_RANGES_IPV6; do
            ruleset+="        ip6 daddr ${range} accept\n"
        done
    fi

    # SMTP
    if [[ "${SMTP_ENABLE:-true}" == "true" ]]; then
        ruleset+="\n        # SMTP outgoing\n"
        ruleset+="        tcp dport 25 accept\n"
        ruleset+="        tcp dport 587 accept\n"
    fi

    # ICMP output
    if [[ "${ICMP_ENABLE:-true}" == "true" ]]; then
        ruleset+="\n        # ICMP\n"
        ruleset+="        ip protocol icmp accept\n"
        ruleset+="        ip6 nexthdr icmpv6 accept\n"
    fi

    # Multicast output
    if [[ "${MULTICAST_ENABLE:-false}" == "true" ]]; then
        ruleset+="\n        # Multicast\n"
        ruleset+="        pkttype multicast accept\n"
        ruleset+="        pkttype broadcast accept\n"
        ruleset+="        ip daddr 224.0.0.0/4 accept\n"
        ruleset+="        ip6 daddr ff00::/8 accept\n"
    fi

    if [[ "${LOG_DROPPED:-true}" == "true" ]]; then
        ruleset+="\n        # Log dropped packets\n"
        ruleset+="        limit rate 5/minute burst 10 packets log prefix \"binadit-drop-out: \" level warn\n"
    fi

    ruleset+="    }\n\n"

    # --- FORWARD chain ---
    ruleset+="    chain forward {\n"
    ruleset+="        type filter hook forward priority 0; policy drop;\n"

    if [[ "${NAT_ENABLE:-false}" == "true" ]]; then
        ruleset+="\n        # NAT forwarding\n"
        ruleset+="        ct state established,related accept\n"
        local iface="${NAT_INTERNAL_IFACE:-eth1}"
        ruleset+="        iif ${iface} accept\n"
        ruleset+="        oif ${iface} accept\n"
    fi

    ruleset+="    }\n"

    # --- NAT table ---
    if [[ "${NAT_ENABLE:-false}" == "true" ]]; then
        local ext_iface="${NAT_EXTERNAL_IFACE:-eth0}"

        # Port forwarding (DNAT)
        if [[ -n "${PORT_FORWARD_RULES:-}" ]]; then
            ruleset+="\n    chain prerouting {\n"
            ruleset+="        type nat hook prerouting priority -100;\n"
            local IFS_OLD="$IFS"
            IFS=$'\n'
            for rule in $PORT_FORWARD_RULES; do
                IFS="$IFS_OLD"
                local proto ext_port int_dest
                proto=$(echo "$rule" | awk -F'|' '{print $1}' | xargs)
                ext_port=$(echo "$rule" | awk -F'|' '{print $2}' | xargs)
                int_dest=$(echo "$rule" | awk -F'|' '{print $3}' | xargs)
                if [[ -n "$proto" && -n "$ext_port" && -n "$int_dest" ]]; then
                    ruleset+="        ${proto} dport ${ext_port} dnat to ${int_dest}\n"
                fi
                IFS=$'\n'
            done
            IFS="$IFS_OLD"
            ruleset+="    }\n"
        fi

        ruleset+="\n    chain postrouting {\n"
        ruleset+="        type nat hook postrouting priority 100;\n"
        ruleset+="        oif ${ext_iface} masquerade\n"
        ruleset+="    }\n"
    fi

    ruleset+="}\n"

    # Write and apply
    local rules_file="/etc/binadit-firewall/rules.nft"
    mkdir -p /etc/binadit-firewall
    echo -e "$ruleset" > "$rules_file"

    # Apply with nft
    # We need to handle the delete separately since it may fail if table doesn't exist
    nft delete table inet "$NFT_TABLE_NAME" 2>/dev/null || true

    # Apply the ruleset (skip the delete line and shebang)
    local apply_file
    apply_file=$(mktemp)
    grep -v "^delete table" "$rules_file" | grep -v "^#!" > "$apply_file" || true
    if nft -f "$apply_file" 2>/dev/null; then
        log_success "nftables rules applied successfully"
    else
        log_error "Failed to apply nftables rules. Check $rules_file for syntax errors."
        rm -f "$apply_file"
        return 1
    fi
    rm -f "$apply_file"

    # Enable IP forwarding if NAT is enabled
    if [[ "${NAT_ENABLE:-false}" == "true" ]]; then
        echo 1 > /proc/sys/net/ipv4/ip_forward
        log_info "IP forwarding enabled"
    fi
}

# Show current nftables status
nft_status() {
    log_header "nftables Status (binadit-firewall)"
    if nft list table inet "$NFT_TABLE_NAME" 2>/dev/null; then
        return 0
    else
        log_warn "No binadit-firewall rules loaded"
        return 1
    fi
}
