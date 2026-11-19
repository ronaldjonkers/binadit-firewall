#!/usr/bin/env bash
# =============================================================================
# binadit-firewall - nftables backend implementation
# =============================================================================
# All firewall operations using native nftables (nft) commands.
#
# The complete ruleset is generated into one file and loaded in a single
# transaction: either the new rules are fully active, or (on any error) the
# previous rules stay untouched. There is never a moment without a firewall.
# =============================================================================

readonly NFT_TABLE_NAME="binadit"
readonly NFT_NAT_TABLE_NAME="binadit_nat"

# Match for "first packet of a new TCP connection"
readonly NFT_SYN='tcp flags & (fin | syn | rst | ack) == syn'

# Convert a config port list ("80 443 8000:9000") to an nft set body
# ("80, 443, 8000-9000"), removing duplicates.
_nft_port_set() {
    local out="" p seen=" "
    for p in "$@"; do
        p="${p/:/-}"
        [[ "$seen" == *" $p "* ]] && continue
        seen+="$p "
        out+="${out:+, }$p"
    done
    echo "$out"
}

# Emit a named interval set
_nft_emit_set() {
    local name="$1" type="$2"
    shift 2
    echo "    set ${name} {"
    echo "        type ${type}"
    echo "        flags interval"
    echo "        auto-merge"
    if (( $# > 0 )); then
        echo "        elements = { $(join_comma "$@") }"
    fi
    echo "    }"
    echo ""
}

# Print the complete ruleset for the loaded configuration.
# Requires: load_config and resolve_config_hosts have run.
nft_build_ruleset() {
    local T="$NFT_TABLE_NAME" N="$NFT_NAT_TABLE_NAME"
    local ssh_set tcp_set udp_set line p a

    ssh_set=$(_nft_port_set $SSH_PORTS)

    echo "#!/usr/sbin/nft -f"
    echo "# binadit-firewall v${BINADIT_VERSION} - generated $(date '+%Y-%m-%d %H:%M:%S')"
    echo "# Do not edit manually - managed by binadit-firewall"
    echo ""
    echo "# Replace our tables in one atomic transaction"
    echo "table inet ${T}"
    echo "delete table inet ${T}"
    echo "table ip ${N}"
    echo "delete table ip ${N}"
    echo ""
    echo "table inet ${T} {"

    # ---- Address sets -------------------------------------------------------
    collect_addrs $BLACKLIST $BLACKLIST_IPV6 $BLOCKED_RANGES $BLOCKED_RANGES_IPV6
    _nft_emit_set blacklist_v4 ipv4_addr ${ADDR4[@]+"${ADDR4[@]}"}
    _nft_emit_set blacklist_v6 ipv6_addr ${ADDR6[@]+"${ADDR6[@]}"}

    collect_addrs $TRUSTED_IPS $TRUSTED_IPS_IPV6 $TRUSTED_RANGES $TRUSTED_RANGES_IPV6
    _nft_emit_set trusted_v4 ipv4_addr ${ADDR4[@]+"${ADDR4[@]}"}
    _nft_emit_set trusted_v6 ipv6_addr ${ADDR6[@]+"${ADDR6[@]}"}

    collect_addrs $SSH_ALLOWED_IPS $SSH_ALLOWED_IPS_IPV6
    _nft_emit_set ssh_allowed_v4 ipv4_addr ${ADDR4[@]+"${ADDR4[@]}"}
    _nft_emit_set ssh_allowed_v6 ipv6_addr ${ADDR6[@]+"${ADDR6[@]}"}

    # ---- INPUT --------------------------------------------------------------
    echo "    chain input {"
    echo "        type filter hook input priority 0; policy drop;"
    echo ""
    echo "        # Loopback"
    echo "        iif lo accept"
    echo ""
    echo "        # Blacklist: blocked completely, including existing connections"
    echo "        ip saddr @blacklist_v4 drop"
    echo "        ip6 saddr @blacklist_v6 drop"
    echo ""
    echo "        # Connection tracking"
    echo "        ct state established,related accept"
    if [[ "$DROP_INVALID" == "true" ]]; then
        echo "        ct state invalid drop"
    fi

    if [[ -n "${BLOCKED_TCP_PORTS// /}" ]]; then
        echo ""
        echo "        # Blocked TCP ports (override everything below, including trusted IPs)"
        echo "        tcp dport { $(_nft_port_set $BLOCKED_TCP_PORTS) } drop"
    fi
    if [[ -n "${BLOCKED_UDP_PORTS// /}" ]]; then
        echo ""
        echo "        # Blocked UDP ports"
        echo "        udp dport { $(_nft_port_set $BLOCKED_UDP_PORTS) } drop"
    fi

    echo ""
    echo "        # Trusted IPs - full access, exempt from all limits"
    echo "        ip saddr @trusted_v4 accept"
    echo "        ip6 saddr @trusted_v6 accept"
    echo ""
    echo "        # ICMPv6 that IPv6 cannot work without (never blocked)"
    echo "        icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem, nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept"
    echo "        # DHCPv6 replies to this host"
    echo "        ip6 saddr fe80::/10 udp dport 546 accept"

    if ssh_is_restricted; then
        echo ""
        echo "        # SSH allow-list (accepted before any rate limit: admins are never throttled)"
        echo "        ip saddr @ssh_allowed_v4 tcp dport { ${ssh_set} } accept"
        echo "        ip6 saddr @ssh_allowed_v6 tcp dport { ${ssh_set} } accept"
    fi

    if [[ "$SYN_FLOOD_PROTECT" == "true" ]]; then
        echo ""
        echo "        # SYN flood protection: drop TCP packets with impossible flag combinations"
        echo "        # (kernel SYN cookies are enabled separately)"
        echo "        tcp flags & (fin | syn) == fin | syn drop"
        echo "        tcp flags & (syn | rst) == syn | rst drop"
        echo "        tcp flags & (fin | syn | rst | psh | ack | urg) == 0x0 drop"
    fi

    if [[ "$CONN_LIMIT_ENABLE" == "true" ]]; then
        echo ""
        echo "        # Max concurrent TCP connections per source IP (IPv6: per /64)"
        echo "        ${NFT_SYN} meter connlimit_v4 size 65535 { ip saddr ct count over ${CONN_LIMIT_PER_IP} } drop"
        echo "        ${NFT_SYN} meter connlimit_v6 size 65535 { ip6 saddr & ffff:ffff:ffff:ffff:: ct count over ${CONN_LIMIT_PER_IP} } drop"
    fi

    if [[ "${CONN_RATE_PER_IP:-0}" =~ ^[0-9]+$ ]] && (( 10#${CONN_RATE_PER_IP:-0} > 0 )); then
        local cr=$((10#$CONN_RATE_PER_IP))
        echo ""
        echo "        # Hard cap: new TCP connections per second per source IP"
        echo "        ${NFT_SYN} meter connrate_v4 size 65535 { ip saddr timeout 60s limit rate over ${cr}/second burst ${cr} packets } drop"
        echo "        ${NFT_SYN} meter connrate_v6 size 65535 { ip6 saddr & ffff:ffff:ffff:ffff:: timeout 60s limit rate over ${cr}/second burst ${cr} packets } drop"
    fi

    if [[ "$RATE_LIMIT_ENABLE" == "true" ]]; then
        local rate="$RATE_LIMIT_RATE"
        [[ "$rate" == */* ]] || rate="${rate}/second"
        echo ""
        echo "        # Rate limit: new TCP connections per source IP, with burst allowance"
        echo "        ${NFT_SYN} meter ratelimit_v4 size 65535 { ip saddr timeout 60s limit rate over ${rate} burst ${RATE_LIMIT_BURST} packets } drop"
        echo "        ${NFT_SYN} meter ratelimit_v6 size 65535 { ip6 saddr & ffff:ffff:ffff:ffff:: timeout 60s limit rate over ${rate} burst ${RATE_LIMIT_BURST} packets } drop"
    fi

    if [[ -n "${PORT_IP_RULES// /}" ]]; then
        echo ""
        echo "        # Port-specific IP access rules"
        while IFS= read -r line; do
            [[ -z "${line// /}" ]] && continue
            split_rule "$line"
            [[ -n "$R1" && -n "$R2" && -n "$R3" ]] || continue
            collect_addrs "$R3"
            for a in ${ADDR4[@]+"${ADDR4[@]}"}; do
                echo "        ip saddr ${a} ${R1} dport ${R2/:/-} accept"
            done
            for a in ${ADDR6[@]+"${ADDR6[@]}"}; do
                echo "        ip6 saddr ${a} ${R1} dport ${R2/:/-} accept"
            done
        done <<< "$PORT_IP_RULES"
    fi

    echo ""
    if ssh_is_restricted; then
        echo "        # SSH is restricted: everyone not accepted above is refused,"
        echo "        # even when the SSH port is also listed in TCP_PORTS"
        echo "        tcp dport { ${ssh_set} } drop"
    else
        echo "        # SSH: always reachable (prevents lockout)"
        echo "        tcp dport { ${ssh_set} } accept"
    fi

    tcp_set=$(_nft_port_set $(public_tcp_ports))
    if [[ -n "$tcp_set" ]]; then
        echo ""
        echo "        # Open TCP ports"
        echo "        tcp dport { ${tcp_set} } accept"
    fi
    udp_set=$(_nft_port_set $UDP_PORTS)
    if [[ -n "$udp_set" ]]; then
        echo ""
        echo "        # Open UDP ports"
        echo "        udp dport { ${udp_set} } accept"
    fi

    echo ""
    if [[ "$ICMP_ENABLE" == "true" ]]; then
        echo "        # Ping"
        echo "        icmp type echo-request accept"
        echo "        icmpv6 type echo-request accept"
    else
        echo "        # Ping disabled"
        echo "        icmp type echo-request drop"
        echo "        icmpv6 type echo-request drop"
    fi

    if [[ "$MULTICAST_ENABLE" == "true" ]]; then
        echo ""
        echo "        # Multicast / broadcast"
        echo "        meta pkttype { multicast, broadcast } accept"
        echo "        ip daddr 224.0.0.0/4 accept"
        echo "        ip6 daddr ff00::/8 accept"
    fi

    if [[ "$BLOCK_COMMON_ATTACKS" == "true" ]]; then
        echo ""
        echo "        # Common attack ports: dropped silently (kept out of the log)"
        echo "        tcp dport { 23, 135, 137-139, 445, 1900 } drop"
        echo "        udp dport { 23, 135, 137-139, 445, 1900 } drop"
    fi

    if [[ "$LOG_DROPPED" == "true" ]]; then
        echo ""
        echo "        # Log what is about to be dropped by the chain policy"
        echo "        limit rate 5/minute burst 10 packets log prefix \"binadit-drop: \" level warn"
    fi
    echo "    }"
    echo ""

    # ---- OUTPUT -------------------------------------------------------------
    echo "    chain output {"
    echo "        type filter hook output priority 0; policy accept;"
    echo ""
    echo "        oif lo accept"
    echo "        ip daddr @blacklist_v4 drop"
    echo "        ip6 daddr @blacklist_v6 drop"
    tcp_set=$(_nft_port_set $BLOCKED_TCP_PORTS $BLOCKED_TCP_PORTS_OUTPUT)
    if [[ -n "$tcp_set" ]]; then
        echo "        # Blocked outgoing TCP ports"
        echo "        tcp dport { ${tcp_set} } drop"
    fi
    udp_set=$(_nft_port_set $BLOCKED_UDP_PORTS $BLOCKED_UDP_PORTS_OUTPUT)
    if [[ -n "$udp_set" ]]; then
        echo "        # Blocked outgoing UDP ports"
        echo "        udp dport { ${udp_set} } drop"
    fi
    echo "    }"
    echo ""

    # ---- FORWARD ------------------------------------------------------------
    echo "    chain forward {"
    echo "        type filter hook forward priority 0; policy drop;"
    if [[ "$NAT_ENABLE" == "true" ]]; then
        echo ""
        echo "        ip saddr @blacklist_v4 drop"
        echo "        ip daddr @blacklist_v4 drop"
        echo "        ct state established,related accept"
        if [[ "$DROP_INVALID" == "true" ]]; then
            echo "        ct state invalid drop"
        fi
        echo "        # LAN -> anywhere"
        echo "        iifname \"${NAT_INTERNAL_IFACE}\" accept"
        echo "        # Port forwards (DNAT) -> LAN"
        echo "        ct status dnat accept"
    fi
    echo "    }"
    echo "}"

    # ---- NAT (separate IPv4 table: works on every kernel) -------------------
    if [[ "$NAT_ENABLE" == "true" ]]; then
        echo ""
        echo "table ip ${N} {"
        echo "    chain prerouting {"
        echo "        type nat hook prerouting priority -100; policy accept;"
        while IFS= read -r line; do
            [[ -z "${line// /}" ]] && continue
            split_rule "$line"
            [[ -n "$R1" && -n "$R2" && -n "$R3" ]] || continue
            echo "        iifname \"${NAT_EXTERNAL_IFACE}\" ${R1} dport ${R2/:/-} dnat to ${R3}"
        done <<< "${PORT_FORWARD_RULES:-}"
        echo "    }"
        echo ""
        echo "    chain postrouting {"
        echo "        type nat hook postrouting priority 100; policy accept;"
        echo "        oifname \"${NAT_EXTERNAL_IFACE}\" masquerade"
        echo "    }"
        echo "}"
    fi
}

# Generate the ruleset and verify it with the kernel without applying it.
# Prints errors; returns 1 when the ruleset would not load.
nft_check() {
    local rules_file="$1" out
    nft_build_ruleset > "$rules_file"
    if ! out=$(nft -c -f "$rules_file" 2>&1); then
        log_error "The generated nftables ruleset is not valid:"
        while IFS= read -r line; do
            log_error "  $line"
        done <<< "$out"
        return 1
    fi
    return 0
}

# Build and atomically apply the ruleset.
# Requires: load_config and resolve_config_hosts have run.
nft_apply() {
    local rules_file="${CONFIG_DIR}/rules.nft"
    local new_file="${rules_file}.new"
    mkdir -p "$CONFIG_DIR"

    log_info "Building nftables ruleset..."
    if ! nft_check "$new_file"; then
        log_error "Firewall rules were NOT changed (ruleset kept in ${new_file})"
        return 1
    fi

    local out
    if ! out=$(nft -f "$new_file" 2>&1); then
        log_error "Failed to apply nftables rules (previous rules are still active):"
        while IFS= read -r line; do
            log_error "  $line"
        done <<< "$out"
        return 1
    fi
    mv -f "$new_file" "$rules_file"
    log_success "nftables rules applied"

    # Custom rules file (nft syntax, loaded after the managed ruleset)
    if [[ -n "${CUSTOM_RULES_FILE:-}" ]] && [[ -f "${CUSTOM_RULES_FILE}" ]]; then
        log_info "Loading custom rules from ${CUSTOM_RULES_FILE}..."
        if out=$(nft -f "${CUSTOM_RULES_FILE}" 2>&1); then
            log_success "Custom rules loaded"
        else
            log_warn "Failed to load custom rules from ${CUSTOM_RULES_FILE}:"
            while IFS= read -r line; do
                log_warn "  $line"
            done <<< "$out"
        fi
    fi
    return 0
}

# Remove all rules managed by binadit-firewall
nft_flush() {
    log_info "Removing nftables rules..."
    nft delete table inet "$NFT_TABLE_NAME" 2>/dev/null || true
    nft delete table ip "$NFT_NAT_TABLE_NAME" 2>/dev/null || true
    log_success "nftables rules removed"
}

# True when our ruleset is loaded
nft_is_active() {
    nft list chain inet "$NFT_TABLE_NAME" input &>/dev/null
}

# Show current nftables status
nft_status() {
    nft list table inet "$NFT_TABLE_NAME" 2>/dev/null || return 1
    nft list table ip "$NFT_NAT_TABLE_NAME" 2>/dev/null || true
}
