#!/usr/bin/env bash
# =============================================================================
# binadit-firewall - iptables backend implementation
# =============================================================================
# All firewall operations using iptables/ip6tables.
# Supports both iptables-legacy and iptables-nft variants.
#
# Rules are generated in iptables-restore format, verified with
# "iptables-restore --test" and then committed in one transaction per table.
# A broken rule can therefore never leave a half-configured firewall behind.
# =============================================================================

# Marker chain: its existence means "binadit-firewall rules are loaded"
readonly IPT_MARKER_CHAIN="binadit-firewall"
readonly IPT_LOG_CHAIN="BINADIT-LOG"

# hashlimit keeps its per-IP table in the kernel under the rule's name, and a
# reload re-uses an existing table WITH ITS OLD SETTINGS. Put the settings in
# the name so that changed limits always get a fresh table. (max 15 chars)
_ipt_hl_name() {
    local kind="$1" fam="$2" params="$3" sum
    sum=$(printf '%s' "$params" | cksum)
    echo "bfw${kind}${fam}-${sum%% *}" | cut -c1-15
}

# Emit "-A <chain> <src/dst match> <rest>" for one address (CIDR or a-b range)
# $1 chain  $2 s|d (source/destination)  $3 address  $4... rest of the rule
_ipt_addr_rule() {
    local chain="$1" dir="$2" addr="$3"
    shift 3
    if [[ "$addr" == *-* ]]; then
        local opt="--src-range"
        [[ "$dir" == "d" ]] && opt="--dst-range"
        echo "-A ${chain} -m iprange ${opt} ${addr} $*"
    else
        echo "-A ${chain} -${dir} ${addr} $*"
    fi
}

# Print the ruleset in iptables-restore format for one address family.
# $1 = 4 or 6, $2 = true when the nat table should be included (IPv4 only)
# Requires: load_config and resolve_config_hosts have run.
ipt_build_ruleset() {
    local fam="$1" with_nat="${2:-false}"
    local p a line
    local -a addrs=()

    # Select the address list of the requested family after collect_addrs
    _fam_addrs() {
        if [[ "$fam" == "4" ]]; then
            addrs=(${ADDR4[@]+"${ADDR4[@]}"})
        else
            addrs=(${ADDR6[@]+"${ADDR6[@]}"})
        fi
    }

    local mask="32" hl_mask="" icmp_proto="icmp" suffix="4"
    if [[ "$fam" == "6" ]]; then
        mask="64"; hl_mask=" --hashlimit-srcmask 64"; icmp_proto="ipv6-icmp"; suffix="6"
    fi

    echo "# binadit-firewall v${BINADIT_VERSION} - IPv${fam} - generated $(date '+%Y-%m-%d %H:%M:%S')"
    echo "# Do not edit manually - managed by binadit-firewall"
    echo "*filter"
    echo ":INPUT DROP [0:0]"
    echo ":FORWARD DROP [0:0]"
    echo ":OUTPUT ACCEPT [0:0]"
    echo ":${IPT_MARKER_CHAIN} - [0:0]"
    echo ":${IPT_LOG_CHAIN} - [0:0]"

    # Loopback
    echo "-A INPUT -i lo -j ACCEPT"
    echo "-A OUTPUT -o lo -j ACCEPT"

    # Blacklist: blocked completely (in and out), including existing connections
    collect_addrs $BLACKLIST $BLACKLIST_IPV6 $BLOCKED_RANGES $BLOCKED_RANGES_IPV6
    _fam_addrs
    local -a blacklist=(${addrs[@]+"${addrs[@]}"})
    for a in ${blacklist[@]+"${blacklist[@]}"}; do
        _ipt_addr_rule INPUT s "$a" -j DROP
        _ipt_addr_rule OUTPUT d "$a" -j DROP
    done

    # Connection tracking
    echo "-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
    if [[ "$DROP_INVALID" == "true" ]]; then
        echo "-A INPUT -m conntrack --ctstate INVALID -j DROP"
    fi

    # Blocked ports (override everything below, including trusted IPs)
    for p in $BLOCKED_TCP_PORTS; do
        echo "-A INPUT -p tcp --dport ${p} -j DROP"
        echo "-A OUTPUT -p tcp --dport ${p} -j DROP"
    done
    for p in $BLOCKED_UDP_PORTS; do
        echo "-A INPUT -p udp --dport ${p} -j DROP"
        echo "-A OUTPUT -p udp --dport ${p} -j DROP"
    done
    for p in $BLOCKED_TCP_PORTS_OUTPUT; do
        echo "-A OUTPUT -p tcp --dport ${p} -j DROP"
    done
    for p in $BLOCKED_UDP_PORTS_OUTPUT; do
        echo "-A OUTPUT -p udp --dport ${p} -j DROP"
    done

    # Trusted IPs - full access, exempt from all limits
    collect_addrs $TRUSTED_IPS $TRUSTED_IPS_IPV6 $TRUSTED_RANGES $TRUSTED_RANGES_IPV6
    _fam_addrs
    for a in ${addrs[@]+"${addrs[@]}"}; do
        _ipt_addr_rule INPUT s "$a" -j ACCEPT
    done

    if [[ "$fam" == "6" ]]; then
        # ICMPv6 that IPv6 cannot work without (never blocked)
        local t
        for t in destination-unreachable packet-too-big time-exceeded parameter-problem \
                 router-solicitation router-advertisement neighbour-solicitation neighbour-advertisement; do
            echo "-A INPUT -p ipv6-icmp --icmpv6-type ${t} -j ACCEPT"
        done
        # DHCPv6 replies to this host
        echo "-A INPUT -s fe80::/10 -p udp --dport 546 -j ACCEPT"
    fi

    # SSH allow-list (accepted before any rate limit: admins are never throttled)
    if ssh_is_restricted; then
        collect_addrs $SSH_ALLOWED_IPS $SSH_ALLOWED_IPS_IPV6
        _fam_addrs
        for a in ${addrs[@]+"${addrs[@]}"}; do
            for p in $SSH_PORTS; do
                _ipt_addr_rule INPUT s "$a" -p tcp --dport "$p" -j ACCEPT
            done
        done
    fi

    # SYN flood protection: drop TCP packets with impossible flag combinations
    if [[ "$SYN_FLOOD_PROTECT" == "true" ]]; then
        echo "-A INPUT -p tcp --tcp-flags FIN,SYN FIN,SYN -j DROP"
        echo "-A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP"
        echo "-A INPUT -p tcp --tcp-flags ALL NONE -j DROP"
    fi

    # Max concurrent TCP connections per source IP (IPv6: per /64)
    if [[ "$CONN_LIMIT_ENABLE" == "true" ]]; then
        echo "-A INPUT -p tcp --syn -m connlimit --connlimit-above ${CONN_LIMIT_PER_IP} --connlimit-mask ${mask} -j DROP"
    fi

    # Hard cap: new TCP connections per second per source IP
    if [[ "${CONN_RATE_PER_IP:-0}" =~ ^[0-9]+$ ]] && (( 10#${CONN_RATE_PER_IP:-0} > 0 )); then
        local cr=$((10#$CONN_RATE_PER_IP))
        echo "-A INPUT -p tcp --syn -m hashlimit --hashlimit-name $(_ipt_hl_name c "$suffix" "$cr") --hashlimit-mode srcip${hl_mask} --hashlimit-above ${cr}/second --hashlimit-burst ${cr} --hashlimit-htable-expire 60000 -j DROP"
    fi

    # Rate limit: new TCP connections per source IP, with burst allowance
    if [[ "$RATE_LIMIT_ENABLE" == "true" ]]; then
        local rate="$RATE_LIMIT_RATE"
        [[ "$rate" == */* ]] || rate="${rate}/second"
        echo "-A INPUT -p tcp --syn -m hashlimit --hashlimit-name $(_ipt_hl_name r "$suffix" "${rate}-${RATE_LIMIT_BURST}") --hashlimit-mode srcip${hl_mask} --hashlimit-above ${rate} --hashlimit-burst ${RATE_LIMIT_BURST} --hashlimit-htable-expire 60000 -j DROP"
    fi

    # Port-specific IP access rules
    while IFS= read -r line; do
        [[ -z "${line// /}" ]] && continue
        split_rule "$line"
        [[ -n "$R1" && -n "$R2" && -n "$R3" ]] || continue
        collect_addrs "$R3"
        _fam_addrs
        for a in ${addrs[@]+"${addrs[@]}"}; do
            _ipt_addr_rule INPUT s "$a" -p "$R1" --dport "$R2" -j ACCEPT
        done
    done <<< "${PORT_IP_RULES:-}"

    # SSH
    for p in $SSH_PORTS; do
        if ssh_is_restricted; then
            # Everyone not accepted above is refused, even when the SSH port
            # is also listed in TCP_PORTS
            echo "-A INPUT -p tcp --dport ${p} -j DROP"
        else
            # Always reachable (prevents lockout)
            echo "-A INPUT -p tcp --dport ${p} -j ACCEPT"
        fi
    done

    # Open ports
    for p in $(public_tcp_ports); do
        echo "-A INPUT -p tcp --dport ${p} -j ACCEPT"
    done
    for p in $UDP_PORTS; do
        echo "-A INPUT -p udp --dport ${p} -j ACCEPT"
    done

    # Ping
    local echo_type="echo-request"
    if [[ "$ICMP_ENABLE" == "true" ]]; then
        if [[ "$fam" == "4" ]]; then
            echo "-A INPUT -p icmp --icmp-type ${echo_type} -j ACCEPT"
        else
            echo "-A INPUT -p ipv6-icmp --icmpv6-type ${echo_type} -j ACCEPT"
        fi
    else
        if [[ "$fam" == "4" ]]; then
            echo "-A INPUT -p icmp --icmp-type ${echo_type} -j DROP"
        else
            echo "-A INPUT -p ipv6-icmp --icmpv6-type ${echo_type} -j DROP"
        fi
    fi

    # Multicast / broadcast
    if [[ "$MULTICAST_ENABLE" == "true" ]]; then
        if [[ "$fam" == "4" ]]; then
            echo "-A INPUT -d 224.0.0.0/4 -j ACCEPT"
            echo "-A INPUT -m pkttype --pkt-type broadcast -j ACCEPT"
        else
            echo "-A INPUT -d ff00::/8 -j ACCEPT"
        fi
        echo "-A INPUT -m pkttype --pkt-type multicast -j ACCEPT"
    fi

    # Common attack ports: dropped silently (kept out of the log)
    if [[ "$BLOCK_COMMON_ATTACKS" == "true" ]]; then
        for p in 23 135 137:139 445 1900; do
            echo "-A INPUT -p tcp --dport ${p} -j DROP"
            echo "-A INPUT -p udp --dport ${p} -j DROP"
        done
    fi

    # Log what is about to be dropped by the chain policy
    if [[ "$LOG_DROPPED" == "true" ]]; then
        local prefix="binadit-drop: "
        [[ "$fam" == "6" ]] && prefix="binadit-drop6: "
        echo "-A INPUT -j ${IPT_LOG_CHAIN}"
        echo "-A ${IPT_LOG_CHAIN} -m limit --limit 5/min --limit-burst 10 -j LOG --log-prefix \"${prefix}\" --log-level 4"
    fi

    # Forwarding (NAT router, IPv4 only)
    if [[ "$fam" == "4" && "$NAT_ENABLE" == "true" ]]; then
        for a in ${blacklist[@]+"${blacklist[@]}"}; do
            _ipt_addr_rule FORWARD s "$a" -j DROP
            _ipt_addr_rule FORWARD d "$a" -j DROP
        done
        echo "-A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
        if [[ "$DROP_INVALID" == "true" ]]; then
            echo "-A FORWARD -m conntrack --ctstate INVALID -j DROP"
        fi
        echo "-A FORWARD -i ${NAT_INTERNAL_IFACE} -j ACCEPT"
        echo "-A FORWARD -m conntrack --ctstate DNAT -j ACCEPT"
    fi
    echo "COMMIT"

    if [[ "$fam" == "4" && "$with_nat" == "true" ]]; then
        echo "*nat"
        echo ":PREROUTING ACCEPT [0:0]"
        echo ":INPUT ACCEPT [0:0]"
        echo ":OUTPUT ACCEPT [0:0]"
        echo ":POSTROUTING ACCEPT [0:0]"
        if [[ "$NAT_ENABLE" == "true" ]]; then
            while IFS= read -r line; do
                [[ -z "${line// /}" ]] && continue
                split_rule "$line"
                [[ -n "$R1" && -n "$R2" && -n "$R3" ]] || continue
                echo "-A PREROUTING -i ${NAT_EXTERNAL_IFACE} -p ${R1} --dport ${R2} -j DNAT --to-destination ${R3}"
            done <<< "${PORT_FORWARD_RULES:-}"
            echo "-A POSTROUTING -o ${NAT_EXTERNAL_IFACE} -j MASQUERADE"
        fi
        echo "COMMIT"
    fi
}

# Is IPv6 filtering available on this system?
_ipt6_available() {
    local ipt6
    ipt6=$(get_ip6tables_cmd 2>/dev/null) || return 1
    get_ip6tables_restore_cmd &>/dev/null || return 1
    "$ipt6" -S INPUT &>/dev/null
}

# Is the nat table available?
_ipt_nat_available() {
    local ipt
    ipt=$(get_iptables_cmd 2>/dev/null) || return 1
    "$ipt" -t nat -S &>/dev/null
}

# Generate both rule files and verify them without applying.
# Sets IPT_V4_FILE / IPT_V6_FILE (V6 empty when IPv6 is unavailable).
ipt_check() {
    local ipt_restore out with_nat="false"
    ipt_restore=$(get_iptables_restore_cmd) || { log_error "iptables-restore not found"; return 1; }
    mkdir -p "$CONFIG_DIR"

    if _ipt_nat_available; then
        with_nat="true"
    elif [[ "$NAT_ENABLE" == "true" ]]; then
        log_error "NAT_ENABLE=true but the iptables nat table is not available on this system"
        return 1
    fi

    IPT_V4_FILE="${CONFIG_DIR}/rules.v4.new"
    IPT_V6_FILE=""
    ipt_build_ruleset 4 "$with_nat" > "$IPT_V4_FILE"
    if ! out=$("$ipt_restore" --test < "$IPT_V4_FILE" 2>&1); then
        log_error "The generated iptables (IPv4) ruleset is not valid:"
        while IFS= read -r line; do log_error "  $line"; done <<< "$out"
        return 1
    fi

    if _ipt6_available; then
        local ipt6_restore
        ipt6_restore=$(get_ip6tables_restore_cmd)
        IPT_V6_FILE="${CONFIG_DIR}/rules.v6.new"
        ipt_build_ruleset 6 > "$IPT_V6_FILE"
        if ! out=$("$ipt6_restore" --test < "$IPT_V6_FILE" 2>&1); then
            log_error "The generated ip6tables (IPv6) ruleset is not valid:"
            while IFS= read -r line; do log_error "  $line"; done <<< "$out"
            return 1
        fi
    else
        log_warn "ip6tables not available — IPv6 is not filtered by binadit-firewall"
    fi
    return 0
}

# Build, verify and apply the rules.
# Requires: load_config and resolve_config_hosts have run.
ipt_apply() {
    local ipt_restore out
    ipt_restore=$(get_iptables_restore_cmd) || { log_error "iptables-restore not found"; return 1; }

    log_info "Building iptables ruleset..."
    modprobe nf_conntrack 2>/dev/null || true

    if ! ipt_check; then
        log_error "Firewall rules were NOT changed"
        return 1
    fi

    if ! out=$("$ipt_restore" < "$IPT_V4_FILE" 2>&1); then
        log_error "Failed to apply iptables rules: $out"
        return 1
    fi
    mv -f "$IPT_V4_FILE" "${CONFIG_DIR}/rules.v4"

    if [[ -n "$IPT_V6_FILE" ]]; then
        local ipt6_restore
        ipt6_restore=$(get_ip6tables_restore_cmd)
        if ! out=$("$ipt6_restore" < "$IPT_V6_FILE" 2>&1); then
            log_error "Failed to apply ip6tables rules: $out"
            return 1
        fi
        mv -f "$IPT_V6_FILE" "${CONFIG_DIR}/rules.v6"
    fi
    log_success "iptables rules applied"

    # Custom rules file (iptables-restore format, appended to the managed rules)
    if [[ -n "${CUSTOM_RULES_FILE:-}" ]] && [[ -f "${CUSTOM_RULES_FILE}" ]]; then
        log_info "Loading custom rules from ${CUSTOM_RULES_FILE}..."
        if out=$("$ipt_restore" --noflush < "${CUSTOM_RULES_FILE}" 2>&1); then
            log_success "Custom rules loaded"
        else
            log_warn "Failed to load custom rules (iptables-restore format expected): $out"
        fi
    fi
    return 0
}

# Flush all iptables rules and allow all traffic
ipt_flush() {
    log_info "Removing iptables rules..."

    local ipt ipt6
    ipt=$(get_iptables_cmd) || { log_error "iptables not found"; return 1; }
    ipt6=$(get_ip6tables_cmd 2>/dev/null) || ipt6=""

    "$ipt" -P INPUT ACCEPT 2>/dev/null || true
    "$ipt" -P OUTPUT ACCEPT 2>/dev/null || true
    "$ipt" -P FORWARD ACCEPT 2>/dev/null || true
    "$ipt" -F 2>/dev/null || true
    "$ipt" -X 2>/dev/null || true
    "$ipt" -t nat -F 2>/dev/null || true
    "$ipt" -t nat -X 2>/dev/null || true

    if [[ -n "$ipt6" ]] && "$ipt6" -S INPUT &>/dev/null; then
        "$ipt6" -P INPUT ACCEPT 2>/dev/null || true
        "$ipt6" -P OUTPUT ACCEPT 2>/dev/null || true
        "$ipt6" -P FORWARD ACCEPT 2>/dev/null || true
        "$ipt6" -F 2>/dev/null || true
        "$ipt6" -X 2>/dev/null || true
    fi

    log_success "iptables rules removed"
}

# True when our rules are loaded
ipt_is_active() {
    local ipt
    ipt=$(get_iptables_cmd 2>/dev/null) || return 1
    "$ipt" -S "$IPT_MARKER_CHAIN" &>/dev/null && return 0
    # Rules loaded by binadit-firewall <= 3.0.x (no marker chain yet)
    "$ipt" -S 2>/dev/null | grep -q 'binadit-drop'
}

# Show current iptables status
ipt_status() {
    local ipt ipt6
    ipt=$(get_iptables_cmd) || { log_error "iptables not found"; return 1; }
    ipt6=$(get_ip6tables_cmd 2>/dev/null) || ipt6=""

    log_header "IPv4 rules"
    "$ipt" -n -L -v --line-numbers 2>/dev/null || "$ipt" -n -L

    if [[ -n "$ipt6" ]] && "$ipt6" -S INPUT &>/dev/null; then
        log_header "IPv6 rules"
        "$ipt6" -n -L -v --line-numbers 2>/dev/null || "$ipt6" -n -L
    fi
}
