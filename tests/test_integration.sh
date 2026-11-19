#!/usr/bin/env bash
# =============================================================================
# binadit-firewall - Integration tests (real kernel, real packets)
# =============================================================================
# Proves that the firewall does what the configuration says, by loading the
# rules into the kernel and making real connections through them.
#
# Layout (everything lives in private network namespaces, the firewall of the
# machine running the tests is never touched):
#
#   client A (10.99.1.2 / fd99:1::2) ─┐
#                                     ├─ firewall host (10.99.x.1 / fd99:x::1)
#   client B (10.99.2.2 / fd99:2::2) ─┘
#
# Requirements: Linux, root, bash 4+, iproute2, util-linux, python3 and
# nftables and/or iptables.
#
# Usage: sudo bash tests/test_integration.sh [nftables|iptables]
# =============================================================================

set -uo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${TEST_DIR}/.." && pwd)"
FW="${PROJECT_DIR}/src/binadit-firewall.sh"

RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'; BOLD=$'\033[1m'; NC=$'\033[0m'

if [[ "$(uname -s)" != "Linux" ]]; then
    echo "Integration tests need Linux — skipped"
    exit 0
fi
if [[ $EUID -ne 0 ]]; then
    echo "Integration tests need root: sudo bash $0" >&2
    exit 1
fi

# Re-run inside a private network + mount namespace
if [[ "${BFW_TEST_ISOLATED:-}" != "1" ]]; then
    export BFW_TEST_ISOLATED=1
    exec unshare --net --mount --propagation private bash "$0" "$@"
fi

# -----------------------------------------------------------------------------
# Environment
# -----------------------------------------------------------------------------
WORK=$(mktemp -d /tmp/bfw-itest.XXXXXX)
export BINADIT_CONFIG_DIR="$WORK/etc"
export BINADIT_SKIP_SYSTEM_HOOKS=true
mkdir -p "$BINADIT_CONFIG_DIR"
CONF="$BINADIT_CONFIG_DIR/firewall.conf"

# Private /etc/hosts so hostname changes can be simulated
cp /etc/hosts "$WORK/hosts" 2>/dev/null || : > "$WORK/hosts"
mount --bind "$WORK/hosts" /etc/hosts

HOST_A4="10.99.1.1"; A4="10.99.1.2"; HOST_A6="fd99:1::1"; A6="fd99:1::2"
HOST_B4="10.99.2.1"; B4="10.99.2.2"; HOST_B6="fd99:2::1"; B6="fd99:2::2"

PIDS=()
cleanup() {
    local p
    for p in ${PIDS[@]+"${PIDS[@]}"}; do kill "$p" 2>/dev/null; done
    wait 2>/dev/null
    umount /etc/hosts 2>/dev/null
    rm -rf "$WORK"
}
trap cleanup EXIT
set +m

ip link set lo up

make_client() {
    local name="$1" host4="$2" cli4="$3" host6="$4" cli6="$5" pid
    unshare --net sleep infinity >/dev/null 2>&1 &
    pid=$!
    sleep 0.2
    ip link add "veth-${name}" type veth peer name eth0 netns "$pid"
    ip addr add "${host4}/24" dev "veth-${name}"
    ip -6 addr add "${host6}/64" dev "veth-${name}" nodad
    ip link set "veth-${name}" up
    nsenter -t "$pid" -n ip link set lo up
    nsenter -t "$pid" -n ip addr add "${cli4}/24" dev eth0
    nsenter -t "$pid" -n ip -6 addr add "${cli6}/64" dev eth0 nodad
    nsenter -t "$pid" -n ip link set eth0 up
    nsenter -t "$pid" -n ip route add default via "$host4"
    echo "$pid"
}

PID_A=$(make_client a "$HOST_A4" "$A4" "$HOST_A6" "$A6")
PID_B=$(make_client b "$HOST_B4" "$B4" "$HOST_B6" "$B6")
PIDS+=("$PID_A" "$PID_B")

# TCP listeners on the firewall host (dual-stack) and inside client A
cat > "$WORK/listen.py" <<'PY'
import socket, sys, threading
def serve(port):
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    s.bind(("::", port)); s.listen(256)
    conns = []
    while True:
        c, _ = s.accept()
        conns.append(c)          # keep open until the client closes
        threading.Thread(target=lambda c=c: (c.recv(1), c.close()), daemon=True).start()
for p in sys.argv[1:]:
    threading.Thread(target=serve, args=(int(p),), daemon=True).start()
threading.Event().wait()
PY
python3 "$WORK/listen.py" 22 80 443 3306 8080 9999 >/dev/null 2>&1 &
PIDS+=("$!")
nsenter -t "$PID_A" -n python3 "$WORK/listen.py" 25 80 >/dev/null 2>&1 &
PIDS+=("$!")
nsenter -t "$PID_B" -n python3 "$WORK/listen.py" 80 >/dev/null 2>&1 &
PIDS+=("$!")
sleep 1

# -----------------------------------------------------------------------------
# Test helpers
# -----------------------------------------------------------------------------
TESTS=0; FAILED=0

pass() { TESTS=$((TESTS + 1)); echo "  ${GREEN}✓${NC} $1"; }
fail() { TESTS=$((TESTS + 1)); FAILED=$((FAILED + 1)); echo "  ${RED}✗${NC} $1"; }

# connect <client-pid|host> <address> <port>  → 0 when the TCP connection opens
connect() {
    local from="$1" addr="$2" port="$3"
    if [[ "$from" == "host" ]]; then
        timeout 1 bash -c "exec 3<>/dev/tcp/${addr}/${port}" 2>/dev/null
    else
        nsenter -t "$from" -n timeout 1 bash -c "exec 3<>/dev/tcp/${addr}/${port}" 2>/dev/null
    fi
}

expect_open() {
    local desc="$1"; shift
    if connect "$@"; then pass "$desc"; else fail "$desc (expected OPEN, was blocked)"; fi
}

expect_closed() {
    local desc="$1"; shift
    if connect "$@"; then fail "$desc (expected BLOCKED, was open)"; else pass "$desc"; fi
}

expect_ok() {
    local desc="$1"; shift
    if "$@" >/dev/null 2>&1; then pass "$desc"; else fail "$desc"; fi
}

expect_fail() {
    local desc="$1"; shift
    if "$@" >/dev/null 2>&1; then fail "$desc (unexpectedly succeeded)"; else pass "$desc"; fi
}

fw() { bash "$FW" "$@"; }

# Point a test hostname at an address (empty address = remove it).
# /etc/hosts is a bind mount, so it must be rewritten in place.
set_host() {
    local name="$1" addr="${2:-}" content
    content=$(grep -v " ${name}\$" /etc/hosts || true)
    [[ -n "$addr" ]] && content+=$'\n'"${addr} ${name}"
    printf '%s\n' "$content" > /etc/hosts
}

# Write a config (defaults + overrides from stdin) and apply it
apply_config() {
    {
        echo 'SSH_PORT="22"'
        echo 'LOG_DROPPED="false"'
        cat
    } > "$CONF"
    if ! fw reload > "$WORK/last.log" 2>&1; then
        echo "  ${RED}reload failed:${NC}"; sed 's/^/      /' "$WORK/last.log"
        return 1
    fi
}

section() { echo ""; echo "${BOLD}$1${NC}"; }

# -----------------------------------------------------------------------------
# The test scenarios (run once per backend)
# -----------------------------------------------------------------------------
run_suite() {
    local backend="$1"
    export BINADIT_BACKEND="$backend"

    echo ""
    echo "${BOLD}════════ Backend: ${backend} ════════${NC}"

    section "Not started: everything reachable, status says inactive"
    fw stop >/dev/null 2>&1
    expect_open   "no firewall: port 3306 reachable"                 "$PID_A" "$HOST_A4" 3306
    fw status >/dev/null 2>&1; local rc=$?
    if [[ $rc -eq 3 ]]; then pass "status exit code is 3 when inactive"; else fail "status exit code is 3 when inactive (got $rc)"; fi

    section "Default policy: only configured ports are open"
    apply_config <<'EOF'
TCP_PORTS="80 443"
EOF
    expect_ok     "status exit code is 0 when active"                fw status
    expect_open   "TCP 80 (in TCP_PORTS) is open"                    "$PID_A" "$HOST_A4" 80
    expect_open   "TCP 443 (in TCP_PORTS) is open"                   "$PID_A" "$HOST_A4" 443
    expect_open   "SSH port is open when not restricted"             "$PID_A" "$HOST_A4" 22
    expect_closed "TCP 3306 (not configured) is blocked"             "$PID_A" "$HOST_A4" 3306
    expect_closed "TCP 9999 (not configured) is blocked"             "$PID_A" "$HOST_A4" 9999
    local i leaked=0
    for i in 1 2 3 4 5 6 7 8; do
        connect "$PID_B" "$HOST_B4" 3306 && leaked=$((leaked + 1))
    done
    if [[ $leaked -eq 0 ]]; then pass "closed port stays closed on repeated attempts (0/8 leaked)"; else fail "closed port leaked ${leaked}/8 connections"; fi
    expect_open   "IPv6: TCP 80 is open"                             "$PID_A" "$HOST_A6" 80
    expect_open   "IPv6: SSH port is open"                           "$PID_A" "$HOST_A6" 22
    expect_closed "IPv6: TCP 3306 is blocked"                        "$PID_A" "$HOST_A6" 3306
    expect_ok     "ping answered (ICMP_ENABLE=true)"                 nsenter -t "$PID_A" -n ping -c1 -W1 "$HOST_A4"
    expect_ok     "IPv6 ping answered"                               nsenter -t "$PID_A" -n ping -6 -c1 -W1 "$HOST_A6"
    expect_open   "outgoing connections are allowed"                 host "$A4" 80
    expect_open   "loopback is not filtered"                         host 127.0.0.1 3306

    section "Port ranges and TCP_PORTS_INPUT"
    apply_config <<'EOF'
TCP_PORTS="8000:8100"
TCP_PORTS_INPUT="443"
EOF
    expect_open   "port inside range 8000:8100 is open"              "$PID_A" "$HOST_A4" 8080
    expect_open   "TCP_PORTS_INPUT port is open"                     "$PID_A" "$HOST_A4" 443
    expect_closed "port outside range is blocked"                    "$PID_A" "$HOST_A4" 9999
    expect_closed "port 80 no longer open after reload"              "$PID_A" "$HOST_A4" 80

    section "ICMP_ENABLE=false"
    apply_config <<'EOF'
TCP_PORTS="80"
ICMP_ENABLE="false"
EOF
    expect_fail   "ping not answered"                                nsenter -t "$PID_A" -n ping -c1 -W1 "$HOST_A4"
    expect_fail   "IPv6 ping not answered"                           nsenter -t "$PID_A" -n ping -6 -c1 -W1 "$HOST_A6"
    expect_open   "IPv6 still works without ping (neighbour discovery allowed)" "$PID_A" "$HOST_A6" 80

    section "SSH_ALLOWED_IPS restricts SSH (even with 22 in TCP_PORTS)"
    apply_config <<EOF
TCP_PORTS="22 80"
SSH_ALLOWED_IPS="${A4}"
EOF
    expect_open   "allowed IP reaches SSH"                           "$PID_A" "$HOST_A4" 22
    expect_closed "other IP cannot reach SSH"                        "$PID_B" "$HOST_B4" 22
    expect_closed "IPv6 SSH closed when only IPv4 is allowed"        "$PID_B" "$HOST_B6" 22
    expect_open   "other ports stay public"                          "$PID_B" "$HOST_B4" 80

    apply_config <<EOF
TCP_PORTS="80"
SSH_ALLOWED_IPS_IPV6="${B6}"
EOF
    expect_open   "IPv6-only allow-list: allowed IPv6 reaches SSH"   "$PID_B" "$HOST_B6" 22
    expect_closed "IPv6-only allow-list: IPv4 SSH is closed"         "$PID_A" "$HOST_A4" 22
    expect_closed "IPv6-only allow-list: other IPv6 is closed"       "$PID_A" "$HOST_A6" 22

    section "TRUSTED_IPS, BLACKLIST, PORT_IP_RULES"
    apply_config <<EOF
TCP_PORTS="80"
TRUSTED_IPS="${A4}"
TRUSTED_IPS_IPV6="${A6}"
EOF
    expect_open   "trusted IP reaches a closed port"                 "$PID_A" "$HOST_A4" 3306
    expect_open   "trusted IPv6 reaches a closed port"               "$PID_A" "$HOST_A6" 3306
    expect_closed "untrusted IP does not"                            "$PID_B" "$HOST_B4" 3306

    apply_config <<EOF
TCP_PORTS="80"
BLACKLIST="${B4}"
BLOCKED_RANGES_IPV6="fd99:2::/64"
EOF
    expect_closed "blacklisted IP cannot reach an open port"         "$PID_B" "$HOST_B4" 80
    expect_closed "blacklisted IPv6 range cannot reach an open port" "$PID_B" "$HOST_B6" 80
    expect_closed "blacklisted IP cannot reach SSH"                  "$PID_B" "$HOST_B4" 22
    expect_open   "other IP still reaches the open port"             "$PID_A" "$HOST_A4" 80

    apply_config <<EOF
TCP_PORTS="80"
BLACKLIST="${A4}"
EOF
    expect_closed "outgoing connections to a blacklisted IP are blocked" host "$A4" 80

    apply_config <<EOF
TCP_PORTS="80"
TRUSTED_RANGES="10.99.1.1-10.99.1.10"
BLOCKED_RANGES="10.99.2.2-10.99.2.5"
EOF
    expect_open   "trusted range (a-b notation) has full access"     "$PID_A" "$HOST_A4" 3306
    expect_closed "blocked range (a-b notation) is blocked"          "$PID_B" "$HOST_B4" 80

    apply_config <<EOF
TCP_PORTS="80"
PORT_IP_RULES="tcp|3306|${A4}
tcp|8080|${B6}"
EOF
    expect_open   "PORT_IP_RULES: listed IP reaches the port"        "$PID_A" "$HOST_A4" 3306
    expect_closed "PORT_IP_RULES: other IP does not"                 "$PID_B" "$HOST_B4" 3306
    expect_closed "PORT_IP_RULES: listed IP gets only that port"     "$PID_A" "$HOST_A4" 9999
    expect_open   "PORT_IP_RULES: IPv6 address works"                "$PID_B" "$HOST_B6" 8080
    expect_closed "PORT_IP_RULES: IPv6 rule does not open it for others" "$PID_A" "$HOST_A6" 8080

    section "Blocked ports"
    apply_config <<EOF
TCP_PORTS="80 443"
TRUSTED_IPS="${A4}"
BLOCKED_TCP_PORTS="443"
BLOCKED_TCP_PORTS_OUTPUT="25"
EOF
    expect_closed "BLOCKED_TCP_PORTS wins over TCP_PORTS"            "$PID_B" "$HOST_B4" 443
    expect_closed "BLOCKED_TCP_PORTS wins over trusted IPs"          "$PID_A" "$HOST_A4" 443
    expect_closed "BLOCKED_TCP_PORTS_OUTPUT blocks outgoing port 25" host "$A4" 25
    expect_open   "other outgoing ports still work"                  host "$A4" 80

    section "Rate limit is per source IP and only bites above the limit"
    apply_config <<'EOF'
TCP_PORTS="80"
RATE_LIMIT_ENABLE="true"
RATE_LIMIT_RATE="1"
RATE_LIMIT_BURST="5"
EOF
    local ok=0
    for i in $(seq 1 20); do
        nsenter -t "$PID_A" -n timeout 0.3 bash -c "exec 3<>/dev/tcp/${HOST_A4}/80" 2>/dev/null && ok=$((ok + 1))
    done
    if (( ok >= 4 && ok <= 14 )); then pass "flooding IP is throttled (${ok}/20 connections got through)"; else fail "flooding IP should be throttled to roughly the burst (${ok}/20 got through)"; fi
    expect_open   "another IP is not affected by that flood"         "$PID_B" "$HOST_B4" 80
    expect_closed "rate limiter never opens a closed port"           "$PID_B" "$HOST_B4" 3306

    apply_config <<EOF
TCP_PORTS="80"
RATE_LIMIT_RATE="1"
RATE_LIMIT_BURST="2"
TRUSTED_IPS="${A4}"
EOF
    ok=0
    for i in $(seq 1 12); do
        nsenter -t "$PID_A" -n timeout 0.3 bash -c "exec 3<>/dev/tcp/${HOST_A4}/80" 2>/dev/null && ok=$((ok + 1))
    done
    if (( ok == 12 )); then pass "trusted IPs are exempt from the rate limit (12/12)"; else fail "trusted IPs should be exempt from the rate limit (${ok}/12)"; fi

    section "CONN_RATE_PER_IP hard cap"
    apply_config <<'EOF'
TCP_PORTS="80"
RATE_LIMIT_ENABLE="false"
CONN_RATE_PER_IP="2"
EOF
    ok=0
    for i in $(seq 1 15); do
        nsenter -t "$PID_A" -n timeout 0.3 bash -c "exec 3<>/dev/tcp/${HOST_A4}/80" 2>/dev/null && ok=$((ok + 1))
    done
    if (( ok >= 2 && ok <= 11 )); then pass "new connections per IP are capped (${ok}/15 got through)"; else fail "CONN_RATE_PER_IP should cap new connections (${ok}/15 got through)"; fi
    expect_open   "another IP is not affected"                       "$PID_B" "$HOST_B4" 80

    section "CONN_LIMIT_PER_IP limits concurrent connections per IP"
    apply_config <<'EOF'
TCP_PORTS="80"
RATE_LIMIT_ENABLE="false"
CONN_LIMIT_ENABLE="true"
CONN_LIMIT_PER_IP="2"
EOF
    nsenter -t "$PID_A" -n bash -c "exec 3<>/dev/tcp/${HOST_A4}/80; exec 4<>/dev/tcp/${HOST_A4}/80; sleep 4" 2>/dev/null &
    local holder=$!
    sleep 1
    expect_closed "third concurrent connection from the same IP is refused" "$PID_A" "$HOST_A4" 80
    expect_open   "another IP can still connect"                     "$PID_B" "$HOST_B4" 80
    wait "$holder" 2>/dev/null
    sleep 1
    expect_open   "after closing connections the IP can connect again" "$PID_A" "$HOST_A4" 80

    section "Hostnames: resolved, cached, and reloaded when the address changes"
    set_host admin.bfw.test "$A4"
    apply_config <<'EOF'
TCP_PORTS="80"
SSH_ALLOWED_IPS="admin.bfw.test"
EOF
    expect_open   "hostname in SSH_ALLOWED_IPS: its address reaches SSH" "$PID_A" "$HOST_A4" 22
    expect_closed "other address cannot reach SSH"                   "$PID_B" "$HOST_B4" 22
    local out
    out=$(fw dns-refresh 2>&1)
    if [[ "$out" == *"no address changes"* ]]; then pass "dns-refresh: no reload when nothing changed"; else fail "dns-refresh without changes should not reload: $out"; fi

    set_host admin.bfw.test "$B4"
    expect_closed "before dns-refresh the new address is not yet allowed" "$PID_B" "$HOST_B4" 22
    out=$(fw dns-refresh 2>&1)
    if [[ "$out" == *"rules reloaded"* ]]; then pass "dns-refresh: detects the changed address and reloads"; else fail "dns-refresh should reload after an address change: $out"; fi
    expect_open   "new address behind the hostname reaches SSH"      "$PID_B" "$HOST_B4" 22
    expect_closed "old address no longer reaches SSH"                "$PID_A" "$HOST_A4" 22

    set_host admin.bfw.test ""
    fw dns-refresh >/dev/null 2>&1
    expect_open   "DNS failure: last known address keeps working"    "$PID_B" "$HOST_B4" 22
    fw reload >/dev/null 2>&1
    expect_open   "DNS failure during reload: cached address is used" "$PID_B" "$HOST_B4" 22

    # A pending (not yet applied) edit must not be applied by dns-refresh
    set_host admin.bfw.test "$B4"
    fw reload >/dev/null 2>&1
    sed -i 's/^TCP_PORTS=.*/TCP_PORTS="80 3306"/' "$CONF"
    set_host admin.bfw.test "$A4"
    fw dns-refresh >/dev/null 2>&1
    expect_open   "dns-refresh applied the new address"              "$PID_A" "$HOST_A4" 22
    expect_closed "dns-refresh did NOT apply an unapplied config edit" "$PID_B" "$HOST_B4" 3306
    set_host admin.bfw.test ""

    section "A broken config never breaks the running firewall"
    apply_config <<'EOF'
TCP_PORTS="80"
EOF
    echo 'TCP_PORTS="80 notaport"' >> "$CONF"
    expect_fail   "reload with invalid config fails"                 fw reload
    expect_open   "previous rules still active: 80 open"             "$PID_A" "$HOST_A4" 80
    expect_closed "previous rules still active: 3306 blocked"        "$PID_A" "$HOST_A4" 3306
    expect_ok     "firewall still reported active"                   fw status
    expect_fail   "restart with invalid config fails"                fw restart
    expect_closed "restart did not open the firewall: 3306 blocked"  "$PID_A" "$HOST_A4" 3306

    section "Reload keeps established connections"
    apply_config <<'EOF'
TCP_PORTS="80"
EOF
    nsenter -t "$PID_A" -n bash -c "exec 3<>/dev/tcp/${HOST_A4}/80; sleep 3; printf x >&3; timeout 3 cat <&3 >/dev/null" 2>/dev/null &
    holder=$!
    sleep 0.5
    fw reload >/dev/null 2>&1
    if wait "$holder"; then pass "connection opened before reload still works after it"; else fail "reload broke an established connection"; fi

    section "NAT ruleset loads"
    apply_config <<'EOF'
TCP_PORTS="80"
NAT_ENABLE="true"
NAT_EXTERNAL_IFACE="veth-a"
NAT_INTERNAL_IFACE="veth-b"
PORT_FORWARD_RULES="tcp|8443|10.99.2.2:80"
EOF
    expect_ok     "firewall active with NAT + port forward"          fw status
    expect_open   "port forward: external client reaches LAN host through DNAT" "$PID_A" "$HOST_A4" 8443
    apply_config <<'EOF'
TCP_PORTS="80"
NAT_ENABLE="true"
NAT_EXTERNAL_IFACE="wan-absent0"
NAT_INTERNAL_IFACE="lan-absent0"
EOF
    expect_ok     "NAT rules load even when interfaces do not exist yet (boot)" fw status

    section "Stop removes everything"
    fw stop >/dev/null 2>&1
    expect_open   "after stop: port 3306 reachable again"            "$PID_A" "$HOST_A4" 3306
    if [[ "$backend" == "nftables" ]]; then
        if ! nft list tables 2>/dev/null | grep -q binadit; then pass "after stop: no binadit tables left in nftables"; else fail "after stop: binadit tables left behind"; fi
    fi
}

# -----------------------------------------------------------------------------
# Run
# -----------------------------------------------------------------------------
BACKENDS=()
if [[ $# -gt 0 ]]; then
    BACKENDS=("$@")
else
    command -v nft &>/dev/null && nft list tables &>/dev/null && BACKENDS+=("nftables")
    command -v iptables-restore &>/dev/null && iptables -S &>/dev/null && BACKENDS+=("iptables")
fi

if (( ${#BACKENDS[@]} == 0 )); then
    echo "${RED}No usable firewall backend (nftables/iptables) found${NC}" >&2
    exit 1
fi

for b in "${BACKENDS[@]}"; do
    run_suite "$b"
done

echo ""
echo "${BOLD}════════════════════════════════════════${NC}"
if [[ $FAILED -eq 0 ]]; then
    echo "${GREEN}${BOLD}All ${TESTS} integration tests passed${NC} (backends: ${BACKENDS[*]})"
else
    echo "${RED}${BOLD}${FAILED} of ${TESTS} integration tests FAILED${NC} (backends: ${BACKENDS[*]})"
fi
echo ""
[[ $FAILED -eq 0 ]]
