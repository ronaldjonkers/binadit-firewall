#!/usr/bin/env bash
# =============================================================================
# binadit-firewall - Unit tests
# =============================================================================
# Tests validation, configuration handling, hostname resolution/caching and
# the generated rulesets. Needs no root and no firewall backend (bash 4+).
#
# The companion tests/test_integration.sh loads the rules into a real kernel
# and verifies them with real connections.
#
# Usage: bash tests/test_firewall.sh
# =============================================================================

set -uo pipefail

if (( BASH_VERSINFO[0] < 4 )); then
    echo "These tests need bash 4 or newer (found ${BASH_VERSION})." >&2
    echo "On macOS: brew install bash && /opt/homebrew/bin/bash tests/test_firewall.sh" >&2
    exit 1
fi

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Determine paths
TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${TEST_DIR}/.." && pwd)"
SRC_DIR="${PROJECT_DIR}/src"
LIB_DIR="${SRC_DIR}/lib"
EXAMPLE_CONF="${PROJECT_DIR}/config/firewall.conf.example"
FW="${SRC_DIR}/binadit-firewall.sh"

WORK=$(mktemp -d "${TMPDIR:-/tmp}/bfw-test.XXXXXX")
trap 'rm -rf "$WORK"' EXIT
CONFIG_DIR="$WORK/etc"
mkdir -p "$CONFIG_DIR"

# Source libraries
source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/backend.sh"
source "${LIB_DIR}/backend_nftables.sh"
source "${LIB_DIR}/backend_iptables.sh"
set +e

# =============================================================================
# Test framework
# =============================================================================

_pass() { TESTS_RUN=$((TESTS_RUN + 1)); TESTS_PASSED=$((TESTS_PASSED + 1)); echo -e "  ${GREEN}✓${NC} $1"; }
_fail() { TESTS_RUN=$((TESTS_RUN + 1)); TESTS_FAILED=$((TESTS_FAILED + 1)); echo -e "  ${RED}✗${NC} $1"; [[ -n "${2:-}" ]] && echo -e "      $2"; }

assert_equals() {
    local description="$1" expected="$2" actual="$3"
    if [[ "$expected" == "$actual" ]]; then
        _pass "$description"
    else
        _fail "$description" "expected: '${expected}'  actual: '${actual}'"
    fi
}

assert_true() {
    local description="$1"; shift
    if "$@" >/dev/null 2>&1; then _pass "$description"; else _fail "$description" "(returned false)"; fi
}

assert_false() {
    local description="$1"; shift
    if "$@" >/dev/null 2>&1; then _fail "$description" "(returned true, expected false)"; else _pass "$description"; fi
}

# assert_has "desc" "$text" "fixed string"
assert_has() {
    if [[ "$2" == *"$3"* ]]; then _pass "$1"; else _fail "$1" "missing: $3"; fi
}

assert_lacks() {
    if [[ "$2" == *"$3"* ]]; then _fail "$1" "should not contain: $3"; else _pass "$1"; fi
}

# assert_matches "desc" "$text" "extended regex"
assert_matches() {
    if grep -Eq -- "$3" <<< "$2"; then _pass "$1"; else _fail "$1" "no line matches: $3"; fi
}

assert_no_match() {
    local hit
    if hit=$(grep -En -- "$3" <<< "$2"); then _fail "$1" "offending line: ${hit%%$'\n'*}"; else _pass "$1"; fi
}

# Line number of the first line containing a fixed string (0 = not found)
line_of() {
    local n
    n=$(grep -Fn -- "$2" <<< "$1" | head -1 | cut -d: -f1)
    echo "${n:-0}"
}

# assert_before "desc" "$text" "first" "second"
assert_before() {
    local a b
    a=$(line_of "$2" "$3"); b=$(line_of "$2" "$4")
    if (( a > 0 && b > 0 && a < b )); then
        _pass "$1"
    else
        _fail "$1" "'$3' (line $a) must come before '$4' (line $b)"
    fi
}

section() { echo -e "\n${BOLD}Test: $1${NC}"; }

# Write a config file with the given lines and load it
CONF="$CONFIG_DIR/firewall.conf"
use_config() {
    { echo 'SSH_PORT="22"'; cat; } > "$CONF"
    load_config "$CONF"
}

# DNS stub: test.example hosts resolve from the DNS4/DNS6 maps
declare -A DNS4=() DNS6=()
_dns_lookup() {
    if [[ "$2" == "4" ]]; then echo "${DNS4[$1]:-}"; else echo "${DNS6[$1]:-}"; fi
}

build_nft() { resolve_config_hosts 2>/dev/null; nft_build_ruleset; }
build_ipt() { resolve_config_hosts 2>/dev/null; ipt_build_ruleset "$1" "${2:-false}"; }

# The part of an nft ruleset belonging to one chain
nft_chain() {
    awk -v c="chain $2 {" 'index($0, c) { on = 1 } on { print } on && /^    }/ { exit }' <<< "$1"
}

# =============================================================================
# Validation
# =============================================================================

test_validation() {
    section "IPv4 validation"
    assert_true  "192.168.1.1"                is_valid_ipv4 "192.168.1.1"
    assert_true  "0.0.0.0"                    is_valid_ipv4 "0.0.0.0"
    assert_true  "255.255.255.255"            is_valid_ipv4 "255.255.255.255"
    assert_false "256.1.1.1"                  is_valid_ipv4 "256.1.1.1"
    assert_false "1.2.3"                      is_valid_ipv4 "1.2.3"
    assert_false "1.2.3.4.5"                  is_valid_ipv4 "1.2.3.4.5"
    assert_false "abc.def.ghi.jkl"            is_valid_ipv4 "abc.def.ghi.jkl"
    assert_false "leading zero 010.1.1.1"     is_valid_ipv4 "010.1.1.1"
    assert_false "octal trap 1.2.3.08"        is_valid_ipv4 "1.2.3.08"
    assert_false "empty"                      is_valid_ipv4 ""
    assert_false "with CIDR"                  is_valid_ipv4 "10.0.0.0/8"

    section "IPv6 validation"
    assert_true  "::1"                        is_valid_ipv6 "::1"
    assert_true  "::"                         is_valid_ipv6 "::"
    assert_true  "2001:db8::1"                is_valid_ipv6 "2001:db8::1"
    assert_true  "fe80::1"                    is_valid_ipv6 "fe80::1"
    assert_true  "full address"               is_valid_ipv6 "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
    assert_true  "trailing ::"                is_valid_ipv6 "2001:db8::"
    assert_false "IPv4 address"               is_valid_ipv6 "192.168.1.1"
    assert_false "hostname"                   is_valid_ipv6 "example.com"
    assert_false "two :: groups"              is_valid_ipv6 "2001::db8::1"
    assert_false "triple colon"               is_valid_ipv6 "2001:::1"
    assert_false "too many groups"            is_valid_ipv6 "1:2:3:4:5:6:7:8:9"
    assert_false "too few groups"             is_valid_ipv6 "1:2:3:4"
    assert_false "group too long"             is_valid_ipv6 "2001:db8::12345"
    assert_false "non-hex"                    is_valid_ipv6 "2001:db8::g"
    assert_false "single leading colon"       is_valid_ipv6 ":1:2:3:4:5:6:7"
    assert_false "empty"                      is_valid_ipv6 ""

    section "CIDR validation"
    assert_true  "10.0.0.0/8"                 is_valid_cidr "10.0.0.0/8"
    assert_true  "192.168.1.0/24"             is_valid_cidr "192.168.1.0/24"
    assert_true  "0.0.0.0/0"                  is_valid_cidr "0.0.0.0/0"
    assert_true  "2001:db8::/32"              is_valid_cidr "2001:db8::/32"
    assert_true  "::/0"                       is_valid_cidr "::/0"
    assert_false "IPv4 /33"                   is_valid_cidr "10.0.0.0/33"
    assert_false "IPv6 /129"                  is_valid_cidr "2001:db8::/129"
    assert_false "no prefix"                  is_valid_cidr "10.0.0.0"
    assert_false "non-numeric prefix"         is_valid_cidr "10.0.0.0/abc"
    assert_false "empty prefix"               is_valid_cidr "10.0.0.0/"

    section "Port validation"
    assert_true  "80"                         is_valid_port "80"
    assert_true  "1"                          is_valid_port "1"
    assert_true  "65535"                      is_valid_port "65535"
    assert_true  "range 8000:9000"            is_valid_port "8000:9000"
    assert_true  "leading zero 08 is decimal" is_valid_port "08"
    assert_false "0"                          is_valid_port "0"
    assert_false "65536"                      is_valid_port "65536"
    assert_false "reversed range"             is_valid_port "9000:8000"
    assert_false "dash range (nft style)"     is_valid_port "8000-9000"
    assert_false "text"                       is_valid_port "http"
    assert_false "negative"                   is_valid_port "-1"
    assert_false "empty"                      is_valid_port ""

    section "Address classification"
    classify_addr "1.2.3.4";               assert_equals "IPv4 address"        "v4"      "$ADDR_KIND"
    classify_addr "10.0.0.0/8";            assert_equals "IPv4 CIDR"           "v4"      "$ADDR_KIND"
    classify_addr "1.2.3.4-1.2.3.9";       assert_equals "IPv4 range"          "v4range" "$ADDR_KIND"
    classify_addr "2001:db8::1";           assert_equals "IPv6 address"        "v6"      "$ADDR_KIND"
    classify_addr "2001:db8::/32";         assert_equals "IPv6 CIDR"           "v6"      "$ADDR_KIND"
    classify_addr "2001:db8::1-2001:db8::9"; assert_equals "IPv6 range"        "v6range" "$ADDR_KIND"
    classify_addr "office.example.com";    assert_equals "hostname"            "host"    "$ADDR_KIND"
    classify_addr "my-server.example.com"; assert_equals "hostname with dash"  "host"    "$ADDR_KIND"
    classify_addr "localhost";             assert_equals "single-label host"   "host"    "$ADDR_KIND"
    assert_false "mistyped IP 300.1.1.1 is not a hostname" classify_addr "300.1.1.1"
    assert_false "incomplete IP 1.2.3 is not a hostname"   classify_addr "1.2.3"
    assert_false "reversed range"                          classify_addr "1.2.3.9-1.2.3.4"
    assert_false "garbage range 1.2.3.4-foo"               classify_addr "1.2.3.4-"
    assert_false "invalid characters"                      classify_addr "host name!"
    assert_false "shell metacharacters"                    classify_addr 'a;rm -rf'
    assert_false "leading dash"                            classify_addr "-bad.example.com"
    assert_false "empty"                                   classify_addr ""

    section "Rate and interface validation"
    assert_true  "rate 25"                    is_valid_rate "25"
    assert_true  "rate 25/second"             is_valid_rate "25/second"
    assert_true  "rate 600/minute"            is_valid_rate "600/minute"
    assert_false "rate 0"                     is_valid_rate "0"
    assert_false "rate 25/fortnight"          is_valid_rate "25/fortnight"
    assert_false "rate text"                  is_valid_rate "fast"
    assert_true  "iface eth0"                 is_valid_iface "eth0"
    assert_true  "iface ens18.100"            is_valid_iface "ens18.100"
    assert_false "iface with space"           is_valid_iface "eth 0"
    assert_false "iface too long"             is_valid_iface "averyveryverylongname"
    assert_false "iface with quote"           is_valid_iface 'eth0"'
}

# =============================================================================
# Project files
# =============================================================================

test_project() {
    section "Project structure and syntax"
    local f
    for f in install.sh get.sh src/binadit-firewall.sh src/lib/common.sh src/lib/backend.sh \
             src/lib/backend_nftables.sh src/lib/backend_iptables.sh \
             tests/test_firewall.sh tests/test_integration.sh; do
        assert_true "bash syntax OK: $f" bash -n "${PROJECT_DIR}/$f"
    done
    for f in config/firewall.conf.example config/binadit-firewall.service README.md CHANGELOG.md LICENSE; do
        assert_true "exists: $f" test -f "${PROJECT_DIR}/$f"
    done

    section "Version consistency"
    local v="$BINADIT_VERSION"
    assert_matches "version is semver"               "$v" '^[0-9]+\.[0-9]+\.[0-9]+$'
    assert_has "main script header has v$v"          "$(head -5 "$FW")"                              "v$v"
    assert_has "installer header has v$v"            "$(head -5 "${PROJECT_DIR}/install.sh")"        "v$v"
    assert_has "example config header has v$v"       "$(head -5 "$EXAMPLE_CONF")"                    "v$v"
    assert_has "README badge has $v"                 "$(cat "${PROJECT_DIR}/README.md")"             "version-$v-"
    assert_has "CHANGELOG has an entry for $v"       "$(cat "${PROJECT_DIR}/CHANGELOG.md")"          "## [$v]"
    assert_equals "newest CHANGELOG entry is $v"     "## [$v]" "$(grep -m1 '^## \[' "${PROJECT_DIR}/CHANGELOG.md" | cut -d' ' -f1-2)"

    section "Systemd service"
    local unit
    unit=$(cat "${PROJECT_DIR}/config/binadit-firewall.service")
    assert_has "runs start"                          "$unit" "ExecStart=/usr/local/sbin/binadit-firewall start"
    assert_has "runs stop"                           "$unit" "ExecStop=/usr/local/sbin/binadit-firewall stop"
    assert_has "supports reload"                     "$unit" "ExecReload=/usr/local/sbin/binadit-firewall reload"
    assert_has "oneshot that stays active"           "$unit" "RemainAfterExit=yes"
    assert_matches "ordered before the network"      "$unit" '^Before=.*network-pre\.target'
    assert_has "enabled for multi-user"              "$unit" "WantedBy=multi-user.target"
}

# =============================================================================
# Configuration handling
# =============================================================================

test_config_handling() {
    section "Example configuration"
    load_config "$EXAMPLE_CONF"
    config_validate
    assert_equals "example config has no validation errors"   "0" "${#CT_ERRORS[@]}"
    assert_equals "example config has no warnings"            "0" "${#CT_WARNINGS[@]}"
    local key missing="" undocumented="" features readme
    features=$(BINADIT_CONFIG_DIR="$CONFIG_DIR" bash "$FW" features 2>/dev/null)
    readme=$(cat "${PROJECT_DIR}/README.md")
    for key in $ALL_CONFIG_KEYS; do
        grep -q "^${key}=" "$EXAMPLE_CONF" || missing+=" $key"
        [[ "$features" == *"$key"* && "$readme" == *"$key"* ]] || undocumented+=" $key"
    done
    assert_equals "every supported key is in the example config"          "" "$missing"
    assert_equals "every supported key is documented (features + README)" "" "$undocumented"
    local unknown=""
    while IFS='=' read -r key _; do
        [[ " $ALL_CONFIG_KEYS " == *" $key "* ]] || unknown+=" $key"
    done < <(grep -E '^[A-Z_0-9]+=' "$EXAMPLE_CONF")
    assert_equals "example config has no unknown keys"                    "" "$unknown"

    section "Defaults for configs written by older versions"
    echo 'TCP_PORTS="80"' > "$CONF"
    local out
    out=$(set -u; load_config "$CONF"; echo "ok:${RATE_LIMIT_ENABLE}:${BLACKLIST}:${CONN_RATE_PER_IP}:${DNS_REFRESH_INTERVAL}" 2>&1)
    assert_equals "missing keys get defaults (no unbound variables)" "ok:true::0:5" "$out"
    load_config "$CONF"; resolve_config_hosts
    assert_true  "nft ruleset builds from a minimal config"      nft_build_ruleset
    assert_true  "iptables ruleset builds from a minimal config" ipt_build_ruleset 4

    section "config_set_value"
    cat > "$CONF" <<'EOF'
# comment
TCP_PORTS="80 443"
PORT_IP_RULES="tcp|3306|10.0.0.5
tcp|5432|10.0.0.6"
BLACKLIST=""
# trailing comment
EOF
    chmod 640 "$CONF"
    config_set_value "$CONF" TCP_PORTS "22 80"
    assert_equals "replaces a value"                  '22 80' "$(load_config "$CONF"; echo "$TCP_PORTS")"
    config_set_value "$CONF" BLACKLIST "10.0.0.0/8 1.2.3.4-1.2.3.9 a&b.example.com"
    assert_equals "handles / & and - in values"       '10.0.0.0/8 1.2.3.4-1.2.3.9 a&b.example.com' "$(load_config "$CONF"; echo "$BLACKLIST")"
    config_set_value "$CONF" PORT_IP_RULES "tcp|6379|10.0.0.7"
    assert_equals "replaces a multi-line value completely" 'tcp|6379|10.0.0.7' "$(load_config "$CONF"; echo "$PORT_IP_RULES")"
    assert_true   "file is still valid bash afterwards"  bash -n "$CONF"
    assert_equals "no leftover lines from the old multi-line value" "0" "$(grep -c '5432' "$CONF")"
    config_set_value "$CONF" PORT_IP_RULES $'tcp|1|10.0.0.1\ntcp|2|10.0.0.2'
    assert_equals "writes a multi-line value"         "2" "$(load_config "$CONF"; echo "$PORT_IP_RULES" | wc -l | tr -d ' ')"
    config_set_value "$CONF" UDP_PORTS "53"
    assert_equals "appends a key that is missing"     '53' "$(load_config "$CONF"; echo "$UDP_PORTS")"
    assert_equals "comments are preserved"            "2" "$(grep -c '^# ' "$CONF")"
    assert_false  "refuses a value with a double quote"   config_set_value "$CONF" TCP_PORTS '80" ; reboot ; "'
    assert_false  "refuses a value with \$( )"            config_set_value "$CONF" TCP_PORTS '$(reboot)'
    assert_false  "refuses a value with backticks"        config_set_value "$CONF" TCP_PORTS '`reboot`'
    assert_equals "refused values leave the file untouched" '22 80' "$(load_config "$CONF"; echo "$TCP_PORTS")"
    local perms
    perms=$(stat -c '%a' "$CONF" 2>/dev/null || stat -f '%Lp' "$CONF")
    assert_equals "file permissions are preserved"    "640" "$perms"

    section "configtest"
    _ct() { use_config; config_validate; }
    assert_true  "valid config passes"                                 _ct <<< 'TCP_PORTS="80 443 8000:9000"'
    assert_false "invalid port fails"                                  _ct <<< 'TCP_PORTS="80 abc"'
    assert_false "port 70000 fails"                                    _ct <<< 'UDP_PORTS="70000"'
    assert_false "invalid port in BLOCKED_TCP_PORTS_OUTPUT fails"      _ct <<< 'BLOCKED_TCP_PORTS_OUTPUT="25,587"'
    assert_false "invalid boolean fails"                               _ct <<< 'ICMP_ENABLE="yes"'
    assert_false "uppercase TRUE fails"                                _ct <<< 'NAT_ENABLE="TRUE"'
    assert_false "invalid address fails"                               _ct <<< 'TRUSTED_IPS="300.1.1.1"'
    assert_false "invalid IPv6 entry fails"                            _ct <<< 'BLACKLIST_IPV6="2001:db8::zz"'
    assert_false "invalid IPv6 SSH entry fails"                        _ct <<< 'SSH_ALLOWED_IPS_IPV6="fe80:::1"'
    assert_true  "IPv6 in a generic list is accepted"                  _ct <<< 'TRUSTED_IPS="2001:db8::1 10.0.0.1"'
    assert_true  "hostname is accepted"                                _ct <<< 'SSH_ALLOWED_IPS="office.example.com"'
    assert_false "non-numeric CONN_LIMIT_PER_IP fails"                 _ct <<< 'CONN_LIMIT_PER_IP="many"'
    assert_false "invalid RATE_LIMIT_RATE fails"                       _ct <<< 'RATE_LIMIT_RATE="fast"'
    assert_false "RATE_LIMIT_BURST=0 fails"                            _ct <<< 'RATE_LIMIT_BURST="0"'
    assert_false "invalid SSH_PORT fails"                              _ct <<< 'SSH_PORT="ssh"'
    assert_false "PORT_IP_RULES with bad protocol fails"               _ct <<< 'PORT_IP_RULES="icmp|80|10.0.0.1"'
    assert_false "PORT_IP_RULES with missing field fails"              _ct <<< 'PORT_IP_RULES="tcp|3306"'
    assert_false "PORT_IP_RULES with bad address fails"                _ct <<< 'PORT_IP_RULES="tcp|3306|10.0.0.999"'
    assert_true  "PORT_IP_RULES multi-line is accepted"                _ct <<< $'PORT_IP_RULES="tcp|3306|10.0.0.5\nudp|5060|sip.example.com"'
    assert_false "PORT_FORWARD_RULES with hostname target fails"       _ct <<< $'NAT_ENABLE="true"\nPORT_FORWARD_RULES="tcp|80|web.example.com:80"'
    assert_false "PORT_FORWARD_RULES with bad port fails"              _ct <<< $'NAT_ENABLE="true"\nPORT_FORWARD_RULES="tcp|80|10.0.0.5:99999"'
    assert_true  "valid PORT_FORWARD_RULES is accepted"                _ct <<< $'NAT_ENABLE="true"\nPORT_FORWARD_RULES="tcp|8080|10.0.0.5:80"'
    assert_false "NAT with invalid interface name fails"               _ct <<< $'NAT_ENABLE="true"\nNAT_EXTERNAL_IFACE="eth0; drop"'

    _warns() { use_config; config_validate; [[ "${CT_WARNINGS[*]:-}" == *"$WARN_NEEDLE"* ]]; }
    WARN_NEEDLE="SMTP_ENABLE=false has no effect";  assert_true "warns that SMTP_ENABLE=false does nothing"       _warns <<< 'SMTP_ENABLE="false"'
    WARN_NEEDLE="TCP_PORTS_OUTPUT has no effect";   assert_true "warns that TCP_PORTS_OUTPUT does nothing"        _warns <<< 'TCP_PORTS_OUTPUT="123"'
    WARN_NEEDLE="port forwarding is NOT active";    assert_true "warns about port forwards without NAT"           _warns <<< 'PORT_FORWARD_RULES="tcp|8080|10.0.0.5:80"'
    WARN_NEEDLE="does not exist";                   assert_true "warns about a missing custom rules file"         _warns <<< 'CUSTOM_RULES_FILE="/nonexistent/rules"'
    WARN_NEEDLE="the restriction wins";             assert_true "warns when SSH port is in TCP_PORTS but SSH is restricted" _warns <<< $'TCP_PORTS="22 80"\nSSH_ALLOWED_IPS="1.2.3.4"'
    WARN_NEEDLE="No open ports defined";            assert_true "warns when no ports are open"                    _warns <<< 'TCP_PORTS=""'

    echo 'TCP_PORTS="80' > "$CONF"
    assert_false "bash syntax error in config fails configtest"   configtest "$CONF"
    assert_false "missing config file fails configtest"           configtest "$WORK/nope.conf"
    echo 'TCP_PORTS="80 bad"' > "$CONF"
    out=$(BINADIT_CONFIG_DIR="$CONFIG_DIR" bash "$FW" configtest 2>&1); local rc=$?
    assert_equals "CLI configtest exits 1 on errors"              "1" "$rc"
    assert_has    "CLI configtest names the bad value"            "$out" "bad"
    assert_has    "CLI configtest prints the FAILED summary"      "$out" "FAILED"
}

# =============================================================================
# CLI
# =============================================================================

test_cli() {
    section "CLI"
    local out rc
    fw() { BINADIT_CONFIG_DIR="$CONFIG_DIR" BINADIT_SKIP_SYSTEM_HOOKS=true bash "$FW" "$@"; }

    out=$(fw help 2>&1); rc=$?
    assert_equals "help exits 0"                       "0" "$rc"
    local cmd
    for cmd in start stop restart reload status "config show" configtest dns-refresh setup features \
               update auto-update upgrade backup motd-on motd-off prompt-on prompt-off version; do
        assert_has "help documents '$cmd'"             "$out" "$cmd"
    done
    out=$(fw bogus 2>&1); rc=$?
    assert_equals "unknown command exits 1"            "1" "$rc"
    out=$(fw version 2>&1)
    assert_has "version prints the version"            "$out" "$BINADIT_VERSION"
    assert_true "features exits 0"                     fw features

    cp "$EXAMPLE_CONF" "$CONF"
    assert_equals "config get"                         "80 443" "$(fw config get TCP_PORTS 2>/dev/null)"
    assert_false  "config get refuses unknown keys"    fw config get NOPE
    assert_true   "config show works"                  fw config show

    if [[ $EUID -ne 0 ]]; then
        echo -e "  ${YELLOW}⊘${NC} config set/add/remove tests need root — skipped"
        return 0
    fi

    assert_true   "config add"                         fw config add TCP_PORTS 8080
    assert_equals "config add appended the value"      "80 443 8080" "$(fw config get TCP_PORTS)"
    fw config add TCP_PORTS 8080 >/dev/null 2>&1
    assert_equals "config add ignores duplicates"      "80 443 8080" "$(fw config get TCP_PORTS)"
    assert_false  "config add refuses an invalid port" fw config add TCP_PORTS notaport
    assert_equals "…and leaves the config untouched"   "80 443 8080" "$(fw config get TCP_PORTS)"
    assert_true   "config remove"                      fw config remove TCP_PORTS 443
    assert_equals "config remove removed only that value" "80 8080" "$(fw config get TCP_PORTS)"
    fw config add BLACKLIST 1.2.3.4 >/dev/null 2>&1; fw config add BLACKLIST 1.2.3.44 >/dev/null 2>&1
    fw config remove BLACKLIST 1.2.3.4 >/dev/null 2>&1
    assert_equals "config remove matches whole values only" "1.2.3.44" "$(fw config get BLACKLIST)"
    assert_true   "config add accepts a CIDR"          fw config add TRUSTED_IPS 10.0.0.0/8
    assert_true   "config add accepts a hostname"      fw config add SSH_ALLOWED_IPS office.example.com
    assert_false  "config add refuses an invalid address" fw config add TRUSTED_IPS 300.1.1.1
    assert_false  "config add refuses non-list keys"   fw config add ICMP_ENABLE true
    assert_true   "config set boolean"                 fw config set ICMP_ENABLE false
    assert_equals "config set stored the value"        "false" "$(fw config get ICMP_ENABLE)"
    assert_false  "config set refuses an invalid boolean" fw config set ICMP_ENABLE maybe
    assert_equals "…and leaves the config untouched"   "false" "$(fw config get ICMP_ENABLE)"
    assert_true   "config set to empty"                fw config set SSH_ALLOWED_IPS ""
    assert_equals "config set stored the empty value"  "" "$(fw config get SSH_ALLOWED_IPS)"
    assert_true   "config set multi-line rules"        fw config set PORT_IP_RULES $'tcp|3306|10.0.0.5\ntcp|5432|10.0.0.6'
    assert_true   "config set replaces multi-line rules" fw config set PORT_IP_RULES "tcp|6379|10.0.0.7"
    assert_equals "…completely"                        "tcp|6379|10.0.0.7" "$(fw config get PORT_IP_RULES)"
    assert_false  "config set refuses unknown keys"    fw config set NOPE 1
    load_config "$CONF"; config_validate
    assert_equals "config is still valid after all CLI edits" "0" "${#CT_ERRORS[@]}"
}

# =============================================================================
# Hostname resolution and cache
# =============================================================================

test_dns() {
    section "Hostname resolution and cache"
    rm -rf "$CONFIG_DIR/state"
    DNS4=([office.test.example]="198.51.100.7" [multi.test.example]="198.51.100.1 198.51.100.2")
    DNS6=([office.test.example]="2001:db8::7")
    use_config <<'EOF'
SSH_ALLOWED_IPS="office.test.example 10.0.0.1"
TRUSTED_IPS="multi.test.example Office.Test.Example"
PORT_IP_RULES="tcp|3306|multi.test.example"
EOF
    assert_equals "finds each hostname once (case-insensitive)" "office.test.example multi.test.example" "$(config_hostnames | tr '\n' ' ' | sed 's/ $//')"
    resolve_config_hosts
    collect_addrs $SSH_ALLOWED_IPS
    assert_equals "hostname resolves to its IPv4 address"   "198.51.100.7 10.0.0.1" "${ADDR4[*]}"
    assert_equals "hostname resolves to its IPv6 address"   "2001:db8::7"           "${ADDR6[*]}"
    collect_addrs multi.test.example
    assert_equals "all A records are used"                  "198.51.100.1 198.51.100.2" "${ADDR4[*]}"
    dns_cache_save
    assert_true   "cache file is written"                   test -s "$(dns_cache_file)"
    local first; first=$(dns_cache_render)

    # DNS goes down: cached addresses are used
    DNS4=(); DNS6=()
    resolve_config_hosts 2>/dev/null
    collect_addrs office.test.example
    assert_equals "DNS failure: cached IPv4 address is used"   "198.51.100.7" "${ADDR4[*]:-}"
    assert_equals "DNS failure: cached IPv6 address is used"   "2001:db8::7"  "${ADDR6[*]:-}"
    assert_has    "DNS failure is recorded as stale"           "$_DNS_STALE" "office.test.example"
    assert_equals "DNS failure does not look like a change"    "$first" "$(dns_cache_render)"

    # Address changes
    DNS4=([office.test.example]="203.0.113.9" [multi.test.example]="198.51.100.1 198.51.100.2")
    DNS6=()
    resolve_config_hosts
    collect_addrs office.test.example
    assert_equals "changed address is picked up"            "203.0.113.9" "${ADDR4[*]:-}"
    assert_equals "removed AAAA record is dropped"          "" "${ADDR6[*]:-}"
    assert_true   "change is detectable against the cache"  test "$first" != "$(dns_cache_render)"

    # Never resolvable
    use_config <<< 'TRUSTED_IPS="nope.test.example"'
    resolve_config_hosts 2>/dev/null
    collect_addrs $TRUSTED_IPS
    assert_equals "unresolvable host without cache yields no address" "0" "${#ADDR4[@]}"
    assert_has    "…and is reported"                        "$_DNS_UNRESOLVED" "nope.test.example"
    local rules; rules=$(nft_build_ruleset)
    assert_lacks  "unresolvable hostname never ends up in the ruleset" "$rules" "nope.test.example"
    DNS4=(); DNS6=()
}

# =============================================================================
# Generated rulesets
# =============================================================================

test_rulesets() {
    local nft ipt4 ipt6 input

    section "nftables ruleset — default configuration"
    load_config "$EXAMPLE_CONF"; SSH_PORTS="22"
    nft=$(build_nft)
    input=$(nft_chain "$nft" input)
    assert_has    "replaces the table atomically"              "$nft" "delete table inet binadit"
    assert_has    "input policy is drop"                       "$input" "type filter hook input priority 0; policy drop;"
    assert_has    "forward policy is drop"                     "$nft" "type filter hook forward priority 0; policy drop;"
    assert_has    "output policy is accept"                    "$nft" "type filter hook output priority 0; policy accept;"
    assert_has    "configured ports are opened"                "$input" "tcp dport { 80, 443 } accept"
    assert_has    "SSH stays reachable"                        "$input" "tcp dport { 22 } accept"
    # The 3.0.x hole: rate limiters that ACCEPT traffic to any port
    assert_no_match "no rate limiter accepts traffic"          "$input" 'limit rate.*accept'
    assert_no_match "no blanket accept for new connections"    "$input" 'ct state new.*accept'
    assert_no_match "every accept is tied to a port, address, interface or ICMP type" \
        "$(grep -E 'accept$' <<< "$input")" '^ *(tcp flags|ct state new|meta l4proto|ip protocol|accept)'
    assert_matches "rate limit is per source IP"               "$input" 'meter ratelimit_v4 .*ip saddr .*limit rate over 25/second burst 100 packets \} drop'
    assert_matches "IPv6 rate limit is per /64"                "$input" 'meter ratelimit_v6 .*ip6 saddr & ffff:ffff:ffff:ffff::'
    assert_before  "rate limit is checked before ports are opened" "$input" "meter ratelimit_v4" "tcp dport { 80, 443 } accept"
    assert_before  "blacklist is checked before established"   "$input" "@blacklist_v4 drop" "ct state established,related accept"
    assert_before  "trusted IPs bypass the rate limit"         "$input" "@trusted_v4 accept" "meter ratelimit_v4"
    assert_has    "invalid packets are dropped"                "$input" "ct state invalid drop"
    assert_has    "ping is answered"                           "$input" "icmp type echo-request accept"
    assert_has    "essential ICMPv6 is allowed"                "$input" "nd-neighbor-solicit"
    assert_has    "dropped packets are logged"                 "$input" 'log prefix "binadit-drop: "'
    assert_lacks  "no NAT table without NAT_ENABLE"            "$nft" "table ip binadit_nat {"
    assert_lacks  "CONN_RATE_PER_IP=0 adds no rule"            "$input" "connrate_v4"
    assert_lacks  "CONN_LIMIT_ENABLE=false adds no rule"       "$input" "connlimit_v4"

    section "nftables ruleset — every setting changes the rules"
    DNS4=([office.test.example]="198.51.100.7"); DNS6=([office.test.example]="2001:db8::7")
    use_config <<'EOF'
TCP_PORTS="22 80 8000:9000 80"
TCP_PORTS_INPUT="8443"
UDP_PORTS="53 5000:5010"
BLOCKED_TCP_PORTS="23"
BLOCKED_UDP_PORTS="69"
BLOCKED_TCP_PORTS_OUTPUT="25 587"
BLOCKED_UDP_PORTS_OUTPUT="1900"
SSH_PORT="22 2222"
SSH_ALLOWED_IPS="office.test.example 10.0.0.0/24"
TRUSTED_IPS="10.9.9.9"
TRUSTED_IPS_IPV6="2001:db8:1::/48"
TRUSTED_RANGES="192.168.1.1-192.168.1.254"
BLACKLIST="5.6.7.8"
BLACKLIST_IPV6="2001:db8:bad::/64"
BLOCKED_RANGES="65.208.151.1-65.208.151.254"
PORT_IP_RULES="tcp|3306|10.0.0.5
tcp|5432|office.test.example
udp|5060:5070|2001:db8::5"
ICMP_ENABLE="false"
MULTICAST_ENABLE="true"
RATE_LIMIT_RATE="600/minute"
RATE_LIMIT_BURST="50"
CONN_LIMIT_ENABLE="true"
CONN_LIMIT_PER_IP="30"
CONN_RATE_PER_IP="15"
DROP_INVALID="false"
BLOCK_COMMON_ATTACKS="false"
LOG_DROPPED="false"
SYN_FLOOD_PROTECT="false"
NAT_ENABLE="true"
NAT_EXTERNAL_IFACE="wan0"
NAT_INTERNAL_IFACE="lan0"
PORT_FORWARD_RULES="tcp|8080|192.168.1.100:80
udp|6000:6010|192.168.1.200"
EOF
    nft=$(build_nft)
    input=$(nft_chain "$nft" input)
    local output forward
    output=$(nft_chain "$nft" output); forward=$(nft_chain "$nft" forward)
    assert_has    "port ranges use nft syntax, duplicates removed" "$input" "tcp dport { 80, 8000-9000, 8443 } accept"
    assert_has    "UDP ports and ranges"                        "$input" "udp dport { 53, 5000-5010 } accept"
    assert_has    "blocked TCP port dropped on input"           "$input" "tcp dport { 23 } drop"
    assert_has    "blocked UDP port dropped on input"           "$input" "udp dport { 69 } drop"
    assert_before "blocked ports win over trusted IPs"          "$input" "tcp dport { 23 } drop" "@trusted_v4 accept"
    assert_has    "blocked + output-blocked TCP ports on output" "$output" "tcp dport { 23, 25, 587 } drop"
    assert_has    "blocked + output-blocked UDP ports on output" "$output" "udp dport { 69, 1900 } drop"
    assert_has    "blacklist blocks outgoing too"               "$output" "ip daddr @blacklist_v4 drop"
    assert_matches "blacklist set: address and range"           "$nft" 'elements = \{ 5\.6\.7\.8, 65\.208\.151\.1-65\.208\.151\.254 \}'
    assert_matches "blacklist v6 set"                           "$nft" 'elements = \{ 2001:db8:bad::/64 \}'
    assert_matches "trusted set: address and range"             "$nft" 'elements = \{ 10\.9\.9\.9, 192\.168\.1\.1-192\.168\.1\.254 \}'
    assert_matches "SSH allow-list: resolved hostname + CIDR"   "$nft" 'elements = \{ 198\.51\.100\.7, 10\.0\.0\.0/24 \}'
    assert_matches "SSH allow-list: hostname AAAA record"       "$nft" 'elements = \{ 2001:db8::7 \}'
    assert_has    "SSH allow-list covers all SSH ports"         "$input" "ip saddr @ssh_allowed_v4 tcp dport { 22, 2222 } accept"
    assert_has    "restricted SSH is closed for everyone else"  "$input" "tcp dport { 22, 2222 } drop"
    assert_before "…before TCP_PORTS could open it again"       "$input" "tcp dport { 22, 2222 } drop" "tcp dport { 80, 8000-9000, 8443 } accept"
    assert_before "SSH allow-list is not rate limited"          "$input" "@ssh_allowed_v4 tcp dport" "meter ratelimit_v4"
    assert_has    "PORT_IP_RULES: IPv4"                         "$input" "ip saddr 10.0.0.5 tcp dport 3306 accept"
    assert_has    "PORT_IP_RULES: hostname → IPv4"              "$input" "ip saddr 198.51.100.7 tcp dport 5432 accept"
    assert_has    "PORT_IP_RULES: hostname → IPv6"              "$input" "ip6 saddr 2001:db8::7 tcp dport 5432 accept"
    assert_has    "PORT_IP_RULES: IPv6 + port range"            "$input" "ip6 saddr 2001:db8::5 udp dport 5060-5070 accept"
    assert_has    "ICMP_ENABLE=false drops ping"                "$input" "icmp type echo-request drop"
    assert_has    "…for IPv6 too"                               "$input" "icmpv6 type echo-request drop"
    assert_has    "…but keeps essential ICMPv6"                 "$input" "nd-neighbor-advert } accept"
    assert_has    "MULTICAST_ENABLE adds multicast rules"       "$input" "ip daddr 224.0.0.0/4 accept"
    assert_matches "RATE_LIMIT_RATE with unit and burst"        "$input" 'ratelimit_v4 .*limit rate over 600/minute burst 50 packets'
    assert_matches "CONN_LIMIT_PER_IP is per source IP"         "$input" 'meter connlimit_v4 .*ip saddr ct count over 30 \} drop'
    assert_matches "CONN_RATE_PER_IP is per source IP"          "$input" 'meter connrate_v4 .*ip saddr .*limit rate over 15/second burst 15 packets \} drop'
    assert_lacks  "DROP_INVALID=false removes the rule"         "$input" "ct state invalid drop"
    assert_lacks  "BLOCK_COMMON_ATTACKS=false removes the rule" "$input" "137-139"
    assert_lacks  "LOG_DROPPED=false removes the log rule"      "$input" "binadit-drop"
    assert_lacks  "SYN_FLOOD_PROTECT=false removes flag checks" "$input" "tcp flags & (fin | syn) == fin | syn drop"
    assert_has    "NAT: LAN may go out"                         "$forward" 'iifname "lan0" accept'
    assert_has    "NAT: only port forwards may come in"         "$forward" "ct status dnat accept"
    assert_lacks  "NAT: no blanket accept towards the LAN"      "$forward" 'oifname "lan0" accept'
    assert_no_match "NAT: interfaces matched by name (works before they exist)" "$nft" '(iif|oif) (wan0|lan0)'
    assert_has    "NAT: masquerade on the external interface"   "$nft" 'oifname "wan0" masquerade'
    assert_has    "NAT: port forward on the external interface" "$nft" 'iifname "wan0" tcp dport 8080 dnat to 192.168.1.100:80'
    assert_has    "NAT: port-range forward"                     "$nft" 'iifname "wan0" udp dport 6000-6010 dnat to 192.168.1.200'

    use_config <<< 'SSH_ALLOWED_IPS_IPV6="2001:db8::1"'
    input=$(nft_chain "$(build_nft)" input)
    assert_has    "IPv6-only SSH allow-list also closes IPv4 SSH" "$input" "tcp dport { 22 } drop"
    assert_no_match "…no open SSH accept remains"                "$input" '^ +tcp dport \{ 22 \} accept'

    use_config <<< $'NAT_ENABLE="false"\nPORT_FORWARD_RULES="tcp|8080|192.168.1.100:80"'
    assert_lacks  "port forwards are not installed without NAT_ENABLE" "$(build_nft)" "dnat to"

    use_config <<< $'TCP_PORTS=""\nUDP_PORTS=""'
    input=$(nft_chain "$(build_nft)" input)
    assert_has    "no ports configured: SSH still reachable"    "$input" "tcp dport { 22 } accept"
    assert_no_match "no ports configured: no empty port sets"   "$input" 'dport \{ *\}'

    section "iptables ruleset — default configuration"
    load_config "$EXAMPLE_CONF"; SSH_PORTS="22"
    ipt4=$(build_ipt 4 true); ipt6=$(build_ipt 6)
    assert_has    "IPv4 input policy is DROP"                   "$ipt4" ":INPUT DROP"
    assert_has    "IPv4 forward policy is DROP"                 "$ipt4" ":FORWARD DROP"
    assert_has    "IPv4 output policy is ACCEPT"                "$ipt4" ":OUTPUT ACCEPT"
    assert_has    "IPv6 input policy is DROP"                   "$ipt6" ":INPUT DROP"
    assert_has    "configured ports are opened"                 "$ipt4" "-A INPUT -p tcp --dport 443 -j ACCEPT"
    assert_has    "IPv6: configured ports are opened"           "$ipt6" "-A INPUT -p tcp --dport 443 -j ACCEPT"
    assert_has    "SSH stays reachable"                         "$ipt4" "-A INPUT -p tcp --dport 22 -j ACCEPT"
    assert_has    "IPv6: SSH stays reachable"                   "$ipt6" "-A INPUT -p tcp --dport 22 -j ACCEPT"
    # The 3.0.x hole: "-m limit ... -j ACCEPT" on every SYN
    assert_no_match "no rate limiter accepts traffic"           "$ipt4" '-m (limit|hashlimit).*-j ACCEPT'
    assert_no_match "IPv6: no rate limiter accepts traffic"     "$ipt6" '-m (limit|hashlimit).*-j ACCEPT'
    assert_no_match "every INPUT accept is tied to a port, address, interface, state or ICMP type" \
        "$(grep -E '^-A INPUT.*-j ACCEPT$' <<< "$ipt4")" '^-A INPUT (-p (tcp|udp) )?-j ACCEPT$'
    assert_matches "rate limit is per source IP"                "$ipt4" '--hashlimit-mode srcip --hashlimit-above 25/second --hashlimit-burst 100 .*-j DROP'
    assert_matches "IPv6 rate limit is per /64"                 "$ipt6" '--hashlimit-mode srcip --hashlimit-srcmask 64 --hashlimit-above 25/second'
    assert_before  "rate limit is checked before ports are opened" "$ipt4" "--hashlimit-above 25/second" "--dport 443 -j ACCEPT"
    assert_has    "essential ICMPv6 is allowed"                 "$ipt6" "--icmpv6-type neighbour-solicitation -j ACCEPT"
    assert_has    "marker chain present (status detection)"     "$ipt4" ":binadit-firewall -"
    assert_equals "IPv4 file has filter + nat COMMIT"           "2" "$(grep -c '^COMMIT$' <<< "$ipt4")"
    assert_lacks  "no NAT rules without NAT_ENABLE"             "$ipt4" "MASQUERADE"
    assert_lacks  "IPv6 file has no nat table"                  "$ipt6" "*nat"

    section "iptables ruleset — every setting changes the rules"
    use_config <<'EOF'
TCP_PORTS="22 80 8000:9000"
UDP_PORTS="53"
BLOCKED_TCP_PORTS="23"
BLOCKED_TCP_PORTS_OUTPUT="25"
SSH_ALLOWED_IPS="office.test.example 10.0.0.0/24"
TRUSTED_IPS="10.9.9.9 2001:db8:1::/48"
TRUSTED_RANGES="192.168.1.1-192.168.1.254"
BLACKLIST="5.6.7.8"
BLOCKED_RANGES="65.208.151.1-65.208.151.254"
BLOCKED_RANGES_IPV6="2001:db8:bad::1-2001:db8:bad::ff"
PORT_IP_RULES="tcp|3306|10.0.0.5
tcp|5432|office.test.example"
ICMP_ENABLE="false"
CONN_LIMIT_ENABLE="true"
CONN_LIMIT_PER_IP="30"
CONN_RATE_PER_IP="15"
NAT_ENABLE="true"
NAT_EXTERNAL_IFACE="wan0"
NAT_INTERNAL_IFACE="lan0"
PORT_FORWARD_RULES="tcp|8080|192.168.1.100:80"
EOF
    ipt4=$(build_ipt 4 true); ipt6=$(build_ipt 6)
    assert_has    "port range"                                  "$ipt4" "-A INPUT -p tcp --dport 8000:9000 -j ACCEPT"
    assert_has    "blocked port: input"                         "$ipt4" "-A INPUT -p tcp --dport 23 -j DROP"
    assert_has    "blocked port: output"                        "$ipt4" "-A OUTPUT -p tcp --dport 23 -j DROP"
    assert_has    "output-only blocked port"                    "$ipt4" "-A OUTPUT -p tcp --dport 25 -j DROP"
    assert_lacks  "output-only blocked port is not blocked inbound" "$ipt4" "-A INPUT -p tcp --dport 25 -j DROP"
    assert_has    "IPv6: blocked ports apply too"               "$ipt6" "-A OUTPUT -p tcp --dport 25 -j DROP"
    assert_has    "blacklist in"                                "$ipt4" "-A INPUT -s 5.6.7.8 -j DROP"
    assert_has    "blacklist out"                               "$ipt4" "-A OUTPUT -d 5.6.7.8 -j DROP"
    assert_has    "blocked range uses iprange"                  "$ipt4" "-A INPUT -m iprange --src-range 65.208.151.1-65.208.151.254 -j DROP"
    assert_has    "IPv6 blocked range uses iprange"             "$ipt6" "-A INPUT -m iprange --src-range 2001:db8:bad::1-2001:db8:bad::ff -j DROP"
    assert_has    "trusted IPv4"                                "$ipt4" "-A INPUT -s 10.9.9.9 -j ACCEPT"
    assert_has    "trusted IPv6 from a generic list"            "$ipt6" "-A INPUT -s 2001:db8:1::/48 -j ACCEPT"
    assert_lacks  "IPv6 addresses never end up in the IPv4 rules" "$ipt4" "2001:db8"
    assert_lacks  "IPv4 addresses never end up in the IPv6 rules" "$ipt6" "10.9.9.9"
    assert_has    "SSH allow-list: resolved hostname"           "$ipt4" "-A INPUT -s 198.51.100.7 -p tcp --dport 22 -j ACCEPT"
    assert_has    "SSH allow-list: hostname AAAA record"        "$ipt6" "-A INPUT -s 2001:db8::7 -p tcp --dport 22 -j ACCEPT"
    assert_has    "restricted SSH is closed for everyone else"  "$ipt4" "-A INPUT -p tcp --dport 22 -j DROP"
    assert_has    "IPv6: restricted SSH is closed for everyone else" "$ipt6" "-A INPUT -p tcp --dport 22 -j DROP"
    assert_before "…before TCP_PORTS could open it again"       "$ipt4" "-A INPUT -p tcp --dport 22 -j DROP" "-A INPUT -p tcp --dport 80 -j ACCEPT"
    assert_lacks  "SSH port from TCP_PORTS is not accepted for everyone" "$ipt4" "-A INPUT -p tcp --dport 22 -j ACCEPT"
    assert_has    "PORT_IP_RULES"                               "$ipt4" "-A INPUT -s 10.0.0.5 -p tcp --dport 3306 -j ACCEPT"
    assert_has    "PORT_IP_RULES: hostname → IPv6"              "$ipt6" "-A INPUT -s 2001:db8::7 -p tcp --dport 5432 -j ACCEPT"
    assert_has    "ICMP_ENABLE=false drops ping"                "$ipt4" "--icmp-type echo-request -j DROP"
    assert_matches "connection limit per IP"                    "$ipt4" '--connlimit-above 30 --connlimit-mask 32 -j DROP'
    assert_matches "IPv6 connection limit per /64"              "$ipt6" '--connlimit-above 30 --connlimit-mask 64 -j DROP'
    assert_matches "connection rate per IP"                     "$ipt4" '--hashlimit-above 15/second --hashlimit-burst 15 .*-j DROP'
    assert_has    "NAT: LAN may go out"                         "$ipt4" "-A FORWARD -i lan0 -j ACCEPT"
    assert_has    "NAT: only port forwards may come in"         "$ipt4" "-A FORWARD -m conntrack --ctstate DNAT -j ACCEPT"
    assert_lacks  "NAT: no blanket accept towards the LAN"      "$ipt4" "-A FORWARD -o lan0 -j ACCEPT"
    assert_has    "NAT: masquerade"                             "$ipt4" "-A POSTROUTING -o wan0 -j MASQUERADE"
    assert_has    "NAT: port forward on the external interface" "$ipt4" "-A PREROUTING -i wan0 -p tcp --dport 8080 -j DNAT --to-destination 192.168.1.100:80"
    assert_lacks  "IPv6 gets no NAT forwarding rules"           "$ipt6" "-A FORWARD"

    local n1 n2
    use_config <<< $'RATE_LIMIT_RATE="25"\nRATE_LIMIT_BURST="100"'; n1=$(build_ipt 4 | grep -o 'hashlimit-name [^ ]*')
    use_config <<< $'RATE_LIMIT_RATE="50"\nRATE_LIMIT_BURST="100"'; n2=$(build_ipt 4 | grep -o 'hashlimit-name [^ ]*')
    assert_true   "changed limits get a fresh hashlimit table (kernel keeps old settings per name)" test "$n1" != "$n2"
    assert_true   "hashlimit name fits the 15 character kernel limit" test "${#n1}" -le 30
    DNS4=(); DNS6=()
}

# =============================================================================
# Migration and helpers
# =============================================================================

test_migration() {
    section "v1.x config migration"
    local old="$WORK/host.conf" new="$WORK/migrated.conf"
    cat > "$old" <<'EOF'
TCPPORTS="80 443 20000:25000"		# TCP ports to open
TCPPORTS_INPUT="8080"
TCPPORTS_OUTPUT="123"
UDPPORTS="53"
DMZS="10.0.0.0/24 office.example.com"
SSHACCESS="1.2.3.4"
SSHACCESS_IPv6="2001:db8::1"
DMZRANGE="65.208.151.1-65.208.151.254"
BLACKLIST="5.6.7.8"
BLOCKRANGE=""
DMZS_IPv6=""
BLACKLIST_IPv6=""
MULTICAST_ENABLE="TRUE"
NATROUTER_ENABLE="FALSE"
EOF
    export BINADIT_V1_SSH_PORTS="22"
    migrate_v1_config "$old" "$new" "$EXAMPLE_CONF" >/dev/null 2>&1
    assert_true   "new config is created"              test -f "$new"
    load_config "$new"
    assert_equals "TCP ports migrated"                 "80 443 20000:25000" "$TCP_PORTS"
    assert_equals "TCP input ports migrated"           "8080" "$TCP_PORTS_INPUT"
    assert_equals "UDP ports migrated"                 "53" "$UDP_PORTS"
    assert_equals "DMZ with CIDR migrated (slash-safe)" "10.0.0.0/24 office.example.com" "$TRUSTED_IPS"
    assert_equals "SSH access keeps SSHACCESS + DMZS + DMZRANGE" \
        "1.2.3.4 10.0.0.0/24 office.example.com 65.208.151.1-65.208.151.254" "$SSH_ALLOWED_IPS"
    assert_equals "IPv6 SSH access migrated"           "2001:db8::1" "$SSH_ALLOWED_IPS_IPV6"
    assert_true   "SSH is restricted after migration"  ssh_is_restricted
    assert_equals "DMZ range migrated"                 "65.208.151.1-65.208.151.254" "$TRUSTED_RANGES"
    assert_equals "blacklist migrated"                 "5.6.7.8" "$BLACKLIST"
    assert_equals "TRUE becomes true"                  "true" "$MULTICAST_ENABLE"
    assert_equals "FALSE stays false"                  "false" "$NAT_ENABLE"
    config_validate
    assert_equals "migrated config validates"          "0" "${#CT_ERRORS[@]}"
    assert_false  "old config is moved away"           test -f "$old"
    assert_true   "old config is kept as backup"       bash -c "ls '$old'.migrated.* >/dev/null 2>&1"

    cat > "$old" <<< 'TCPPORTS=""'
    rm -f "$new"
    migrate_v1_config "$old" "$new" "$EXAMPLE_CONF" >/dev/null 2>&1
    load_config "$new"
    assert_equals "empty v1 port list does not become 80 443" "" "$TCP_PORTS"

    # v1 with only DMZS: SSH was reachable from the DMZ only — must stay so
    printf '%s\n' 'TCPPORTS="80 443"' 'DMZS="10.1.1.1"' 'DMZS_IPv6="2001:db8::1-2001:db8::ff"' > "$old"
    rm -f "$new"
    migrate_v1_config "$old" "$new" "$EXAMPLE_CONF" >/dev/null 2>&1
    load_config "$new"
    assert_equals "DMZS alone restricts SSH"           "10.1.1.1" "$SSH_ALLOWED_IPS"
    assert_equals "DMZS_IPv6 alone restricts SSH"      "2001:db8::1-2001:db8::ff" "$SSH_ALLOWED_IPS_IPV6"
    config_validate
    assert_equals "DMZ-only migration validates"       "0" "${#CT_ERRORS[@]}"

    # v1 with the SSH port in TCPPORTS: SSH was public — stays public
    for ports in '22 80' '20:30 80'; do
        printf '%s\n' "TCPPORTS=\"$ports\"" 'SSHACCESS="1.2.3.4"' 'DMZS="10.1.1.1"' > "$old"
        rm -f "$new"
        migrate_v1_config "$old" "$new" "$EXAMPLE_CONF" >/dev/null 2>&1
        load_config "$new"
        assert_equals "SSH port in TCPPORTS ($ports) keeps SSH public" "" "$SSH_ALLOWED_IPS$SSH_ALLOWED_IPS_IPV6"
    done

    # v1 that allowed SSH from nobody: cannot be expressed, must warn loudly
    printf '%s\n' 'TCPPORTS="80"' > "$old"
    rm -f "$new"
    local out
    out=$(migrate_v1_config "$old" "$new" "$EXAMPLE_CONF" 2>&1)
    assert_has    "warns when v1 had SSH closed for all" "$out" "OPEN TO EVERYONE"
    rm -f "$old".migrated.*
    unset BINADIT_V1_SSH_PORTS

    assert_true   "port_in_list: single port"          port_in_list 22 "80 22"
    assert_true   "port_in_list: range"                port_in_list 22 "80 20:25"
    assert_false  "port_in_list: no match"             port_in_list 22 "80 220 2:21"

    cat > "$old" <<< 'TCPPORTS="9999"'
    echo 'TCP_PORTS="80"' > "$new"
    migrate_v1_config "$old" "$new" "$EXAMPLE_CONF" >/dev/null 2>&1
    assert_equals "an existing new config is never overwritten" 'TCP_PORTS="80"' "$(cat "$new")"

    section "Helpers"
    assert_equals "join_comma"                         "a, b, c" "$(join_comma a b c)"
    assert_equals "_nft_port_set converts and dedupes" "80, 8000-9000, 443" "$(_nft_port_set 80 8000:9000 80 443)"
    split_rule " tcp | 3306 | 10.0.0.5 "
    assert_equals "split_rule trims fields"            "tcp/3306/10.0.0.5/3" "$R1/$R2/$R3/$RULE_NF"
    assert_true   "detect_ssh_ports returns a valid port" is_valid_port "$(detect_ssh_port)"
    use_config <<< 'SSH_PORT="2222"'
    assert_equals "SSH_PORT overrides detection"       "2222" "$SSH_PORTS"
    assert_equals "resolve_hostname passes IPs through" "1.2.3.4" "$(resolve_hostname 1.2.3.4)"
    assert_equals "resolve_hostname passes CIDR through" "10.0.0.0/8" "$(resolve_hostname 10.0.0.0/8)"
    local out
    out=$(log_info "x" 2>&1);    assert_has "log_info prints"    "$out" "x"
    out=$(log_error "x" 2>&1);   assert_has "log_error prints"   "$out" "x"
    out=$(BINADIT_DEBUG=false log_debug "x" 2>&1); assert_equals "log_debug is silent by default" "" "$out"
    out=$(BINADIT_DEBUG=true log_debug "x" 2>&1);  assert_has "log_debug prints when enabled" "$out" "x"
    out=$(show_banner 2>&1);     assert_has "banner shows the version" "$out" "v${BINADIT_VERSION}"
    cp "$EXAMPLE_CONF" "$CONF"
    out=$(print_rule_summary "$CONF" 2>&1)
    assert_has "rule summary lists open ports"         "$out" "80 443"
    assert_has "rule summary states SSH policy"        "$out" "open to everyone"
    NON_INTERACTIVE=true ask out "question? " "fallback"
    assert_equals "ask returns the default when non-interactive" "fallback" "$out"
    ask out "question? " "eof-default" < /dev/null >/dev/null 2>&1
    assert_equals "ask returns the default at end of input"      "eof-default" "$out"
    unset NON_INTERACTIVE
}

# =============================================================================
# Run all tests
# =============================================================================

main() {
    echo ""
    echo -e "${BOLD}========================================${NC}"
    echo -e "${BOLD} binadit-firewall v${BINADIT_VERSION} unit tests${NC}"
    echo -e "${BOLD}========================================${NC}"

    test_validation
    test_project
    test_config_handling
    test_cli
    test_dns
    test_rulesets
    test_migration

    echo ""
    echo -e "${BOLD}========================================${NC}"
    echo -e " Total:  ${TESTS_RUN}"
    echo -e " ${GREEN}Passed: ${TESTS_PASSED}${NC}"
    if [[ $TESTS_FAILED -gt 0 ]]; then
        echo -e " ${RED}Failed: ${TESTS_FAILED}${NC}"
        echo -e "${BOLD}========================================${NC}"
        exit 1
    fi
    echo -e " Failed: 0"
    echo -e "${BOLD}========================================${NC}"
    echo -e "\n ${GREEN}${BOLD}All tests passed!${NC}\n"
}

main "$@"
