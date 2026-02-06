#!/usr/bin/env bash
# =============================================================================
# binadit-firewall - Test Suite
# =============================================================================
# Tests for validation functions, config parsing, and backend detection.
# These tests can run on any system (macOS or Linux) without root.
#
# Usage: bash tests/test_firewall.sh
# =============================================================================

set -euo pipefail

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

# Determine paths
TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${TEST_DIR}/.." && pwd)"
SRC_DIR="${PROJECT_DIR}/src"
LIB_DIR="${SRC_DIR}/lib"
CONFIG_DIR="${PROJECT_DIR}/config"

# Source libraries (common.sh uses _BINADIT_COMMON_LOADED guard for re-source safety)
source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/backend.sh"

# =============================================================================
# Test framework
# =============================================================================

assert_equals() {
    local description="$1"
    local expected="$2"
    local actual="$3"
    TESTS_RUN=$((TESTS_RUN + 1))

    if [[ "$expected" == "$actual" ]]; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
        echo -e "  ${GREEN}✓${NC} $description"
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
        echo -e "  ${RED}✗${NC} $description"
        echo -e "    Expected: ${GREEN}${expected}${NC}"
        echo -e "    Actual:   ${RED}${actual}${NC}"
    fi
}

assert_true() {
    local description="$1"
    shift
    TESTS_RUN=$((TESTS_RUN + 1))

    if "$@" 2>/dev/null; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
        echo -e "  ${GREEN}✓${NC} $description"
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
        echo -e "  ${RED}✗${NC} $description (returned false)"
    fi
}

assert_false() {
    local description="$1"
    shift
    TESTS_RUN=$((TESTS_RUN + 1))

    if "$@" 2>/dev/null; then
        TESTS_FAILED=$((TESTS_FAILED + 1))
        echo -e "  ${RED}✗${NC} $description (returned true, expected false)"
    else
        TESTS_PASSED=$((TESTS_PASSED + 1))
        echo -e "  ${GREEN}✓${NC} $description"
    fi
}

assert_file_exists() {
    local description="$1"
    local filepath="$2"
    TESTS_RUN=$((TESTS_RUN + 1))

    if [[ -f "$filepath" ]]; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
        echo -e "  ${GREEN}✓${NC} $description"
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
        echo -e "  ${RED}✗${NC} $description (file not found: $filepath)"
    fi
}

assert_file_executable() {
    local description="$1"
    local filepath="$2"
    TESTS_RUN=$((TESTS_RUN + 1))

    if [[ -x "$filepath" ]] || head -1 "$filepath" 2>/dev/null | grep -q "^#!"; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
        echo -e "  ${GREEN}✓${NC} $description"
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
        echo -e "  ${RED}✗${NC} $description (not executable: $filepath)"
    fi
}

assert_contains() {
    local description="$1"
    local file="$2"
    local pattern="$3"
    TESTS_RUN=$((TESTS_RUN + 1))

    if grep -q "$pattern" "$file" 2>/dev/null; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
        echo -e "  ${GREEN}✓${NC} $description"
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
        echo -e "  ${RED}✗${NC} $description (pattern not found: $pattern)"
    fi
}

# =============================================================================
# Test: IPv4 validation
# =============================================================================

test_ipv4_validation() {
    echo -e "\n${BOLD}Test: IPv4 Validation${NC}"

    assert_true  "Valid IPv4: 192.168.1.1"       is_valid_ipv4 "192.168.1.1"
    assert_true  "Valid IPv4: 0.0.0.0"           is_valid_ipv4 "0.0.0.0"
    assert_true  "Valid IPv4: 255.255.255.255"   is_valid_ipv4 "255.255.255.255"
    assert_true  "Valid IPv4: 10.0.0.1"          is_valid_ipv4 "10.0.0.1"
    assert_false "Invalid IPv4: 256.1.1.1"       is_valid_ipv4 "256.1.1.1"
    assert_false "Invalid IPv4: 1.2.3"           is_valid_ipv4 "1.2.3"
    assert_false "Invalid IPv4: 1.2.3.4.5"       is_valid_ipv4 "1.2.3.4.5"
    assert_false "Invalid IPv4: abc.def.ghi.jkl" is_valid_ipv4 "abc.def.ghi.jkl"
    assert_false "Invalid IPv4: empty string"     is_valid_ipv4 ""
}

# =============================================================================
# Test: IPv6 validation
# =============================================================================

test_ipv6_validation() {
    echo -e "\n${BOLD}Test: IPv6 Validation${NC}"

    assert_true  "Valid IPv6: ::1"                              is_valid_ipv6 "::1"
    assert_true  "Valid IPv6: ::"                               is_valid_ipv6 "::"
    assert_true  "Valid IPv6: 2001:db8::1"                      is_valid_ipv6 "2001:db8::1"
    assert_true  "Valid IPv6: fe80::1"                          is_valid_ipv6 "fe80::1"
    assert_true  "Valid IPv6: 2001:0db8:85a3:0000:0000:8a2e:0370:7334" is_valid_ipv6 "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
    assert_false "Invalid IPv6: not-an-ip"                      is_valid_ipv6 "not-an-ip"
    assert_false "Invalid IPv6: 192.168.1.1"                    is_valid_ipv6 "192.168.1.1"
}

# =============================================================================
# Test: CIDR validation
# =============================================================================

test_cidr_validation() {
    echo -e "\n${BOLD}Test: CIDR Validation${NC}"

    assert_true  "Valid CIDR: 10.0.0.0/8"        is_valid_cidr "10.0.0.0/8"
    assert_true  "Valid CIDR: 192.168.1.0/24"     is_valid_cidr "192.168.1.0/24"
    assert_true  "Valid CIDR: 0.0.0.0/0"          is_valid_cidr "0.0.0.0/0"
    assert_true  "Valid CIDR: 10.0.0.1/32"        is_valid_cidr "10.0.0.1/32"
    assert_true  "Valid CIDR: 2001:db8::/32"       is_valid_cidr "2001:db8::/32"
    assert_false "Invalid CIDR: 10.0.0.0/33"      is_valid_cidr "10.0.0.0/33"
    assert_false "Invalid CIDR: 10.0.0.0"         is_valid_cidr "10.0.0.0"
    assert_false "Invalid CIDR: /24"              is_valid_cidr "/24"
    assert_false "Invalid CIDR: abc/24"           is_valid_cidr "abc/24"
}

# =============================================================================
# Test: Port validation
# =============================================================================

test_port_validation() {
    echo -e "\n${BOLD}Test: Port Validation${NC}"

    assert_true  "Valid port: 80"          is_valid_port "80"
    assert_true  "Valid port: 1"           is_valid_port "1"
    assert_true  "Valid port: 65535"       is_valid_port "65535"
    assert_true  "Valid port: 443"         is_valid_port "443"
    assert_true  "Valid range: 8000:9000"  is_valid_port "8000:9000"
    assert_true  "Valid range: 1:65535"    is_valid_port "1:65535"
    assert_false "Invalid port: 0"         is_valid_port "0"
    assert_false "Invalid port: 65536"     is_valid_port "65536"
    assert_false "Invalid port: abc"       is_valid_port "abc"
    assert_false "Invalid port: -1"        is_valid_port "-1"
    assert_false "Invalid range: 9000:8000" is_valid_port "9000:8000"
}

# =============================================================================
# Test: Host validation
# =============================================================================

test_host_validation() {
    echo -e "\n${BOLD}Test: Host Validation${NC}"

    assert_true  "Valid host: 192.168.1.1"       is_valid_host "192.168.1.1"
    assert_true  "Valid host: 10.0.0.0/24"       is_valid_host "10.0.0.0/24"
    assert_true  "Valid host: example.com"        is_valid_host "example.com"
    assert_true  "Valid host: sub.example.com"    is_valid_host "sub.example.com"
    assert_true  "Valid host: 2001:db8::1"        is_valid_host "2001:db8::1"
    assert_true  "Valid host: 1.2.3.4-5.6.7.8"   is_valid_host "1.2.3.4-5.6.7.8"
    assert_false "Invalid host: empty"            is_valid_host ""
}

# =============================================================================
# Test: Project structure
# =============================================================================

test_project_structure() {
    echo -e "\n${BOLD}Test: Project Structure${NC}"

    assert_file_exists "Main script exists"         "${SRC_DIR}/binadit-firewall.sh"
    assert_file_exists "Common lib exists"           "${LIB_DIR}/common.sh"
    assert_file_exists "Backend lib exists"          "${LIB_DIR}/backend.sh"
    assert_file_exists "nftables backend exists"     "${LIB_DIR}/backend_nftables.sh"
    assert_file_exists "iptables backend exists"     "${LIB_DIR}/backend_iptables.sh"
    assert_file_exists "Example config exists"       "${CONFIG_DIR}/firewall.conf.example"
    assert_file_exists "Systemd service exists"      "${CONFIG_DIR}/binadit-firewall.service"
    assert_file_exists "Install script exists"       "${PROJECT_DIR}/install.sh"
    assert_file_exists "README exists"               "${PROJECT_DIR}/README.md"
    assert_file_exists "CHANGELOG exists"            "${PROJECT_DIR}/CHANGELOG.md"
    assert_file_exists ".gitignore exists"           "${PROJECT_DIR}/.gitignore"

    assert_file_executable "Main script is executable"   "${SRC_DIR}/binadit-firewall.sh"
    assert_file_executable "Install script is executable" "${PROJECT_DIR}/install.sh"
}

# =============================================================================
# Test: Configuration file
# =============================================================================

test_config_file() {
    echo -e "\n${BOLD}Test: Configuration File${NC}"

    local config="${CONFIG_DIR}/firewall.conf.example"

    assert_contains "Config has TCP_PORTS"          "$config" "^TCP_PORTS="
    assert_contains "Config has TCP_PORTS_INPUT"    "$config" "^TCP_PORTS_INPUT="
    assert_contains "Config has TCP_PORTS_OUTPUT"   "$config" "^TCP_PORTS_OUTPUT="
    assert_contains "Config has UDP_PORTS"          "$config" "^UDP_PORTS="
    assert_contains "Config has BLOCKED_TCP_PORTS"  "$config" "^BLOCKED_TCP_PORTS="
    assert_contains "Config has BLOCKED_UDP_PORTS"  "$config" "^BLOCKED_UDP_PORTS="
    assert_contains "Config has SSH_ALLOWED_IPS"    "$config" "^SSH_ALLOWED_IPS="
    assert_contains "Config has TRUSTED_IPS"        "$config" "^TRUSTED_IPS="
    assert_contains "Config has BLACKLIST"          "$config" "^BLACKLIST="
    assert_contains "Config has PORT_IP_RULES"      "$config" "^PORT_IP_RULES="
    assert_contains "Config has ICMP_ENABLE"        "$config" "^ICMP_ENABLE="
    assert_contains "Config has MULTICAST_ENABLE"   "$config" "^MULTICAST_ENABLE="
    assert_contains "Config has NAT_ENABLE"         "$config" "^NAT_ENABLE="
    assert_contains "Config has RATE_LIMIT_ENABLE"  "$config" "^RATE_LIMIT_ENABLE="
    assert_contains "Config has LOG_DROPPED"        "$config" "^LOG_DROPPED="
    assert_contains "Config has SMTP_ENABLE"        "$config" "^SMTP_ENABLE="
    assert_contains "Config has TRUSTED_RANGES"     "$config" "^TRUSTED_RANGES="
    assert_contains "Config has BLOCKED_RANGES"     "$config" "^BLOCKED_RANGES="

    # v2.1.0 new features
    assert_contains "Config has SYN_FLOOD_PROTECT"    "$config" "^SYN_FLOOD_PROTECT="
    assert_contains "Config has CONN_LIMIT_ENABLE"    "$config" "^CONN_LIMIT_ENABLE="
    assert_contains "Config has CONN_LIMIT_PER_IP"    "$config" "^CONN_LIMIT_PER_IP="
    assert_contains "Config has CONN_RATE_PER_IP"     "$config" "^CONN_RATE_PER_IP="
    assert_contains "Config has DROP_INVALID"          "$config" "^DROP_INVALID="
    assert_contains "Config has BLOCK_COMMON_ATTACKS" "$config" "^BLOCK_COMMON_ATTACKS="
    assert_contains "Config has PORT_FORWARD_RULES"   "$config" "^PORT_FORWARD_RULES="
    assert_contains "Config has CUSTOM_RULES_FILE"    "$config" "^CUSTOM_RULES_FILE="

    # Verify config is valid bash
    TESTS_RUN=$((TESTS_RUN + 1))
    if bash -n "$config" 2>/dev/null; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
        echo -e "  ${GREEN}✓${NC} Config file is valid bash syntax"
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
        echo -e "  ${RED}✗${NC} Config file has bash syntax errors"
    fi
}

# =============================================================================
# Test: Systemd service file
# =============================================================================

test_systemd_service() {
    echo -e "\n${BOLD}Test: Systemd Service File${NC}"

    local service="${CONFIG_DIR}/binadit-firewall.service"

    assert_contains "Service has ExecStart"   "$service" "ExecStart="
    assert_contains "Service has ExecStop"    "$service" "ExecStop="
    assert_contains "Service has ExecReload"  "$service" "ExecReload="
    assert_contains "Service is Type=oneshot" "$service" "Type=oneshot"
    assert_contains "Service has RemainAfterExit" "$service" "RemainAfterExit=yes"
    assert_contains "Service has WantedBy"    "$service" "WantedBy=multi-user.target"
}

# =============================================================================
# Test: Install script
# =============================================================================

test_install_script() {
    echo -e "\n${BOLD}Test: Install Script${NC}"

    local installer="${PROJECT_DIR}/install.sh"

    assert_contains "Installer has set -euo pipefail"  "$installer" "set -euo pipefail"
    assert_contains "Installer handles --uninstall"    "$installer" "uninstall"
    assert_contains "Installer handles --non-interactive" "$installer" "non-interactive"
    assert_contains "Installer disables firewalld"     "$installer" "firewalld"
    assert_contains "Installer disables ufw"           "$installer" "ufw"
    assert_contains "Installer supports apt"           "$installer" "apt-get"
    assert_contains "Installer supports dnf"           "$installer" "dnf"
    assert_contains "Installer supports yum"           "$installer" "yum"
    assert_contains "Installer supports pacman"        "$installer" "pacman"
    assert_contains "Installer supports apk"           "$installer" "apk"
    assert_contains "Installer supports zypper"        "$installer" "zypper"
    assert_contains "Installer migrates old config"    "$installer" "migrate_old_config"

    # v2.1.0 new installer features
    assert_contains "Installer detects existing install" "$installer" "detect_existing_install"
    assert_contains "Installer supports OpenRC"          "$installer" "rc-service"
    assert_contains "Installer supports upgrade"         "$installer" "Upgrade"
}

# =============================================================================
# Test: Backend detection functions exist
# =============================================================================

test_backend_functions() {
    echo -e "\n${BOLD}Test: Backend Functions${NC}"

    # Test that functions are defined
    TESTS_RUN=$((TESTS_RUN + 1))
    if declare -f detect_backend &>/dev/null; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
        echo -e "  ${GREEN}✓${NC} detect_backend function exists"
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
        echo -e "  ${RED}✗${NC} detect_backend function not found"
    fi

    TESTS_RUN=$((TESTS_RUN + 1))
    if declare -f detect_distro &>/dev/null; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
        echo -e "  ${GREEN}✓${NC} detect_distro function exists"
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
        echo -e "  ${RED}✗${NC} detect_distro function not found"
    fi

    TESTS_RUN=$((TESTS_RUN + 1))
    if declare -f detect_distro_family &>/dev/null; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
        echo -e "  ${GREEN}✓${NC} detect_distro_family function exists"
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
        echo -e "  ${RED}✗${NC} detect_distro_family function not found"
    fi

    TESTS_RUN=$((TESTS_RUN + 1))
    if declare -f backup_rules &>/dev/null; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
        echo -e "  ${GREEN}✓${NC} backup_rules function exists"
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
        echo -e "  ${RED}✗${NC} backup_rules function not found"
    fi

    TESTS_RUN=$((TESTS_RUN + 1))
    if declare -f resolve_hostname &>/dev/null; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
        echo -e "  ${GREEN}✓${NC} resolve_hostname function exists"
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
        echo -e "  ${RED}✗${NC} resolve_hostname function not found"
    fi
}

# =============================================================================
# Test: UI functions (v2.1.0)
# =============================================================================

test_ui_functions() {
    echo -e "\n${BOLD}Test: UI Functions${NC}"

    TESTS_RUN=$((TESTS_RUN + 1))
    if declare -f show_banner &>/dev/null; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
        echo -e "  ${GREEN}✓${NC} show_banner function exists"
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
        echo -e "  ${RED}✗${NC} show_banner function not found"
    fi

    TESTS_RUN=$((TESTS_RUN + 1))
    if declare -f show_protected &>/dev/null; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
        echo -e "  ${GREEN}✓${NC} show_protected function exists"
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
        echo -e "  ${RED}✗${NC} show_protected function not found"
    fi

    TESTS_RUN=$((TESTS_RUN + 1))
    if declare -f show_unprotected &>/dev/null; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
        echo -e "  ${GREEN}✓${NC} show_unprotected function exists"
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
        echo -e "  ${RED}✗${NC} show_unprotected function not found"
    fi

    TESTS_RUN=$((TESTS_RUN + 1))
    if declare -f print_rule_summary &>/dev/null; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
        echo -e "  ${GREEN}✓${NC} print_rule_summary function exists"
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
        echo -e "  ${RED}✗${NC} print_rule_summary function not found"
    fi

    TESTS_RUN=$((TESTS_RUN + 1))
    if declare -f log_rule &>/dev/null; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
        echo -e "  ${GREEN}✓${NC} log_rule function exists"
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
        echo -e "  ${RED}✗${NC} log_rule function not found"
    fi

    # Test show_banner output contains expected text
    TESTS_RUN=$((TESTS_RUN + 1))
    local banner_output
    banner_output=$(show_banner 2>&1)
    if [[ "$banner_output" == *"Firewall Manager"* ]]; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
        echo -e "  ${GREEN}✓${NC} show_banner contains 'Firewall Manager'"
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
        echo -e "  ${RED}✗${NC} show_banner output missing 'Firewall Manager'"
    fi

    # Test show_protected output
    TESTS_RUN=$((TESTS_RUN + 1))
    local prot_output
    prot_output=$(show_protected 2>&1)
    if [[ "$prot_output" == *"PROTECTED"* ]]; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
        echo -e "  ${GREEN}✓${NC} show_protected contains 'PROTECTED'"
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
        echo -e "  ${RED}✗${NC} show_protected output missing 'PROTECTED'"
    fi

    # Test show_unprotected output
    TESTS_RUN=$((TESTS_RUN + 1))
    local unprot_output
    unprot_output=$(show_unprotected 2>&1)
    if [[ "$unprot_output" == *"DISABLED"* ]]; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
        echo -e "  ${GREEN}✓${NC} show_unprotected contains 'DISABLED'"
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
        echo -e "  ${RED}✗${NC} show_unprotected output missing 'DISABLED'"
    fi
}

# =============================================================================
# Test: New security features in backends (v2.1.0)
# =============================================================================

test_security_features() {
    echo -e "\n${BOLD}Test: Security Features (v2.1.0)${NC}"

    local nft_backend="${LIB_DIR}/backend_nftables.sh"
    local ipt_backend="${LIB_DIR}/backend_iptables.sh"

    assert_contains "nftables: SYN flood protection"      "$nft_backend" "SYN flood"
    assert_contains "nftables: connection limit"           "$nft_backend" "CONN_LIMIT"
    assert_contains "nftables: common attack ports"        "$nft_backend" "BLOCK_COMMON_ATTACKS"
    assert_contains "nftables: port forwarding"            "$nft_backend" "PORT_FORWARD_RULES"

    assert_contains "iptables: SYN flood protection"      "$ipt_backend" "SYN_FLOOD"
    assert_contains "iptables: connection limit"           "$ipt_backend" "CONN_LIMIT"
    assert_contains "iptables: connection rate limit"      "$ipt_backend" "CONN_RATE_PER_IP"
    assert_contains "iptables: common attack ports"        "$ipt_backend" "BLOCK_COMMON_ATTACKS"
    assert_contains "iptables: port forwarding"            "$ipt_backend" "PORT_FORWARD_RULES"
    assert_contains "iptables: custom rules"               "$ipt_backend" "CUSTOM_RULES_FILE"

    # Main script has upgrade command
    assert_contains "Main script: upgrade command"         "${SRC_DIR}/binadit-firewall.sh" "fw_upgrade"
    assert_contains "Main script: configtest command"      "${SRC_DIR}/binadit-firewall.sh" "fw_configtest"
    assert_contains "Main script: motd-on command"         "${SRC_DIR}/binadit-firewall.sh" "motd-on"
    assert_contains "Main script: motd-off command"        "${SRC_DIR}/binadit-firewall.sh" "motd-off"
}

# =============================================================================
# Test: configtest function
# =============================================================================

test_configtest() {
    echo -e "\n${BOLD}Test: Configuration Test (configtest)${NC}"

    # configtest function exists
    TESTS_RUN=$((TESTS_RUN + 1))
    if declare -f configtest &>/dev/null; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
        echo -e "  ${GREEN}✓${NC} configtest function exists"
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
        echo -e "  ${RED}✗${NC} configtest function not found"
    fi

    # Test with valid example config
    TESTS_RUN=$((TESTS_RUN + 1))
    local ct_tmpfile
    ct_tmpfile=$(mktemp)
    if configtest "${CONFIG_DIR}/firewall.conf.example" >"$ct_tmpfile" 2>&1; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
        echo -e "  ${GREEN}✓${NC} configtest passes on example config"
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
        echo -e "  ${RED}✗${NC} configtest failed on example config"
    fi

    # Test output contains 'Configuration Test'
    TESTS_RUN=$((TESTS_RUN + 1))
    if grep -q "Configuration Test" "$ct_tmpfile" 2>/dev/null; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
        echo -e "  ${GREEN}✓${NC} configtest output contains header"
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
        echo -e "  ${RED}✗${NC} configtest output missing header"
    fi
    rm -f "$ct_tmpfile"

    # Test with nonexistent file
    TESTS_RUN=$((TESTS_RUN + 1))
    if configtest "/tmp/nonexistent_binadit_config_$$" >/dev/null 2>&1; then
        TESTS_FAILED=$((TESTS_FAILED + 1))
        echo -e "  ${RED}✗${NC} configtest should fail on missing config"
    else
        TESTS_PASSED=$((TESTS_PASSED + 1))
        echo -e "  ${GREEN}✓${NC} configtest fails on missing config"
    fi

    # Test with bad syntax config
    TESTS_RUN=$((TESTS_RUN + 1))
    local bad_config
    bad_config=$(mktemp)
    echo 'TCP_PORTS="80 443' > "$bad_config"  # Missing closing quote
    if configtest "$bad_config" >/dev/null 2>&1; then
        TESTS_FAILED=$((TESTS_FAILED + 1))
        echo -e "  ${RED}✗${NC} configtest should fail on syntax error"
    else
        TESTS_PASSED=$((TESTS_PASSED + 1))
        echo -e "  ${GREEN}✓${NC} configtest fails on syntax error"
    fi
    rm -f "$bad_config"

    # Test with invalid port
    TESTS_RUN=$((TESTS_RUN + 1))
    local bad_port_config
    bad_port_config=$(mktemp)
    echo 'TCP_PORTS="80 99999"' > "$bad_port_config"
    if configtest "$bad_port_config" >/dev/null 2>&1; then
        TESTS_FAILED=$((TESTS_FAILED + 1))
        echo -e "  ${RED}✗${NC} configtest should fail on invalid port"
    else
        TESTS_PASSED=$((TESTS_PASSED + 1))
        echo -e "  ${GREEN}✓${NC} configtest fails on invalid port (99999)"
    fi
    rm -f "$bad_port_config"

    # Test with invalid boolean
    TESTS_RUN=$((TESTS_RUN + 1))
    local bad_bool_config
    bad_bool_config=$(mktemp)
    echo 'ICMP_ENABLE="yes"' > "$bad_bool_config"
    if configtest "$bad_bool_config" >/dev/null 2>&1; then
        TESTS_FAILED=$((TESTS_FAILED + 1))
        echo -e "  ${RED}✗${NC} configtest should fail on invalid boolean"
    else
        TESTS_PASSED=$((TESTS_PASSED + 1))
        echo -e "  ${GREEN}✓${NC} configtest fails on invalid boolean ('yes')"
    fi
    rm -f "$bad_bool_config"
}

# =============================================================================
# Test: Version consistency
# =============================================================================

test_version_consistency() {
    echo -e "\n${BOLD}Test: Version Consistency${NC}"

    local version_common version_main version_changelog version_readme

    version_common=$(grep "BINADIT_VERSION=" "${LIB_DIR}/common.sh" | head -1 | sed 's/.*"\([0-9.]*\)".*/\1/')
    version_main=$(grep "binadit-firewall v" "${SRC_DIR}/binadit-firewall.sh" | head -1 | sed 's/.*v\([0-9.]*\).*/\1/' || echo "")

    assert_equals "Version in common.sh" "2.1.1" "$version_common"

    # Check CHANGELOG has the version
    if [[ -f "${PROJECT_DIR}/CHANGELOG.md" ]]; then
        TESTS_RUN=$((TESTS_RUN + 1))
        if grep -q "${version_common}" "${PROJECT_DIR}/CHANGELOG.md"; then
            TESTS_PASSED=$((TESTS_PASSED + 1))
            echo -e "  ${GREEN}✓${NC} CHANGELOG contains version ${version_common}"
        else
            TESTS_FAILED=$((TESTS_FAILED + 1))
            echo -e "  ${RED}✗${NC} CHANGELOG missing version ${version_common}"
        fi
    fi
}

# =============================================================================
# Test: Logging functions
# =============================================================================

test_logging_functions() {
    echo -e "\n${BOLD}Test: Logging Functions${NC}"

    TESTS_RUN=$((TESTS_RUN + 1))
    local output
    output=$(log_info "test message" 2>&1)
    if [[ "$output" == *"test message"* ]]; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
        echo -e "  ${GREEN}✓${NC} log_info outputs message"
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
        echo -e "  ${RED}✗${NC} log_info failed"
    fi

    TESTS_RUN=$((TESTS_RUN + 1))
    output=$(log_error "error test" 2>&1)
    if [[ "$output" == *"error test"* ]]; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
        echo -e "  ${GREEN}✓${NC} log_error outputs message"
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
        echo -e "  ${RED}✗${NC} log_error failed"
    fi

    TESTS_RUN=$((TESTS_RUN + 1))
    output=$(log_warn "warn test" 2>&1)
    if [[ "$output" == *"warn test"* ]]; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
        echo -e "  ${GREEN}✓${NC} log_warn outputs message"
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
        echo -e "  ${RED}✗${NC} log_warn failed"
    fi

    TESTS_RUN=$((TESTS_RUN + 1))
    local tmpfile
    tmpfile=$(mktemp)
    local old_debug="${BINADIT_DEBUG:-false}"
    BINADIT_DEBUG=true
    log_debug "debug test" 2>"$tmpfile" || true
    if grep -q "debug test" "$tmpfile" 2>/dev/null; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
        echo -e "  ${GREEN}✓${NC} log_debug outputs message when BINADIT_DEBUG=true"
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
        echo -e "  ${RED}✗${NC} log_debug failed"
    fi
    rm -f "$tmpfile"

    TESTS_RUN=$((TESTS_RUN + 1))
    tmpfile=$(mktemp)
    BINADIT_DEBUG=false
    log_debug "hidden" 2>"$tmpfile" || true
    if ! grep -q "hidden" "$tmpfile" 2>/dev/null; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
        echo -e "  ${GREEN}✓${NC} log_debug silent when BINADIT_DEBUG=false"
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
        echo -e "  ${RED}✗${NC} log_debug should be silent when debug is off"
    fi
    BINADIT_DEBUG="$old_debug"
    rm -f "$tmpfile"
}

# =============================================================================
# Test: Resolve hostname (IP passthrough)
# =============================================================================

test_resolve_passthrough() {
    echo -e "\n${BOLD}Test: Hostname Resolution (Passthrough)${NC}"

    local result

    TESTS_RUN=$((TESTS_RUN + 1))
    result=$(resolve_hostname "192.168.1.1")
    if [[ "$result" == "192.168.1.1" ]]; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
        echo -e "  ${GREEN}✓${NC} IPv4 address passes through unchanged"
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
        echo -e "  ${RED}✗${NC} IPv4 passthrough failed: got '$result'"
    fi

    TESTS_RUN=$((TESTS_RUN + 1))
    result=$(resolve_hostname "2001:db8::1")
    if [[ "$result" == "2001:db8::1" ]]; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
        echo -e "  ${GREEN}✓${NC} IPv6 address passes through unchanged"
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
        echo -e "  ${RED}✗${NC} IPv6 passthrough failed: got '$result'"
    fi

    TESTS_RUN=$((TESTS_RUN + 1))
    result=$(resolve_hostname "10.0.0.0/24")
    if [[ "$result" == "10.0.0.0/24" ]]; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
        echo -e "  ${GREEN}✓${NC} CIDR notation passes through unchanged"
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
        echo -e "  ${RED}✗${NC} CIDR passthrough failed: got '$result'"
    fi
}

# =============================================================================
# Run all tests
# =============================================================================

main() {
    echo ""
    echo -e "${BOLD}╔══════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}║     binadit-firewall Test Suite v2.0.0       ║${NC}"
    echo -e "${BOLD}╚══════════════════════════════════════════════╝${NC}"

    test_ipv4_validation
    test_ipv6_validation
    test_cidr_validation
    test_port_validation
    test_host_validation
    test_project_structure
    test_config_file
    test_systemd_service
    test_install_script
    test_backend_functions
    test_ui_functions
    test_security_features
    test_configtest
    test_version_consistency
    test_logging_functions
    test_resolve_passthrough

    # Summary
    echo ""
    echo -e "${BOLD}═══════════════════════════════════════════════${NC}"
    echo -e "  Tests run:    ${BOLD}${TESTS_RUN}${NC}"
    echo -e "  Passed:       ${GREEN}${TESTS_PASSED}${NC}"
    echo -e "  Failed:       ${RED}${TESTS_FAILED}${NC}"
    echo -e "${BOLD}═══════════════════════════════════════════════${NC}"
    echo ""

    if [[ $TESTS_FAILED -gt 0 ]]; then
        echo -e "${RED}${BOLD}TESTS FAILED${NC}"
        exit 1
    else
        echo -e "${GREEN}${BOLD}ALL TESTS PASSED${NC}"
        exit 0
    fi
}

main
