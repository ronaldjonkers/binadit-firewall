# Changelog

All notable changes to binadit-firewall will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-02-06

### Added
- **nftables support**: Native nftables backend for modern Linux distributions
- **Dual backend**: Automatic detection and use of nftables or iptables (legacy/nft)
- **Port blocking**: `BLOCKED_TCP_PORTS` and `BLOCKED_UDP_PORTS` configuration
- **Port-specific IP rules**: Allow specific IPs for specific ports via `PORT_IP_RULES`
- **IP range support**: CIDR notation and dash-range support for trusted/blocked ranges
- **Rate limiting**: Built-in DDoS protection with configurable rate limits
- **Connection tracking**: Modern `conntrack` module usage instead of deprecated `state`
- **Interactive setup wizard**: `binadit-firewall setup` for easy initial configuration
- **Systemd service**: Native systemd integration with `binadit-firewall.service`
- **Init.d fallback**: Automatic fallback for systems without systemd
- **Automatic backup**: Rules backed up before every change (last 30 kept)
- **Competing firewall detection**: Installer detects and disables firewalld, ufw, iptables-services
- **Migration support**: Automatic migration from v1.x configuration format
- **Multi-distro support**: Debian, Ubuntu, CentOS, RHEL, Rocky, Alma, Fedora, Arch, Alpine, SUSE
- **SMTP control**: Configurable outgoing SMTP (ports 25, 587)
- **Drop logging**: Configurable logging of dropped packets to syslog
- **Debug mode**: `BINADIT_DEBUG=true` for troubleshooting
- **Comprehensive test suite**: 70+ tests for validation, structure, and configuration
- **Hostname resolution**: Automatic DNS resolution for hostnames in config
- **Uninstall support**: `install.sh --uninstall` for clean removal
- **Non-interactive mode**: `install.sh --non-interactive` for automation

### Changed
- **Complete rewrite** of the firewall script for modern Linux (2026+)
- Renamed config variables for clarity (e.g., `DMZS` → `TRUSTED_IPS`)
- Moved from `/etc/init.d/firewall` to `/usr/local/sbin/binadit-firewall`
- Config moved from `/etc/firewall.d/host.conf` to `/etc/binadit-firewall/firewall.conf`
- Uses `conntrack` module instead of deprecated `state` module
- Modular architecture: separate library files for each backend
- Improved IPv6 support with proper ICMPv6 handling

### Removed
- Legacy init.d-only support (replaced by systemd with init.d fallback)
- Hardcoded `aptitude` dependency
- Duplicate `setup()` function definitions

## [1.0.0] - 2015-01-20

### Added
- Initial release with iptables support
- IPv4 and IPv6 firewall rules
- TCP/UDP port management
- DMZ (trusted IP) support
- SSH access restrictions
- IP blacklisting
- IP range support
- Multicast option
- NAT routing
- CentOS, Debian, and Ubuntu support
- Configuration via `/etc/firewall.d/host.conf`
