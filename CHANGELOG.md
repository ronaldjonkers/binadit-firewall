# Changelog

All notable changes to binadit-firewall will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.2] - 2026-02-06

### Added
- **Single-line installer**: `curl -sL .../get.sh | sudo bash` for instant installation
- **Bootstrap script** (`get.sh`): Downloads and runs the installer, cleans up after itself, supports `--non-interactive` flag
- Works with both `curl` and `wget`, downloads via `git clone` or tarball fallback

## [2.1.1] - 2026-02-06

### Added
- **configtest command**: `binadit-firewall configtest` validates every config variable with clear, actionable feedback — checks ports, IPs, booleans, numeric values, PORT_IP_RULES, PORT_FORWARD_RULES, NAT dependencies, and SSH access safety
- **Config validation on start/reload**: configtest runs automatically before applying rules — if config has errors, firewall stays unchanged (prevents accidental lockout)
- **Login status indicator**: `binadit-firewall motd-on` installs a subtle one-line status in `/etc/profile.d/` so admins see firewall status on every SSH login; `motd-off` removes it
- **Installer MOTD offer**: installer now offers to enable the login status indicator during setup

### Changed
- `validate_config` now runs full configtest instead of basic syntax check
- Installer completion screen shows `configtest` and `motd-on` commands
- Test suite expanded to 148 tests (added configtest validation tests)

## [2.1.0] - 2026-02-06

### Added
- **ASCII art banners**: Beautiful colored output for start, stop, and status commands
- **Rule summary**: Clear overview of active rules displayed on start and status
- **Protection banner**: "YOUR SERVER IS NOW PROTECTED" ASCII art on firewall start
- **Warning banner**: "FIREWALL DISABLED - SERVER EXPOSED" on firewall stop
- **SYN flood protection**: `SYN_FLOOD_PROTECT` option (enabled by default)
- **Connection limit per IP**: `CONN_LIMIT_ENABLE` / `CONN_LIMIT_PER_IP` to prevent resource hogging
- **Connection rate limiting per IP**: `CONN_RATE_PER_IP` for per-source rate control
- **Common attack port blocking**: `BLOCK_COMMON_ATTACKS` blocks telnet, netbios, etc.
- **Port forwarding (DNAT)**: `PORT_FORWARD_RULES` for NAT port forwarding
- **Custom rules file**: `CUSTOM_RULES_FILE` for advanced users to add raw rules
- **Drop invalid packets**: `DROP_INVALID` option (enabled by default)
- **Upgrade command**: `binadit-firewall upgrade` for seamless v1.x → v2.x migration
- **In-place upgrade**: Installer detects existing v2.x and upgrades without config loss
- **OpenRC support**: Native OpenRC service for Alpine Linux and Gentoo
- **SysVinit support**: Improved init.d script for legacy systems

### Changed
- Beautified all terminal output with Unicode box-drawing characters and color coding
- Logging functions use Unicode symbols (▸, ✓, ✗, ⚠) for better readability
- Status command now shows rule summary alongside raw rules
- Version command shows configuration status
- Help command displays ASCII art banner
- Installer shows completion banner with service management commands
- Test suite expanded from 108 to 138+ tests

### Removed
- Legacy `etc/` folder with old v1.x scripts (no longer needed in repository)

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
