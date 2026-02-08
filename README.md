# binadit-firewall

**Simple, powerful Linux firewall manager** with support for both **nftables** and **iptables**.

Manage your server's firewall through a single, clean configuration file. No complex syntax, no GUI needed — just edit, apply, done.

[![License: GPL v2](https://img.shields.io/badge/License-GPL_v2-blue.svg)](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html)
[![Version](https://img.shields.io/badge/version-2.1.2-green.svg)]()

## One-Line Install

```bash
curl -sL https://raw.githubusercontent.com/ronaldjonkers/binadit-firewall/master/get.sh | sudo bash
```

Or with `wget`:

```bash
wget -qO- https://raw.githubusercontent.com/ronaldjonkers/binadit-firewall/master/get.sh | sudo bash
```

For automated/unattended installs:

```bash
curl -sL https://raw.githubusercontent.com/ronaldjonkers/binadit-firewall/master/get.sh | sudo bash -s -- --non-interactive
```

That's it. The installer will detect your distro, install dependencies, disable competing firewalls, run the setup wizard, and start the firewall.

## Features

- **Dual backend** — Automatically uses nftables or iptables (whatever is available)
- **One config file** — All rules in `/etc/binadit-firewall/firewall.conf`
- **Beautiful output** — ASCII art banners, colored rule summaries, clear status indicators
- **IPv4 + IPv6** — Full dual-stack support
- **Port blocking** — Block specific ports explicitly
- **IP-per-port rules** — Allow specific IPs for specific ports (e.g., MySQL only from `10.0.0.5`)
- **Port forwarding** — DNAT rules for forwarding external ports to internal IPs
- **IP ranges** — CIDR and dash-notation support for trusted/blocked ranges
- **SSH protection** — Restrict SSH to specific IPs
- **SYN flood protection** — Built-in SYN flood mitigation
- **Rate limiting** — DDoS protection with configurable rate/burst
- **Connection limits** — Per-IP connection limits and rate limiting
- **Common attack blocking** — Auto-block telnet, netbios, and other attack vectors
- **Custom rules** — Load additional raw rules from a file
- **Config validation** — `configtest` validates every setting before applying (prevents lockout)
- **Login status** — Optional one-line firewall status on every SSH login
- **Auto-backup** — Rules backed up before every change
- **Setup wizard** — Interactive setup for common configurations
- **Seamless upgrade** — Upgrade from v1.x or older v2.x without config loss
- **Boot persistence** — Systemd, OpenRC (Alpine/Gentoo), and SysVinit support
- **Migration** — Automatic migration from v1.x configs
- **Multi-distro** — Debian, Ubuntu, CentOS, RHEL, Rocky, Alma, Fedora, Arch, Alpine, SUSE

## Supported Distributions

| Distribution | Version | Backend |
|---|---|---|
| Ubuntu | 20.04+ | nftables |
| Debian | 10+ | nftables |
| CentOS / RHEL | 8+ | nftables |
| Rocky / AlmaLinux | 8+ | nftables |
| Fedora | 32+ | nftables |
| Arch Linux | Rolling | nftables |
| Alpine Linux | 3.14+ | iptables/nftables |
| openSUSE | 15+ | nftables |
| CentOS 7 | 7.x | iptables-legacy |
| Debian 9 | 9.x | iptables-legacy |

## Quick Start

The fastest way is the **one-line installer** at the top of this page. Alternatively, clone and install manually:

```bash
git clone https://github.com/ronaldjonkers/binadit-firewall.git
cd binadit-firewall
sudo bash install.sh
```

### Uninstall

**One-line remote uninstall** (no local files needed):

```bash
curl -sL https://raw.githubusercontent.com/ronaldjonkers/binadit-firewall/master/get.sh | sudo bash -s -- --uninstall
```

Or with `wget`:

```bash
wget -qO- https://raw.githubusercontent.com/ronaldjonkers/binadit-firewall/master/get.sh | sudo bash -s -- --uninstall
```

Or locally if the repo is cloned:

```bash
sudo bash install.sh --uninstall
```

> **Note:** Uninstall removes the firewall binary, systemd service, and flushes all rules.
> Your configuration in `/etc/binadit-firewall/` is **preserved**. To fully remove it: `sudo rm -rf /etc/binadit-firewall`

## Usage

```bash
binadit-firewall start       # Apply firewall rules (shows protection banner)
binadit-firewall stop        # Remove all rules (shows warning banner)
binadit-firewall restart     # Stop and start
binadit-firewall reload      # Reload configuration
binadit-firewall status      # Show rule summary + active rules
binadit-firewall configtest  # Validate config without applying
binadit-firewall setup       # Interactive setup wizard
binadit-firewall upgrade     # Upgrade from v1.x or update v2.x in-place
binadit-firewall backup      # Create manual backup
binadit-firewall motd-on     # Show firewall status on every login
binadit-firewall motd-off    # Remove login status indicator
binadit-firewall version     # Show version and system info
```

## Configuration

Edit `/etc/binadit-firewall/firewall.conf`:

```bash
# Open TCP ports (space-separated, ranges with colon)
TCP_PORTS="80 443 8080"

# Open UDP ports
UDP_PORTS="51820"

# Block specific ports
BLOCKED_TCP_PORTS="23 135 139 445"

# Restrict SSH to specific IPs
SSH_ALLOWED_IPS="1.2.3.4 office.example.com 10.0.0.0/24"

# Trusted IPs (full access)
TRUSTED_IPS="10.0.0.1 management.example.com"

# Blacklisted IPs
BLACKLIST="5.6.7.8 bad-actor.example.com"

# Allow specific IPs for specific ports
# Format: protocol|port|ip
PORT_IP_RULES="tcp|3306|10.0.0.5
tcp|5432|10.0.0.6
tcp|6379|192.168.1.0/24"

# IP ranges (CIDR or dash notation)
TRUSTED_RANGES="192.168.1.0/24"
BLOCKED_RANGES="65.208.151.1-65.208.151.254"

# Features
ICMP_ENABLE="true"           # Allow ping
MULTICAST_ENABLE="false"     # For clusters/load balancers
SMTP_ENABLE="true"           # Outgoing mail
RATE_LIMIT_ENABLE="true"     # DDoS protection
LOG_DROPPED="true"           # Log dropped packets

# Security hardening
SYN_FLOOD_PROTECT="true"     # SYN flood protection
CONN_LIMIT_ENABLE="false"    # Per-IP connection limit
CONN_LIMIT_PER_IP="50"       # Max connections per IP
BLOCK_COMMON_ATTACKS="true"  # Block telnet, netbios, etc.

# Port forwarding (requires NAT_ENABLE)
PORT_FORWARD_RULES="tcp|8080|192.168.1.100:80
tcp|2222|192.168.1.100:22"

# NAT routing
NAT_ENABLE="false"
NAT_EXTERNAL_IFACE="eth0"
NAT_INTERNAL_IFACE="eth1"

# Custom rules (for advanced users)
CUSTOM_RULES_FILE="/etc/binadit-firewall/custom.rules"
```

See `config/firewall.conf.example` for the full configuration reference with all options documented.

## Upgrading

### From v1.x

The easiest way to upgrade:

```bash
binadit-firewall upgrade
```

Or run the installer — it automatically detects and migrates old configurations from `/etc/firewall.d/host.conf`.

### From v2.0.x to v2.1.x

Re-run the installer or use the upgrade command. Your configuration is preserved:

```bash
sudo bash install.sh          # detects existing install, preserves config
# or
binadit-firewall upgrade      # in-place upgrade
```

### Variable mappings (v1.x → v2.x)

| Old (v1.x) | New (v2.0) |
|---|---|
| `TCPPORTS` | `TCP_PORTS` |
| `TCPPORTS_INPUT` | `TCP_PORTS_INPUT` |
| `TCPPORTS_OUTPUT` | `TCP_PORTS_OUTPUT` |
| `UDPPORTS` | `UDP_PORTS` |
| `DMZS` | `TRUSTED_IPS` |
| `SSHACCESS` | `SSH_ALLOWED_IPS` |
| `DMZRANGE` | `TRUSTED_RANGES` |
| `BLACKLIST` | `BLACKLIST` |
| `BLOCKRANGE` | `BLOCKED_RANGES` |
| `MULTICAST_ENABLE` | `MULTICAST_ENABLE` (now `true`/`false` instead of `TRUE`/`FALSE`) |
| `NATROUTER_ENABLE` | `NAT_ENABLE` |

## Architecture

```
binadit-firewall/
├── get.sh                              # One-line installer bootstrap
├── install.sh                          # Universal installer
├── config/
│   ├── firewall.conf.example           # Configuration template
│   └── binadit-firewall.service        # Systemd service file
├── src/
│   ├── binadit-firewall.sh             # Main entry point
│   └── lib/
│       ├── common.sh                   # Shared utilities, validation, logging
│       ├── backend.sh                  # Backend detection (nftables vs iptables)
│       ├── backend_nftables.sh         # nftables implementation
│       └── backend_iptables.sh         # iptables implementation
├── tests/
│   └── test_firewall.sh               # Test suite (148+ tests)
├── CHANGELOG.md
├── LICENSE                             # GPL-2.0
└── README.md
```

## Running Tests

```bash
bash tests/test_firewall.sh
```

Tests cover:
- IPv4/IPv6/CIDR/port validation
- Configuration file completeness (including v2.1.0 features)
- Project structure integrity
- Systemd service correctness
- Install script coverage (including OpenRC, upgrade detection)
- Backend function availability
- UI functions (banners, rule summary)
- configtest validation (valid config, bad syntax, invalid ports, invalid booleans)
- Security features (SYN flood, conn limits, port forwarding)
- Version consistency
- Logging functions

## How It Works

1. **Backend detection** — On start, binadit-firewall checks for `nft` (nftables) first, then falls back to `iptables`
2. **Config parsing** — The configuration file is sourced as bash, making it simple and familiar
3. **Rule generation** — Rules are generated based on the detected backend:
   - **nftables**: Generates a complete ruleset file and applies it atomically
   - **iptables**: Applies rules sequentially via iptables/ip6tables commands
4. **Persistence** — Systemd service ensures rules are applied on boot
5. **Backup** — Before any change, current rules are backed up to `/etc/binadit-firewall/backups/`

## Troubleshooting

```bash
# Enable debug mode
BINADIT_DEBUG=true binadit-firewall start

# Check which backend is used
binadit-firewall version

# View current rules
binadit-firewall status

# Check systemd service
systemctl status binadit-firewall

# View drop logs
journalctl -k | grep binadit-drop

# Emergency: disable firewall
binadit-firewall stop
```

## License

GPL-2.0 — See [LICENSE](LICENSE) for details.

## Author

Ronald Jonkers — [binadit](https://binadit.com)

Originally created in 2013, completely rewritten in 2026 for modern Linux.

---

*binadit-firewall — making firewall management easy since 2013* 🛡️