# binadit-firewall

**Simple, powerful Linux firewall manager** with support for both **nftables** and **iptables**.

Manage your server's firewall through a single, clean configuration file. No complex syntax, no GUI needed — just edit, apply, done.

[![License: GPL v2](https://img.shields.io/badge/License-GPL_v2-blue.svg)](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html)
[![Version](https://img.shields.io/badge/version-2.0.0-green.svg)]()

## Features

- **Dual backend** — Automatically uses nftables or iptables (whatever is available)
- **One config file** — All rules in `/etc/binadit-firewall/firewall.conf`
- **IPv4 + IPv6** — Full dual-stack support
- **Port blocking** — Block specific ports explicitly
- **IP-per-port rules** — Allow specific IPs for specific ports (e.g., MySQL only from `10.0.0.5`)
- **IP ranges** — CIDR and dash-notation support for trusted/blocked ranges
- **SSH protection** — Restrict SSH to specific IPs
- **Rate limiting** — Built-in DDoS protection
- **Auto-backup** — Rules backed up before every change
- **Setup wizard** — Interactive setup for common configurations
- **Boot persistence** — Systemd service (with init.d fallback)
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

### Install

```bash
git clone https://github.com/ronaldjonkers/binadit-firewall.git
cd binadit-firewall
sudo bash install.sh
```

The installer will:
1. Detect your Linux distribution
2. Disable competing firewalls (firewalld, ufw, etc.)
3. Install required dependencies
4. Run the interactive setup wizard
5. Start the firewall

### Non-interactive Install

```bash
sudo bash install.sh --non-interactive
```

### Uninstall

```bash
sudo bash install.sh --uninstall
```

## Usage

```bash
binadit-firewall start       # Apply firewall rules
binadit-firewall stop        # Remove all rules (allow all traffic)
binadit-firewall restart     # Stop and start
binadit-firewall reload      # Reload configuration
binadit-firewall status      # Show current rules
binadit-firewall setup       # Interactive setup wizard
binadit-firewall backup      # Create manual backup
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

# NAT routing
NAT_ENABLE="false"
NAT_EXTERNAL_IFACE="eth0"
NAT_INTERNAL_IFACE="eth1"
```

See `config/firewall.conf.example` for the full configuration reference with all options documented.

## Migrating from v1.x

The installer automatically detects and migrates old configurations from `/etc/firewall.d/host.conf`. Variable mappings:

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
│   └── test_firewall.sh               # Test suite (70+ tests)
├── etc/                                # Legacy v1.x files (preserved for reference)
│   ├── init.d/firewall
│   └── firewall.d/host.conf
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
- Configuration file completeness
- Project structure integrity
- Systemd service correctness
- Install script coverage
- Backend function availability
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