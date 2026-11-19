# binadit-firewall

**Simple, powerful Linux firewall manager** with support for both **nftables** and **iptables**.

Manage your server's firewall through a single, clean configuration file. No complex syntax, no GUI needed — just edit, apply, done.

[![License: GPL v2](https://img.shields.io/badge/License-GPL_v2-blue.svg)](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html)
[![Version](https://img.shields.io/badge/version-3.1.1-green.svg)]()

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

That's it. The installer detects your distro, installs a firewall backend if needed, asks which services should be reachable, validates the configuration and only then switches over: other firewalls (firewalld, ufw, ...) are disabled at the last moment, right before binadit-firewall starts. If anything fails before that point, nothing on your server has changed.

Without a terminal (CI, Ansible, cloud-init) the installer never asks questions: it opens HTTP, HTTPS and SSH and keeps an existing configuration untouched.

Requires `bash` 4+ and `curl` or `wget`.

## Features

- **Dual backend** — Automatically uses nftables or iptables (whatever is available)
- **One config file** — All rules in `/etc/binadit-firewall/firewall.conf`
- **Default deny** — Incoming traffic is dropped unless you allow it; outgoing traffic is allowed unless you block it
- **Atomic reloads** — The complete ruleset is verified and then swapped in one transaction. A mistake never leaves you with a half-loaded or missing firewall, and open connections survive a reload
- **IPv4 + IPv6** — Every rule applies to both; every address setting accepts IPv4, IPv6, CIDR, ranges and hostnames
- **Hostnames that stay correct** — Hostnames are re-checked every 5 minutes; when the IP behind one changes, the rules are reloaded automatically. Resolved addresses are cached, so a DNS outage (or an early boot without DNS) never locks you out
- **SSH protection** — Restrict SSH to specific IPs/hostnames; without a restriction SSH is always kept reachable
- **Port blocking** — Block specific ports inbound + outbound, or outbound only
- **IP-per-port rules** — Allow specific IPs for specific ports (e.g., MySQL only from `10.0.0.5`)
- **Rate limiting** — Per source IP limit on new TCP connections, with configurable rate/burst
- **Connection limits** — Per-IP limit on concurrent connections
- **SYN flood protection** — Kernel SYN cookies + dropping of TCP packets with impossible flags
- **Port forwarding / NAT** — Use the server as NAT router with DNAT port forwards
- **Custom rules** — Load additional raw rules from a file
- **Config validation** — `configtest` validates every setting and lets the kernel verify the generated ruleset, without applying it
- **Login status** — Optional one-line firewall status on every SSH login, and 🟢/🔴 in your prompt
- **Auto-backup** — Loaded rules are saved before every start/stop
- **Setup wizard** — Interactive setup for common configurations
- **Seamless upgrade** — Upgrade from any older version without config loss
- **Boot persistence** — Systemd, OpenRC (Alpine/Gentoo), and SysVinit support; rules load before the network comes up
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

> **Note:** Uninstall removes the program, the boot service, scheduled jobs and all firewall rules — the server has **no firewall** afterwards.
> Firewalls that the installer disabled (firewalld, ufw, ...) are unmasked again so you can re-enable them.
> Your configuration in `/etc/binadit-firewall/` is preserved unless you answer yes to removing it.

## Usage

```bash
# Firewall control
binadit-firewall start                      # Validate config and apply rules
binadit-firewall stop                       # Remove all rules (allow all)
binadit-firewall reload                     # Re-read config, replace rules atomically
binadit-firewall restart                    # Same as reload (never an unprotected moment)
binadit-firewall status                     # Active or not + rules (exit 0 = active, 3 = not)

# Configuration via CLI (no need to edit files)
binadit-firewall config show                # View all current settings
binadit-firewall config get TCP_PORTS       # Get a specific setting
binadit-firewall config set TCP_PORTS "80 443 8080"  # Set a value
binadit-firewall config add TCP_PORTS 8080  # Add to a list setting
binadit-firewall config remove TCP_PORTS 8080  # Remove from a list
binadit-firewall configtest                 # Validate config before applying
binadit-firewall dns-refresh                # Re-check hostnames now, reload if an IP changed

# Setup & documentation
binadit-firewall setup                      # Interactive setup wizard
binadit-firewall features                   # Full feature overview + docs

# Updates
binadit-firewall update                     # Download & install latest version
binadit-firewall auto-update on             # Enable weekly auto-updates
binadit-firewall auto-update off            # Disable auto-updates
binadit-firewall auto-update status         # Show auto-update status & log
binadit-firewall upgrade                    # Migrate a v1.x (2013) config, then update

# System
binadit-firewall backup                     # Create manual backup
binadit-firewall motd-on                    # Show firewall status on login
binadit-firewall motd-off                   # Remove login status indicator
binadit-firewall prompt-on                  # Show 🟢/🔴 emoji in shell prompt
binadit-firewall prompt-off                 # Remove prompt indicator
binadit-firewall version                    # Show version and system info
binadit-firewall help                       # Show all commands
```

Configuration changes take effect when you run `binadit-firewall reload`. Until then `binadit-firewall status` tells you that the config differs from what is loaded.

### CLI Configuration Management

You can manage **all** firewall settings directly from the command line — no need to edit files manually. Every change is validated; a value that would make the configuration invalid is refused and the file is left untouched.

```bash
# View all current settings
binadit-firewall config show

# Open port 8080
binadit-firewall config add TCP_PORTS 8080
binadit-firewall reload        # Apply

# Block an IP
binadit-firewall config add BLACKLIST 1.2.3.4
binadit-firewall reload

# Restrict SSH to specific IPs
binadit-firewall config set SSH_ALLOWED_IPS "10.0.0.1 office.example.com"
binadit-firewall reload

# Remove a port
binadit-firewall config remove TCP_PORTS 8080
binadit-firewall reload

# Get a single value (scriptable)
binadit-firewall config get TCP_PORTS
```

**List-type settings** (support `add`/`remove`): `TCP_PORTS`, `TCP_PORTS_INPUT`, `UDP_PORTS`, `BLOCKED_TCP_PORTS`, `BLOCKED_UDP_PORTS`, `BLOCKED_TCP_PORTS_OUTPUT`, `BLOCKED_UDP_PORTS_OUTPUT`, `SSH_PORT`, `SSH_ALLOWED_IPS`, `TRUSTED_IPS`, `TRUSTED_RANGES`, `BLACKLIST`, `BLOCKED_RANGES` (and their `_IPV6` variants).

**All other settings** use `config set` (e.g., booleans, numbers, interfaces).

Run `binadit-firewall features` for a complete reference of every setting with descriptions and defaults.

### Hostnames

Every address setting accepts hostnames (`office.example.com`). They are resolved to **all** their A and AAAA records when the rules are loaded.

- **Automatic re-check** — every `DNS_REFRESH_INTERVAL` minutes (default `5`) all hostnames are resolved again. If an address changed, the rules are reloaded atomically and the change is written to syslog (`journalctl -t binadit-firewall`). Nothing happens when nothing changed. Set `DNS_REFRESH_INTERVAL="0"` to turn it off.
- **Cache** — the last known addresses are stored in `/etc/binadit-firewall/state/dns-cache`. If DNS is unavailable (also: at boot, before the network is up) the cached addresses are used, so you are never locked out by a DNS problem.
- **Safe** — the automatic reload uses the configuration that is currently loaded. A half-finished edit of `firewall.conf` is never applied behind your back.
- **Run it now** — `binadit-firewall dns-refresh`

The schedule is a systemd timer (`binadit-firewall-dns.timer`), or a cron job on systems without systemd (`/etc/cron.d/binadit-firewall-dns`; on Alpine `/etc/periodic/15min/`, which runs every 15 minutes regardless of the configured interval). It is created automatically when your configuration contains hostnames and removed when it does not.

### Self-Update

```bash
# Check for updates and install
binadit-firewall update

# Enable weekly automatic updates
binadit-firewall auto-update on

# Check auto-update status
binadit-firewall auto-update status

# Disable auto-updates
binadit-firewall auto-update off
```

An update replaces the program files only — your configuration is **always preserved**. The download is verified before anything is installed. If the firewall is active, the rules are then reloaded with the new version (atomically, using the configuration that is currently loaded); if that reload fails, the old rules simply stay active.

Auto-update uses `/etc/cron.weekly/` when it exists and a systemd timer (`binadit-firewall-update.timer`) otherwise, and logs to `/var/log/binadit-firewall-update.log`.

During installation, you are offered the option to enable weekly auto-updates automatically.

### Prompt Indicator

Show a live firewall status emoji before your shell prompt:

```bash
# Enable — shows 🟢 (active) or 🔴 (inactive) before every prompt
binadit-firewall prompt-on

# Disable
binadit-firewall prompt-off
```

Example with firewall active:
```
🟢 [root@server ~]#
```

Example with firewall stopped:
```
🔴 [root@server ~]#
```

The indicator is re-checked on every prompt, so you'll immediately see if the firewall goes down. Works in bash, for root and members of the `sudo`/`wheel` group. Takes effect on next login.

## Configuration

Edit `/etc/binadit-firewall/firewall.conf` or use `binadit-firewall config` commands, then run `binadit-firewall reload`.

```bash
# Incoming TCP/UDP ports open to everyone (ranges with a colon)
TCP_PORTS="80 443 8000:9000"
TCP_PORTS_INPUT=""               # same as TCP_PORTS (compatibility)
UDP_PORTS="51820"

# Block ports in both directions (wins over every allow rule)
BLOCKED_TCP_PORTS="23 135 139 445"
BLOCKED_UDP_PORTS=""

# Block outgoing ports only (e.g. prevent the server from sending mail)
BLOCKED_TCP_PORTS_OUTPUT="25 465 587"
BLOCKED_UDP_PORTS_OUTPUT=""

# SSH: empty SSH_PORT = detected from sshd. Empty allow-list = open to all.
# With an allow-list SSH is closed for everyone else.
SSH_PORT=""
SSH_ALLOWED_IPS="1.2.3.4 office.example.com 10.0.0.0/24 2001:db8::/32"

# Trusted (full access, never rate limited) and blacklisted (blocked in + out)
TRUSTED_IPS="10.0.0.1 management.example.com"
TRUSTED_RANGES="192.168.1.1-192.168.1.254"
BLACKLIST="5.6.7.8 bad-actor.example.com"
BLOCKED_RANGES="65.208.151.1-65.208.151.254"

# Open a port for specific addresses only — format: protocol|port|address
PORT_IP_RULES="tcp|3306|10.0.0.5
tcp|5432|db-client.example.com
tcp|6379|192.168.1.0/24"

# Re-check hostnames every N minutes, reload when an IP changed (0 = off)
DNS_REFRESH_INTERVAL="5"

# Rate limiting: new TCP connections per source IP
RATE_LIMIT_ENABLE="true"
RATE_LIMIT_RATE="25"             # per second; or e.g. "600/minute"
RATE_LIMIT_BURST="100"           # extra connections allowed in a burst
CONN_RATE_PER_IP="0"             # optional hard cap per second, no burst (0 = off)
CONN_LIMIT_ENABLE="false"        # limit concurrent connections per IP
CONN_LIMIT_PER_IP="50"

# Hardening
SYN_FLOOD_PROTECT="true"         # kernel SYN cookies + drop impossible TCP flags
DROP_INVALID="true"              # drop packets that belong to no connection
BLOCK_COMMON_ATTACKS="true"      # silently drop telnet/netbios/SMB/SSDP probes

# Features
ICMP_ENABLE="true"               # answer ping
MULTICAST_ENABLE="false"         # for clusters/load balancers
LOG_DROPPED="true"               # log dropped packets (max 5/minute)

# NAT routing + port forwarding — format: protocol|ext_port|ip:port
NAT_ENABLE="false"
NAT_EXTERNAL_IFACE="eth0"
NAT_INTERNAL_IFACE="eth1"
PORT_FORWARD_RULES="tcp|8080|192.168.1.100:80
tcp|2222|192.168.1.100:22"

# Custom rules (nft syntax on nftables, iptables-restore syntax on iptables)
CUSTOM_RULES_FILE="/etc/binadit-firewall/custom.rules"
```

The `_IPV6` variants of the address settings (`SSH_ALLOWED_IPS_IPV6`, `TRUSTED_IPS_IPV6`, `TRUSTED_RANGES_IPV6`, `BLACKLIST_IPV6`, `BLOCKED_RANGES_IPV6`) still work and behave exactly like the settings without the suffix. `TCP_PORTS_OUTPUT` and `SMTP_ENABLE` are deprecated and have no effect: outgoing traffic is always allowed unless blocked with `BLOCKED_*_PORTS_OUTPUT`. `BINADIT_DEBUG="true"` enables debug logging.

See `config/firewall.conf.example` for the full configuration reference with all options documented.

### In which order are rules checked?

For incoming traffic, the first match wins:

1. Loopback → allowed
2. `BLACKLIST` / `BLOCKED_RANGES` → dropped (also existing connections)
3. Existing connections → allowed; invalid packets → dropped
4. `BLOCKED_TCP_PORTS` / `BLOCKED_UDP_PORTS` → dropped
5. `TRUSTED_IPS` / `TRUSTED_RANGES` → allowed
6. ICMPv6 that IPv6 itself needs → allowed
7. `SSH_ALLOWED_IPS` → allowed on the SSH port
8. SYN flood protection, connection limit, rate limits → dropped when over the limit
9. `PORT_IP_RULES` → allowed
10. SSH → allowed (no allow-list) or dropped (allow-list set)
11. `TCP_PORTS` / `UDP_PORTS` → allowed
12. Ping, multicast (when enabled) → allowed
13. Everything else → dropped (and logged)

### Limitations

- **Docker / Kubernetes hosts** are not supported: forwarded traffic is dropped by default, which breaks container networking. (On the iptables backend, `start`/`stop` also flush the rules Docker created.)
- Rate and connection limits only apply to TCP.
- Port forwarding is IPv4 only.

## Upgrading

### From any v2.x / v3.x

```bash
binadit-firewall update        # download & install the latest version
```

or re-run the one-line installer. Your configuration is preserved either way.

**Upgrading from 3.0.x to 3.1:** versions up to 3.0.3 keep the old rules loaded after `binadit-firewall update`. Run `binadit-firewall restart` once to load the corrected rules (from 3.1 on, an update reloads the rules by itself). See the [CHANGELOG](CHANGELOG.md) for what changed — most importantly, closed ports are now really closed.

**Breaking change in v3.0:** The OUTPUT chain policy changed from `DROP` to `ACCEPT`. All outgoing traffic works by default. Use `BLOCKED_TCP_PORTS_OUTPUT` / `BLOCKED_UDP_PORTS_OUTPUT` to block specific outgoing ports, e.g. `BLOCKED_TCP_PORTS_OUTPUT="25 465 587"` to block outgoing mail. `SMTP_ENABLE` no longer has any effect.

### From v1.x (2013)

```bash
curl -sL https://raw.githubusercontent.com/ronaldjonkers/binadit-firewall/master/get.sh | sudo bash
```

The installer detects the old `/etc/firewall.d/host.conf` and migrates all settings to the new format. Old files are renamed, not deleted, the old init script is retired, and the v1 rules still loaded in the kernel are removed once the new firewall is active.

**SSH access is preserved.** v1 only allowed SSH from `SSHACCESS`, `DMZS` and `DMZRANGE` (unless the SSH port was in `TCPPORTS`). Those addresses are all written to `SSH_ALLOWED_IPS`, so SSH is not suddenly open to everyone. If v1 allowed SSH from nobody at all, the migration warns: binadit-firewall never closes SSH completely.

### Variable mappings (v1.x → v3.x)

| Old (v1.x) | New |
|---|---|
| `TCPPORTS` | `TCP_PORTS` |
| `TCPPORTS_INPUT` | `TCP_PORTS_INPUT` |
| `TCPPORTS_OUTPUT` | *(not needed: outgoing traffic is allowed)* |
| `UDPPORTS` | `UDP_PORTS` |
| `DMZS` | `TRUSTED_IPS` |
| `SSHACCESS` | `SSH_ALLOWED_IPS` |
| `DMZS`, `DMZRANGE` | also added to `SSH_ALLOWED_IPS` (they had SSH access in v1) |
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
│   ├── test_firewall.sh                # Unit tests (no root needed)
│   └── test_integration.sh             # Real-kernel tests with real connections
├── CHANGELOG.md
├── LICENSE                             # GPL-2.0
└── README.md
```

## Running Tests

```bash
bash tests/test_firewall.sh              # unit tests — no root, no firewall needed
sudo bash tests/test_integration.sh      # integration tests — Linux + root
```

The **unit tests** cover validation, config handling, the CLI, hostname resolution/caching, v1 migration, and the generated rulesets for both backends (including: no rule may ever accept traffic that the configuration did not open).

The **integration tests** load the rules into the kernel and verify them with real connections between network namespaces, for nftables and iptables: open ports are open, everything else is closed, SSH restrictions, trusted/blacklisted addresses, per-IP rate and connection limits, hostname changes, atomic reload and more. They run in a private network namespace and never touch the firewall of the machine you run them on.

Both suites run in CI on every push.

## How It Works

1. **Backend detection** — binadit-firewall uses `nft` (nftables) when it works, otherwise `iptables`. Force one with `BINADIT_BACKEND=nftables|iptables`.
2. **Config parsing** — The configuration file is sourced as bash, making it simple and familiar. Keys that are missing (configs from older versions) get safe defaults.
3. **Hostname resolution** — Hostnames are resolved (A + AAAA) with a cache fallback.
4. **Rule generation** — A complete ruleset is generated and verified by the kernel first (`nft -c` / `iptables-restore --test`):
   - **nftables**: own tables `inet binadit` (+ `ip binadit_nat` for NAT), replaced in one transaction. Other tables on the system are not touched.
   - **iptables**: the `filter` (and `nat`) table is replaced in one `iptables-restore` commit, for IPv4 and IPv6.
5. **Persistence** — The boot service loads the rules before the network comes up.
6. **Backup** — Before every start/stop the loaded rules are saved to `/etc/binadit-firewall/backups/` (the 30 newest files are kept).

## Troubleshooting

```bash
# Enable debug mode
BINADIT_DEBUG=true binadit-firewall start

# Check which backend is used
binadit-firewall version

# View current rules
binadit-firewall status

# Validate the config and let the kernel check the generated rules
binadit-firewall configtest

# Check systemd service and the hostname re-check timer
systemctl status binadit-firewall
systemctl list-timers 'binadit-firewall*'
journalctl -t binadit-firewall

# View drop logs
journalctl -k | grep binadit-drop

# Emergency: disable firewall
binadit-firewall stop
```

## License

GPL-2.0 — See [LICENSE](LICENSE) for details.

## Author

**Ronald Jonkers** — [Binadit BV](https://binadit.com)

Copyright © 2013-2026 Ronald Jonkers — Binadit BV. All rights reserved.

Originally created in 2013, completely rewritten in 2026 for modern Linux.

---

*binadit-firewall — making firewall management easy since 2013* 🛡️
*A product of [Binadit BV](https://binadit.com)*