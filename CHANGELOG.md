# Changelog

All notable changes to binadit-firewall will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.1.0] - 2026-11-19

Security and correctness release. Every documented feature was checked against
what the firewall really does in the kernel; the differences are fixed below.
**After updating from 3.0.x, run `binadit-firewall restart` once** to load the
corrected rules.

### 🔒 Security
- **Closed ports were reachable.** The "rate limiting" rule (`RATE_LIMIT_ENABLE`, on by default) *accepted* every new connection to *any* port as long as it stayed under the rate, and the "SYN flood protection" rule did the same for TCP. In practice ports that were not in `TCP_PORTS` (databases, admin panels, ...) were open to the internet on both backends. Limiters now only ever **drop** traffic that exceeds a limit; nothing is accepted unless the configuration opens it.
- **`SSH_ALLOWED_IPS` could be bypassed.** With the SSH port also in `TCP_PORTS`, or with only `SSH_ALLOWED_IPS_IPV6` set, SSH stayed open to everyone. An allow-list (IPv4 or IPv6) now always closes SSH for everybody else.
- **NAT router exposed the LAN.** Anything routed to the internal interface was accepted. Now only replies and configured port forwards may enter the LAN, and port forwards only apply to traffic arriving on the external interface (previously a forward for port 443 also hijacked the LAN's own outgoing HTTPS).
- **`BLACKLIST` on nftables** now also blocks existing connections and outgoing traffic to the address, like the iptables backend already did.

### Added
- **Automatic hostname re-check**: hostnames in the configuration are resolved again every `DNS_REFRESH_INTERVAL` minutes (default 5). When the IP behind a hostname changed, the rules are reloaded automatically and the change is logged. New command: `binadit-firewall dns-refresh`. Installed as systemd timer (or `/etc/cron.d` job) as soon as the configuration contains hostnames.
- **DNS cache**: resolved addresses are stored on disk. When DNS is down — or not available yet at boot — the last known addresses are used instead of silently dropping the rule (which could lock an admin out after a reboot).
- **Hostnames everywhere**: all A *and* AAAA records of a hostname are used, in every address setting (`BLACKLIST` and `PORT_IP_RULES` included). Every address setting accepts IPv4, IPv6, CIDR, ranges and hostnames.
- **`SSH_PORT`** setting to set the SSH port(s) explicitly. Auto-detection now reads the effective sshd configuration (`sshd -T`, `sshd_config.d`, multiple ports).
- **Kernel dry-run**: `configtest` (as root) generates the ruleset and has the kernel verify it without applying.
- **`status`** now states whether the firewall is active (exit code 0/3) and warns when `firewall.conf` was edited but not applied yet.
- **Integration test suite** (`tests/test_integration.sh`): loads the rules into a real kernel and verifies behaviour with real connections, for both backends. Runs in CI together with the unit tests.
- `auto-update` works on systems without cron (systemd timer). `update --force` reinstalls the current version.
- DHCPv6 client replies are accepted (IPv6 addresses via DHCPv6 kept working only by accident).

### Changed
- **Atomic apply on both backends.** The ruleset is generated, verified, and swapped in a single transaction. Previously nftables deleted the old table first (a rejected ruleset left the server with *no* firewall) and iptables applied rules one by one (an error half-way left a half-configured firewall, possibly without SSH access).
- **`restart` no longer stops the firewall first** — it replaces the rules atomically, like `reload`. No unprotected moment, and a config error can no longer leave the firewall switched off.
- **Rate limits are per source IP** (IPv6: per /64) and apply to new TCP connections on your open ports, where they previously had no effect at all. One abusive client can no longer use up the limit for everyone. Trusted IPs and the SSH allow-list are exempt.
  - `RATE_LIMIT_RATE` / `RATE_LIMIT_BURST`: sustained rate + burst per IP.
  - `CONN_RATE_PER_IP`: hard per-second cap per IP (was not implemented on nftables). **Existing configs contain `15` from the old template and this is now enforced**; set it to `0` if clients behind one address (NAT, proxy, load balancer) legitimately open more than 15 connections per second — or add them to `TRUSTED_IPS`. New installs default to `0`.
  - `CONN_LIMIT_PER_IP`: was a single global counter on nftables, is now per IP.
- **`SYN_FLOOD_PROTECT`** enables kernel SYN cookies and drops TCP packets with impossible flag combinations (replaces the 1 connection/second rule described above).
- **`update` reloads the rules** with the new version when the firewall is active (atomically; on failure the old rules stay). The download is verified before installing, and the program directory is swapped atomically.
- **Automatic reloads** (hostname change, update) use the configuration that is actually loaded, never a half-edited `firewall.conf`.
- **Installer**
  - Other firewalls (firewalld, ufw, ...) are disabled only *after* binadit-firewall is installed and its configuration validated, right before it starts. A failed install no longer leaves the server without any firewall. `netfilter-persistent` is handled too.
  - Without a terminal (Ansible, cloud-init, CI) the installer no longer aborts at its first question; it runs unattended.
  - Re-running the installer on an existing installation keeps your ports. The port review is optional and pre-selects what your configuration already opens (previously pressing Enter replaced `TCP_PORTS`/`UDP_PORTS` with a default selection).
  - Services listening on localhost only are no longer offered to be opened. SSH is no longer shown as a toggle that had no effect.
  - Entered addresses are validated. "Installation complete" is only reported when the firewall is really running.
  - Works on bash 4.2 (CentOS 7). No packages are installed when a backend is already present.
- **Uninstall** unmasks the firewalls the installer disabled, removes timers/cron jobs and boot links, and states clearly that the server has no firewall afterwards.
- **systemd unit**: rules are loaded before the network is brought up (`Before=network-pre.target`).
- **nftables NAT** lives in its own `ip binadit_nat` table and matches interfaces by name, so it loads on older kernels and before the interfaces exist.
- `config set/add/remove` validate the result and refuse changes that would break the configuration; multi-line values (`PORT_IP_RULES`) are replaced correctly; values containing `/` or `&` no longer corrupt the file.
- `configtest` validates everything it previously skipped: all IPv6 lists, ranges, rates, interface names, port-forward targets. Mistyped IPs such as `300.1.1.1` are no longer accepted as "hostnames". It warns about settings that have no effect (`SMTP_ENABLE="false"`, `TCP_PORTS_OUTPUT`).
- `config show` shows every setting.
- Login/prompt indicators check for binadit-firewall's own rules (they reported "active" when *any* nftables chain existed, e.g. Docker's) and work for non-root admins.
- The setup wizard no longer opens ports 80/443 when you answer "no".

### Fixed
- nftables: port ranges (`8000:9000`) made the whole ruleset fail to load.
- nftables: a NAT interface that did not exist yet (boot) made the whole ruleset fail to load.
- Configs from older versions that lack newer keys crashed with "unbound variable" (on iptables half-way through applying).
- iptables: `PORT_IP_RULES`, trusted/blocked ranges and SSH rules for IPv6; `CONN_RATE_PER_IP` above 20 made rule loading fail.
- iptables: changed rate limits only took effect after a reboot (the kernel kept the old limiter).
- v1.x migration failed on values containing a `/` (CIDR) and could overwrite an existing new configuration.
- `update` left its temporary directory behind; `configtest` exited without a summary on the first invalid value.

### Deprecated
- `TCP_PORTS_OUTPUT` (never had an effect since 3.0) and `SMTP_ENABLE`. Both are still accepted; `configtest` explains what to use instead.

## [3.0.3] - 2026-02-08

### Fixed
- **Self-update syntax error**: `binadit-firewall update` now exits immediately after replacing its own script file. Previously, bash would continue reading the replaced file at the wrong byte offset, causing a syntax error.

## [3.0.2] - 2026-02-08

### Fixed
- **Update version comparison**: `binadit-firewall update` now uses proper semver comparison (`sort -V`) instead of string equality. Prevents offering to "update" to an older version when GitHub CDN is caching.

## [3.0.1] - 2026-02-08

### Fixed
- **Installer service menu**: HTTP (80) and HTTPS (443) now always appear in the interactive port selection menu, even when no web server is running. Pre-selected by default, toggleable by user.

## [3.0.0] - 2026-02-08

### ⚠️ Breaking Changes
- **OUTPUT policy: ACCEPT** — Firewall now only protects inbound traffic by default. All outgoing connections (DNS, HTTP, NTP, SMTP, etc.) work without explicit rules. Previously OUTPUT was `DROP`, requiring explicit accept rules for every outgoing connection.
- **SMTP_ENABLE deprecated** — Outgoing mail works by default (OUTPUT accept). To block outgoing SMTP, use `BLOCKED_TCP_PORTS_OUTPUT="25 587"` instead. The config key is kept for backwards compatibility but no longer has any effect.

### Added
- **Outgoing port blocking**: New `BLOCKED_TCP_PORTS_OUTPUT` and `BLOCKED_UDP_PORTS_OUTPUT` config keys to block outgoing ports only (e.g., `"25 587"` to block outgoing SMTP/email)
- **CUSTOM_RULES_FILE support in nftables**: Custom rules file now works in both backends (was iptables-only)
- **iptables IPv6 security hardening**: Added SYN flood protection, rate limiting, connection limits, and common attack port blocking to IPv6 rules (were completely missing)
- **iptables IPv6 port blocking**: `BLOCKED_TCP/UDP_PORTS` and `BLOCKED_TCP/UDP_PORTS_OUTPUT` now applied to IPv6 (were IPv4-only)
- **Default ports 80/443**: HTTP and HTTPS open by default in example config, pre-selected in installer

### Changed
- **DROP_INVALID** now respects config — Was always hardcoded to true, now checks the `DROP_INVALID` config option in both backends
- **ICMP blocking** — When `ICMP_ENABLE=false`, explicit drop rules are added before the rate limiter in nftables (previously the rate limiter catch-all accepted ICMP packets)
- **Upgrade path** — Installer handles v1.x (2013), v2.x, and v3.x upgrades seamlessly with automatic config migration

### Fixed
- **nftables SYN flood rule**: Fixed syntax error — `burst 3` changed to `burst 3 packets` (nft requires `packets` keyword)
- **Firewall not starting**: Fixed `get_backend()` stdout pollution — `log_info` output was captured by command substitution, causing "Unsupported backend" error
- **nftables ruleset syntax**: Removed invalid shell syntax (`2>/dev/null || true`) from generated nft file
- **nftables rate limit unit**: `RATE_LIMIT_RATE` now automatically appends `/second` if no unit specified
- **nftables error reporting**: `nft -f` errors are now displayed instead of silenced
- **SSH lockout prevention**: Both backends now explicitly allow SSH when port is not in `TCP_PORTS` and `SSH_ALLOWED_IPS` is empty
- **ICMP/ping not blocked**: Fixed nftables rate limiter (`ct state new limit rate ... accept`) accepting ICMP before policy drop

### Tests
- Test suite expanded from 148 to 188 tests

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
