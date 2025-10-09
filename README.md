binadit-firewall
================

A simple secure firewall for Centos / Debian / Ubuntu with config file. Supports
both classic iptables rules and firewalld (using direct rules) so you can use it
on systems that prefer either backend.

How to install?
===============

Download files and place them in your /etc/ folder. Make /etc/init.d/firewall executable: chmod +x /etc/init.d/firewall

### Selecting the firewall backend

The generated `/etc/firewall.d/host.conf` now contains two additional options:

* `FIREWALL_BACKEND` – set to `auto`, `iptables` or `firewalld` to force a
  specific implementation. With `auto` the script automatically selects
  firewalld when it is running (`firewall-cmd --state` succeeds) and falls back
  to iptables otherwise.
* `FIREWALLD_ZONE` – determines the zone that will be used for firewalld
  operations if you extend the script later on. The current implementation uses
  direct rules and does not change zone assignments, so the value is advisory.

When `firewalld` is selected the script recreates the rule set using direct
permanent rules and then reloads the daemon, ensuring behaviour equivalent to
the iptables configuration.

To automatically start the firewall on boot:

CENTOS/FEDORA: chkconfig firewall on
UBUNTU/DEBIAN: update-rc.d firewall defaults
