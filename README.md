# 🔐 Comprehensive Security Hardening Guide for Linux (Ubuntu, Debian, SUSE, Rocky, Alma, Arch) and FreeBSD

Securing servers is a **layered process** there is no silver bullet. A hardened system reduces attack surface, enforces least privilege, and ensures monitoring and recovery are possible. This guide presents a **deep-dive into hardening techniques** across common Linux distributions (Ubuntu/Debian, SUSE, RHEL-derived Rocky/Alma, Arch) and FreeBSD.

## 🧩 1. Baseline Principles

- **Minimize attack surface**: Only install required packages/services.  
- **Apply least privilege**: Restrict users, processes, and filesystems.  
- **Defense in depth**: Firewalls, intrusion detection, encryption, logging.  
- **Automate security updates**: Patch frequently.  
- **Audit and monitor**: Know what is happening on the system.  

## ⚙️ 2. OS Installation & Partitioning

### General
- Use **LVM with encryption (LUKS/cryptsetup or geli on FreeBSD)** for sensitive data.  
- Separate partitions for:
  - `/boot` (read-only after boot)
  - `/var` (logs, spool, prevent DoS from filling `/`)
  - `/home`
  - `/tmp` (with `noexec,nosuid,nodev`)
  - `/var/tmp` (symlink to `/tmp`)
- Use **UEFI Secure Boot** with custom keys if possible.

### FreeBSD
- Use **ZFS with GELI** encryption.  
- Mount `/tmp` and `/var/tmp` with `nosuid,noexec`.  
- Enable `kern.securelevel=2` in `/etc/sysctl.conf` for immutable system protection.

## 🔑 3. User & Authentication Hardening

### Common (Linux + BSD)
- Disable root login:
  ```bash
  # Linux: in /etc/ssh/sshd_config
  PermitRootLogin no
  ```

```shell
# FreeBSD: in /etc/ssh/sshd_config
PermitRootLogin prohibit-password
```

* Create unprivileged sudo user with key-based login.
* Enforce password policies:

  * **Linux PAM** (`/etc/security/pwquality.conf`)
  * **FreeBSD** (`pw(8)` with `passwd_format=sha512`)
* Lock unused accounts:

  ```bash
  sudo usermod -L <user>
  ```
* Disable TTY for system/service accounts (`/sbin/nologin` or `/usr/sbin/nologin`).

### MFA

* Use **Google Authenticator/PAM-OATH** on Linux.
* FreeBSD: `login_google_authenticator` in `/etc/login.conf`.

## 🔐 4. SSH Security

* Change port (obscurity, not security, but reduces noise).

* Key-based auth only:

  ```bash
  PasswordAuthentication no
  ```

* Limit users/groups:

  ```bash
  AllowUsers admin site1 site2
  ```

* Enable rate limiting:

  * Linux: `ufw limit ssh` or `iptables recent module`.
  * FreeBSD: `pf` table with `max-src-conn-rate`.

* Enable `Banner` in sshd to warn about authorized use.

## 🛡️ 5. Firewalling & Packet Filtering

### Ubuntu/Debian/Rocky/Alma

* **nftables** (preferred over iptables).
* Example baseline:

  ```bash
  table inet filter {
      chain input {
          type filter hook input priority 0;
          policy drop;
          iif lo accept
          ct state established,related accept
          tcp dport { 22, 80, 443 } accept
      }
  }
  ```

### SUSE

* Firewalld default; configure zones (`public`, `internal`).

### Arch

* nftables, or raw iptables for fine-grained control.

### FreeBSD

* Use **pf**:

  ```pf
  block in all
  pass out all keep state
  pass in on egress proto tcp from any to (egress) port { 22, 80, 443 }
  ```

## 🧾 6. Mandatory Access Control (MAC)

* **Ubuntu/Debian/RHEL/Alma/Rocky**: Use **AppArmor** (Ubuntu default) or **SELinux** (RHEL family default).

  * Keep profiles in enforcing mode, not permissive.
* **SUSE**: AppArmor by default.
* **Arch**: AppArmor/SELinux available via AUR and kernel hooks.
* **FreeBSD**: Use **MAC framework** (`mac_bsdextended`, `mac_portacl`) to restrict process and port access.

## 🧪 7. Kernel Hardening

### sysctl (Linux)

Add to `/etc/sysctl.d/99-hardening.conf`:

```bash
# Disable IP forwarding
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# Ignore broadcast/malformed packets
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0

# Enable TCP SYN cookies
net.ipv4.tcp_syncookies = 1

# Restrict kernel pointers
kernel.kptr_restrict = 2
```

### FreeBSD sysctl

`/etc/sysctl.conf`:

```shell
net.inet.icmp.drop_redirect=1
net.inet.tcp.drop_synfin=1
net.inet.ip.forwarding=0
security.bsd.see_other_uids=0
security.bsd.see_other_gids=0
```

## 🔍 8. Intrusion Detection & Monitoring

### Linux

* **Auditd**: Kernel audit framework (`auditctl`, `ausearch`).
* **OSSEC/Wazuh**: HIDS with log correlation.
* **Fail2ban**: Ban brute-force attempts (SSH, nginx, etc.).
* **Tripwire/AIDE**: File integrity monitoring.

### FreeBSD

* `auditd(8)` built into base system.
* `security/aide` for file integrity.
* `sshguard` for SSH brute-force prevention.

## 🔄 9. Automatic Updates

* **Ubuntu/Debian**: `unattended-upgrades`.
* **RHEL/Rocky/Alma**: `dnf-automatic`.
* **SUSE**: `zypper ps` + `zypper patch`.
* **Arch**: Use `reflector` + pacman hooks; test before cron automation.
* **FreeBSD**: `freebsd-update cron` + `pkg audit -F`.

## 🧯 10. Logging & Centralization

* Use **journald** + `rsyslog` to forward logs to a central syslog server.
* Enable **systemd rate limiting** to prevent log flooding.
* FreeBSD: `syslogd_flags="-ss"` to disable remote logging unless required.

Consider **ELK stack (Elasticsearch + Logstash + Kibana)** or **Graylog** for central analysis.

## 🕵️ 11. Application-Level Security

* Run services under **dedicated system users**.
* Drop privileges with `systemd` directives:

  ```ini
  [Service]
  User=nginx
  PrivateTmp=true
  NoNewPrivileges=true
  ProtectSystem=strict
  ProtectHome=yes
  ```
* FreeBSD rc.d equivalents: `setfib`, `jail(8)`, and capsicum (`cap_enter()`).

## 🧩 12. Virtualization & Container Security

* Enable **cgroups v2** and `seccomp` on Linux.
* Use **Podman** or rootless Docker where possible.
* FreeBSD: Prefer **jails** with VNET isolation, assign each jail its own IP.

## 🛠️ 13. Advanced Hardening

* **Kernel hardening projects**:

  * Linux: `grsecurity` (commercial), `linux-hardened` kernel.
  * Arch: `linux-hardened` in repos.
  * FreeBSD: HardenedBSD fork.

* **Compiler hardening**:

  * Enable `-fstack-protector-strong`, `-D_FORTIFY_SOURCE=2`.
  * Use PIE (Position Independent Executables).

* **Filesystem**:

  * Mount `/boot` as read-only.
  * `nosuid,noexec,nodev` on `/home`, `/var/tmp`, `/tmp`.

## ✅ 14. Auditing and Compliance

* **Lynis** (Linux/Unix hardening audit tool).
* **OpenSCAP** for compliance scans (CIS, NIST).
* **FreeBSD**: `pkg install lynis`, run periodic audits.

## 📌 15. Checklist Summary

* [x] Minimal OS install with encrypted partitions
* [x] Disable root SSH, use key-based auth
* [x] Enforce password/MFA policies
* [x] Configure nftables/pf with default-deny ruleset
* [x] Apply AppArmor/SELinux or FreeBSD MAC modules
* [x] Harden sysctl network/kernel parameters
* [x] Enable IDS/IPS, file integrity, fail2ban/sshguard
* [x] Automate updates, audit logs centrally
* [x] Sandbox applications (systemd hardening, jails)
* [x] Regularly audit with Lynis/OpenSCAP

## 📚 References

* [Ubuntu Security Guide](https://ubuntu.com/security)
* [Debian Security FAQ](https://www.debian.org/security/)
* [SUSE Security Best Practices](https://documentation.suse.com/sles/)
* [RHEL Hardening](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/)
* [Arch Wiki: Security](https://wiki.archlinux.org/title/Security)
* [FreeBSD Handbook: Security](https://docs.freebsd.org/en/books/handbook/security/)
* [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks)
