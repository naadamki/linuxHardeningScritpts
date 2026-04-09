# Collection of Linux hardening scripts for a newly installed server
---
## **Before running: open 02_ssh_hardening.sh and confirm your public key is already in ~/.ssh/authorized_keys — the script disables password auth.**

- **00_run_all.sh** — Orchestrator. Detects your distro (Debian/Ubuntu, RHEL/Fedora, openSUSE), runs all modules in order, and writes a timestamped log to /var/log/.
- **01_system_updates.sh** — Applies all pending patches and enables unattended security updates (unattended-upgrades on Debian, dnf-automatic on RHEL).
- **02_ssh_hardening.sh** — Disables root login and password auth, restricts to modern ciphers/MACs/kex algorithms, sets idle timeouts, adds a legal banner, and validates the config before restarting sshd.
- **03_firewall.sh** — Default-deny inbound policy using UFW (Debian) or firewalld (RHEL/SUSE), with rate-limiting on SSH. Edit ALLOWED_TCP_PORTS at the top for your workload.
- **04_user_accounts.sh** — 90-day password expiry, libpwquality complexity policy, faillock account lockout, sudo hardening with session logging, home dir permissions set to 750.
- **05_kernel_params.sh** — ~40 sysctl parameters covering ASLR, SYN cookies, ICMP hardening, source routing, martian logging, ptrace restriction, dmesg restriction, and optional IPv6 disable.
- **06_filesystem_security.sh** — /tmp and /dev/shm mounted with nodev,nosuid,noexec, sticky bits on world-writable dirs, SUID/SGID audit report, /proc with hidepid=2, permissions tightened on critical files.
- **07_logging_auditing.sh** — Full auditd setup with CIS-aligned rules (identity changes, execve, privilege escalation, cron, SSH config, kernel modules), rsyslog auth log separation, 90-day logrotate retention.
- **08_services.sh** — Stops and disables telnet, cups, avahi, SNMP, Bluetooth, etc. Blacklists uncommon kernel modules (DCCP, SCTP, cramfs, USB storage, etc.). Restricts cron/at to root.
- **09_fail2ban.sh** — Installs fail2ban with a jail.local covering SSH and PAM. Includes commented-out jails for nginx, Apache, and Postfix ready to enable.
- **10_audit_check.sh** — Verification script. Run it after applying hardening to get a PASS/FAIL/WARN report across SSH, sysctl, file permissions, services, firewall, and password policy.

## Usage:
`sudo bash 00_run_all.sh`
`sudo bash 10_audit_check.sh   # verify`

