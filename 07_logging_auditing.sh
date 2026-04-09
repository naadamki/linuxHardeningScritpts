#!/usr/bin/env bash
# =============================================================================
# Module 07 — Logging & Auditing (auditd, rsyslog, logrotate)
# Covers: auditd rules (CIS-aligned), rsyslog permissions, logrotate tuning.
# =============================================================================
set -euo pipefail

echo "[07] Configuring logging and auditing..."

# ── Install auditd ────────────────────────────────────────────────────────────
case "$DISTRO" in
  debian) apt-get install -y -q auditd audispd-plugins ;;
  rhel)   dnf install -y -q audit audit-libs ;;
  suse)   zypper -n install -y audit ;;
esac

# ── auditd configuration ──────────────────────────────────────────────────────
AUDIT_CONF="/etc/audit/auditd.conf"
if [[ -f "$AUDIT_CONF" ]]; then
  sed -i 's/^max_log_file_action.*/max_log_file_action = ROTATE/' "$AUDIT_CONF"
  sed -i 's/^num_logs.*/num_logs = 10/'                           "$AUDIT_CONF"
  sed -i 's/^max_log_file .*/max_log_file = 50/'                 "$AUDIT_CONF"
  sed -i 's/^space_left_action.*/space_left_action = email/'     "$AUDIT_CONF"
  sed -i 's/^admin_space_left_action.*/admin_space_left_action = halt/' "$AUDIT_CONF"
  echo "  auditd.conf tuned."
fi

# ── Audit rules (CIS Benchmark aligned) ─────────────────────────────────────
RULES_DIR="/etc/audit/rules.d"
mkdir -p "$RULES_DIR"

cat > "${RULES_DIR}/99-hardening.rules" <<'EOF'
# Delete all existing rules
-D

# Increase buffer size for busy systems
-b 8192

# Failure mode: 1 = print message, 2 = panic (use 2 only on critical systems)
-f 1

# ── Identity & auth ──────────────────────────────────────────────────────────
-w /etc/passwd     -p wa -k identity
-w /etc/shadow     -p wa -k identity
-w /etc/group      -p wa -k identity
-w /etc/gshadow    -p wa -k identity
-w /etc/sudoers    -p wa -k sudo_changes
-w /etc/sudoers.d/ -p wa -k sudo_changes
-w /var/log/sudo.log -p wa -k sudo_log

# ── Login/logout ─────────────────────────────────────────────────────────────
-w /var/log/faillog  -p wa -k logins
-w /var/log/lastlog  -p wa -k logins
-w /var/log/wtmp     -p wa -k logins
-w /var/log/btmp     -p wa -k logins

# ── Privileged escalation calls ───────────────────────────────────────────────
-a always,exit -F arch=b64 -S setuid,setgid,setreuid,setregid,setresuid,setresgid -F auid!=4294967295 -k privilege_escalation
-a always,exit -F arch=b32 -S setuid,setgid,setreuid,setregid,setresuid,setresgid -F auid!=4294967295 -k privilege_escalation

# ── System calls: process execution ──────────────────────────────────────────
-a always,exit -F arch=b64 -S execve -F auid!=4294967295 -k execve_monitor
-a always,exit -F arch=b32 -S execve -F auid!=4294967295 -k execve_monitor

# ── File deletion ─────────────────────────────────────────────────────────────
-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=4294967295 -k delete

# ── Kernel modules ────────────────────────────────────────────────────────────
-w /sbin/insmod    -p x -k modules
-w /sbin/rmmod     -p x -k modules
-w /sbin/modprobe  -p x -k modules
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k modules

# ── cron / scheduled jobs ─────────────────────────────────────────────────────
-w /etc/cron.allow      -p wa -k cron
-w /etc/cron.deny       -p wa -k cron
-w /etc/cron.d/         -p wa -k cron
-w /etc/cron.daily/     -p wa -k cron
-w /etc/cron.hourly/    -p wa -k cron
-w /etc/cron.monthly/   -p wa -k cron
-w /etc/cron.weekly/    -p wa -k cron
-w /etc/crontab         -p wa -k cron
-w /var/spool/cron/     -p wa -k cron

# ── Network configuration ─────────────────────────────────────────────────────
-w /etc/hosts           -p wa -k network
-w /etc/hostname        -p wa -k network
-w /etc/resolv.conf     -p wa -k network
-w /etc/network/        -p wa -k network
-w /etc/sysconfig/network -p wa -k network 2>/dev/null || true

# ── SSH configuration ─────────────────────────────────────────────────────────
-w /etc/ssh/sshd_config -p wa -k sshd_config

# ── Mount operations ─────────────────────────────────────────────────────────
-a always,exit -F arch=b64 -S mount   -F auid>=1000 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b32 -S mount   -F auid>=1000 -F auid!=4294967295 -k mounts

# ── Lock audit rules (no changes until reboot) ───────────────────────────────
-e 2
EOF

chmod 600 "${RULES_DIR}/99-hardening.rules"
echo "  Audit rules written to: ${RULES_DIR}/99-hardening.rules"

# Load rules immediately
if augenrules --load 2>/dev/null; then
  echo "  Audit rules loaded via augenrules."
elif auditctl -R "${RULES_DIR}/99-hardening.rules" 2>/dev/null; then
  echo "  Audit rules loaded via auditctl."
else
  echo "  Warning: could not load audit rules live — will apply on reboot."
fi

systemctl enable auditd
systemctl restart auditd
echo "  auditd enabled and restarted."

# ── rsyslog hardening ─────────────────────────────────────────────────────────
RSYSLOG_HARDENING="/etc/rsyslog.d/99-hardening.conf"
if command -v rsyslogd &>/dev/null; then
  cat > "$RSYSLOG_HARDENING" <<'EOF'
# Log auth and sudo to dedicated files
auth,authpriv.*                 /var/log/auth.log
:msg, contains, "sudo"          /var/log/sudo.log

# Keep all messages >= warning in the main log
*.warn                          /var/log/syslog-warn.log

# Avoid logging private auth info
module(load="imuxsock")
module(load="imklog")
EOF

  # Permissions on log files
  for logfile in /var/log/auth.log /var/log/sudo.log; do
    touch "$logfile"
    chmod 640 "$logfile"
    chown root:adm "$logfile" 2>/dev/null || chown root:root "$logfile"
  done

  systemctl restart rsyslog 2>/dev/null || true
  echo "  rsyslog hardened."
fi

# ── logrotate ────────────────────────────────────────────────────────────────
LOGROTATE_HARDENING="/etc/logrotate.d/hardening"
cat > "$LOGROTATE_HARDENING" <<'EOF'
/var/log/auth.log
/var/log/sudo.log
/var/log/syslog-warn.log
/var/log/audit/audit.log {
    daily
    missingok
    rotate 90
    compress
    delaycompress
    notifempty
    create 0640 root adm
    sharedscripts
    postrotate
        /usr/sbin/auditctl -e 1 2>/dev/null || true
    endscript
}
EOF
echo "  logrotate policy configured (90-day retention, daily rotation)."

echo "[07] Logging and auditing module complete."
