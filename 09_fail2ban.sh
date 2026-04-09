#!/usr/bin/env bash
# =============================================================================
# Module 09 — fail2ban
# Installs and configures fail2ban to protect SSH (and optionally other
# services). All customisation is in /etc/fail2ban/jail.local.
# =============================================================================
set -euo pipefail

echo "[09] Installing and configuring fail2ban..."

SSH_PORT=22   # Change if you moved SSH off port 22

case "$DISTRO" in
  debian) apt-get install -y -q fail2ban ;;
  rhel)   dnf install -y -q fail2ban fail2ban-firewalld ;;
  suse)   zypper -n install -y fail2ban ;;
esac

# ── jail.local (overrides jail.conf — never edit jail.conf directly) ─────────
cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
# Ban for 1 hour
bantime      = 3600
# Detection window: 10 minutes
findtime     = 600
# Max retries before ban
maxretry     = 5
# Backend: auto-detect (systemd or polling)
backend      = auto
# Use nftables (preferred) or iptables depending on availability
# On Debian/Ubuntu with ufw, set banaction = ufw
banaction    = iptables-multiport
banaction_allports = iptables-allports

# Email notifications (optional — configure sendmail/postfix separately)
# destemail = admin@yourdomain.com
# action = %(action_mwl)s

# Ignore RFC1918 / localhost — never ban from your own network
ignoreip     = 127.0.0.1/8 ::1 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16

# ── SSH ───────────────────────────────────────────────────────────────────────
[sshd]
enabled  = true
port     = $SSH_PORT
filter   = sshd
logpath  = /var/log/auth.log
maxretry = 3
bantime  = 3600
findtime = 300

# ── PAM-generic (catches failed su/sudo) ─────────────────────────────────────
[pam-generic]
enabled  = true
filter   = pam-generic
logpath  = /var/log/auth.log
maxretry = 5

# ── Optional service jails — uncomment as needed ─────────────────────────────

# [nginx-http-auth]
# enabled  = true
# port     = http,https
# logpath  = /var/log/nginx/error.log
# maxretry = 3

# [nginx-limit-req]
# enabled  = true
# port     = http,https
# logpath  = /var/log/nginx/error.log
# maxretry = 10

# [apache-auth]
# enabled  = true
# port     = http,https
# logpath  = /var/log/apache2/error.log
# maxretry = 3

# [postfix-sasl]
# enabled  = true
# port     = smtp,submission,smtps
# logpath  = /var/log/mail.log
# maxretry = 5
EOF

chmod 640 /etc/fail2ban/jail.local
echo "  /etc/fail2ban/jail.local written."

# ── Persistent ban database ───────────────────────────────────────────────────
mkdir -p /var/lib/fail2ban
touch /var/lib/fail2ban/fail2ban.sqlite3

# ── Start and enable ──────────────────────────────────────────────────────────
systemctl enable fail2ban
systemctl restart fail2ban
sleep 2

if systemctl is-active fail2ban &>/dev/null; then
  echo "  fail2ban running."
  fail2ban-client status 2>/dev/null | head -5 || true
else
  echo "  Warning: fail2ban did not start cleanly. Check: journalctl -u fail2ban"
fi

echo "[09] fail2ban module complete."
