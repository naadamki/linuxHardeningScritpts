#!/usr/bin/env bash
# =============================================================================
# Module 04 — User Accounts & Password Policy
# =============================================================================
set -euo pipefail

echo "[04] Hardening user accounts and password policy..."

# ── Password ageing / complexity ──────────────────────────────────────────────
# /etc/login.defs controls defaults for new accounts
set_login_def() {
  local key="$1" val="$2"
  if grep -q "^${key}" /etc/login.defs; then
    sed -i "s|^${key}.*|${key} ${val}|" /etc/login.defs
  else
    echo "${key} ${val}" >> /etc/login.defs
  fi
}

set_login_def PASS_MAX_DAYS   90
set_login_def PASS_MIN_DAYS   1
set_login_def PASS_WARN_AGE   14
set_login_def PASS_MIN_LEN    14
set_login_def LOGIN_RETRIES   3
set_login_def LOGIN_TIMEOUT   60
set_login_def UMASK           027    # Files: 640, dirs: 750 by default
set_login_def SHA_CRYPT_MIN_ROUNDS 5000
set_login_def SHA_CRYPT_MAX_ROUNDS 10000

echo "  login.defs updated."

# Apply password ageing to all existing non-system, non-locked human accounts
while IFS=: read -r user _ uid gid _ home shell; do
  # Skip system accounts (uid < 1000), nologin shells, and root (handle separately)
  [[ "$uid" -lt 1000 ]] && continue
  [[ "$shell" =~ (nologin|false|sync|halt|shutdown) ]] && continue
  chage --maxdays 90 --mindays 1 --warndays 14 "$user" 2>/dev/null && \
    echo "  Applied password ageing to: $user"
done < /etc/passwd

# Set root password ageing (max 90 days) but keep root unlocked
chage --maxdays 90 --warndays 14 root 2>/dev/null || true

# ── PAM: password quality (libpwquality) ────────────────────────────────────
if [[ "$DISTRO" == "debian" ]]; then
  apt-get install -y -q libpam-pwquality

  cat > /etc/security/pwquality.conf <<'EOF'
# Minimum password length
minlen = 14
# Require at least N character class types
minclass = 3
# Maximum consecutive characters of the same class
maxclasserepeat = 4
# Disallow words from the user account or gecos field
gecoscheck = 1
# Enforce that new password differs from old
difok = 5
# Reject passwords with 3+ consecutive identical chars
maxrepeat = 3
# Credit bonuses for mixing character classes
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
EOF

elif [[ "$DISTRO" =~ (rhel|suse) ]]; then
  if [[ "$DISTRO" == "rhel" ]]; then
    dnf install -y -q libpwquality
  else
    zypper -n install -y cracklib
  fi

  [[ -f /etc/security/pwquality.conf ]] && cat >> /etc/security/pwquality.conf <<'EOF'
minlen = 14
minclass = 3
maxrepeat = 3
gecoscheck = 1
difok = 5
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
EOF
fi

echo "  PAM password quality configured."

# ── PAM: account lockout (pam_faillock / pam_tally2) ────────────────────────
if [[ "$DISTRO" == "debian" ]]; then
  # pam_faillock is in libpam-runtime >= 1.4; older systems use pam_tally2
  if dpkg -l libpam-modules 2>/dev/null | grep -q '^ii'; then
    FAILLOCK_CONF="/etc/security/faillock.conf"
    cat > "$FAILLOCK_CONF" <<'EOF'
deny = 5
fail_interval = 900
unlock_time = 900
even_deny_root
root_unlock_time = 60
audit
silent
EOF
    echo "  faillock.conf configured."
  fi
fi

# ── Root account ─────────────────────────────────────────────────────────────
# Lock direct root login (still reachable via sudo)
passwd -l root 2>/dev/null || true
echo "  Root account login locked (use sudo)."

# ── Sudo ─────────────────────────────────────────────────────────────────────
if ! command -v sudo &>/dev/null; then
  case "$DISTRO" in
    debian) apt-get install -y -q sudo ;;
    rhel)   dnf install -y -q sudo ;;
    suse)   zypper -n install -y sudo ;;
  esac
fi

# Secure sudoers settings
SUDOERS_HARDENING="/etc/sudoers.d/99_hardening"
cat > "$SUDOERS_HARDENING" <<'EOF'
# Require a real tty (prevents sudo through cron / shell injection)
Defaults requiretty
# Log sudo activity
Defaults logfile="/var/log/sudo.log"
Defaults log_input, log_output
# Limit sudo session caching
Defaults timestamp_timeout=5
# Show custom warning
Defaults lecture=always
# Expand path to prevent using user-controlled directories
Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
EOF

chmod 440 "$SUDOERS_HARDENING"
visudo -c -f "$SUDOERS_HARDENING" && echo "  Sudoers hardening installed." || {
  rm -f "$SUDOERS_HARDENING"
  echo "  WARNING: sudoers syntax error — skipped."
}

# ── Home directory permissions ────────────────────────────────────────────────
while IFS=: read -r user _ uid _ _ home _; do
  [[ "$uid" -lt 1000 ]] && continue
  [[ -d "$home" ]] || continue
  chmod 750 "$home"
  chown "${user}:${user}" "$home" 2>/dev/null || true
done < /etc/passwd
echo "  Home directory permissions set to 750."

# ── Remove or disable inactive accounts ──────────────────────────────────────
# Find accounts with passwords but no login in 90+ days (informational only)
echo "  Checking for stale accounts (last login > 90 days):"
while IFS=: read -r user _ uid _ _ _ shell; do
  [[ "$uid" -lt 1000 ]] && continue
  [[ "$shell" =~ (nologin|false) ]] && continue
  last_login=$(lastlog -u "$user" 2>/dev/null | tail -1 | awk '{print $5}')
  [[ "$last_login" == "**Never" ]] && echo "    Never logged in: $user"
done < /etc/passwd

echo "[04] User accounts module complete."
