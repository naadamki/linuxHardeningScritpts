#!/usr/bin/env bash
# =============================================================================
# Module 02 — SSH Hardening
# Backs up the original sshd_config before making changes.
# =============================================================================
set -euo pipefail

SSHD_CONFIG="/etc/ssh/sshd_config"
BACKUP="${SSHD_CONFIG}.bak_$(date +%Y%m%d%H%M%S)"

echo "[02] Hardening SSH..."

cp "$SSHD_CONFIG" "$BACKUP"
echo "  Backed up sshd_config to: $BACKUP"

# Helper: set or replace a directive (handles commented-out lines too)
set_sshd() {
  local key="$1" val="$2"
  if grep -qE "^\s*#?\s*${key}\s" "$SSHD_CONFIG"; then
    sed -i -E "s|^\s*#?\s*${key}\s.*|${key} ${val}|" "$SSHD_CONFIG"
  else
    echo "${key} ${val}" >> "$SSHD_CONFIG"
  fi
}

# ── Protocol & Authentication ─────────────────────────────────────────────────
set_sshd Protocol              2
set_sshd PermitRootLogin       no
set_sshd PasswordAuthentication no   # Require key-based auth; change to 'yes' if needed during initial setup
set_sshd PubkeyAuthentication  yes
set_sshd AuthorizedKeysFile    ".ssh/authorized_keys"
set_sshd PermitEmptyPasswords  no
set_sshd ChallengeResponseAuthentication no
set_sshd UsePAM                yes
set_sshd KerberosAuthentication no
set_sshd GSSAPIAuthentication  no

# ── Session Limits ────────────────────────────────────────────────────────────
set_sshd MaxAuthTries          3
set_sshd MaxSessions           10
set_sshd LoginGraceTime        30
set_sshd ClientAliveInterval   300
set_sshd ClientAliveCountMax   2

# ── Forwarding & Tunnelling ───────────────────────────────────────────────────
set_sshd AllowAgentForwarding  no
set_sshd AllowTcpForwarding    no
set_sshd X11Forwarding         no
set_sshd PermitTunnel          no

# ── Host Keys & Ciphers ───────────────────────────────────────────────────────
# Restrict to strong modern algorithms
set_sshd HostKeyAlgorithms     "ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp521,rsa-sha2-512,rsa-sha2-256"
set_sshd Ciphers               "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr"
set_sshd MACs                  "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com"
set_sshd KexAlgorithms         "curve25519-sha256@libssh.org,curve25519-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512"

# ── Miscellaneous ─────────────────────────────────────────────────────────────
set_sshd Banner                /etc/issue.net
set_sshd LogLevel              VERBOSE
set_sshd PrintLastLog          yes
set_sshd UsePrivilegeSeparation sandbox
set_sshd StrictModes           yes
set_sshd IgnoreRhosts          yes
set_sshd HostbasedAuthentication no
set_sshd AcceptEnv             LANG LC_*

# ── Legal Banner ──────────────────────────────────────────────────────────────
cat > /etc/issue.net <<'EOF'
**********************************************************************
NOTICE: This system is for authorised use only.
Unauthorised access is strictly prohibited and may be subject to
criminal prosecution. All activity is monitored and logged.
**********************************************************************
EOF

cat > /etc/issue <<'EOF'
Authorised access only. All activity is logged.
EOF

# ── Regenerate host keys (only if they don't exist or are weak) ───────────────
if [[ ! -f /etc/ssh/ssh_host_ed25519_key ]]; then
  ssh-keygen -t ed25519 -N "" -f /etc/ssh/ssh_host_ed25519_key
  echo "  Generated new ed25519 host key."
fi

# Remove weak DSA host key if present
rm -f /etc/ssh/ssh_host_dsa_key /etc/ssh/ssh_host_dsa_key.pub

# ── Permissions ───────────────────────────────────────────────────────────────
chmod 600 /etc/ssh/ssh_host_*_key   2>/dev/null || true
chmod 644 /etc/ssh/ssh_host_*_key.pub 2>/dev/null || true
chown root:root /etc/ssh/sshd_config
chmod 600 /etc/ssh/sshd_config

# ── Validate and restart ──────────────────────────────────────────────────────
sshd -t && echo "  sshd config syntax OK." || {
  echo "  ERROR: sshd config invalid — restoring backup."
  cp "$BACKUP" "$SSHD_CONFIG"
  exit 1
}

systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null
echo "  sshd restarted."

echo "[02] SSH hardening complete."
echo "  REMINDER: Ensure at least one public key is in ~/.ssh/authorized_keys"
echo "  before your next login, since PasswordAuthentication is now disabled."
