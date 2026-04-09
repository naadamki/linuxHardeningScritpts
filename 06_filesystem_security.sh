#!/usr/bin/env bash
# =============================================================================
# Module 06 — Filesystem Security
# Mount hardening, SUID/SGID auditing, world-writable file detection.
# =============================================================================
set -euo pipefail

echo "[06] Hardening filesystem..."

REPORT="/var/log/filesystem_audit_$(date +%Y%m%d).txt"

# ── /tmp hardening ────────────────────────────────────────────────────────────
# Mount /tmp as a separate tmpfs (nodev,nosuid,noexec) if it isn't already
if ! findmnt /tmp | grep -q tmpfs; then
  echo "  Adding systemd-tmpfiles-based tmpfs for /tmp"

  if systemctl list-units --all | grep -q tmp.mount; then
    # systemd-style
    cp /usr/share/systemd/tmp.mount /etc/systemd/system/tmp.mount 2>/dev/null || true
    systemctl enable tmp.mount 2>/dev/null && systemctl start tmp.mount 2>/dev/null || true
  else
    # fstab-style fallback
    if ! grep -q "^tmpfs\s*/tmp" /etc/fstab; then
      echo "tmpfs  /tmp  tmpfs  rw,nosuid,nodev,noexec,relatime,size=1G  0 0" >> /etc/fstab
      echo "  Added /tmp tmpfs entry to /etc/fstab (requires reboot to take effect)."
    fi
  fi
else
  # Re-mount with hardened options if already tmpfs
  mount -o remount,nodev,nosuid,noexec /tmp 2>/dev/null && \
    echo "  /tmp remounted with nodev,nosuid,noexec." || \
    echo "  Warning: could not remount /tmp — will take effect after reboot."
fi

# ── /dev/shm hardening ────────────────────────────────────────────────────────
if findmnt /dev/shm &>/dev/null; then
  mount -o remount,nodev,nosuid,noexec /dev/shm 2>/dev/null && \
    echo "  /dev/shm remounted with nodev,nosuid,noexec." || true
fi

# Make the /dev/shm options persist via /etc/fstab
if ! grep -q "^tmpfs\s*/dev/shm" /etc/fstab; then
  echo "tmpfs  /dev/shm  tmpfs  rw,nosuid,nodev,noexec,relatime  0 0" >> /etc/fstab
fi

# ── Sticky bit on world-writable directories ──────────────────────────────────
echo "  Setting sticky bit on world-writable directories..."
find / \( -path /proc -o -path /sys -o -path /dev \) -prune -o \
         -type d -perm -0002 -print | while read -r dir; do
  chmod +t "$dir" && echo "  Sticky bit set: $dir"
done

# ── SUID/SGID audit ──────────────────────────────────────────────────────────
{
  echo "=== SUID/SGID Audit Report — $(date) ==="
  echo ""
  echo "--- SUID files ---"
  find / \( -path /proc -o -path /sys -o -path /dev \) -prune -o \
           -type f -perm /4000 -print 2>/dev/null | sort

  echo ""
  echo "--- SGID files ---"
  find / \( -path /proc -o -path /sys -o -path /dev \) -prune -o \
           -type f -perm /2000 -print 2>/dev/null | sort

  echo ""
  echo "--- World-writable files (not in /tmp or /proc) ---"
  find / \( -path /proc -o -path /sys -o -path /dev -o -path /tmp -o -path /var/tmp \) \
         -prune -o -type f -perm -0002 -print 2>/dev/null | sort
} > "$REPORT"
echo "  Filesystem audit report written to: $REPORT"

# ── Remove common SUID bits that are rarely needed ───────────────────────────
# Only remove if the binary exists and is not essential for your workload
UNNECESSARY_SUID=(
  /usr/bin/at
  /usr/sbin/traceroute6.iputils
  /usr/bin/wall
  /usr/bin/write
  /usr/bin/rcp
  /usr/bin/rsh
  /usr/bin/rlogin
)
for bin in "${UNNECESSARY_SUID[@]}"; do
  if [[ -f "$bin" ]]; then
    chmod u-s "$bin" && echo "  Removed SUID from: $bin" || true
  fi
done

# ── Permissions on critical files ────────────────────────────────────────────
declare -A CRITICAL_PERMS=(
  ["/etc/passwd"]="0644"
  ["/etc/group"]="0644"
  ["/etc/shadow"]="0000"    # root-read only; managed via setuid utilities
  ["/etc/gshadow"]="0000"
  ["/etc/sudoers"]="0440"
  ["/etc/crontab"]="0600"
  ["/etc/ssh/sshd_config"]="0600"
  ["/boot"]="0700"
  ["/var/log"]="0755"
)

for file in "${!CRITICAL_PERMS[@]}"; do
  perm="${CRITICAL_PERMS[$file]}"
  if [[ -e "$file" ]]; then
    chmod "$perm" "$file" 2>/dev/null && echo "  Permission $perm set on: $file" || true
  fi
done

# /etc/shadow and /etc/gshadow need special group ownership on some distros
chown root:shadow /etc/shadow  2>/dev/null || chown root:root /etc/shadow  2>/dev/null || true
chown root:shadow /etc/gshadow 2>/dev/null || chown root:root /etc/gshadow 2>/dev/null || true

# ── /proc hardening ───────────────────────────────────────────────────────────
if ! grep -q "hidepid" /etc/fstab; then
  echo "proc  /proc  proc  defaults,hidepid=2,gid=0  0 0" >> /etc/fstab
  mount -o remount,hidepid=2 /proc 2>/dev/null && \
    echo "  /proc remounted with hidepid=2." || \
    echo "  Note: /proc hidepid will apply on next reboot."
fi

echo "[06] Filesystem security module complete."
