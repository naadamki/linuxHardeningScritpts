#!/usr/bin/env bash
# =============================================================================
# Module 08 — Disable Unnecessary Services & Kernel Modules
# Stops and disables services that are rarely needed on a hardened server.
# Edit the lists below to match your workload before running.
# =============================================================================
set -euo pipefail

echo "[08] Disabling unnecessary services and kernel modules..."

# ── Services to disable ───────────────────────────────────────────────────────
# Review carefully — only disable what you don't need.
SERVICES_TO_DISABLE=(
  # Legacy remote access
  telnet rsh rlogin rexec
  # Legacy printing
  cups cups-browsed
  # NIS/NFS (disable if not a file server)
  rpcbind nfs-server nfs-kernel-server nfs-client.target
  # Avahi (zeroconf/mDNS — not needed on servers)
  avahi-daemon avahi-dnsconfd
  # SNMP (unless you use it for monitoring)
  snmpd
  # Bluetooth
  bluetooth blueman-mechanism
  # ISDN
  isdnutils isdn4linux
  # X11
  gdm gdm3 lightdm sddm xdm
  # Legacy talk
  talk ntalk
)

for svc in "${SERVICES_TO_DISABLE[@]}"; do
  # Check by service name only (systemd unit may differ)
  for unit in "${svc}" "${svc}.service"; do
    if systemctl list-units --all --full -q 2>/dev/null | grep -q "^${unit}"; then
      systemctl stop    "$unit" 2>/dev/null && echo "  Stopped:   $unit" || true
      systemctl disable "$unit" 2>/dev/null && echo "  Disabled:  $unit" || true
    fi
  done
done

# ── Remove dangerous packages (if installed) ─────────────────────────────────
PACKAGES_TO_REMOVE=(
  telnet rsh-client rsh-redone-client
  nis yp-tools
  talk talkd
  xinetd inetd openbsd-inetd
  nmap           # Remove from servers; keep on bastion/jumpboxes
  tcpdump        # Comment out if you need for diagnostics
)

case "$DISTRO" in
  debian)
    for pkg in "${PACKAGES_TO_REMOVE[@]}"; do
      if dpkg -l "$pkg" 2>/dev/null | grep -q "^ii"; then
        apt-get purge -y -q "$pkg" && echo "  Removed: $pkg" || true
      fi
    done
    ;;
  rhel)
    for pkg in "${PACKAGES_TO_REMOVE[@]}"; do
      if rpm -q "$pkg" &>/dev/null; then
        dnf remove -y -q "$pkg" && echo "  Removed: $pkg" || true
      fi
    done
    ;;
esac

# ── Disable unused kernel modules via modprobe ────────────────────────────────
MODULES_CONF="/etc/modprobe.d/hardening.conf"
cat > "$MODULES_CONF" <<'EOF'
# Disabled by hardening suite — uncomment to re-enable

# Uncommon network protocols (rarely needed)
install dccp     /bin/false
install sctp     /bin/false
install rds      /bin/false
install tipc     /bin/false
install n-hdlc   /bin/false
install ax25     /bin/false
install netrom   /bin/false
install x25      /bin/false
install rose     /bin/false
install decnet   /bin/false
install econet   /bin/false
install af_802154 /bin/false
install ipx      /bin/false
install appletalk /bin/false
install psnap    /bin/false
install p8022    /bin/false
install p8023    /bin/false
install llc      /bin/false

# Bluetooth
install bluetooth /bin/false
install btusb    /bin/false

# FireWire (rare on cloud/virtual servers)
install firewire-core /bin/false
install ohci1394  /bin/false

# USB storage (if this is a headless server with no USB peripherals)
# CAUTION: comment out if USB storage is needed for backups
install usb-storage /bin/false

# Cramfs / squashfs / udf — uncommon filesystems
install cramfs   /bin/false
install freevxfs /bin/false
install jffs2    /bin/false
install hfs      /bin/false
install hfsplus  /bin/false
install udf      /bin/false

# Disable IP source routing support in kernel
options ipv6 disable=1
EOF

chmod 644 "$MODULES_CONF"
echo "  Kernel module blacklist written to: $MODULES_CONF"

# Update initramfs so the module blacklist is baked in
case "$DISTRO" in
  debian) update-initramfs -u 2>/dev/null && echo "  initramfs updated." || true ;;
  rhel)   dracut -f 2>/dev/null && echo "  initramfs (dracut) updated." || true ;;
esac

# ── Secure cron ───────────────────────────────────────────────────────────────
# Only allow root (and explicitly whitelisted users) to use cron
echo "root" > /etc/cron.allow
chmod 600 /etc/cron.allow
if [[ -f /etc/cron.deny ]]; then
  rm -f /etc/cron.deny
fi

# Only allow root to use at
echo "root" > /etc/at.allow 2>/dev/null || true
chmod 600 /etc/at.allow 2>/dev/null || true
rm -f /etc/at.deny 2>/dev/null || true

echo "  cron/at restricted to root."

# ── Disable core dumps ────────────────────────────────────────────────────────
# Set via limits.conf and systemd
cat > /etc/security/limits.d/10-hardening.conf <<'EOF'
# Disable core dumps for all users
*    hard    core    0
root hard    core    0
EOF

SYSTEMD_COREDUMP="/etc/systemd/coredump.conf.d/disable.conf"
mkdir -p /etc/systemd/coredump.conf.d/
cat > "$SYSTEMD_COREDUMP" <<'EOF'
[Coredump]
Storage=none
ProcessSizeMax=0
EOF

echo "  Core dumps disabled."

echo "[08] Services module complete."
