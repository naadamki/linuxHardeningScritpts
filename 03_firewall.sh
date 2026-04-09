#!/usr/bin/env bash
# =============================================================================
# Module 03 — Firewall (UFW on Debian/Ubuntu, firewalld on RHEL/Fedora)
# Default posture: deny all inbound, allow SSH + established.
# Extend ALLOWED_TCP_PORTS below for your workload.
# =============================================================================
set -euo pipefail

echo "[03] Configuring firewall..."

# ── Customise these ───────────────────────────────────────────────────────────
SSH_PORT=22
ALLOWED_TCP_PORTS=(22)      # Add 80 443 etc. as needed, e.g. (22 80 443)
ALLOWED_UDP_PORTS=()        # e.g. (51820) for WireGuard

# ── Debian / Ubuntu — UFW ────────────────────────────────────────────────────
if [[ "$DISTRO" == "debian" ]]; then
  apt-get install -y -q ufw

  ufw --force reset
  ufw default deny incoming
  ufw default allow outgoing
  ufw default deny forward

  for port in "${ALLOWED_TCP_PORTS[@]}"; do
    ufw allow "$port/tcp"
    echo "  Allowed TCP $port"
  done
  for port in "${ALLOWED_UDP_PORTS[@]}"; do
    ufw allow "$port/udp"
    echo "  Allowed UDP $port"
  done

  # Rate-limit SSH to mitigate brute-force
  ufw limit "${SSH_PORT}/tcp"
  echo "  Rate-limited SSH (port $SSH_PORT)."

  # Logging
  ufw logging on
  ufw logging medium

  ufw --force enable
  ufw status verbose
  echo "  UFW enabled."

# ── RHEL / Fedora — firewalld ────────────────────────────────────────────────
elif [[ "$DISTRO" == "rhel" ]]; then
  dnf install -y -q firewalld

  systemctl enable --now firewalld

  # Remove ssh from default zone if not wanted on default interface
  firewall-cmd --set-default-zone=drop

  for port in "${ALLOWED_TCP_PORTS[@]}"; do
    firewall-cmd --permanent --add-port="${port}/tcp"
    echo "  Allowed TCP $port"
  done
  for port in "${ALLOWED_UDP_PORTS[@]}"; do
    firewall-cmd --permanent --add-port="${port}/udp"
    echo "  Allowed UDP $port"
  done

  # Allow established/related return traffic (default in firewalld)
  firewall-cmd --permanent --add-service=ssh

  firewall-cmd --reload
  firewall-cmd --list-all
  echo "  firewalld configured."

# ── openSUSE — firewalld ─────────────────────────────────────────────────────
elif [[ "$DISTRO" == "suse" ]]; then
  zypper -n install -y firewalld

  systemctl enable --now firewalld

  firewall-cmd --set-default-zone=drop
  for port in "${ALLOWED_TCP_PORTS[@]}"; do
    firewall-cmd --permanent --add-port="${port}/tcp"
  done
  firewall-cmd --reload
  echo "  firewalld configured."
fi

# ── IPv6 ─────────────────────────────────────────────────────────────────────
# Disable IPv6 at the kernel level if unused (optional — comment out if needed)
# See also 05_kernel_params.sh where net.ipv6.conf.all.disable_ipv6 = 1 is set.

echo "[03] Firewall module complete."
