#!/usr/bin/env bash
# =============================================================================
# Module 01 — System Updates & Unattended Security Upgrades
# =============================================================================
set -euo pipefail

echo "[01] Updating package lists and upgrading system..."

case "$DISTRO" in
  debian)
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -q
    apt-get upgrade -y -q
    apt-get autoremove -y -q

    # Install unattended-upgrades
    apt-get install -y -q unattended-upgrades apt-listchanges

    cat > /etc/apt/apt.conf.d/50unattended-upgrades <<'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};
Unattended-Upgrade::Package-Blacklist {};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Automatic-Reboot-Time "03:00";
EOF

    cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF

    systemctl enable unattended-upgrades
    systemctl restart unattended-upgrades
    echo "  Unattended-upgrades configured and enabled."
    ;;

  rhel)
    dnf upgrade -y -q
    dnf install -y -q dnf-automatic

    # Enable security-only automatic updates
    sed -i 's/^apply_updates = .*/apply_updates = yes/'   /etc/dnf/automatic.conf
    sed -i 's/^upgrade_type = .*/upgrade_type = security/' /etc/dnf/automatic.conf

    systemctl enable --now dnf-automatic.timer
    echo "  dnf-automatic configured and enabled."
    ;;

  suse)
    zypper -n update -y
    zypper -n install -y yast2-online-update
    echo "  System updated. Configure YaST online update for automatic patches."
    ;;
esac

echo "[01] System update module complete."
