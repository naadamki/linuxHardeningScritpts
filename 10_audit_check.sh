#!/usr/bin/env bash
# =============================================================================
# Security Audit — verify hardening was applied
# Run after 00_run_all.sh to confirm the major settings are in place.
# Exits 0 if all checks pass, 1 if any fail.
# =============================================================================
set -euo pipefail

PASS=0; FAIL=0; WARN=0

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'

pass() { echo -e "${GREEN}  PASS${NC}  $*"; ((PASS++)); }
fail() { echo -e "${RED}  FAIL${NC}  $*"; ((FAIL++)); }
warn() { echo -e "${YELLOW}  WARN${NC}  $*"; ((WARN++)); }

check() {
  local desc="$1"; shift
  if "$@" &>/dev/null; then pass "$desc"; else fail "$desc"; fi
}

sshd_val() { sshd -T 2>/dev/null | grep -qi "^$1 $2"; }

echo "========================================================"
echo " Hardening Audit — $(date)"
echo "========================================================"

echo
echo "── SSH ───────────────────────────────────────────────"
check "PermitRootLogin no"              sshd_val permitrootlogin no
check "PasswordAuthentication no"       sshd_val passwordauthentication no
check "PermitEmptyPasswords no"         sshd_val permitemptypasswords no
check "X11Forwarding no"                sshd_val x11forwarding no
check "MaxAuthTries <= 4"               bash -c 'val=$(sshd -T 2>/dev/null | grep -i "^maxauthtries" | awk "{print \$2}"); [[ -n "$val" && "$val" -le 4 ]]'
check "Protocol 2"                      sshd_val protocol 2

echo
echo "── Kernel parameters ────────────────────────────────"
check "ASLR enabled (=2)"               bash -c '[[ "$(sysctl -n kernel.randomize_va_space)" == "2" ]]'
check "SYN cookies enabled"             bash -c '[[ "$(sysctl -n net.ipv4.tcp_syncookies)" == "1" ]]'
check "ICMP broadcast ignored"          bash -c '[[ "$(sysctl -n net.ipv4.icmp_echo_ignore_broadcasts)" == "1" ]]'
check "IP source routing disabled"      bash -c '[[ "$(sysctl -n net.ipv4.conf.all.accept_source_route)" == "0" ]]'
check "ICMP redirects ignored"          bash -c '[[ "$(sysctl -n net.ipv4.conf.all.accept_redirects)" == "0" ]]'
check "ptrace restricted"               bash -c '[[ "$(sysctl -n kernel.yama.ptrace_scope 2>/dev/null)" -ge 1 ]]'
check "dmesg restricted"                bash -c '[[ "$(sysctl -n kernel.dmesg_restrict)" == "1" ]]'
check "kptr restricted"                 bash -c '[[ "$(sysctl -n kernel.kptr_restrict)" -ge 1 ]]'

echo
echo "── Filesystem ────────────────────────────────────────"
check "/etc/shadow perms 0000 or 0400"  bash -c '[[ "$(stat -c %a /etc/shadow)" =~ ^0?[04]00$ ]]'
check "/etc/passwd perms 644"           bash -c '[[ "$(stat -c %a /etc/passwd)" == "644" ]]'
check "/etc/sudoers perms 440"          bash -c '[[ "$(stat -c %a /etc/sudoers)" == "440" ]]'
check "sshd_config perms 600"           bash -c '[[ "$(stat -c %a /etc/ssh/sshd_config)" == "600" ]]'

echo
echo "── Services ──────────────────────────────────────────"
for svc in telnet rsh avahi-daemon cups; do
  if systemctl is-active "$svc" &>/dev/null; then
    fail "$svc is running (should be disabled)"
  else
    pass "$svc is not active"
  fi
done
check "fail2ban running"                systemctl is-active fail2ban
check "auditd running"                  systemctl is-active auditd

echo
echo "── Firewall ──────────────────────────────────────────"
if command -v ufw &>/dev/null; then
  check "UFW enabled"  bash -c 'ufw status | grep -q "Status: active"'
elif command -v firewall-cmd &>/dev/null; then
  check "firewalld running"  systemctl is-active firewalld
else
  warn "No supported firewall detected"
fi

echo
echo "── Password policy ───────────────────────────────────"
check "PASS_MAX_DAYS <= 90"  bash -c 'val=$(grep "^PASS_MAX_DAYS" /etc/login.defs | awk "{print \$2}"); [[ -n "$val" && "$val" -le 90 ]]'
check "PASS_MIN_DAYS >= 1"   bash -c 'val=$(grep "^PASS_MIN_DAYS" /etc/login.defs | awk "{print \$2}"); [[ -n "$val" && "$val" -ge 1 ]]'
check "PASS_WARN_AGE >= 7"   bash -c 'val=$(grep "^PASS_WARN_AGE" /etc/login.defs | awk "{print \$2}"); [[ -n "$val" && "$val" -ge 7 ]]'

echo
echo "── Automatic updates ─────────────────────────────────"
if command -v apt-get &>/dev/null; then
  check "unattended-upgrades enabled"  systemctl is-enabled unattended-upgrades
elif command -v dnf &>/dev/null; then
  check "dnf-automatic enabled"  systemctl is-enabled dnf-automatic.timer
fi

echo
echo "========================================================"
echo -e " ${GREEN}PASS: $PASS${NC}   ${RED}FAIL: $FAIL${NC}   ${YELLOW}WARN: $WARN${NC}"
echo "========================================================"

[[ $FAIL -eq 0 ]]
