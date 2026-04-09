#!/usr/bin/env bash
# =============================================================================
# Linux Server Hardening Suite — Orchestrator
# Run this as root to apply all hardening scripts in sequence.
# Each module is idempotent and can be re-run safely.
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="/var/log/hardening_$(date +%Y%m%d_%H%M%S).log"
ERRORS=0

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

log()   { echo -e "${CYAN}[$(date +%T)]${NC} $*" | tee -a "$LOG_FILE"; }
ok()    { echo -e "${GREEN}  ✔ $*${NC}"           | tee -a "$LOG_FILE"; }
warn()  { echo -e "${YELLOW}  ⚠ $*${NC}"          | tee -a "$LOG_FILE"; }
error() { echo -e "${RED}  ✘ $*${NC}"             | tee -a "$LOG_FILE"; ((ERRORS++)); }

[[ $EUID -ne 0 ]] && { error "Must be run as root."; exit 1; }

# Detect distro family
if   command -v apt-get &>/dev/null; then DISTRO=debian
elif command -v dnf     &>/dev/null; then DISTRO=rhel
elif command -v zypper  &>/dev/null; then DISTRO=suse
else error "Unsupported distro. Only Debian/Ubuntu, RHEL/Fedora, and openSUSE are supported."; exit 1
fi
export DISTRO

log "========================================================"
log " Linux Server Hardening Suite"
log " Distro family : $DISTRO"
log " Log file      : $LOG_FILE"
log "========================================================"

MODULES=(
  "01_system_updates.sh"
  "02_ssh_hardening.sh"
  "03_firewall.sh"
  "04_user_accounts.sh"
  "05_kernel_params.sh"
  "06_filesystem_security.sh"
  "07_logging_auditing.sh"
  "08_services.sh"
  "09_fail2ban.sh"
)

for module in "${MODULES[@]}"; do
  script="$SCRIPT_DIR/$module"
  if [[ -f "$script" ]]; then
    log "Running: $module"
    if bash "$script" >> "$LOG_FILE" 2>&1; then
      ok "Completed: $module"
    else
      error "Failed:    $module (see log for details)"
    fi
  else
    warn "Skipping: $module (not found)"
  fi
done

log "========================================================"
if [[ $ERRORS -eq 0 ]]; then
  log " Hardening complete — no errors."
else
  log " Hardening complete — $ERRORS error(s). Review: $LOG_FILE"
fi
log "========================================================"
echo
warn "IMPORTANT: Review /etc/ssh/sshd_config and test SSH access before closing this session!"
warn "A reboot is recommended to apply kernel parameter changes."
