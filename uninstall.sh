#!/usr/bin/env bash
# uninstall.sh — Log-IDS removal script
# ─────────────────────────────────────────────────────────────────────────────
# Removes the IDS service, binary, web assets, desktop launcher, and
# auditd rules. The database at /opt/ids/data/ is preserved by default
# so you do not lose alert history. Pass --purge to remove everything.
#
# Run as:  sudo bash uninstall.sh
#          sudo bash uninstall.sh --purge   (removes database too)
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BOLD='\033[1m'; NC='\033[0m'

ok()   { echo -e "${GREEN}[OK]${NC}    $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC}  $*"; }
info() { echo -e "        $*"; }

PURGE=false
if [[ "${1:-}" == "--purge" ]]; then
    PURGE=true
fi

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[ERROR]${NC} Run as root: sudo bash uninstall.sh"
    exit 1
fi

echo -e "\n${BOLD}── Stopping and disabling service ──${NC}"
if systemctl is-active --quiet ids-agent 2>/dev/null; then
    systemctl stop ids-agent
    ok "Service stopped (iptables NFLOG rules removed)"
else
    warn "Service was not running"
fi

if systemctl is-enabled --quiet ids-agent 2>/dev/null; then
    systemctl disable ids-agent
    ok "Service disabled"
fi

echo -e "\n${BOLD}── Removing systemd unit ──${NC}"
rm -f /etc/systemd/system/ids-agent.service
systemctl daemon-reload
ok "Unit file removed"

echo -e "\n${BOLD}── Removing auditd rules ──${NC}"
if [[ -f /etc/audit/rules.d/ids.rules ]]; then
    rm -f /etc/audit/rules.d/ids.rules
    if command -v augenrules &>/dev/null; then
        augenrules --load 2>/dev/null || true
        systemctl restart auditd 2>/dev/null || true
    fi
    ok "Auditd rules removed"
else
    warn "No auditd rules file found at /etc/audit/rules.d/ids.rules"
fi

echo -e "\n${BOLD}── Removing desktop launcher ──${NC}"
rm -f /usr/share/applications/ids-dashboard.desktop
update-desktop-database /usr/share/applications/ 2>/dev/null || true
ok "Desktop launcher removed"

echo -e "\n${BOLD}── Removing installation directory ──${NC}"
if [[ "$PURGE" == "true" ]]; then
    rm -rf /opt/ids
    ok "Removed /opt/ids/ (including database — all alert history deleted)"
else
    # Keep data/ so the user does not lose their alert history
    rm -f  /opt/ids/ids-agent
    rm -rf /opt/ids/web
    rm -rf /opt/ids/configs
    rm -rf /opt/ids/scripts
    ok "Removed binary, web assets, and configs"
    warn "Database preserved at /opt/ids/data/ids.db"
    info "To delete it too: sudo rm -rf /opt/ids"
fi

echo ""
echo -e "${GREEN}${BOLD}Log-IDS has been uninstalled.${NC}"
