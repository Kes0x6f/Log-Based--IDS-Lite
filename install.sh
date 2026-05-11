#!/usr/bin/env bash
# install.sh — Log-IDS installation script
# ─────────────────────────────────────────────────────────────────────────────
# Installs the IDS as a systemd service that starts automatically on boot.
# After installation, open http://127.0.0.1:8888 in a browser to view the
# dashboard, or click "IDS Dashboard" in your application menu.
#
# Run as:  sudo bash install.sh
#
# What this script does:
#   1. Checks prerequisites (OS, root, Go, required tools)
#   2. Builds the ids-agent binary
#   3. Creates /opt/ids/ with the correct directory structure
#   4. Copies the binary and web assets
#   5. Installs auditd detection rules
#   6. Installs and enables the systemd service
#   7. Installs the desktop application launcher
#   8. Starts the service immediately
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

# ── Colour helpers ────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${BLUE}[INFO]${NC}  $*"; }
ok()      { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }
section() { echo -e "\n${BOLD}── $* ──${NC}"; }

# ── Constants ─────────────────────────────────────────────────────────────────
INSTALL_DIR="/opt/ids"
SERVICE_NAME="ids-agent"
SERVICE_FILE="configs/systemd/ids-agent.service"
AUDITD_RULES="configs/auditd/ids.rules"
DESKTOP_FILE="configs/desktop/ids-dashboard.desktop"
DESKTOP_DEST="/usr/share/applications/ids-dashboard.desktop"

# ─────────────────────────────────────────────────────────────────────────────
# 1. Pre-flight checks
# ─────────────────────────────────────────────────────────────────────────────
section "Pre-flight checks"

# Must run as root
if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root: sudo bash install.sh"
    exit 1
fi
ok "Running as root"

# Must be a Linux system
if [[ "$(uname -s)" != "Linux" ]]; then
    error "Log-IDS requires Linux. Detected: $(uname -s)"
    exit 1
fi
ok "Linux detected: $(uname -r)"

# Must be run from the project root (go.mod must exist here)
if [[ ! -f "go.mod" ]]; then
    error "Run this script from the project root directory (where go.mod is)."
    error "Example: cd ~/Log-Based--IDS && sudo bash install.sh"
    exit 1
fi
ok "Project root confirmed"

# Go must be installed
if ! command -v go &>/dev/null; then
    error "Go is not installed."
    error "Install it: sudo apt install golang-go"
    exit 1
fi
GO_VER=$(go version | awk '{print $3}')
ok "Go found: $GO_VER"

# systemd must be available
if ! command -v systemctl &>/dev/null; then
    error "systemctl not found — this installer requires systemd."
    exit 1
fi
ok "systemd found"

# Check optional but important tools
if ! command -v auditctl &>/dev/null; then
    warn "auditd not installed — audit-based detections will not fire."
    warn "Install: sudo apt install auditd"
    AUDITD_AVAILABLE=false
else
    ok "auditd found"
    AUDITD_AVAILABLE=true
fi

if ! command -v ufw &>/dev/null; then
    warn "UFW not found — firewall-based detections may be limited."
    warn "Install: sudo apt install ufw"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 2. Build the binary
# ─────────────────────────────────────────────────────────────────────────────
section "Building ids-agent"

info "Running: go mod tidy"
go mod tidy

info "Running: go build -o ids-agent ."
go build -o ids-agent .
ok "Binary built: $(du -sh ids-agent | cut -f1) — $(file ids-agent | cut -d: -f2 | xargs)"

# ─────────────────────────────────────────────────────────────────────────────
# 3. Create directory structure
# ─────────────────────────────────────────────────────────────────────────────
section "Creating $INSTALL_DIR"

mkdir -p "$INSTALL_DIR/web"
mkdir -p "$INSTALL_DIR/data"
mkdir -p "$INSTALL_DIR/configs/auditd"
mkdir -p "$INSTALL_DIR/scripts"
ok "Directory structure created"

# ─────────────────────────────────────────────────────────────────────────────
# 4. Copy files
# ─────────────────────────────────────────────────────────────────────────────
section "Copying files to $INSTALL_DIR"

# Binary
cp ids-agent "$INSTALL_DIR/ids-agent"
chmod 755    "$INSTALL_DIR/ids-agent"
ok "Binary → $INSTALL_DIR/ids-agent"

# Web assets — the server serves these from the web/ subdirectory
if [[ -d "web" ]]; then
    cp -r web/. "$INSTALL_DIR/web/"
    ok "Web assets → $INSTALL_DIR/web/"
else
    error "web/ directory not found in project root."
    error "Expected: web/index.html, web/alerts.html, etc."
    error "Make sure you are running install.sh from the project root."
    exit 1
fi

# Simulation scripts (optional but useful)
if [[ -d "scripts" ]]; then
    cp -r scripts/. "$INSTALL_DIR/scripts/"
    chmod +x "$INSTALL_DIR/scripts/simulate/"*.sh 2>/dev/null || true
    ok "Simulation scripts → $INSTALL_DIR/scripts/"
fi

# Auditd rules config
cp "$AUDITD_RULES" "$INSTALL_DIR/configs/auditd/ids.rules"
ok "Auditd rules → $INSTALL_DIR/configs/auditd/ids.rules"

# Set ownership: root owns everything
chown -R root:root "$INSTALL_DIR"
# The data directory needs write permission for the database
chmod 750 "$INSTALL_DIR/data"
ok "Permissions set"

# ─────────────────────────────────────────────────────────────────────────────
# 5. Install auditd rules
# ─────────────────────────────────────────────────────────────────────────────
section "Installing auditd rules"

if [[ "$AUDITD_AVAILABLE" == "true" ]]; then
    cp "$INSTALL_DIR/configs/auditd/ids.rules" /etc/audit/rules.d/ids.rules
    augenrules --load
    systemctl restart auditd
    ok "Auditd rules installed and loaded"
    info "Verify with: sudo auditctl -l | grep ids"
else
    warn "Skipping auditd rule installation (auditd not installed)."
    warn "Install auditd and run: sudo cp $INSTALL_DIR/configs/auditd/ids.rules /etc/audit/rules.d/"
    warn "Then: sudo augenrules --load && sudo systemctl restart auditd"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 6. Install systemd service
# ─────────────────────────────────────────────────────────────────────────────
section "Installing systemd service"

cp "$SERVICE_FILE" "/etc/systemd/system/$SERVICE_NAME.service"
ok "Unit file → /etc/systemd/system/$SERVICE_NAME.service"

systemctl daemon-reload
ok "systemd daemon reloaded"

systemctl enable "$SERVICE_NAME"
ok "Service enabled (will start on every boot)"

systemctl start "$SERVICE_NAME"
sleep 2  # give it a moment to initialise

if systemctl is-active --quiet "$SERVICE_NAME"; then
    ok "Service is running"
else
    error "Service failed to start. Check logs:"
    error "  sudo journalctl -u $SERVICE_NAME --no-pager -n 40"
    exit 1
fi

# ─────────────────────────────────────────────────────────────────────────────
# 7. Install desktop launcher
# ─────────────────────────────────────────────────────────────────────────────
section "Installing desktop launcher"

cp "$DESKTOP_FILE" "$DESKTOP_DEST"
chmod 644 "$DESKTOP_DEST"

# Refresh the desktop database so the launcher appears immediately
if command -v update-desktop-database &>/dev/null; then
    update-desktop-database /usr/share/applications/ 2>/dev/null || true
fi
ok "Desktop launcher installed → $DESKTOP_DEST"
info "Search for 'IDS Dashboard' in your application menu, or:"
info "  xdg-open http://127.0.0.1:8888"

# ─────────────────────────────────────────────────────────────────────────────
# Done
# ─────────────────────────────────────────────────────────────────────────────
section "Installation complete"

echo ""
echo -e "${GREEN}${BOLD}Log-IDS is installed and running.${NC}"
echo ""
echo "  Dashboard:     http://127.0.0.1:8888"
echo "  Service logs:  sudo journalctl -u ids-agent -f"
echo "  Service status:sudo systemctl status ids-agent"
echo "  Stop:          sudo systemctl stop ids-agent"
echo "  Uninstall:     sudo bash uninstall.sh"
echo ""

if [[ "$AUDITD_AVAILABLE" == "false" ]]; then
    echo -e "${YELLOW}  NOTE: Install auditd for full detection coverage:${NC}"
    echo "        sudo apt install auditd"
    echo "        sudo cp $INSTALL_DIR/configs/auditd/ids.rules /etc/audit/rules.d/"
    echo "        sudo augenrules --load && sudo systemctl restart auditd"
    echo ""
fi
