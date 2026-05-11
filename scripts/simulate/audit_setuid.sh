#!/usr/bin/env bash
# simulate/audit_setuid.sh
# ─────────────────────────────────────────────────────────────────────────────
# Triggers:
#   Setuid Bit Set on Binary  (CRITICAL) — chmod sets setuid on a binary
#
# Requirements:
#   1. Run as ROOT (sudo bash audit_setuid.sh) — setuid requires root
#   2. auditd must be running:
#        sudo systemctl status auditd
#   3. The IDS auditd rules must be loaded:
#        sudo auditctl -l | grep setuid_binary
#      If not loaded:
#        sudo cp configs/auditd/ids.rules /etc/audit/rules.d/ids.rules
#        sudo augenrules --load && sudo systemctl restart auditd
#
# What it does:
#   Creates a harmless test binary in /tmp, sets the setuid bit on it
#   (which auditd catches), then immediately cleans up.
#   The binary never actually runs with elevated privileges — it is just
#   a chmod call to demonstrate detection.
#
# Run as:  sudo bash audit_setuid.sh
# ─────────────────────────────────────────────────────────────────────────────

if [[ $EUID -ne 0 ]]; then
    echo "[!] This script must be run as root: sudo bash audit_setuid.sh"
    exit 1
fi

echo "[*] Auditd setuid simulation starting"
echo "[*] Watch the dashboard at http://127.0.0.1:8888"
echo ""

TEST_BIN="/tmp/ids_test_setuid_$(date +%s)"

# Create a harmless test binary (just an echo script)
echo "#!/bin/bash" > "$TEST_BIN"
echo "echo 'ids test binary'" >> "$TEST_BIN"
chmod +x "$TEST_BIN"

echo "[1/1] Setting setuid bit on $TEST_BIN ..."
# This is the call auditd will catch with key=setuid_binary
chmod u+s "$TEST_BIN"
echo "    Done. Expect: Setuid Bit Set on Binary (CRITICAL)"

# Wait a moment for auditd to flush the record
sleep 1

# Clean up immediately — the detection already fired
rm -f "$TEST_BIN"
echo "    Cleaned up test binary."

echo ""
echo "[*] Simulation complete. Check http://127.0.0.1:8888/alerts.html"
echo "[*] Note: alert may appear within 1-2 seconds as auditd flushes records."
