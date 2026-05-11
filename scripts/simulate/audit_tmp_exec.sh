#!/usr/bin/env bash
# simulate/audit_tmp_exec.sh
# ─────────────────────────────────────────────────────────────────────────────
# Triggers:
#   Execution from Temp Directory  (CRITICAL) — write then execute in /tmp
#                                  (HIGH)     — execute from /tmp without write
#
# Requirements:
#   1. auditd must be running:
#        sudo systemctl status auditd
#   2. The IDS auditd rules must be loaded (both exec_tmp AND tmp_write keys):
#        sudo auditctl -l | grep -E "exec_tmp|tmp_write"
#      If not loaded:
#        sudo cp configs/auditd/ids.rules /etc/audit/rules.d/ids.rules
#        sudo augenrules --load && sudo systemctl restart auditd
#   3. Run as your normal user (no root needed for /tmp execution)
#
# What it does:
#   Phase 1: Simulates a dropper — writes a script to /tmp then executes it.
#            The IDS correlates the write and exec events and raises CRITICAL.
#   Phase 2: Simulates execution-only from /tmp (no preceding write by this
#            process). Raises HIGH.
#
# Run as:  bash audit_tmp_exec.sh
# ─────────────────────────────────────────────────────────────────────────────

echo "[*] Auditd temp-execution simulation starting"
echo "[*] Watch the dashboard at http://127.0.0.1:8888"
echo ""

DROPPER="/tmp/ids_dropper_$(date +%s).sh"
EXEC_ONLY="/tmp/ids_execonly_$(date +%s).sh"

# ── Phase 1: Write → execute (dropper pattern) ───────────────────────────────
echo "[1/2] Simulating dropper: writing then executing $DROPPER ..."

# Write step — auditd records this with key=tmp_write
cat > "$DROPPER" << 'EOF'
#!/bin/bash
echo "ids dropper payload executed"
EOF
chmod +x "$DROPPER"

# Small delay so auditd can record the write before the exec
sleep 0.5

# Execute step — auditd records this with key=exec_tmp
# The IDS correlates the write+exec within the 10-minute window → CRITICAL
bash "$DROPPER"

echo "    Done. Expect: Execution from Temp Directory (CRITICAL — dropper pattern)"
sleep 1
rm -f "$DROPPER"

# ── Phase 2: Execute only (no preceding write) ────────────────────────────────
echo "[2/2] Simulating execution-only from /tmp ..."

# Pre-create the script WITHOUT going through the write-detection path
# by copying it instead (copy is not a monitored open+write syscall here)
cp /bin/echo "$EXEC_ONLY"
chmod +x "$EXEC_ONLY"

sleep 0.5

# Execute from /tmp — auditd records key=exec_tmp but no matching tmp_write
"$EXEC_ONLY" "ids exec-only test"

echo "    Done. Expect: Execution from Temp Directory (HIGH — exec only)"
sleep 1
rm -f "$EXEC_ONLY"

echo ""
echo "[*] Simulation complete. Check http://127.0.0.1:8888/alerts.html"
echo "[*] Note: CRITICAL alert requires both write and exec to occur within"
echo "    the 10-minute correlation window."
