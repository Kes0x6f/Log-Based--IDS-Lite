#!/usr/bin/env bash
# simulate/sudo_fail.sh
# ─────────────────────────────────────────────────────────────────────────────
# Triggers:
#   SUDO Brute Force            (HIGH)   — 5+ wrong sudo passwords
#   SUDO Success After Failure  (HIGH)   — sudo succeeds after failures
#   SUDO Command Abuse          (HIGH)   — 5+ sudo commands in 2 minutes
#   SUDO Sensitive Command      (varies) — dangerous commands via sudo
#
# Requirements:
#   - Run as a non-root user that has sudo access (e.g. your normal login user)
#   - sudo must be installed (it is by default on Ubuntu)
#
# How it works:
#   Phase 1 uses 'sudo -k' to clear the cached credential then attempts sudo
#   with a wrong password fed via stdin. This produces real PAM failure entries
#   in /var/log/auth.log exactly as a real attacker would.
#
# Run as:  bash sudo_fail.sh
# ─────────────────────────────────────────────────────────────────────────────

echo "[*] SUDO simulation starting"
echo "[*] Watch the dashboard at http://127.0.0.1:8888"
echo ""

WRONG_PASS="wrongpassword123"

# ── Phase 1: SUDO brute force (wrong password, repeated) ─────────────────────
echo "[1/3] Sending 7 wrong sudo passwords..."
for i in $(seq 1 7); do
    # -k clears the cached credential so every attempt prompts for a password.
    # We pipe a wrong password to non-interactive stdin.
    echo "$WRONG_PASS" | sudo -k -S id >/dev/null 2>&1
    sleep 0.5
done
echo "    Done. Expect: SUDO Brute Force"
sleep 3

# ── Phase 2: SUDO success after failure ──────────────────────────────────────
# Now run a real sudo command (with correct auth via -k and your actual
# password) immediately after the failures above are still in the window.
echo "[2/3] Running a successful sudo command after failures..."
echo "      You will be prompted for your REAL sudo password."
sudo -k id
echo "    Done. Expect: SUDO Success After Failure"
sleep 2

# ── Phase 3: Rapid sudo command execution (command abuse) ────────────────────
echo "[3/3] Running 6 sudo commands quickly..."
for cmd in "id" "whoami" "ls /root" "cat /etc/hostname" "uptime" "date"; do
    sudo $cmd >/dev/null 2>&1
    sleep 0.3
done
echo "    Done. Expect: SUDO Command Abuse"

# ── Phase 4: Sensitive sudo command ──────────────────────────────────────────
echo "[4/3] Running a sensitive sudo command (passwd)..."
echo "n" | sudo passwd root 2>/dev/null || true
echo "    Done. Expect: SUDO Sensitive Command Execution"

echo ""
echo "[*] Simulation complete. Check http://127.0.0.1:8888/alerts.html"
