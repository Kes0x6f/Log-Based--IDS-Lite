#!/usr/bin/env bash
# simulate/su_fail.sh
# ─────────────────────────────────────────────────────────────────────────────
# Triggers:
#   SU Brute Force          (HIGH)     — 5+ failed su attempts
#   SU Success After Failure (CRITICAL) — su succeeds after failures
#
# Requirements:
#   - Run as a non-root user
#   - 'su' must be installed (default on Ubuntu)
#   - Phase 2 (success after failure) requires you to know the root password.
#     If root has no password set (locked), skip Phase 2 — Phase 1 is enough
#     to trigger SU Brute Force on its own.
#
# Note on how su failures are logged:
#   'su' logs failures through PAM to /var/log/auth.log. Piping a wrong
#   password to su via stdin produces a genuine PAM failure entry.
#   The script uses 'expect' if available for cleaner output, otherwise
#   falls back to a plain stdin pipe.
#
# Run as:  bash su_fail.sh
# ─────────────────────────────────────────────────────────────────────────────

echo "[*] SU simulation starting"
echo "[*] Watch the dashboard at http://127.0.0.1:8888"
echo ""

WRONG_PASS="wrongpassword456"

# ── Phase 1: SU brute force ───────────────────────────────────────────────────
echo "[1/2] Sending 7 wrong su passwords targeting root..."
for i in $(seq 1 7); do
    # su reads from the controlling terminal, not stdin, in strict mode.
    # Using 'su -c exit root' with a here-string works on most Ubuntu setups.
    echo "$WRONG_PASS" | su -c "exit" root 2>/dev/null
    sleep 0.5
done
echo "    Done. Expect: SU Brute Force"
sleep 3

# ── Phase 2: SU success after failure (optional) ─────────────────────────────
echo "[2/2] Attempting su with the correct root password..."
echo "      Skip this phase (Ctrl+C) if root login is disabled."
echo "      Enter the root password when prompted:"
su -c "echo 'su succeeded'" root
echo "    Done. Expect: SU Success After Failure (CRITICAL)"

echo ""
echo "[*] Simulation complete. Check http://127.0.0.1:8888/alerts.html"
