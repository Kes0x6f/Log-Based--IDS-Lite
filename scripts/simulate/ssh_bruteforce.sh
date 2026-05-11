#!/usr/bin/env bash
# simulate/ssh_bruteforce.sh
# ─────────────────────────────────────────────────────────────────────────────
# Triggers:
#   SSH Brute Force            (HIGH)   — 5+ failed attempts from one IP
#   Invalid User Brute Force   (MEDIUM) — attempts against non-existent users
#   SSH Username Enumeration   (HIGH)   — many distinct usernames tried
#   SSH Root Targeting         (HIGH)   — attempts against root
#
# Requirements: openssh-client installed (ssh command available)
# Run as:       bash ssh_bruteforce.sh
# ─────────────────────────────────────────────────────────────────────────────

TARGET="127.0.0.1"
PORT=22
TIMEOUT=3

echo "[*] SSH Brute Force simulation starting against $TARGET:$PORT"
echo "[*] Watch the dashboard at http://127.0.0.1:8888"
echo ""

# ── Phase 1: Root targeting + brute force ────────────────────────────────────
echo "[1/3] Attempting root login (10 tries)..."
for i in $(seq 1 10); do
    ssh -o StrictHostKeyChecking=no \
        -o ConnectTimeout=$TIMEOUT \
        -o PasswordAuthentication=yes \
        -o BatchMode=no \
        -p $PORT \
        root@$TARGET \
        exit 2>/dev/null &
    sleep 0.3
done
wait
echo "    Done. Expect: SSH Root Targeting, SSH Brute Force"
sleep 2

# ── Phase 2: Invalid / non-existent usernames ─────────────────────────────────
echo "[2/3] Attempting logins with non-existent users (8 tries)..."
FAKE_USERS=("ghost" "hacker" "admin123" "oracle" "deploy" "ubuntu" "ec2-user" "pi")
for user in "${FAKE_USERS[@]}"; do
    ssh -o StrictHostKeyChecking=no \
        -o ConnectTimeout=$TIMEOUT \
        -o PasswordAuthentication=yes \
        -o BatchMode=no \
        -p $PORT \
        "${user}@${TARGET}" \
        exit 2>/dev/null &
    sleep 0.3
done
wait
echo "    Done. Expect: Invalid User Brute Force, SSH Username Enumeration"
sleep 2

# ── Phase 3: Rapid reconnect ──────────────────────────────────────────────────
echo "[3/3] Rapid reconnect pattern (6 quick connects/disconnects)..."
for i in $(seq 1 6); do
    ssh -o StrictHostKeyChecking=no \
        -o ConnectTimeout=1 \
        -o PasswordAuthentication=no \
        -o BatchMode=yes \
        -p $PORT \
        testuser@$TARGET \
        exit 2>/dev/null
    sleep 0.2
done
echo "    Done. Expect: SSH Rapid Reconnect Attack"

echo ""
echo "[*] Simulation complete. Check http://127.0.0.1:8888/alerts.html"
