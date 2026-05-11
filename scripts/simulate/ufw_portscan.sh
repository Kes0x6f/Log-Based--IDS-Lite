#!/usr/bin/env bash
# simulate/ufw_portscan.sh
# ─────────────────────────────────────────────────────────────────────────────
# Triggers:
#   UFW Port Scan Detected   (HIGH)     — 6+ distinct ports hit in 1 minute
#   UFW Repeated Block       (MEDIUM)   — 20+ blocks from same IP in 2 minutes
#   UFW Sensitive Port Probe (varies)   — probing SSH, RDP, databases, Docker
#
# Requirements:
#   1. UFW must be enabled and blocking inbound connections:
#        sudo ufw status
#      If not enabled:
#        sudo ufw enable
#        sudo ufw default deny incoming
#   2. The IDS NFLOG collector must be running (it requires root and inserts
#      its own iptables rules on startup). This is done automatically when
#      you run the IDS binary as root.
#   3. nmap must be installed for the cleanest simulation:
#        sudo apt install nmap
#      If nmap is not available, the script falls back to nc (netcat).
#   4. Run from a DIFFERENT machine on the same network, OR from the same
#      machine using the external/LAN IP (not 127.0.0.1) so UFW actually
#      processes and blocks the packets.
#
# Usage:
#   # From another machine targeting the IDS host:
#   bash ufw_portscan.sh 192.168.1.100
#
#   # From the same machine using its LAN IP:
#   bash ufw_portscan.sh $(hostname -I | awk '{print $1}')
#
# ─────────────────────────────────────────────────────────────────────────────

TARGET="${1:-}"

if [[ -z "$TARGET" ]]; then
    echo "Usage: bash ufw_portscan.sh <target-ip>"
    echo ""
    echo "  <target-ip>  The IP address of the machine running the IDS."
    echo "               Use the LAN IP (e.g. 192.168.1.100), not 127.0.0.1."
    echo "               To find your LAN IP: hostname -I | awk '{print \$1}'"
    exit 1
fi

echo "[*] UFW port scan simulation targeting $TARGET"
echo "[*] Watch the dashboard at http://127.0.0.1:8888 on the IDS machine"
echo ""

# ── Phase 1: Broad port scan (triggers UFW Port Scan Detected) ───────────────
echo "[1/3] Scanning 12 distinct ports..."

if command -v nmap &>/dev/null; then
    echo "    Using nmap..."
    # -Pn: skip host discovery (don't send ICMP ping first)
    # --max-retries 0: don't retry — we want fast blocked packets, not answers
    # -T4: aggressive timing
    nmap -Pn --max-retries 0 -T4 \
        -p 21,22,23,25,80,443,3306,3389,5432,6379,8080,8443 \
        "$TARGET" 2>/dev/null
else
    echo "    nmap not found — using nc fallback..."
    PORTS=(21 22 23 25 80 443 3306 3389 5432 6379 8080 8443)
    for port in "${PORTS[@]}"; do
        nc -z -w 1 "$TARGET" "$port" 2>/dev/null &
        sleep 0.1
    done
    wait
fi
echo "    Done. Expect: UFW Port Scan Detected"
sleep 3

# ── Phase 2: Sensitive port probes ────────────────────────────────────────────
echo "[2/3] Probing sensitive ports (SSH, Telnet, MySQL, Redis, Docker)..."
SENSITIVE_PORTS=(22 23 3306 6379 2375 9200 5432 27017)

for port in "${SENSITIVE_PORTS[@]}"; do
    nc -z -w 1 "$TARGET" "$port" 2>/dev/null &
    sleep 0.2
done
wait
echo "    Done. Expect: UFW Sensitive Port Probe (multiple)"
sleep 3

# ── Phase 3: Repeated blocks from one IP ─────────────────────────────────────
echo "[3/3] Sending 25 rapid connection attempts to one port..."
for i in $(seq 1 25); do
    nc -z -w 1 "$TARGET" 9999 2>/dev/null &
    sleep 0.08
done
wait
echo "    Done. Expect: UFW Repeated Block"

echo ""
echo "[*] Simulation complete."
echo "[*] Check http://127.0.0.1:8888/alerts.html on the IDS machine."
echo ""
echo "    Tip: If no UFW alerts appeared, verify with:"
echo "      sudo ufw status          — confirm UFW is active"
echo "      sudo iptables -L -n | grep NFLOG  — confirm IDS NFLOG rules are loaded"
