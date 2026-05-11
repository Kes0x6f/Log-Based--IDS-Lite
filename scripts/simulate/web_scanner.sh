#!/usr/bin/env bash
# simulate/web_scanner.sh
# ─────────────────────────────────────────────────────────────────────────────
# Triggers:
#   Web Scanner Detected      (HIGH)   — known scanner user-agent
#   Web Path Enumeration      (MEDIUM) — 15+ 404 responses in 1 minute
#   Web Path Probe            (HIGH/CRITICAL) — attack patterns in URI
#   Web Login Brute Force     (HIGH)   — 5+ 401/403 responses
#   Unusual HTTP Method       (MEDIUM) — TRACE, OPTIONS, PUT etc.
#   High Request Rate         (MEDIUM) — 100+ requests/min
#
# Requirements:
#   - curl must be installed:  sudo apt install curl
#   - A web server must be running on the target port. By default this script
#     targets port 80 (Apache/Nginx). Change TARGET_URL below if your web
#     server runs on a different port (e.g. http://127.0.0.1:3000).
#   - If no web server is running, the IDS will still log connection attempts
#     but HTTP status codes won't be available for classification. Install one:
#       sudo apt install apache2   (then visit http://127.0.0.1 to confirm)
#
# Run as:  bash web_scanner.sh
# ─────────────────────────────────────────────────────────────────────────────

TARGET_URL="http://127.0.0.1"
SILENT="-s -o /dev/null"

echo "[*] Web attack simulation starting against $TARGET_URL"
echo "[*] Watch the dashboard at http://127.0.0.1:8888"
echo "[*] Tip: tail -f /var/log/apache2/access.log to watch raw requests"
echo ""

# ── Phase 1: Scanner user-agent ───────────────────────────────────────────────
echo "[1/6] Sending requests with known scanner user-agents..."
SCANNER_UAS=(
    "Nikto/2.1.6"
    "sqlmap/1.7.8"
    "Gobuster/3.6"
    "nuclei/2.9.1"
    "python-requests/2.31.0"
)
for ua in "${SCANNER_UAS[@]}"; do
    curl $SILENT -A "$ua" "$TARGET_URL/" &
    sleep 0.2
done
wait
echo "    Done. Expect: Web Scanner Detected"
sleep 2

# ── Phase 2: 404 path enumeration ────────────────────────────────────────────
echo "[2/6] Sending 20 requests for non-existent paths..."
PATHS=(
    "/admin" "/wp-admin" "/phpmyadmin" "/.env" "/config.php"
    "/backup.zip" "/.git/config" "/wp-config.php" "/robots.txt"
    "/api/v1/users" "/shell.php" "/upload.php" "/test.php"
    "/admin/login" "/.htpasswd" "/server-status" "/xmlrpc.php"
    "/old/index.php" "/setup.php" "/install.php"
)
for path in "${PATHS[@]}"; do
    curl $SILENT "$TARGET_URL$path" &
    sleep 0.1
done
wait
echo "    Done. Expect: Web Path Enumeration"
sleep 2

# ── Phase 3: Attack patterns in URI ──────────────────────────────────────────
echo "[3/6] Sending requests with attack patterns in URI..."

# Directory traversal
curl $SILENT "$TARGET_URL/../../../etc/passwd" &
curl $SILENT "$TARGET_URL/%2e%2e%2fetc%2fshadow" &

# SQL injection
curl $SILENT "$TARGET_URL/search?q=%27+OR+1%3D1--" &
curl $SILENT "$TARGET_URL/users?id=1+UNION+SELECT+1,2,3--" &

# XSS
curl $SILENT "$TARGET_URL/search?q=<script>alert(1)</script>" &

# RCE / shell
curl $SILENT "$TARGET_URL/exec?cmd=;cat+/etc/passwd" &

wait
echo "    Done. Expect: Web Path Probe (CRITICAL/HIGH)"
sleep 2

# ── Phase 4: Auth brute force (401/403 responses) ────────────────────────────
echo "[4/6] Sending 8 failed auth requests..."
for i in $(seq 1 8); do
    curl $SILENT -u "admin:wrongpassword$i" "$TARGET_URL/" &
    sleep 0.3
done
wait
echo "    Done. Expect: Web Login Brute Force"
sleep 2

# ── Phase 5: Unusual HTTP methods ────────────────────────────────────────────
echo "[5/6] Sending unusual HTTP methods..."
for method in TRACE OPTIONS PUT DELETE PATCH CONNECT; do
    curl $SILENT -X "$method" "$TARGET_URL/" &
    sleep 0.2
done
wait
echo "    Done. Expect: Unusual HTTP Method"
sleep 2

# ── Phase 6: High request rate ────────────────────────────────────────────────
echo "[6/6] Sending 120 rapid requests (high request rate)..."
for i in $(seq 1 120); do
    curl $SILENT "$TARGET_URL/" &
    # Run 10 in parallel, then wait
    if (( i % 10 == 0 )); then wait; fi
done
wait
echo "    Done. Expect: High Request Rate"

echo ""
echo "[*] Simulation complete. Check http://127.0.0.1:8888/alerts.html"
