# Log-IDS — Full Documentation

← [Back to README](https://claude.ai/chat/README.md)

---

## Table of Contents

1. [How It Works](https://claude.ai/chat/8f6b3612-a682-491f-9822-24f2044a4a76#how-it-works)
2. [Warnings and Considerations](https://claude.ai/chat/8f6b3612-a682-491f-9822-24f2044a4a76#warnings-and-considerations)
3. [Installation](https://claude.ai/chat/8f6b3612-a682-491f-9822-24f2044a4a76#installation)
4. [Managing the Service](https://claude.ai/chat/8f6b3612-a682-491f-9822-24f2044a4a76#managing-the-service)
5. [Dashboard Pages](https://claude.ai/chat/8f6b3612-a682-491f-9822-24f2044a4a76#dashboard-pages)
6. [Detection Coverage](https://claude.ai/chat/8f6b3612-a682-491f-9822-24f2044a4a76#detection-coverage)
7. [Enabling Audit Rules](https://claude.ai/chat/8f6b3612-a682-491f-9822-24f2044a4a76#enabling-audit-rules)
8. [Simulating Attacks](https://claude.ai/chat/8f6b3612-a682-491f-9822-24f2044a4a76#simulating-attacks)
9. [Configuration](https://claude.ai/chat/8f6b3612-a682-491f-9822-24f2044a4a76#configuration)
10. [Uninstalling](https://claude.ai/chat/8f6b3612-a682-491f-9822-24f2044a4a76#uninstalling)
11. [Known Limitations](https://claude.ai/chat/8f6b3612-a682-491f-9822-24f2044a4a76#known-limitations)

---

## How It Works

```
Log files ──► File Collectors ──► Parser ──► Detection Engine ──► Alert Database
                                                                        │
NFLOG packets ──► NFLOG Collector ─────────────────────────────────────┘
                                                                        │
                                                         Web Dashboard ◄┘
                                                    http://127.0.0.1:8888
```

**Collectors** tail log files (`auth.log`, `kern.log`, `audit.log`, `access.log`) using fsnotify and capture kernel netfilter packets via NFLOG for firewall events. Each collector tags its output with a source label (`auth`, `kern`, `audit`, `ufw`, `apache2`, `nginx`).

**Parser** normalises raw log lines into `NormalizedEvent` structs — extracting timestamp, host, program, event type, source IP, username, command, port, and raw line. Audit log lines bypass the syslog header parser and are handled by a dedicated multi-record correlator that joins `SYSCALL` and `PATH` records by serial number.

**Detection Engine** loads all 41 rules into a three-level index (log source → program → event type). On each event it resolves the effective config (compiled defaults → global sensitivity overrides → per-rule DB overrides) and calls every matching rule's `Evaluate` method. Rules maintain private state (sliding windows, cooldown timers, cross-event correlation buffers) in a shared `DetectionContext`.

**Alert Manager** receives fired alerts, inserts them into SQLite, enforces the max-rows cap, and dispatches webhook notifications (with deduplication).

**API** serves the dashboard frontend from `web/` and exposes JSON endpoints for alerts, rule config, settings, and source stats. The SSE endpoint (`/stream/logs`) streams live log lines tagged with their source to browser clients.

---

## Warnings and Considerations

### Ethical and Legal Use

This software is developed as an academic project for educational purposes. It is intended to be installed and operated **only on systems you own or have explicit written permission to monitor**.

- Running an IDS on a system without authorisation may violate computer misuse laws in your jurisdiction regardless of intent.
- Do not install this on shared university infrastructure, cloud VMs you do not own, or any machine belonging to another person without permission.
- The simulation scripts generate real attack-pattern traffic. Run them only on your own lab machine or a VM you control.

### This Is a Learning Project, Not a Production Security Tool

Log-IDS demonstrates core IDS concepts — log collection, event normalisation, stateful rule evaluation, and alert management. It has real detection capability but is **not a replacement** for production tools such as Wazuh, Suricata, or Falco. Specific gaps:

- No HTTPS on the dashboard
- No user authentication
- SQLite is not suitable for high-throughput production environments
- Rule thresholds are tuned for demonstration and may produce false positives on busy servers

### False Positives

Some rules fire on legitimate administrator activity:

|Rule|Common legitimate trigger|
|---|---|
|SUDO Command Abuse|Developer running many sudo commands during system setup|
|Capability Change Detected|System daemons that drop privileges on startup (systemd, sshd)|
|Execution from Temp Directory|Package manager scripts that extract and run from /tmp|
|Web Path Enumeration|Monitoring tools or uptime checkers making frequent requests|
|OOM Kill Detected|Memory-constrained VM under normal load|

When a false positive fires, open the Rules Manager (`/rules.html`), find the rule, click **edit**, and raise its threshold or disable it. Changes apply within 10 seconds without a service restart.

### Running as Root

The IDS requires root for iptables NFLOG insertion, reading `/var/log/audit/audit.log`, and HTTP server binding. A critical bug in the process could affect the whole system. For a lab or demo environment this is acceptable. For any production-adjacent deployment, use Linux capabilities (`CAP_NET_ADMIN`, `CAP_DAC_READ_SEARCH`) instead of full root — this is outside the scope of this project.

### Data Privacy

The IDS stores raw log lines in its database. Those lines can contain usernames, IP addresses, sudo commands, file paths, and HTTP request URIs. Treat the database file (`/opt/ids/data/ids.db`) and the dashboard accordingly. Do not expose the dashboard on a shared or public network.

### Resource Usage

The IDS is lightweight under normal conditions — it only processes new log lines as they arrive. Set a retention policy in Settings (`/settings.html → Data Retention`) to keep the database size manageable over time.

---

## Installation

### Requirements

|Requirement|Notes|
|---|---|
|**OS**|Ubuntu 22.04 or 24.04 LTS, 64-bit|
|**Privileges**|Must run as root|
|**Go**|1.21 or later — `sudo apt install golang-go`|
|**auditd**|For audit detections — `sudo apt install auditd`|
|**UFW**|For firewall detections — `sudo apt install ufw`|
|**iptables**|Installed by default on Ubuntu|
|**Web server** _(optional)_|For web attack detections — `sudo apt install apache2`|

### Steps

**1. Install prerequisites**

```bash
sudo apt update && sudo apt install golang-go auditd ufw
# Optional: sudo apt install apache2
```

**2. Enable UFW**

```bash
sudo ufw allow ssh
sudo ufw enable
sudo ufw default deny incoming
sudo ufw status    # confirm: Status: active
```

**3. Clone the repository**

```bash
git clone https://github.com/Kes0x6f/Log-Based--IDS.git
cd Log-Based--IDS
```

**4. Run the installer**

```bash
sudo bash install.sh
```

The installer:

1. Checks prerequisites and warns about anything missing
2. Builds the `ids-agent` binary
3. Creates `/opt/ids/` and copies the binary, web assets, configs, and scripts
4. Installs auditd rules to `/etc/audit/rules.d/ids.rules` and reloads auditd
5. Installs and enables the systemd service (starts on every boot)
6. Starts the service immediately
7. Installs the **IDS Dashboard** desktop launcher

**5. Verify**

```bash
sudo systemctl status ids-agent
```

**6. Open the dashboard**

```bash
xdg-open http://127.0.0.1:8888
```

---

## Managing the Service

```bash
sudo systemctl status ids-agent          # is it running?
sudo systemctl stop   ids-agent          # stop cleanly (removes iptables rules)
sudo systemctl start  ids-agent          # start
sudo systemctl restart ids-agent         # restart after config change
sudo systemctl enable ids-agent          # start on boot
sudo systemctl disable ids-agent         # don't start on boot

sudo journalctl -u ids-agent -f          # live engine output
sudo journalctl -u ids-agent -n 50 --no-pager  # last 50 lines
```

### If the service was killed with kill -9

Stale iptables rules may remain. Remove them manually:

```bash
sudo iptables -D ufw-logging-deny -j NFLOG \
  --nflog-group 100 --nflog-prefix "IDS_BLOCK " --nflog-threshold 1 2>/dev/null || true

sudo iptables -D OUTPUT -p tcp -m multiport \
  --dports 1080,1337,3333,3334,4444,4445,6667,6697,9001,9030,9050,9051,14444,31337,45700 \
  -j NFLOG --nflog-group 100 --nflog-prefix "IDS_BLOCK " --nflog-threshold 1 2>/dev/null || true

sudo iptables -D OUTPUT -p udp -m multiport \
  --dports 1080,1337,3333,3334,4444,4445,6667,6697,9001,9030,9050,9051,14444,31337,45700 \
  -j NFLOG --nflog-group 100 --nflog-prefix "IDS_BLOCK " --nflog-threshold 1 2>/dev/null || true
```

### Accessing the dashboard from another machine

Use SSH port forwarding — do not expose port 8888 directly:

```bash
ssh -L 8888:127.0.0.1:8888 user@ids-machine-ip
# Then open http://127.0.0.1:8888 on your local machine
```

---

## Dashboard Pages

|Page|URL|Purpose|
|---|---|---|
|Dashboard|`/`|Summary cards, severity donut, alert timeline, top IPs, recent alerts, live log stream|
|Alerts|`/alerts.html`|Full alert table — filter by severity, category, IP, keyword; sort; CSV export|
|Alert Detail|`/alert-detail.html?id=...`|Per-alert raw log evidence, threat context, related alerts from same IP|
|IP Profile|`/ip-profile.html?ip=...`|Per-IP attack timeline, severity breakdown, targeted usernames, all alerts|
|Brute Force|`/brute-force.html`|Active brute-force campaigns grouped by attacker IP with sparklines|
|Attack Timeline|`/timeline.html`|Chronological or IP-grouped event view with 24h volume chart|
|Rules Manager|`/rules.html`|Fire counts, enable/disable rules, override thresholds and cooldowns, change history, dry-run simulator|
|Log Sources|`/sources.html`|Collector health, lines ingested per source, parser registry|
|Reports|`/reports.html`|Aggregated statistics with configurable time window, top IPs table, CSV export|
|Settings|`/settings.html`|Retention policy, max alert rows, webhook URL, detection sensitivity, clock format|
|Live Logs|`/live`|Real-time SSE stream of raw log lines, filterable by source and keyword|

---

## Detection Coverage

### SSH — source: auth, program: sshd

|Rule|Severity|Threshold|Window|Cooldown|
|---|---|---|---|---|
|SSH Brute Force|HIGH|5 failures|2 min|2 min|
|SSH Username Enumeration|HIGH|5 distinct usernames|3 min|3 min|
|SSH Suspicious Login|CRITICAL|3 prior failures|5 min|5 min|
|Invalid User Brute Force|MEDIUM|5 failures|2 min|2 min|
|SSH Rapid Reconnect Attack|HIGH|3 disconnects|2 min|2 min|
|SSH Root Targeting|HIGH|first occurrence|—|2 min|
|Distributed Brute Force|HIGH|3 distinct IPs|3 min|3 min|

### Sudo — source: auth, program: sudo

|Rule|Severity|Threshold|Window|Cooldown|
|---|---|---|---|---|
|SUDO Brute Force|HIGH|5 failures|2 min|2 min|
|SUDO Success After Failure|HIGH|3 prior failures|5 min|5 min|
|SUDO Sensitive Command Execution|varies|risk score ≥ 40|—|—|
|SUDO Command Abuse|HIGH|5 commands|2 min|2 min|
|SUDO Root Abuse|HIGH|5 escalations|2 min|2 min|
|SUDO Session Abuse|MEDIUM|4 sessions|2 min|2 min|

### SU — source: auth, program: su

|Rule|Severity|Threshold|Window|Cooldown|
|---|---|---|---|---|
|SU Brute Force|HIGH|5 failures|2 min|2 min|
|SU Success After Failure|CRITICAL|3 prior failures|5 min|5 min|

### Account Changes — source: auth

|Rule|Severity|Program|Trigger|
|---|---|---|---|
|New Account Created|HIGH|useradd|Any new local user|
|Group Membership Changed|CRITICAL / MEDIUM|usermod|CRITICAL for sudo/wheel/docker/shadow/adm; MEDIUM otherwise|
|Password Changed|CRITICAL / MEDIUM|passwd|CRITICAL for root/daemon/nobody; MEDIUM otherwise|

### UFW / Firewall — source: ufw (NFLOG)

|Rule|Severity|Threshold|Window|Cooldown|
|---|---|---|---|---|
|UFW Port Scan Detected|HIGH|6 distinct ports|1 min|5 min|
|UFW Repeated Block|MEDIUM|20 blocks|2 min|2 min|
|UFW Block Storm|CRITICAL|200 total blocks|1 min|5 min|
|UFW Sensitive Port Probe|varies by port|first occurrence|—|10 min|
|UFW Suspicious Outbound Block|CRITICAL|first occurrence|—|15 min|

Sensitive ports monitored: SSH (22), Telnet (23), RDP (3389), VNC (5900), MySQL (3306), PostgreSQL (5432), Redis (6379), MongoDB (27017), Elasticsearch (9200), Docker (2375/2376), Kubernetes (6443), etcd (2379), LDAP (389/636), SNMP (161).

Suspicious outbound ports: Metasploit (4444/4445), backdoor (1337/31337), IRC (6667/6697), Tor (9001/9030/9050/9051), mining pools (3333/3334/14444/45700), SOCKS (1080).

### Kernel — source: kern, program: kernel

|Rule|Severity|Threshold|Window|Cooldown|
|---|---|---|---|---|
|Kernel Module Load|CRITICAL|every occurrence|—|—|
|Sensitive Binary Segfault|HIGH|first per binary|—|10 min|
|OOM Kill Detected|HIGH (critical proc) / MEDIUM|1 (critical) / 3|5 min|10 min|
|Disk I/O Errors Detected|HIGH / MEDIUM|5 / 20|5 min|15 min|

Sensitive binaries for segfault: sshd, sudo, su, passwd, login, polkitd, dbus-daemon, systemd, cron.

### Auditd — source: audit, program: auditd

|Rule|Severity|Trigger|Requires auditd key|
|---|---|---|---|
|Sensitive File Read|HIGH|Untrusted process reads /etc/shadow, /etc/sudoers, authorized_keys|`read_sensitive`|
|Sensitive File Modified|CRITICAL|Write to /etc/passwd, /etc/shadow, /root/.ssh|`write_sensitive`|
|Cron Job Created or Modified|HIGH|Write to any cron directory or /etc/crontab|`cron_write`|
|Systemd Service Created or Modified|CRITICAL|Unit file written to system directories|`service_write`|
|Setuid Bit Set on Binary|CRITICAL|chmod sets setuid bit (mode & 04000)|`setuid_binary`|
|Ptrace Syscall Detected|CRITICAL|Any process calls ptrace|`ptrace`|
|Capability Change Detected|HIGH / CRITICAL|Process modifies capability set; CRITICAL for CAP_SETUID, CAP_SYS_ADMIN, etc.|`capset`|
|Execution from Temp Directory|CRITICAL (dropper) / HIGH|Binary executed from /tmp or /dev/shm; CRITICAL if a write preceded it within 10 min|`exec_tmp` + `tmp_write`|
|UFW Firewall Rule Changed|CRITICAL / HIGH|UFW config files modified; CRITICAL for user.rules/user6.rules|`ufw_change`|

### Web Attacks — source: web, program: httpd

|Rule|Severity|Threshold|Window|Cooldown|
|---|---|---|---|---|
|Web Scanner Detected|HIGH|first per UA signature|—|10 min|
|Web Path Probe|CRITICAL / HIGH|first per category|—|5 min|
|Web Path Enumeration|MEDIUM|15 × 404|1 min|5 min|
|Web Login Brute Force|HIGH|5 × 401/403|3 min|10 min|
|Unusual HTTP Method|HIGH / MEDIUM|first per method|—|15 min|
|High Request Rate|HIGH / MEDIUM|100 / 500 req|1 min|5 min|

---

## Enabling Audit Rules

The audit rules are installed automatically by `install.sh`. If you need to install or verify them manually:

### Verify

```bash
sudo auditctl -l | grep -E "key=(read_sensitive|write_sensitive|cron_write|service_write|setuid_binary|ptrace|capset|exec_tmp|tmp_write|ufw_change)"
```

Each active rule prints one line. Empty output means rules are not loaded.

### Manual install

```bash
sudo cp /opt/ids/configs/auditd/ids.rules /etc/audit/rules.d/ids.rules
sudo augenrules --load
sudo systemctl restart auditd
```

### Audit key reference

|Key|Detection|
|---|---|
|`read_sensitive`|Sensitive File Read|
|`write_sensitive`|Sensitive File Modified|
|`cron_write`|Cron Job Created or Modified|
|`service_write`|Systemd Service Created or Modified|
|`setuid_binary`|Setuid Bit Set on Binary|
|`ptrace`|Ptrace Syscall Detected|
|`capset`|Capability Change Detected|
|`exec_tmp`|Execution from Temp Directory|
|`tmp_write`|Write side of dropper correlation|
|`ufw_change`|UFW Firewall Rule Changed|

---

## Simulating Attacks

All scripts are in `/opt/ids/scripts/simulate/`. Run them on the IDS machine to verify detections are working.

### SSH brute force

```bash
# Triggers: SSH Brute Force, Root Targeting, Username Enumeration, Rapid Reconnect
bash /opt/ids/scripts/simulate/ssh_bruteforce.sh
```

### Sudo failures

```bash
# Triggers: SUDO Brute Force, Success After Failure, Command Abuse, Sensitive Command
# Run as your normal non-root user — do NOT run as root
bash /opt/ids/scripts/simulate/sudo_fail.sh
```

### SU failures

```bash
# Triggers: SU Brute Force, SU Success After Failure
bash /opt/ids/scripts/simulate/su_fail.sh
```

### Web attacks

```bash
# Requires: Apache2 or Nginx running, curl installed
# Triggers: Web Scanner, Path Probe, 404 Enumeration, Auth Brute Force, Unusual Methods, High Rate
bash /opt/ids/scripts/simulate/web_scanner.sh
```

### Audit — setuid backdoor

```bash
# Requires: auditd with ids.rules loaded, must run as root
sudo bash /opt/ids/scripts/simulate/audit_setuid.sh
```

### Audit — temp directory dropper

```bash
# Requires: auditd with ids.rules loaded
bash /opt/ids/scripts/simulate/audit_tmp_exec.sh
```

### UFW port scan

```bash
# Requires: UFW enabled, IDS running
# Use the machine's LAN IP — 127.0.0.1 bypasses UFW
bash /opt/ids/scripts/simulate/ufw_portscan.sh $(hostname -I | awk '{print $1}')
```

---

## Configuration

Configuration is done via environment variables with safe built-in defaults. No config file is needed for normal use.

### Changing a setting

```bash
sudo systemctl edit ids-agent
```

Add under `[Service]`:

```ini
[Service]
Environment="IDS_ADDR=127.0.0.1:8888"
Environment="IDS_DB=/opt/ids/data/ids.db"
```

Then:

```bash
sudo systemctl daemon-reload && sudo systemctl restart ids-agent
```

### Environment variables

|Variable|Default|Description|
|---|---|---|
|`IDS_ADDR`|`127.0.0.1:8888`|HTTP listen address. Do not expose to the network without authentication.|
|`IDS_DB`|`data/ids.db`|SQLite path. Relative paths resolve from `/opt/ids/`.|
|`IDS_LOG_AUTH`|`/var/log/auth.log`|Auth log|
|`IDS_LOG_KERN`|`/var/log/kern.log`|Kernel log|
|`IDS_LOG_AUDIT`|`/var/log/audit/audit.log`|Auditd log|
|`IDS_LOG_APACHE`|`/var/log/apache2/access.log`|Apache2 access log (optional)|
|`IDS_LOG_NGINX`|`/var/log/nginx/access.log`|Nginx access log (optional)|

### Dashboard settings (stored in database)

Open `http://127.0.0.1:8888/settings.html` to configure:

- **Data Retention** — max alert rows, retention period (days), manual prune
- **Detection Sensitivity** — global threshold multiplier, window override, cooldown override
- **Notifications** — webhook URL, minimum severity, deduplication window
- **Dashboard** — refresh rates, rows per page, timeline bucket size, clock format

---

## Uninstalling

```bash
# Remove service, binary, web assets, desktop launcher — preserves database
sudo bash uninstall.sh

# Remove everything including alert history
sudo bash uninstall.sh --purge
```

---

## Known Limitations

**Requires Linux with NFLOG support.** The firewall collector uses the kernel netfilter NFLOG facility. A no-op stub is included so the code compiles on non-Linux systems, but firewall rules produce no alerts.

**Audit detections require auditd with the IDS rules loaded.** Without `/etc/audit/rules.d/ids.rules`, no audit alerts fire. The installer handles this automatically.

**Web detections require a running web server.** The IDS watches Apache2 and Nginx access logs. If neither is installed, those alerts never fire. The service logs a warning at startup and continues.

**The live log stream is not persisted.** The Live Logs page (`/live`) shows a real-time stream only. Navigating away clears it. All alerts are stored in the database.

**The dashboard has no authentication.** Bound to `127.0.0.1` by default. Do not change `IDS_ADDR` to a non-loopback address without adding authentication — the dashboard exposes raw log lines and destructive endpoints.

**Syslog timestamps omit the year.** The parser injects the current year. Log entries spanning a year boundary may have incorrect timestamps.

**Always stop with systemctl.** `kill -9` skips the NFLOG iptables cleanup. See [Managing the Service](https://claude.ai/chat/8f6b3612-a682-491f-9822-24f2044a4a76#managing-the-service) for manual cleanup.

**Rule config changes take up to 10 seconds.** The engine caches rule overrides with a 10-second TTL. Global sensitivity changes apply immediately.