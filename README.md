
<div align="center">

# Log-Based--IDS-Lite

**A host-based intrusion detection system for Linux**

![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go&logoColor=white) ![Platform](https://img.shields.io/badge/Platform-Linux-FCC624?style=flat&logo=linux&logoColor=black) ![Service](https://img.shields.io/badge/Service-systemd-black?style=flat&logo=systemd) ![Database](https://img.shields.io/badge/Database-SQLite-003B57?style=flat&logo=sqlite&logoColor=white) ![License](https://img.shields.io/badge/License-MIT-22c55e?style=flat)

Monitors your system logs and network traffic in real time, detects intrusion patterns, and surfaces alerts through a local web dashboard.

</div>

---
## Screenshots

### Dashboard Overview

<a href="assets/dashboard1.jpg">
  <img src="assets/dashboard1.jpg" alt="Dashboard overview" width="100%">
</a>

<p align="center">
  <em>Main dashboard showing alert statistics, severity distribution, and recent activity.</em>
</p>

### Dashboard Pages

<table>
  <tr>
    <td width="50%">
      <a href="assets/dashboard2.jpg">
        <img src="assets/dashboard2.jpg" alt="Dashboard analytics" width="100%">
      </a>
      <p align="center"><strong>Dashboard Analytics</strong></p>
    </td>
    <td width="50%">
      <a href="assets/alerts.jpg">
        <img src="assets/alerts.jpg" alt="Alerts page" width="100%">
      </a>
      <p align="center"><strong>Alerts</strong></p>
    </td>
  </tr>
  <tr>
    <td width="50%">
      <a href="assets/live.jpg">
        <img src="assets/live.jpg" alt="Live logs page" width="100%">
      </a>
      <p align="center"><strong>Live Logs</strong></p>
    </td>
    <td width="50%">
      <a href="assets/ip-profile.jpg">
        <img src="assets/ip-profile.jpg" alt="IP profile page" width="100%">
      </a>
      <p align="center"><strong>IP Profile</strong></p>
    </td>
  </tr>
  <tr>
    <td width="50%">
      <a href="assets/alert-detail.jpg">
        <img src="assets/alert-detail.jpg" alt="Alert detail page" width="100%">
      </a>
      <p align="center"><strong>Alert Detail</strong></p>
    </td>
    <td width="50%">
      <a href="assets/brute-force.jpg">
        <img src="assets/brute-force.jpg" alt="Brute force detection page" width="100%">
      </a>
      <p align="center"><strong>Brute Force Detection</strong></p>
    </td>
  </tr>
  <tr>
    <td width="50%">
      <a href="assets/timeline.jpg">
        <img src="assets/timeline.jpg" alt="Attack timeline page" width="100%">
      </a>
      <p align="center"><strong>Attack Timeline</strong></p>
    </td>
    <td width="50%">
      <a href="assets/rules.jpg">
        <img src="assets/rules.jpg" alt="Rules manager page" width="100%">
      </a>
      <p align="center"><strong>Rules Manager</strong></p>
    </td>
  </tr>
  <tr>
    <td width="50%">
      <a href="assets/sources.jpg">
        <img src="assets/sources.jpg" alt="Log sources page" width="100%">
      </a>
      <p align="center"><strong>Log Sources</strong></p>
    </td>
    <td width="50%">
      <a href="assets/reports.jpg">
        <img src="assets/reports.jpg" alt="Reports page" width="100%">
      </a>
      <p align="center"><strong>Reports</strong></p>
    </td>
  </tr>
  <tr>
    <td width="50%">
      <a href="assets/settings.jpg">
        <img src="assets/settings.jpg" alt="Settings page" width="100%">
      </a>
      <p align="center"><strong>Settings</strong></p>
    </td>
    <td width="50%">
      <p align="center"><em></em></p>
    </td>
  </tr>
</table>
---

## What It Does

Log-IDS runs as a **background service** that starts on boot. It watches your system logs and network traffic continuously. When it detects suspicious activity — brute-force attacks, privilege escalation, malware droppers, port scans — it stores an alert in a local database. Open the dashboard any time to review what has been detected.

```
http://127.0.0.1:8888
```

Or click **IDS Dashboard** in your application menu.

---

## Features

- **41 detection rules** covering SSH, sudo, su, account changes, UFW/firewall, kernel events, auditd syscalls, and web attacks
- **Stateful detection** — rules use sliding windows, cooldowns, and cross-event correlation (e.g. write-then-execute in /tmp → CRITICAL dropper alert)
- **Real-time log stream** — live SSE feed of raw log lines by source, filterable by source and keyword
- **IP profiling** — per-IP attack timeline, severity breakdown, and all associated alerts in one view
- **Rules Manager** — enable/disable individual rules and override thresholds at runtime without restarting
- **Webhook support** — POST alert payloads to any endpoint when a rule fires
- **Zero dependencies at runtime** — single binary, SQLite database, no external services required
- **systemd integration** — starts on boot, survives reboots, cleans up iptables rules on shutdown

---

## Quick Start

### 1 — Prerequisites

```bash
sudo apt update && sudo apt install golang-go auditd ufw
```

Enable UFW before installing (keeps your SSH session alive):

```bash
sudo ufw allow ssh && sudo ufw enable && sudo ufw default deny incoming
```

### 2 — Clone and install

```bash
git clone https://github.com/Kes0x6f/Log-Based--IDS.git
cd Log-Based--IDS
sudo bash install.sh
```

The installer builds the binary, copies files to `/opt/ids/`, loads auditd rules, registers and starts the systemd service, and adds a desktop launcher.

### 3 — Open the dashboard

```bash
xdg-open http://127.0.0.1:8888
```

Or search for **IDS Dashboard** in your application menu.

---

## Detection Coverage at a Glance

|Source|Rules|Example detections|
|---|---|---|
|`auth`|16|SSH brute force, sudo abuse, SU attacks, account creation|
|`ufw`|5|Port scan, block storm, outbound C2 connections|
|`kern`|4|Rootkit module load, segfault on sshd/sudo, OOM kill|
|`audit`|9|Setuid backdoor, ptrace, credential file access, dropper execution|
|`web`|6|Scanner UA, SQL injection, path traversal, login brute force|

→ See [DOCS.md](./DOCS.md#detection-coverage) for the full rule list with thresholds and severity levels.

---

## Service Management

```bash
sudo systemctl status ids-agent      # check if running
sudo systemctl stop   ids-agent      # stop (removes iptables rules cleanly)
sudo systemctl start  ids-agent      # start
sudo journalctl -u ids-agent -f      # live engine logs
```

> **Always stop with `systemctl stop`** — the service inserts iptables NFLOG rules on startup and must remove them cleanly. `kill -9` skips this.

---

## Project Structure

```
Log-Based--IDS/
├── main.go                         Entry point — wiring and startup
├── web/                            Dashboard frontend (HTML/CSS/JS)
├── internal/
│   ├── collector/                  File tail collectors + NFLOG packet capture
│   ├── parser/                     Log line normalisation → NormalizedEvent
│   ├── detection/
│   │   ├── engine.go               Rule evaluation + config cache
│   │   ├── rule_registry.go        Route events to matching rules
│   │   └── rules/
│   │       ├── auth/               16 SSH/sudo/su/account rules
│   │       ├── audit/              9 auditd rules
│   │       ├── kernel/             9 kernel/UFW rules
│   │       └── web/                6 web attack rules
│   ├── model/                      Alert and NormalizedEvent types
│   ├── database/                   SQLite repositories (alerts, settings, rule config)
│   ├── api/                        HTTP handlers and routes
│   └── stream/                     SSE broadcaster for live logs
├── configs/
│   ├── auditd/ids.rules            Auditd rules required for audit detections
│   ├── systemd/ids-agent.service   systemd unit file
│   └── desktop/ids-dashboard.desktop  Application menu launcher
├── scripts/simulate/               Attack simulation scripts (one per rule family)
├── install.sh                      One-command installer
├── uninstall.sh                    Clean removal
└── DOCS.md                         Full reference documentation
```

---

## Documentation

Full reference documentation is in **[DOCS.md](./DOCS.md)**:

- [Full detection rule list with thresholds](./DOCS.md#detection-coverage)
- [Enabling and verifying auditd rules](./DOCS.md#enabling-audit-rules)
- [Simulating attacks for demo/testing](./DOCS.md#simulating-attacks)
- [Configuration via environment variables](./DOCS.md#configuration)
- [Dashboard pages reference](./DOCS.md#dashboard-pages)
- [Warnings and ethical considerations](./DOCS.md#warnings-and-considerations)
- [Known limitations](./DOCS.md#known-limitations)
- [Uninstalling](./DOCS.md#uninstalling)

---

## Built With

- [Go](https://golang.org/) — detection engine and HTTP API
- [SQLite](https://sqlite.org/) via [go-sqlite3](https://github.com/mattn/go-sqlite3) — alert storage
- [go-nflog](https://github.com/florianl/go-nflog) — kernel netfilter packet capture
- [fsnotify](https://github.com/fsnotify/fsnotify) — real-time log file tailing
- [Chart.js](https://www.chartjs.org/) — dashboard charts

---
## License
This project was developed as an academic capstone project for **Universidad De Dagupan** and is intended for **educational purposes only**.
- ✅ You may study, reference, and learn from this code
- ✅ You may fork it for your own academic or personal learning
- ❌ Commercial use is not permitted
- ❌ Redistribution as your own work is not permitted
All rights reserved by this author.