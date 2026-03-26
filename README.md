# WinSec CLI — Windows & PowerShell for Cyber Defense

A Python-based **Command-Line Interface (CLI)** tool that consolidates multiple Windows and PowerShell security operations into one interface. Designed to support **system administrators, SOC analysts, and security professionals** in incident response, threat hunting, and forensics.

> Based on: **Windows and PowerShell Commands: Essential Guide for Cybersecurity Professionals** — *Okan YILDIZ*

---

## 🚀 Features

### Menu Overview

| # | Module | Description |
|---|--------|-------------|
| 1 | **System Information** | Systeminfo, hotfixes, disks, BitLocker status, SHA-256 hashes of core binaries |
| 2 | **Network Analysis** | ipconfig, netstat with PID correlation, interactive filters, firewall profiles, Wi-Fi key reveal |
| 3 | **Processes & Services** | Signature validation, suspicious path detection, typosquatting checks, SHA-256 hashes, port correlation |
| 4 | **Persistence Checks** | Registry Run keys, Startup folders, Scheduled Tasks, WMI subscriptions, IFEO hijacks |
| 5 | **Event Logs / Threat Hunting** | Critical event IDs (4624, 4625, 4688, 7045…) with regex filtering and pattern highlights |
| 6 | **Windows Defender** | Status, detected threats, signature updates, quick/full scans |
| 7 | **Security Policies / Audit / Firewall** | Audit policy, security config export, firewall + RDP settings |
| 8 | **Quick Forensics** | Recently modified files with extension, size, and age filters |
| 9 | **Threat Hunting — Quick Wins** | Scores suspicious events (service creation, encoded PowerShell, logon anomalies) |
| 10 | **Incident Response Bundle** | Snapshot processes, network, services, persistence, and logs — with ZIP export |
| 11 | **Remote Assessment** | Lightweight triage via PowerShell Remoting: processes, netstat, services, security events |
| 12 | **Security Summary** | Consolidated security score (0–100) with findings and remediation tips |
| 13 | **Token Privileges** | Lists all current token privileges via native Windows API (`ctypes`) — no subprocess |

---

## ✨ What's New

### 🔄 Live Progress Spinner (Modules 3 & 8)
Long-running operations now display a real-time animated spinner so users always know the app is working. Module 3 shows step-by-step progress with counters:

```
⠹  Checking process signatures (47/312)...
⠸  Checking service signatures (12/198)...
⠼  Computing SHA-256 for flagged binaries (3/17)...
```

Module 8 shows the directory being actively scanned:

```
⠦  Scanning: C:\Users\user\AppData\Roaming\...
```

### 🌐 Automatic Multilanguage Support
The CLI detects the Windows system language via `GetUserDefaultUILanguage` (LCID) and adapts all interface strings automatically — no configuration required.

| Language | Detection |
|----------|-----------|
| 🇧🇷 Portuguese (PT-BR) | LCID `0x16` or `locale pt_*` |
| 🇪🇸 Spanish | LCID `0x0A` or `locale es_*` |
| 🇺🇸 English | Default fallback |

All menus, prompts, error messages, and export confirmations are translated.

### 🔑 Token Privileges — Module 13
Lists all privileges of the current process token using the native Windows API directly via `ctypes` — zero subprocess, zero PowerShell:

| Step | API | Purpose |
|------|-----|---------|
| 1 | `OpenProcessToken` | Obtain handle to the current process token |
| 2 | `GetTokenInformation` (size) | Determine required buffer size |
| 3 | `create_string_buffer` | Safe buffer allocation (no integer division) |
| 4 | `GetTokenInformation` (fill) | Populate `TOKEN_PRIVILEGES` structure |
| 5 | `LookupPrivilegeNameW` | Resolve each LUID to a human-readable name |
| 6 | `CloseHandle` (in `finally`) | Always release the token handle |

Decoded attribute flags per privilege: `Enabled`, `Default`, `Removed`, `UsedForAccess`, `Disabled`.

If `ctypes.wintypes` is unavailable, the module displays a clear install instruction instead of a raw traceback.

---

## ⚙️ Requirements

- **Python 3.10+**
- **Windows** (PowerShell must be available in `PATH`)
- No external dependencies — standard library only
- Some modules benefit from **Administrator privileges**:

| Module | Behavior without Admin |
|--------|----------------------|
| 1, 3, 5, 6, 7, 10 | Some data may be unavailable |
| 13 | Works, but privilege list may be truncated |

---

## 📦 Installation

```bash
git clone https://github.com/ThaynerKesley/winsec-cli.git
cd winsec-cli
python winsec.py
```

---

## 🖥️ Usage

```
WinSec CLI — Main Menu
────────────────────────────────────────────────────────────
1)  System Information
2)  Network Analysis
3)  Processes & Services
4)  Persistence (Run Keys / Startup / Tasks / WMI / IFEO)
5)  Event Logs / Threat Hunting
6)  Windows Defender (status & scans)
7)  Security Policies / Audit / Firewall
8)  Quick Forensics (recent files)
9)  Threat Hunting — Quick Wins
10) Incident Response — Bundle Snapshot
11) Remote Assessment (PowerShell Remoting)
12) Security Summary — Consolidated Score
13) Token Privileges — Windows API (ctypes)
0)  Exit
────────────────────────────────────────────────────────────
```

Each module prints results to screen and optionally exports to **TXT, JSON, or Markdown**.

---

## 🔐 Disclaimer

This tool is provided for **educational and defensive purposes only**.
Do not use it on systems you do not own or have explicit authorization to analyze.

---

## 👤 Author

Developed by **Thayner Kesley**
GitHub: [https://github.com/ThaynerKesley](https://github.com/ThaynerKesley)
