# WinSec CLI — Windows & PowerShell for Cyber Defense

A Python-based **Command-Line Interface (CLI)** tool that consolidates
multiple Windows and PowerShell security operations into one interface.
Designed to support **system administrators, SOC analysts, and security
professionals** in incident response, threat hunting, and forensics.

This project was developed based on techniques and recommendations from the book:

> **Windows and PowerShell Commands: Essential Guide for Cybersecurity Professionals**
> by *Okan YILDIZ*

---

## 🚀 Features

The CLI provides a **menu-driven interface** with 13 modules:

1. **System Information**
   Collect system info, hotfixes, disks, BitLocker status, and SHA-256 hashes of core binaries.

2. **Network Analysis**
   Show network configuration, netstat with PID correlation, interactive filters (LISTENING/ESTABLISHED/port/process), firewall profiles, and Wi-Fi key reveal.

3. **Processes & Services**
   List processes and services with **digital signature validation**, suspicious path detection, typosquatting checks, and SHA-256 hashes. Cross-references listening ports per process.

4. **Persistence Checks**
   Analyze registry Run keys, Startup folders, Scheduled Tasks, WMI subscriptions, and IFEO hijacks.

5. **Event Logs / Threat Hunting**
   Extract critical event IDs (4624, 4625, 4688, 7045, etc.) with optional regex filtering and suspicious pattern highlights.

6. **Windows Defender**
   Display status, list detected threats, update signatures, and trigger quick/full scans.

7. **Security Policies / Audit / Firewall**
   Collect audit policy, export security configuration, and check firewall + RDP settings.

8. **Quick Forensics**
   List recently modified files with filters for extension, size, and age.

9. **Threat Hunting — Quick Wins**
   Score suspicious events (e.g., service creation, encoded PowerShell, logon anomalies).

10. **Incident Response Bundle**
    Snapshot processes, network, services, persistence, and logs into a single report (with ZIP export option).

11. **Remote Assessment (PowerShell Remoting)**
    Execute lightweight triage remotely: top processes, netstat, services, and security events.

12. **Security Summary — Consolidated Score**
    Generate a security score (0–100) with key findings and remediation tips across Defender, Firewall, Audit Policy, RDP/NLA, and event-based signals.

13. **Token Privileges — Windows API (ctypes)** *(NEW)*
    List all privileges of the current process token via **native Windows API** (`OpenProcessToken` + `GetTokenInformation` + `LookupPrivilegeNameW`) using `ctypes` — no subprocess, no PowerShell. Displays each privilege name alongside its decoded attribute flags (`Enabled`, `Default`, `Removed`, `UsedForAccess`). Warns if not running as Administrator. Exports via the built-in `write_file()` handler.

---

## ⚙️ Requirements

- **Python 3.10+**
- Run on **Windows**
- PowerShell available in `PATH`
- Some modules require **Administrator privileges**
  - Modules 1, 3, 5, 6, 7, 10 benefit significantly from elevated execution
  - Module 13 works as standard user but may show a truncated privilege list without elevation

---

## 📦 Installation

Clone the repository:

```bash
git clone https://github.com/ThaynerKesley/winsec-cli.git
cd winsec-cli
```

Run the script:

```bash
python winsec.py
```

> No external dependencies required. All modules use Python standard library + Windows built-ins.

---

## 🖥️ Usage

The program provides an interactive menu:

```
WinSec CLI — Main Menu
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
```

Each module prints results on screen and optionally allows export to **TXT, JSON, or Markdown**.

---

## 🔬 Module 13 — Token Privileges (Technical Detail)

Module 13 implements privilege enumeration via the Windows API directly, without spawning any subprocess:

| Step | API Call | Purpose |
|------|----------|---------|
| 1 | `OpenProcessToken` | Obtain handle to the current process token |
| 2 | `GetTokenInformation` (size query) | Determine required buffer size |
| 3 | `create_string_buffer` | Allocate safe buffer without integer division |
| 4 | `GetTokenInformation` (fill) | Populate `TOKEN_PRIVILEGES` structure |
| 5 | `LookupPrivilegeNameW` | Resolve each `LUID` to a human-readable name |
| 6 | `CloseHandle` (in `finally`) | Always release the token handle |

Attribute flags decoded per privilege:

| Flag | Constant | Meaning |
|------|----------|---------|
| `Enabled` | `SE_PRIVILEGE_ENABLED` | Currently active |
| `Default` | `SE_PRIVILEGE_ENABLED_BY_DEFAULT` | Enabled at token creation |
| `Removed` | `SE_PRIVILEGE_REMOVED` | Stripped from the token |
| `UsedForAccess` | `SE_PRIVILEGE_USED_FOR_ACCESS` | Used in an access check |
| `Disabled` | *(none set)* | Present but not active |

---

## 🔐 Disclaimer

This tool is provided for **educational and defensive purposes only**.
Do not use it on systems you do not own or have explicit authorization to analyze.

---

## 📚 Reference

The design and feature set of this project are based on:

**Windows and PowerShell Commands: Essential Guide for Cybersecurity Professionals**
*Okan YILDIZ — Global Cybersecurity Leader*

---

## 👤 Author

Developed by **Thayner Kesley**
GitHub: [https://github.com/ThaynerKesley](https://github.com/ThaynerKesley)
