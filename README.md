# WinSec CLI --- Windows & PowerShell for Cyber Defense

A Python-based **Command-Line Interface (CLI)** tool that consolidates
multiple Windows and PowerShell security operations into one interface.\
It is designed to support **system administrators, SOC analysts, and
security professionals** in incident response, threat hunting, and
forensics.

This project was developed based on techniques and recommendations from
the book:

> **Windows and PowerShell Commands: Essential Guide for Cybersecurity
> Professionals**\
> by *Okan YILDIZ*

------------------------------------------------------------------------

## 🚀 Features

The CLI provides a **menu-driven interface** with 12 modules:

1.  **System Information**\
    Collect system info, hotfixes, disks, BitLocker status, and hashes
    of core binaries.

2.  **Network Analysis**\
    Show network configuration, netstat (with PID correlation), firewall
    profiles, and Wi-Fi keys.

3.  **Processes & Services**\
    List processes and services with **digital signature validation**,
    suspicious path detection, typosquatting checks, and SHA-256 hashes.

4.  **Persistence Checks**\
    Analyze registry Run keys, Startup folders, Scheduled Tasks, WMI
    subscriptions, and IFEO hijacks.

5.  **Event Logs / Threat Hunting**\
    Extract critical event IDs (4624, 4625, 4688, 7045, etc.) with
    optional regex filtering and suspicious pattern highlights.

6.  **Windows Defender**\
    Display status, list detected threats, update signatures, and
    trigger quick/full scans.

7.  **Security Policies / Audit / Firewall**\
    Collect audit policy, export security configuration, and check
    firewall + RDP settings.

8.  **Quick Forensics**\
    List recently modified files with filters for extension, size, and
    age.

9.  **Threat Hunting --- Quick Wins**\
    Score suspicious events (e.g., service creation, encoded PowerShell,
    logon anomalies).

10. **Incident Response Bundle**\
    Snapshot processes, network, services, persistence, and logs into a
    single report (with ZIP export option).

11. **Remote Assessment (PowerShell Remoting)**\
    Execute lightweight triage remotely: top processes, netstat,
    services, and security events.

12. **Security Summary --- Consolidated Score**\
    Generate a quick security score (0--100) with key findings and
    remediation tips.

------------------------------------------------------------------------

## ⚙️ Requirements

-   **Python 3.10+**
-   Run on **Windows**\
-   PowerShell available in PATH
-   Some modules require **Administrator privileges**

------------------------------------------------------------------------

## 📦 Installation

Clone the repository:

``` bash
git clone https://github.com/ThaynerKesley/winsec-cli.git
cd winsec-cli
```

Run the script:

``` bash
python winsec.py
```

------------------------------------------------------------------------

## 🖥️ Usage

The program provides an interactive **menu**:

    WinSec CLI — Main Menu
    1) System Information
    2) Network Analysis
    3) Processes & Services
    ...
    12) Security Summary
    0) Exit

Each module prints results on screen and optionally allows export to
**TXT, JSON, or Markdown**.

------------------------------------------------------------------------

## 🔐 Disclaimer

This tool is provided for **educational and defensive purposes only**.\
Do not use it on systems you do not own or have explicit authorization
to analyze.

------------------------------------------------------------------------

## 📚 Reference

The design and feature set of this project are based on:

**Windows and PowerShell Commands: Essential Guide for Cybersecurity
Professionals**\
*Okan YILDIZ --- Global Cybersecurity Leader*

------------------------------------------------------------------------

## 👤 Author

Developed by **Thayner Kesley**\
GitHub: <https://github.com/ThaynerKesley>
