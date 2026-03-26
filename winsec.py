#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WinSec CLI — Windows & PowerShell for Cyber Defense (CLI)

This build includes:
  [1] System Information (enhanced + export)
  [2] Network Analysis (enhanced, with PID correlation and interactive filters)
  [3] Processes & Services (signatures, hashes, heuristics, port correlation)
  [4] Persistence (Run Keys / Startup / Tasks / WMI / IFEO)
  [5] Event Logs / Threat Hunting (IDs + highlights)
  [6] Windows Defender (status, threats, scans)
  [7] Security Policies / Audit / Firewall
  [8] Quick Forensics (recent/suspicious files)
  [9] Threat Hunting — Quick Wins
  [10] Incident Response — Bundle Snapshot
  [11] Remote Assessment (PowerShell Remoting)
  [12] Security Summary — Consolidated Score

No external APIs used. Designed for Windows (PowerShell required for some parts) made by Thayner Kesley.
"""

import os
import sys
import platform
import subprocess
from datetime import datetime
import ctypes
import ctypes.wintypes
import json
import re
import hashlib
import threading
import itertools
import locale

# ==========================
# Internationalisation (i18n)
# ==========================

def _detect_lang() -> str:
    """Detect Windows UI language via GetUserDefaultUILanguage LCID, fallback to locale."""
    try:
        lcid = ctypes.windll.kernel32.GetUserDefaultUILanguage()
        # Primary language IDs (low 10 bits of LCID)
        primary = lcid & 0x3FF
        # 0x16 = Portuguese, 0x0A = Spanish, 0x09 = English
        if primary == 0x16:
            return "pt"
        if primary == 0x0A:
            return "es"
    except Exception:
        pass
    try:
        loc = (locale.getdefaultlocale()[0] or "").lower()
        if loc.startswith("pt"):
            return "pt"
        if loc.startswith("es"):
            return "es"
    except Exception:
        pass
    return "en"


_STRINGS: dict[str, dict[str, str]] = {
    "en": {
        # Menu
        "menu_title":       "WinSec CLI — Main Menu (Made by Thayner Kesley)",
        "menu_os":          "OS",
        "menu_admin":       "Admin",
        "menu_time":        "Time",
        "menu_admin_yes":   "YES",
        "menu_admin_no":    "NO",
        "select_option":    "Select option: ",
        "invalid_option":   "Invalid option.",
        "os_only_windows":  "[error] Windows only.",
        # Export
        "export_prompt":    "Export format? (txt/json/md/none): ",
        "export_txt":       "[+] Exported TXT: {}",
        "export_md":        "[+] Exported MD: {}",
        "export_json":      "[+] Exported JSON: {}",
        "export_skip":      "[-] Export skipped.",
        # Common prompts
        "hours_back":       "Hours to look back (default {}): ",
        "compare_baseline": "Compare against baseline persistence JSON? (path or blank): ",
        # Module 2
        "filter_listening": "Filter LISTENING only? (y/N): ",
        "filter_established":"Filter ESTABLISHED only? (y/N): ",
        "filter_port":      "Filter by local port (blank = none): ",
        "filter_pname":     "Filter by process name contains (blank = none): ",
        "wifi_reveal":      "Reveal Wi-Fi key for a profile? Enter SSID or leave blank: ",
        # Module 3
        "show_unsigned":    "Show unsigned only? (y/N): ",
        "show_suspath":     "Show suspicious paths only? (y/N): ",
        "filter_port3":     "Filter by listening port (blank = none): ",
        "filter_name3":     "Filter by name contains (blank = none): ",
        # Module 5
        "event_ids_prompt": "Event IDs (comma-separated) or blank for default set: ",
        "grep_regex":       "Grep regex (case-insensitive) to filter Message (blank = none): ",
        # Module 8
        "days_back":        "Days back (default 7): ",
        "ext_filter":       "Extensions to filter (comma-separated, blank=all): ",
        "min_size":         "Min size in bytes (blank=0): ",
        "max_size":         "Max size in bytes (blank=none): ",
        # Module 10
        "zip_snapshot":     "ZIP the snapshot? (y/N): ",
        # Module 11
        "remote_host":      "Remote hostname or IP: ",
        # Module 12
        "security_hours":   "Hours to look back (default 72): ",
        # Module 13
        "token_admin_warn": "⚠️  Privileges may be truncated — run as Administrator for the full list",
        "token_open_err":   "[error] OpenProcessToken failed: {}",
        "token_api_err":    "[error] Windows API failed: {}",
        "token_exported":   "[+] Report automatically exported via write_file().",
        "token_count":      "Total privileges: {}",
        "token_no_wintypes":"[error] ctypes.wintypes unavailable. Run: pip install pywin32 --or-- ensure Python 3.10+ on Windows.",
        # Progress spinner labels
        "spin_pid_ports":   "Mapping listening ports to PIDs...",
        "spin_enum_proc":   "Enumerating processes via WMI...",
        "spin_sig_proc":    "Checking process signatures ({}/{})",
        "spin_enum_svc":    "Enumerating services via WMI...",
        "spin_sig_svc":     "Checking service signatures ({}/{})",
        "spin_drivers":     "Querying kernel drivers...",
        "spin_hashes":      "Computing SHA-256 for flagged binaries ({}/{})",
        "spin_scan_dir":    "Scanning: {}",
        "spin_sorting":     "Sorting results...",
        "spin_done":        "Done.",
    },
    "pt": {
        "menu_title":       "WinSec CLI — Menu Principal (Desenvolvido por Thayner Kesley)",
        "menu_os":          "SO",
        "menu_admin":       "Admin",
        "menu_time":        "Hora",
        "menu_admin_yes":   "SIM",
        "menu_admin_no":    "NÃO",
        "select_option":    "Selecione uma opção: ",
        "invalid_option":   "Opção inválida.",
        "os_only_windows":  "[erro] Apenas Windows.",
        "export_prompt":    "Formato de exportação? (txt/json/md/none): ",
        "export_txt":       "[+] Exportado TXT: {}",
        "export_md":        "[+] Exportado MD: {}",
        "export_json":      "[+] Exportado JSON: {}",
        "export_skip":      "[-] Exportação cancelada.",
        "hours_back":       "Horas para analisar (padrão {}): ",
        "compare_baseline": "Comparar com JSON de baseline de persistência? (caminho ou vazio): ",
        "filter_listening": "Filtrar apenas LISTENING? (s/N): ",
        "filter_established":"Filtrar apenas ESTABLISHED? (s/N): ",
        "filter_port":      "Filtrar por porta local (vazio = nenhum): ",
        "filter_pname":     "Filtrar por nome do processo (vazio = nenhum): ",
        "wifi_reveal":      "Revelar senha de Wi-Fi? Digite o SSID ou deixe vazio: ",
        "show_unsigned":    "Exibir apenas não assinados? (s/N): ",
        "show_suspath":     "Exibir apenas caminhos suspeitos? (s/N): ",
        "filter_port3":     "Filtrar por porta em escuta (vazio = nenhum): ",
        "filter_name3":     "Filtrar por nome (vazio = nenhum): ",
        "event_ids_prompt": "IDs de evento (separados por vírgula) ou vazio para padrão: ",
        "grep_regex":       "Regex para filtrar a mensagem (vazio = nenhum): ",
        "days_back":        "Dias para analisar (padrão 7): ",
        "ext_filter":       "Extensões (separadas por vírgula, vazio = todas): ",
        "min_size":         "Tamanho mínimo em bytes (vazio = 0): ",
        "max_size":         "Tamanho máximo em bytes (vazio = sem limite): ",
        "zip_snapshot":     "Compactar o snapshot em ZIP? (s/N): ",
        "remote_host":      "Hostname ou IP remoto: ",
        "security_hours":   "Horas para analisar (padrão 72): ",
        "token_admin_warn": "⚠️  Privilégios podem estar truncados — execute como Administrador para a lista completa",
        "token_open_err":   "[erro] OpenProcessToken falhou: {}",
        "token_api_err":    "[erro] API do Windows falhou: {}",
        "token_exported":   "[+] Relatório exportado automaticamente via write_file().",
        "token_count":      "Total de privilégios: {}",
        "token_no_wintypes":"[erro] ctypes.wintypes indisponível. Execute: pip install pywin32 --ou-- certifique-se de usar Python 3.10+ no Windows.",
        "spin_pid_ports":   "Mapeando portas em escuta por PID...",
        "spin_enum_proc":   "Enumerando processos via WMI...",
        "spin_sig_proc":    "Verificando assinaturas de processos ({}/{})",
        "spin_enum_svc":    "Enumerando serviços via WMI...",
        "spin_sig_svc":     "Verificando assinaturas de serviços ({}/{})",
        "spin_drivers":     "Consultando drivers do kernel...",
        "spin_hashes":      "Calculando SHA-256 de binários sinalizados ({}/{})",
        "spin_scan_dir":    "Escaneando: {}",
        "spin_sorting":     "Ordenando resultados...",
        "spin_done":        "Concluído.",
    },
    "es": {
        "menu_title":       "WinSec CLI — Menú Principal (Desarrollado por Thayner Kesley)",
        "menu_os":          "SO",
        "menu_admin":       "Admin",
        "menu_time":        "Hora",
        "menu_admin_yes":   "SÍ",
        "menu_admin_no":    "NO",
        "select_option":    "Seleccione una opción: ",
        "invalid_option":   "Opción inválida.",
        "os_only_windows":  "[error] Solo Windows.",
        "export_prompt":    "Formato de exportación? (txt/json/md/none): ",
        "export_txt":       "[+] Exportado TXT: {}",
        "export_md":        "[+] Exportado MD: {}",
        "export_json":      "[+] Exportado JSON: {}",
        "export_skip":      "[-] Exportación omitida.",
        "hours_back":       "Horas a analizar (predeterminado {}): ",
        "compare_baseline": "¿Comparar con JSON de baseline de persistencia? (ruta o vacío): ",
        "filter_listening": "¿Filtrar solo LISTENING? (s/N): ",
        "filter_established":"¿Filtrar solo ESTABLISHED? (s/N): ",
        "filter_port":      "Filtrar por puerto local (vacío = ninguno): ",
        "filter_pname":     "Filtrar por nombre de proceso (vacío = ninguno): ",
        "wifi_reveal":      "¿Revelar clave Wi-Fi? Ingrese SSID o deje vacío: ",
        "show_unsigned":    "¿Mostrar solo no firmados? (s/N): ",
        "show_suspath":     "¿Mostrar solo rutas sospechosas? (s/N): ",
        "filter_port3":     "Filtrar por puerto en escucha (vacío = ninguno): ",
        "filter_name3":     "Filtrar por nombre (vacío = ninguno): ",
        "event_ids_prompt": "IDs de evento (separados por coma) o vacío para predeterminado: ",
        "grep_regex":       "Regex para filtrar mensaje (vacío = ninguno): ",
        "days_back":        "Días a analizar (predeterminado 7): ",
        "ext_filter":       "Extensiones (separadas por coma, vacío = todas): ",
        "min_size":         "Tamaño mínimo en bytes (vacío = 0): ",
        "max_size":         "Tamaño máximo en bytes (vacío = sin límite): ",
        "zip_snapshot":     "¿Comprimir snapshot en ZIP? (s/N): ",
        "remote_host":      "Hostname o IP remoto: ",
        "security_hours":   "Horas a analizar (predeterminado 72): ",
        "token_admin_warn": "⚠️  Los privilegios pueden estar truncados — ejecute como Administrador para la lista completa",
        "token_open_err":   "[error] OpenProcessToken falló: {}",
        "token_api_err":    "[error] API de Windows falló: {}",
        "token_exported":   "[+] Informe exportado automáticamente via write_file().",
        "token_count":      "Total de privilegios: {}",
        "token_no_wintypes":"[error] ctypes.wintypes no disponible. Ejecute: pip install pywin32 --o-- asegúrese de usar Python 3.10+ en Windows.",
        "spin_pid_ports":   "Mapeando puertos en escucha por PID...",
        "spin_enum_proc":   "Enumerando procesos via WMI...",
        "spin_sig_proc":    "Verificando firmas de procesos ({}/{})",
        "spin_enum_svc":    "Enumerando servicios via WMI...",
        "spin_sig_svc":     "Verificando firmas de servicios ({}/{})",
        "spin_drivers":     "Consultando drivers del kernel...",
        "spin_hashes":      "Calculando SHA-256 de binarios marcados ({}/{})",
        "spin_scan_dir":    "Escaneando: {}",
        "spin_sorting":     "Ordenando resultados...",
        "spin_done":        "Completado.",
    },
}

_LANG = _detect_lang()


def t(key: str, *args) -> str:
    """Return translated string for current system language, fallback to English."""
    s = _STRINGS.get(_LANG, _STRINGS["en"]).get(key) or _STRINGS["en"].get(key, key)
    return s.format(*args) if args else s


# ==========================
# Utilities
# ==========================

def is_windows():
    return platform.system().lower().startswith("win")


def is_admin():
    if not is_windows():
        return False
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def slugify(name: str) -> str:
    bad = " <>:/\\|?*\"'\n\r\t"
    for ch in bad:
        name = name.replace(ch, "_")
    return name[:80].strip("_.") or "output"


def write_file(basename: str, content: str, ext: str = "txt") -> str:
    fname = f"{slugify(basename)}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{ext}"
    with open(fname, "w", encoding="utf-8", errors="replace") as f:
        f.write(content)
    return os.path.abspath(fname)


def export_prompt(default_name: str, text_dump: str, json_obj: dict | None = None):
    print(t("export_prompt"), end="")
    fmt = input().strip().lower()
    if fmt == "txt":
        path = write_file(default_name, text_dump, "txt")
        print(t("export_txt", path))
    elif fmt == "md":
        md = f"# {default_name}\n\n````\n{text_dump}\n````\n"
        path = write_file(default_name, md, "md")
        print(t("export_md", path))
    elif fmt == "json":
        if json_obj is None:
            json_obj = {"generated_at": now_str(), "text": text_dump}
        path = write_file(default_name, json.dumps(json_obj, indent=2), "json")
        print(t("export_json", path))
    else:
        print(t("export_skip"))

def maybe_export(default_name: str, text_dump: str, json_obj: dict | None = None):
    return export_prompt(default_name, text_dump, json_obj)

# ==========================
# Progress Spinner
# ==========================

class Spinner:
    """Thread-safe CLI spinner. Shows the user the app is alive during long ops."""

    _FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

    def __init__(self):
        self._msg   = ""
        self._stop  = threading.Event()
        self._lock  = threading.Lock()
        self._thread: threading.Thread | None = None

    def start(self, message: str = "") -> "Spinner":
        self._msg = message
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        return self

    def update(self, message: str) -> None:
        with self._lock:
            self._msg = message

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join()
        # Clear the spinner line
        sys.stdout.write("\r" + " " * 90 + "\r")
        sys.stdout.flush()

    def _loop(self) -> None:
        for ch in itertools.cycle(self._FRAMES):
            if self._stop.is_set():
                break
            with self._lock:
                msg = self._msg
            line = f"\r{ch}  {msg}"
            sys.stdout.write(line[:88].ljust(88))
            sys.stdout.flush()
            self._stop.wait(0.1)



def header(title: str) -> str:
    line = "=" * 104
    return f"{line}\n{title}\n{line}\nTimestamp: {now_str()}  |  Admin: {'YES' if is_admin() else 'NO'}\n\n"


def run_cmd(cmd: str) -> str:
    try:
        cp = subprocess.run(cmd, shell=True, capture_output=True, text=True, encoding="utf-8", errors="replace")
        return (cp.stdout or "") + ("\n[stderr]\n" + cp.stderr if (cp.stderr and cp.stderr.strip()) else "")
    except Exception as e:
        return f"[error] CMD failed: {e}"


def run_ps(ps: str) -> str:
    if not is_windows():
        return "[error] PowerShell unavailable on this OS."
    try:
        cmd = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps]
        cp = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
        return (cp.stdout or "") + ("\n[stderr]\n" + cp.stderr if (cp.stderr and cp.stderr.strip()) else "")
    except Exception as e:
        return f"[error] PowerShell failed: {e}"

# ==========================
# [1] System Information
# ==========================

def mod_system_info():
    out = []
    out.append(header("[1] System Information"))
    out.append(f"Admin: {'YES' if is_admin() else 'NO'}\n")

    cmds = [
        "systeminfo",
        "whoami /all",
        "hostname",
        "wmic qfe list full /format:table",
        "wmic logicaldisk get Caption,Description,FileSystem,Size,FreeSpace",
        "bcdedit /enum",
    ]
    for c in cmds:
        out.append(f"[CMD] {c}\n" + run_cmd(c))

    out.append("\n[PS] Win32_OperatingSystem\n" + run_ps("Get-CimInstance Win32_OperatingSystem | Format-List *"))
    out.append("\n[PS] LastBootUpTime\n" + run_ps("(Get-CimInstance Win32_OperatingSystem).LastBootUpTime"))
    out.append("\n[PS] BitLocker (best-effort)\n" + run_ps("try { Get-BitLockerVolume | Select-Object MountPoint,ProtectionStatus,VolumeStatus,EncryptionMethod | Format-Table -AutoSize } catch { 'BitLocker cmdlet unavailable' }"))

    # Hashes for core binaries
    core_bins = [r"C:\\Windows\\System32\\cmd.exe", r"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"]
    for bin in core_bins:
        if os.path.isfile(bin):
            try:
                with open(bin, "rb") as f: h = hashlib.sha256(f.read()).hexdigest()
                out.append(f"[HASH] {bin} -> {h}")
            except Exception as e:
                out.append(f"[HASH] {bin} -> error {e}")

    content = "\n".join(out)
    print(content)
    export_prompt("system_info", content)

# ==========================
# [2] Network Analysis (with correlation and filters)
# ==========================

SUSPECT_PORTS = {22, 2222, 1337, 4444, 3389, 5985, 5986, 1433, 1521, 3306, 5432}


def _parse_netstat(output: str):
    entries = []
    for line in (output or '').splitlines():
        line = line.strip()
        if not line or not (line.startswith('TCP') or line.startswith('UDP')):
            continue
        parts = re.split(r"\s+", line)
        try:
            proto = parts[0]
            if proto == 'UDP':
                local = parts[1]
                foreign = parts[2] if len(parts) > 2 else ''
                pid = int(parts[-1]) if parts[-1].isdigit() else None
                state = ''
            else:  # TCP
                local = parts[1]
                foreign = parts[2]
                state = parts[3] if len(parts) > 4 else ''
                pid = int(parts[-1]) if parts[-1].isdigit() else None
            def split_hostport(addr):
                if addr.count(':') >= 1:
                    host, port = addr.rsplit(':', 1)
                    return host, port
                return addr, ''
            lhost, lport = split_hostport(local)
            fhost, fport = split_hostport(foreign)
            entries.append({
                'proto': proto,
                'local_addr': lhost, 'local_port': lport,
                'foreign_addr': fhost, 'foreign_port': fport,
                'state': state, 'pid': pid
            })
        except Exception:
            continue
    return entries


def _proc_map():
    ps = (
        "try { Get-Process | Select-Object Id,Name,Path | ConvertTo-Json -Depth 3 } "
        "catch { '[]' }"
    )
    raw = run_ps(ps)
    try:
        data = json.loads(raw)
        m = {}
        for p in (data if isinstance(data, list) else []):
            pid = p.get('Id')
            if pid is None:
                continue
            m[int(pid)] = {'name': p.get('Name') or '', 'path': p.get('Path') or ''}
        if m:
            return m
    except Exception:
        pass
    # Fallback to tasklist CSV (name, pid)
    csv = run_cmd('tasklist /V /FO CSV')
    m = {}
    for line in csv.splitlines():
        if line.count(',') < 2:
            continue
        try:
            parts = [s.strip().strip('"') for s in line.split(',')]
            name = parts[0]
            pid = int(parts[1])
            m[pid] = {'name': name, 'path': ''}
        except Exception:
            continue
    return m


def _correlate(entries, pmap):
    rows = []
    for e in entries:
        pid = e.get('pid')
        pd = pmap.get(pid, {}) if pid is not None else {}
        name = pd.get('name', '')
        path = pd.get('path', '')
        lport = e.get('local_port')
        suspicious = False
        try:
            if lport and lport.isdigit() and int(lport) in SUSPECT_PORTS and (e.get('state') in ('LISTENING', '', None)):
                suspicious = True
        except Exception:
            pass
        rows.append({**e, 'proc_name': name, 'proc_path': path, 'flag_suspicious': suspicious})
    return rows


def _format_rows(rows):
    out = []
    out.append("Proto | Local | Foreign | State | PID | Proc | Suspicious")
    out.append("-"*104)
    for r in rows:
        loc = f"{r.get('local_addr')}:{r.get('local_port')}"
        forg = f"{r.get('foreign_addr')}:{r.get('foreign_port')}"
        out.append(f"{r.get('proto'):>4} | {loc:<24} | {forg:<24} | {r.get('state', ''):<11} | {str(r.get('pid') or ''):<5} | {r.get('proc_name',''):<20} | {'*' if r.get('flag_suspicious') else ''}")
    return "\n".join(out)


def parse_listening_ports_by_pid() -> dict:
    cmd = 'netstat -ano'
    out = run_cmd(cmd)
    entries = _parse_netstat(out)
    pid_ports = {}
    for e in entries:
        if e.get('state') == 'LISTENING' and e.get('local_port'):
            pid = e.get('pid')
            if pid is None:
                continue
            pid_ports.setdefault(pid, set()).add(e.get('local_port'))
    return pid_ports


def mod_network_analysis():
    txt = []
    txt.append(header("[2] Network Analysis"))
    txt.append("[CMD] ipconfig /all\n" + run_cmd("ipconfig /all"))

    admin = is_admin()
    net_cmd = "netstat -abno" if admin else "netstat -ano"
    net_out = run_cmd(net_cmd)
    txt.append(f"\n[CMD] {net_cmd}\n" + net_out)

    entries = _parse_netstat(net_out)
    pmap = _proc_map()

    # Interactive filters
    print("Filter LISTENING only? (y/N): ", end=""); f_listen = input().strip().lower().startswith('y')
    print("Filter ESTABLISHED only? (y/N): ", end=""); f_est = input().strip().lower().startswith('y')
    print("Filter by local port (blank = none): ", end=""); f_port = input().strip()
    print("Filter by process name contains (blank = none): ", end=""); f_pname = input().strip().lower()

    rows = _correlate(entries, pmap)
    def apply_filters(r):
        if f_listen and r.get('state') != 'LISTENING':
            return False
        if f_est and r.get('state') != 'ESTABLISHED':
            return False
        if f_port and r.get('local_port') != f_port:
            return False
        if f_pname and f_pname not in (r.get('proc_name','').lower()):
            return False
        return True

    rows = [r for r in rows if apply_filters(r)]
    rows_sorted = sorted(rows, key=lambda x: (x.get('proto',''), int(x.get('local_port') or 0)))
    txt.append("\n[Correlated netstat ↔ process list]\n" + _format_rows(rows_sorted))

    # Other helpers
    txt.append("\n[CMD] arp -a\n" + run_cmd("arp -a"))
    txt.append("\n[CMD] route print\n" + run_cmd("route print"))
    txt.append("\n[CMD] netsh advfirewall show allprofiles\n" + run_cmd("netsh advfirewall show allprofiles"))
    txt.append("\n[CMD] netsh wlan show profiles\n" + run_cmd("netsh wlan show profiles"))

    # Optional: Wi-Fi key reveal
    print("Reveal Wi-Fi key for a profile? Enter SSID or leave blank: ", end=""); ssid = input().strip()
    if ssid:
        keyinfo = run_cmd(f"netsh wlan show profile name=\"{ssid}\" key=clear")
        txt.append(f"\n[CMD] netsh wlan show profile name=\"{ssid}\" key=clear\n" + keyinfo)

    content = "\n".join(txt)
    print(content)
    export_prompt("network_analysis", content)

# ==========================
# [3] Processes & Services (signatures, hashes, heuristics)
# ==========================

SUSP_PATH_HINTS = (
    r"\\AppData\\", r"\\Temp\\", r"\\ProgramData\\", r"\\Users\\Public\\", r"\\Downloads\\"
)

TYPO_PATTERNS = [
    r"svch0st", r"svchosts", r"scvhost", r"expl0rer", r"exp1orer", r"lsasss", r"isass", r"csrsss", r"win1ogon", r"conhst", r"rund11"
]


def _ps_json(ps: str):
    raw = run_ps(ps)
    try:
        return json.loads(raw)
    except Exception:
        return []


def get_processes():
    ps = (
        "Get-CimInstance Win32_Process | "
        "Select-Object ProcessId,Name,CommandLine,ExecutablePath | ConvertTo-Json -Depth 4"
    )
    return _ps_json(ps)


def get_services():
    ps = (
        "Get-CimInstance Win32_Service | "
        "Select-Object Name,DisplayName,State,StartMode,PathName,ProcessId | ConvertTo-Json -Depth 4"
    )
    return _ps_json(ps)


def get_drivers_raw():
    return run_cmd("driverquery /v")


def extract_exe_from_pathname(pathname: str) -> str:
    if not pathname:
        return ""
    # Handle quoted path or first token as exe
    pn = pathname.strip()
    if pn.startswith('"') and '"' in pn[1:]:
        exe = pn.split('"')[1]
    else:
        exe = pn.split(' ')[0]
    return exe


def is_suspicious_path(path: str) -> bool:
    if not path:
        return True
    p = path.lower()
    return any(hint.lower() in p for hint in SUSP_PATH_HINTS)


def is_typosquat(name: str) -> bool:
    if not name:
        return False
    n = name.lower()
    return any(re.search(p, n) for p in TYPO_PATTERNS)


def check_signature(path: str) -> str:
    if not path or not os.path.isfile(path):
        return "NotFound"
    esc = path.replace('"', '`"')
    status = run_ps(f"try {{ (Get-AuthenticodeSignature -FilePath \"{esc}\").Status }} catch {{ 'Error' }}")
    status = (status or '').strip().splitlines()[0] if status else 'Unknown'
    return status or "Unknown"


def sha256_file(path: str) -> str:
    try:
        with open(path, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception:
        return ""


def mod_process_services():
    out = []
    out.append(header("[3] Processes & Services"))

    # Interactive filters
    print(t("show_unsigned"), end=""); f_unsigned = input().strip().lower().startswith('y')
    print(t("show_suspath"), end=""); f_suspath = input().strip().lower().startswith('y')
    print(t("filter_port3"), end=""); f_port = input().strip()
    print(t("filter_name3"), end=""); f_name = input().strip().lower()

    spinner = Spinner()

    # Port map by PID
    spinner.start(t("spin_pid_ports"))
    pid_ports = parse_listening_ports_by_pid()
    spinner.stop()

    # --- Processes ---
    spinner.start(t("spin_enum_proc"))
    procs = get_processes()
    spinner.stop()

    rows_p = []
    sig_cache = {}
    hash_targets = set()
    total_p = len(procs) if isinstance(procs, list) else 0

    for i, p in enumerate(procs if isinstance(procs, list) else []):
        pid = p.get('ProcessId')
        name = p.get('Name') or ''
        path = p.get('ExecutablePath') or ''
        cmd = p.get('CommandLine') or ''
        spinner.update(t("spin_sig_proc", i + 1, total_p))
        spinner.start() if i == 0 else None
        sig = sig_cache.get(path)
        if sig is None:
            sig = check_signature(path)
            sig_cache[path] = sig
        flags = []
        if is_suspicious_path(path):
            flags.append('USER_DIR_EXEC')
        if is_typosquat(name):
            flags.append('NAME_TYPO')
        if ('powershell' in name.lower()) and ('-enc' in cmd.lower()):
            flags.append('ENCODED_PS')
        ports = sorted(list(pid_ports.get(int(pid), set()))) if isinstance(pid, int) else []
        if ports:
            flags.append('LISTENING')
        if sig not in ('Valid', 'Trusted', 'SignatureValid'):
            flags.append('UNSIGNED_OR_INVALID')
        if f_unsigned and not ('UNSIGNED_OR_INVALID' in flags):
            continue
        if f_suspath and not is_suspicious_path(path):
            continue
        if f_port and (f_port not in ports):
            continue
        if f_name and f_name not in name.lower():
            continue
        rows_p.append({
            'pid': pid, 'name': name, 'signed': sig, 'ports': ports, 'flags': ",".join(flags), 'path': path
        })
        if 'UNSIGNED_OR_INVALID' in flags or 'USER_DIR_EXEC' in flags or 'NAME_TYPO' in flags:
            if path:
                hash_targets.add(path)

    if total_p > 0:
        spinner.stop()

    # --- Services ---
    spinner.start(t("spin_enum_svc"))
    srvs = get_services()
    spinner.stop()

    rows_s = []
    total_s = len(srvs) if isinstance(srvs, list) else 0

    for i, s in enumerate(srvs if isinstance(srvs, list) else []):
        name = s.get('Name') or ''
        disp = s.get('DisplayName') or ''
        state = s.get('State') or ''
        start = s.get('StartMode') or ''
        pn = s.get('PathName') or ''
        exe = extract_exe_from_pathname(pn)
        spinner.update(t("spin_sig_svc", i + 1, total_s))
        spinner.start() if i == 0 else None
        sig = sig_cache.get(exe)
        if sig is None:
            sig = check_signature(exe)
            sig_cache[exe] = sig
        flags = []
        if is_suspicious_path(exe):
            flags.append('USER_DIR_EXEC')
        if sig not in ('Valid', 'Trusted', 'SignatureValid'):
            flags.append('UNSIGNED_OR_INVALID')
        if start.lower() == 'auto' and ('USER_DIR_EXEC' in flags):
            flags.append('PERSIST_AUTO_SUS')
        if f_unsigned and not ('UNSIGNED_OR_INVALID' in flags):
            continue
        if f_suspath and not is_suspicious_path(exe):
            continue
        if f_name and (f_name not in name.lower() and f_name not in disp.lower()):
            continue
        rows_s.append({
            'name': name, 'display': disp, 'state': state, 'start': start, 'signed': sig, 'flags': ",".join(flags), 'exe': exe
        })
        if 'UNSIGNED_OR_INVALID' in flags or 'USER_DIR_EXEC' in flags or 'PERSIST_AUTO_SUS' in flags:
            if exe:
                hash_targets.add(exe)

    if total_s > 0:
        spinner.stop()

    # Format output
    def fmt_procs(rows):
        out = []
        out.append("PID   | Name                 | Signed         | Ports      | Flags                 | Path")
        out.append("-"*120)
        for r in sorted(rows, key=lambda x: (str(x['name']).lower(), int(x['pid']) if isinstance(x['pid'], int) else 0)):
            ports = ",".join(r['ports']) if isinstance(r['ports'], list) else ''
            out.append(f"{str(r['pid']):<5} | {r['name'][:20]:<20} | {r['signed'][:14]:<14} | {ports[:10]:<10} | {r['flags'][:21]:<21} | {r['path']}")
        return "\n".join(out)

    def fmt_services(rows):
        out = []
        out.append("Name                 | State   | Start  | Signed         | Flags                 | Exec Path")
        out.append("-"*120)
        for r in sorted(rows, key=lambda x: x['name'].lower()):
            out.append(f"{r['name'][:20]:<20} | {r['state'][:7]:<7} | {r['start'][:6]:<6} | {r['signed'][:14]:<14} | {r['flags'][:21]:<21} | {r['exe']}")
        return "\n".join(out)

    out.append("\n[Processes]\n" + (fmt_procs(rows_p) if rows_p else "(no matches)"))
    out.append("\n[Services]\n" + (fmt_services(rows_s) if rows_s else "(no matches)"))

    # Drivers (raw)
    spinner.start(t("spin_drivers"))
    drivers_raw = get_drivers_raw()
    spinner.stop()
    out.append("\n[Drivers — driverquery /v]\n" + drivers_raw)

    # Hashes for flagged binaries (limit to 150)
    out.append("\n[SHA256 for flagged binaries]\n")
    hash_list = sorted(hash_targets)
    spinner.start(t("spin_hashes", 0, len(hash_list)))
    for i, pth in enumerate(hash_list):
        if i >= 150:
            out.append("(truncated)")
            break
        spinner.update(t("spin_hashes", i + 1, len(hash_list)))
        h = sha256_file(pth)
        out.append(f"{pth} -> {h if h else 'hash_error_or_missing'}")
    spinner.stop()

    content = "\n".join(out)
    print(content)
    export_prompt("processes_services", content)

# ==========================
# 4) Persistence (Run Keys, Startup, Tasks, WMI, IFEO) — Enhanced
# ==========================

def mod_persistence():
    out = []
    out.append(header("Persistence Checks"))

    # Interactive filter for new items (days)
    print("Show only items modified in last N days? (blank = all): ", end=""); ndays = input().strip()
    try:
        ndays = int(ndays) if ndays else None
    except Exception:
        ndays = None

    def filter_recent(path):
        if not ndays:
            return True
        try:
            stat = os.stat(path)
            age_days = (datetime.now() - datetime.fromtimestamp(stat.st_mtime)).days
            return age_days <= ndays
        except Exception:
            return True

    # Run keys
    run_keys = [
        r"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        r"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        r"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        r"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
    ]
    for k in run_keys:
        out.append(f"[CMD] reg query {k}\n" + run_cmd(f"reg query {k}"))

    # Startup folders (filter by recency)
    for path in [r"%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup", r"C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"]:
        exp = os.path.expandvars(path)
        listing = []
        try:
            for fn in os.listdir(exp):
                fpath = os.path.join(exp, fn)
                if filter_recent(fpath):
                    listing.append(fn)
        except Exception as e:
            listing.append(f"error: {e}")
        out.append(f"[Startup folder] {path}\n" + "\n".join(listing))

    # Scheduled tasks
    tasks = run_cmd("schtasks /query /fo LIST /v")
    if ndays:
        # Rough filter by date string present
        lines = []
        for line in tasks.splitlines():
            if "Created:" in line or "Last Run Time:" in line:
                lines.append(line)
            elif ndays and any(str(y) in line for y in range(datetime.now().year-1, datetime.now().year+1)):
                lines.append(line)
        out.append("[CMD] schtasks (filtered)\n" + "\n".join(lines))
    else:
        out.append("[CMD] schtasks /query /fo LIST /v\n" + tasks)

    # WMI Subscriptions
    out.append("[CMD] WMI __EventFilter\n" + run_cmd(r"wmic /namespace:\\root\\subscription PATH __EventFilter get * /format:list"))
    out.append("[CMD] WMI CommandLineEventConsumer\n" + run_cmd(r"wmic /namespace:\\root\\subscription PATH CommandLineEventConsumer get * /format:list"))
    out.append("[CMD] WMI __FilterToConsumerBinding\n" + run_cmd(r"wmic /namespace:\\root\\subscription PATH __FilterToConsumerBinding get * /format:list"))

    # IFEO & Shell/Userinit
    out.append("[CMD] IFEO\n" + run_cmd("reg query \"HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\""))
    out.append("[CMD] Winlogon Shell\n" + run_cmd("reg query \"HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" /v Shell"))
    out.append("[CMD] Winlogon Userinit\n" + run_cmd("reg query \"HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" /v Userinit"))

    # Baseline/diff
    print("Compare against baseline persistence JSON? (path or blank): ", end=""); p = input().strip()
    if p and os.path.isfile(p):
        try:
            with open(p,"r",encoding="utf-8",errors="replace") as f: old = json.load(f)
            diff = {"added":[],"removed":[]}
            cur = tasks.splitlines()
            prev = old.get("tasks",[])
            diff["added"] = [l for l in cur if l not in prev]
            diff["removed"] = [l for l in prev if l not in cur]
            out.append("[Baseline diff — tasks]\n" + json.dumps(diff,indent=2))
        except Exception as e:
            out.append(f"[Baseline diff error] {e}")

    content = "\n".join(out)
    print(content)
    maybe_export("persistence", content)

# ==========================
# 5) Event Logs / Threat Hunting (IDs + since + grep + highlights)
# ==========================

def mod_event_logs():
    out = []
    out.append(header("Event Logs / Threat Hunting"))

    # Interactive parameters
    print("Hours to look back (default 24): ", end=""); sin = input().strip()
    try:
        since_h = int(sin) if sin else 24
    except Exception:
        since_h = 24

    print("Event IDs (comma-separated) or blank for default set: ", end=""); ids_in = input().strip()
    default_ids = "4624,4625,4672,4688,4698,7045,4720,4732,4733"
    ids_str = ids_in if ids_in else default_ids
    ids_list = [i for i in [s.strip() for s in ids_str.split(',')] if i.isdigit()]
    ids_ps = ",".join(ids_list) if ids_list else default_ids

    print("Grep regex (case-insensitive) to filter Message (blank = none): ", end=""); grep_re = input().strip()

    # PowerShell query (Security + small System/Application tails)
    ps = f"""
    $since = (Get-Date).AddHours(-{since_h})
    $ids = @({ids_ps})
    Write-Output "== Security Log (since: $since; ids: $($ids -join ', ')) =="
    try {{
      Get-WinEvent -FilterHashtable @{{LogName='Security'; StartTime=$since; Id=$ids}} |
        Select-Object TimeCreated, Id, ProviderName, Message |
        Format-Table -Wrap -AutoSize
    }} catch {{ Write-Output "[error] Security log query failed: $($_)" }}

    Write-Output "`n== System (last 50) =="
    try {{ Get-WinEvent -LogName System -MaxEvents 50 | Select-Object TimeCreated, Id, Message | Format-Table -Wrap -AutoSize }} catch {{}}

    Write-Output "`n== Application (last 50) =="
    try {{ Get-WinEvent -LogName Application -MaxEvents 50 | Select-Object TimeCreated, Id, Message | Format-Table -Wrap -AutoSize }} catch {{}}
    """

    sec_text = run_ps(ps)
    out.append(sec_text)

    # Highlights (simple heuristics + optional grep)
    HINTS = [r"-enc", r"-nop", r"mshta", r"rundll32", r"regsvr32", r"wscript", r"cscript",
             r"powershell.exe", r"certutil", r"bitsadmin", r"\bbase64\b", r"curl ", r"ftp "]
    highlight_lines = []
    for line in sec_text.splitlines():
        L = line.lower()
        if any(h.lower() in L for h in HINTS):
            highlight_lines.append(line)
        if grep_re:
            try:
                if re.search(grep_re, line, re.IGNORECASE):
                    highlight_lines.append(line)
            except Exception:
                pass

    if highlight_lines:
        out.append("\n[HIGHLIGHTS — suspicious patterns / grep matches]\n" +
                   "\n".join(dict.fromkeys(highlight_lines)))  # dedupe while preserving order

    content = "\n".join(out)
    print(content)
    maybe_export("event_logs", content)

# ==========================
# 6) Windows Defender (status, threats, scans)
# ==========================

def mod_defender():
    out = []
    out.append(header("Windows Defender — Status & Scans"))

    # Show status summary
    ps_status = "Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,AntispywareEnabled,RealTimeProtectionEnabled,IoavProtectionEnabled,BehaviorMonitorEnabled,OnAccessProtectionEnabled,AMProductVersion | Format-List"
    out.append("[PS] Defender status summary\n" + run_ps(ps_status))

    # Threats seen
    ps_threats = "Get-MpThreat | Format-Table -AutoSize"
    out.append("\n[PS] Detected threats (if any)\n" + run_ps(ps_threats))

    # Preferences (to see exclusions etc.)
    ps_pref = "Get-MpPreference | Select-Object DisableRealtimeMonitoring,ExclusionPath,ExclusionProcess,ExclusionExtension | Format-List"
    out.append("\n[PS] Defender preferences (notable exclusions / realtime)\n" + run_ps(ps_pref))

    # Offer scans
    print("Run a quick scan now? (y/N): ", end=""); ans = input().strip().lower()
    if ans.startswith("y"):
        out.append("\n[PS] Start-MpScan -ScanType QuickScan\n" + run_ps("Start-MpScan -ScanType QuickScan"))
    print("Run a full scan now? (y/N): ", end=""); ans2 = input().strip().lower()
    if ans2.startswith("y"):
        out.append("\n[PS] Start-MpScan -ScanType FullScan\n" + run_ps("Start-MpScan -ScanType FullScan"))

    # Offer signature update
    print("Update signatures before scan? (y/N): ", end=""); ans3 = input().strip().lower()
    if ans3.startswith("y"):
        out.append("\n[PS] Update-MpSignature\n" + run_ps("Update-MpSignature"))

    content = "\n".join(out)
    print(content)
    maybe_export("defender", content)

# ==========================
# 7) Security Policies / Audit / Firewall
# ==========================

def mod_policies():
    out = []
    out.append(header("Security Policies / Audit / Firewall"))

    # Audit policy
    out.append("[CMD] auditpol /get /category:*\n" + run_cmd("auditpol /get /category:*"))

    # Security configuration export
    out.append("\n[CMD] secedit /export /cfg secedit_export.cfg\n" + run_cmd("secedit /export /cfg secedit_export.cfg"))

    # Firewall profiles
    out.append("\n[CMD] netsh advfirewall show allprofiles\n" + run_cmd("netsh advfirewall show allprofiles"))

    # RDP configuration checks
    out.append("\n[CMD] reg query \"HKLM\\System\\CurrentControlSet\\Control\\Terminal Server\" /v fDenyTSConnections\n" + run_cmd("reg query \"HKLM\\System\\CurrentControlSet\\Control\\Terminal Server\" /v fDenyTSConnections"))
    out.append("\n[CMD] reg query \"HKLM\\System\\CurrentControlSet\\Control\\Terminal Server\" /v UserAuthentication\n" + run_cmd("reg query \"HKLM\\System\\CurrentControlSet\\Control\\Terminal Server\" /v UserAuthentication"))

    # Optional summarization of audit gaps
    audit_txt = run_cmd("auditpol /get /category:*")
    gaps = []
    for line in audit_txt.splitlines():
        if "No Auditing" in line:
            gaps.append(line.strip())
    if gaps:
        out.append("\n[!] Audit categories with NO auditing enabled:\n" + "\n".join(gaps))

    content = "\n".join(out)
    print(content)
    maybe_export("policies", content)

# ==========================
# 8) Quick Forensics — recent/suspicious files
# ==========================

def list_recent_files(paths, days=7, exts=None, min_bytes=0, max_bytes=None):
    limit = datetime.now().timestamp() - (days*86400)
    rows = []
    for base in paths:
        base = os.path.expandvars(base)
        if not os.path.isdir(base):
            continue
        for root, dirs, files in os.walk(base):
            for fn in files:
                fpath = os.path.join(root, fn)
                try:
                    stat = os.stat(fpath)
                    if stat.st_mtime < limit:
                        continue
                    if min_bytes and stat.st_size < min_bytes:
                        continue
                    if max_bytes and stat.st_size > max_bytes:
                        continue
                    if exts:
                        if not any(fn.lower().endswith(e.lower()) for e in exts):
                            continue
                    rows.append((datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"), fpath, stat.st_size))
                except Exception:
                    continue
    rows.sort(key=lambda x: x[0], reverse=True)
    return rows


def mod_quick_forensics():
    out = []
    out.append(header("Quick Forensics — recent files"))

    print(t("days_back", 7), end=""); d = input().strip()
    try: days = int(d) if d else 7
    except: days = 7

    print(t("ext_filter"), end=""); e = input().strip()
    exts = [x.strip() for x in e.split(',') if x.strip()] if e else None

    print(t("min_size"), end=""); m1 = input().strip()
    try: min_b = int(m1) if m1 else 0
    except: min_b = 0

    print(t("max_size"), end=""); m2 = input().strip()
    try: max_b = int(m2) if m2 else None
    except: max_b = None

    targets = [r"%TEMP%", r"%APPDATA%", r"%LOCALAPPDATA%", r"C:\\ProgramData", r"%USERPROFILE%\\Downloads", r"%USERPROFILE%\\Desktop"]

    spinner = Spinner()
    rows: list = []

    cutoff = datetime.now().timestamp() - days * 86400
    for target in targets:
        exp = os.path.expandvars(target)
        spinner.start(t("spin_scan_dir", exp))
        for root, _dirs, files in os.walk(exp):
            spinner.update(t("spin_scan_dir", root[:70]))
            for fn in files:
                fpath = os.path.join(root, fn)
                try:
                    stat = os.stat(fpath)
                    if stat.st_mtime < cutoff:
                        continue
                    if min_b and stat.st_size < min_b:
                        continue
                    if max_b and stat.st_size > max_b:
                        continue
                    if exts:
                        if not any(fn.lower().endswith(ex.lower()) for ex in exts):
                            continue
                    rows.append((datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"), fpath, stat.st_size))
                except Exception:
                    continue
        spinner.stop()

    spinner.start(t("spin_sorting"))
    rows.sort(key=lambda x: x[0], reverse=True)
    spinner.stop()

    if not rows:
        out.append("No recent files found under given criteria.")
    else:
        out.append("TimeModified           | Size(bytes) | Path")
        out.append("-"*100)
        for r in rows[:1000]:
            out.append(f"{r[0]} | {r[2]} | {r[1]}")
        if len(rows) > 1000:
            out.append(f"... truncated {len(rows)-1000} more entries ...")

    content = "\n".join(out)
    print(content)
    maybe_export("quick_forensics", content)

# ==========================
# 9) Threat Hunting — quick wins (last 24h)
# ==========================

def mod_hunting_quickwins():
    out = []
    out.append(header("Threat Hunting — Quick Wins (last 24h)"))

    # Ask how many hours back
    print("Hours to look back (default 24): ", end=""); sin = input().strip()
    try:
        since_h = int(sin) if sin else 24
    except Exception:
        since_h = 24

    # Build PS script
    ps = f"""
    $since = (Get-Date).AddHours(-{since_h})
    $ids = 4624,4625,4672,4688,4698,7045,4720
    Write-Output "== Security events since $since =="
    Get-WinEvent -FilterHashtable @{{LogName='Security'; StartTime=$since; Id=$ids}} |
      Select-Object TimeCreated, Id, Message |
      Format-Table -Wrap -AutoSize

    Write-Output "\n== TaskScheduler created tasks (Id 106) =="
    if ((Get-WinEvent -ListLog 'Microsoft-Windows-TaskScheduler/Operational' -ErrorAction SilentlyContinue)) {{
      Get-WinEvent -FilterHashtable @{{LogName='Microsoft-Windows-TaskScheduler/Operational'; StartTime=$since; Id=106}} |
        Select-Object TimeCreated, Id, Message |
        Format-Table -Wrap -AutoSize
    }} else {{ Write-Output "TaskScheduler log not enabled." }}
    """

    events = run_ps(ps)
    out.append(events)

    # Score heuristics
    score_items = []
    for line in events.splitlines():
        l = line.lower()
        pts = 0
        if "logon type 3" in l or "logon type 10" in l:
            pts += 1
        if any(x in l for x in ["-enc","-nop","mshta","rundll32","wscript","regsvr32","certutil"]):
            pts += 3
        if "service" in l and "created" in l:
            pts += 2
        if "task" in l and "created" in l:
            pts += 2
        if pts>0:
            score_items.append((pts,line))
    if score_items:
        score_items.sort(key=lambda x: -x[0])
        out.append("\n[Top suspicious entries scored]\n")
        for pts, line in score_items[:50]:
            out.append(f"[{pts}] {line}")

    content = "\n".join(out)
    print(content)
    maybe_export("hunting_quickwins", content)

# ==========================
# 10) Incident Response — bundle snapshot
# ==========================

def mod_incident_response():
    out = []
    out.append(header("Incident Response — Bundle Snapshot"))

    # Processes
    out.append("[CMD] tasklist /v\n" + run_cmd("tasklist /v"))

    # Netstat
    out.append("\n[CMD] netstat -ano\n" + run_cmd("netstat -ano"))

    # Services
    out.append("\n[CMD] sc query type= service state= all\n" + run_cmd("sc query type= service state= all"))

    # Scheduled tasks
    out.append("\n[CMD] schtasks /query /fo LIST /v\n" + run_cmd("schtasks /query /fo LIST /v"))

    # Persistence keys
    run_keys = [
        r"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        r"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    ]
    for k in run_keys:
        out.append(f"\n[CMD] reg query {k}\n" + run_cmd(f"reg query {k}"))

    # Event logs sample
    ps = r'''
    $ids = 4624,4625,4672,4688,4720,7045
    $sec = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=$ids} -MaxEvents 200 |
      Select-Object TimeCreated, Id, Message | Out-String -Width 500
    $sys = Get-WinEvent -LogName System -MaxEvents 100 | Select-Object TimeCreated, Id, Message | Out-String -Width 500
    $app = Get-WinEvent -LogName Application -MaxEvents 100 | Select-Object TimeCreated, Id, Message | Out-String -Width 500
    Write-Output "[SECURITY]\n$sec\n[SYSTEM]\n$sys\n[APPLICATION]\n$app"
    '''
    out.append("\n[PS] Event Logs (Security/System/Application)\n" + run_ps(ps))

    # Package export: ask user if zip all
    content = "\n".join(out)
    print(content)

    print("Export as a bundle ZIP? (y/N): ", end=""); ans = input().strip().lower()
    if ans.startswith("y"):
        import zipfile, tempfile
        tmpdir = tempfile.mkdtemp()
        mainfile = os.path.join(tmpdir,"ir_bundle.txt")
        with open(mainfile,"w",encoding="utf-8",errors="replace") as f:
            f.write(content)
        zipname = f"incident_response_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
        with zipfile.ZipFile(zipname,"w",zipfile.ZIP_DEFLATED) as z:
            z.write(mainfile,arcname="ir_bundle.txt")
        print(f"[+] Bundle exported to {zipname}")
    else:
        maybe_export("incident_response", content)

# ==========================
# 11) Remote Assessment — PowerShell Remoting
# ==========================

def mod_remote_assessment():
    out = []
    out.append(header("Remote Assessment — PowerShell Remoting"))

    print("Target computer (hostname or IP): ", end=""); target = input().strip()
    if not target:
        print("[-] No target provided.")
        return

    print("Use current credentials (y) or specify new credentials (n)? (y/N): ", end=""); usecur = input().strip().lower()
    cred_str = ""
    if usecur.startswith("n"):
        cred_str = " -Credential (Get-Credential) "

    ps = f'''
    try {{
      Invoke-Command -ComputerName {target} {cred_str} -ScriptBlock {{
        $admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        Write-Output ('Hostname: ' + $env:COMPUTERNAME)
        Write-Output ('Admin: ' + $admin)

        Write-Output "\n== Top 15 Processes by memory =="
        Get-Process | Sort-Object WS -Descending | Select-Object -First 15 Name,Id,WS | Format-Table -AutoSize | Out-String -Width 500

        Write-Output "\n== Netstat (TCP connections) =="
        netstat -ano | Out-String -Width 500

        Write-Output "\n== Running Services =="
        Get-Service | Where-Object {{$_.Status -eq 'Running'}} | Select-Object Name,DisplayName,Status | Format-Table -AutoSize | Out-String -Width 500

        Write-Output "\n== Recent Security Events (4624,4625,4688,7045) =="
        $ids = 4624,4625,4688,7045
        Get-WinEvent -FilterHashtable @{{LogName='Security'; Id=$ids}} -MaxEvents 50 |
          Select-Object TimeCreated, Id, Message | Out-String -Width 500
      }}
    }} catch {{ Write-Output "[error] Remote command failed: $($_)" }}
    '''

    result = run_ps(ps)
    out.append(result)

    content = "\n".join(out)
    print(content)
    maybe_export("remote_assessment", content)

# ==========================
# 12) Security Summary — Consolidated Score
# ==========================

def mod_security_summary():
    out = []
    out.append(header("Security Summary — Consolidated"))

    # Hours window
    print("Hours to look back (default 72): ", end=""); sin = input().strip()
    try:
        since_h = int(sin) if sin else 72
    except Exception:
        since_h = 72

    # 1) Defender status (JSON via PS)
    ps_def_json = (
        "try { Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,AntispywareEnabled,"
        "RealTimeProtectionEnabled,IoavProtectionEnabled,BehaviorMonitorEnabled,OnAccessProtectionEnabled,AMProductVersion "
        "| ConvertTo-Json -Depth 2 } catch { '{}' }"
    )
    def_raw = run_ps(ps_def_json)
    try:
        def_stat = json.loads(def_raw)
    except Exception:
        def_stat = {}

    # 2) Firewall profiles
    fw_txt = run_cmd("netsh advfirewall show allprofiles")

    # 3) Audit policy
    audit_txt = run_cmd("auditpol /get /category:*")

    # 4) RDP config (enabled? NLA?)
    rdp_deny = run_cmd("reg query \"HKLM\\System\\CurrentControlSet\\Control\\Terminal Server\" /v fDenyTSConnections")
    rdp_nla  = run_cmd("reg query \"HKLM\\System\\CurrentControlSet\\Control\\Terminal Server\" /v UserAuthentication")

    # 5) Recent risky events
    ps_events = f"""
    $since = (Get-Date).AddHours(-{since_h})
    $ids = 4625,4688,4698,4720,7045
    Get-WinEvent -FilterHashtable @{{LogName='Security'; StartTime=$since; Id=$ids}} |
      Select-Object TimeCreated, Id, Message | ConvertTo-Json -Depth 3
    """
    ev_raw = run_ps(ps_events)
    try:
        events = json.loads(ev_raw)
        if isinstance(events, dict):
            events = [events]
    except Exception:
        events = []

    # ---- scoring
    score = 100
    notes = []

    # Defender realtime
    def_ok = bool(def_stat.get('AntivirusEnabled')) and bool(def_stat.get('RealTimeProtectionEnabled'))
    if not def_ok:
        score -= 20; notes.append("Defender realtime protection is OFF or unavailable.")

    # Firewall profiles ON?
    import re as _re
    profiles = {
        'Domain': bool(_re.search(r"Domain Profile Settings[\\s\\S]*?State\\s*ON", fw_txt, _re.IGNORECASE)),
        'Private': bool(_re.search(r"Private Profile Settings[\\s\\S]*?State\\s*ON", fw_txt, _re.IGNORECASE)),
        'Public': bool(_re.search(r"Public Profile Settings[\\s\\S]*?State\\s*ON", fw_txt, _re.IGNORECASE)),
    }
    if not all(profiles.values()):
        score -= 15; notes.append("Firewall is OFF in one or more profiles (Domain/Private/Public).")

    # Audit gaps
    gaps = [ln.strip() for ln in audit_txt.splitlines() if "No Auditing" in ln]
    if gaps:
        score -= 10; notes.append("Audit policy has categories with NO Auditing enabled.")

    # RDP + NLA
    rdp_open = ('0x0' in rdp_deny.lower() or '\t0' in rdp_deny.lower())  # 0 => allow connections
    nla_on   = ('0x1' in rdp_nla.lower()  or '\t1' in rdp_nla.lower())
    if rdp_open and not nla_on:
        score -= 15; notes.append("RDP is enabled without Network Level Authentication (NLA).")

    # Event-based signals
    failed_logons    = sum(1 for e in events if e.get('Id') == 4625)
    service_created  = sum(1 for e in events if e.get('Id') == 7045)
    task_created     = sum(1 for e in events if e.get('Id') == 4698)
    user_created     = sum(1 for e in events if e.get('Id') == 4720)
    SUSP_KW = ['-enc','-nop','mshta','rundll32','wscript','cscript','regsvr32','certutil','bitsadmin']
    suspicious_4688  = sum(1 for e in events if e.get('Id') == 4688 and any(k in (e.get('Message') or '').lower() for k in SUSP_KW))

    if failed_logons > 20:
        score -= 10; notes.append(f"{failed_logons} failed logons in last {since_h}h.")
    if service_created > 0:
        score -= 10; notes.append(f"{service_created} service(s) created (7045).")
    if task_created > 0:
        score -= 8;  notes.append(f"{task_created} scheduled task(s) created (4698).")
    if user_created > 0:
        score -= 10; notes.append(f"{user_created} local user account(s) created (4720).")
    if suspicious_4688 > 0:
        score -= 10; notes.append(f"{suspicious_4688} suspicious process creation event(s) (4688).")

    score = max(0, min(100, score))

    # ---- output
    out.append("Defender:    " + ("OK (Realtime ON)" if def_ok else "Issue (Realtime OFF/NA)"))
    out.append("Firewall:    " + ("All profiles ON" if all(profiles.values()) else f"Profiles with issues: {[k for k,v in profiles.items() if not v]}"))
    out.append("Audit gaps:  " + ("None detected" if not gaps else f"{len(gaps)} lines with 'No Auditing'"))
    out.append(f"RDP/NLA:     RDP={'ENABLED' if rdp_open else 'DISABLED'}; NLA={'ON' if nla_on else 'OFF'}")
    out.append(f"Events:      4625={failed_logons}, 7045={service_created}, 4698={task_created}, 4720={user_created}, 4688_susp={suspicious_4688}")

    out.append("\nSCORE (0-100): " + str(score))

    # Top remediation tips (max 3)
    hints = []
    if not def_ok:
        hints.append("Enable Defender realtime and update engine/signatures.")
    if not all(profiles.values()):
        hints.append("Enable Windows Firewall for all profiles and review inbound rules.")
    if rdp_open and not nla_on:
        hints.append("Require NLA for RDP or disable RDP if not needed.")
    if gaps:
        hints.append("Enable auditing for critical categories (Logon, Account Mgmt, Detailed Tracking).")
    if service_created or task_created or suspicious_4688:
        hints.append("Investigate newly created services/tasks and suspicious process launches.")

    if hints:
        out.append("\nRemediation (top):\n- " + "\n- ".join(hints[:3]))
    if notes:
        out.append("\nNotes:\n- " + "\n- ".join(notes))

    content = "\n".join(out)
    print(content)
    maybe_export("security_summary", content)

# ==========================
# [13] Token Privileges — ctypes + Windows API
# ==========================

# --- Constantes nomeadas (winnt.h) — NÃO alterar para magic numbers ---
SE_PRIVILEGE_ENABLED            = 0x00000002
SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001
SE_PRIVILEGE_REMOVED            = 0x00000004
SE_PRIVILEGE_USED_FOR_ACCESS    = 0x00080000
TOKEN_QUERY                     = 0x0008
TokenPrivileges                 = 20  # TOKEN_INFORMATION_CLASS


class _LUID(ctypes.Structure):
    _fields_ = [
        ("LowPart",  ctypes.c_ulong),
        ("HighPart", ctypes.c_long),
    ]


class _LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("Luid",       _LUID),
        ("Attributes", ctypes.c_ulong),
    ]


class _TOKEN_PRIVILEGES(ctypes.Structure):
    """Placeholder com 1 entrada; cast dinâmico alocado via create_string_buffer."""
    _fields_ = [
        ("PrivilegeCount", ctypes.c_ulong),
        ("Privileges",     _LUID_AND_ATTRIBUTES * 1),
    ]


def mod_token_privileges() -> None:
    """
    Lista privilégios do token atual via ctypes + Windows API.
    Output: print() formatado + opção de export via write_file().
    Requer: Windows, privilégios de leitura de token (user ou admin).
    """
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    out = []
    out.append(header("[13] Token Privileges — Windows API (ctypes)"))

    # Verificação explícita de ctypes.wintypes antes de qualquer uso
    try:
        import ctypes.wintypes as _wintypes
        _HANDLE = _wintypes.HANDLE
        _DWORD  = _wintypes.DWORD
    except (ImportError, AttributeError):
        msg = t("token_no_wintypes")
        print(msg)
        return

    if not is_admin():
        warn = t("token_admin_warn")
        print(warn)
        out.append(warn + "\n")

    if not is_windows():
        msg = "[error] Este módulo requer Windows."
        print(msg)
        return

    kernel32  = ctypes.windll.kernel32
    advapi32  = ctypes.windll.advapi32

    hProcess = kernel32.GetCurrentProcess()
    hToken   = _HANDLE()

    if not advapi32.OpenProcessToken(hProcess, TOKEN_QUERY, ctypes.byref(hToken)):
        err = ctypes.WinError(ctypes.get_last_error())
        msg = t("token_open_err", err)
        print(msg)
        out.append(msg)
        return

    try:
        # --- 1ª chamada: obter tamanho necessário do buffer ---
        return_length = _DWORD(0)
        advapi32.GetTokenInformation(
            hToken,
            TokenPrivileges,
            None,
            0,
            ctypes.byref(return_length),
        )

        if return_length.value == 0:
            raise ctypes.WinError(ctypes.get_last_error())

        # --- Alocação segura via create_string_buffer (sem divisão inteira) ---
        buffer = ctypes.create_string_buffer(return_length.value)

        # --- 2ª chamada: preencher buffer ---
        success = advapi32.GetTokenInformation(
            hToken,
            TokenPrivileges,
            buffer,
            return_length,
            ctypes.byref(return_length),
        )
        if not success:
            raise ctypes.WinError(ctypes.get_last_error())

        # --- Cast dinâmico para estrutura TOKEN_PRIVILEGES ---
        tp = ctypes.cast(buffer, ctypes.POINTER(_TOKEN_PRIVILEGES)).contents
        count = tp.PrivilegeCount

        # Reinterpretar Privileges[] com o tamanho real
        LuidAttrArray = _LUID_AND_ATTRIBUTES * count
        privileges = ctypes.cast(
            ctypes.addressof(tp.Privileges),
            ctypes.POINTER(LuidAttrArray),
        ).contents

        # --- Cabeçalho da tabela ---
        col_name  = 45
        col_attr  = 35
        col_luid  = 20
        sep = f"{'─' * col_name}+{'─' * col_attr}+{'─' * col_luid}"
        hdr = f"{'Privilege Name':<{col_name}}| {'Attributes':<{col_attr}}| {'LUID (High:Low)':<{col_luid}}"
        out.append(t("token_count", count) + "\n")
        out.append(hdr)
        out.append(sep)

        name_buf  = ctypes.create_unicode_buffer(256)
        name_size = _DWORD(256)

        for i in range(count):
            luid  = privileges[i].Luid
            attrs = privileges[i].Attributes

            # LookupPrivilegeNameW — resolve LUID → nome legível
            name_size.value = 256
            ok = advapi32.LookupPrivilegeNameW(
                None,
                ctypes.byref(luid),
                name_buf,
                ctypes.byref(name_size),
            )
            priv_name = name_buf.value if ok else f"<unknown:{luid.HighPart}:{luid.LowPart}>"

            # Decodificar todos os flags (exibir TODOS, inclusive Disabled)
            flags = []
            if attrs & SE_PRIVILEGE_ENABLED:            flags.append("Enabled")
            if attrs & SE_PRIVILEGE_ENABLED_BY_DEFAULT: flags.append("Default")
            if attrs & SE_PRIVILEGE_REMOVED:            flags.append("Removed")
            if attrs & SE_PRIVILEGE_USED_FOR_ACCESS:    flags.append("UsedForAccess")
            attr_str = " | ".join(flags) if flags else "Disabled"

            luid_str = f"{luid.HighPart}:{luid.LowPart}"
            row = f"{priv_name:<{col_name}}| {attr_str:<{col_attr}}| {luid_str:<{col_luid}}"
            out.append(row)

        out.append(sep)

    except ctypes.WinError as we:
        msg = t("token_api_err", we)
        print(msg)
        out.append(msg)
    finally:
        # CloseHandle SEMPRE executado, independente de erros
        kernel32.CloseHandle(hToken)

    content = "\n".join(out)
    print(content)
    write_file("token_privileges", content, ext="txt")
    print(t("token_exported"))
    maybe_export("token_privileges", content)


# ==========================
# Menu
# ==========================

def print_menu():
    admin_str = t("menu_admin_yes") if is_admin() else t("menu_admin_no")
    print(" "*104)
    print(t("menu_title"))
    print("\033[4;34mGitHub: https://github.com/ThaynerKesley\033[0m")
    print(f"{t('menu_os')}: {platform.platform()} | {t('menu_admin')}: {admin_str} | {t('menu_time')}: {now_str()}")
    print(" "*104)
    print("-"*104)
    print("1)  System Information")
    print("2)  Network Analysis")
    print("3)  Processes & Services")
    print("4)  Persistence (Run Keys / Startup / Tasks / WMI / IFEO)")
    print("5)  Event Logs / Threat Hunting")
    print("6)  Windows Defender (status & scans)")
    print("7)  Security Policies / Audit / Firewall")
    print("8)  Quick Forensics (recent files)")
    print("9)  Threat Hunting — Quick Wins")
    print("10) Incident Response — Bundle Snapshot")
    print("11) Remote Assessment (PowerShell Remoting)")
    print("12) Security Summary — Consolidated Score")
    print("13) Token Privileges — Windows API (ctypes)")
    print("0)  Exit")
    print("-"*104)

actions = {
    "1":  mod_system_info,
    "2":  mod_network_analysis,
    "3":  mod_process_services,
    "4":  mod_persistence,
    "5":  mod_event_logs,
    "6":  mod_defender,
    "7":  mod_policies,
    "8":  mod_quick_forensics,
    "9":  mod_hunting_quickwins,
    "10": mod_incident_response,
    "11": mod_remote_assessment,
    "12": mod_security_summary,
    "13": mod_token_privileges,
}

def main():
    if not is_windows():
        print(t("os_only_windows"))
        sys.exit(1)
    while True:
        print_menu()
        choice = input(t("select_option")).strip()
        if choice == "0":
            break
        func = actions.get(choice)
        if func:
            func()
        else:
            print(t("invalid_option"))


if __name__ == "__main__":
    main()