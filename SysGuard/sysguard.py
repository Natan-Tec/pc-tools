#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SysGuard - utilitario de seguranca e diagnostico para Windows
Complemento ao Windows Defender (nao substitui antivirus).

Abas: Hosts | Sistema | Disco | Integridade | Arquivos suspeitos | Limpeza | Registro
Dependencia opcional: psutil  (pip install psutil)
"""
import os
import re
import sys
import json
import time
import stat
import queue
import shutil
import socket
import hashlib
import platform
import datetime
import threading
import subprocess
import webbrowser
import tempfile
from pathlib import Path

import tkinter as tk
from tkinter import ttk, messagebox, filedialog

try:
    import psutil
except ImportError:  # app continua funcionando sem psutil, com menos dados
    psutil = None

APP_NAME = "SysGuard"
APP_VERSION = "0.1"
IS_WIN = os.name == "nt"

# ----------------------------------------------------------------------------
# Pastas do app, log
# ----------------------------------------------------------------------------
APP_DIR = Path(os.environ.get("SYSGUARD_HOME") or
               (Path(os.environ.get("APPDATA", Path.home())) / "SysGuard"))
BACKUP_DIR = APP_DIR / "backups_hosts"
QUARANTINE_DIR = APP_DIR / "quarentena"
LOG_FILE = APP_DIR / "registro.log"
for _d in (APP_DIR, BACKUP_DIR, QUARANTINE_DIR):
    _d.mkdir(parents=True, exist_ok=True)

_log_lock = threading.Lock()
_log_listeners = []


def log(msg):
    line = f"[{datetime.datetime.now():%Y-%m-%d %H:%M:%S}] {msg}"
    with _log_lock:
        try:
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except OSError:
            pass
    for cb in list(_log_listeners):
        try:
            cb(line)
        except Exception:
            pass


def sizefmt(n):
    n = float(n or 0)
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or u == "TB":
            return f"{n:.0f} {u}" if u == "B" else f"{n:.1f} {u}"
        n /= 1024


def is_admin():
    try:
        if IS_WIN:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return False


def relaunch_as_admin():
    if not IS_WIN:
        return False
    import ctypes
    frozen = getattr(sys, "frozen", False)
    exe = sys.executable
    args = sys.argv[1:] if frozen else sys.argv
    params = " ".join(f'"{a}"' for a in args)
    r = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)
    return r > 32


def run_cmd(cmd, timeout=120, shell=False):
    """Executa comando e devolve texto (trata UTF-16 do sfc/dism)."""
    flags = 0x08000000 if IS_WIN else 0  # CREATE_NO_WINDOW
    p = subprocess.run(cmd, capture_output=True, timeout=timeout, shell=shell,
                       creationflags=flags)
    raw = (p.stdout or b"") + (p.stderr or b"")
    if b"\x00" in raw:
        text = raw.decode("utf-16-le", errors="replace")
    else:
        text = raw.decode("cp850" if IS_WIN else "utf-8", errors="replace")
    return p.returncode, text.replace("\r", "")


def powershell(script, timeout=60):
    rc, out = run_cmd(["powershell", "-NoProfile", "-NonInteractive",
                       "-ExecutionPolicy", "Bypass", "-Command", script],
                      timeout=timeout)
    return out


# ----------------------------------------------------------------------------
# HOSTS
# ----------------------------------------------------------------------------
def hosts_path():
    env = os.environ.get("SYSGUARD_HOSTS")
    if env:
        return Path(env)
    if IS_WIN:
        return Path(os.environ.get("SystemRoot", r"C:\Windows")) / \
            "System32" / "drivers" / "etc" / "hosts"
    return Path("/etc/hosts")


BLOCK_IPS = {"0.0.0.0", "127.0.0.1", "::1", "::", "0"}
DEFAULT_DOMAINS = {"localhost", "ip6-localhost", "ip6-loopback", "broadcasthost",
                   "ip6-allnodes", "ip6-allrouters", "ip6-localnet",
                   "ip6-mcastprefix"}

SECURITY_SHORT = {"avg", "eset", "avira", "avast", "norton", "mcafee"}
SECURITY_KEYS = [
    "malwarebytes", "kaspersky", "bitdefender", "symantec", "sophos",
    "trendmicro", "drweb", "f-secure", "fsecure", "pandasecurity", "comodo",
    "emsisoft", "hitmanpro", "clamav", "virustotal", "windowsdefender",
    "safebrowsing", "superantispyware", "zonealarm", "webroot", "gdata",
    "crowdstrike", "adaware", "spybot", "bleepingcomputer", "avast", "avira",
    "norton", "mcafee", "eset", "securityessentials", "defender.microsoft",
]
UPDATE_KEYS = ["windowsupdate", "update.microsoft", "download.microsoft",
               "sls.microsoft", "microsoft.com"]
PIRACY_KEYS = [
    "torrent", "repack", "piratebay", "pirate", "1337x", "rarbg", "fitgirl",
    "dodi", "igg-games", "gog-games", "steamunlocked", "skidrow", "crack",
    "warez", "rutor", "rutracker", "onlinefix", "limetorrents", "yts",
    "nyaa", "jogosgratis",
]
ADS_KEYS = ["doubleclick", "adservice", "googlesyndication", "adsystem",
            "analytics", "telemetry", "tracking", "adnxs", "adform"]


def categorize(domain):
    d = domain.lower().strip(".")
    labels = d.split(".")
    if any(l in SECURITY_SHORT for l in labels) or \
            any(k in d for k in SECURITY_KEYS):
        return "Antivirus/Seguranca"
    if any(k in d for k in UPDATE_KEYS):
        return "Microsoft/Windows Update"
    if any(k in d for k in PIRACY_KEYS):
        return "Torrent/Pirataria"
    if any(k in d for k in ADS_KEYS):
        return "Anuncios/Rastreio"
    return "Outros"


def decode_text(raw):
    if raw.startswith(b"\xff\xfe") or raw.startswith(b"\xfe\xff"):
        return raw.decode("utf-16", errors="replace")
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw[3:].decode("utf-8", errors="replace")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("cp1252", errors="replace")


def read_hosts(path=None):
    p = Path(path) if path else hosts_path()
    return decode_text(p.read_bytes())


def parse_hosts(text):
    """Devolve lista de entradas {line, ip, domain, category, status, risk}."""
    entries = []
    for no, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        ip, domains = parts[0], parts[1:]
        for dom in domains:
            cat = categorize(dom)
            blocked = ip in BLOCK_IPS
            default = dom.lower() in DEFAULT_DOMAINS
            if default:
                status, risk = "Padrao", "ok"
            elif blocked:
                status = "Bloqueado"
                risk = "alto" if cat in ("Antivirus/Seguranca",
                                         "Microsoft/Windows Update") else "info"
            else:
                status = f"Redireciona -> {ip}"
                risk = "alto" if cat in ("Antivirus/Seguranca",
                                         "Microsoft/Windows Update") else "medio"
            entries.append(dict(line=no, ip=ip, domain=dom, category=cat,
                                status=status, risk=risk))
    return entries


def hosts_summary(entries):
    ativos = [e for e in entries if e["risk"] != "ok"]
    alto = [e for e in ativos if e["risk"] == "alto"]
    return (f"{len(ativos)} entrada(s) fora do padrao, "
            f"{len(alto)} de risco ALTO (antivirus/Windows Update bloqueados ou redirecionados).")


def diff_hosts(old_text, new_text):
    def keyset(t):
        return {(e["ip"], e["domain"].lower()) for e in parse_hosts(t)}
    a, b = keyset(old_text), keyset(new_text)
    return sorted(b - a), sorted(a - b)  # (adicionadas, removidas)


def backup_hosts(tag="manual"):
    src = hosts_path()
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    dst = BACKUP_DIR / f"hosts_{stamp}_{tag}.bak"
    shutil.copy2(src, dst)
    log(f"Backup do hosts criado: {dst.name}")
    return dst


def list_backups():
    return sorted(BACKUP_DIR.glob("hosts_*.bak"), reverse=True)


def _write_hosts_bytes(data):
    p = hosts_path()
    try:
        os.chmod(p, stat.S_IWRITE | stat.S_IREAD)  # malware as vezes marca somente leitura
    except OSError:
        pass
    p.write_bytes(data)
    if IS_WIN:
        try:
            run_cmd(["ipconfig", "/flushdns"], timeout=15)
        except Exception:
            pass


def restore_hosts(backup_file):
    backup_hosts("antes_de_restaurar")
    _write_hosts_bytes(Path(backup_file).read_bytes())
    log(f"Hosts restaurado a partir de {Path(backup_file).name}")


def strip_security_blocks(text):
    """Remove dominios de antivirus/Windows Update bloqueados ou redirecionados.
    Devolve (novo_texto, quantidade_removida)."""
    out, removed = [], 0
    for raw in text.splitlines():
        body, sep, comment = raw.partition("#")
        parts = body.split()
        if len(parts) >= 2:
            ip, doms = parts[0], parts[1:]
            keep = []
            for d in doms:
                if d.lower() in DEFAULT_DOMAINS or categorize(d) not in (
                        "Antivirus/Seguranca", "Microsoft/Windows Update"):
                    keep.append(d)
                else:
                    removed += 1
            if not keep:
                continue
            if len(keep) != len(doms):
                raw = f"{ip} {' '.join(keep)}" + (f" #{comment}" if sep else "")
        out.append(raw)
    return "\n".join(out) + "\n", removed


def apply_hosts_text(new_text):
    backup_hosts("antes_de_alterar")
    _write_hosts_bytes(new_text.encode("utf-8"))


AV_TEST_SITES = ["www.malwarebytes.com", "www.kaspersky.com", "www.avast.com",
                 "www.bitdefender.com", "www.eset.com", "www.virustotal.com",
                 "www.microsoft.com", "windowsupdate.microsoft.com"]


def test_site(host, timeout=4):
    try:
        ip = socket.gethostbyname(host)
    except OSError:
        return "Sem DNS / sem internet"
    if ip in BLOCK_IPS:
        return f"BLOQUEADO (resolve para {ip})"
    try:
        with socket.create_connection((host, 443), timeout=timeout):
            return f"OK ({ip})"
    except OSError:
        return f"Sem resposta ({ip})"


# ----------------------------------------------------------------------------
# SISTEMA (tipo CPU-Z / GPU-Z)
# ----------------------------------------------------------------------------
def _as_list(x):
    if x is None:
        return []
    return x if isinstance(x, list) else [x]


def gather_system_info():
    sections = {}
    sections["Sistema operacional"] = {
        "Sistema": f"{platform.system()} {platform.release()}",
        "Versao": platform.version(),
        "Arquitetura": platform.machine(),
        "Nome do PC": platform.node(),
    }
    cpu = {"Processador": platform.processor() or "?"}
    if psutil:
        cpu["Nucleos fisicos"] = psutil.cpu_count(logical=False)
        cpu["Threads"] = psutil.cpu_count(logical=True)
        f = psutil.cpu_freq()
        if f:
            cpu["Frequencia atual (MHz)"] = round(f.current)
            if f.max:
                cpu["Frequencia maxima (MHz)"] = round(f.max)
    sections["CPU"] = cpu
    if psutil:
        vm = psutil.virtual_memory()
        sections["Memoria"] = {"Total": sizefmt(vm.total),
                               "Em uso": f"{sizefmt(vm.used)} ({vm.percent}%)"}
    if IS_WIN:
        ps = (
            "$o=[ordered]@{};"
            "$o.cpu=@(Get-CimInstance Win32_Processor|Select Name,NumberOfCores,NumberOfLogicalProcessors,MaxClockSpeed,L2CacheSize,L3CacheSize,SocketDesignation);"
            "$o.board=@(Get-CimInstance Win32_BaseBoard|Select Manufacturer,Product);"
            "$o.bios=@(Get-CimInstance Win32_BIOS|Select SMBIOSBIOSVersion,ReleaseDate);"
            "$o.gpu=@(Get-CimInstance Win32_VideoController|Select Name,AdapterRAM,DriverVersion,CurrentHorizontalResolution,CurrentVerticalResolution,CurrentRefreshRate);"
            "$o.ram=@(Get-CimInstance Win32_PhysicalMemory|Select Manufacturer,Capacity,Speed,PartNumber,BankLabel);"
            "$o.os=@(Get-CimInstance Win32_OperatingSystem|Select Caption,Version,OSArchitecture);"
            "$o|ConvertTo-Json -Depth 4 -Compress"
        )
        try:
            data = json.loads(powershell(ps, 60))
        except Exception as e:
            data = {}
            sections["Aviso"] = {"WMI": f"nao foi possivel ler: {e}"}
        for c in _as_list(data.get("cpu")):
            sections["CPU"] = {
                "Modelo": str(c.get("Name", "")).strip(),
                "Socket": c.get("SocketDesignation"),
                "Nucleos": c.get("NumberOfCores"),
                "Threads": c.get("NumberOfLogicalProcessors"),
                "Clock base (MHz)": c.get("MaxClockSpeed"),
                "Cache L2 (KB)": c.get("L2CacheSize"),
                "Cache L3 (KB)": c.get("L3CacheSize"),
            }
        for b in _as_list(data.get("board")):
            sections["Placa-mae"] = {"Fabricante": b.get("Manufacturer"),
                                     "Modelo": b.get("Product")}
        for b in _as_list(data.get("bios")):
            sections["BIOS"] = {"Versao": b.get("SMBIOSBIOSVersion")}
        for i, g in enumerate(_as_list(data.get("gpu")), 1):
            ram = g.get("AdapterRAM")
            sections[f"GPU {i}"] = {
                "Modelo": g.get("Name"),
                "Driver": g.get("DriverVersion"),
                "VRAM (WMI, limite 4 GB)": sizefmt(ram) if ram else "?",
                "Resolucao": f"{g.get('CurrentHorizontalResolution')}x{g.get('CurrentVerticalResolution')} @ {g.get('CurrentRefreshRate')} Hz",
            }
        for i, m in enumerate(_as_list(data.get("ram")), 1):
            sections[f"Pente de RAM {i}"] = {
                "Fabricante": str(m.get("Manufacturer", "")).strip(),
                "Modelo": str(m.get("PartNumber", "")).strip(),
                "Capacidade": sizefmt(m.get("Capacity") or 0),
                "Velocidade (MHz)": m.get("Speed"),
                "Slot": m.get("BankLabel"),
            }
    else:
        try:
            for line in open("/proc/cpuinfo", encoding="utf-8"):
                if line.startswith("model name"):
                    sections["CPU"]["Modelo"] = line.split(":", 1)[1].strip()
                    break
        except OSError:
            pass
    return sections


def format_sections(sections):
    out = []
    for title, d in sections.items():
        out.append(f"=== {title} ===")
        for k, v in d.items():
            out.append(f"  {k:<28} {v}")
        out.append("")
    return "\n".join(out)


def live_stats():
    if not psutil:
        return "Instale o psutil para ver uso em tempo real (pip install psutil)"
    cpu = psutil.cpu_percent(interval=None)
    vm = psutil.virtual_memory()
    s = f"CPU: {cpu:.0f}%    RAM: {vm.percent:.0f}% ({sizefmt(vm.used)} / {sizefmt(vm.total)})"
    try:
        temps = psutil.sensors_temperatures()  # nao existe no Windows
        for name, arr in temps.items():
            if arr:
                s += f"    Temp {name}: {arr[0].current:.0f}C"
                break
    except Exception:
        pass
    return s


# ----------------------------------------------------------------------------
# DISCO: saude + benchmark
# ----------------------------------------------------------------------------
def disk_health():
    """Lista de dicts com saude dos discos fisicos."""
    if IS_WIN:
        ps = (
            "$d=@(Get-PhysicalDisk|ForEach-Object{$r=$_|Get-StorageReliabilityCounter -ErrorAction SilentlyContinue;"
            "[pscustomobject]@{Nome=$_.FriendlyName;Tipo=[string]$_.MediaType;Barramento=[string]$_.BusType;"
            "Saude=[string]$_.HealthStatus;Status=[string]$_.OperationalStatus;TamanhoGB=[math]::Round($_.Size/1GB,1);"
            "Temperatura=$r.Temperature;Desgaste=$r.Wear;Horas=$r.PowerOnHours;"
            "ErrosLeitura=$r.ReadErrorsTotal;ErrosEscrita=$r.WriteErrorsTotal}});"
            "$d|ConvertTo-Json -Compress"
        )
        try:
            return _as_list(json.loads(powershell(ps, 60)))
        except Exception as e:
            return [{"Nome": "Falha ao ler discos (execute como administrador)",
                     "Erro": str(e)}]
    if shutil.which("smartctl"):
        rc, out = run_cmd(["smartctl", "-H", "/dev/sda"], 20)
        return [{"Nome": "/dev/sda", "Saude": out.strip().splitlines()[-1] if out else "?"}]
    return [{"Nome": "Leitura de SMART so disponivel no Windows (ou com smartctl)"}]


def list_volumes():
    vols = []
    if psutil:
        for p in psutil.disk_partitions(all=False):
            if "cdrom" in p.opts or not p.fstype:
                continue
            try:
                u = psutil.disk_usage(p.mountpoint)
                vols.append((p.mountpoint, u.total, u.free))
            except OSError:
                pass
    if not vols:
        t, _, f = shutil.disk_usage(tempfile.gettempdir())
        vols.append((tempfile.gettempdir(), t, f))
    return vols


def disk_benchmark(target_dir, size_mb, progress=lambda t, f: None):
    """Teste sequencial (blocos de 1 MB). A leitura pode refletir cache do SO."""
    fn = Path(target_dir) / f".sysguard_bench_{os.getpid()}.tmp"
    block = os.urandom(1024 * 1024)
    try:
        t0 = time.perf_counter()
        with open(fn, "wb", buffering=0) as f:
            for i in range(size_mb):
                f.write(block)
                if i % 8 == 0:
                    progress("Escrevendo...", i / size_mb * 0.5)
            f.flush()
            os.fsync(f.fileno())
        wt = max(time.perf_counter() - t0, 1e-6)
        t0 = time.perf_counter()
        total = 0
        with open(fn, "rb", buffering=0) as f:
            while True:
                b = f.read(1024 * 1024)
                if not b:
                    break
                total += len(b)
                if (total // (1024 * 1024)) % 8 == 0:
                    progress("Lendo...", 0.5 + total / (size_mb * 1024 * 1024) * 0.5)
        rt = max(time.perf_counter() - t0, 1e-6)
        progress("Concluido", 1.0)
        return size_mb / wt, size_mb / rt
    finally:
        try:
            fn.unlink()
        except OSError:
            pass


# ----------------------------------------------------------------------------
# INTEGRIDADE
# ----------------------------------------------------------------------------
INTEGRITY_CMDS = {
    "SFC (verificar arquivos do Windows)": ["sfc", "/verifyonly"],
    "DISM - CheckHealth (rapido)": ["DISM", "/Online", "/Cleanup-Image", "/CheckHealth"],
    "DISM - ScanHealth (demorado)": ["DISM", "/Online", "/Cleanup-Image", "/ScanHealth"],
    "CHKDSK C: (somente leitura)": ["chkdsk", "C:"],
}


def run_integrity(cmd):
    return run_cmd(cmd, timeout=3600)


# ----------------------------------------------------------------------------
# VERIFICACAO DE ARQUIVOS SUSPEITOS (antes do antivirus)
# ----------------------------------------------------------------------------
EXEC_EXT = {".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js",
            ".jse", ".wsf", ".jar", ".msi", ".com", ".pif", ".hta", ".cpl"}
DOC_EXT = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".jpeg", ".png",
           ".txt", ".mp3", ".mp4", ".zip", ".rar", ".gif"}
RANDOM_NAME = re.compile(r"^[a-f0-9]{8,}$|^[a-z0-9]{12,}$", re.I)


def default_scan_folders():
    home = Path.home()
    cands = [home / "Downloads", home / "Desktop", Path(tempfile.gettempdir())]
    if IS_WIN:
        for env in ("APPDATA", "LOCALAPPDATA", "PROGRAMDATA"):
            if os.environ.get(env):
                cands.append(Path(os.environ[env]))
    return [c for c in cands if c.exists()]


def file_sha256(path, limit=300 * 1024 * 1024):
    if os.path.getsize(path) > limit:
        return "(arquivo grande demais)"
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def score_file(path, st, recent_days):
    reasons, score = [], 0
    p = Path(path)
    stem_ext = Path(p.stem).suffix.lower()
    if stem_ext in DOC_EXT:
        reasons.append("extensao dupla (parece documento)")
        score += 3
    low = str(p).lower()
    if any(k in low for k in ("\\temp\\", "/temp/", "\\appdata\\", "/tmp/")):
        reasons.append("em pasta temporaria/AppData")
        score += 1
    if time.time() - st.st_mtime < recent_days * 86400:
        reasons.append(f"criado/alterado ha menos de {recent_days} dias")
        score += 1
    if RANDOM_NAME.match(p.stem) and p.suffix.lower() in {".exe", ".dll", ".scr"}:
        reasons.append("nome aleatorio")
        score += 1
    if IS_WIN and getattr(st, "st_file_attributes", 0) & 0x2:
        reasons.append("oculto")
        score += 1
    if p.suffix.lower() in {".scr", ".pif", ".hta", ".vbs", ".jse", ".wsf"}:
        reasons.append("tipo de script/executavel incomum")
        score += 1
    return score, reasons


def scan_suspicious(folders, recent_days=14, max_results=3000,
                    cancel=lambda: False, progress=lambda s: None):
    found = []
    for folder in folders:
        for root, dirs, files in os.walk(folder):
            if cancel():
                return found
            progress(root)
            for name in files:
                if Path(name).suffix.lower() not in EXEC_EXT:
                    continue
                full = os.path.join(root, name)
                try:
                    st = os.stat(full)
                except OSError:
                    continue
                score, reasons = score_file(full, st, recent_days)
                if score >= 2:
                    found.append(dict(path=full, size=st.st_size, score=score,
                                      level="ALTO" if score >= 3 else "MEDIO",
                                      reasons="; ".join(reasons),
                                      mtime=datetime.datetime.fromtimestamp(
                                          st.st_mtime).strftime("%Y-%m-%d %H:%M")))
                    if len(found) >= max_results:
                        return found
    found.sort(key=lambda x: -x["score"])
    return found


# ----------------------------------------------------------------------------
# LIMPEZA: pastas de programas que nao estao instalados
# ----------------------------------------------------------------------------
PROTECTED = {n.lower() for n in [
    "microsoft", "windows", "windowsapps", "common files", "internet explorer",
    "windows defender", "windows defender advanced threat protection",
    "windows mail", "windows media player", "windows nt", "windows photo viewer",
    "windows security", "windowspowershell", "reference assemblies", "msbuild",
    "dotnet", "modifiablewindowsapps", "packages", "package cache",
    "microsoft shared", "uninstall information", "installshield installation information",
    "temp", "programs", "connecteddevicesplatform", "d3dscache", "publishers",
    "comms", "history", "low", "virtualstore", "nvidia", "nvidia corporation",
    "intel", "amd", "realtek", "dell", "hp", "lenovo", "asus", "desktop.ini",
    "application data", "ssh", "pip", "npm", "python", "nuget", "microsoft edge",
    "microsoft office", "google", "mozilla", "steam", "epic games", "discord",
    "systemcertificates", "usoshared", "regid.1991-06.com.microsoft",
    "soft", "boot", "recovery", "$recycle.bin", "system volume information",
]}


def norm(s):
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


def installed_programs():
    if not IS_WIN:
        return []
    import winreg
    base = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    keys = [(winreg.HKEY_LOCAL_MACHINE, base),
            (winreg.HKEY_LOCAL_MACHINE, base.replace("SOFTWARE\\", "SOFTWARE\\WOW6432Node\\")),
            (winreg.HKEY_CURRENT_USER, base)]
    out = []
    for hive, path in keys:
        try:
            k = winreg.OpenKey(hive, path)
        except OSError:
            continue
        i = 0
        while True:
            try:
                sub = winreg.EnumKey(k, i)
            except OSError:
                break
            i += 1
            try:
                sk = winreg.OpenKey(k, sub)
            except OSError:
                continue
            d = {}
            for v in ("DisplayName", "InstallLocation", "Publisher",
                      "DisplayIcon", "UninstallString"):
                try:
                    d[v] = str(winreg.QueryValueEx(sk, v)[0])
                except OSError:
                    d[v] = ""
            if d["DisplayName"]:
                out.append(d)
    return out


class Known:
    """Decide se uma pasta pertence a algum programa instalado."""

    def __init__(self, programs):
        self.names, self.locs = set(), []
        for p in programs:
            for f in ("DisplayName", "Publisher"):
                n = norm(p.get(f))
                if len(n) >= 4:
                    self.names.add(n)
            for f in ("InstallLocation", "DisplayIcon", "UninstallString"):
                v = (p.get(f) or "").split(",")[0].strip().strip('"').lower()
                if not v:
                    continue
                if f != "InstallLocation":
                    v = os.path.dirname(v)
                v = v.rstrip("\\/")
                if len(v) > 5:
                    self.locs.append(v)

    def match(self, path):
        lp = str(path).lower().rstrip("\\/")
        for loc in self.locs:
            if lp == loc or loc.startswith(lp + os.sep) or lp.startswith(loc + os.sep):
                return True
        n = norm(Path(path).name)
        if len(n) < 4:
            return True  # nomes curtos demais: nao arriscar
        return any(n in x or x in n for x in self.names)


def dir_size(path, max_seconds=4.0):
    total, t0 = 0, time.time()
    stack = [path]
    while stack:
        cur = stack.pop()
        try:
            with os.scandir(cur) as it:
                for e in it:
                    try:
                        if e.is_symlink():
                            continue
                        if e.is_dir(follow_symlinks=False):
                            stack.append(e.path)
                        else:
                            total += e.stat(follow_symlinks=False).st_size
                    except OSError:
                        pass
        except OSError:
            pass
        if time.time() - t0 > max_seconds:
            return total, True
    return total, False


def scan_roots():
    roots = []
    env = os.environ
    if IS_WIN:
        for key, label in (("ProgramFiles", "Program Files"),
                           ("ProgramFiles(x86)", "Program Files (x86)"),
                           ("ProgramData", "ProgramData")):
            if env.get(key):
                roots.append((label, Path(env[key])))
        if env.get("LOCALAPPDATA"):
            roots.append(("AppData\\Local\\Programs", Path(env["LOCALAPPDATA"]) / "Programs"))
            roots.append(("AppData\\Local", Path(env["LOCALAPPDATA"])))
        if env.get("APPDATA"):
            roots.append(("AppData\\Roaming", Path(env["APPDATA"])))
    return roots


def find_leftovers(include_roots, include_temp, known, cancel=lambda: False,
                   progress=lambda s: None):
    items = []
    for label, root in scan_roots():
        if label not in include_roots or not root.exists():
            continue
        try:
            children = list(root.iterdir())
        except OSError:
            continue
        for c in children:
            if cancel():
                return items
            progress(str(c))
            if c.name.lower() in PROTECTED or not c.is_dir() or c.is_symlink():
                continue
            if known.match(c):
                continue
            size, partial = dir_size(str(c))
            empty = size == 0
            try:
                mt = datetime.datetime.fromtimestamp(c.stat().st_mtime).strftime("%Y-%m-%d")
            except OSError:
                mt = "?"
            items.append(dict(name=c.name, path=str(c), size=size, partial=partial,
                              origin=label, modified=mt,
                              reason="Pasta vazia" if empty else
                              "Nenhum programa instalado corresponde"))
    if include_temp:
        tmp = Path(tempfile.gettempdir())
        try:
            children = list(tmp.iterdir())
        except OSError:
            children = []
        for c in children:
            if cancel():
                return items
            try:
                if c.is_symlink():
                    continue
                if c.is_dir():
                    size, partial = dir_size(str(c), 2.0)
                else:
                    size, partial = c.stat().st_size, False
                mt = datetime.datetime.fromtimestamp(c.stat().st_mtime).strftime("%Y-%m-%d")
            except OSError:
                continue
            items.append(dict(name=c.name, path=str(c), size=size, partial=partial,
                              origin="Temporarios", modified=mt,
                              reason="Arquivo temporario"))
    items.sort(key=lambda x: -x["size"])
    return items


def _allowed_for_delete(path):
    p = Path(path)
    if not p.exists() or p.is_symlink():
        return False
    allowed = [r for _, r in scan_roots()] + [Path(tempfile.gettempdir())]
    for r in allowed:
        try:
            if p.resolve() != r.resolve() and r.resolve() in p.resolve().parents:
                if p.name.lower() in PROTECTED and p.parent.resolve() != Path(tempfile.gettempdir()).resolve():
                    return False
                return True
        except OSError:
            continue
    return False


def _rm_readonly(func, path, exc):
    try:
        os.chmod(path, stat.S_IWRITE)
        func(path)
    except OSError:
        pass


def delete_items(items, permanent=False):
    """Move para quarentena (padrao) ou apaga de vez. Devolve (ok, falhas)."""
    ok, fails = [], []
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    qdir = QUARANTINE_DIR / stamp
    for it in items:
        path = it["path"]
        if not _allowed_for_delete(path):
            fails.append((path, "caminho protegido ou inexistente"))
            continue
        try:
            if permanent:
                if os.path.isdir(path):
                    shutil.rmtree(path, onerror=_rm_readonly)
                else:
                    os.remove(path)
                if os.path.exists(path):
                    raise OSError("alguns itens estao em uso")
                log(f"APAGADO: {path} ({sizefmt(it['size'])})")
            else:
                qdir.mkdir(parents=True, exist_ok=True)
                dest = qdir / (it["name"] + "__" + hashlib.md5(path.encode()).hexdigest()[:6])
                shutil.move(path, dest)
                log(f"QUARENTENA: {path} -> {dest}")
            ok.append(path)
        except Exception as e:
            fails.append((path, str(e)))
            log(f"FALHA ao remover {path}: {e}")
    return ok, fails


# ----------------------------------------------------------------------------
# DESINSTALADOR EM LOTE
# ----------------------------------------------------------------------------
_SKIP_NAMES = re.compile(r"^(KB\d+|Update for|Security Update|Hotfix|"
                         r"Microsoft Visual C\+\+ .*Redistributable.*\(x\d\d\)$)", re.I)


def _rv(sk, name, default=""):
    import winreg
    try:
        return winreg.QueryValueEx(sk, name)[0]
    except OSError:
        return default


def list_uninstallable(show_redist=False):
    """Programas desinstalaveis (sem componentes de sistema e atualizacoes)."""
    if not IS_WIN:
        return []
    import winreg
    base = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    roots = [(winreg.HKEY_LOCAL_MACHINE, base),
             (winreg.HKEY_LOCAL_MACHINE, base.replace("SOFTWARE\\", "SOFTWARE\\WOW6432Node\\")),
             (winreg.HKEY_CURRENT_USER, base)]
    items, seen = [], set()
    for hive, path in roots:
        try:
            k = winreg.OpenKey(hive, path)
        except OSError:
            continue
        i = 0
        while True:
            try:
                sub = winreg.EnumKey(k, i)
            except OSError:
                break
            i += 1
            try:
                sk = winreg.OpenKey(k, sub)
            except OSError:
                continue
            name = str(_rv(sk, "DisplayName")).strip()
            if not name or _rv(sk, "SystemComponent", 0) == 1 or _rv(sk, "ParentKeyName"):
                continue
            if _SKIP_NAMES.search(name) and not show_redist:
                continue
            uni = str(_rv(sk, "UninstallString")).strip()
            quiet = str(_rv(sk, "QuietUninstallString")).strip()
            if not uni and not quiet:
                continue
            ver = str(_rv(sk, "DisplayVersion"))
            if (name.lower(), ver) in seen:
                continue
            seen.add((name.lower(), ver))
            d = str(_rv(sk, "InstallDate"))
            if re.fullmatch(r"\d{8}", d):
                d = f"{d[:4]}-{d[4:6]}-{d[6:]}"
            items.append(dict(
                name=name, version=ver, publisher=str(_rv(sk, "Publisher")),
                date=d, size=int(_rv(sk, "EstimatedSize", 0) or 0) * 1024,
                uninstall=uni, quiet=quiet, reg=(hive, path, sub)))
    items.sort(key=lambda x: x["name"].lower())
    return items


def build_uninstall_cmd(p, silent=True):
    """Devolve (comando, e_silencioso)."""
    q, u = p.get("quiet", "").strip(), p.get("uninstall", "").strip()
    if silent and q:
        return q, True
    m = re.search(r"msiexec(?:\.exe)?\s+/[IX]\s*(\{[0-9A-F-]+\})", u, re.I)
    if m:
        flags = "/qn /norestart" if silent else "/norestart"
        return f"msiexec.exe /x {m.group(1)} {flags}", silent
    return u, False


def still_installed(p):
    if not IS_WIN:
        return False
    import winreg
    hive, path, sub = p["reg"]
    try:
        winreg.OpenKey(hive, path + "\\" + sub)
        return True
    except OSError:
        return False


def create_restore_point(desc="SysGuard - antes de desinstalar"):
    if not IS_WIN:
        return False
    out = powershell(f"Checkpoint-Computer -Description '{desc}' "
                     "-RestorePointType APPLICATION_UNINSTALL -ErrorAction Stop; 'OK'", 90)
    ok = "OK" in out
    log("Ponto de restauracao " + ("criado" if ok else f"nao criado: {out.strip()[:200]}"))
    return ok


def uninstall_one(p, silent=True, timeout=1800):
    """Executa o desinstalador e confere no registro. Devolve (status, detalhe)."""
    cmd, is_silent = build_uninstall_cmd(p, silent)
    if not cmd:
        return "falha", "sem comando de desinstalacao"
    log(f"DESINSTALAR: {p['name']} -> {cmd}")
    try:
        flags = 0x08000000 if (IS_WIN and is_silent) else 0
        rc = subprocess.run(cmd, shell=True, timeout=timeout, creationflags=flags).returncode
    except subprocess.TimeoutExpired:
        return "falha", "tempo esgotado"
    except OSError as e:
        return "falha", str(e)
    for _ in range(20):  # alguns desinstaladores terminam em segundo plano
        if not still_installed(p):
            break
        time.sleep(1)
    gone = not still_installed(p)
    log(f"  codigo {rc}, removido={gone}")
    if gone:
        return "ok", "reiniciar o PC pode ser necessario" if rc == 3010 else ""
    return "falha", f"codigo {rc}; o programa ainda aparece instalado (cancelado ou precisa de admin)"


# ----------------------------------------------------------------------------
# INTERFACE
# ----------------------------------------------------------------------------
BG, BG2, FG, ACC = "#1b1d24", "#262932", "#e8e8ec", "#4f8cff"
RED, ORANGE, GREEN, GREY = "#ff6b6b", "#ffb454", "#5fd38d", "#9aa0ac"
FONT = ("Segoe UI", 10) if IS_WIN else ("DejaVu Sans", 10)
MONO = ("Consolas", 10) if IS_WIN else ("DejaVu Sans Mono", 10)


def make_tree(parent, cols, height=10):
    """cols: [(id, titulo, largura, anchor)]. Devolve (frame, treeview)."""
    fr = ttk.Frame(parent)
    tv = ttk.Treeview(fr, columns=[c[0] for c in cols], show="headings", height=height)
    for cid, title, w, anc in cols:
        tv.heading(cid, text=title)
        tv.column(cid, width=w, anchor=anc, stretch=(cid == cols[-1][0]))
    sb = ttk.Scrollbar(fr, orient="vertical", command=tv.yview)
    tv.configure(yscrollcommand=sb.set)
    tv.pack(side="left", fill="both", expand=True)
    sb.pack(side="right", fill="y")
    tv.tag_configure("alto", foreground=RED)
    tv.tag_configure("medio", foreground=ORANGE)
    tv.tag_configure("info", foreground=GREY)
    tv.tag_configure("ok", foreground=GREEN)
    return fr, tv


def make_text(parent, height=10):
    fr = ttk.Frame(parent)
    t = tk.Text(fr, height=height, bg=BG2, fg=FG, insertbackground=FG,
                relief="flat", font=MONO, wrap="word")
    sb = ttk.Scrollbar(fr, orient="vertical", command=t.yview)
    t.configure(yscrollcommand=sb.set)
    t.pack(side="left", fill="both", expand=True)
    sb.pack(side="right", fill="y")
    return fr, t


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"{APP_NAME} {APP_VERSION}")
        self.geometry("1100x720")
        self.minsize(900, 560)
        self.configure(bg=BG)
        self.q = queue.Queue()
        self.cancel_flag = threading.Event()
        self._style()
        self._header()
        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True, padx=10, pady=(0, 6))
        self.tab_hosts()
        self.tab_system()
        self.tab_disk()
        self.tab_integrity()
        self.tab_scan()
        self.tab_uninstall()
        self.tab_clean()
        self.tab_log()
        self.status = tk.StringVar(value="Pronto.")
        ttk.Label(self, textvariable=self.status, style="Status.TLabel").pack(
            fill="x", padx=10, pady=(0, 8))
        self.after(100, self._pump)
        self.after(1500, self._tick_live)
        self.refresh_hosts()
        log(f"{APP_NAME} iniciado (admin={is_admin()})")

    # ---- infraestrutura ----------------------------------------------------
    def _style(self):
        s = ttk.Style(self)
        s.theme_use("clam")
        s.configure(".", background=BG, foreground=FG, fieldbackground=BG2, font=FONT)
        s.configure("TNotebook", background=BG, borderwidth=0)
        s.configure("TNotebook.Tab", background=BG2, foreground=FG, padding=(14, 7))
        s.map("TNotebook.Tab", background=[("selected", ACC)], foreground=[("selected", "#fff")])
        s.configure("TButton", background=BG2, foreground=FG, padding=(10, 6), borderwidth=0)
        s.map("TButton", background=[("active", "#323644")])
        s.configure("Accent.TButton", background=ACC, foreground="#fff")
        s.map("Accent.TButton", background=[("active", "#6aa0ff")])
        s.configure("Danger.TButton", background="#b3403f", foreground="#fff")
        s.map("Danger.TButton", background=[("active", "#d04f4e")])
        s.configure("Treeview", background=BG2, fieldbackground=BG2, foreground=FG,
                    rowheight=24, borderwidth=0)
        s.configure("Treeview.Heading", background="#323644", foreground=FG, relief="flat")
        s.map("Treeview", background=[("selected", ACC)])
        s.configure("Status.TLabel", background=BG, foreground=GREY)
        s.configure("Title.TLabel", font=(FONT[0], 15, "bold"))
        s.configure("Sub.TLabel", foreground=GREY)
        s.configure("TCheckbutton", background=BG, foreground=FG)
        s.configure("TProgressbar", background=ACC, troughcolor=BG2)

    def _header(self):
        h = ttk.Frame(self)
        h.pack(fill="x", padx=12, pady=10)
        ttk.Label(h, text=f"{APP_NAME}", style="Title.TLabel").pack(side="left")
        ttk.Label(h, text="  complemento ao Windows Defender", style="Sub.TLabel").pack(side="left")
        if is_admin():
            ttk.Label(h, text="Administrador", foreground=GREEN).pack(side="right")
        else:
            if IS_WIN:
                ttk.Button(h, text="Reabrir como administrador",
                           command=self.go_admin).pack(side="right")
            ttk.Label(h, text="Sem privilegio de administrador  ",
                      foreground=ORANGE).pack(side="right")

    def go_admin(self):
        if relaunch_as_admin():
            self.destroy()
        else:
            messagebox.showwarning(APP_NAME, "Nao foi possivel elevar privilegios.")

    def bg(self, fn, done=None, *args):
        """Roda fn em thread; done(resultado, erro) roda na thread da UI."""
        def work():
            try:
                r, e = fn(*args), None
            except Exception as ex:  # noqa
                r, e = None, ex
            if done:
                self.q.put(lambda: done(r, e))
        threading.Thread(target=work, daemon=True).start()

    def ui(self, fn, *a):
        self.q.put(lambda: fn(*a))

    def _pump(self):
        try:
            while True:
                self.q.get_nowait()()
        except queue.Empty:
            pass
        self.after(100, self._pump)

    def _tick_live(self):
        try:
            self.live_var.set(live_stats())
        except Exception:
            pass
        self.after(1500, self._tick_live)

    def say(self, msg):
        self.status.set(msg)

    def need_admin(self, e):
        if isinstance(e, PermissionError):
            if messagebox.askyesno(APP_NAME, "Acesso negado. Esta acao precisa de administrador.\n"
                                   "Reabrir o programa como administrador agora?"):
                self.go_admin()
            return True
        return False

    # ---- aba HOSTS ---------------------------------------------------------
    def tab_hosts(self):
        f = ttk.Frame(self.nb, padding=10)
        self.nb.add(f, text="Hosts")
        bar = ttk.Frame(f)
        bar.pack(fill="x")
        for text, cmd, sty in (
                ("Criar backup agora", self.hosts_backup, "Accent.TButton"),
                ("Analisar", self.refresh_hosts, "TButton"),
                ("Testar sites de antivirus", self.hosts_test_sites, "TButton"),
                ("Remover bloqueios de antivirus", self.hosts_strip, "Danger.TButton"),
                ("Abrir arquivo", self.hosts_open, "TButton")):
            ttk.Button(bar, text=text, command=cmd, style=sty).pack(side="left", padx=(0, 6))
        self.hosts_info = tk.StringVar()
        ttk.Label(f, textvariable=self.hosts_info, style="Sub.TLabel").pack(anchor="w", pady=6)
        pw = ttk.PanedWindow(f, orient="vertical")
        pw.pack(fill="both", expand=True)
        top = ttk.Frame(pw)
        fr, self.hosts_tree = make_tree(top, [
            ("line", "Linha", 60, "center"), ("ip", "IP", 120, "w"),
            ("domain", "Dominio", 330, "w"), ("cat", "Categoria", 190, "w"),
            ("status", "Situacao", 250, "w")], height=12)
        fr.pack(fill="both", expand=True)
        pw.add(top, weight=3)
        bot = ttk.Frame(pw)
        ttk.Label(bot, text="Backups salvos (duplo clique compara com o hosts atual)").pack(anchor="w")
        fr2, self.bk_tree = make_tree(bot, [("name", "Arquivo", 420, "w"),
                                            ("size", "Tamanho", 90, "e"),
                                            ("when", "Data", 200, "w")], height=4)
        fr2.pack(fill="x")
        self.bk_tree.bind("<Double-1>", lambda e: self.hosts_compare())
        row = ttk.Frame(bot)
        row.pack(fill="x", pady=4)
        ttk.Button(row, text="Comparar com atual", command=self.hosts_compare).pack(side="left", padx=(0, 6))
        ttk.Button(row, text="Restaurar selecionado", command=self.hosts_restore).pack(side="left", padx=(0, 6))
        ttk.Button(row, text="Abrir pasta de backups",
                   command=lambda: self.open_path(BACKUP_DIR)).pack(side="left")
        fr3, self.hosts_out = make_text(bot, height=6)
        fr3.pack(fill="both", expand=True)
        pw.add(bot, weight=2)

    def refresh_hosts(self):
        self.hosts_tree.delete(*self.hosts_tree.get_children())
        try:
            text = read_hosts()
        except OSError as e:
            self.hosts_info.set(f"Nao foi possivel ler o hosts: {e}")
            return
        self.hosts_entries = parse_hosts(text)
        for e in self.hosts_entries:
            self.hosts_tree.insert("", "end", values=(e["line"], e["ip"], e["domain"],
                                                      e["category"], e["status"]),
                                   tags=(e["risk"],))
        self.hosts_info.set(f"{hosts_path()}  -  {hosts_summary(self.hosts_entries)}")
        self.bk_tree.delete(*self.bk_tree.get_children())
        for b in list_backups():
            st = b.stat()
            self.bk_tree.insert("", "end", iid=str(b), values=(
                b.name, sizefmt(st.st_size),
                datetime.datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S")))
        self.say("Hosts analisado.")

    def hosts_backup(self):
        try:
            d = backup_hosts()
        except OSError as e:
            messagebox.showerror(APP_NAME, f"Falha no backup: {e}")
            return
        self.refresh_hosts()
        self.say(f"Backup criado: {d.name}")

    def _sel_backup(self):
        s = self.bk_tree.selection()
        if not s:
            messagebox.showinfo(APP_NAME, "Selecione um backup na lista.")
            return None
        return s[0]

    def hosts_compare(self):
        b = self._sel_backup()
        if not b:
            return
        add, rem = diff_hosts(read_hosts(b), read_hosts())
        t = self.hosts_out
        t.delete("1.0", "end")
        t.insert("end", f"Comparando backup {Path(b).name} -> hosts atual\n\n")
        t.insert("end", f"Adicionadas desde o backup ({len(add)}):\n")
        for ip, d in add:
            t.insert("end", f"  + {ip}  {d}   [{categorize(d)}]\n")
        t.insert("end", f"\nRemovidas desde o backup ({len(rem)}):\n")
        for ip, d in rem:
            t.insert("end", f"  - {ip}  {d}\n")
        if not add and not rem:
            t.insert("end", "\nNenhuma diferenca.\n")

    def hosts_restore(self):
        b = self._sel_backup()
        if not b:
            return
        if not messagebox.askyesno(APP_NAME, f"Restaurar {Path(b).name}?\nO hosts atual sera salvo antes."):
            return
        try:
            restore_hosts(b)
        except OSError as e:
            if not self.need_admin(e):
                messagebox.showerror(APP_NAME, str(e))
            return
        self.refresh_hosts()
        self.say("Hosts restaurado.")

    def hosts_strip(self):
        try:
            new, n = strip_security_blocks(read_hosts())
        except OSError as e:
            messagebox.showerror(APP_NAME, str(e))
            return
        if n == 0:
            messagebox.showinfo(APP_NAME, "Nenhum bloqueio de antivirus/Windows Update encontrado.")
            return
        if not messagebox.askyesno(APP_NAME, f"Remover {n} dominio(s) de antivirus/Windows Update do hosts?\n"
                                   "Um backup sera criado antes."):
            return
        try:
            apply_hosts_text(new)
        except OSError as e:
            if not self.need_admin(e):
                messagebox.showerror(APP_NAME, str(e))
            return
        log(f"Removidos {n} bloqueios de seguranca do hosts")
        self.refresh_hosts()

    def hosts_test_sites(self):
        self.hosts_out.delete("1.0", "end")
        self.hosts_out.insert("end", "Testando acesso...\n")
        self.say("Testando sites de antivirus...")

        def work():
            return [(h, test_site(h)) for h in AV_TEST_SITES]

        def done(r, e):
            self.hosts_out.delete("1.0", "end")
            for h, res in (r or []):
                self.hosts_out.insert("end", f"{h:<34} {res}\n")
            self.say("Teste concluido.")
        self.bg(work, done)

    def hosts_open(self):
        self.open_path(hosts_path())

    def open_path(self, p):
        try:
            if IS_WIN:
                os.startfile(str(p))  # noqa
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(p)])
            else:
                subprocess.Popen(["xdg-open", str(p)])
        except Exception as e:
            messagebox.showerror(APP_NAME, str(e))

    # ---- aba SISTEMA ---------------------------------------------------------
    def tab_system(self):
        f = ttk.Frame(self.nb, padding=10)
        self.nb.add(f, text="Sistema")
        bar = ttk.Frame(f)
        bar.pack(fill="x")
        ttk.Button(bar, text="Ler hardware", style="Accent.TButton",
                   command=self.load_system).pack(side="left", padx=(0, 6))
        ttk.Button(bar, text="Copiar relatorio", command=self.copy_system).pack(side="left")
        self.live_var = tk.StringVar(value="")
        ttk.Label(f, textvariable=self.live_var, foreground=ACC).pack(anchor="w", pady=6)
        fr, self.sys_text = make_text(f, height=20)
        fr.pack(fill="both", expand=True)

    def load_system(self):
        self.say("Lendo hardware...")
        self.sys_text.delete("1.0", "end")
        self.sys_text.insert("end", "Lendo...\n")

        def done(r, e):
            self.sys_text.delete("1.0", "end")
            self.sys_text.insert("end", format_sections(r) if r else f"Erro: {e}")
            self.say("Hardware lido.")
        self.bg(gather_system_info, done)

    def copy_system(self):
        self.clipboard_clear()
        self.clipboard_append(self.sys_text.get("1.0", "end"))
        self.say("Relatorio copiado.")

    # ---- aba DISCO -----------------------------------------------------------
    def tab_disk(self):
        f = ttk.Frame(self.nb, padding=10)
        self.nb.add(f, text="Disco")
        ttk.Label(f, text="Saude dos discos (SMART)").pack(anchor="w")
        ttk.Button(f, text="Verificar saude", command=self.load_disks,
                   style="Accent.TButton").pack(anchor="w", pady=4)
        fr, self.disk_text = make_text(f, height=9)
        fr.pack(fill="x")
        ttk.Separator(f).pack(fill="x", pady=10)
        ttk.Label(f, text="Benchmark de armazenamento (sequencial, blocos de 1 MB)").pack(anchor="w")
        row = ttk.Frame(f)
        row.pack(fill="x", pady=4)
        self.vols = list_volumes()
        self.vol_combo = ttk.Combobox(
            row, state="readonly", width=34,
            values=[f"{m}  (livre {sizefmt(fr_)})" for m, _, fr_ in self.vols])
        self.vol_combo.pack(side="left", padx=(0, 6))
        self.vol_combo.current(0)
        self.size_var = tk.StringVar(value="512")
        ttk.Combobox(row, textvariable=self.size_var, state="readonly", width=8,
                     values=["128", "256", "512", "1024", "2048"]).pack(side="left", padx=(0, 4))
        ttk.Label(row, text="MB").pack(side="left", padx=(0, 10))
        self.bench_btn = ttk.Button(row, text="Iniciar teste", command=self.run_bench,
                                    style="Accent.TButton")
        self.bench_btn.pack(side="left")
        self.bench_prog = ttk.Progressbar(f, maximum=1.0)
        self.bench_prog.pack(fill="x", pady=6)
        self.bench_res = tk.StringVar(value="")
        ttk.Label(f, textvariable=self.bench_res, font=(FONT[0], 13, "bold")).pack(anchor="w")
        ttk.Label(f, style="Sub.TLabel", wraplength=900,
                  text="Obs.: a leitura pode aparecer inflada se o Windows mantiver o arquivo em cache. "
                       "Use tamanhos maiores que a RAM livre para um valor mais realista.").pack(anchor="w", pady=6)

    def load_disks(self):
        self.disk_text.delete("1.0", "end")
        self.disk_text.insert("end", "Lendo...\n")
        self.say("Lendo saude dos discos...")

        def done(r, e):
            t = self.disk_text
            t.delete("1.0", "end")
            for d in (r or []):
                for k, v in d.items():
                    t.insert("end", f"  {k:<14} {v}\n")
                t.insert("end", "\n")
            if e:
                t.insert("end", f"Erro: {e}")
            t.insert("end", "Dica: Saude 'Healthy' e Desgaste/erros baixos indicam disco bom. "
                            "Alguns campos so aparecem como administrador.\n")
            self.say("Leitura concluida.")
        self.bg(disk_health, done)

    def run_bench(self):
        mount = self.vols[self.vol_combo.current()][0]
        size = int(self.size_var.get())
        self.bench_btn.state(["disabled"])
        self.bench_res.set("Testando...")

        def prog(txt, frac):
            self.ui(lambda: (self.bench_prog.configure(value=frac), self.say(txt)))

        def done(r, e):
            self.bench_btn.state(["!disabled"])
            if e:
                self.bench_res.set(f"Erro: {e}")
                return
            w, rd = r
            self.bench_res.set(f"Escrita: {w:.0f} MB/s     Leitura: {rd:.0f} MB/s")
            log(f"Benchmark {mount} {size}MB: escrita {w:.0f} MB/s, leitura {rd:.0f} MB/s")
        self.bg(disk_benchmark, done, mount, size, prog)

    # ---- aba INTEGRIDADE -----------------------------------------------------
    def tab_integrity(self):
        f = ttk.Frame(self.nb, padding=10)
        self.nb.add(f, text="Integridade")
        ttk.Label(f, text="Verificacoes de integridade do Windows (somente leitura, nada e alterado).",
                  style="Sub.TLabel").pack(anchor="w")
        bar = ttk.Frame(f)
        bar.pack(fill="x", pady=6)
        for name, cmd in INTEGRITY_CMDS.items():
            ttk.Button(bar, text=name,
                       command=lambda n=name, c=cmd: self.run_integrity(n, c)).pack(side="left", padx=(0, 6))
        fr, self.int_text = make_text(f, height=20)
        fr.pack(fill="both", expand=True)

    def run_integrity(self, name, cmd):
        if not IS_WIN:
            messagebox.showinfo(APP_NAME, "Estas verificacoes existem apenas no Windows.")
            return
        if not is_admin() and cmd[0] != "chkdsk":
            messagebox.showwarning(APP_NAME, "SFC e DISM exigem administrador.")
            return
        self.int_text.delete("1.0", "end")
        self.int_text.insert("end", f"Executando: {' '.join(cmd)}\nPode demorar varios minutos...\n")
        self.say(f"{name} em andamento...")

        def done(r, e):
            self.int_text.insert("end", f"\n{r[1] if r else e}\n\nCodigo de saida: {r[0] if r else '-'}\n")
            log(f"Integridade: {name} -> codigo {r[0] if r else 'erro'}")
            self.say("Concluido.")
        self.bg(run_integrity, done, cmd)

    # ---- aba ARQUIVOS SUSPEITOS ------------------------------------------------
    def tab_scan(self):
        f = ttk.Frame(self.nb, padding=10)
        self.nb.add(f, text="Arquivos suspeitos")
        ttk.Label(f, style="Sub.TLabel", wraplength=1000,
                  text="Varredura por indicios (nao e antivirus): executaveis/scripts com extensao dupla, "
                       "em pastas temporarias, recentes ou com nome aleatorio. Use o hash para conferir no VirusTotal.").pack(anchor="w")
        row = ttk.Frame(f)
        row.pack(fill="x", pady=6)
        self.scan_folders = default_scan_folders()
        self.scan_lbl = tk.StringVar()
        self._upd_scan_lbl()
        ttk.Button(row, text="Escolher pastas...", command=self.pick_folders).pack(side="left", padx=(0, 6))
        ttk.Label(row, text="Recentes (dias):").pack(side="left")
        self.days_var = tk.StringVar(value="14")
        ttk.Spinbox(row, from_=1, to=365, width=5, textvariable=self.days_var).pack(side="left", padx=(4, 10))
        self.scan_btn = ttk.Button(row, text="Verificar", style="Accent.TButton", command=self.run_scan)
        self.scan_btn.pack(side="left", padx=(0, 6))
        ttk.Button(row, text="Parar", command=self.cancel_flag.set).pack(side="left")
        ttk.Label(f, textvariable=self.scan_lbl, style="Sub.TLabel", wraplength=1000).pack(anchor="w")
        fr, self.scan_tree = make_tree(f, [
            ("lvl", "Risco", 70, "center"), ("name", "Arquivo", 230, "w"),
            ("size", "Tamanho", 80, "e"), ("when", "Alterado", 120, "w"),
            ("why", "Motivos", 300, "w"), ("path", "Caminho", 400, "w")], height=14)
        fr.pack(fill="both", expand=True, pady=6)
        self.scan_data = {}
        self.scan_tree.bind("<Button-3>", self.scan_menu)
        row2 = ttk.Frame(f)
        row2.pack(fill="x")
        ttk.Button(row2, text="Calcular SHA-256 e abrir no VirusTotal",
                   command=self.scan_vt).pack(side="left", padx=(0, 6))
        ttk.Button(row2, text="Mostrar na pasta", command=self.scan_reveal).pack(side="left")
        self.hash_var = tk.StringVar()
        ttk.Entry(row2, textvariable=self.hash_var, width=70).pack(side="left", padx=8)

    def _upd_scan_lbl(self):
        self.scan_lbl.set("Pastas: " + " | ".join(str(p) for p in self.scan_folders))

    def pick_folders(self):
        d = filedialog.askdirectory(title="Adicionar pasta para verificar")
        if d:
            self.scan_folders.append(Path(d))
            self._upd_scan_lbl()

    def run_scan(self):
        self.scan_tree.delete(*self.scan_tree.get_children())
        self.scan_data.clear()
        self.cancel_flag.clear()
        self.scan_btn.state(["disabled"])
        try:
            days = int(self.days_var.get())
        except ValueError:
            days = 14

        def work():
            return scan_suspicious(self.scan_folders, days,
                                   cancel=self.cancel_flag.is_set,
                                   progress=lambda s: self.ui(self.say, f"Verificando {s[:90]}"))

        def done(r, e):
            self.scan_btn.state(["!disabled"])
            for it in (r or []):
                iid = self.scan_tree.insert("", "end", values=(
                    it["level"], os.path.basename(it["path"]), sizefmt(it["size"]),
                    it["mtime"], it["reasons"], it["path"]),
                    tags=("alto" if it["level"] == "ALTO" else "medio",))
                self.scan_data[iid] = it
            self.say(f"Verificacao concluida: {len(r or [])} item(ns) com indicios." +
                     (f" Erro: {e}" if e else ""))
            log(f"Verificacao de arquivos: {len(r or [])} suspeitos")
        self.bg(work, done)

    def scan_menu(self, ev):
        iid = self.scan_tree.identify_row(ev.y)
        if iid:
            self.scan_tree.selection_set(iid)
            m = tk.Menu(self, tearoff=0)
            m.add_command(label="Calcular hash / VirusTotal", command=self.scan_vt)
            m.add_command(label="Mostrar na pasta", command=self.scan_reveal)
            m.tk_popup(ev.x_root, ev.y_root)

    def scan_vt(self):
        s = self.scan_tree.selection()
        if not s:
            return
        path = self.scan_data[s[0]]["path"]
        self.say("Calculando hash...")

        def done(r, e):
            if e:
                messagebox.showerror(APP_NAME, str(e))
                return
            self.hash_var.set(r)
            self.say("Hash calculado.")
            if re.fullmatch(r"[0-9a-f]{64}", r):
                webbrowser.open(f"https://www.virustotal.com/gui/file/{r}")
        self.bg(file_sha256, done, path)

    def scan_reveal(self):
        s = self.scan_tree.selection()
        if s:
            p = self.scan_data[s[0]]["path"]
            if IS_WIN:
                subprocess.Popen(["explorer", "/select,", p])
            else:
                self.open_path(Path(p).parent)

    # ---- aba LIMPEZA -----------------------------------------------------------
    def tab_clean(self):
        f = ttk.Frame(self.nb, padding=10)
        self.nb.add(f, text="Limpeza")
        ttk.Label(f, style="Sub.TLabel", wraplength=1000,
                  text="Lista pastas e arquivos que nao correspondem a nenhum programa instalado (restos de "
                       "desinstalacoes) e arquivos temporarios. Revise antes: a deteccao e por nome e pode errar "
                       "com programas portateis.").pack(anchor="w")
        opts = ttk.Frame(f)
        opts.pack(fill="x", pady=6)
        self.root_vars = {}
        for label, _ in scan_roots() or [("(somente Windows)", None)]:
            v = tk.BooleanVar(value=label in ("Program Files", "Program Files (x86)",
                                              "AppData\\Local\\Programs", "ProgramData"))
            self.root_vars[label] = v
            ttk.Checkbutton(opts, text=label, variable=v).pack(side="left", padx=(0, 10))
        self.temp_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(opts, text="Arquivos temporarios", variable=self.temp_var).pack(side="left")
        self.clean_scan_btn = ttk.Button(opts, text="Procurar", style="Accent.TButton",
                                         command=self.run_clean_scan)
        self.clean_scan_btn.pack(side="right")
        fr, self.clean_tree = make_tree(f, [
            ("chk", "", 34, "center"), ("name", "Nome", 220, "w"),
            ("size", "Tamanho", 90, "e"), ("origin", "Origem", 160, "w"),
            ("mod", "Alterado", 90, "w"), ("reason", "Motivo", 230, "w"),
            ("path", "Caminho", 400, "w")], height=14)
        fr.pack(fill="both", expand=True)
        self.clean_data, self.clean_checked = {}, set()
        self.clean_tree.bind("<Button-1>", self.clean_click)
        row = ttk.Frame(f)
        row.pack(fill="x", pady=6)
        ttk.Button(row, text="Marcar todos", command=lambda: self.clean_mark(True)).pack(side="left", padx=(0, 6))
        ttk.Button(row, text="Desmarcar todos", command=lambda: self.clean_mark(False)).pack(side="left", padx=(0, 6))
        self.perm_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(row, text="Apagar de vez (sem quarentena)", variable=self.perm_var).pack(side="left", padx=10)
        self.clean_sum = tk.StringVar()
        ttk.Label(row, textvariable=self.clean_sum, foreground=ACC).pack(side="left", padx=10)
        ttk.Button(row, text="Deletar arquivos inuteis", style="Danger.TButton",
                   command=self.clean_delete).pack(side="right")
        ttk.Button(row, text="Abrir quarentena",
                   command=lambda: self.open_path(QUARANTINE_DIR)).pack(side="right", padx=6)

    def run_clean_scan(self):
        if not IS_WIN:
            messagebox.showinfo(APP_NAME, "A deteccao de programas instalados usa o registro do Windows.")
        roots = {k for k, v in self.root_vars.items() if v.get()}
        include_temp = self.temp_var.get()
        self.clean_scan_btn.state(["disabled"])
        self.cancel_flag.clear()
        self.say("Procurando restos de programas...")

        def work():
            known = Known(installed_programs())
            return find_leftovers(roots, include_temp, known, self.cancel_flag.is_set,
                                  lambda s: self.ui(self.say, f"Analisando {s[:90]}"))

        def done(r, e):
            self.clean_scan_btn.state(["!disabled"])
            self.clean_tree.delete(*self.clean_tree.get_children())
            self.clean_data.clear()
            self.clean_checked.clear()
            for it in (r or []):
                iid = self.clean_tree.insert("", "end", values=(
                    "\u2610", it["name"], sizefmt(it["size"]) + ("+" if it["partial"] else ""),
                    it["origin"], it["modified"], it["reason"], it["path"]))
                self.clean_data[iid] = it
            self._upd_clean_sum()
            self.say(f"{len(r or [])} item(ns) encontrados." + (f" Erro: {e}" if e else ""))
        self.bg(work, done)

    def clean_click(self, ev):
        if self.clean_tree.identify_region(ev.x, ev.y) != "cell":
            return
        if self.clean_tree.identify_column(ev.x) != "#1":
            return
        iid = self.clean_tree.identify_row(ev.y)
        if iid:
            self._set_check(iid, iid not in self.clean_checked)
            self._upd_clean_sum()

    def _set_check(self, iid, on):
        if on:
            self.clean_checked.add(iid)
        else:
            self.clean_checked.discard(iid)
        self.clean_tree.set(iid, "chk", "\u2611" if on else "\u2610")

    def clean_mark(self, on):
        for iid in self.clean_tree.get_children():
            self._set_check(iid, on)
        self._upd_clean_sum()

    def _upd_clean_sum(self):
        tot = sum(self.clean_data[i]["size"] for i in self.clean_checked)
        self.clean_sum.set(f"{len(self.clean_checked)} marcado(s) - {sizefmt(tot)}")

    def clean_delete(self):
        if not self.clean_checked:
            messagebox.showinfo(APP_NAME, "Marque os itens que deseja remover.")
            return
        items = [self.clean_data[i] for i in self.clean_checked]
        perm = self.perm_var.get()
        tot = sum(i["size"] for i in items)
        how = "APAGADOS DE VEZ (sem volta)" if perm else "movidos para a quarentena do SysGuard"
        if not messagebox.askyesno(APP_NAME, f"{len(items)} item(ns), {sizefmt(tot)}, serao {how}.\nContinuar?",
                                   icon="warning"):
            return
        self.say("Removendo...")

        def done(r, e):
            ok, fails = r if r else ([], [])
            for iid, it in list(self.clean_data.items()):
                if it["path"] in ok:
                    self.clean_tree.delete(iid)
                    self.clean_data.pop(iid)
                    self.clean_checked.discard(iid)
            self._upd_clean_sum()
            msg = f"{len(ok)} removido(s)."
            if fails:
                msg += f"\n{len(fails)} falha(s):\n" + "\n".join(f"- {p}: {m}" for p, m in fails[:8])
                if any("negado" in m.lower() or "denied" in m.lower() for _, m in fails):
                    msg += "\n\nDica: reabra como administrador."
            messagebox.showinfo(APP_NAME, msg)
            self.say("Concluido.")
        self.bg(delete_items, done, items, perm)

    # ---- aba DESINSTALADOR -------------------------------------------------------
    def tab_uninstall(self):
        f = ttk.Frame(self.nb, padding=10)
        self.nb.add(f, text="Desinstalador")
        ttk.Label(f, style="Sub.TLabel", wraplength=1000,
                  text="Marque varios programas e desinstale todos de uma vez (um apos o outro). "
                       "Programas sem modo silencioso abrem o desinstalador proprio deles.").pack(anchor="w")
        row = ttk.Frame(f)
        row.pack(fill="x", pady=6)
        ttk.Label(row, text="Buscar:").pack(side="left")
        self.un_filter = tk.StringVar()
        self.un_filter.trace_add("write", lambda *a: self.un_render())
        ttk.Entry(row, textvariable=self.un_filter, width=30).pack(side="left", padx=(4, 10))
        ttk.Button(row, text="Atualizar lista", command=self.un_load).pack(side="left", padx=(0, 10))
        self.un_silent = tk.BooleanVar(value=True)
        ttk.Checkbutton(row, text="Silencioso quando possivel", variable=self.un_silent).pack(side="left", padx=(0, 10))
        self.un_restore = tk.BooleanVar(value=True)
        ttk.Checkbutton(row, text="Criar ponto de restauracao", variable=self.un_restore).pack(side="left")
        fr, self.un_tree = make_tree(f, [
            ("chk", "", 34, "center"), ("name", "Programa", 330, "w"),
            ("ver", "Versao", 110, "w"), ("pub", "Fabricante", 220, "w"),
            ("size", "Tamanho", 90, "e"), ("date", "Instalado", 100, "w")], height=15)
        fr.pack(fill="both", expand=True)
        self.un_items, self.un_checked, self.un_sort = [], set(), ("name", False)
        for cid, key in (("name", "name"), ("ver", "version"), ("pub", "publisher"),
                         ("size", "size"), ("date", "date")):
            self.un_tree.heading(cid, text=self.un_tree.heading(cid)["text"],
                                 command=lambda k=key: self.un_sort_by(k))
        self.un_tree.bind("<Button-1>", self.un_click)
        row2 = ttk.Frame(f)
        row2.pack(fill="x", pady=6)
        ttk.Button(row2, text="Marcar visiveis", command=lambda: self.un_mark(True)).pack(side="left", padx=(0, 6))
        ttk.Button(row2, text="Desmarcar todos", command=lambda: self.un_mark(False)).pack(side="left", padx=(0, 6))
        self.un_sum = tk.StringVar()
        ttk.Label(row2, textvariable=self.un_sum, foreground=ACC).pack(side="left", padx=10)
        self.un_btn = ttk.Button(row2, text="Desinstalar marcados", style="Danger.TButton",
                                 command=self.un_run)
        self.un_btn.pack(side="right")
        ttk.Button(row2, text="Parar apos o atual", command=self.cancel_flag.set).pack(side="right", padx=6)
        self.un_prog = ttk.Progressbar(f, maximum=1.0)
        self.un_prog.pack(fill="x")
        self.un_loaded = False
        self.nb.bind("<<NotebookTabChanged>>", self._tab_changed)

    def _tab_changed(self, _ev=None):
        if self.nb.tab(self.nb.select(), "text") == "Desinstalador" and not self.un_loaded:
            self.un_load()

    def un_load(self):
        if not IS_WIN:
            messagebox.showinfo(APP_NAME, "O desinstalador funciona apenas no Windows.")
            return
        self.un_loaded = True
        self.say("Lendo programas instalados...")

        def done(r, e):
            self.un_items = r or []
            self.un_checked.clear()
            self.un_render()
            self.say(f"{len(self.un_items)} programas." + (f" Erro: {e}" if e else ""))
        self.bg(list_uninstallable, done)

    def un_sort_by(self, key):
        col, rev = self.un_sort
        self.un_sort = (key, (not rev) if col == key else False)
        self.un_render()

    def un_render(self):
        self.un_tree.delete(*self.un_tree.get_children())
        q = self.un_filter.get().strip().lower()
        key, rev = self.un_sort
        rows = [(i, p) for i, p in enumerate(self.un_items)
                if not q or q in p["name"].lower() or q in p["publisher"].lower()]
        rows.sort(key=lambda t: (t[1][key].lower() if isinstance(t[1][key], str) else t[1][key]),
                  reverse=rev)
        for i, p in rows:
            self.un_tree.insert("", "end", iid=str(i), values=(
                "☑" if i in self.un_checked else "☐", p["name"], p["version"],
                p["publisher"], sizefmt(p["size"]) if p["size"] else "", p["date"]))
        self._upd_un_sum()

    def un_click(self, ev):
        if self.un_tree.identify_region(ev.x, ev.y) != "cell" or \
                self.un_tree.identify_column(ev.x) != "#1":
            return
        iid = self.un_tree.identify_row(ev.y)
        if iid:
            i = int(iid)
            self.un_checked.symmetric_difference_update({i})
            self.un_tree.set(iid, "chk", "☑" if i in self.un_checked else "☐")
            self._upd_un_sum()

    def un_mark(self, on):
        if on:
            self.un_checked.update(int(i) for i in self.un_tree.get_children())
        else:
            self.un_checked.clear()
        self.un_render()

    def _upd_un_sum(self):
        tot = sum(self.un_items[i]["size"] for i in self.un_checked)
        self.un_sum.set(f"{len(self.un_checked)} marcado(s) - {sizefmt(tot)}")

    def un_run(self):
        sel = [self.un_items[i] for i in sorted(self.un_checked)]
        if not sel:
            messagebox.showinfo(APP_NAME, "Marque os programas que deseja desinstalar.")
            return
        names = "\n".join(f"- {p['name']}" for p in sel[:15]) + (f"\n... e mais {len(sel) - 15}" if len(sel) > 15 else "")
        if not messagebox.askyesno(APP_NAME, f"Desinstalar {len(sel)} programa(s)?\n\n{names}\n\n"
                                   "Salve seu trabalho antes. Alguns podem abrir janelas proprias.",
                                   icon="warning"):
            return
        silent, restore = self.un_silent.get(), self.un_restore.get()
        self.cancel_flag.clear()
        self.un_btn.state(["disabled"])

        def work():
            results = []
            if restore:
                self.ui(self.say, "Criando ponto de restauracao...")
                create_restore_point()
            for n, p in enumerate(sel, 1):
                if self.cancel_flag.is_set():
                    break
                self.ui(lambda n=n, p=p: (self.say(f"Desinstalando {n}/{len(sel)}: {p['name']}"),
                                          self.un_prog.configure(value=(n - 1) / len(sel))))
                results.append((p, *uninstall_one(p, silent)))
            return results

        def done(r, e):
            self.un_btn.state(["!disabled"])
            self.un_prog.configure(value=1.0)
            r = r or []
            ok = [x for x in r if x[1] == "ok"]
            bad = [x for x in r if x[1] != "ok"]
            msg = f"{len(ok)} removido(s), {len(bad)} falha(s)."
            for p, st, det in bad[:8]:
                msg += f"\n- {p['name']}: {det}"
            if any(x[2] for x in ok):
                msg += "\n\nAlgum programa pede para reiniciar o PC."
            self.un_load()
            if ok and messagebox.askyesno(APP_NAME, msg + "\n\nProcurar restos desses programas na aba Limpeza?"):
                self.nb.select(self.nb.index("end") - 2)
            else:
                messagebox.showinfo(APP_NAME, msg)
        self.bg(work, done)

    # ---- aba REGISTRO ------------------------------------------------------------
    def tab_log(self):
        f = ttk.Frame(self.nb, padding=10)
        self.nb.add(f, text="Registro")
        bar = ttk.Frame(f)
        bar.pack(fill="x")
        ttk.Button(bar, text="Abrir arquivo de log", command=lambda: self.open_path(LOG_FILE)).pack(side="left")
        fr, self.log_text = make_text(f, height=20)
        fr.pack(fill="both", expand=True, pady=6)
        try:
            self.log_text.insert("end", LOG_FILE.read_text(encoding="utf-8")[-20000:])
        except OSError:
            pass
        _log_listeners.append(lambda line: self.ui(self._log_add, line))

    def _log_add(self, line):
        self.log_text.insert("end", line + "\n")
        self.log_text.see("end")


def main():
    App().mainloop()


if __name__ == "__main__":
    main()
