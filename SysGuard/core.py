#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SysGuard - núcleo (sem interface): hosts, sistema, disco, integridade, scan,
desinstalador, limpeza, log e configuração.
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
        return "Antivírus/Segurança"
    if any(k in d for k in UPDATE_KEYS):
        return "Microsoft/Windows Update"
    if any(k in d for k in PIRACY_KEYS):
        return "Torrent/Pirataria"
    if any(k in d for k in ADS_KEYS):
        return "Anúncios/Rastreio"
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
                status, risk = "Padrão", "ok"
            elif blocked:
                status = "Bloqueado"
                risk = "alto" if cat in ("Antivírus/Segurança",
                                         "Microsoft/Windows Update") else "info"
            else:
                status = f"Redireciona -> {ip}"
                risk = "alto" if cat in ("Antivírus/Segurança",
                                         "Microsoft/Windows Update") else "medio"
            entries.append(dict(line=no, ip=ip, domain=dom, category=cat,
                                status=status, risk=risk))
    return entries


def hosts_summary(entries):
    ativos = [e for e in entries if e["risk"] != "ok"]
    alto = [e for e in ativos if e["risk"] == "alto"]
    return (f"{len(ativos)} entrada(s) fora do padrão, "
            f"{len(alto)} de risco ALTO (antivírus/Windows Update bloqueados ou redirecionados).")


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
    """Remove domínios de antivírus/Windows Update bloqueados ou redirecionados.
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
                        "Antivírus/Segurança", "Microsoft/Windows Update"):
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
        "Versão": platform.version(),
        "Arquitetura": platform.machine(),
        "Nome do PC": platform.node(),
    }
    cpu = {"Processador": platform.processor() or "?"}
    if psutil:
        cpu["Núcleos físicos"] = psutil.cpu_count(logical=False)
        cpu["Threads"] = psutil.cpu_count(logical=True)
        f = psutil.cpu_freq()
        if f:
            cpu["Frequência atual (MHz)"] = round(f.current)
            if f.max:
                cpu["Frequência máxima (MHz)"] = round(f.max)
    sections["CPU"] = cpu
    if psutil:
        vm = psutil.virtual_memory()
        sections["Memória"] = {"Total": sizefmt(vm.total),
                               "Em uso": f"{sizefmt(vm.used)} ({vm.percent}%)"}
    if IS_WIN:
        ps = (
            "$o=[ordered]@{};"
            "$o.cpu=@(Get-CimInstance Win32_Processor|Select Name,NumberOfCores,NumberOfLogicalProcessors,MaxClockSpeed,L2CacheSize,L3CacheSize,SocketDesignation);"
            "$o.board=@(Get-CimInstance Win32_BaseBoard|Select Manufacturer,Product);"
            "$o.bios=@(Get-CimInstance Win32_BIOS|Select SMBIOSBIOSVersion,ReleaseDate);"
            "$o.gpu=@(Get-CimInstance Win32_VideoController|Select Name,AdapterRAM,DriverVersion,CurrentHorizontalResolution,CurrentVerticalResolution,CurrentRefreshRate);"
            "$o.ram=@(Get-CimInstance Win32_PhysicalMemory|Select Manufacturer,Capacity,Speed,PartNumber,BankLabel);"
            "$o.os=@(Get-CimInstance Win32_OperatingSystem|Select Caption,Version,OSArchitecture,LastBootUpTime);"
            "$o.cs=@(Get-CimInstance Win32_ComputerSystem|Select Manufacturer,Model,SystemType);"
            "$o.disk=@(Get-CimInstance Win32_DiskDrive|Select Model,Size,InterfaceType,MediaType);"
            "$o|ConvertTo-Json -Depth 4 -Compress"
        )
        try:
            data = json.loads(powershell(ps, 60))
        except Exception as e:
            data = {}
            sections["Aviso"] = {"WMI": f"não foi possível ler: {e}"}
        for c in _as_list(data.get("cpu")):
            sections["CPU"] = {
                "Modelo": str(c.get("Name", "")).strip(),
                "Socket": c.get("SocketDesignation"),
                "Núcleos": c.get("NumberOfCores"),
                "Threads": c.get("NumberOfLogicalProcessors"),
                "Clock base (MHz)": c.get("MaxClockSpeed"),
                "Cache L2 (KB)": c.get("L2CacheSize"),
                "Cache L3 (KB)": c.get("L3CacheSize"),
            }
        for c in _as_list(data.get("cs")):
            sections["Computador"] = {"Fabricante": c.get("Manufacturer"), "Modelo": c.get("Model"),
                                      "Tipo": c.get("SystemType")}
        for i, dk in enumerate(_as_list(data.get("disk")), 1):
            sections[f"Disco físico {i}"] = {
                "Modelo": dk.get("Model"), "Capacidade": sizefmt(dk.get("Size") or 0),
                "Interface": dk.get("InterfaceType"), "Tipo": dk.get("MediaType")}
        for o in _as_list(data.get("os")):
            sections["Sistema operacional"]["Edicao"] = o.get("Caption")
        for b in _as_list(data.get("board")):
            sections["Placa-mãe"] = {"Fabricante": b.get("Manufacturer"),
                                     "Modelo": b.get("Product")}
        for b in _as_list(data.get("bios")):
            sections["BIOS"] = {"Versão": b.get("SMBIOSBIOSVersion")}
        for i, g in enumerate(_as_list(data.get("gpu")), 1):
            ram = g.get("AdapterRAM")
            sections[f"GPU {i}"] = {
                "Modelo": g.get("Name"),
                "Driver": g.get("DriverVersion"),
                "VRAM (WMI, limite 4 GB)": sizefmt(ram) if ram else "?",
                "Resolução": f"{g.get('CurrentHorizontalResolution')}x{g.get('CurrentVerticalResolution')} @ {g.get('CurrentRefreshRate')} Hz",
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
        temps = psutil.sensors_temperatures()  # não existe no Windows
        for name, arr in temps.items():
            if arr:
                s += f"    Temp {name}: {arr[0].current:.0f}C"
                break
    except Exception:
        pass
    return s


# ----------------------------------------------------------------------------
# DISCO: saúde + benchmark
# ----------------------------------------------------------------------------
def disk_health():
    """Lista de dicts com saúde dos discos físicos."""
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
    return [{"Nome": "Leitura de SMART só disponível no Windows (ou com smartctl)"}]


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
        progress("Concluído", 1.0)
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
    "DISM - CheckHealth (rápido)": ["DISM", "/Online", "/Cleanup-Image", "/CheckHealth"],
    "DISM - ScanHealth (demorado)": ["DISM", "/Online", "/Cleanup-Image", "/ScanHealth"],
    "CHKDSK C: (somente leitura)": ["chkdsk", "C:"],
}


def run_integrity(cmd):
    return run_cmd(cmd, timeout=3600)


# ----------------------------------------------------------------------------
# VERIFICACAO DE ARQUIVOS SUSPEITOS (antes do antivírus)
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
        reasons.append("extensão dupla (parece documento)")
        score += 3
    low = str(p).lower()
    if any(k in low for k in ("\\temp\\", "/temp/", "\\appdata\\", "/tmp/")):
        reasons.append("em pasta temporária/AppData")
        score += 1
    if time.time() - st.st_mtime < recent_days * 86400:
        reasons.append(f"criado/alterado há menos de {recent_days} dias")
        score += 1
    if RANDOM_NAME.match(p.stem) and p.suffix.lower() in {".exe", ".dll", ".scr"}:
        reasons.append("nome aleatório")
        score += 1
    if IS_WIN and getattr(st, "st_file_attributes", 0) & 0x2:
        reasons.append("oculto")
        score += 1
    if p.suffix.lower() in {".scr", ".pif", ".hta", ".vbs", ".jse", ".wsf"}:
        reasons.append("tipo de script/executável incomum")
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
# LIMPEZA: pastas de programas que não estão instalados
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
            return True  # nomes curtos demais: não arriscar
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
                              origin="Temporários", modified=mt,
                              reason="Arquivo temporário"))
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
    """Move para quarentena (padrão) ou apaga de vez. Devolve (ok, falhas)."""
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
                    raise OSError("alguns itens estão em uso")
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
    """Programas desinstaláveis (sem componentes de sistema e atualizacoes)."""
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
    log("Ponto de restauração " + ("criado" if ok else f"não criado: {out.strip()[:200]}"))
    return ok


def uninstall_one(p, silent=True, timeout=1800):
    """Executa o desinstalador e confere no registro. Devolve (status, detalhe)."""
    cmd, is_silent = build_uninstall_cmd(p, silent)
    if not cmd:
        return "falha", "sem comando de desinstalação"
    log(f"DESINSTALAR: {p['name']} -> {cmd}")
    try:
        flags = 0x08000000 if IS_WIN else 0  # sem janela de console (janelas graficas dos instaladores continuam aparecendo)
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
    log(f"  código {rc}, removido={gone}")
    if gone:
        return "ok", "reiniciar o PC pode ser necessário" if rc == 3010 else ""
    return "falha", f"código {rc}; o programa ainda aparece instalado (cancelado ou precisa de admin)"


# ----------------------------------------------------------------------------
# CONFIGURACAO (config.json em APP_DIR)
# ----------------------------------------------------------------------------
CONFIG_FILE = APP_DIR / "config.json"
DEFAULT_CONFIG = {
    "overlay": {
        "enabled": False, "corner": "top-left", "scale": 1.0, "opacity": 0.85,
        "click_through": True, "x": 20, "y": 20,
        "items": {"cpu": True, "cpu_temp": True, "gpu": True, "gpu_temp": True,
                  "vram": True, "ram": True, "net": False, "battery": False,
                  "clock": False, "fan": False},
    },
    "openrgb_path": "", "lhm_path": "", "lhm_dll_dir": "",
    "fan_reset_on_exit": True,
}
_cfg_lock = threading.Lock()


def _merge(base, over):
    out = dict(base)
    for k, v in (over or {}).items():
        out[k] = _merge(base[k], v) if isinstance(v, dict) and isinstance(base.get(k), dict) else v
    return out


def load_config():
    try:
        return _merge(DEFAULT_CONFIG, json.loads(CONFIG_FILE.read_text(encoding="utf-8")))
    except (OSError, ValueError):
        return _merge(DEFAULT_CONFIG, {})


def save_config(cfg):
    with _cfg_lock:
        try:
            CONFIG_FILE.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
        except OSError:
            pass
