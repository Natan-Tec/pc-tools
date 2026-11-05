# -*- coding: utf-8 -*-
"""
SysGuard - sensores em tempo real e bateria (sem interface grafica).

Fontes, em ordem de preferencia:
  - psutil: CPU, RAM, rede, disco, bateria (e temperaturas/fans no Linux)
  - nvidia-smi: GPU NVIDIA (carga, temperatura, VRAM, consumo, fan)
  - LibreHardwareMonitor/OpenHardwareMonitor via WMI (se estiver aberto): temperaturas,
    rotação de ventoinhas, carga/VRAM de GPU AMD/Intel
  - WMI nativo do Windows: zona termica ACPI (precisa de admin) e contadores de GPU
"""
import os
import re
import csv
import json
import time
import shutil
import tempfile
import threading
import subprocess
import datetime
import xml.etree.ElementTree as ET
from collections import deque
from pathlib import Path

from core import IS_WIN, APP_DIR, log, run_cmd

try:
    import psutil
except ImportError:
    psutil = None


def _num(x):
    try:
        return float(str(x).strip())
    except (TypeError, ValueError):
        return None


# ----------------------------------------------------------------------------
# NVIDIA
# ----------------------------------------------------------------------------
NV_FIELDS = "name,utilization.gpu,temperature.gpu,memory.used,memory.total,power.draw,fan.speed,clocks.gr"


def parse_nvidia_smi(text):
    line = (text or "").strip().splitlines()
    if not line:
        return None
    p = [x.strip() for x in line[0].split(",")]
    if len(p) < 8:
        return None
    return dict(name=p[0], load=_num(p[1]), temp=_num(p[2]), vram_used=_num(p[3]),
                vram_total=_num(p[4]), power=_num(p[5]), fan_pct=_num(p[6]),
                clock=_num(p[7]))


def nvidia_query():
    exe = shutil.which("nvidia-smi")
    if not exe and IS_WIN:
        cand = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / \
            "NVIDIA Corporation" / "NVSMI" / "nvidia-smi.exe"
        exe = str(cand) if cand.exists() else None
    if not exe:
        return None
    try:
        rc, out = run_cmd([exe, f"--query-gpu={NV_FIELDS}", "--format=csv,noheader,nounits"], 6)
    except Exception:
        return None
    return parse_nvidia_smi(out) if rc == 0 else None


# ----------------------------------------------------------------------------
# LibreHardwareMonitor / ACPI / contadores de GPU (via WMI no Windows)
# ----------------------------------------------------------------------------
def parse_lhm(rows):
    r = dict(cpu_temp=None, gpu_temp=None, gpu_load=None, gpu_vram_used=None,
             gpu_vram_total=None, cpu_power=None, gpu_power=None, cpu_clock=None,
             gpu_clock=None, fans=[], controls=[], temps={})
    cpu_pref, cpu_all = None, []
    for row in rows or []:
        val = _num(row.get("Value"))
        if val is None:
            continue
        ident = str(row.get("Identifier", "")).lower()
        typ, name = row.get("SensorType"), str(row.get("Name", ""))
        is_cpu = "/intelcpu/" in ident or "/amdcpu/" in ident
        is_gpu = "/gpu-" in ident or "/gpu/" in ident
        if typ == "Temperature":
            r["temps"][name] = val
            if is_cpu:
                cpu_all.append(val)
                if re.search(r"package|tctl|tdie", name, re.I):
                    cpu_pref = val
            elif is_gpu and r["gpu_temp"] is None and re.search(r"core|gpu", name, re.I):
                r["gpu_temp"] = val
        elif typ == "Load" and is_gpu and name == "GPU Core":
            r["gpu_load"] = val
        elif typ in ("SmallData", "Data") and is_gpu:
            if name in ("GPU Memory Used", "D3D Dedicated Memory Used"):
                r["gpu_vram_used"] = val
            elif name == "GPU Memory Total":
                r["gpu_vram_total"] = val
        elif typ == "Power":
            if is_cpu and re.search(r"package", name, re.I):
                r["cpu_power"] = val
            elif is_gpu and r["gpu_power"] is None:
                r["gpu_power"] = val
        elif typ == "Clock":
            if is_cpu and name.startswith("Core"):
                r["cpu_clock"] = max(val, r["cpu_clock"] or 0)
            elif is_gpu and name == "GPU Core":
                r["gpu_clock"] = val
        elif typ == "Fan":
            r["fans"].append((name, val))
        elif typ == "Control":
            r["controls"].append((name, val))
    r["cpu_temp"] = cpu_pref if cpu_pref is not None else (max(cpu_all) if cpu_all else None)
    return r


def parse_acpi(rows):
    vals = []
    for row in rows or []:
        v = _num(row.get("CurrentTemperature"))
        if v and v > 2000:  # decikelvin
            vals.append(v / 10.0 - 273.15)
    return max(vals) if vals else None


def parse_gpu_engines(rows):
    """Carga de GPU como no Gerenciador de Tarefas: maior soma por tipo de engine."""
    per = {}
    for row in rows or []:
        m = re.search(r"engtype_(\w+)", str(row.get("Name", "")))
        v = _num(row.get("UtilizationPercentage"))
        if m and v is not None:
            per[m.group(1)] = per.get(m.group(1), 0.0) + v
    return min(100.0, max(per.values())) if per else None


def parse_gpu_mem(rows):
    used = sum(_num(r.get("DedicatedUsage")) or 0 for r in rows or [])
    return used / (1024 * 1024) if used else None  # MB


PS_LOOP = r"""
$ErrorActionPreference='SilentlyContinue'
$skipGpu=__SKIPGPU__
[Console]::OutputEncoding=[Text.Encoding]::UTF8
while($true){
  $o=@{}
  foreach($ns in 'root/LibreHardwareMonitor','root/OpenHardwareMonitor'){
    $s=Get-CimInstance -Namespace $ns -ClassName Sensor
    if($s){ $o.lhm=@($s|Select-Object Name,SensorType,Value,Identifier); break }
  }
  $t=Get-CimInstance -Namespace root/wmi -ClassName MSAcpi_ThermalZoneTemperature
  if($t){ $o.acpi=@($t|Select-Object InstanceName,CurrentTemperature) }
  if(-not $skipGpu){
    $g=Get-CimInstance Win32_PerfFormattedData_GPUPerformanceCounters_GPUEngine
    if($g){ $o.gpueng=@($g|Select-Object Name,UtilizationPercentage) }
    $m=Get-CimInstance Win32_PerfFormattedData_GPUPerformanceCounters_GPUAdapterMemory
    if($m){ $o.gpumem=@($m|Select-Object Name,DedicatedUsage) }
  }
  ($o|ConvertTo-Json -Depth 4 -Compress)
  [Console]::Out.Flush()
  Start-Sleep -Seconds 3
}
"""


class PsStream:
    """Um único PowerShell persistente que imprime um JSON por linha (barato em CPU)."""

    def __init__(self, script, on_json):
        self.script, self.on_json, self.proc = script, on_json, None

    def start(self):
        try:
            self.proc = subprocess.Popen(
                ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                 "-Command", self.script],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL,
                creationflags=0x08000000)
        except OSError as e:
            log(f"PowerShell de sensores não iniciou: {e}")
            return
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self):
        for raw in self.proc.stdout:
            try:
                self.on_json(json.loads(raw.decode("utf-8", "replace")))
            except ValueError:
                pass

    def stop(self):
        try:
            if self.proc:
                self.proc.terminate()
        except OSError:
            pass


# ----------------------------------------------------------------------------
# SensorHub: uma thread que mantem um "snapshot" com tudo
# ----------------------------------------------------------------------------
class SensorHub:
    HIST = 90

    def __init__(self):
        self._lock = threading.Lock()
        self._data = {}
        self._extra = {}
        self._nv = None
        self._stop = threading.Event()
        self._ps = None
        self._last_net = self._last_disk = None
        self.hist = {k: deque(maxlen=self.HIST) for k in
                     ("cpu", "gpu", "ram", "cpu_temp", "gpu_temp")}
        self.has_nvidia = bool(shutil.which("nvidia-smi")) or (IS_WIN and nvidia_query() is not None)

    def start(self):
        if psutil:
            psutil.cpu_percent(None)
            psutil.cpu_percent(None, percpu=True)
        threading.Thread(target=self._loop, daemon=True).start()
        if self.has_nvidia:
            threading.Thread(target=self._nv_loop, daemon=True).start()
        if IS_WIN:
            self._ps = PsStream(PS_LOOP.replace("__SKIPGPU__", "$true" if self.has_nvidia else "$false"), self._on_ps)
            self._ps.start()

    def stop(self):
        self._stop.set()
        if self._ps:
            self._ps.stop()

    def snapshot(self):
        with self._lock:
            d = dict(self._data)
        d["hist"] = {k: list(v) for k, v in self.hist.items()}
        return d

    # --- fontes lentas -------------------------------------------------------
    def _nv_loop(self):
        while not self._stop.wait(2.0):
            self._nv = nvidia_query()

    def _on_ps(self, obj):
        e = {}
        if obj.get("lhm"):
            e["lhm"] = parse_lhm(obj["lhm"])
        if obj.get("acpi"):
            e["acpi_temp"] = parse_acpi(obj["acpi"])
        if obj.get("gpueng"):
            e["gpu_eng_load"] = parse_gpu_engines(obj["gpueng"])
        if obj.get("gpumem"):
            e["gpu_mem_used"] = parse_gpu_mem(obj["gpumem"])
        self._extra = e

    # --- amostragem de 1 s ---------------------------------------------------
    def _loop(self):
        while not self._stop.wait(1.0):
            try:
                self._sample()
            except Exception as ex:  # nunca derrubar a thread
                log(f"sensor: {ex}")

    def _sample(self):
        d = {"ts": time.time()}
        if psutil:
            d["cpu"] = psutil.cpu_percent(None)
            d["cores"] = psutil.cpu_percent(None, percpu=True)
            f = psutil.cpu_freq()
            d["cpu_mhz"] = f.current if f else None
            vm = psutil.virtual_memory()
            d.update(ram=vm.percent, ram_used=vm.used, ram_total=vm.total)
            now = time.time()
            n = psutil.net_io_counters()
            if self._last_net:
                dt = max(now - self._last_net[0], 1e-3)
                d["net_up"] = (n.bytes_sent - self._last_net[1]) / dt
                d["net_down"] = (n.bytes_recv - self._last_net[2]) / dt
            self._last_net = (now, n.bytes_sent, n.bytes_recv)
            try:
                io = psutil.disk_io_counters()
                if io and self._last_disk:
                    dt = max(now - self._last_disk[0], 1e-3)
                    d["disk_read"] = (io.read_bytes - self._last_disk[1]) / dt
                    d["disk_write"] = (io.write_bytes - self._last_disk[2]) / dt
                if io:
                    self._last_disk = (now, io.read_bytes, io.write_bytes)
            except Exception:
                pass
            b = battery_live()
            if b:
                d["battery"] = b
            d["cpu_temp"], d["fans"] = self._psutil_temps()
        ex = self._extra
        lhm = ex.get("lhm") or {}
        if lhm.get("cpu_temp") is not None:
            d["cpu_temp"] = lhm["cpu_temp"]
        elif d.get("cpu_temp") is None and ex.get("acpi_temp") is not None:
            d["cpu_temp"] = ex["acpi_temp"]
        if lhm.get("fans"):
            d["fans"] = lhm["fans"]
        d["controls"] = lhm.get("controls", [])
        d["cpu_power"], d["gpu_power"] = lhm.get("cpu_power"), lhm.get("gpu_power")
        if lhm.get("cpu_clock"):
            d["cpu_mhz"] = lhm["cpu_clock"]
        nv = self._nv
        g = dict(name=None, load=None, temp=None, vram_used=None, vram_total=None,
                 power=None, fan_pct=None, clock=None)
        if nv:
            g.update(nv)
        else:
            g["load"] = lhm.get("gpu_load") if lhm.get("gpu_load") is not None else ex.get("gpu_eng_load")
            g["temp"] = lhm.get("gpu_temp")
            g["vram_used"] = lhm.get("gpu_vram_used") if lhm.get("gpu_vram_used") is not None else ex.get("gpu_mem_used")
            g["vram_total"] = lhm.get("gpu_vram_total")
            g["power"], g["clock"] = lhm.get("gpu_power"), lhm.get("gpu_clock")
        d["gpu"] = g
        d["sources"] = dict(lhm=bool(lhm), nvidia=bool(nv), acpi=ex.get("acpi_temp") is not None)
        with self._lock:
            self._data = d
        for k, v in (("cpu", d.get("cpu")), ("gpu", g["load"]), ("ram", d.get("ram")),
                     ("cpu_temp", d.get("cpu_temp")), ("gpu_temp", g["temp"])):
            self.hist[k].append(v)

    @staticmethod
    def _psutil_temps():
        temp, fans = None, []
        try:
            t = psutil.sensors_temperatures()  # só existe no Linux
            for key in ("coretemp", "k10temp", "zenpower", "cpu_thermal", "acpitz"):
                if t.get(key):
                    temp = t[key][0].current
                    break
        except Exception:
            pass
        try:
            for name, arr in psutil.sensors_fans().items():
                for i, f in enumerate(arr):
                    fans.append((f.label or f"{name} {i + 1}", f.current))
        except Exception:
            pass
        return temp, fans


# ----------------------------------------------------------------------------
# BATERIA
# ----------------------------------------------------------------------------
def battery_live():
    if not psutil or not hasattr(psutil, "sensors_battery"):
        return None
    try:
        b = psutil.sensors_battery()
    except Exception:
        return None
    if not b:
        return None
    secs = b.secsleft if b.secsleft not in (None, -1, -2) and b.secsleft >= 0 else None
    return dict(percent=b.percent, plugged=bool(b.power_plugged), secs_left=secs)


def parse_battery_xml(data):
    """Le o XML de 'powercfg /batteryreport /xml'."""
    root = ET.fromstring(data)
    for el in root.iter():  # remove namespaces
        el.tag = el.tag.split("}", 1)[-1]
    out = []
    for b in root.iter("Battery"):
        g = lambda k: (b.findtext(k) or "").strip()  # noqa
        design, full = _num(g("DesignCapacity")), _num(g("FullChargeCapacity"))
        if not design:
            continue
        out.append(dict(
            id=g("Id"), manufacturer=g("Manufacturer"), chemistry=g("Chemistry"),
            serial=g("SerialNumber"), design_mwh=design, full_mwh=full,
            cycles=int(_num(g("CycleCount")) or 0),
            health=round(full / design * 100, 1) if full else None))
    return out


def read_sysfs_battery(base="/sys/class/power_supply"):
    out = []
    for p in sorted(Path(base).glob("BAT*")):
        def rd(n, p=p):
            try:
                return (p / n).read_text().strip()
            except OSError:
                return ""
        design = _num(rd("energy_full_design")) or _num(rd("charge_full_design"))
        full = _num(rd("energy_full")) or _num(rd("charge_full"))
        if not design:
            continue
        k = 1 / 1000.0  # uWh -> mWh (se for carga, uAh -> mAh)
        out.append(dict(id=p.name, manufacturer=rd("manufacturer"), chemistry=rd("technology"),
                        serial=rd("serial_number"), design_mwh=design * k,
                        full_mwh=(full or 0) * k, cycles=int(_num(rd("cycle_count")) or 0),
                        health=round(full / design * 100, 1) if full else None))
    return out


def battery_report():
    """Lista de baterias com capacidade de projeto x atual (saúde)."""
    if IS_WIN:
        path = Path(tempfile.gettempdir()) / "sysguard_battery.xml"
        rc, out = run_cmd(["powercfg", "/batteryreport", "/xml", "/output", str(path)], 40)
        if not path.exists():
            raise RuntimeError(out.strip() or "powercfg não gerou o relatório (PC sem bateria?)")
        try:
            return parse_battery_xml(path.read_bytes())
        finally:
            try:
                path.unlink()
            except OSError:
                pass
    return read_sysfs_battery()


def battery_html_report(dest=None):
    dest = Path(dest or (APP_DIR / "relatorio_bateria.html"))
    run_cmd(["powercfg", "/batteryreport", "/output", str(dest)], 40)
    return dest


def battery_verdict(health):
    if health is None:
        return "Sem dados de capacidade.", "muted"
    if health >= 85:
        return "Bateria em ótimo estado.", "ok"
    if health >= 70:
        return "Desgaste normal. Ainda atende bem.", "ok"
    if health >= 50:
        return "Desgaste considerável: a autonomia já caiu bastante.", "warn"
    return "Bateria muito degradada. Considere trocar.", "bad"


def format_secs(s):
    if s is None:
        return "-"
    h, m = divmod(int(s) // 60, 60)
    return f"{h} h {m:02d} min"


BATT_HIST = APP_DIR / "bateria_historico.json"


def record_battery_health(b):
    """Guarda no máximo 1 ponto por dia para acompanhar o desgaste."""
    try:
        hist = json.loads(BATT_HIST.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        hist = []
    today = datetime.date.today().isoformat()
    if b.get("health") is not None and not any(h["date"] == today for h in hist):
        hist.append(dict(date=today, health=b["health"], full=b["full_mwh"], design=b["design_mwh"],
                         cycles=b.get("cycles", 0)))
        try:
            BATT_HIST.write_text(json.dumps(hist[-400:]), encoding="utf-8")
        except OSError:
            pass
    return hist
