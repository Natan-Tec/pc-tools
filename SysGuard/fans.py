# -*- coding: utf-8 -*-
"""
SysGuard - controle de ventoinhas via LibreHardwareMonitorLib (opcional).

Funciona só em PCs cujo chip de monitoramento (Super I/O) ou GPU aceite controle por
software. A maioria dos notebooks controla a ventoinha pela BIOS/EC e NÃO aparece aqui.
Requer: administrador, `pip install pythonnet` e LibreHardwareMonitorLib.dll (+ HidSharp.dll)
numa pasta (configuravel).
"""
import sys
import threading
from pathlib import Path

from core import IS_WIN, log

MIN_PCT = 25  # nunca desliga a ventoinha por completo

PRESETS = {
    "Silencioso": [(40, 25), (60, 35), (75, 60), (85, 100)],
    "Equilibrado": [(40, 35), (55, 45), (70, 70), (80, 100)],
    "Turbo": [(30, 60), (50, 75), (65, 100)],
}


def curve_pct(points, temp):
    """Interpolacao linear da curva (lista de (temp, %))."""
    pts = sorted(points)
    if temp <= pts[0][0]:
        return float(pts[0][1])
    if temp >= pts[-1][0]:
        return float(pts[-1][1])
    for (t0, p0), (t1, p1) in zip(pts, pts[1:]):
        if t0 <= temp <= t1:
            return p0 + (p1 - p0) * (temp - t0) / (t1 - t0)
    return float(pts[-1][1])


def find_dll_dir(cfg):
    cands = []
    if cfg.get("lhm_dll_dir"):
        cands.append(Path(cfg["lhm_dll_dir"]))
    if cfg.get("lhm_path"):
        cands.append(Path(cfg["lhm_path"]).parent)
    cands.append(Path(sys.argv[0]).resolve().parent)
    cands.append(Path(__file__).resolve().parent)
    for c in cands:
        if (c / "LibreHardwareMonitorLib.dll").exists():
            return c
    return None


class LhmFanControl:
    def __init__(self, dll_dir):
        self.ok, self.reason = False, ""
        self._sensors, self._computer = {}, None
        if not IS_WIN:
            self.reason = "Disponível apenas no Windows."
            return
        if not dll_dir:
            self.reason = "LibreHardwareMonitorLib.dll não encontrada."
            return
        try:
            import clr  # pythonnet
        except ImportError:
            self.reason = "Instale o pythonnet:  pip install pythonnet"
            return
        try:
            sys.path.append(str(dll_dir))
            clr.AddReference(str(Path(dll_dir) / "LibreHardwareMonitorLib.dll"))
            from LibreHardwareMonitor.Hardware import Computer, SensorType
            c = Computer()
            c.IsCpuEnabled = c.IsGpuEnabled = c.IsMotherboardEnabled = c.IsControllerEnabled = True
            c.Open()
            self._computer, self._ST = c, SensorType
            self.ok = True
            self.refresh()
        except Exception as e:  # noqa
            self.reason = f"Falha ao carregar a biblioteca: {e}"

    def _walk(self, hw):
        hw.Update()
        for s in hw.Sensors:
            yield hw, s
        for sub in hw.SubHardware:
            yield from self._walk(sub)

    def refresh(self):
        """Lista de controles: [{id, name, hw, value}]"""
        out, self._sensors = [], {}
        for top in self._computer.Hardware:
            for hw, s in self._walk(top):
                if s.SensorType == self._ST.Control and s.Control is not None:
                    sid = str(s.Identifier)
                    self._sensors[sid] = s
                    out.append(dict(id=sid, name=str(s.Name), hw=str(hw.Name),
                                    value=float(s.Value) if s.Value is not None else None))
        return out

    def set_pct(self, sid, pct):
        pct = max(MIN_PCT, min(100.0, float(pct)))
        self._sensors[sid].Control.SetSoftware(pct)

    def reset(self, sid):
        self._sensors[sid].Control.SetDefault()

    def reset_all(self):
        for sid in list(self._sensors):
            try:
                self.reset(sid)
            except Exception:
                pass

    def close(self):
        self.reset_all()
        try:
            self._computer.Close()
        except Exception:
            pass


class FanAutopilot:
    """Aplica uma curva temperatura -> % nos controles escolhidos."""

    def __init__(self, ctl, ids, points, temp_fn, interval=3.0):
        self.ctl, self.ids, self.points, self.temp_fn = ctl, list(ids), points, temp_fn
        self.interval, self._stop = interval, threading.Event()
        self.last = None

    def start(self):
        self._stop.clear()
        threading.Thread(target=self._run, daemon=True).start()

    def stop(self):
        self._stop.set()
        self.ctl.reset_all()

    def tick(self):
        t = self.temp_fn()
        if t is None:  # sem leitura de temperatura: devolve o controle a BIOS
            self.ctl.reset_all()
            self.last = None
            return None
        pct = max(MIN_PCT, curve_pct(self.points, t))
        for sid in self.ids:
            self.ctl.set_pct(sid, pct)
        self.last = pct
        return pct

    def _run(self):
        while not self._stop.wait(self.interval):
            try:
                self.tick()
            except Exception as e:  # noqa
                log(f"autopilot ventoinha: {e}")
