# -*- coding: utf-8 -*-
"""SysGuard - overlay de monitoramento (estilo MSI Afterburner / RTSS)."""
import time
import tkinter as tk
import tkinter.font as tkfont

import widgets as W
from widgets import C, px
from core import IS_WIN, sizefmt

KEY = "#010203"  # cor transparente (Windows)
CORNERS = {"Topo esquerdo": "top-left", "Topo direito": "top-right",
           "Base esquerda": "bottom-left", "Base direita": "bottom-right"}

ITEM_LABELS = {
    "cpu": "CPU - uso", "cpu_temp": "CPU - temperatura", "gpu": "GPU - uso",
    "gpu_temp": "GPU - temperatura", "vram": "GPU - memória (VRAM)", "ram": "Memória RAM",
    "net": "Rede (download/upload)", "battery": "Bateria", "clock": "Relógio",
    "fan": "Ventoinha (RPM)",
}


def fmt_rate(bps):
    if bps is None:
        return "--"
    for u in ("B/s", "KB/s", "MB/s", "GB/s"):
        if bps < 1024 or u == "GB/s":
            return f"{bps:.0f} {u}" if u == "B/s" else f"{bps:.1f} {u}"
        bps /= 1024


def overlay_rows(snap, items):
    """-> lista de (rotulo, valor, cor, fracao|None). Função pura (testável)."""
    rows = []
    g = snap.get("gpu") or {}

    def pct_row(label, v, extra=""):
        if v is None:
            rows.append((label, "--", C["dim"], None))
        else:
            rows.append((label, f"{v:.0f}%{extra}", W.level_color(v), v / 100.0))

    def temp_row(label, t):
        if t is None:
            rows.append((label, "--", C["dim"], None))
        else:
            rows.append((label, f"{t:.0f}°C", W.level_color(t, 65, 80), min(t / 100.0, 1.0)))
    if items.get("cpu"):
        mhz = snap.get("cpu_mhz")
        pct_row("CPU", snap.get("cpu"), f"  {mhz / 1000:.1f} GHz" if mhz else "")
    if items.get("cpu_temp"):
        temp_row("CPU temp", snap.get("cpu_temp"))
    if items.get("gpu"):
        pct_row("GPU", g.get("load"))
    if items.get("gpu_temp"):
        temp_row("GPU temp", g.get("temp"))
    if items.get("vram"):
        u, t = g.get("vram_used"), g.get("vram_total")
        if u is None:
            rows.append(("VRAM", "--", C["dim"], None))
        elif t:
            rows.append(("VRAM", f"{u / 1024:.1f}/{t / 1024:.0f} GB", W.level_color(u / t * 100), u / t))
        else:
            rows.append(("VRAM", f"{u / 1024:.1f} GB", C["text"], None))
    if items.get("ram"):
        if snap.get("ram") is None:
            rows.append(("RAM", "--", C["dim"], None))
        else:
            rows.append(("RAM", f"{sizefmt(snap.get('ram_used'))}  {snap['ram']:.0f}%",
                         W.level_color(snap["ram"], 70, 90), snap["ram"] / 100.0))
    if items.get("net"):
        rows.append(("Rede", f"↓ {fmt_rate(snap.get('net_down'))}  ↑ {fmt_rate(snap.get('net_up'))}",
                     C["text"], None))
    if items.get("battery"):
        b = snap.get("battery")
        if b:
            rows.append(("Bateria", f"{b['percent']:.0f}%" + (" (carregando)" if b["plugged"] else ""),
                         W.level_color(100 - b["percent"], 70, 85), b["percent"] / 100.0))
        else:
            rows.append(("Bateria", "--", C["dim"], None))
    if items.get("fan"):
        fans = snap.get("fans") or []
        rows.append(("Fan", f"{fans[0][1]:.0f} RPM" if fans else "--", C["text"] if fans else C["dim"], None))
    if items.get("clock"):
        rows.append(("Hora", time.strftime("%H:%M:%S"), C["text"], None))
    return rows


class Overlay(tk.Toplevel):
    def __init__(self, app):
        super().__init__(app)
        self.app = app
        self.withdraw()
        self.overrideredirect(True)
        self.attributes("-topmost", True)
        self.configure(bg=KEY)
        try:
            self.attributes("-transparentcolor", KEY)
        except tk.TclError:
            pass
        self.cv = tk.Canvas(self, bg=KEY, highlightthickness=0)
        self.cv.pack(fill="both", expand=True)
        self.visible = False
        self._size = (0, 0)
        self._drag = None
        self.cv.bind("<ButtonPress-1>", self._press)
        self.cv.bind("<B1-Motion>", self._move)
        self.cv.bind("<ButtonRelease-1>", self._release)

    # --- ciclo de vida ---------------------------------------------------------
    @property
    def cfg(self):
        return self.app.cfg["overlay"]

    def show(self):
        self.visible = True
        self.deiconify()
        self.lift()
        self.attributes("-topmost", True)
        self.apply_cfg()
        self.update_idletasks()
        self._style_click_through()
        self.update_data(self.app.hub.snapshot())

    def hide(self):
        self.visible = False
        self.withdraw()

    def apply_cfg(self):
        try:
            self.attributes("-alpha", float(self.cfg["opacity"]))
        except tk.TclError:
            pass
        self._style_click_through()
        if self.visible:
            self.update_data(self.app.hub.snapshot())

    def _style_click_through(self):
        if not IS_WIN:
            return
        try:
            import ctypes
            u = ctypes.windll.user32
            hwnd = u.GetParent(self.winfo_id()) or self.winfo_id()
            ex = u.GetWindowLongW(hwnd, -20)
            ex |= 0x80000 | 0x80 | 0x08000000  # LAYERED | TOOLWINDOW | NOACTIVATE
            ex = (ex | 0x20) if self.cfg["click_through"] else (ex & ~0x20)
            u.SetWindowLongW(hwnd, -20, ex)
        except Exception:
            pass

    # --- desenho -------------------------------------------------------------
    def update_data(self, snap):
        if not self.visible:
            return
        sc = float(self.cfg["scale"])
        rows = overlay_rows(snap, self.cfg["items"])
        f = tkfont.Font(family=W.FONT, size=max(7, int(round(10 * sc))), weight="bold")
        fm = tkfont.Font(family=W.MONO, size=max(7, int(round(10 * sc))), weight="bold")
        lh, pad = int(f.metrics("linespace") * 1.55), px(10)
        lw = max([f.measure(r[0]) for r in rows] or [0]) + px(14)
        vw = max([fm.measure(r[1]) for r in rows] or [0])
        width = pad * 2 + lw + vw + px(4)
        height = pad * 2 + lh * max(len(rows), 1)
        self.cv.delete("all")
        self._round_rect(0, 0, width - 1, height - 1, px(10), "#0b0e15", "#2a3042")
        if not rows:
            self.cv.create_text(pad, pad, text="Nenhum item ativo", fill=C["muted"], anchor="nw", font=f)
        for i, (lab, val, color, frac) in enumerate(rows):
            y = pad + i * lh
            self.cv.create_text(pad, y + lh / 2 - px(1), text=lab, fill=C["muted"], anchor="w", font=f)
            self.cv.create_text(width - pad, y + lh / 2 - px(1), text=val, fill=color, anchor="e", font=fm)
            if frac is not None:
                x0, x1, yb = pad, width - pad, y + lh - px(3)
                self.cv.create_line(x0, yb, x1, yb, fill="#1b2130", width=px(2))
                self.cv.create_line(x0, yb, x0 + (x1 - x0) * max(0.0, min(1.0, frac)), yb,
                                    fill=color, width=px(2))
        if (width, height) != self._size:
            self._size = (width, height)
            self.cv.configure(width=width, height=height)
        self._place(width, height)

    def _round_rect(self, x0, y0, x1, y1, r, fill, outline):
        pts = [x0 + r, y0, x1 - r, y0, x1, y0, x1, y0 + r, x1, y1 - r, x1, y1, x1 - r, y1,
               x0 + r, y1, x0, y1, x0, y1 - r, x0, y0 + r, x0, y0]
        self.cv.create_polygon(pts, smooth=True, fill=fill, outline=outline)

    def _place(self, w, h):
        if self._drag:
            return
        sw, sh, m = self.winfo_screenwidth(), self.winfo_screenheight(), px(16)
        corner = self.cfg["corner"]
        if corner == "custom":
            x, y = int(self.cfg["x"]), int(self.cfg["y"])
        else:
            x = m if corner.endswith("left") else sw - w - m
            y = m if corner.startswith("top") else sh - h - m - px(40)
        self.geometry(f"{w}x{h}+{x}+{y}")

    # --- arrastar (somente sem click-through) ------------------------------------
    def _press(self, e):
        if not self.cfg["click_through"]:
            self._drag = (e.x_root - self.winfo_x(), e.y_root - self.winfo_y())

    def _move(self, e):
        if self._drag:
            self.geometry(f"+{e.x_root - self._drag[0]}+{e.y_root - self._drag[1]}")

    def _release(self, _e):
        if self._drag:
            self._drag = None
            self.cfg.update(corner="custom", x=self.winfo_x(), y=self.winfo_y())
            self.app.save_cfg()
