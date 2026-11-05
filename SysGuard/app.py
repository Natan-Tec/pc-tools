# -*- coding: utf-8 -*-
"""SysGuard - janela principal (menu lateral + paginas)."""
import queue
import subprocess
import sys
import threading
import tkinter as tk
import traceback

import core
import sensors
import widgets as W
from widgets import C, px, lbl, Btn, Chip
from overlay import Overlay
from hotkey import GlobalHotkey
from rgb import RGBController
from pages_system import Dashboard, Specs, Battery, Disk
from pages_perf import Benchmark, OverlayPage, RgbFans
from pages_tools import Hosts, Scan, Integrity, Uninstaller, Cleaner, LogPage

NAV = [
    ("SISTEMA", [("dash", "Painel", Dashboard), ("specs", "Especificações", Specs),
                 ("battery", "Bateria", Battery), ("disk", "Discos", Disk)]),
    ("DESEMPENHO", [("bench", "Benchmark", Benchmark), ("overlay", "Overlay", OverlayPage),
                    ("rgb", "RGB e Ventoinhas", RgbFans)]),
    ("SEGURANÇA", [("hosts", "Hosts", Hosts), ("scan", "Arquivos suspeitos", Scan),
                   ("integrity", "Integridade", Integrity)]),
    ("MANUTENÇÃO", [("uninstall", "Desinstalador", Uninstaller), ("clean", "Limpeza", Cleaner),
                    ("log", "Registro", LogPage)]),
]
PAGES = {key: cls for _, items in NAV for key, _, cls in items}


class NavItem(tk.Frame):
    def __init__(self, parent, text, command):
        super().__init__(parent, bg=C["side"], cursor="hand2")
        self.bar = tk.Frame(self, bg=C["side"], width=px(3))
        self.bar.pack(side="left", fill="y")
        self.label = tk.Label(self, text=text, bg=C["side"], fg=C["muted"], font=W.font(10),
                              anchor="w", padx=px(14), pady=px(7))
        self.label.pack(side="left", fill="x", expand=True)
        self.active = False
        for w in (self, self.label, self.bar):
            w.bind("<Button-1>", lambda e: command())
            w.bind("<Enter>", lambda e: self._paint(True))
            w.bind("<Leave>", lambda e: self._paint(False))

    def _paint(self, hover):
        bg = C["card2"] if self.active else (C["hover"] if hover else C["side"])
        for w in (self, self.label):
            w.configure(bg=bg)
        self.label.configure(fg=C["text"] if (self.active or hover) else C["muted"])
        self.bar.configure(bg=C["accent"] if self.active else bg)

    def set_active(self, on):
        self.active = on
        self._paint(False)
        self.label.configure(font=W.font(10, on))


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("SysGuard")
        self.configure(bg=C["bg"])
        W.init_style(self)
        self.geometry(f"{px(1180)}x{px(780)}")
        self.minsize(px(1020), px(660))
        W.dark_titlebar(self)
        self.cfg = core.load_config()
        self.q = queue.Queue()
        self.cancel_flag = threading.Event()
        self.hub = sensors.SensorHub()
        self.hub.start()
        self.rgb = RGBController()
        self.fans = {"ctl": None, "ap": None}
        self.pages, self.current, self.nav = {}, None, {}
        self._shell()
        self.overlay = Overlay(self)
        self.hotkey = GlobalHotkey(lambda: self.ui(self.toggle_overlay))
        self.hotkey.start()
        self.protocol("WM_DELETE_WINDOW", self.close)
        self.show("dash")
        self.after(100, self._pump)
        self.after(1000, self._tick)
        if self.cfg["overlay"].get("enabled"):
            self.after(600, lambda: self.set_overlay(True))
        core.log(f"SysGuard iniciado (admin={core.is_admin()})")

    # ---- estrutura ---------------------------------------------------------------
    def _shell(self):
        side = tk.Frame(self, bg=C["side"], width=px(236))
        side.pack(side="left", fill="y")
        side.pack_propagate(False)
        logo = tk.Frame(side, bg=C["side"])
        logo.pack(fill="x", padx=px(18), pady=(px(22), px(14)))
        mark = tk.Canvas(logo, width=px(26), height=px(26), bg=C["side"], highlightthickness=0)
        mark.create_oval(1, 1, px(25), px(25), fill=C["accent"], outline="")
        mark.create_arc(px(6), px(6), px(20), px(20), start=225, extent=-270, style="arc", width=px(3),
                        outline="#0b0f1a")
        mark.pack(side="left")
        t = tk.Frame(logo, bg=C["side"])
        t.pack(side="left", padx=10)
        lbl(t, "SysGuard", 14, "text", True, bg="side").pack(anchor="w")
        lbl(t, "v0.2", 8, "dim", bg="side").pack(anchor="w")
        for section, items in NAV:
            lbl(side, section, 8, "dim", True, bg="side").pack(anchor="w", padx=px(20), pady=(px(12), px(3)))
            for key, text, _ in items:
                n = NavItem(side, text, lambda k=key: self.show(k))
                n.pack(fill="x", padx=(0, px(10)))
                self.nav[key] = n
        foot = tk.Frame(side, bg=C["side"])
        foot.pack(side="bottom", fill="x", padx=px(16), pady=px(16))
        if core.is_admin():
            Chip(foot, "Administrador", "ok").pack(anchor="w")
        else:
            c = Chip(foot, "Sem privilégio de administrador", "warn")
            c.pack(anchor="w")
            if core.IS_WIN:
                Btn(foot, "Reabrir como administrador", self.go_admin, "ghost").pack(anchor="w", pady=(8, 0))
        main = tk.Frame(self, bg=C["bg"])
        main.pack(side="left", fill="both", expand=True)
        self.status_var = tk.StringVar(value="Pronto.")
        tk.Label(main, textvariable=self.status_var, bg=C["bg"], fg=C["dim"], font=W.font(9),
                 anchor="w").pack(side="bottom", fill="x", padx=px(26), pady=(0, px(8)))
        self.content = tk.Frame(main, bg=C["bg"])
        self.content.pack(fill="both", expand=True)

    def show(self, key):
        if self.current:
            self.current.on_hide()
            self.current.pack_forget()
        if key not in self.pages:
            self.pages[key] = PAGES[key](self, self.content)
        self.current = self.pages[key]
        self.current.pack(fill="both", expand=True)
        for k, n in self.nav.items():
            n.set_active(k == key)
        self.current.on_show()
        self.current.tick(self.hub.snapshot())

    # ---- servicos usados pelas paginas --------------------------------------------
    def bg(self, fn, done=None, *args):
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

    def _tick(self):
        try:
            snap = self.hub.snapshot()
            if self.current:
                self.current.tick(snap)
            self.overlay.update_data(snap)
        except Exception:
            core.log("ERRO no tick:\n" + traceback.format_exc())
        self.after(1000, self._tick)

    def say(self, msg):
        self.status_var.set(msg)

    def save_cfg(self):
        core.save_config(self.cfg)

    def ask(self, title, msg, yes="Confirmar", no="Cancelar", danger=False):
        return W.ask(self, title, msg, yes, no, danger)

    def info(self, title, msg):
        W.info(self, title, msg)

    def error(self, title, msg):
        W.info(self, title, msg, "error")

    def need_admin(self, e):
        if isinstance(e, PermissionError):
            if self.ask("Acesso negado", "Esta ação precisa de administrador.\nReabrir o SysGuard como administrador agora?",
                        "Reabrir"):
                self.go_admin()
            return True
        return False

    def go_admin(self):
        if core.relaunch_as_admin():
            self.close()
        else:
            self.error("Administrador", "Não foi possível elevar privilégios.")

    def open_path(self, p):
        import os
        try:
            if core.IS_WIN:
                os.startfile(str(p))  # noqa
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(p)])
            else:
                subprocess.Popen(["xdg-open", str(p)])
        except Exception as e:  # noqa
            self.error("Abrir", str(e))

    def set_overlay(self, on):
        self.cfg["overlay"]["enabled"] = bool(on)
        self.save_cfg()
        (self.overlay.show if on else self.overlay.hide)()
        p = self.pages.get("overlay")
        if p:
            p.v_on.set(bool(on))

    def toggle_overlay(self):
        self.set_overlay(not self.overlay.visible)

    def report_callback_exception(self, exc, val, tb):
        text = "".join(traceback.format_exception(exc, val, tb))
        core.log("ERRO NA INTERFACE:\n" + text)
        self.error("Ocorreu um erro", f"{val}\n\nDetalhes no Registro.")

    def close(self):
        try:
            self.hub.stop()
            self.hotkey.stop()
            self.rgb.disconnect()
            ap, ctl = self.fans.get("ap"), self.fans.get("ctl")
            if ap:
                ap.stop()
            if ctl and ctl.ok and self.cfg.get("fan_reset_on_exit", True):
                ctl.close()
        except Exception:
            pass
        self.destroy()
