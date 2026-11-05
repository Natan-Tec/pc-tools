# -*- coding: utf-8 -*-
"""Páginas: Benchmark, Overlay, RGB e Ventoinhas."""
import os
import subprocess
import threading
import tkinter as tk
from tkinter import filedialog, colorchooser

import widgets as W
from widgets import (C, Page, Card, Btn, Chip, KV, Bar, Spark, Toggle, lbl, px, combo, make_tree,
                     toggle_row)
import core
import bench
import fans
from overlay import CORNERS, ITEM_LABELS


def delta(new, old, unit=""):
    if new is None:
        return "--"
    s = f"{new:,.0f}{unit}" if new >= 100 else f"{new:.1f}{unit}"
    if old:
        pct = (new - old) / old * 100
        s += f"   ({pct:+.0f}% vs. anterior)"
    return s


# ----------------------------------------------------------------------------
class Benchmark(Page):
    title = "Benchmark"
    subtitle = "Mede CPU, memória e disco. Os resultados ficam salvos para você comparar depois."
    scroll = True

    def build(self):
        b = self.body
        c = Card(b, "Executar teste")
        c.pack(fill="x")
        row = tk.Frame(c.body, bg=C["card"])
        row.pack(fill="x")
        self.v = {k: tk.BooleanVar(value=True) for k in ("cpu", "ram", "disk")}
        for key, text in (("cpu", "CPU"), ("ram", "Memória"), ("disk", "Disco")):
            f = tk.Frame(row, bg=C["card"])
            f.pack(side="left", padx=(0, 22))
            Toggle(f, self.v[key]).pack(side="left")
            lbl(f, text, 10, "text", bg="card").pack(side="left", padx=8)
        r2 = tk.Frame(c.body, bg=C["card"])
        r2.pack(fill="x", pady=(px(10), 0))
        lbl(r2, "Disco:", 10, "muted", bg="card").pack(side="left")
        self.vols = core.list_volumes()
        self.disk_cb = combo(r2, [f"{m}  (livre {core.sizefmt(fr)})" for m, _, fr in self.vols], 30)
        self.disk_cb.pack(side="left", padx=(6, 14))
        lbl(r2, "Tamanho do teste:", 10, "muted", bg="card").pack(side="left")
        self.size_cb = combo(r2, ["128 MB", "256 MB", "512 MB", "1024 MB", "2048 MB"], 10)
        self.size_cb.current(2)
        self.size_cb.pack(side="left", padx=6)
        r3 = tk.Frame(c.body, bg=C["card"])
        r3.pack(fill="x", pady=(px(14), 0))
        self.run_btn = Btn(r3, "Executar", self.run, "accent")
        self.run_btn.pack(side="left")
        self.stop_btn = Btn(r3, "Parar", self.stop, "default")
        self.stop_btn.pack(side="left", padx=8)
        self.stop_btn.disable()
        self.status = lbl(r3, "", 10, "muted", bg="card")
        self.status.pack(side="left", padx=10)
        self.prog = Bar(c.body, 8)
        self.prog.pack(fill="x", pady=(px(10), 0))
        lbl(c.body, "A leitura de disco pode parecer maior por causa do cache do Windows. "
                    "Use o mesmo tamanho para comparar resultados.", 9, "muted", bg="card"
            ).pack(anchor="w", pady=(6, 0))

        res = Card(b, "Resultado")
        res.pack(fill="x", pady=(px(12), 0))
        self.kv = {}
        for k in ("CPU - 1 núcleo (SHA-256)", "CPU - ponto flutuante", "CPU - todos os núcleos",
                  "Pontuação 1 núcleo", "Pontuação multi-núcleo", "Memória RAM (cópia)",
                  "Disco - escrita", "Disco - leitura"):
            self.kv[k] = KV(res.body, k)
            self.kv[k].pack(fill="x", pady=2)
        lbl(res.body, "As pontuações são internas: servem para comparar o SEU PC antes e depois "
                      "de uma mudanca, não com outros PCs.", 9, "muted", bg="card",
            wraplength=px(700), justify="left").pack(anchor="w", pady=(6, 0))

        hist = Card(b, "Histórico")
        hist.pack(fill="x", pady=(px(12), 0))
        fr, self.tree = make_tree(hist.body, [
            ("date", "Data", 140, "w"), ("s1", "1 núcleo", 90, "e"), ("sm", "Multi", 90, "e"),
            ("ram", "RAM GB/s", 90, "e"), ("dw", "Escrita MB/s", 110, "e"),
            ("dr", "Leitura MB/s", 110, "e")], height=6)
        fr.pack(fill="x")
        self._fill_hist()

        st = Card(b, "Teste de estresse da CPU",
                  "Carga máxima em todos os núcleos para ver temperatura e clock sob pressão.")
        st.pack(fill="x", pady=(px(12), px(6)))
        sr = tk.Frame(st.body, bg=C["card"])
        sr.pack(fill="x")
        self.dur_cb = combo(sr, ["30 s", "60 s", "120 s", "300 s"], 8)
        self.dur_cb.current(1)
        self.dur_cb.pack(side="left")
        self.stress_btn = Btn(sr, "Iniciar estresse", self.stress, "danger")
        self.stress_btn.pack(side="left", padx=10)
        self.stress_kv = KV(sr, "", "")
        self.live = lbl(sr, "", 10, "muted", bg="card")
        self.live.pack(side="left", padx=10)
        self.stress_bar = Bar(st.body, 8)
        self.stress_bar.pack(fill="x", pady=(px(10), 0))
        sp = tk.Frame(st.body, bg=C["card"])
        sp.pack(fill="x", pady=(px(8), 0))
        sp.columnconfigure((0, 1), weight=1, uniform="x")
        for i, (key, name, color) in enumerate((("cpu", "Uso (%)", C["accent"]), ("cpu_temp", "Temperatura (°C)", C["bad"]))):
            f = tk.Frame(sp, bg=C["card"])
            f.grid(row=0, column=i, sticky="nsew", padx=(0 if i == 0 else 8, 0))
            lbl(f, name, 9, "muted", bg="card").pack(anchor="w")
            s = Spark(f, 60, color)
            s.pack(fill="x")
            setattr(self, "sp_" + key, s)
        self._stop_ev = None
        self._stress_ev = None

    # --- histórico ---------------------------------------------------------------
    def _fill_hist(self):
        self.tree.delete(*self.tree.get_children())
        for h in reversed(bench.history()[-30:]):
            f = lambda k, n=0: ("" if h.get(k) is None else f"{h[k]:.{n}f}")  # noqa
            self.tree.insert("", "end", values=(h.get("date", ""), f("score_single"), f("score_multi"),
                                                f("ram_gbs", 1), f("disk_write"), f("disk_read")))

    # --- execução ----------------------------------------------------------------
    def run(self):
        parts = {k for k, v in self.v.items() if v.get()}
        if not parts:
            self.app.info("Benchmark", "Marque ao menos um item para testar.")
            return
        disk_dir = self.vols[self.disk_cb.current()][0] if self.vols else None
        size = int(self.size_cb.get().split()[0])
        prev = (bench.history() or [{}])[-1]
        self._stop_ev = threading.Event()
        self.run_btn.disable()
        self.stop_btn.disable(False)
        threads = os.cpu_count() or 2

        def prog(txt, frac):
            self.app.ui(self._prog, txt, frac)

        def work():
            return bench.run_suite(parts, threads, disk_dir, size, prog, self._stop_ev)

        def done(r, e):
            self.run_btn.disable(False)
            self.stop_btn.disable()
            if e or not r:
                self.status.configure(text=f"Erro: {e}", fg=C["bad"])
                return
            if self._stop_ev.is_set():
                self.status.configure(text="Interrompido.", fg=C["warn"])
            bench.save_result(r)
            self._show(r, prev)
            self._fill_hist()
            core.log("Benchmark: " + ", ".join(f"{k}={v:.0f}" for k, v in r.items()))
        self.app.bg(work, done)

    def _prog(self, txt, frac):
        self.status.configure(text=txt, fg=C["muted"])
        self.prog.set(frac, C["accent"])

    def stop(self):
        if self._stop_ev:
            self._stop_ev.set()

    def _show(self, r, p):
        k = self.kv
        k["CPU - 1 núcleo (SHA-256)"].set(delta(r.get("single"), p.get("single"), " MB/s"))
        k["CPU - ponto flutuante"].set(delta(r.get("float"), p.get("float"), " M it/s"))
        k["CPU - todos os núcleos"].set(delta(r.get("multi"), p.get("multi"), " MB/s"))
        k["Pontuação 1 núcleo"].set(delta(r.get("score_single"), p.get("score_single")), "accent")
        k["Pontuação multi-núcleo"].set(delta(r.get("score_multi"), p.get("score_multi")), "accent")
        k["Memória RAM (cópia)"].set(delta(r.get("ram_gbs"), p.get("ram_gbs"), " GB/s"))
        k["Disco - escrita"].set(delta(r.get("disk_write"), p.get("disk_write"), " MB/s"))
        k["Disco - leitura"].set(delta(r.get("disk_read"), p.get("disk_read"), " MB/s"))

    # --- estresse ---------------------------------------------------------------
    def stress(self):
        if self._stress_ev and not self._stress_ev.is_set():
            self._stress_ev.set()
            return
        secs = int(self.dur_cb.get().split()[0])
        if not self.app.ask("Teste de estresse", f"A CPU ficará a 100% por {secs} segundos. "
                            "O PC pode esquentar e ficar lento. Feche outros programas pesados.",
                            "Iniciar", danger=True):
            return
        self._stress_ev = threading.Event()
        self.stress_btn.configure(text="Parar estresse")
        ev = self._stress_ev

        def work():
            bench.cpu_stress(secs, os.cpu_count() or 2, ev,
                             lambda f: self.app.ui(self.stress_bar.set, f, C["bad"]))

        def done(r, e):
            self.stress_btn.configure(text="Iniciar estresse")
            self.stress_bar.set(0)
        self.app.bg(work, done)

    def tick(self, s):
        h = (s or {}).get("hist")
        if not h:
            return
        self.sp_cpu.set(h["cpu"], 100)
        self.sp_cpu_temp.set(h["cpu_temp"], 100)
        mhz, t = s.get("cpu_mhz"), s.get("cpu_temp")
        self.live.configure(text=f"CPU {s.get('cpu', 0):.0f}%" + (f"  |  {mhz / 1000:.2f} GHz" if mhz else "")
                                 + (f"  |  {t:.0f} °C" if t is not None else ""))


# ----------------------------------------------------------------------------
class OverlayPage(Page):
    title = "Overlay"
    subtitle = "Painel flutuante sobre os jogos e janelas, como o do MSI Afterburner."
    scroll = True

    def build(self):
        b, o = self.body, self.app.cfg["overlay"]
        c = Card(b, "Overlay")
        c.pack(fill="x")
        self.v_on = tk.BooleanVar(value=self.app.overlay.visible)
        toggle_row(c.body, "Mostrar overlay", self.v_on, lambda v: self.app.set_overlay(v),
                   hint="Atalho global: Ctrl + Shift + F10 liga/desliga em qualquer janela.").pack(fill="x", pady=4)
        self.v_ct = tk.BooleanVar(value=o["click_through"])
        toggle_row(c.body, "Ignorar cliques do mouse", self.v_ct, self._ct,
                   hint="Ligado: o overlay não atrapalha o jogo. Desligue para arrastar com o mouse."
                   ).pack(fill="x", pady=4)
        r = tk.Frame(c.body, bg=C["card"])
        r.pack(fill="x", pady=(px(10), 0))
        lbl(r, "Posição", 10, "muted", bg="card").grid(row=0, column=0, sticky="w")
        lbl(r, "Tamanho", 10, "muted", bg="card").grid(row=0, column=1, sticky="w", padx=14)
        lbl(r, "Opacidade", 10, "muted", bg="card").grid(row=0, column=2, sticky="w")
        self.cb_pos = combo(r, list(CORNERS) + ["Personalizada (arrastada)"], 24)
        inv = {v: k for k, v in CORNERS.items()}
        if o["corner"] in inv:
            self.cb_pos.set(inv[o["corner"]])
        else:
            self.cb_pos.set("Personalizada (arrastada)")
        self.cb_pos.grid(row=1, column=0, sticky="w")
        self.cb_pos.bind("<<ComboboxSelected>>", self._pos)
        self.cb_sc = combo(r, ["75%", "100%", "125%", "150%", "200%"], 8)
        self.cb_sc.set(f"{round(o['scale'] * 100)}%")
        self.cb_sc.grid(row=1, column=1, sticky="w", padx=14)
        self.cb_sc.bind("<<ComboboxSelected>>", self._sc)
        self.cb_op = combo(r, ["50%", "65%", "80%", "90%", "100%"], 8)
        self.cb_op.set(f"{round(o['opacity'] * 100)}%" if f"{round(o['opacity'] * 100)}%" in self.cb_op["values"] else "90%")
        self.cb_op.grid(row=1, column=2, sticky="w")
        self.cb_op.bind("<<ComboboxSelected>>", self._op)

        it = Card(b, "O que mostrar")
        it.pack(fill="x", pady=(px(12), 0))
        grid = tk.Frame(it.body, bg=C["card"])
        grid.pack(fill="x")
        grid.columnconfigure((0, 1), weight=1, uniform="i")
        self.item_vars = {}
        for i, (key, text) in enumerate(ITEM_LABELS.items()):
            var = tk.BooleanVar(value=o["items"].get(key, False))
            self.item_vars[key] = var
            toggle_row(grid, text, var, lambda v, k=key: self._item(k, v)).grid(
                row=i // 2, column=i % 2, sticky="ew", padx=(0, px(16)), pady=4)

        note = Card(b, "Sobre FPS e jogos em tela cheia")
        note.pack(fill="x", pady=(px(12), px(6)))
        lbl(note.body, "•  O overlay mostra uso de CPU/GPU/RAM, temperaturas, rede e bateria. "
                       "FPS dentro do jogo exige injetar código no jogo (como o RTSS) e não é feito pelo SysGuard.",
            10, "muted", bg="card", wraplength=px(760), justify="left").pack(anchor="w", pady=2)
        lbl(note.body, "•  Jogos em tela cheia exclusiva escondem janelas de outros programas. "
                       "Use o modo 'janela sem bordas' do jogo.", 10, "muted", bg="card",
            wraplength=px(760), justify="left").pack(anchor="w", pady=2)
        lbl(note.body, "•  Temperaturas no Windows dependem do LibreHardwareMonitor aberto "
                       "(veja a página RGB e Ventoinhas).", 10, "muted", bg="card",
            wraplength=px(760), justify="left").pack(anchor="w", pady=2)

    def on_show(self):
        self.v_on.set(self.app.overlay.visible)

    def _save(self):
        self.app.save_cfg()
        self.app.overlay.apply_cfg()

    def _ct(self, v):
        self.app.cfg["overlay"]["click_through"] = bool(v)
        self._save()

    def _pos(self, _e=None):
        name = self.cb_pos.get()
        if name in CORNERS:
            self.app.cfg["overlay"]["corner"] = CORNERS[name]
            self._save()

    def _sc(self, _e=None):
        self.app.cfg["overlay"]["scale"] = int(self.cb_sc.get().rstrip("%")) / 100
        self._save()

    def _op(self, _e=None):
        self.app.cfg["overlay"]["opacity"] = int(self.cb_op.get().rstrip("%")) / 100
        self._save()

    def _item(self, key, v):
        self.app.cfg["overlay"]["items"][key] = bool(v)
        self._save()


# ----------------------------------------------------------------------------
SWATCHES = ["#ff2d2d", "#ff7a00", "#ffd400", "#2dff4a", "#00e5ff", "#2d5bff", "#9b30ff",
            "#ff2dc8", "#ffffff"]


class RgbFans(Page):
    title = "RGB e Ventoinhas"
    subtitle = "Controle de luzes (via OpenRGB) e de ventoinhas (via LibreHardwareMonitor), quando o seu hardware permitir."
    scroll = True

    def build(self):
        self._color = (45, 91, 255)
        self._build_rgb()
        self._build_fans()

    # ---------------- RGB -------------------------------------------------------
    def _build_rgb(self):
        c = Card(self.body, "RGB", "Usa o OpenRGB (gratuito, openrgb.org), que reconhece placas-mãe, "
                                    "memórias, coolers, GPUs, teclados e fitas de várias marcas.")
        c.pack(fill="x")
        top = tk.Frame(c.body, bg=C["card"])
        top.pack(fill="x")
        self.rgb_chip = Chip(top, "Desconectado", "muted")
        self.rgb_chip.pack(side="left")
        Btn(top, "Conectar", self.rgb_connect, "accent").pack(side="left", padx=(10, 6))
        Btn(top, "Iniciar OpenRGB", self.rgb_launch).pack(side="left", padx=(0, 6))
        Btn(top, "Escolher OpenRGB.exe...", self.rgb_pick).pack(side="left")
        self.rgb_msg = lbl(c.body, "", 9, "warn", bg="card", wraplength=px(760), justify="left")
        self.rgb_msg.pack(anchor="w", pady=(6, 0))
        fr, self.dev_tree = make_tree(c.body, [("name", "Dispositivo", 360, "w"),
                                               ("type", "Tipo", 140, "w"), ("leds", "LEDs", 70, "e")],
                                      height=4)
        fr.pack(fill="x", pady=(px(10), 0))
        r = tk.Frame(c.body, bg=C["card"])
        r.pack(fill="x", pady=(px(12), 0))
        lbl(r, "Cor:", 10, "muted", bg="card").pack(side="left")
        for col_hex in SWATCHES:
            s = tk.Label(r, bg=col_hex, width=3, height=1, cursor="hand2")
            s.pack(side="left", padx=3)
            s.bind("<Button-1>", lambda e, h=col_hex: self.rgb_color(h))
        Btn(r, "Outra...", self.rgb_choose, kind="ghost").pack(side="left", padx=(10, 0))
        self.cur = tk.Label(r, bg="#2d5bff", width=6, height=1)
        self.cur.pack(side="left", padx=10)
        lbl(r, "Aplicar em:", 10, "muted", bg="card").pack(side="left")
        self.target = combo(r, ["Todos", "Selecionado"], 12)
        self.target.pack(side="left", padx=6)
        r2 = tk.Frame(c.body, bg=C["card"])
        r2.pack(fill="x", pady=(px(10), 0))
        Btn(r2, "Arco-iris", lambda: self._fx("rainbow")).pack(side="left", padx=(0, 6))
        Btn(r2, "Respirar", lambda: self._fx("breath")).pack(side="left", padx=(0, 6))
        Btn(r2, "Parar efeito", self._fx_stop).pack(side="left", padx=(0, 6))
        Btn(r2, "Desligar luzes", self._off, "danger").pack(side="left", padx=(0, 14))
        lbl(r2, "Velocidade:", 10, "muted", bg="card").pack(side="left")
        self.speed = combo(r2, ["Lenta", "Média", "Rápida"], 8)
        self.speed.current(1)
        self.speed.pack(side="left", padx=6)

    def _spd(self):
        return (0.2, 0.5, 1.0)[self.speed.current()]

    def _need(self):
        if not self.app.rgb.connected:
            self.app.info("RGB", "Conecte-se ao OpenRGB primeiro (veja as instruções acima).")
            return False
        return True

    def rgb_connect(self):
        def done(ok, e):
            if ok:
                self.rgb_chip.set("Conectado", "ok")
                self.rgb_msg.configure(text="")
                self.dev_tree.delete(*self.dev_tree.get_children())
                for d in self.app.rgb.devices():
                    self.dev_tree.insert("", "end", iid=str(d["index"]), values=(d["name"], d["type"], d["leds"]))
            else:
                self.rgb_chip.set("Desconectado", "warn")
                self.rgb_msg.configure(text=self.app.rgb.error + "\nPasso a passo: 1) abra o OpenRGB  "
                                            "2) aba 'SDK Server' > Start Server  3) clique em Conectar.")
        self.app.bg(self.app.rgb.connect, done)

    def rgb_pick(self):
        p = filedialog.askopenfilename(title="Escolha o OpenRGB.exe",
                                       filetypes=[("Executável", "*.exe"), ("Todos", "*.*")])
        if p:
            self.app.cfg["openrgb_path"] = p
            self.app.save_cfg()

    def rgb_launch(self):
        from rgb import start_openrgb_server
        if not self.app.cfg.get("openrgb_path"):
            self.rgb_pick()
        try:
            start_openrgb_server(self.app.cfg.get("openrgb_path"))
            self.app.say("OpenRGB iniciado. Aguarde alguns segundos e clique em Conectar.")
        except Exception as e:  # noqa
            self.app.error("OpenRGB", str(e))

    def rgb_color(self, hex_):
        self._color = tuple(int(hex_[i:i + 2], 16) for i in (1, 3, 5))
        self.cur.configure(bg=hex_)
        if self.app.rgb.connected:
            self._apply(self._color)

    def rgb_choose(self):
        rgb, hex_ = colorchooser.askcolor(color="#%02x%02x%02x" % self._color, title="Cor do RGB")
        if hex_:
            self.rgb_color(hex_)

    def _apply(self, rgb):
        self.app.rgb.stop_fx()
        sel = self.dev_tree.selection()
        try:
            if self.target.get() == "Selecionado" and sel:
                self.app.rgb.set_device(int(sel[0]), rgb)
            else:
                self.app.rgb.set_all(rgb)
        except Exception as e:  # noqa
            self.app.error("RGB", str(e))

    def _fx(self, kind):
        if not self._need():
            return
        if kind == "rainbow":
            self.app.rgb.rainbow(self._spd())
        else:
            self.app.rgb.breathing(self._color, self._spd())

    def _fx_stop(self):
        if self.app.rgb.connected:
            self.app.rgb.stop_fx()

    def _off(self):
        if self._need():
            self.app.rgb.off()

    # ---------------- Ventoinhas -------------------------------------------------
    def _build_fans(self):
        c = Card(self.body, "Ventoinhas", "Leitura de rotação e, se o seu PC permitir, controle.")
        c.pack(fill="x", pady=(px(12), px(6)))
        top = tk.Frame(c.body, bg=C["card"])
        top.pack(fill="x")
        self.mon_chip = Chip(top, "Sensores: LibreHardwareMonitor inativo", "muted")
        self.mon_chip.pack(side="left")
        Btn(top, "Abrir LibreHardwareMonitor", self.lhm_launch, "accent").pack(side="left", padx=(10, 6))
        Btn(top, "Escolher .exe...", self.lhm_pick).pack(side="left")
        self.fan_txt = lbl(c.body, "Nenhuma leitura de ventoinha ainda.", 10, "muted", bg="card",
                           justify="left")
        self.fan_txt.pack(anchor="w", pady=(px(10), 0))
        ttk_sep = tk.Frame(c.body, bg=C["border"], height=1)
        ttk_sep.pack(fill="x", pady=px(12))
        ctl = tk.Frame(c.body, bg=C["card"])
        ctl.pack(fill="x")
        self.ctl_chip = Chip(ctl, "Controle: não carregado", "muted")
        self.ctl_chip.pack(side="left")
        Btn(ctl, "Carregar controle", self.fan_load).pack(side="left", padx=(10, 0))
        self.fan_msg = lbl(c.body, "", 9, "warn", bg="card", wraplength=px(760), justify="left")
        self.fan_msg.pack(anchor="w", pady=(6, 0))
        fr, self.ctl_tree = make_tree(c.body, [("name", "Controle", 260, "w"), ("hw", "Dispositivo", 260, "w"),
                                               ("val", "Atual", 80, "e")], height=4, selectmode="extended")
        fr.pack(fill="x", pady=(px(8), 0))
        r = tk.Frame(c.body, bg=C["card"])
        r.pack(fill="x", pady=(px(10), 0))
        lbl(r, "Modo:", 10, "muted", bg="card").pack(side="left")
        self.mode = combo(r, ["Automático (BIOS)", "Manual", "Curva: Silencioso", "Curva: Equilibrado",
                              "Curva: Turbo"], 22)
        self.mode.pack(side="left", padx=6)
        self.pct = tk.Scale(r, from_=fans.MIN_PCT, to=100, orient="horizontal", length=px(220),
                            bg=C["card"], fg=C["text"], troughcolor=C["input"], highlightthickness=0,
                            bd=0, sliderrelief="flat", activebackground=C["accent"], font=W.font(9))
        self.pct.set(60)
        self.pct.pack(side="left", padx=10)
        Btn(r, "Aplicar", self.fan_apply, "accent").pack(side="left")
        lbl(c.body, "A rotação nunca fica abaixo de 25%. Ao fechar o SysGuard, as ventoinhas voltam para o "
                    "controle automático. Em notebooks a ventoinha normalmente é controlada pela BIOS e "
                    "não aparece aqui. Requer administrador, `pip install pythonnet` e a "
                    "LibreHardwareMonitorLib.dll (do pacote do LibreHardwareMonitor) na pasta do SysGuard.",
            9, "muted", bg="card", wraplength=px(760), justify="left").pack(anchor="w", pady=(10, 0))

    def lhm_pick(self):
        p = filedialog.askopenfilename(title="Escolha o LibreHardwareMonitor.exe",
                                       filetypes=[("Executável", "*.exe"), ("Todos", "*.*")])
        if p:
            self.app.cfg["lhm_path"] = p
            self.app.save_cfg()
            self.lhm_launch()

    def lhm_launch(self):
        p = self.app.cfg.get("lhm_path")
        if not p:
            self.lhm_pick()
            return
        try:
            subprocess.Popen([p], cwd=os.path.dirname(p))
            self.app.say("LibreHardwareMonitor aberto. Em Options, ative 'Start Minimized' se quiser.")
        except OSError as e:
            self.app.error("LibreHardwareMonitor", str(e))

    def fan_load(self):
        cfg = self.app.cfg

        def work():
            return fans.LhmFanControl(fans.find_dll_dir(cfg))

        def done(ctl, e):
            if e or not ctl:
                self.fan_msg.configure(text=f"Erro: {e}")
                return
            self.app.fans["ctl"] = ctl
            if not ctl.ok:
                self.ctl_chip.set("Controle: indisponível", "warn")
                self.fan_msg.configure(text=ctl.reason)
                return
            lst = ctl.refresh()
            self.ctl_tree.delete(*self.ctl_tree.get_children())
            for d in lst:
                self.ctl_tree.insert("", "end", iid=d["id"], values=(d["name"], d["hw"],
                                     "-" if d["value"] is None else f"{d['value']:.0f}%"))
            if lst:
                self.ctl_chip.set(f"Controle: {len(lst)} disponível(is)", "ok")
                self.fan_msg.configure(text="")
            else:
                self.ctl_chip.set("Controle: nenhum encontrado", "warn")
                self.fan_msg.configure(text="Este PC não expoe controle de ventoinha por software "
                                            "(comum em notebooks). Use o software do fabricante.")
        self.app.bg(work, done)

    def fan_apply(self):
        ctl = self.app.fans.get("ctl")
        if not ctl or not ctl.ok:
            self.app.info("Ventoinhas", "Carregue o controle primeiro.")
            return
        ids = list(self.ctl_tree.selection()) or list(self.ctl_tree.get_children())
        if not ids:
            self.app.info("Ventoinhas", "Nenhum controle disponível neste PC.")
            return
        ap = self.app.fans.get("ap")
        if ap:
            ap.stop()
            self.app.fans["ap"] = None
        mode = self.mode.get()
        try:
            if mode.startswith("Automático"):
                ctl.reset_all()
                self.app.say("Ventoinhas voltaram ao controle automático.")
            elif mode == "Manual":
                for i in ids:
                    ctl.set_pct(i, self.pct.get())
                self.app.say(f"Ventoinhas em {self.pct.get()}%.")
            else:
                name = mode.split(": ")[1]

                def temp():
                    s = self.app.hub.snapshot()
                    ts = [t for t in (s.get("cpu_temp"), (s.get("gpu") or {}).get("temp")) if t is not None]
                    return max(ts) if ts else None
                ap = fans.FanAutopilot(ctl, ids, fans.PRESETS[name], temp)
                ap.start()
                self.app.fans["ap"] = ap
                self.app.say(f"Curva '{name}' ativa.")
            core.log(f"Ventoinhas: modo {mode}")
        except Exception as e:  # noqa
            self.app.error("Ventoinhas", str(e))

    # ---------------- tick -------------------------------------------------------
    def tick(self, s):
        if not s:
            return
        src = s.get("sources", {})
        if src.get("lhm"):
            self.mon_chip.set("Sensores: LibreHardwareMonitor ativo", "ok")
        else:
            self.mon_chip.set("Sensores: LibreHardwareMonitor inativo", "warn" if core.IS_WIN else "muted")
        fl = s.get("fans") or []
        g = (s.get("gpu") or {}).get("fan_pct")
        lines = [f"{n}:  {v:.0f} RPM" for n, v in fl]
        if g is not None:
            lines.append(f"GPU (NVIDIA):  {g:.0f}%")
        self.fan_txt.configure(text="\n".join(lines) if lines else
                               "Nenhuma leitura de ventoinha. No Windows, abra o LibreHardwareMonitor (como administrador).")
