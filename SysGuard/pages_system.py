# -*- coding: utf-8 -*-
"""Páginas: Painel, Specs, Bateria, Disco."""
import time
import tkinter as tk

import widgets as W
from widgets import C, Page, Card, Btn, Chip, KV, Gauge, Bar, Spark, lbl, px, kv_rows, make_text
import core
import sensors


def ftemp(v):
    return "--" if v is None else f"{v:.0f} °C"


def fpct(v):
    return "--" if v is None else f"{v:.0f}%"


def fwatt(v):
    return "--" if v is None else f"{v:.0f} W"


# ----------------------------------------------------------------------------
class Dashboard(Page):
    title = "Painel"
    subtitle = "Visão geral do PC em tempo real."
    scroll = True

    def build(self):
        b = self.body
        grid = tk.Frame(b, bg=C["bg"])
        grid.pack(fill="x")
        for i in range(4):
            grid.columnconfigure(i, weight=1, uniform="g")
        self.gauges = {}
        for i, (key, label) in enumerate((("cpu", "CPU"), ("gpu", "GPU"), ("ram", "MEMÓRIA"),
                                          ("extra", "BATERIA"))):
            card = Card(grid, pad=12)
            card.grid(row=0, column=i, sticky="nsew", padx=(0 if i == 0 else px(6), 0))
            g = Gauge(card.body, 150, label)
            g.pack()
            d = lbl(card.body, "\n", 9, "muted", bg="card", justify="center", height=2)
            d.pack(pady=(px(2), 0))
            self.gauges[key] = (g, d)

        row = tk.Frame(b, bg=C["bg"])
        row.pack(fill="x", pady=(px(12), 0))
        row.columnconfigure((0, 1), weight=1, uniform="r")
        c1 = Card(row, "Temperaturas e energia")
        c1.grid(row=0, column=0, sticky="nsew", padx=(0, px(6)))
        self.kv = {}
        for k in ("CPU", "GPU", "Consumo CPU", "Consumo GPU", "Ventoinhas"):
            self.kv[k] = KV(c1.body, k)
            self.kv[k].pack(fill="x", pady=2)
        self.src_hint = lbl(c1.body, "", 9, "warn", bg="card", wraplength=px(380), justify="left")
        self.src_hint.pack(anchor="w", pady=(px(8), 0))
        c2 = Card(row, "Rede e disco")
        c2.grid(row=0, column=1, sticky="nsew", padx=(px(6), 0))
        for k in ("Download", "Upload", "Leitura de disco", "Escrita de disco"):
            self.kv[k] = KV(c2.body, k)
            self.kv[k].pack(fill="x", pady=2)

        hist = Card(b, "Últimos 90 segundos")
        hist.pack(fill="x", pady=(px(12), 0))
        self.sparks = {}
        hr = tk.Frame(hist.body, bg=C["card"])
        hr.pack(fill="x")
        hr.columnconfigure((0, 1, 2, 3), weight=1, uniform="s")
        for i, (key, label, color) in enumerate((("cpu", "Uso da CPU", C["accent"]),
                                                 ("gpu", "Uso da GPU", C["ok"]),
                                                 ("ram", "Uso da RAM", C["warn"]),
                                                 ("cpu_temp", "Temp. CPU", C["bad"]))):
            f = tk.Frame(hr, bg=C["card"])
            f.grid(row=0, column=i, sticky="nsew", padx=(0 if i == 0 else px(10), 0))
            lbl(f, label, 9, "muted", bg="card").pack(anchor="w")
            sp = Spark(f, 64, color)
            sp.pack(fill="x")
            self.sparks[key] = sp

        quick = Card(b, "Atalhos")
        quick.pack(fill="x", pady=(px(12), px(6)))
        qr = tk.Frame(quick.body, bg=C["card"])
        qr.pack(fill="x")
        for text, page, kind in (("Executar benchmark", "bench", "accent"), ("Ligar overlay", "overlay", "default"),
                                 ("Analisar hosts", "hosts", "default"), ("Verificar arquivos", "scan", "default")):
            Btn(qr, text, lambda p=page: self.app.show(p), kind).pack(side="left", padx=(0, 8))

    def tick(self, s):
        if not s:
            return
        g = s.get("gpu") or {}
        gc, gd = self.gauges["cpu"]
        mhz = s.get("cpu_mhz")
        gc.set(s.get("cpu"), sub=f"{mhz / 1000:.1f} GHz" if mhz else None)
        gd.configure(text=f"Temp. {ftemp(s.get('cpu_temp'))}")
        gg, gdd = self.gauges["gpu"]
        gg.set(g.get("load"))
        vr = ""
        if g.get("vram_used") is not None:
            vr = f"\nVRAM {g['vram_used'] / 1024:.1f}" + (f"/{g['vram_total'] / 1024:.0f}" if g.get("vram_total") else "") + " GB"
        gdd.configure(text=f"Temp. {ftemp(g.get('temp'))}{vr}")
        gr, grd = self.gauges["ram"]
        gr.set(s.get("ram"), color=None, warn=70, bad=90)
        grd.configure(text=f"{core.sizefmt(s.get('ram_used'))} de {core.sizefmt(s.get('ram_total'))}")
        ge, ged = self.gauges["extra"]
        bt = s.get("battery")
        if bt:
            ge.label = "BATERIA"
            ge.set(bt["percent"], color=W.level_color(100 - bt["percent"], 70, 85),
                   sub="carregando" if bt["plugged"] else sensors.format_secs(bt["secs_left"]))
            ged.configure(text="Na tomada" if bt["plugged"] else "Na bateria")
        else:
            ge.label = "TEMP. CPU"
            t = s.get("cpu_temp")
            ge.set(t, text=ftemp(t) if t is not None else "--", warn=65, bad=80)
            ged.configure(text="Sem bateria (PC de mesa)")
        self.kv["CPU"].set(ftemp(s.get("cpu_temp")))
        self.kv["GPU"].set(ftemp(g.get("temp")))
        self.kv["Consumo CPU"].set(fwatt(s.get("cpu_power")))
        self.kv["Consumo GPU"].set(fwatt(g.get("power")))
        fans = s.get("fans") or []
        self.kv["Ventoinhas"].set(", ".join(f"{v:.0f} RPM" for _, v in fans[:3]) if fans else "--")
        self.kv["Download"].set(_rate(s.get("net_down")))
        self.kv["Upload"].set(_rate(s.get("net_up")))
        self.kv["Leitura de disco"].set(_rate(s.get("disk_read")))
        self.kv["Escrita de disco"].set(_rate(s.get("disk_write")))
        src = s.get("sources", {})
        if core.IS_WIN and s.get("cpu_temp") is None:
            self.src_hint.configure(text="Sem leitura de temperatura. Abra o LibreHardwareMonitor "
                                         "(como administrador) em Desempenho > RGB e Ventoinhas.")
        else:
            self.src_hint.configure(text="")
        for k, sp in self.sparks.items():
            sp.set(s["hist"].get(k), 100 if k != "cpu_temp" else 100)


def _rate(v):
    from overlay import fmt_rate
    return fmt_rate(v)


# ----------------------------------------------------------------------------
class Specs(Page):
    title = "Especificações"
    subtitle = "Hardware e sistema do seu PC (como CPU-Z e GPU-Z)."
    scroll = True

    def build(self):
        Btn(self.head_right, "Copiar relatório", self.copy).pack(side="right", padx=(8, 0))
        Btn(self.head_right, "Atualizar", self.load, "accent").pack(side="right")
        self.holder = tk.Frame(self.body, bg=C["bg"])
        self.holder.pack(fill="both", expand=True)
        self.sections, self.loaded = {}, False

    def on_show(self):
        if not self.loaded:
            self.load()

    def load(self):
        self.loaded = True
        for w in self.holder.winfo_children():
            w.destroy()
        lbl(self.holder, "Lendo hardware...", 11, "muted", bg="bg").pack(pady=30)
        self.app.say("Lendo hardware...")
        self.app.bg(core.gather_system_info, self._done)

    def _done(self, r, e):
        for w in self.holder.winfo_children():
            w.destroy()
        if not r:
            lbl(self.holder, f"Erro: {e}", 10, "bad", bg="bg").pack(pady=30)
            return
        self.sections = r
        if core.psutil:
            import psutil
            up = time.time() - psutil.boot_time()
            r.setdefault("Sistema operacional", {})["Ligado há"] = f"{int(up // 3600)} h {int(up % 3600 // 60)} min"
        grid = tk.Frame(self.holder, bg=C["bg"])
        grid.pack(fill="x")
        grid.columnconfigure((0, 1), weight=1, uniform="c")
        order = ["Computador", "Sistema operacional", "CPU", "Placa-mãe", "BIOS", "Memória"]
        keys = [k for k in order if k in r] + [k for k in r if k not in order]
        for i, title in enumerate(keys):
            card = Card(grid, title)
            card.grid(row=i // 2, column=i % 2, sticky="nsew", pady=(0, px(10)),
                      padx=(0 if i % 2 == 0 else px(5), px(5) if i % 2 == 0 else 0))
            kv_rows(card.body, r[title])
        self.app.say("Hardware lido.")

    def copy(self):
        if self.sections:
            self.app.clipboard_clear()
            self.app.clipboard_append(core.format_sections(self.sections))
            self.app.say("Relatório copiado para a área de transferência.")


# ----------------------------------------------------------------------------
class Battery(Page):
    title = "Bateria"
    subtitle = "Carga atual e saúde real (capacidade de fábrica x capacidade atual)."
    scroll = True

    def build(self):
        Btn(self.head_right, "Relatório completo (HTML)", self.html).pack(side="right", padx=(8, 0))
        Btn(self.head_right, "Atualizar", self.load, "accent").pack(side="right")
        b = self.body
        top = tk.Frame(b, bg=C["bg"])
        top.pack(fill="x")
        top.columnconfigure(1, weight=1)
        gc = Card(top, pad=12)
        gc.grid(row=0, column=0, sticky="nsew", padx=(0, px(10)))
        self.gauge = Gauge(gc.body, 170, "CARGA")
        self.gauge.pack()
        self.state_lbl = lbl(gc.body, "", 10, "muted", bg="card")
        self.state_lbl.pack(pady=(px(2), 0))
        self.health = Card(top, "Saúde da bateria")
        self.health.grid(row=0, column=1, sticky="nsew")
        self.verdict = lbl(self.health.body, "Lendo...", 12, "muted", True, bg="card", justify="left",
                           wraplength=px(480))
        self.verdict.pack(anchor="w")
        self.hbar = Bar(self.health.body, 10)
        self.hbar.pack(fill="x", pady=(px(8), px(10)))
        self.kv = {}
        for k in ("Capacidade de fábrica", "Capacidade atual máxima", "Saúde", "Ciclos de carga",
                  "Fabricante", "Química"):
            self.kv[k] = KV(self.health.body, k)
            self.kv[k].pack(fill="x", pady=2)
        h = Card(b, "Evolução da saúde", "Um ponto por dia em que você abre esta página.")
        h.pack(fill="x", pady=(px(12), 0))
        self.spark = Spark(h.body, 80, C["ok"])
        self.spark.pack(fill="x")
        self.hist_lbl = lbl(h.body, "", 9, "muted", bg="card")
        self.hist_lbl.pack(anchor="w")
        tips = Card(b, "Para a bateria durar mais")
        tips.pack(fill="x", pady=(px(12), px(6)))
        for t in ("Evite deixar sempre em 100% ou chegar a 0%: entre 20% e 80% desgasta menos.",
                  "Calor é o maior inimigo. Não use o notebook sobre cama ou sofa.",
                  "Se ficar muito tempo na tomada, use o limitador de carga do fabricante (se houver)."):
            lbl(tips.body, "•  " + t, 10, "muted", bg="card", wraplength=px(760), justify="left"
                ).pack(anchor="w", pady=1)
        self.has_battery = None

    def on_show(self):
        self.load()

    def load(self):
        self.verdict.configure(text="Lendo...", fg=C["muted"])
        self.app.bg(sensors.battery_report, self._done)

    def _done(self, r, e):
        if e or not r:
            self.has_battery = False
            self.verdict.configure(text="Nenhuma bateria detectada (PC de mesa?)." if not e else
                                   f"Não foi possível ler a bateria: {e}", fg=C["warn"])
            self.hbar.set(0)
            return
        self.has_battery = True
        b = r[0]
        text, level = sensors.battery_verdict(b["health"])
        color = {"ok": C["ok"], "warn": C["warn"], "bad": C["bad"]}.get(level, C["muted"])
        self.verdict.configure(text=text, fg=color)
        self.hbar.set((b["health"] or 0) / 100, color)
        self.kv["Capacidade de fábrica"].set(f"{b['design_mwh'] / 1000:.1f} Wh")
        self.kv["Capacidade atual máxima"].set(f"{b['full_mwh'] / 1000:.1f} Wh")
        self.kv["Saúde"].set(f"{b['health']:.0f}%" if b["health"] is not None else "--", color)
        self.kv["Ciclos de carga"].set(str(b["cycles"]) if b["cycles"] else "--")
        self.kv["Fabricante"].set(b["manufacturer"] or "--")
        self.kv["Química"].set(b["chemistry"] or "--")
        hist = sensors.record_battery_health(b)
        self.spark.set([h["health"] for h in hist], 100)
        if hist:
            self.hist_lbl.configure(text=f"{len(hist)} registro(s). Primeiro: {hist[0]['date']} ({hist[0]['health']:.0f}%)")

    def tick(self, s):
        bt = (s or {}).get("battery")
        if bt:
            self.gauge.set(bt["percent"], color=W.level_color(100 - bt["percent"], 70, 85))
            self.state_lbl.configure(text=("Carregando" if bt["plugged"] else
                                           f"Restam {sensors.format_secs(bt['secs_left'])}"))
        else:
            self.gauge.set(None)
            self.state_lbl.configure(text="Sem bateria")

    def html(self):
        if not core.IS_WIN:
            self.app.info("Relatório", "O relatório completo usa o powercfg, do Windows.")
            return
        self.app.bg(sensors.battery_html_report, lambda r, e: self.app.open_path(r) if r else
                    self.app.error("Relatório", str(e)))


# ----------------------------------------------------------------------------
class Disk(Page):
    title = "Discos"
    subtitle = "Espaco usado e saúde (SMART) de cada disco."
    scroll = True

    def build(self):
        Btn(self.head_right, "Verificar saúde", self.load, "accent").pack(side="right")
        self.vols = Card(self.body, "Volumes")
        self.vols.pack(fill="x")
        self.smart = tk.Frame(self.body, bg=C["bg"])
        self.smart.pack(fill="x", pady=(px(12), 0))
        self.loaded = False

    def on_show(self):
        self._volumes()
        if not self.loaded:
            self.load()

    def _volumes(self):
        for w in list(self.vols.body.winfo_children())[2:]:
            w.destroy()
        for mount, total, free in core.list_volumes():
            used = total - free
            r = tk.Frame(self.vols.body, bg=C["card"])
            r.pack(fill="x", pady=px(5))
            top = tk.Frame(r, bg=C["card"])
            top.pack(fill="x")
            lbl(top, mount, 10, "text", True, bg="card").pack(side="left")
            lbl(top, f"{core.sizefmt(used)} usados de {core.sizefmt(total)}  -  {core.sizefmt(free)} livres",
                10, "muted", bg="card").pack(side="right")
            bar = Bar(r, 9)
            bar.pack(fill="x", pady=(4, 0))
            bar.after(50, lambda b=bar, u=used, t=total: b.set(u / t if t else 0, W.level_color(u / t * 100, 75, 90)))

    def load(self):
        self.loaded = True
        for w in self.smart.winfo_children():
            w.destroy()
        lbl(self.smart, "Lendo SMART...", 10, "muted", bg="bg").pack(anchor="w")
        self.app.bg(core.disk_health, self._done)

    def _done(self, r, e):
        for w in self.smart.winfo_children():
            w.destroy()
        for d in (r or []):
            card = Card(self.smart, d.get("Nome", "Disco"))
            card.pack(fill="x", pady=(0, px(10)))
            health = str(d.get("Saude", ""))
            chip = Chip(card.body, health or "?", "ok" if health.lower() == "healthy" else "warn")
            chip.pack(anchor="w", pady=(0, 6))
            rest = {k: v for k, v in d.items() if k not in ("Nome", "Saude")}
            labels = {"TamanhoGB": "Tamanho (GB)", "ErrosLeitura": "Erros de leitura",
                      "ErrosEscrita": "Erros de escrita", "Horas": "Horas ligado",
                      "Temperatura": "Temperatura (°C)"}
            kv_rows(card.body, {labels.get(k, k): v for k, v in rest.items()})
        if e:
            lbl(self.smart, f"Erro: {e}", 10, "bad", bg="bg").pack(anchor="w")
        lbl(self.smart, "Alguns campos (temperatura, desgaste, horas) só aparecem como administrador.",
            9, "muted", bg="bg").pack(anchor="w")
