# -*- coding: utf-8 -*-
"""Páginas: Hosts, Arquivos suspeitos, Integridade, Desinstalador, Limpeza, Registro."""
import os
import re
import datetime
import subprocess
import tkinter as tk
from pathlib import Path
from tkinter import filedialog

import widgets as W
from widgets import (C, Page, Card, Btn, Chip, Bar, lbl, px, combo, entry, make_tree, make_text,
                     Toggle, toggle_row)
import core
from core import IS_WIN, sizefmt

CHK_ON, CHK_OFF = "☑", "☐"


# ----------------------------------------------------------------------------
class Hosts(Page):
    title = "Hosts"
    subtitle = "Protege o arquivo hosts: backup, analise, comparação e restauração."
    scroll = True

    def build(self):
        Btn(self.head_right, "Analisar", self.refresh).pack(side="right", padx=(8, 0))
        Btn(self.head_right, "Criar backup agora", self.backup, "accent").pack(side="right")
        b = self.body
        self.info_chip = Chip(b, "", "muted")
        self.info_chip.pack(anchor="w")
        self.info = lbl(b, "", 10, "muted", bg="bg", wraplength=px(820), justify="left")
        self.info.pack(anchor="w", pady=(6, 8))
        fr, self.tree = make_tree(b, [("line", "Linha", 60, "center"), ("ip", "IP", 120, "w"),
                                      ("domain", "Domínio", 300, "w"), ("cat", "Categoria", 180, "w"),
                                      ("status", "Situação", 220, "w")], height=9)
        fr.pack(fill="x")
        r = tk.Frame(b, bg=C["bg"])
        r.pack(fill="x", pady=(px(10), 0))
        Btn(r, "Testar sites de antivírus", self.test_sites).pack(side="left", padx=(0, 8))
        Btn(r, "Remover bloqueios de antivírus", self.strip, "danger").pack(side="left", padx=(0, 8))
        Btn(r, "Abrir arquivo hosts", lambda: self.app.open_path(core.hosts_path())).pack(side="left")
        bk = Card(b, "Backups salvos", "Duplo clique compara o backup com o hosts atual.")
        bk.pack(fill="x", pady=(px(14), 0))
        fr2, self.bk = make_tree(bk.body, [("name", "Arquivo", 400, "w"), ("size", "Tamanho", 90, "e"),
                                           ("when", "Data", 190, "w")], height=4)
        fr2.pack(fill="x")
        self.bk.bind("<Double-1>", lambda e: self.compare())
        rr = tk.Frame(bk.body, bg=C["card"])
        rr.pack(fill="x", pady=(px(8), 0))
        Btn(rr, "Comparar com atual", self.compare).pack(side="left", padx=(0, 8))
        Btn(rr, "Restaurar selecionado", self.restore).pack(side="left", padx=(0, 8))
        Btn(rr, "Abrir pasta de backups", lambda: self.app.open_path(core.BACKUP_DIR), kind="ghost").pack(side="left")
        fr3, self.out = make_text(b, height=7)
        fr3.pack(fill="x", pady=(px(12), px(6)))

    def on_show(self):
        self.refresh()

    def refresh(self):
        self.tree.delete(*self.tree.get_children())
        try:
            text = core.read_hosts()
        except OSError as e:
            self.info.configure(text=f"Não foi possível ler o hosts: {e}")
            return
        ents = core.parse_hosts(text)
        for e in ents:
            self.tree.insert("", "end", values=(e["line"], e["ip"], e["domain"], e["category"], e["status"]),
                             tags=(e["risk"],))
        high = sum(1 for e in ents if e["risk"] == "alto")
        active = sum(1 for e in ents if e["risk"] != "ok")
        self.info_chip.set("Risco ALTO" if high else ("Atenção" if active else "Limpo"),
                           "bad" if high else ("warn" if active else "ok"))
        self.info.configure(text=f"{core.hosts_path()}\n{core.hosts_summary(ents)}")
        self.bk.delete(*self.bk.get_children())
        for p in core.list_backups():
            st = p.stat()
            self.bk.insert("", "end", iid=str(p), values=(
                p.name, sizefmt(st.st_size), datetime.datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S")))
        self.app.say("Hosts analisado.")

    def backup(self):
        try:
            d = core.backup_hosts()
        except OSError as e:
            self.app.error("Backup", f"Falha no backup: {e}")
            return
        self.refresh()
        self.app.say(f"Backup criado: {d.name}")

    def _sel(self):
        s = self.bk.selection()
        if not s:
            self.app.info("Backups", "Selecione um backup na lista.")
            return None
        return s[0]

    def compare(self):
        b = self._sel()
        if not b:
            return
        add, rem = core.diff_hosts(core.read_hosts(b), core.read_hosts())
        t = self.out
        t.delete("1.0", "end")
        t.insert("end", f"Backup {Path(b).name}  ->  hosts atual\n\nAdicionadas ({len(add)}):\n")
        for ip, d in add:
            t.insert("end", f"  + {ip}  {d}   [{core.categorize(d)}]\n")
        t.insert("end", f"\nRemovidas ({len(rem)}):\n")
        for ip, d in rem:
            t.insert("end", f"  - {ip}  {d}\n")
        if not add and not rem:
            t.insert("end", "\nNenhuma diferenca.\n")

    def restore(self):
        b = self._sel()
        if not b or not self.app.ask("Restaurar hosts", f"Restaurar {Path(b).name}?\nO hosts atual será salvo antes."):
            return
        try:
            core.restore_hosts(b)
        except OSError as e:
            if not self.app.need_admin(e):
                self.app.error("Restaurar", str(e))
            return
        self.refresh()

    def strip(self):
        try:
            new, n = core.strip_security_blocks(core.read_hosts())
        except OSError as e:
            self.app.error("Hosts", str(e))
            return
        if n == 0:
            self.app.info("Hosts", "Nenhum bloqueio de antivírus ou Windows Update encontrado.")
            return
        if not self.app.ask("Remover bloqueios", f"Remover {n} domínio(s) de antivírus/Windows Update do hosts?\n"
                            "Um backup será criado antes.", "Remover", danger=True):
            return
        try:
            core.apply_hosts_text(new)
        except OSError as e:
            if not self.app.need_admin(e):
                self.app.error("Hosts", str(e))
            return
        core.log(f"Removidos {n} bloqueios de segurança do hosts")
        self.refresh()

    def test_sites(self):
        self.out.delete("1.0", "end")
        self.out.insert("end", "Testando acesso...\n")
        self.app.bg(lambda: [(h, core.test_site(h)) for h in core.AV_TEST_SITES], self._tested)

    def _tested(self, r, e):
        self.out.delete("1.0", "end")
        for h, res in (r or []):
            self.out.insert("end", f"{h:<34} {res}\n")


# ----------------------------------------------------------------------------
class Scan(Page):
    title = "Arquivos suspeitos"
    subtitle = "Varredura por indícios (não e antivírus): extensão dupla, pastas temporárias, nomes aleatórios."

    def build(self):
        b = self.body
        self.folders = core.default_scan_folders()
        c = Card(b, pad=14)
        c.pack(fill="x")
        r = tk.Frame(c.body, bg=C["card"])
        r.pack(fill="x")
        Btn(r, "Escolher pastas...", self.pick).pack(side="left", padx=(0, 10))
        lbl(r, "Recentes (dias):", 10, "muted", bg="card").pack(side="left")
        self.days = combo(r, ["7", "14", "30", "90"], 5)
        self.days.current(1)
        self.days.pack(side="left", padx=(6, 12))
        self.btn = Btn(r, "Verificar", self.run, "accent")
        self.btn.pack(side="left", padx=(0, 8))
        Btn(r, "Parar", self.app.cancel_flag.set).pack(side="left")
        self.fl = lbl(c.body, "", 9, "muted", bg="card", wraplength=px(820), justify="left")
        self.fl.pack(anchor="w", pady=(8, 0))
        self._upd()
        fr, self.tree = make_tree(b, [("lvl", "Risco", 70, "center"), ("name", "Arquivo", 220, "w"),
                                      ("size", "Tamanho", 80, "e"), ("when", "Alterado", 120, "w"),
                                      ("why", "Motivos", 300, "w"), ("path", "Caminho", 380, "w")], height=12)
        fr.pack(fill="both", expand=True, pady=(px(12), 0))
        self.data = {}
        r2 = tk.Frame(b, bg=C["bg"])
        r2.pack(fill="x", pady=(px(10), 0))
        Btn(r2, "Calcular SHA-256 e abrir no VirusTotal", self.vt).pack(side="left", padx=(0, 8))
        Btn(r2, "Mostrar na pasta", self.reveal).pack(side="left", padx=(0, 10))
        self.hv = tk.StringVar()
        entry(r2, self.hv, 60).pack(side="left", fill="x", expand=True, ipady=5)

    def _upd(self):
        self.fl.configure(text="Pastas: " + "  |  ".join(str(p) for p in self.folders))

    def pick(self):
        d = filedialog.askdirectory(title="Adicionar pasta para verificar")
        if d:
            self.folders.append(Path(d))
            self._upd()

    def run(self):
        self.tree.delete(*self.tree.get_children())
        self.data.clear()
        self.app.cancel_flag.clear()
        self.btn.disable()
        days = int(self.days.get())

        def work():
            return core.scan_suspicious(self.folders, days, cancel=self.app.cancel_flag.is_set,
                                        progress=lambda s: self.app.ui(self.app.say, f"Verificando {s[:90]}"))

        def done(r, e):
            self.btn.disable(False)
            for it in (r or []):
                iid = self.tree.insert("", "end", values=(it["level"], os.path.basename(it["path"]), sizefmt(it["size"]),
                                                          it["mtime"], it["reasons"], it["path"]),
                                       tags=("alto" if it["level"] == "ALTO" else "medio",))
                self.data[iid] = it
            self.app.say(f"Verificação concluída: {len(r or [])} item(ns) com indícios." + (f" Erro: {e}" if e else ""))
            core.log(f"Verificação de arquivos: {len(r or [])} suspeitos")
        self.app.bg(work, done)

    def vt(self):
        s = self.tree.selection()
        if not s:
            self.app.info("Verificação", "Selecione um arquivo na lista.")
            return
        path = self.data[s[0]]["path"]

        def done(r, e):
            if e:
                self.app.error("Hash", str(e))
                return
            self.hv.set(r)
            if re.fullmatch(r"[0-9a-f]{64}", r):
                import webbrowser
                webbrowser.open(f"https://www.virustotal.com/gui/file/{r}")
        self.app.bg(core.file_sha256, done, path)

    def reveal(self):
        s = self.tree.selection()
        if s:
            p = self.data[s[0]]["path"]
            if IS_WIN:
                subprocess.Popen(["explorer", "/select,", p])
            else:
                self.app.open_path(Path(p).parent)


# ----------------------------------------------------------------------------
class Integrity(Page):
    title = "Integridade do Windows"
    subtitle = "Verificações somente leitura: nada é alterado no sistema."

    def build(self):
        r = tk.Frame(self.body, bg=C["bg"])
        r.pack(fill="x")
        for name, cmd in core.INTEGRITY_CMDS.items():
            Btn(r, name, lambda n=name, c=cmd: self.run(n, c)).pack(side="left", padx=(0, 8), pady=(0, 6))
        fr, self.out = make_text(self.body, height=18)
        fr.pack(fill="both", expand=True, pady=(px(8), 0))

    def run(self, name, cmd):
        if not IS_WIN:
            self.app.info("Integridade", "Estas verificações existem apenas no Windows.")
            return
        if not core.is_admin() and cmd[0] != "chkdsk":
            self.app.info("Integridade", "SFC e DISM exigem administrador.")
            return
        self.out.delete("1.0", "end")
        self.out.insert("end", f"Executando: {' '.join(cmd)}\nPode demorar vários minutos...\n")
        self.app.say(f"{name} em andamento...")

        def done(r, e):
            self.out.insert("end", f"\n{r[1] if r else e}\n\nCodigo de saída: {r[0] if r else '-'}\n")
            core.log(f"Integridade: {name} -> código {r[0] if r else 'erro'}")
            self.app.say("Concluído.")
        self.app.bg(core.run_integrity, done, cmd)


# ----------------------------------------------------------------------------
class _Checks:
    """Treeview com caixinhas na primeira coluna."""

    def __init__(self, tree, on_change):
        self.tree, self.checked, self.on_change = tree, set(), on_change
        tree.bind("<Button-1>", self._click)

    def _click(self, ev):
        if self.tree.identify_region(ev.x, ev.y) != "cell" or self.tree.identify_column(ev.x) != "#1":
            return
        iid = self.tree.identify_row(ev.y)
        if iid:
            self.set(iid, iid not in self.checked)
            self.on_change()

    def set(self, iid, on):
        (self.checked.add if on else self.checked.discard)(iid)
        self.tree.set(iid, "chk", CHK_ON if on else CHK_OFF)

    def all(self, on):
        for iid in self.tree.get_children():
            self.set(iid, on)
        self.on_change()


class Uninstaller(Page):
    title = "Desinstalador"
    subtitle = "Marque vários programas e desinstale tudo de uma vez."

    def build(self):
        b = self.body
        r = tk.Frame(b, bg=C["bg"])
        r.pack(fill="x")
        lbl(r, "Buscar", 10, "muted", bg="bg").pack(side="left")
        self.q = tk.StringVar()
        self.q.trace_add("write", lambda *a: self.render())
        entry(r, self.q, 28).pack(side="left", padx=(8, 14), ipady=5)
        Btn(r, "Atualizar lista", self.load).pack(side="left", padx=(0, 14))
        self.v_silent = tk.BooleanVar(value=True)
        Toggle(r, self.v_silent, bg="bg").pack(side="left")
        lbl(r, "Silencioso", 10, "text", bg="bg").pack(side="left", padx=(6, 14))
        self.v_restore = tk.BooleanVar(value=True)
        Toggle(r, self.v_restore, bg="bg").pack(side="left")
        lbl(r, "Ponto de restauração", 10, "text", bg="bg").pack(side="left", padx=6)
        fr, self.tree = make_tree(b, [("chk", "", 36, "center"), ("name", "Programa", 320, "w"),
                                      ("ver", "Versão", 110, "w"), ("pub", "Fabricante", 210, "w"),
                                      ("size", "Tamanho", 90, "e"), ("date", "Instalado", 100, "w")], height=14)
        fr.pack(fill="both", expand=True, pady=(px(12), 0))
        self.items, self.sort = [], ("name", False)
        for cid, key in (("name", "name"), ("ver", "version"), ("pub", "publisher"), ("size", "size"),
                         ("date", "date")):
            self.tree.heading(cid, command=lambda k=key: self.sort_by(k))
        self.chk = _Checks(self.tree, self._sum)
        r2 = tk.Frame(b, bg=C["bg"])
        r2.pack(fill="x", pady=(px(10), 0))
        Btn(r2, "Marcar visiveis", lambda: self.chk.all(True)).pack(side="left", padx=(0, 8))
        Btn(r2, "Desmarcar todos", lambda: self.chk.all(False)).pack(side="left", padx=(0, 12))
        self.sum = lbl(r2, "", 10, "accent", True, bg="bg")
        self.sum.pack(side="left")
        self.btn = Btn(r2, "Desinstalar marcados", self.run, "danger")
        self.btn.pack(side="right")
        Btn(r2, "Parar após o atual", self.app.cancel_flag.set).pack(side="right", padx=8)
        self.prog = Bar(b, 6, bg="bg")
        self.prog.pack(fill="x", pady=(px(8), 0))
        self.loaded = False

    def on_show(self):
        if not self.loaded:
            self.load()

    def load(self):
        if not IS_WIN:
            self.app.info("Desinstalador", "O desinstalador funciona apenas no Windows.")
            return
        self.loaded = True
        self.app.say("Lendo programas instalados...")

        def done(r, e):
            self.items = r or []
            self.render()
            self.app.say(f"{len(self.items)} programas." + (f" Erro: {e}" if e else ""))
        self.app.bg(core.list_uninstallable, done)

    def sort_by(self, key):
        col, rev = self.sort
        self.sort = (key, (not rev) if col == key else False)
        self.render()

    def render(self):
        keep = {int(i) for i in self.chk.checked}
        self.tree.delete(*self.tree.get_children())
        self.chk.checked = set()
        q = self.q.get().strip().lower()
        key, rev = self.sort
        rows = [(i, p) for i, p in enumerate(self.items) if not q or q in p["name"].lower() or q in p["publisher"].lower()]
        rows.sort(key=lambda t: (t[1][key].lower() if isinstance(t[1][key], str) else t[1][key]), reverse=rev)
        for i, p in rows:
            on = i in keep
            self.tree.insert("", "end", iid=str(i), values=(CHK_ON if on else CHK_OFF, p["name"], p["version"],
                                                            p["publisher"], sizefmt(p["size"]) if p["size"] else "", p["date"]))
            if on:
                self.chk.checked.add(str(i))
        self._sum()

    def _sum(self):
        tot = sum(self.items[int(i)]["size"] for i in self.chk.checked)
        self.sum.configure(text=f"{len(self.chk.checked)} marcado(s) - {sizefmt(tot)}")

    def run(self):
        sel = [self.items[int(i)] for i in sorted(self.chk.checked, key=int)]
        if not sel:
            self.app.info("Desinstalador", "Marque os programas que deseja desinstalar.")
            return
        names = "\n".join(f"• {p['name']}" for p in sel[:12]) + (f"\n... e mais {len(sel) - 12}" if len(sel) > 12 else "")
        if not self.app.ask("Desinstalar programas", f"{len(sel)} programa(s) serão desinstalados:\n\n{names}\n\n"
                            "Salve seu trabalho antes. Alguns abrem janelas próprias.", "Desinstalar", danger=True):
            return
        silent, restore = self.v_silent.get(), self.v_restore.get()
        self.app.cancel_flag.clear()
        self.btn.disable()

        def work():
            res = []
            if restore:
                self.app.ui(self.app.say, "Criando ponto de restauração...")
                core.create_restore_point()
            for n, p in enumerate(sel, 1):
                if self.app.cancel_flag.is_set():
                    break
                self.app.ui(lambda n=n, p=p: (self.app.say(f"Desinstalando {n}/{len(sel)}: {p['name']}"),
                                              self.prog.set((n - 1) / len(sel), C["accent"])))
                res.append((p, *core.uninstall_one(p, silent)))
            return res

        def done(r, e):
            self.btn.disable(False)
            self.prog.set(1.0, C["ok"])
            r = r or []
            ok = [x for x in r if x[1] == "ok"]
            bad = [x for x in r if x[1] != "ok"]
            msg = f"{len(ok)} removido(s), {len(bad)} falha(s)."
            for p, st, det in bad[:8]:
                msg += f"\n• {p['name']}: {det}"
            if any(x[2] for x in ok):
                msg += "\n\nAlgum programa pede para reiniciar o PC."
            self.loaded = False
            self.load()
            if ok and self.app.ask("Concluído", msg + "\n\nProcurar restos desses programas na Limpeza?", "Procurar", "Agora não"):
                self.app.show("clean")
            else:
                self.app.info("Concluído", msg)
        self.app.bg(work, done)


# ----------------------------------------------------------------------------
class Cleaner(Page):
    title = "Limpeza"
    subtitle = "Restos de programas que não estão instalados e arquivos temporários."

    def build(self):
        b = self.body
        c = Card(b, pad=14)
        c.pack(fill="x")
        r = tk.Frame(c.body, bg=C["card"])
        r.pack(fill="x")
        self.roots = {}
        for label, _ in core.scan_roots() or [("(somente Windows)", None)]:
            v = tk.BooleanVar(value=label in ("Program Files", "Program Files (x86)", "AppData\\Local\\Programs", "ProgramData"))
            self.roots[label] = v
            f = tk.Frame(r, bg=C["card"])
            f.pack(side="left", padx=(0, 14), pady=2)
            Toggle(f, v).pack(side="left")
            lbl(f, label, 10, "text", bg="card").pack(side="left", padx=6)
        f = tk.Frame(r, bg=C["card"])
        f.pack(side="left", pady=2)
        self.v_tmp = tk.BooleanVar(value=True)
        Toggle(f, self.v_tmp).pack(side="left")
        lbl(f, "Temporários", 10, "text", bg="card").pack(side="left", padx=6)
        self.btn = Btn(r, "Procurar", self.scan, "accent")
        self.btn.pack(side="right")
        lbl(c.body, "A detecção é por nome é pode errar com programas portateis. Por isso o padrão e mover para a "
                    "quarentena, de onde você pode recuperar.", 9, "muted", bg="card", wraplength=px(820),
            justify="left").pack(anchor="w", pady=(8, 0))
        fr, self.tree = make_tree(b, [("chk", "", 36, "center"), ("name", "Nome", 210, "w"), ("size", "Tamanho", 90, "e"),
                                      ("origin", "Origem", 150, "w"), ("mod", "Alterado", 90, "w"),
                                      ("reason", "Motivo", 220, "w"), ("path", "Caminho", 380, "w")], height=12)
        fr.pack(fill="both", expand=True, pady=(px(12), 0))
        self.data = {}
        self.chk = _Checks(self.tree, self._sum)
        r2 = tk.Frame(b, bg=C["bg"])
        r2.pack(fill="x", pady=(px(10), 0))
        Btn(r2, "Marcar todos", lambda: self.chk.all(True)).pack(side="left", padx=(0, 8))
        Btn(r2, "Desmarcar todos", lambda: self.chk.all(False)).pack(side="left", padx=(0, 14))
        self.v_perm = tk.BooleanVar(value=False)
        Toggle(r2, self.v_perm, bg="bg").pack(side="left")
        lbl(r2, "Apagar de vez (sem quarentena)", 10, "text", bg="bg").pack(side="left", padx=(6, 14))
        self.sum = lbl(r2, "", 10, "accent", True, bg="bg")
        self.sum.pack(side="left")
        Btn(r2, "Deletar arquivos inúteis", self.delete, "danger").pack(side="right")
        Btn(r2, "Abrir quarentena", lambda: self.app.open_path(core.QUARANTINE_DIR)).pack(side="right", padx=8)

    def scan(self):
        if not IS_WIN:
            self.app.info("Limpeza", "A detecção de programas instalados usa o registro do Windows.")
        roots = {k for k, v in self.roots.items() if v.get()}
        tmp = self.v_tmp.get()
        self.btn.disable()
        self.app.cancel_flag.clear()
        self.app.say("Procurando restos de programas...")

        def work():
            known = core.Known(core.installed_programs())
            return core.find_leftovers(roots, tmp, known, self.app.cancel_flag.is_set,
                                       lambda s: self.app.ui(self.app.say, f"Analisando {s[:90]}"))

        def done(r, e):
            self.btn.disable(False)
            self.tree.delete(*self.tree.get_children())
            self.data.clear()
            self.chk.checked.clear()
            for it in (r or []):
                iid = self.tree.insert("", "end", values=(CHK_OFF, it["name"], sizefmt(it["size"]) + ("+" if it["partial"] else ""),
                                                          it["origin"], it["modified"], it["reason"], it["path"]))
                self.data[iid] = it
            self._sum()
            self.app.say(f"{len(r or [])} item(ns) encontrados." + (f" Erro: {e}" if e else ""))
        self.app.bg(work, done)

    def _sum(self):
        tot = sum(self.data[i]["size"] for i in self.chk.checked if i in self.data)
        self.sum.configure(text=f"{len(self.chk.checked)} marcado(s) - {sizefmt(tot)}")

    def delete(self):
        items = [self.data[i] for i in self.chk.checked if i in self.data]
        if not items:
            self.app.info("Limpeza", "Marque os itens que deseja remover.")
            return
        perm = self.v_perm.get()
        tot = sum(i["size"] for i in items)
        how = "APAGADOS DE VEZ (sem volta)" if perm else "movidos para a quarentena do SysGuard"
        if not self.app.ask("Remover itens", f"{len(items)} item(ns), {sizefmt(tot)}, serão {how}.", "Remover", danger=True):
            return
        self.app.say("Removendo...")

        def done(r, e):
            ok, fails = r if r else ([], [])
            for iid, it in list(self.data.items()):
                if it["path"] in ok:
                    self.tree.delete(iid)
                    self.data.pop(iid)
                    self.chk.checked.discard(iid)
            self._sum()
            msg = f"{len(ok)} removido(s)."
            if fails:
                msg += f"\n{len(fails)} falha(s):\n" + "\n".join(f"• {p}: {m}" for p, m in fails[:8])
                if any("negado" in m.lower() or "denied" in m.lower() for _, m in fails):
                    msg += "\n\nDica: reabra como administrador."
            self.app.info("Limpeza", msg)
        self.app.bg(core.delete_items, done, items, perm)


# ----------------------------------------------------------------------------
class LogPage(Page):
    title = "Registro"
    subtitle = "Histórico de tudo o que o SysGuard fez."

    def build(self):
        Btn(self.head_right, "Abrir arquivo de log", lambda: self.app.open_path(core.LOG_FILE)).pack(side="right")
        fr, self.text = make_text(self.body, height=20)
        fr.pack(fill="both", expand=True)
        try:
            self.text.insert("end", core.LOG_FILE.read_text(encoding="utf-8")[-20000:])
            self.text.see("end")
        except OSError:
            pass
        core._log_listeners.append(lambda line: self.app.ui(self._add, line))

    def _add(self, line):
        self.text.insert("end", line + "\n")
        self.text.see("end")
