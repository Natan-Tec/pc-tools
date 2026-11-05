# -*- coding: utf-8 -*-
"""SysGuard - tema e componentes visuais (Tkinter puro, sem dependencias)."""
import math
import tkinter as tk
from tkinter import ttk

from core import IS_WIN

# ----------------------------------------------------------------------------
# Tema
# ----------------------------------------------------------------------------
C = dict(
    bg="#0d0f15", side="#11141c", card="#161a24", card2="#1e2330", border="#262c3b",
    text="#e8eaf0", muted="#8b93a7", dim="#566074", accent="#6d8dff", accent_h="#8aa3ff",
    ok="#4ade80", warn="#fbbf24", bad="#f87171", input="#0f1219", hover="#222838",
    sel="#27304a",
)
FONT = "Segoe UI" if IS_WIN else "DejaVu Sans"
MONO = "Consolas" if IS_WIN else "DejaVu Sans Mono"
SCALE = 1.0
TEST_ANSWER = None  # testes automatizados: resposta fixa para dialogos


def px(n):
    return int(round(n * SCALE))


def font(size=10, bold=False, mono=False):
    return (MONO if mono else FONT, size, "bold" if bold else "normal")


def col(x):
    return C.get(x, x)


def level_color(v, warn=60, bad=85):
    if v is None:
        return C["dim"]
    return C["ok"] if v < warn else (C["warn"] if v < bad else C["bad"])


def lbl(parent, text="", size=10, color="text", bold=False, bg=None, mono=False, **kw):
    if bg is None:
        try:
            bg = parent.cget("bg")
        except tk.TclError:
            bg = C["card"]
    return tk.Label(parent, text=text, bg=col(bg), fg=col(color),
                    font=font(size, bold, mono), **kw)


def init_style(root):
    global SCALE
    try:
        SCALE = max(1.0, root.winfo_fpixels("1i") / 96.0)
    except tk.TclError:
        SCALE = 1.0
    s = ttk.Style(root)
    s.theme_use("clam")
    s.configure(".", background=C["bg"], foreground=C["text"], fieldbackground=C["input"],
                font=font(10), borderwidth=0)
    # Treeview
    s.configure("Treeview", background=C["card"], fieldbackground=C["card"], foreground=C["text"],
                rowheight=px(30), borderwidth=0, relief="flat", font=font(10))
    s.configure("Treeview.Heading", background=C["card2"], foreground=C["muted"], relief="flat",
                font=font(9, True), padding=(8, 7), borderwidth=0)
    s.map("Treeview", background=[("selected", C["sel"])], foreground=[("selected", C["text"])])
    s.map("Treeview.Heading", background=[("active", C["hover"])])
    s.layout("Treeview", [("Treeview.treearea", {"sticky": "nswe"})])
    # Scrollbar fina
    for o in ("Vertical", "Horizontal"):
        s.layout(f"{o}.TScrollbar", [(f"{o}.Scrollbar.trough", {"children": [
            (f"{o}.Scrollbar.thumb", {"expand": "1", "sticky": "nswe"})], "sticky": "nswe"})])
    s.configure("TScrollbar", background=C["card2"], troughcolor=C["card"], bordercolor=C["card"],
                lightcolor=C["card2"], darkcolor=C["card2"], gripcount=0, width=px(10))
    s.map("TScrollbar", background=[("active", C["dim"])])
    # Combobox
    s.configure("TCombobox", fieldbackground=C["input"], background=C["card2"], foreground=C["text"],
                arrowcolor=C["muted"], bordercolor=C["border"], lightcolor=C["border"],
                darkcolor=C["border"], padding=6, selectbackground=C["input"], selectforeground=C["text"])
    s.map("TCombobox", fieldbackground=[("readonly", C["input"])],
          foreground=[("readonly", C["text"])], bordercolor=[("focus", C["accent"])])
    root.option_add("*TCombobox*Listbox.background", C["input"])
    root.option_add("*TCombobox*Listbox.foreground", C["text"])
    root.option_add("*TCombobox*Listbox.selectBackground", C["accent"])
    root.option_add("*TCombobox*Listbox.selectForeground", "#0b0f1a")
    root.option_add("*TCombobox*Listbox.font", font(10))
    root.option_add("*Font", font(10))
    s.configure("TProgressbar", background=C["accent"], troughcolor=C["card2"], bordercolor=C["card2"],
                lightcolor=C["accent"], darkcolor=C["accent"])
    s.configure("TPanedwindow", background=C["bg"])
    s.configure("Sash", sashthickness=6, background=C["bg"])
    s.configure("TSeparator", background=C["border"])


def dark_titlebar(win):
    if not IS_WIN:
        return
    try:
        import ctypes
        win.update_idletasks()
        hwnd = ctypes.windll.user32.GetParent(win.winfo_id())
        val = ctypes.c_int(1)
        for attr in (20, 19):  # DWMWA_USE_IMMERSIVE_DARK_MODE (Win10 2004+/Win11)
            ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, attr, ctypes.byref(val), 4)
    except Exception:
        pass


# ----------------------------------------------------------------------------
# Botao
# ----------------------------------------------------------------------------
class Btn(tk.Label):
    KINDS = {
        "default": ("card2", "text", "hover"),
        "accent": ("accent", "#0b0f1a", "accent_h"),
        "danger": ("#e5484d", "#ffffff", "#f0646a"),
        "ghost": ("card", "muted", "card2"),
    }

    def __init__(self, parent, text, command=None, kind="default", **kw):
        self._bg, self._fg, self._hov = (col(x) for x in self.KINDS[kind])
        kw.setdefault("padx", px(14))
        kw.setdefault("pady", px(7))
        super().__init__(parent, text=text, bg=self._bg, fg=self._fg, font=font(10, True),
                         cursor="hand2", **kw)
        self.command, self._disabled, self.kind = command, False, kind
        self.bind("<Enter>", lambda e: self._hover(True))
        self.bind("<Leave>", lambda e: self._hover(False))
        self.bind("<ButtonRelease-1>", self._click)

    def _hover(self, on):
        if not self._disabled:
            self.configure(bg=self._hov if on else self._bg)

    def _click(self, e):
        if self._disabled or not self.command:
            return
        if 0 <= e.x <= self.winfo_width() and 0 <= e.y <= self.winfo_height():
            self.command()

    def disable(self, flag=True):
        self._disabled = flag
        self.configure(fg=C["dim"] if flag else self._fg, bg=self._bg,
                       cursor="arrow" if flag else "hand2")


# ----------------------------------------------------------------------------
# Card / Chip / Linhas de informacao
# ----------------------------------------------------------------------------
class Card(tk.Frame):
    def __init__(self, parent, title=None, subtitle=None, pad=16, **kw):
        super().__init__(parent, bg=C["card"], highlightthickness=1,
                         highlightbackground=C["border"], highlightcolor=C["border"], **kw)
        self.body = tk.Frame(self, bg=C["card"])
        self.body.pack(fill="both", expand=True, padx=px(pad), pady=px(pad - 2))
        if title:
            lbl(self.body, title, 11, "text", True, bg="card").pack(anchor="w")
        if subtitle:
            lbl(self.body, subtitle, 9, "muted", bg="card", justify="left",
                wraplength=px(520)).pack(anchor="w", pady=(2, 0))
        if title or subtitle:
            tk.Frame(self.body, bg=C["card"], height=px(8)).pack()


class Chip(tk.Label):
    def __init__(self, parent, text="", color="muted", **kw):
        super().__init__(parent, text=text, font=font(9, True), padx=px(8), pady=px(2), **kw)
        self.set(text, color)

    def set(self, text, color="muted"):
        c = col(color)
        self.configure(text=text, fg=c, bg=C["card2"])


class KV(tk.Frame):
    """Linha 'rotulo ........ valor'."""

    def __init__(self, parent, key, value="-", bg="card", vcolor="text", mono=False):
        super().__init__(parent, bg=col(bg))
        self.k = lbl(self, key, 10, "muted", bg=bg)
        self.k.pack(side="left")
        self.v = lbl(self, value, 10, vcolor, True, bg=bg, mono=mono, justify="right")
        self.v.pack(side="right")

    def set(self, value, color="text"):
        self.v.configure(text=value, fg=col(color))


def kv_rows(parent, data, bg="card"):
    for k, v in data.items():
        KV(parent, str(k), "-" if v in (None, "") else str(v), bg=bg).pack(fill="x", pady=2)


# ----------------------------------------------------------------------------
# Graficos
# ----------------------------------------------------------------------------
class Gauge(tk.Canvas):
    """Medidor em arco de 270 graus."""

    def __init__(self, parent, size=150, label="", **kw):
        self.size = px(size)
        super().__init__(parent, width=self.size, height=self.size, bg=C["card"],
                         highlightthickness=0, **kw)
        self.label = label
        self.set(None)

    def set(self, value, text=None, sub=None, color=None, warn=60, bad=85):
        self.delete("all")
        s, w = self.size, px(11)
        pad = w // 2 + px(4)
        box = (pad, pad, s - pad, s - pad)
        self.create_arc(*box, start=225, extent=-270, style="arc", width=w, outline=C["card2"])
        if value is not None:
            v = max(0.0, min(100.0, value))
            if v > 0.3:
                self.create_arc(*box, start=225, extent=-270 * v / 100, style="arc", width=w,
                                outline=color or level_color(v, warn, bad))
        shown = text if text is not None else ("--" if value is None else f"{value:.0f}%")
        self.create_text(s / 2, s / 2 - px(6), text=shown, fill=C["text"], font=font(19, True))
        if sub:
            self.create_text(s / 2, s / 2 + px(17), text=sub, fill=C["muted"], font=font(9))
        self.create_text(s / 2, s - px(10), text=self.label, fill=C["muted"], font=font(9, True))


class Bar(tk.Canvas):
    def __init__(self, parent, height=8, bg="card", **kw):
        self.h = px(height)
        super().__init__(parent, height=self.h, bg=col(bg), highlightthickness=0, **kw)
        self._frac, self._color = 0.0, C["accent"]
        self.bind("<Configure>", lambda e: self._draw())

    def set(self, frac, color=None):
        self._frac = max(0.0, min(1.0, frac or 0.0))
        self._color = color or level_color(self._frac * 100)
        self._draw()

    def _draw(self):
        self.delete("all")
        w, h = self.winfo_width(), self.h
        if w < h * 2:
            return
        r = h / 2
        self.create_line(r, h / 2, w - r, h / 2, width=h, capstyle="round", fill=C["card2"])
        x1 = r + (w - 2 * r) * self._frac
        if self._frac > 0.005:
            self.create_line(r, h / 2, max(r + 0.1, x1), h / 2, width=h, capstyle="round",
                             fill=self._color)


class Spark(tk.Canvas):
    def __init__(self, parent, height=60, color="accent", maxv=100, bg="card", **kw):
        super().__init__(parent, height=px(height), bg=col(bg), highlightthickness=0, **kw)
        self.color, self.maxv, self.values = col(color), maxv, []
        self.bind("<Configure>", lambda e: self.draw())

    def set(self, values, maxv=None):
        self.values = list(values or [])
        if maxv:
            self.maxv = maxv
        self.draw()

    def draw(self):
        self.delete("all")
        w, h = self.winfo_width(), int(self.cget("height"))
        for i in (0.25, 0.5, 0.75):
            self.create_line(0, h * i, w, h * i, fill=C["card2"])
        vals = [v for v in self.values]
        if len([v for v in vals if v is not None]) < 2 or w < 10:
            return
        n, mx = len(vals), max(self.maxv, max(v for v in vals if v is not None) * 1.05, 1)
        pts, step = [], w / max(n - 1, 1)
        for i, v in enumerate(vals):
            if v is None:
                if len(pts) >= 4:
                    self.create_line(*pts, fill=self.color, width=px(2), smooth=True)
                pts = []
                continue
            pts += [i * step, h - 3 - (h - 6) * (v / mx)]
        if len(pts) >= 4:
            self.create_line(*pts, fill=self.color, width=px(2), smooth=True)


class Toggle(tk.Canvas):
    def __init__(self, parent, variable=None, command=None, bg="card", **kw):
        self.w, self.h = px(38), px(20)
        super().__init__(parent, width=self.w, height=self.h, bg=col(bg), highlightthickness=0,
                         cursor="hand2", **kw)
        self.var = variable or tk.BooleanVar(value=False)
        self.command = command
        self.bind("<Button-1>", self._click)
        self.var.trace_add("write", lambda *a: self._draw())
        self._draw()

    def _click(self, _e):
        self.var.set(not self.var.get())
        if self.command:
            self.command(self.var.get())

    def _draw(self):
        self.delete("all")
        on = bool(self.var.get())
        h = self.h
        self.create_line(h / 2, h / 2, self.w - h / 2, h / 2, width=h - 2, capstyle="round",
                         fill=C["accent"] if on else C["card2"])
        x = self.w - h / 2 - 1 if on else h / 2 + 1
        r = h / 2 - 4
        self.create_oval(x - r, h / 2 - r, x + r, h / 2 + r, fill="#ffffff" if on else C["muted"],
                         outline="")


def toggle_row(parent, text, var, command=None, bg="card", hint=None):
    f = tk.Frame(parent, bg=col(bg))
    left = tk.Frame(f, bg=col(bg))
    left.pack(side="left", fill="x", expand=True)
    lbl(left, text, 10, "text", bg=bg).pack(anchor="w")
    if hint:
        lbl(left, hint, 9, "muted", bg=bg, wraplength=px(420), justify="left").pack(anchor="w")
    Toggle(f, var, command, bg=bg).pack(side="right", padx=(8, 0))
    return f


def entry(parent, var=None, width=20, **kw):
    return tk.Entry(parent, textvariable=var, width=width, bg=C["input"], fg=C["text"],
                    insertbackground=C["text"], relief="flat", font=font(10),
                    highlightthickness=1, highlightbackground=C["border"],
                    highlightcolor=C["accent"], **kw)


def combo(parent, values, width=22, var=None):
    cb = ttk.Combobox(parent, values=values, state="readonly", width=width, textvariable=var)
    if values and not var:
        cb.current(0)
    return cb


# ----------------------------------------------------------------------------
# Arvore / texto / rolagem
# ----------------------------------------------------------------------------
def make_tree(parent, cols, height=10, selectmode="browse"):
    """cols: [(id, titulo, largura, anchor)] -> (frame, treeview)"""
    fr = tk.Frame(parent, bg=C["card"], highlightthickness=1, highlightbackground=C["border"])
    tv = ttk.Treeview(fr, columns=[c[0] for c in cols], show="headings", height=height,
                      selectmode=selectmode)
    for cid, title, w, anc in cols:
        tv.heading(cid, text=title)
        tv.column(cid, width=px(w), anchor=anc, stretch=(cid == cols[-1][0]))
    sb = ttk.Scrollbar(fr, orient="vertical", command=tv.yview)
    tv.configure(yscrollcommand=sb.set)
    tv.pack(side="left", fill="both", expand=True)
    sb.pack(side="right", fill="y")
    tv.tag_configure("alto", foreground=C["bad"])
    tv.tag_configure("medio", foreground=C["warn"])
    tv.tag_configure("info", foreground=C["muted"])
    tv.tag_configure("ok", foreground=C["ok"])
    return fr, tv


def make_text(parent, height=10):
    fr = tk.Frame(parent, bg=C["input"], highlightthickness=1, highlightbackground=C["border"])
    t = tk.Text(fr, height=height, bg=C["input"], fg=C["text"], insertbackground=C["text"],
                relief="flat", font=font(10, mono=True), wrap="word", padx=10, pady=8,
                selectbackground=C["sel"], borderwidth=0, highlightthickness=0)
    sb = ttk.Scrollbar(fr, orient="vertical", command=t.yview)
    t.configure(yscrollcommand=sb.set)
    t.pack(side="left", fill="both", expand=True)
    sb.pack(side="right", fill="y")
    return fr, t


class ScrollFrame(tk.Frame):
    """Area rolavel; coloque o conteudo em .inner"""

    def __init__(self, parent, bg="bg"):
        super().__init__(parent, bg=col(bg))
        self.cv = tk.Canvas(self, bg=col(bg), highlightthickness=0)
        self.sb = ttk.Scrollbar(self, orient="vertical", command=self.cv.yview)
        self.cv.configure(yscrollcommand=self.sb.set)
        self.sb.pack(side="right", fill="y")
        self.cv.pack(side="left", fill="both", expand=True)
        self.inner = tk.Frame(self.cv, bg=col(bg))
        self._win = self.cv.create_window(0, 0, window=self.inner, anchor="nw")
        self.inner.bind("<Configure>", self._on_inner)
        self.cv.bind("<Configure>", lambda e: self.cv.itemconfigure(self._win, width=e.width))
        self.bind("<Enter>", lambda e: self._bind_wheel(True))
        self.bind("<Leave>", lambda e: self._bind_wheel(False))

    def _on_inner(self, _e):
        self.cv.configure(scrollregion=self.cv.bbox("all"))
        need = self.inner.winfo_reqheight() > self.cv.winfo_height()
        if need and not self.sb.winfo_ismapped():
            self.sb.pack(side="right", fill="y", before=self.cv)
        elif not need and self.sb.winfo_ismapped():
            self.sb.pack_forget()

    def _bind_wheel(self, on):
        top = self.winfo_toplevel()
        if on:
            top.bind_all("<MouseWheel>", self._wheel)
            top.bind_all("<Button-4>", self._wheel)
            top.bind_all("<Button-5>", self._wheel)
        else:
            for ev in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
                top.unbind_all(ev)

    def _wheel(self, e):
        if self.inner.winfo_reqheight() <= self.cv.winfo_height():
            return
        d = -1 if (getattr(e, "num", 0) == 4 or getattr(e, "delta", 0) > 0) else 1
        self.cv.yview_scroll(d * 3, "units")


# ----------------------------------------------------------------------------
# Dialogos escuros (substituem messagebox)
# ----------------------------------------------------------------------------
class _Dialog(tk.Toplevel):
    def __init__(self, parent, title, message, buttons, danger=False):
        super().__init__(parent)
        self.result = None
        self.withdraw()
        self.title(title)
        self.configure(bg=C["card"], highlightthickness=1, highlightbackground=C["border"])
        self.transient(parent)
        self.resizable(False, False)
        body = tk.Frame(self, bg=C["card"])
        body.pack(fill="both", expand=True, padx=px(22), pady=(px(20), px(12)))
        lbl(body, title, 13, "bad" if danger else "text", True, bg="card").pack(anchor="w")
        lbl(body, message, 10, "text", bg="card", wraplength=px(440), justify="left"
            ).pack(anchor="w", pady=(px(8), 0))
        row = tk.Frame(self, bg=C["card"])
        row.pack(fill="x", padx=px(22), pady=(px(6), px(18)))
        for i, (text, value, kind) in enumerate(reversed(buttons)):
            Btn(row, text, lambda v=value: self._done(v), kind).pack(side="right", padx=(8, 0))
        self.bind("<Escape>", lambda e: self._done(buttons[0][1] if len(buttons) == 1 else False))
        self.protocol("WM_DELETE_WINDOW", lambda: self._done(False))
        self.update_idletasks()
        try:
            x = parent.winfo_rootx() + (parent.winfo_width() - self.winfo_reqwidth()) // 2
            y = parent.winfo_rooty() + (parent.winfo_height() - self.winfo_reqheight()) // 3
            self.geometry(f"+{max(x, 0)}+{max(y, 0)}")
        except tk.TclError:
            pass
        dark_titlebar(self)
        self.deiconify()
        self.grab_set()
        self.focus_set()

    def _done(self, v):
        self.result = v
        self.grab_release()
        self.destroy()


def ask(parent, title, message, yes="Confirmar", no="Cancelar", danger=False):
    if TEST_ANSWER is not None:
        return TEST_ANSWER
    d = _Dialog(parent, title, message,
                [(no, False, "default"), (yes, True, "danger" if danger else "accent")], danger)
    parent.wait_window(d)
    return bool(d.result)


def info(parent, title, message, kind="info"):
    if TEST_ANSWER is not None:
        return
    d = _Dialog(parent, title, message, [("OK", True, "accent")], danger=(kind == "error"))
    parent.wait_window(d)


# ----------------------------------------------------------------------------
# Pagina base
# ----------------------------------------------------------------------------
class Page(tk.Frame):
    title, subtitle, scroll = "", "", False

    def __init__(self, app, parent):
        super().__init__(parent, bg=C["bg"])
        self.app = app
        head = tk.Frame(self, bg=C["bg"])
        head.pack(fill="x", padx=px(26), pady=(px(22), px(10)))
        self.head_left = tk.Frame(head, bg=C["bg"])
        self.head_left.pack(side="left")
        lbl(self.head_left, self.title, 20, "text", True, bg="bg").pack(anchor="w")
        if self.subtitle:
            lbl(self.head_left, self.subtitle, 10, "muted", bg="bg", wraplength=px(640),
                justify="left").pack(anchor="w", pady=(2, 0))
        self.head_right = tk.Frame(head, bg=C["bg"])
        self.head_right.pack(side="right")
        if self.scroll:
            sf = ScrollFrame(self)
            sf.pack(fill="both", expand=True, padx=(px(26), px(14)), pady=(0, px(10)))
            self.body = sf.inner
        else:
            self.body = tk.Frame(self, bg=C["bg"])
            self.body.pack(fill="both", expand=True, padx=px(26), pady=(0, px(10)))
        self.build()

    def build(self):
        pass

    def on_show(self):
        pass

    def on_hide(self):
        pass

    def tick(self, snap):
        pass
