#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SysGuard 0.2 - seguranca, diagnostico e desempenho para Windows.
Execute:  python sysguard.py   (abre sem janela de terminal)
"""
import os
import sys
import subprocess
from pathlib import Path


def detach_console():
    """Windows: se aberto pelo python.exe (com terminal), reabre pelo pythonw.exe e fecha esta
    instancia. No EXE (--windowed) nao faz nada."""
    if os.name != "nt" or getattr(sys, "frozen", False):
        return
    exe = Path(sys.executable)
    if exe.name.lower() == "python.exe":
        pyw = exe.with_name("pythonw.exe")
        if pyw.exists():
            subprocess.Popen([str(pyw), *sys.argv], creationflags=0x00000008 | 0x08000000)
            sys.exit(0)
    from core import APP_DIR
    if sys.stdout is None:
        sys.stdout = open(os.devnull, "w")
    if sys.stderr is None:
        sys.stderr = open(APP_DIR / "erros.log", "a", encoding="utf-8")


def dpi_aware():
    if os.name != "nt":
        return
    try:
        import ctypes
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            ctypes.windll.user32.SetProcessDPIAware()
    except Exception:
        pass


def main():
    detach_console()
    dpi_aware()
    from app import App
    App().mainloop()


if __name__ == "__main__":
    main()
