# -*- coding: utf-8 -*-
"""
SysGuard - controle de RGB via OpenRGB (servidor SDK, porta 6742).
Requer: OpenRGB aberto com o servidor ligado e `pip install openrgb-python`.
"""
import os
import time
import colorsys
import threading
import subprocess

from core import IS_WIN, log


def start_openrgb_server(path):
    if not path or not os.path.exists(path):
        raise FileNotFoundError("Caminho do OpenRGB não configurado.")
    subprocess.Popen([path, "--server", "--startminimized"],
                     creationflags=0x08000000 if IS_WIN else 0)


class RGBController:
    def __init__(self):
        self.client, self.error = None, ""
        self._fx_stop = threading.Event()
        self._fx_thread = None

    @property
    def connected(self):
        return self.client is not None

    def connect(self, host="127.0.0.1", port=6742):
        try:
            from openrgb import OpenRGBClient
            from openrgb.utils import RGBColor
        except ImportError:
            self.error = "Biblioteca ausente. Instale:  pip install openrgb-python"
            return False
        self._RGB = RGBColor
        try:
            self.client = OpenRGBClient(host, port, name="SysGuard")
            self.error = ""
            return True
        except Exception as e:  # noqa
            self.client = None
            self.error = ("Não foi possível conectar ao OpenRGB. Abra o OpenRGB e ative "
                          f"'SDK Server' (porta {port}).  Detalhe: {e}")
            return False

    def disconnect(self):
        self.stop_fx()
        try:
            if self.client:
                self.client.disconnect()
        except Exception:
            pass
        self.client = None

    def devices(self):
        out = []
        for i, d in enumerate(self.client.devices if self.client else []):
            out.append(dict(index=i, name=d.name, type=str(d.type).split(".")[-1],
                            leds=len(d.leds)))
        return out

    def _apply(self, dev, rgb):
        try:
            dev.set_mode("direct")
        except Exception:
            try:
                dev.set_mode("static")
            except Exception:
                pass
        dev.set_color(self._RGB(*[int(max(0, min(255, c))) for c in rgb]))

    def set_all(self, rgb):
        for d in self.client.devices:
            try:
                self._apply(d, rgb)
            except Exception as e:  # noqa
                log(f"RGB {d.name}: {e}")

    def set_device(self, index, rgb):
        self._apply(self.client.devices[index], rgb)

    def off(self):
        self.stop_fx()
        self.set_all((0, 0, 0))

    # --- efeitos ----------------------------------------------------------------
    def stop_fx(self):
        self._fx_stop.set()
        if self._fx_thread and self._fx_thread.is_alive():
            self._fx_thread.join(timeout=1.5)

    def _start_fx(self, fn):
        self.stop_fx()
        self._fx_stop = threading.Event()
        self._fx_thread = threading.Thread(target=fn, args=(self._fx_stop,), daemon=True)
        self._fx_thread.start()

    def rainbow(self, speed=0.5):
        def run(stop):
            h = 0.0
            while not stop.wait(0.06):
                r, g, b = colorsys.hsv_to_rgb(h, 1, 1)
                self.set_all((r * 255, g * 255, b * 255))
                h = (h + 0.01 * (0.2 + speed * 2)) % 1.0
        self._start_fx(run)

    def breathing(self, rgb, speed=0.5):
        def run(stop):
            t = 0.0
            while not stop.wait(0.05):
                k = (1 + __import__("math").sin(t)) / 2
                self.set_all([c * (0.1 + 0.9 * k) for c in rgb])
                t += 0.1 + speed * 0.4
        self._start_fx(run)
