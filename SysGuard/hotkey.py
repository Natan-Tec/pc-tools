# -*- coding: utf-8 -*-
"""Atalho global (Windows) via RegisterHotKey, em thread propria."""
import threading

from core import IS_WIN, log

MOD_ALT, MOD_CONTROL, MOD_SHIFT = 0x1, 0x2, 0x4
VK_F10 = 0x79


class GlobalHotkey:
    def __init__(self, callback, mods=MOD_CONTROL | MOD_SHIFT, vk=VK_F10, hk_id=0x5347):
        self.callback, self.mods, self.vk, self.id = callback, mods, vk, hk_id
        self._tid = None
        self.ok = False

    def start(self):
        if not IS_WIN:
            return
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        import ctypes
        from ctypes import wintypes
        u32, k32 = ctypes.windll.user32, ctypes.windll.kernel32
        self._tid = k32.GetCurrentThreadId()
        if not u32.RegisterHotKey(None, self.id, self.mods, self.vk):
            log("Atalho global ja esta em uso por outro programa.")
            return
        self.ok = True
        msg = wintypes.MSG()
        while u32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
            if msg.message == 0x0312 and msg.wParam == self.id:  # WM_HOTKEY
                try:
                    self.callback()
                except Exception as e:  # noqa
                    log(f"hotkey: {e}")
        u32.UnregisterHotKey(None, self.id)

    def stop(self):
        if IS_WIN and self._tid:
            import ctypes
            ctypes.windll.user32.PostThreadMessageW(self._tid, 0x0012, 0, 0)  # WM_QUIT
