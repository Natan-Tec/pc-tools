# -*- coding: utf-8 -*-
"""SysGuard - benchmarks de CPU, RAM e disco (sem interface grafica)."""
import os
import json
import math
import time
import hashlib
import datetime
import threading

from core import APP_DIR, disk_benchmark

HIST_FILE = APP_DIR / "benchmarks.json"
_BUF = os.urandom(8 * 1024 * 1024)


def _hash_for(seconds, stop=None):
    """Bytes processados em SHA-256 durante 'seconds' (hashlib libera o GIL)."""
    t0, total = time.perf_counter(), 0
    while time.perf_counter() - t0 < seconds:
        if stop and stop.is_set():
            break
        hashlib.sha256(_BUF).digest()
        total += len(_BUF)
    return total, time.perf_counter() - t0


def cpu_single(seconds=3.0, stop=None):
    n, dt = _hash_for(seconds, stop)
    return n / dt / 1e6  # MB/s


def cpu_multi(threads, seconds=3.0, stop=None):
    res = []

    def work():
        res.append(_hash_for(seconds, stop))
    ts = [threading.Thread(target=work) for _ in range(threads)]
    t0 = time.perf_counter()
    [t.start() for t in ts]
    [t.join() for t in ts]
    dt = time.perf_counter() - t0
    return sum(n for n, _ in res) / dt / 1e6


def cpu_float(seconds=3.0, stop=None):
    """Laco de ponto flutuante em Python puro (1 núcleo): milhoes de iteracoes/s."""
    t0, n, x = time.perf_counter(), 0, 0.0
    sin, sqrt = math.sin, math.sqrt
    while time.perf_counter() - t0 < seconds:
        if stop and stop.is_set():
            break
        for i in range(20000):
            x += sin(i) * sqrt(i + 1.0)
        n += 20000
    return n / (time.perf_counter() - t0) / 1e6


def ram_bandwidth(size_mb=192, rounds=6, stop=None):
    """Copia de memória (GB/s) com memcpy via memoryview."""
    size = size_mb * 1024 * 1024
    src, dst = bytearray(size), bytearray(size)
    src[::4096] = b"\x01" * len(src[::4096])  # forca a alocacao real das paginas
    dst[::4096] = b"\x01" * len(dst[::4096])
    ms, md = memoryview(src), memoryview(dst)
    best = 0.0
    for _ in range(rounds):
        if stop and stop.is_set():
            break
        t0 = time.perf_counter()
        md[:] = ms
        dt = time.perf_counter() - t0
        best = max(best, size / dt / 1e9)
    return best


def cpu_stress(seconds, threads, stop, progress=lambda f: None):
    """Carga máxima em todos os threads (para observar temperatura/clock)."""
    t0 = time.perf_counter()

    def work():
        while time.perf_counter() - t0 < seconds and not stop.is_set():
            hashlib.sha256(_BUF).digest()
    ts = [threading.Thread(target=work, daemon=True) for _ in range(threads)]
    [t.start() for t in ts]
    while time.perf_counter() - t0 < seconds and not stop.is_set():
        progress((time.perf_counter() - t0) / seconds)
        time.sleep(0.25)
    stop.set()
    [t.join() for t in ts]


def scores(r):
    """Pontuação interna (relativa): use para comparar o SEU PC ao longo do tempo."""
    out = {}
    if "single" in r and "float" in r:
        out["score_single"] = round(r["single"] / 10 + r["float"] * 5)
    if "multi" in r:
        out["score_multi"] = round(r["multi"] / 10)
    return out


def run_suite(parts, threads, disk_dir=None, disk_mb=512, progress=lambda t, f: None,
              stop=None):
    """parts: subconjunto de {'cpu','ram','disk'}. Devolve dict de resultados."""
    stop = stop or threading.Event()
    steps = (2 if "cpu" in parts else 0) + (1 if "cpu" in parts else 0) + \
        (1 if "ram" in parts else 0) + (1 if "disk" in parts else 0)
    steps = max(steps, 1)
    done = [0]
    r = {}

    def step(name):
        progress(name, done[0] / steps)
        done[0] += 1
    if "cpu" in parts:
        step("CPU - 1 núcleo (SHA-256)")
        r["single"] = cpu_single(3, stop)
        step("CPU - ponto flutuante")
        r["float"] = cpu_float(3, stop)
        step(f"CPU - {threads} threads")
        r["multi"] = cpu_multi(threads, 3, stop)
    if "ram" in parts and not stop.is_set():
        step("Memória RAM")
        r["ram_gbs"] = ram_bandwidth(stop=stop)
    if "disk" in parts and disk_dir and not stop.is_set():
        step("Disco")
        w, rd = disk_benchmark(disk_dir, disk_mb, lambda t, f: progress(f"Disco - {t}", (done[0] - 1 + f) / steps))
        r["disk_write"], r["disk_read"] = w, rd
    progress("Concluído", 1.0)
    r.update(scores(r))
    return r


def history():
    try:
        return json.loads(HIST_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []


def save_result(r, label=""):
    h = history()
    h.append(dict(r, date=datetime.datetime.now().strftime("%Y-%m-%d %H:%M"), label=label))
    try:
        HIST_FILE.write_text(json.dumps(h[-100:], indent=1), encoding="utf-8")
    except OSError:
        pass
    return h
