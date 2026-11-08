#!/usr/bin/env python3
"""Measure what each media player visualization costs a frame, and compare
two versions of resources/extensions/media_player.py side by side.

Both versions are loaded in one process and measured in interleaved
rounds (old, new; then new, old), so a load spike on the host hits both:
per face the smallest median of --rounds rounds of --frames frames counts.
A frame is tick() + render() of the face into an image of --size, with
--bars bars, fed white noise (the dearest input: the scopes cross their
traces over themselves, every bar moves).

    scripts/bench_visualizer.py --old /path/to/old/media_player.py
    scripts/bench_visualizer.py --old old.py --size 480x200 --bars 32 spectrum line
    scripts/bench_visualizer.py --old old.py --load spin

--load spin runs two Python threads in a busy loop meanwhile (the GIL load
of transfers at their worst) and measures wall time; otherwise the GUI
thread's CPU time (time.thread_time) is measured, which another process's
load disturbs least.
"""

from __future__ import annotations

import argparse
import importlib.util
import os
import statistics
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

RATE = 44100


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _noise(np, frames: int = 2048, seed: int = 3):
    rng = np.random.default_rng(seed)
    return (rng.standard_normal((frames, 2)) * 0.3).astype(np.float32)


def _engine(np, MP):
    """The engine interface the visualizer reads: noise as samples, its
    bars varied each frame (as music would), worked out once."""
    from PyQt6.QtCore import QObject, pyqtSignal

    samples = _noise(np)
    bars = MP.spectrum_bars(samples, RATE, 128)
    rng = np.random.default_rng(5)

    class Engine(QObject):
        changed = pyqtSignal()
        finished_playing = pyqtSignal()
        failed = pyqtSignal(str)
        state = "playing"

        def current_bars(self, n=32):
            return np.clip(bars[:n] * rng.uniform(0.3, 1.0, n), 0.0, 1.0)

        def current_samples(self):
            return samples

    return Engine()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("faces", nargs="*", help="faces to measure (default: all)")
    parser.add_argument("--old", type=Path, required=True,
                        help="the media_player.py to compare with")
    parser.add_argument("--new", type=Path,
                        default=ROOT / "resources" / "extensions" / "media_player.py")
    parser.add_argument("--size", default="1920x1080")
    parser.add_argument("--bars", type=int, default=128)
    parser.add_argument("--rounds", type=int, default=12)
    parser.add_argument("--frames", type=int, default=8)
    parser.add_argument("--load", choices=("none", "spin"), default="none")
    args = parser.parse_args(argv)

    import numpy as np
    from PyQt6.QtGui import QImage
    from PyQt6.QtWidgets import QApplication

    app = QApplication.instance() or QApplication([])  # noqa: F841 - Qt needs it
    width, height = (int(v) for v in args.size.lower().split("x"))
    versions = {"old": _load(args.old, "bench_visualizer_old"),
                "new": _load(args.new, "bench_visualizer_new")}
    faces = args.faces or list(versions["new"].Visualizer.MODES)
    widgets = {}
    for key, MP in versions.items():
        vis = MP.Visualizer(_engine(np, MP))
        vis.resize(width, height)
        vis.set_option("bars", args.bars)
        widgets[key] = vis
    image = QImage(width, height, QImage.Format.Format_ARGB32_Premultiplied)

    clock = time.thread_time
    stop = threading.Event()
    if args.load == "spin":
        clock = time.perf_counter

        def busy() -> None:
            count = 0
            while not stop.is_set():
                count += 1

        for _ in range(2):
            threading.Thread(target=busy, daemon=True).start()

    best = {(face, key): float("inf") for face in faces for key in widgets}
    try:
        for r in range(args.rounds):
            order = ("old", "new") if r % 2 == 0 else ("new", "old")
            for face in faces:
                for key in order:
                    vis = widgets[key]
                    if face not in vis.MODES:
                        continue
                    vis.set_mode(face, announce=False)
                    vis._label_until = 0.0
                    for _ in range(3):
                        vis.tick()
                        vis.render(image)
                    times = []
                    for _ in range(args.frames):
                        start = clock()
                        vis.tick()
                        vis.render(image)
                        times.append((clock() - start) * 1000)
                    best[(face, key)] = min(best[(face, key)], statistics.median(times))
    finally:
        stop.set()
    total_old = total_new = 0.0
    for face in faces:
        old, new = best[(face, "old")], best[(face, "new")]
        if old == float("inf") or new == float("inf"):
            print(f"{face:13s} only in one version")
            continue
        total_old += old
        total_new += new
        print(f"{face:13s} old {old:7.2f}  new {new:7.2f} ms  {_change(old, new)}")
    print(f"{'all':13s} old {total_old:7.2f}  new {total_new:7.2f} ms  "
          f"{_change(total_old, total_new)}")
    return 0


def _change(old: float, new: float) -> str:
    """The change from *old* to *new* in percent; "n/a" when *old* is 0
    (a frame faster than the clock's resolution - a coarse clock, few frames)."""
    if old <= 0:
        return "   n/a"
    return f"{100 * (new - old) / old:+6.1f} %"


if __name__ == "__main__":
    sys.exit(main())
