#!/usr/bin/env python3
"""Measure what core/vt_screen.py's VTScreen.feed costs on the output a
terminal gets, and compare two versions of the module side by side.

Both versions are loaded in one process and measured in interleaved
rounds (old, new; then new, old), so a load spike on the host hits both.
A round feeds the whole workload, in the pieces the widget would get, to
a fresh 80 x 24 screen with the default scrollback, and takes the CPU time
(time.thread_time) of each piece. Every round does the same work piece for
piece, so the smallest time of each piece over --rounds rounds is summed:
on a shared host the CPU time of a long run swings several-fold, the best
of each few-millisecond piece much less.

    scripts/bench_vt_screen.py --old /path/to/old/vt_screen.py
    scripts/bench_vt_screen.py --old old.py --rounds 20 yes cat

Workloads: ``yes`` (y\\r\\n floods, 4 KiB reads), ``cat`` (a text file of
~45-character lines), ``cat_long`` (lines longer than the screen),
``ls_color`` (an ``ls --color`` listing: SGR around every name),
``fullscreen`` (a ``top``-like app: alternate screen, cursor positioning,
erase, a scroll region, reverse video, box drawing), ``wide`` (CJK,
combining marks, emoji) and ``mix`` (all of these, in random pieces that
split escape sequences and UTF-8 characters, decoded as the widget does).
"""

from __future__ import annotations

import argparse
import codecs
import importlib.util
import random
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _pieces(data: str, size: int = 4096) -> list[str]:
    return [data[i:i + size] for i in range(0, len(data), size)]


def _random_pieces(data: str, seed: int = 1) -> list[str]:
    """*data* as UTF-8 cut at random byte offsets (1 byte .. 8 KiB) and
    decoded by an incremental decoder, as the widget gets it."""
    rng = random.Random(seed)
    raw = data.encode()
    decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
    out, i = [], 0
    while i < len(raw):
        n = rng.choice((1, 2, 3, 7, 64, 500, 4096, 8192))
        out.append(decoder.decode(raw[i:i + n]))
        i += n
    out.append(decoder.decode(b"", final=True))
    return out


def workloads() -> dict[str, list[str]]:
    """Name -> the pieces fed to the screen."""
    rng = random.Random(7)
    words = ["alpha", "beta", "gamma", "delta", "src", "build", "README.md", "x"]
    cat = "".join(f"{i:08x} " + " ".join(rng.choice(words) for _ in range(6))[:36] + "\n"
                  for i in range(10000)).replace("\n", "\r\n")
    cat_long = "".join(" ".join(rng.choice(words) for _ in range(rng.randint(20, 60))) + "\r\n"
                       for _ in range(2000))
    colours = ["01;34", "01;32", "00", "01;36", "40;31;01", "01;35"]
    ls = "".join("".join(f"\x1b[0m\x1b[{rng.choice(colours)}m{rng.choice(words)}_{i}_{j}"
                         f"\x1b[0m  " for j in range(5)) + "\r\n" for i in range(4000))
    frames = []
    for f in range(150):
        rows = [f"\x1b[{r + 7};1H\x1b[K{1000 + r:6d} user  20   0 {f * r % 9999:7d} "
                f"\x1b[7m{r % 3}.{f % 10}\x1b[0m  S  0:{f:02d}.{r:02d} proc{r}" for r in range(16)]
        frames.append(f"\x1b[H\x1b[2;5r\x1b[5;1H\r\n\x1b[1;1H\x1b[r\x1b[1;1Htop - up {f} min"
                      f"\x1b[K\r\n┌" + "─" * 60 + "┐\x1b[K\x1b[6;1H\x1b[J"
                      + "".join(rows) + "\x1b[24;1H\x1bM\x1b[2;3H")
    fullscreen = "\x1b[?1049h\x1b[?1h\x1b[H\x1b[2J" + "".join(frames) + "\x1b[?1049l\x1b[?1l"
    wide = "".join("你好世界 é café \U0001f600\U0001f680 "
                   f"ＡＢ line {i} über naïve\r\n" for i in range(3000))
    yes = "y\r\n" * 1365 * 30
    mix = "".join([cat[:100000], ls[:60000], fullscreen, wide[:40000], yes[:40000],
                   "\x1b]0;title\x07\x1b[6n\x1b[5n\x1bP+q\x1b\\" * 50, cat_long[:60000]])
    return {
        "yes": _pieces(yes),
        "cat": _pieces(cat),
        "cat_long": _pieces(cat_long),
        "ls_color": _pieces(ls),
        "fullscreen": _pieces(fullscreen),
        "wide": _pieces(wide),
        "mix": _random_pieces(mix),
    }


def _run(module, pieces: list[str]) -> list[float]:
    """CPU milliseconds of each piece fed to a fresh screen."""
    screen = module.VTScreen(80, 24)
    feed, clock, times = screen.feed, time.thread_time, []
    for piece in pieces:
        start = clock()
        feed(piece)
        screen.take_replies()
        times.append((clock() - start) * 1000)
    return times


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("names", nargs="*", help="workloads to measure (default: all)")
    parser.add_argument("--old", type=Path, required=True, help="the vt_screen.py to compare with")
    parser.add_argument("--new", type=Path, default=ROOT / "core" / "vt_screen.py")
    parser.add_argument("--rounds", type=int, default=10)
    args = parser.parse_args(argv)

    versions = {"old": _load(args.old, "bench_vt_screen_old"),
                "new": _load(args.new, "bench_vt_screen_new")}
    loads = workloads()
    names = args.names or list(loads)
    best: dict[tuple[str, str], list[float]] = {}
    for r in range(args.rounds):
        order = ("old", "new") if r % 2 == 0 else ("new", "old")
        for name in names:
            for key in order:
                times = _run(versions[key], loads[name])
                kept = best.setdefault((name, key), times)
                kept[:] = map(min, kept, times)
    for name in names:
        old, new = sum(best[(name, "old")]), sum(best[(name, "new")])
        size = sum(map(len, loads[name])) // 1024
        print(f"{name:11s} {size:5d} KiB  old {old:8.1f}  new {new:8.1f} ms  x{old / new:5.2f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
