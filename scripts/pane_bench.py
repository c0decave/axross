"""Measure the file panes and the work around them on large folders.

Usage: python scripts/pane_bench.py [--entries 20000] [--transfer-files 2000]
                                    [--transfer-mb 128] [--search-files 30000]
                                    [--only NAME,...] [--json OUT] [--tree DIR]

The numbers the operator's "make axross massively faster" asked for in the
file pane area, made repeatable. A folder of ``--entries`` files (every
20th a folder, every 10th a dot name) on LocalFS and on RamFS, then per
scenario

* ``*_wall_ms``: from the action to its result (a listing shown, a search
  done, every transfer finished),
* ``*_gui_cpu_ms``: CPU time the GUI thread spent meanwhile
  (``time.thread_time``, so other processes' load does not count),
* ``*_gap_max_ms``: the longest the GUI event loop did not run (a 10 ms
  QTimer, as scripts/agent_bench.py measures it) - what a user feels as a
  freeze.

Scenarios: opening the folder (LocalFS, RamFS and RamFS behind a slow
listing), refreshing it with a selection, back and forward, sorting by
every column, typing into the filter field, select all / invert, resizing
(the column fit), showing hidden files and their highlight, the thumbnail
view, six idle seconds on the big folder (``idle_process_cpu_ms_per_s``:
the CPU of every thread, the auto-refresh watcher's polls included), copying many small files and one big file through the transfer queue
with its dock, and Find Files over a local tree.

Everything runs in a temporary HOME with Qt offscreen (unless
QT_QPA_PLATFORM is set): no real settings are read or written. ``--tree``
imports axross from another checkout (an old version extracted with
``git archive``) for an A/B; the script checks that the modules really
come from there. Compare minima of alternating runs: the numbers move with
the host's load.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

SCENARIOS = (
    "open_local", "refresh_local", "back_forward", "sort", "filter", "select",
    "resize", "hidden", "thumbnails", "idle", "open_ramfs", "open_slow", "transfer_many",
    "transfer_big", "search",
)


def make_folder(root: Path, entries: int) -> Path:
    """*entries* names in *root*/big: every 20th a folder, every 10th a dot
    name, sizes and times spread so that every sort column has work."""
    big = root / "big"
    big.mkdir()
    now = time.time()
    for i in range(entries):
        name = f"{'.' if i % 10 == 3 else ''}entry_{(i * 7919) % entries:06d}.dat"
        path = big / name
        if i % 20 == 0:
            path.mkdir()
        else:
            path.write_bytes(b"x" * (i % 97))
        os.utime(path, (now - i * 13, now - i * 13))
    return big


def bench(args) -> dict:
    from PyQt6.QtCore import QEventLoop, Qt, QTimer
    from PyQt6.QtTest import QTest
    from PyQt6.QtWidgets import QApplication

    app = QApplication.instance() or QApplication([])
    import ui.file_pane as FPM

    if not Path(FPM.__file__).resolve().is_relative_to(Path(args.tree).resolve()):
        raise SystemExit(f"ui.file_pane came from {FPM.__file__}, not from {args.tree}")
    from core.local_fs import LocalFS
    from core.ram_fs import RamFsSession

    only = set(filter(None, (args.only or "").split(","))) or set(SCENARIOS)
    unknown = only - set(SCENARIOS)
    if unknown:
        raise SystemExit(f"unknown scenario(s): {', '.join(sorted(unknown))}")
    results: dict = {}

    def record(name: str, value: float) -> None:
        results[name] = round(value, 2)
        print(f"{name:34s} {value:10.2f}", flush=True)

    gaps: list[float] = []
    last = [time.perf_counter()]

    def probe() -> None:
        now = time.perf_counter()
        gaps.append(now - last[0])
        last[0] = now

    timer = QTimer()
    timer.setInterval(10)
    timer.timeout.connect(probe)
    timer.start()
    flags = QEventLoop.ProcessEventsFlag
    wait_flags = flags.AllEvents | flags.WaitForMoreEvents

    def settle(seconds: float = 0.05) -> None:
        end = time.perf_counter() + seconds
        while time.perf_counter() < end:
            app.processEvents(wait_flags)  # the 10 ms probe wakes it

    def measure(name: str, action, done=lambda: True, timeout: float = 600.0,
                settle_s: float = 0.05) -> None:
        """Run *action*, wait until *done()*, let deferred work (fits,
        paints) run for *settle_s*; record wall, GUI CPU and max gap."""
        settle(0.02)
        gaps.clear()
        last[0] = time.perf_counter()
        cpu0 = time.thread_time()
        t0 = time.perf_counter()
        action()
        deadline = t0 + timeout
        while not done():
            if time.perf_counter() > deadline:
                raise SystemExit(f"{name}: no result after {timeout} s")
            app.processEvents(wait_flags)
        wall = time.perf_counter() - t0
        settle(settle_s)
        probe()
        record(f"{name}_wall_ms", wall * 1000)
        record(f"{name}_gui_cpu_ms", (time.thread_time() - cpu0) * 1000)
        record(f"{name}_gap_max_ms", max(gaps) * 1000)

    work = Path(tempfile.mkdtemp(prefix="pane-bench-"))
    panes = []
    try:
        big = make_folder(work, args.entries)
        small = work / "small"
        small.mkdir()
        (small / "one.txt").write_text("one")

        def new_pane(backend, start: str):
            from unittest import mock

            with mock.patch.object(backend, "home", lambda: start):
                pane = FPM.FilePaneWidget(backend)
            pane.resize(1000, 700)
            pane.show()
            panes.append(pane)
            settle(0.1)
            return pane

        def load(pane, path: str, name: str, history="push") -> None:
            state = {}
            pane.navigation_finished.connect(lambda p, ok: state.setdefault("done", ok))
            measure(name, lambda: pane.navigate_async(path, history=history),
                    lambda: "done" in state)
            pane.navigation_finished.disconnect()
            if not state["done"]:
                raise SystemExit(f"{name}: loading {path} failed")

        pane = new_pane(LocalFS(), str(small))
        need_big = only & {"open_local", "refresh_local", "back_forward", "sort", "filter",
                           "select", "resize", "hidden", "thumbnails", "idle"}
        if need_big:
            load(pane, str(big), "open_local")
            if pane._proxy.rowCount() < 2:
                raise SystemExit("open_local: the folder did not show")
        if "refresh_local" in only:
            from PyQt6.QtCore import QItemSelectionModel

            sel = pane._table.selectionModel()
            for r in range(1, 200, 2):
                sel.select(pane._proxy.index(r, 0), QItemSelectionModel.SelectionFlag.Select
                           | QItemSelectionModel.SelectionFlag.Rows)
            load(pane, str(big), "refresh_local", history="keep")
        if "back_forward" in only:
            load(pane, str(small), "nav_small")
            state = {}
            pane.navigation_finished.connect(lambda p, ok: state.setdefault("n", []).append(p))
            measure("back", pane._go_back, lambda: len(state.get("n", ())) >= 1)
            measure("forward", pane._go_forward, lambda: len(state.get("n", ())) >= 2)
            pane.navigation_finished.disconnect()
            load(pane, str(big), "nav_big_again")
        if "sort" in only:
            header = pane._table.horizontalHeader()
            for col, label in enumerate(("name", "size", "modified", "perms", "owner")):
                for order in (Qt.SortOrder.DescendingOrder, Qt.SortOrder.AscendingOrder):
                    tag = "desc" if order == Qt.SortOrder.DescendingOrder else "asc"
                    measure(f"sort_{label}_{tag}",
                            lambda c=col, o=order: header.setSortIndicator(c, o))
            header.setSortIndicator(0, Qt.SortOrder.AscendingOrder)
            settle()
        if "filter" in only:
            edit = pane._filter_edit
            edit.setFocus()
            per_key = []
            for ch in "entry_00123":
                measure("filter_key", lambda c=ch: QTest.keyClicks(edit, c))
                per_key.append((results["filter_key_wall_ms"], results["filter_key_gui_cpu_ms"],
                                results["filter_key_gap_max_ms"]))
            shown = pane._proxy.rowCount()
            for _ in range(len("entry_00123")):
                measure("filter_key", lambda: QTest.keyClick(edit, Qt.Key.Key_Backspace))
                per_key.append((results["filter_key_wall_ms"], results["filter_key_gui_cpu_ms"],
                                results["filter_key_gap_max_ms"]))
            for key in ("filter_key_wall_ms", "filter_key_gui_cpu_ms", "filter_key_gap_max_ms"):
                results.pop(key)
            record("filter_typed_rows_shown", shown)
            record("filter_key_gui_cpu_max_ms", max(k[1] for k in per_key))
            record("filter_key_gui_cpu_total_ms", sum(k[1] for k in per_key))
            record("filter_key_gap_max_ms", max(k[2] for k in per_key))
        if "select" in only:
            measure("select_all", pane._select_all)
            measure("selected_entries", lambda: results.__setitem__(
                "_sel", len(pane._selected_entries())))
            record("selected_count", results.pop("_sel"))
            measure("invert", pane._invert_selection)
            pane._table.clearSelection()
            settle()
        if "resize" in only:
            widths = [700, 1300, 900, 1100, 800, 1200]
            measure("resize", lambda: [pane.resize(w, 700) or app.processEvents()
                                      for w in widths])
            pane.resize(1000, 700)
            settle()
        if "hidden" in only:
            measure("show_hidden_on", lambda: pane.set_show_hidden(True))
            measure("hidden_colour", lambda: pane.set_hidden_style(True, "#aa3311"))
            measure("show_hidden_off", lambda: pane.set_show_hidden(False))
            pane.set_hidden_style(True, None)
            settle()
        if "thumbnails" in only:
            measure("thumbnails_on", lambda: pane.set_view_mode("thumbnails"), settle_s=0.3)
            measure("thumbnails_off", lambda: pane.set_view_mode("details"))

        if "idle" in only:
            # The pane just shows the big folder (its auto-refresh watcher
            # runs): CPU of the whole process, not only the GUI thread.
            import resource

            seconds = 6.0
            usage = resource.getrusage(resource.RUSAGE_SELF)
            before = usage.ru_utime + usage.ru_stime
            measure("idle", lambda: None, settle_s=seconds)
            usage = resource.getrusage(resource.RUSAGE_SELF)
            record("idle_process_cpu_ms_per_s",
                   (usage.ru_utime + usage.ru_stime - before) * 1000 / seconds)
            for key in ("idle_wall_ms", "idle_gui_cpu_ms"):
                results.pop(key)

        if only & {"open_ramfs", "open_slow"}:
            ram = RamFsSession(max_bytes=1 << 30)
            ram.mkdir("/big")
            ram.mkdir("/small")
            for i in range(args.entries):
                name = f"{'.' if i % 10 == 3 else ''}entry_{(i * 7919) % args.entries:06d}.dat"
                if i % 20 == 0:
                    ram.mkdir(f"/big/{name}")
                else:
                    with ram.open_write(f"/big/{name}") as fh:
                        fh.write(b"x" * (i % 97))
            if "open_ramfs" in only:
                rpane = new_pane(ram, "/small")
                load(rpane, "/big", "open_ramfs")
            if "open_slow" in only:
                class Slow:
                    """RamFS whose listing takes 0.5 s, like a far server."""

                    def __init__(self, inner) -> None:
                        self._inner = inner

                    def __getattr__(self, name):
                        return getattr(self._inner, name)

                    def list_dir(self, path):
                        time.sleep(0.5)
                        return self._inner.list_dir(path)

                spane = new_pane(Slow(ram), "/small")
                load(spane, "/big", "open_slow")

        if only & {"transfer_many", "transfer_big"}:
            from core.transfer_manager import TransferManager
            from core.transfer_worker import TransferDirection
            from ui.transfer_dock import TransferDock

            manager = TransferManager()
            dock = TransferDock(manager)
            dock.resize(1000, 300)
            dock.show()
            local = LocalFS()

            def copy(name: str, sources: list[str], dest: Path) -> None:
                dest.mkdir()
                state = {}
                manager.all_finished.connect(lambda: state.setdefault("done", True))
                measure(name, lambda: manager.transfer_files_in_background(
                    local, local, sources, str(dest), TransferDirection.UPLOAD),
                    lambda: "done" in state)
                manager.all_finished.disconnect()

            if "transfer_many" in only:
                src = work / "many"
                src.mkdir()
                for i in range(args.transfer_files):
                    (src / f"f{i:05d}.bin").write_bytes(bytes([i % 251]) * 4096)
                copy("transfer_many", [str(src)], work / "many_out")
                out = work / "many_out" / "many"
                got = sorted(p.name for p in out.iterdir()) if out.is_dir() else []
                same = got == sorted(p.name for p in src.iterdir()) and all(
                    (out / n).read_bytes() == (src / n).read_bytes() for n in got)
                record("transfer_many_files_ok", 1 if same else 0)
                manager.clear_finished()
                dock._clear_finished()
            if "transfer_big" in only:
                blob = work / "blob.bin"
                block = os.urandom(1 << 20)
                with blob.open("wb") as fh:
                    for _ in range(args.transfer_mb):
                        fh.write(block)
                copy("transfer_big", [str(blob)], work / "big_out")
                copied = work / "big_out" / "blob.bin"
                digest = (hashlib.sha256(copied.read_bytes()).digest()
                          if copied.exists() else b"")
                record("transfer_big_bytes_ok",
                       1 if digest == hashlib.sha256(blob.read_bytes()).digest() else 0)
                record("transfer_big_mb_per_s",
                       args.transfer_mb / max(1e-9, results["transfer_big_wall_ms"] / 1000))
            dock.close()
            manager.shutdown()

        if "search" in only:
            from ui import find_files_dialog as FFD

            tree = work / "tree"
            for d in range(args.search_files // 100):
                sub = tree / f"d{d // 10:03d}" / f"s{d:04d}"
                sub.mkdir(parents=True)
                for i in range(100):
                    suffix = ".log" if i % 4 == 0 else ".dat"
                    (sub / f"n{i:03d}{suffix}").write_bytes(b"y" * i)
            dialog = FFD.FindFilesDialog([FFD.ScopeChoice(LocalFS(), str(tree))])
            dialog.show()
            dialog.name_edit.setText("*.log")
            settle(0.1)
            measure("search", dialog.start_search, lambda: not dialog.is_running,
                    settle_s=0.3)
            record("search_rows", dialog.table.rowCount())
            dialog._stop_all()
            dialog.close()
        import resource

        record("peak_rss_mb", resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024)
    finally:
        timer.stop()
        for pane in panes:
            pane.shutdown()
            pane.close()
        shutil.rmtree(work, ignore_errors=True)
    return results


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--entries", type=int, default=20000, help="entries in the big folder")
    parser.add_argument("--transfer-files", type=int, default=2000,
                        help="small files copied through the transfer queue")
    parser.add_argument("--transfer-mb", type=int, default=128, help="size of the big file")
    parser.add_argument("--search-files", type=int, default=30000,
                        help="files in the tree Find Files searches")
    parser.add_argument("--only", help="comma-separated scenarios: " + ", ".join(SCENARIOS))
    parser.add_argument("--json", help="write the results to this file as well")
    parser.add_argument("--tree", default=str(ROOT), help="the axross checkout to measure")
    args = parser.parse_args(argv)
    home = tempfile.mkdtemp(prefix="pane-bench-home-")
    os.environ.update({
        "HOME": home, "XDG_CONFIG_HOME": f"{home}/.config", "XDG_DATA_HOME": f"{home}/.local",
        "XDG_CACHE_HOME": f"{home}/.cache", "XDG_STATE_HOME": f"{home}/.state",
        "PYTHON_KEYRING_BACKEND": "keyring.backends.null.Keyring",
    })
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    sys.path.insert(0, str(Path(args.tree).resolve()))
    try:
        results = bench(args)
    finally:
        shutil.rmtree(home, ignore_errors=True)
    if args.json:
        Path(args.json).write_text(json.dumps(results, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
