"""Measure the windows, docks and dialogs a user opens and clicks.

Usage: python scripts/ui_bench.py [--only NAME,...] [--repeat 20]
                                  [--json OUT] [--tree DIR]

The numbers the operator's "komplettes Review, wo wir noch optimieren
koennen" asked for outside the file panes, made repeatable. One main
window, then per scenario

* ``*_cpu_ms``: CPU time the GUI thread spent on the action and the
  events it posted (``time.thread_time``, so other processes' load does
  not count; the minimum of a few runs),
* ``*_gap_max_ms``: the longest the GUI event loop did not run meanwhile
  (a 10 ms QTimer, as scripts/agent_bench.py measures it),
* ``*_leak_widgets`` / ``*_leak_objects``: how many widgets
  (``QApplication.allWidgets()``) and QObjects are alive after
  ``--repeat`` more open/close rounds than after the first rounds -
  anything above 0 grows with every use.

Deleted dialogs only go away when their DeferredDelete events run, and
``processEvents()`` outside an event loop does not run those: every
measurement flushes them with ``sendPostedEvents(None, DeferredDelete)``,
or leaked-looking dialogs would pile up and slow down what follows.

Scenarios: the main window (open, menus, close), Settings (open, open on
each page, find a setting, Apply), switching themes, every Help/View
dialog, the connection dialog, Manage Bookmarks, the MCP catalog, the
editor window (a text file, the hex view of a big file), Properties, the
metadata window, workspaces (new, switch, detach, attach), the Log dock
(a burst of records), the terminal widget (output throughput), the
console and Scripts docks, the Folder Treemap panel with 20,000 entries.

Everything runs in a temporary HOME with Qt offscreen (unless
QT_QPA_PLATFORM is set): no real settings are read or written. ``--tree``
imports axross from another checkout (an old version extracted with
``git archive``) for an A/B; the script checks that the modules really
come from there. Compare minima of alternating runs: the numbers move with
the host's load.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

SCENARIOS = (
    "window", "settings", "theme", "dialogs", "connection", "connections", "bookmarks",
    "mcp_catalog",
    "editor", "hex", "properties", "metadata", "workspaces", "log", "terminal", "console",
    "scripts", "treemap", "menus", "close",
)


def bench(args) -> dict:
    from PyQt6.QtCore import QCoreApplication, QEvent, QEventLoop, QObject, QTimer
    from PyQt6.QtWidgets import QApplication

    from PyQt6.QtCore import qInstallMessageHandler

    qInstallMessageHandler(  # the offscreen platform's notice for every window
        lambda _kind, _ctx, msg: None if "propagateSizeHints" in msg
        else print(msg, file=sys.stderr))
    app = QApplication.instance() or QApplication([])
    import ui.main_window as MW

    if not Path(MW.__file__).resolve().is_relative_to(Path(args.tree).resolve()):
        raise SystemExit(f"ui.main_window came from {MW.__file__}, not from {args.tree}")
    only = set(filter(None, (args.only or "").split(","))) or set(SCENARIOS)
    unknown = only - set(SCENARIOS)
    if unknown:
        raise SystemExit(f"unknown scenario(s): {', '.join(sorted(unknown))}")
    results: dict = {}

    def record(name: str, value: float) -> None:
        results[name] = round(value, 2)
        print(f"{name:40s} {value:10.2f}", flush=True)

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
    wait = QEventLoop.ProcessEventsFlag.AllEvents | QEventLoop.ProcessEventsFlag.WaitForMoreEvents
    deferred = QEvent.Type.DeferredDelete.value

    def flush() -> None:
        for _ in range(3):
            app.processEvents()
            QCoreApplication.sendPostedEvents(None, deferred)

    def settle(seconds: float = 0.03) -> None:
        end = time.perf_counter() + seconds
        while time.perf_counter() < end:
            app.processEvents(wait)
        flush()

    def measure(name: str, action, runs: int = 3, done=None, timeout: float = 120.0) -> list:
        """Run *action* *runs* times; record the minimum GUI CPU and the
        largest loop gap. *done* (optional) is polled until true."""
        cpus, worst, out = [], 0.0, []
        for _ in range(runs):
            settle()
            gaps.clear()
            last[0] = time.perf_counter()
            cpu0 = time.thread_time()
            out.append(action())
            deadline = time.perf_counter() + timeout
            while done is not None and not done():
                if time.perf_counter() > deadline:
                    raise SystemExit(f"{name}: no result after {timeout} s")
                app.processEvents(wait)
            flush()
            cpus.append(time.thread_time() - cpu0)
            probe()
            worst = max(worst, max(gaps))
        record(f"{name}_cpu_ms", min(cpus) * 1000)
        record(f"{name}_gap_max_ms", worst * 1000)
        return out

    def objects() -> int:
        total = 0
        for top in app.topLevelWidgets():
            total += 1 + len(top.findChildren(QObject))
        return total + len(app.findChildren(QObject))

    def leaks(name: str, action) -> None:
        """Widgets and QObjects alive after --repeat more rounds of
        *action* than after the first two."""
        for _ in range(2):
            action()
            flush()
        settle(0.05)
        widgets0, objects0 = len(app.allWidgets()), objects()
        for _ in range(args.repeat):
            action()
            flush()
        settle(0.05)
        record(f"{name}_leak_widgets", len(app.allWidgets()) - widgets0)
        record(f"{name}_leak_objects", objects() - objects0)

    work = Path(tempfile.mkdtemp(prefix="ui-bench-"))
    try:
        (work / "small.txt").write_text("".join(f"line {i} of a text file\n" for i in range(2000)))
        (work / "big.bin").write_bytes(bytes(range(256)) * (30 * 1024 * 4))  # 30 MiB: the open limit is 32
        win = [None]

        def open_window():
            w = MW.MainWindow()
            w.resize(1400, 900)
            w.show()
            win[0] = w

        if "connections" in only:  # 500 saved profiles, read by the window at its start
            config = Path(os.environ["HOME"]) / ".config" / "axross"
            config.mkdir(parents=True, exist_ok=True)
            (config / "profiles.json").write_text(json.dumps({
                f"host{i:03d}": {"name": f"host{i:03d}", "protocol": "sftp",
                                 "host": f"10.0.{i // 250}.{i % 250}", "port": 22,
                                 "username": "user"} for i in range(500)}))
        if "treemap" in only:  # an extension: switched on before the window starts
            from core import extensions as EX

            EX.set_enabled("bundled:folder_treemap", True)
        if "window" in only:
            def open_close():
                open_window()
                flush()
                w = win[0]
                w.close()
                w.deleteLater()
                win[0] = None
            measure("window_open_close", open_close, runs=2)
        open_window()
        settle(0.5)
        w = win[0]

        def dialog_cycle(make, show=True):
            def go():
                d = make()
                if show:
                    d.show()
                    flush()
                d.close()
                d.deleteLater()
            return go

        if "settings" in only:
            from ui.settings_dialog import SettingsDialog

            measure("settings_open", dialog_cycle(lambda: SettingsDialog(w, window=w)))
            leaks("settings", dialog_cycle(lambda: SettingsDialog(w, window=w)))

            def every_page():
                d = SettingsDialog(w, window=w)
                d.show()
                for page_id in d.page_ids():
                    d.show_page(page_id)
                flush()
                d.reject()
                d.deleteLater()
            leaks("settings_every_page", every_page)
            d = SettingsDialog(w, window=w)
            d.show()
            flush()
            for page_id in list(d.page_ids()):
                measure(f"settings_page_{page_id}", lambda p=page_id: d.show_page(p), runs=1)

            def find():
                for text in ("p", "pr", "pro", "prox", "proxy", ""):
                    d.filter_edit.setText(text)
                    app.processEvents()
            measure("settings_find", find)
            measure("settings_apply_unchanged", d.apply)
            d.reject()
            d.deleteLater()
            flush()

        if "theme" in only:
            from ui import themes

            names = [t for t, _ in themes.THEME_CHOICES]
            for name in names + names[:1]:
                measure(f"theme_{name}", lambda n=name: w.set_theme(n, store=False), runs=1)

            def all_themes():
                for name in names:
                    w.set_theme(name, store=False)
                    flush()
            leaks("theme_cycle", all_themes)

        if "dialogs" in only:
            from ui.features_dialog import FeaturesDialog
            from ui.scripting_guide import ScriptingGuideDialog
            from ui.shortcuts_dialog import ShortcutsDialog
            from ui.tag_ui import TaggedFilesDialog
            from ui.third_party_dialog import ThirdPartyDialog

            # The first open of a session: every backend's packages are probed.
            first = []
            measure("dialog_features_first_open",
                    lambda: (first.append(FeaturesDialog(w)), first[-1].show()), runs=1,
                    done=lambda: getattr(first[-1], "loaded", True))
            first[-1].close()
            first[-1].deleteLater()
            for label, make in (
                ("features", lambda: FeaturesDialog(w)),
                ("shortcuts", lambda: ShortcutsDialog(w)),
                ("third_party", lambda: ThirdPartyDialog(w)),
                ("scripting_guide", lambda: ScriptingGuideDialog(w)),
                ("tagged_files", lambda: TaggedFilesDialog(w, go_to=lambda e: None)),
            ):
                measure(f"dialog_{label}", dialog_cycle(make))
                leaks(f"dialog_{label}", dialog_cycle(make))

        if "connection" in only:
            from ui.connection_dialog import ConnectionDialog

            make = lambda: ConnectionDialog(w._profile_manager, parent=w)  # noqa: E731
            measure("connection_dialog", dialog_cycle(make))
            leaks("connection_dialog", dialog_cycle(make))

        if "connections" in only:
            from ui.connection_dialog import ConnectionDialog

            if len(w._profile_manager.list_names()) != 500:
                raise SystemExit(f"{len(w._profile_manager.list_names())} profiles, not 500")
            w._recent_profiles = [f"host{i:03d}" for i in range(8)]

            def quick_menu():
                menu = w._build_quick_connect_menu()
                menu.popup(w.mapToGlobal(w.rect().center()))
                flush()
                menu.hide()
                menu.deleteLater()
            measure("quick_connect_menu_500", quick_menu)
            make = lambda: ConnectionDialog(w._profile_manager, parent=w)  # noqa: E731
            measure("connection_dialog_500", dialog_cycle(make))

        if "bookmarks" in only:
            from core.bookmarks import Bookmark
            from ui.bookmark_manager_dialog import BookmarkManagerDialog

            manager = w._bookmark_manager
            for i in range(300):
                manager.add(Bookmark(name=f"mark {i}", path=f"/srv/{i}"))
            measure("bookmarks_sidebar_rebuild", w._rebuild_bookmarks_menu)
            make = lambda: BookmarkManagerDialog(manager, w)  # noqa: E731
            measure("bookmarks_manager", dialog_cycle(make))
            leaks("bookmarks_manager", dialog_cycle(make))

        if "mcp_catalog" in only:
            from ui.mcp_catalog_dialog import McpCatalogDialog

            make = lambda: McpCatalogDialog(w, search_now=False)  # noqa: E731
            measure("mcp_catalog", dialog_cycle(make))
            leaks("mcp_catalog", dialog_cycle(make))

        if "editor" in only:
            from core.local_fs import LocalFS
            from ui.editor_window import EditorWindow

            fs = LocalFS()

            def editor_cycle():
                e = EditorWindow(w)
                e.open_file(fs, str(work / "small.txt"))
                e.show()
                flush()
                e.close()
                e.deleteLater()
            measure("editor_open_text", editor_cycle)
            leaks("editor_text", editor_cycle)

        if "hex" in only:
            from core.local_fs import LocalFS
            from ui.hex_editor import HexEditorDialog

            opened = []

            def hex_open():
                d = HexEditorDialog(LocalFS(), str(work / "big.bin"), w, read_only=True,
                                    background=True)
                d.show()
                opened.append(d)

            def hex_close():
                d = opened.pop()
                d.close()
                d.deleteLater()

            measure("hex_open_30mib", hex_open, runs=1,
                    done=lambda: opened[-1]._loaded_once)
            gaps.clear()
            last[0] = time.perf_counter()
            cpu0 = time.thread_time()
            opened[-1]._hex_widget.search_bytes(b"\xfe\xff\x00\x01\x02zz")  # not there
            record("hex_search_miss_cpu_ms", (time.thread_time() - cpu0) * 1000)
            d = opened[-1]
            bar = d._scrollbar
            if bar.maximum() > 0:
                def scroll():
                    for value in range(0, bar.maximum(), max(1, bar.maximum() // 50)):
                        bar.setValue(value)
                        d._hex_widget.repaint()
                measure("hex_scroll_50_pages", scroll, runs=1)
            hex_close()

            def hex_cycle():
                hex_open()
                deadline = time.perf_counter() + 60
                while not opened[-1]._loaded_once and time.perf_counter() < deadline:
                    app.processEvents(wait)
                hex_close()
            leaks("hex", hex_cycle)

        if "properties" in only:
            from core.local_fs import LocalFS
            from ui.properties_dialog import PropertiesDialog

            fs = LocalFS()
            item = fs.stat(str(work / "small.txt"))
            make = lambda: PropertiesDialog(fs, str(work / "small.txt"), item, w)  # noqa: E731
            measure("properties", dialog_cycle(make))
            leaks("properties", dialog_cycle(make))

        if "metadata" in only:
            from core.local_fs import LocalFS
            from ui.metadata_dialog import MetadataDialog

            make = lambda: MetadataDialog(LocalFS(), [(str(work / "small.txt"), False)],  # noqa: E731
                                          parent=w)
            measure("metadata", dialog_cycle(make))
            leaks("metadata", dialog_cycle(make))

        if "workspaces" in only:
            def new_drop():
                ws = w.new_workspace()
                flush()
                w.close_workspace(ws, ask=False)
            measure("workspace_new_close", new_drop)
            leaks("workspace_new_close", new_drop)
            ws2 = w.new_workspace()
            first = w.workspaces()[0]
            measure("workspace_switch", lambda: (w.switch_workspace(first),
                                                 w.switch_workspace(ws2)))

            def detach_attach():
                w.detach_workspace(ws2)
                flush()
                w.attach_workspace(ws2)
            measure("workspace_detach_attach", detach_attach)
            leaks("workspace_detach_attach", detach_attach)
            w.close_workspace(ws2, ask=False)

        if "log" in only:
            import logging

            dock = w._log_dock
            dock.show()
            dock.raise_()
            logger = logging.getLogger("ui-bench")
            logger.setLevel(logging.INFO)
            count0 = dock._msg_count

            def burst():
                for i in range(5000):
                    logger.info("a log line number %d with some words in it", i)
            measure("log_burst_5000", burst, runs=2)
            if dock._msg_count - count0 != 10000:
                raise SystemExit(f"log dock took {dock._msg_count - count0} of 10000 records")

        if "terminal" in only:
            from ui.terminal_widget import TerminalEmulator

            term = TerminalEmulator()
            term.resize(900, 600)
            term.show()
            flush()
            chunk = b"y\r\n" * 1365  # one 4 KiB read of `yes`

            def feed_yes():
                for _ in range(100):  # 400 KiB: `yes | head -133000`
                    term.feed_bytes(chunk)
            measure("terminal_feed_400kib", feed_yes, runs=2)
            text = b"".join(f"{i:08d} some text of a big file being cat\r\n".encode()
                            for i in range(10000))

            def feed_cat():
                for i in range(0, len(text), 4096):
                    term.feed_bytes(text[i:i + 4096])
            measure("terminal_feed_cat_450kib", feed_cat, runs=2)
            term.close()
            term.deleteLater()
            if os.name == "posix":
                from ui.terminal_pane import TerminalPaneWidget

                pane = TerminalPaneWidget(cwd=str(work))
                pane.resize(900, 600)
                pane.show()
                flush()
                pane._start_session() if not pane.is_running else None
                settle(0.5)
                doc = pane._terminal.document()

                def shown(marker: str) -> bool:
                    block = doc.lastBlock()
                    for _ in range(pane._terminal.screen.rows + 2):
                        if block.text().strip() == marker:
                            return True
                        block = block.previous()
                        if not block.isValid():
                            break
                    return False

                # The marker is computed by the shell: the echoed command
                # line does not contain it.
                for name, command, marker in (
                    ("terminal_pty_yes_200000", "yes | head -200000", "UIBENCH2DONE"),
                    ("terminal_pty_cat", f"cat {work / 'cat.txt'}", "UIBENCH3DONE"),
                ):
                    if name.endswith("_cat"):
                        line_count = int(args.terminal_mb * 1024 * 1024 / 56)
                        (work / "cat.txt").write_text("".join(
                            f"{i:08d} some text of a big file being shown by cat\n"
                            for i in range(line_count)))
                    n = marker[7]
                    gaps.clear()
                    last[0] = time.perf_counter()
                    cpu0 = time.thread_time()
                    t0 = time.perf_counter()
                    pane._session.write(f"{command}; echo UIBENCH$((1+{int(n) - 1}))DONE\n".encode())
                    deadline = t0 + 600
                    while not shown(marker):
                        if time.perf_counter() > deadline:
                            raise SystemExit(f"{name}: no result after 600 s")
                        app.processEvents(wait)
                    probe()
                    record(f"{name}_wall_ms", (time.perf_counter() - t0) * 1000)
                    record(f"{name}_cpu_ms", (time.thread_time() - cpu0) * 1000)
                    record(f"{name}_gap_max_ms", max(gaps) * 1000)
                gaps.clear()
                last[0] = time.perf_counter()
                cpu0 = time.thread_time()
                settle(1.0)
                probe()
                record("terminal_idle_1s_cpu_ms", (time.thread_time() - cpu0) * 1000)
                record("terminal_idle_gap_max_ms", max(gaps) * 1000)
                pane.shutdown()
                pane.close()
                pane.deleteLater()
                flush()

        if "console" in only:
            dock = w._console_dock
            measure("console_show", lambda: (dock.show(), dock.raise_()), runs=1)
            repl = dock.repl
            measure("console_print_2000",
                    lambda: repl._run_source("for i in range(2000): print(i)\n", filename="b"))
            repl._append("".join(f"{i:08d} earlier output of the console\n"
                                 for i in range(90000)))  # ~3.5 MB, under the 4 MiB cap
            repl._write_prompt(">>> ")

            def enter():
                repl.insertPlainText("x = 1")
                repl._submit_current()
            measure("console_enter_3mb_buffer", enter)

        if "scripts" in only:
            dock = w._scripts_dock
            measure("scripts_show", lambda: (dock.show(), dock.raise_()), runs=1)

        if "menus" in only:
            menus = [a.menu() for a in w.menuBar().actions() if a.menu() is not None]

            def open_menus():
                for m in menus:
                    m.aboutToShow.emit()
                    m.popup(w.mapToGlobal(w.rect().center()))
                    flush()
                    m.hide()
            measure("menus_open_all", open_menus)

        if "treemap" in only:
            import random

            docks = w.extension_host.docks("bundled:folder_treemap")
            if not docks:
                raise SystemExit("the Folder Treemap extension did not load")
            dock = docks[0]
            dock.setFloating(True)  # visible whatever other panels share its area
            dock.resize(900, 600)
            dock.show()
            dock.raise_()
            view = dock.widget()
            flush()
            if not view.isVisible():
                raise SystemExit("the Folder Treemap panel is not visible")
            rnd = random.Random(1)
            entries = [(f"file{i}", rnd.randint(1, 10**7), i % 20 == 0) for i in range(20000)]

            def first_paint():
                view.set_entries(list(entries), True)
                view.repaint()
            measure("treemap_20000_first_paint", first_paint, runs=2)
            measure("treemap_20000_repaint", view.repaint, runs=3)

        if "close" in only:
            def close():
                w.close()
                w.deleteLater()
            measure("window_close", close, runs=1)
            win[0] = None
        import resource

        record("peak_rss_mb", resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return results


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--only", help="comma-separated scenarios: " + ", ".join(SCENARIOS))
    parser.add_argument("--repeat", type=int, default=20, help="open/close rounds of a leak check")
    parser.add_argument("--terminal-mb", type=float, default=4.0,
                        help="size of the file the terminal scenario shows with cat")
    parser.add_argument("--json", help="write the results to this file as well")
    parser.add_argument("--tree", default=str(ROOT), help="the axross checkout to measure")
    args = parser.parse_args(argv)
    home = tempfile.mkdtemp(prefix="ui-bench-home-")
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
