"""Pausing an extension: no pane events while paused, one catch-up on resume.

Operator (punch list 34): "extensions sollen pausierbar sein, sodass z.b.
eine bestimtte extension ihren content nicht kontinuierlich neu lädt bei
z.b. directory wechsel". Before, every folder change and selection reached
every loaded extension (ExtensionHost.emit), with no way to hold one back.
"""

from __future__ import annotations

import json
import os
import stat
import sys
import textwrap
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QEvent, QItemSelectionModel  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import extensions as EX  # noqa: E402

APP = QApplication.instance() or QApplication([])

WATCHER = """
from PyQt6.QtWidgets import QLabel

EVENTS = []

def activate(api):
    api.add_dock("Watcher", QLabel("watching"))
    api.on("path_changed", lambda ctx: EVENTS.append(("path", ctx.folder)))
    api.on("selection_changed", lambda ctx: EVENTS.append(("sel", tuple(ctx.paths))))
"""


def pump(seconds: float = 0.05) -> None:
    end = time.time() + seconds
    while time.time() < end:
        APP.processEvents()
        time.sleep(0.01)


def write_ext(name: str, body: str) -> Path:
    folder = EX.extensions_dir()
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"{name}.py"
    path.write_text(
        f'EXTENSION = {{"name": "{name.title()}", "version": "1.0", "description": "test"}}\n\n'
        + textwrap.dedent(body)
    )
    return path


@pytest.fixture(autouse=True)
def own_home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))


def _new_window():
    from ui.main_window import MainWindow

    win = MainWindow()
    win._reconnect_timer.stop()
    win.resize(1000, 700)
    win.show()
    pump()
    return win


def _close(win) -> None:
    win.close()
    win.deleteLater()
    APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    pump()


@pytest.fixture
def window():
    win = _new_window()
    yield win
    _close(win)


@pytest.fixture
def folders(tmp_path):
    out = []
    for name in ("one", "two"):
        folder = tmp_path / name
        folder.mkdir()
        (folder / "a.txt").write_text("a")
        (folder / "b.txt").write_text("b")
        out.append(folder)
    return out


def _load_watcher(window, name: str = "watcher"):
    write_ext(name, WATCHER)
    EX.set_enabled(f"user:{name}", True)
    host = window.extension_host
    host.reload()
    (dock,) = host.docks(f"user:{name}")
    dock.show()
    pump()
    return host, dock, host.module(f"user:{name}")


def _navigate(pane, folder) -> None:
    pane.navigate(str(folder))
    pump()


def _select(pane, *names) -> None:
    proxy = pane._table.model()
    sel = pane._table.selectionModel()
    sel.clearSelection()
    for row in range(proxy.rowCount()):
        if proxy.index(row, 0).data() in names:
            sel.select(
                proxy.index(row, 0),
                QItemSelectionModel.SelectionFlag.Select | QItemSelectionModel.SelectionFlag.Rows,
            )
    pump()


def _pause_action(window, ext_name: str):
    return next(
        a for a in window.extensions_menu.actions()
        if a.isCheckable() and a.property("axPauseExtension") == ext_name
    )


# --- happy -----------------------------------------------------------------


def test_happy_e2e_the_title_bar_button_pauses_path_and_selection_events(window, folders):
    host, dock, module = _load_watcher(window)
    pane = window._active_pane
    _navigate(pane, folders[0])
    assert ("path", str(folders[0])) in module.EVENTS
    bar = dock.titleBarWidget()
    bar._pause_btn.click()
    pump()
    assert host.is_paused("user:watcher")
    assert "Paused" in bar._title_label.text()
    assert bar._pause_btn.isChecked()
    module.EVENTS.clear()
    _navigate(pane, folders[1])
    _select(pane, "a.txt")
    assert module.EVENTS == []


def test_happy_e2e_resume_from_the_menu_delivers_one_catch_up_with_the_current_state(
    window, folders
):
    host, dock, module = _load_watcher(window)
    pane = window._active_pane
    _navigate(pane, folders[0])
    action = _pause_action(window, "user:watcher")
    action.trigger()  # pause
    assert action.isChecked() and host.is_paused("user:watcher")
    _navigate(pane, folders[1])
    _navigate(pane, folders[0])
    _navigate(pane, folders[1])
    _select(pane, "a.txt", "b.txt")
    module.EVENTS.clear()
    action.trigger()  # resume
    pump()
    assert not host.is_paused("user:watcher")
    assert "Paused" not in dock.titleBarWidget()._title_label.text()
    expected_sel = tuple(sorted(str(folders[1] / n) for n in ("a.txt", "b.txt")))
    assert [(k, tuple(sorted(v)) if k == "sel" else v) for k, v in module.EVENTS] == [
        ("path", str(folders[1])),
        ("sel", expected_sel),
    ]
    module.EVENTS.clear()
    _navigate(pane, folders[0])
    assert ("path", str(folders[0])) in module.EVENTS  # live again


def test_happy_the_pause_survives_a_restart(folders):
    first = _new_window()
    try:
        host, _dock, _module = _load_watcher(first)
        host.set_paused("user:watcher", True)
    finally:
        _close(first)
    data = json.loads(EX.settings_file().read_text())
    assert data["paused"] == ["user:watcher"] and data["enabled"] == ["user:watcher"]
    second = _new_window()
    try:
        host = second.extension_host
        host.load_enabled()
        (dock,) = host.docks("user:watcher")
        assert host.is_paused("user:watcher")
        assert "Paused" in dock.titleBarWidget()._title_label.text()
        assert _pause_action(second, "user:watcher").isChecked()
        module = host.module("user:watcher")
        module.EVENTS.clear()
        _navigate(second._active_pane, folders[0])
        assert module.EVENTS == []
    finally:
        _close(second)


def test_happy_another_extension_keeps_its_events(window, folders):
    host, _dock, paused_module = _load_watcher(window, "first")
    write_ext("second", WATCHER)
    EX.set_enabled("user:second", True)
    host.load_enabled()
    live_module = host.module("user:second")
    host.set_paused("user:first", True)
    paused_module.EVENTS.clear()
    live_module.EVENTS.clear()
    _navigate(window._active_pane, folders[0])
    assert paused_module.EVENTS == []
    assert ("path", str(folders[0])) in live_module.EVENTS


# --- sad -------------------------------------------------------------------


def test_sad_resume_without_a_missed_event_sends_nothing(window):
    host, _dock, module = _load_watcher(window)
    host.set_paused("user:watcher", True)
    module.EVENTS.clear()
    host.set_paused("user:watcher", False)
    pump()
    assert module.EVENTS == []


def test_sad_an_extension_that_is_not_loaded_cannot_be_paused(window):
    host = window.extension_host
    assert host.set_paused("user:nothere", True) is False
    assert not host.is_paused("user:nothere")
    assert not EX.settings_file().exists()


def test_sad_an_unwritable_settings_file_still_pauses_for_this_session(
    window, folders, monkeypatch
):
    host, _dock, module = _load_watcher(window)

    def refuse(*_a, **_k):
        raise OSError("read-only file system")

    monkeypatch.setattr(EX, "set_paused", refuse)
    assert host.set_paused("user:watcher", True) is True
    assert host.is_paused("user:watcher")
    assert "not saved" in window.statusBar().currentMessage()
    module.EVENTS.clear()
    _navigate(window._active_pane, folders[0])
    assert module.EVENTS == []


def test_sad_a_failing_handler_in_the_catch_up_is_recorded_not_raised(window, folders):
    write_ext(
        "broken",
        """
        def activate(api):
            api.on("path_changed", lambda ctx: 1 / 0)
        """,
    )
    EX.set_enabled("user:broken", True)
    host = window.extension_host
    host.reload()
    host.set_paused("user:broken", True)
    _navigate(window._active_pane, folders[0])
    assert host.error("user:broken") == ""  # paused: not called
    host.set_paused("user:broken", False)
    assert "ZeroDivisionError" in host.error("user:broken")


def test_sad_a_corrupt_paused_entry_pauses_nothing(tmp_path):
    EX.settings_file().parent.mkdir(parents=True, exist_ok=True)
    EX.settings_file().write_text(json.dumps({"enabled": ["user:x"], "paused": "user:x"}))
    assert EX.paused_ids() == set()
    assert EX.enabled_ids() == {"user:x"}


# --- edge ------------------------------------------------------------------


def test_edge_off_and_on_again_stays_paused(window, folders):
    host, _dock, _module = _load_watcher(window)
    host.set_paused("user:watcher", True)
    host.set_enabled("user:watcher", False)
    host.set_enabled("user:watcher", True)
    assert host.is_paused("user:watcher")
    module = host.module("user:watcher")
    module.EVENTS.clear()
    _navigate(window._active_pane, folders[0])
    assert module.EVENTS == []


def test_edge_an_extension_without_events_or_panels_gets_no_pause_entry(window):
    write_ext(
        "menuonly",
        """
        def activate(api):
            api.add_menu_action("Just A Menu", lambda: None)
        """,
    )
    EX.set_enabled("user:menuonly", True)
    window.extension_host.reload()
    entries = [a for a in window.extensions_menu.actions() if a.property("axPauseExtension")]
    assert entries == []


def test_edge_the_settings_file_stays_private_and_keeps_enabled(window):
    host, _dock, _module = _load_watcher(window)
    host.set_paused("user:watcher", True)
    host.set_paused("user:watcher", False)
    path = EX.settings_file()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    data = json.loads(path.read_text())
    assert data["paused"] == [] and data["enabled"] == ["user:watcher"]


def test_edge_a_paused_extension_misses_pane_activation_too(window, folders):
    write_ext(
        "act",
        """
        EVENTS = []

        def activate(api):
            api.on("pane_activated", lambda ctx: EVENTS.append(ctx.folder))
        """,
    )
    EX.set_enabled("user:act", True)
    host = window.extension_host
    host.reload()
    module = host.module("user:act")
    host.set_paused("user:act", True)
    host.emit("pane_activated", window._active_pane)
    assert module.EVENTS == []
    host.set_paused("user:act", False)
    assert module.EVENTS == [window._active_pane.current_path]


def test_edge_the_catch_up_covers_every_event():
    from ui import extension_host as EH

    assert sorted(EH._CATCH_UP_ORDER) == sorted(EH.EVENTS)
