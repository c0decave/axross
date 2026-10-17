"""Loading extensions into the window: the Extensions menu, context actions
in the pane, panels, events - and that a broken extension never takes the
window down."""

from __future__ import annotations

import os
import sys
import textwrap
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import extensions as EX  # noqa: E402

APP = QApplication.instance() or QApplication([])


def pump(seconds: float = 0.05) -> None:
    end = time.time() + seconds
    while time.time() < end:
        APP.processEvents()
        time.sleep(0.01)


def wait_until(cond, timeout: float = 5.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        APP.processEvents()
        if cond():
            return True
        time.sleep(0.01)
    return cond()


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
    # Each test its own extension folder and on/off state.
    monkeypatch.setenv("HOME", str(tmp_path / "home"))


@pytest.fixture
def window(tmp_path):
    from ui.main_window import MainWindow

    win = MainWindow()
    win._reconnect_timer.stop()
    win.resize(1000, 700)
    win.show()
    pump()
    yield win
    win.close()
    win.deleteLater()
    pump()


def _menu_texts(win) -> list[str]:
    return [a.text() for a in win.extensions_menu.actions()]


# --- happy -----------------------------------------------------------------


def test_happy_the_extensions_menu_has_its_fixed_entries(window) -> None:
    texts = _menu_texts(window)
    assert texts[:3] == ["&Manage Extensions…", "&Open Extensions Folder", "&Reload Extensions"]
    menubar = [a.text() for a in window.menuBar().actions()]
    assert menubar.index("E&xtensions") == menubar.index("&Help") - 1


def test_happy_an_enabled_extension_adds_a_menu_action(window) -> None:
    write_ext(
        "hello",
        """
        HITS = []

        def activate(api):
            api.add_menu_action("Say Hello", lambda: HITS.append("hi"))
        """,
    )
    EX.set_enabled("user:hello", True)
    host = window.extension_host
    host.reload()
    action = next(a for a in window.extensions_menu.actions() if a.text() == "Say Hello")
    action.trigger()
    assert host.module("user:hello").HITS == ["hi"]
    assert host.error("user:hello") == ""


def test_happy_a_context_action_gets_the_selection(window, tmp_path) -> None:
    write_ext(
        "ctx",
        """
        SEEN = []

        def activate(api):
            api.add_context_action(
                "Count Files", lambda ctx: SEEN.append(list(ctx.paths)), applies_to="files"
            )
            api.add_context_action("Folder Only", lambda ctx: SEEN.append(ctx.folder),
                                   applies_to="folder")
        """,
    )
    EX.set_enabled("user:ctx", True)
    window.extension_host.reload()
    folder = tmp_path / "data"
    folder.mkdir()
    (folder / "a.txt").write_text("a")
    pane = window._active_pane
    pane.navigate(str(folder))
    pane._table.selectAll()
    labels = [a.text() for a in pane._build_context_menu().actions()]
    assert "Count Files" in labels and "Folder Only" not in labels
    next(a for a in pane._build_context_menu().actions() if a.text() == "Count Files").trigger()
    assert window.extension_host.module("user:ctx").SEEN == [[str(folder / "a.txt")]]
    pane._table.clearSelection()
    labels = [a.text() for a in pane._build_context_menu().actions()]
    assert "Count Files" not in labels and "Folder Only" in labels


def test_happy_a_dock_and_an_event(window, tmp_path) -> None:
    write_ext(
        "watcher",
        """
        from PyQt6.QtWidgets import QLabel

        EVENTS = []

        def activate(api):
            api.add_dock("Watcher", QLabel("watching"))
            api.on("path_changed", lambda ctx: EVENTS.append(ctx.folder))
        """,
    )
    EX.set_enabled("user:watcher", True)
    host = window.extension_host
    host.reload()
    docks = [d for d in host.docks("user:watcher")]
    assert len(docks) == 1 and docks[0].windowTitle() == "Watcher"
    window._active_pane.navigate(str(tmp_path))
    assert wait_until(lambda: str(tmp_path) in host.module("user:watcher").EVENTS)


def test_happy_run_in_background_answers_on_the_gui_thread(window) -> None:
    write_ext(
        "bg",
        """
        import threading

        RESULT = []

        def activate(api):
            main = threading.get_ident()
            api.run_in_background(
                lambda: threading.get_ident(),
                on_done=lambda worker: RESULT.append(
                    (worker != main, threading.get_ident() == main)
                ),
            )
        """,
    )
    EX.set_enabled("user:bg", True)
    window.extension_host.reload()
    assert wait_until(lambda: window.extension_host.module("user:bg").RESULT)
    assert window.extension_host.module("user:bg").RESULT == [(True, True)]


def test_happy_switching_off_removes_everything(window) -> None:
    write_ext(
        "temp",
        """
        from PyQt6.QtWidgets import QLabel

        def activate(api):
            api.add_menu_action("Temp Action", lambda: None)
            api.add_dock("Temp Dock", QLabel("x"))
        """,
    )
    EX.set_enabled("user:temp", True)
    host = window.extension_host
    host.reload()
    assert "Temp Action" in _menu_texts(window)
    host.set_enabled("user:temp", False)
    assert "Temp Action" not in _menu_texts(window)
    assert host.docks("user:temp") == []
    assert "user:temp" not in EX.enabled_ids()
    assert host.module("user:temp") is None


# --- sad -------------------------------------------------------------------


def test_sad_a_failing_activate_leaves_nothing_behind(window) -> None:
    write_ext(
        "broken",
        """
        def activate(api):
            api.add_menu_action("Half Done", lambda: None)
            raise RuntimeError("boom in activate")
        """,
    )
    EX.set_enabled("user:broken", True)
    host = window.extension_host
    host.reload()
    assert "boom in activate" in host.error("user:broken")
    assert "Half Done" not in _menu_texts(window)


def test_sad_a_failing_callback_is_reported_not_raised(window) -> None:
    write_ext(
        "flaky",
        """
        def activate(api):
            api.add_menu_action("Explode", lambda: 1 / 0)
        """,
    )
    EX.set_enabled("user:flaky", True)
    window.extension_host.reload()
    next(a for a in window.extensions_menu.actions() if a.text() == "Explode").trigger()
    assert "ZeroDivisionError" in window.statusBar().currentMessage()
    assert "division by zero" in window.extension_host.error("user:flaky")


def test_sad_a_disabled_extension_never_runs(window) -> None:
    path = write_ext(
        "quiet",
        """
        import pathlib
        pathlib.Path(__file__).with_name("QUIET_RAN").write_text("x")

        def activate(api):
            pass
        """,
    )
    window.extension_host.reload()
    assert not path.with_name("QUIET_RAN").exists()


def test_sad_paranoid_mode_loads_nothing(window, monkeypatch) -> None:
    from core import security_mode

    write_ext(
        "hello2", "def activate(api):\n    api.add_menu_action('Paranoid Hello', lambda: None)\n"
    )
    EX.set_enabled("user:hello2", True)
    monkeypatch.setattr(security_mode, "_CURRENT", security_mode.PARANOID)
    window.extension_host.reload()
    assert "Paranoid Hello" not in _menu_texts(window)
    assert "paranoid" in window.extension_host.error("user:hello2")


def test_sad_an_unknown_event_or_applies_to_is_an_error(window) -> None:
    write_ext(
        "typo",
        """
        def activate(api):
            api.on("selection_changd", lambda ctx: None)
        """,
    )
    EX.set_enabled("user:typo", True)
    window.extension_host.reload()
    assert "selection_changd" in window.extension_host.error("user:typo")


# --- edge ------------------------------------------------------------------


def test_edge_reload_picks_up_a_changed_source(window) -> None:
    # Same length on purpose: a byte code cache keyed on mtime and size
    # within the same second would hand back the old version.
    write_ext("ver", "def activate(api):\n    api.add_menu_action('Version One', lambda: None)\n")
    EX.set_enabled("user:ver", True)
    host = window.extension_host
    host.reload()
    write_ext("ver", "def activate(api):\n    api.add_menu_action('Version Two', lambda: None)\n")
    host.reload()
    texts = _menu_texts(window)
    assert "Version Two" in texts and "Version One" not in texts


def test_edge_a_user_extension_named_like_a_bundled_one_is_separate(window) -> None:
    bundled = next(e for e in EX.discover() if e.source == "bundled")
    write_ext(
        bundled.module_name, "def activate(api):\n    api.add_menu_action('Mine', lambda: None)\n"
    )
    EX.set_enabled(f"user:{bundled.module_name}", True)
    host = window.extension_host
    host.reload()
    assert host.module(f"user:{bundled.module_name}") is not None
    assert host.module(bundled.ext_id) is None  # still off


def test_edge_the_manager_dialog_switches_an_extension_on(window, monkeypatch) -> None:
    from ui.extensions_dialog import ExtensionsDialog

    write_ext("mgr", "def activate(api):\n    api.add_menu_action('From Manager', lambda: None)\n")
    dlg = ExtensionsDialog(window.extension_host, parent=window)
    row = dlg.row_of("user:mgr")
    assert row >= 0
    assert not dlg.is_checked(row)
    dlg.set_checked(row, True)
    assert "From Manager" in _menu_texts(window)
    assert "user:mgr" in EX.enabled_ids()
    assert "runs inside axross" in dlg.warning_text()
    dlg.close()


def test_edge_closing_the_window_deactivates_extensions(tmp_path) -> None:
    from ui.main_window import MainWindow

    marker = EX.extensions_dir() / "DEACTIVATED"
    write_ext(
        "bye",
        f"""
        def activate(api):
            pass

        def deactivate(api):
            open({str(marker)!r}, "w").write("bye")
        """,
    )
    EX.set_enabled("user:bye", True)
    win = MainWindow()
    win._reconnect_timer.stop()
    win.extension_host.reload()
    win.close()
    win.deleteLater()
    pump()
    assert marker.read_text() == "bye"
