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

from PyQt6.QtCore import QEvent  # noqa: E402
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
    # processEvents() never runs DeferredDelete: without this every window
    # lives on and each new one's stylesheet repolishes all of them.
    APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)
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


def _ctx_with(*entries):
    from types import SimpleNamespace

    from ui.extension_host import ExtensionContext

    items = tuple(SimpleNamespace(name=n, is_dir=d) for n, d in entries)
    return ExtensionContext(backend=None, folder="/f", paths=(), items=items)


def test_happy_single_folder_applies_to_exactly_one_folder() -> None:
    from ui.extension_host import APPLIES_TO, _applies

    assert "single_folder" in APPLIES_TO
    assert _applies(_ctx_with(("repo", True)), "single_folder", ())


def test_sad_single_folder_is_not_offered_for_two_folders_or_a_file() -> None:
    from ui.extension_host import _applies

    assert not _applies(_ctx_with(("a", True), ("b", True)), "single_folder", ())
    assert not _applies(_ctx_with(("a", True), ("x.txt", False)), "single_folder", ())
    assert not _applies(_ctx_with(("x.txt", False)), "single_folder", ())


def test_edge_single_folder_ignores_the_parent_entry_and_needs_a_selection() -> None:
    from ui.extension_host import _applies

    assert not _applies(_ctx_with(), "single_folder", ())
    assert _applies(_ctx_with(("..", True), ("repo", True)), "single_folder", ())


def test_e2e_a_single_folder_action_shows_for_one_selected_folder_only(window, tmp_path) -> None:
    write_ext(
        "onefolder",
        """
        SEEN = []

        def activate(api):
            api.add_context_action("One Folder", lambda ctx: SEEN.append(list(ctx.paths)),
                                   applies_to="single_folder")
        """,
    )
    EX.set_enabled("user:onefolder", True)
    window.extension_host.reload()
    folder = tmp_path / "data"
    (folder / "a").mkdir(parents=True)
    (folder / "b").mkdir()
    pane = window._active_pane
    pane.navigate(str(folder))
    pane._table.selectAll()
    labels = [a.text() for a in pane._build_context_menu().actions()]
    assert "One Folder" not in labels  # two folders selected
    pane._table.clearSelection()
    pane._table.selectRow(next(
        r for r in range(pane._proxy.rowCount())
        if pane._proxy.data(pane._proxy.index(r, 0)) == "a"
    ))
    menu = pane._build_context_menu()
    next(a for a in menu.actions() if a.text() == "One Folder").trigger()
    assert window.extension_host.module("user:onefolder").SEEN == [[str(folder / "a")]]


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


def _treemap_like_dock(window, name: str = "panel"):
    write_ext(
        name,
        """
        from PyQt6.QtWidgets import QLabel

        def activate(api):
            api.add_dock("My Panel", QLabel("x"))
        """,
    )
    EX.set_enabled(f"user:{name}", True)
    host = window.extension_host
    host.reload()
    (dock,) = host.docks(f"user:{name}")
    dock.show()
    pump()
    return dock


def test_happy_an_extension_dock_has_the_app_title_bar_with_x_and_float(window) -> None:
    """Operator item 13: the Folder Treemap panel had no [x]. Extension docks
    get the same title bar as the built-in panels."""
    from ui.dock_titlebar import DockTitleBar

    dock = _treemap_like_dock(window)
    bar = dock.titleBarWidget()
    assert isinstance(bar, DockTitleBar)
    assert bar._title_label.text() == "My Panel"
    assert "Extensions menu" in bar._close_btn.toolTip()
    assert dock.isVisible()
    bar._float_btn.click()
    assert dock.isFloating()
    bar._float_btn.click()
    assert not dock.isFloating()


def test_happy_the_x_hides_the_dock_and_the_extensions_menu_brings_it_back(window) -> None:
    dock = _treemap_like_dock(window)
    toggle = next(a for a in window.extensions_menu.actions() if a.text() == "My Panel")
    assert toggle.isChecked()
    dock.titleBarWidget()._close_btn.click()
    pump()
    assert not dock.isVisible()
    assert not toggle.isChecked()
    assert window.extension_host.docks("user:panel") == [dock]  # hidden, not destroyed
    toggle.trigger()
    pump()
    assert dock.isVisible()


def test_edge_a_closed_extension_dock_is_still_removed_when_switched_off(window) -> None:
    dock = _treemap_like_dock(window, "gone")
    dock.titleBarWidget()._close_btn.click()
    pump()
    host = window.extension_host
    host.set_enabled("user:gone", False)
    assert host.docks("user:gone") == []
    assert "My Panel" not in _menu_texts(window)


def test_edge_every_dock_in_the_window_carries_the_app_title_bar(window) -> None:
    """Built-in and extension panels alike: none falls back to Qt's default
    title bar, whose close button the modern theme hides
    (``titlebar-close-icon: none``)."""
    from PyQt6.QtWidgets import QDockWidget

    from ui.dock_titlebar import DockTitleBar

    _treemap_like_dock(window)
    docks = window.findChildren(QDockWidget)
    assert len(docks) > 1
    bare = [
        d.objectName() or d.windowTitle()
        for d in docks
        if not isinstance(d.titleBarWidget(), DockTitleBar)
    ]
    assert bare == []


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


# --- what a drop is about (api.drop_context) ----------------------------------


def _api(window):
    from ui.extension_host import ExtensionAPI

    info = EX.ExtensionInfo(ext_id="user:drop", source="user", module_name="drop",
                            path="drop.py", name="Drop")
    return ExtensionAPI(window.extension_host, info)


def test_happy_drop_context_of_a_pane_drag_names_the_pane_backend(window, tmp_path) -> None:
    from unittest import mock

    from PyQt6.QtCore import QMimeData

    from core.ram_fs import RamFsSession
    from ui.file_pane import TRANSFER_MIME_TYPE

    pane = window._active_pane
    pane.navigate(str(tmp_path))
    mime = QMimeData()
    mime.setData(TRANSFER_MIME_TYPE, pane._encode_transfer_payload([str(tmp_path / "a.mp3")]))
    ctx = _api(window).drop_context(mime)
    assert ctx.is_local and ctx.paths == (str(tmp_path / "a.mp3"),) and ctx.pane is pane
    ram = RamFsSession("drop-ram")
    with mock.patch.object(type(pane), "backend", new_callable=mock.PropertyMock,
                           return_value=ram):
        mime.setData(TRANSFER_MIME_TYPE, pane._encode_transfer_payload(["/m/b.ogg"]))
        ctx = _api(window).drop_context(mime)
        assert ctx.backend is ram and not ctx.is_local and ctx.paths == ("/m/b.ogg",)


def test_happy_drop_context_of_desktop_files_is_local(window, tmp_path) -> None:
    from PyQt6.QtCore import QMimeData, QUrl

    mime = QMimeData()
    mime.setUrls([QUrl.fromLocalFile(str(tmp_path / "x.flac")), QUrl("https://example.com/y")])
    ctx = _api(window).drop_context(mime)
    assert ctx.is_local and ctx.paths == (str(tmp_path / "x.flac"),)
    assert ctx.folder == str(tmp_path)


def test_sad_drop_context_of_anything_else_is_none(window) -> None:
    from PyQt6.QtCore import QMimeData, QUrl

    from ui.file_pane import TRANSFER_MIME_TYPE

    text = QMimeData()
    text.setText("/etc/passwd")
    garbage = QMimeData()
    garbage.setData(TRANSFER_MIME_TYPE, b"\xff not json")
    web = QMimeData()
    web.setUrls([QUrl("https://example.com/a.mp3")])
    api = _api(window)
    assert [api.drop_context(m) for m in (None, text, garbage, web)] == [None] * 4


def test_edge_drop_context_from_a_pane_that_closed(window) -> None:
    """The payload outlives its pane: a local one still means the local
    disk, a remote one's connection is gone."""
    import json

    from PyQt6.QtCore import QMimeData

    from ui.file_pane import TRANSFER_MIME_TYPE

    def payload(filesystem):
        mime = QMimeData()
        mime.setData(TRANSFER_MIME_TYPE, json.dumps(
            {"paths": ["/m/a.mp3"], "source_pane_id": "12345", "dirs": [],
             "filesystem": filesystem}).encode())
        return mime

    api = _api(window)
    ctx = api.drop_context(payload("Local"))
    assert ctx is not None and ctx.is_local and ctx.paths == ("/m/a.mp3",)
    assert api.drop_context(payload("remote:nas")) is None
