"""The Agent dock in the main window: Ctrl+Shift+A, Send to Agent from a
pane, the pane lookups of the + menu and drops, settings at run time."""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtGui import QKeySequence  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import agent_settings as AGS  # noqa: E402
from core import bookmarks as BM  # noqa: E402

APP = QApplication.instance() or QApplication([])


def _pump(seconds=0.3):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        APP.processEvents()
        time.sleep(0.01)


@pytest.fixture
def win(tmp_path, monkeypatch):
    monkeypatch.setattr(AGS, "settings_file", lambda: tmp_path / "agent" / "settings.json")
    from core import agent_session as AS

    monkeypatch.setattr(AS, "sessions_dir", lambda: tmp_path / "agent" / "sessions")
    (tmp_path / "work").mkdir()
    (tmp_path / "work" / "a.txt").write_text("a")
    with mock.patch("pathlib.Path.home", return_value=tmp_path), \
            mock.patch.object(BM, "BOOKMARKS_FILE", tmp_path / "bookmarks.json"):
        from ui.main_window import MainWindow

        w = MainWindow()
        w.show()
        _pump()
        w._active_pane.navigate(str(tmp_path / "work"))
        _pump()
        yield w
        w._agent_dock.shutdown()
        w.close()
        w.deleteLater()
        _pump(0.1)


# -- happy ---------------------------------------------------------------------


def test_happy_ctrl_shift_a_opens_the_agent_and_focuses_the_task(win):
    actions = [a for a in win.actions() if a.shortcut() == QKeySequence("Ctrl+Shift+A")]
    assert len(actions) == 1
    actions[0].trigger()
    _pump()
    assert win._agent_dock.isVisible()
    tab = win._agent_dock.current_tab()
    assert tab.input.hasFocus() or APP.focusWidget() is tab.input


def test_happy_send_to_agent_attaches_the_pane_selection(win, tmp_path):
    pane = win._active_pane
    pane._table.selectAll()
    _pump()
    pane.send_to_agent()
    _pump()
    tab = win._agent_dock.current_tab()
    assert [a["path"] for a in tab._attachments] == [str(tmp_path / "work" / "a.txt")]
    assert win._agent_dock.isVisible()


def test_happy_the_context_menu_offers_send_to_agent(win):
    menu = win._active_pane._build_context_menu()
    assert "Send to Agent" in [a.text() for a in menu.actions()]


# -- sad -----------------------------------------------------------------------


def test_sad_an_unknown_pane_id_counts_as_local_and_nameless(win):
    assert win._agent_pane_backend("no-such-pane") == (None, True)
    assert win._agent_pane_backend(str(id(win._active_pane))) == (None, True)


def test_sad_nothing_selected_sends_the_folder(win, tmp_path):
    win._active_pane._table.clearSelection()
    win._active_pane.send_to_agent()
    _pump()
    tab = win._agent_dock.current_tab()
    assert [a["path"] for a in tab._attachments] == [str(tmp_path / "work")]


# -- edge ----------------------------------------------------------------------


def test_edge_saved_agent_settings_reach_open_tabs(win, tmp_path):
    from core.agent_sandbox import SandboxProfile

    settings = AGS.AgentSettings(sandboxes=[SandboxProfile(name="Ops", level="high")])
    settings.save()
    win._agent_dock.reload_settings()
    tab = win._agent_dock.current_tab()
    names = [tab.sandbox_combo.itemData(i) for i in range(tab.sandbox_combo.count())]
    assert names == ["", "Ops"]


def test_edge_a_remote_pane_names_its_backend_for_the_agent(win):
    from core.ram_fs import RamFsSession

    pane = win._active_pane
    ram = RamFsSession("agent-ram")
    ram.mkdir("/data")
    with mock.patch.object(type(pane), "backend", new_callable=mock.PropertyMock, return_value=ram):
        found = win._agent_pane_items("folder")
        backend = win._agent_pane_backend(str(id(pane)))
        lent = win._agent_remote_backends()
    assert found["local"] is False and found["backend"] == f"pane:{ram.name}"
    assert backend == (f"pane:{ram.name}", False)
    assert lent == [(f"pane:{ram.name}", ram, None)]


def test_edge_the_agent_names_a_pane_connection_by_its_profile(win):
    from core.profiles import ConnectionProfile
    from core.ram_fs import RamFsSession

    pane = win._active_pane
    ram = RamFsSession("agent-ram")
    profile = ConnectionProfile(name="nas", protocol="sftp", host="nas.example")
    win._pane_profiles[pane] = profile
    try:
        with mock.patch.object(
            type(pane), "backend", new_callable=mock.PropertyMock, return_value=ram
        ):
            assert win._agent_remote_backends() == [("pane:nas", ram, profile)]
    finally:
        win._pane_profiles.pop(pane, None)


def test_edge_two_connections_with_one_name_get_two_ids(win):
    from core.ram_fs import RamFsSession

    first, second = RamFsSession("same"), RamFsSession("same")
    panes = [mock.Mock(backend=first), mock.Mock(backend=second), mock.Mock(backend=first)]
    with mock.patch.object(win, "_panes", panes):
        ids = [bid for bid, _b, _p in win._agent_remote_backends()]
    assert ids == [f"pane:{first.name}", f"pane:{first.name}#2"]


def test_sad_local_panes_lend_nothing(win):
    assert win._agent_remote_backends() == []
