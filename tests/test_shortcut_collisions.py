"""No window shortcut takes a key the file list handles itself.

Found in review round 3 (UX, repro ``ctrl_shift_a.py``): Ctrl+Shift+A was
both the window's "Ask the Agent" and the file list's "Invert selection"
(listed so in Ctrl+F1). A window shortcut is matched before the focused
list sees the key, so in a file list Ctrl+Shift+A opened the Agent panel
and the selection stayed as it was. Ask the Agent is Ctrl+Shift+K now.

The pane's keys are read from the pane itself: every window shortcut is
fed to ``FilePaneWidget.eventFilter`` with the pane's handlers replaced by
mocks, and a key it consumes must not be a window shortcut - unless the
window action runs the same command (F5, F6, Ctrl+R).
"""

from __future__ import annotations

import ast
import inspect
import os
import sys
import textwrap
import time
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QEvent, Qt  # noqa: E402
from PyQt6.QtGui import QAction, QKeyEvent, QKeySequence, QShortcut  # noqa: E402
from PyQt6.QtWidgets import QAbstractButton, QApplication, QMenu  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402

from core import agent_settings as AGS  # noqa: E402
from core import bookmarks as BM  # noqa: E402

APP = QApplication.instance() or QApplication([])
PORTABLE = QKeySequence.SequenceFormat.PortableText


def _pump(seconds: float = 0.2) -> None:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        APP.processEvents()
        time.sleep(0.01)


@pytest.fixture
def win(tmp_path, monkeypatch):
    monkeypatch.setattr(AGS, "settings_file", lambda: tmp_path / "agent" / "settings.json")
    from core import agent_session as AS

    monkeypatch.setattr(AS, "sessions_dir", lambda: tmp_path / "agent" / "sessions")
    work = tmp_path / "work"
    work.mkdir()
    for name in ("a.txt", "b.txt", "c.txt"):
        (work / name).write_text(name)
    with mock.patch("pathlib.Path.home", return_value=tmp_path), \
            mock.patch.object(BM, "BOOKMARKS_FILE", tmp_path / "bookmarks.json"):
        from ui.main_window import MainWindow

        w = MainWindow()
        w._reconnect_timer.stop()
        w.resize(1200, 800)
        w.show()
        w.activateWindow()
        _pump(0.3)
        w._active_pane.navigate(str(work))
        _pump(0.4)
        yield w
        w._agent_dock.shutdown()
        w.close()
        w.deleteLater()
        _pump(0.1)


def _window_shortcuts(window, pane) -> dict[str, list[object]]:
    """Portable key text -> the window objects that own it while the file
    list of *pane* has the focus."""
    for menu in window.findChildren(QMenu):  # entries built on first show
        menu.aboutToShow.emit()
    table = pane._table
    owners: dict[str, list[object]] = {}

    def active_for_list(context, widgets) -> bool:
        if context == Qt.ShortcutContext.WidgetShortcut:
            return False
        if context == Qt.ShortcutContext.WidgetWithChildrenShortcut:
            return any(w is table or w.isAncestorOf(table) for w in widgets)
        return True

    for action in window.findChildren(QAction):
        widgets = [o for o in action.associatedObjects() if hasattr(o, "isAncestorOf")]
        if not active_for_list(action.shortcutContext(), widgets or [window]):
            continue
        for seq in action.shortcuts():
            if seq.toString(PORTABLE):
                owners.setdefault(seq.toString(PORTABLE), []).append(action)
    for shortcut in window.findChildren(QShortcut):
        parent = shortcut.parent()
        if parent is None or not active_for_list(shortcut.context(), [parent]):
            continue
        if shortcut.key().toString(PORTABLE):
            owners.setdefault(shortcut.key().toString(PORTABLE), []).append(shortcut)
    for button in window.findChildren(QAbstractButton):
        if button.shortcut().toString(PORTABLE):
            owners.setdefault(button.shortcut().toString(PORTABLE), []).append(button)
    return owners


def _pane_handler_names() -> set[str]:
    """The pane methods ``eventFilter`` calls (``self.<name>(...)``)."""
    from ui.file_pane import FilePaneWidget

    tree = ast.parse(textwrap.dedent(inspect.getsource(FilePaneWidget.eventFilter)))
    names = set()
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name) and node.func.value.id == "self"):
            names.add(node.func.attr)
    return names - {"_key_views"}


def _pane_consumes(pane, key_text: str) -> bool:
    """Whether the file list of *pane* handles *key_text* itself - asked
    of its event filter with every handler mocked out."""
    seq = QKeySequence(key_text)
    if seq.count() != 1:
        return False
    combo = seq[0]
    event = QKeyEvent(QEvent.Type.KeyPress, combo.key().value, combo.keyboardModifiers())
    patches = [mock.patch.object(pane, name) for name in _pane_handler_names()
               if callable(getattr(pane, name, None))]
    for p in patches:
        p.start()
    try:
        return bool(pane.eventFilter(pane._table, event))
    finally:
        for p in patches:
            p.stop()


def _same_command(window) -> dict[str, object]:
    """Window shortcuts that run the very command the list runs for that key."""
    return {
        "F5": window._copy_target_action,
        "F6": window._move_target_action,
        "Ctrl+R": window._refresh_action,
    }


# -- happy ---------------------------------------------------------------------


def test_happy_no_window_shortcut_takes_a_key_of_the_file_list(win):
    """Ctrl+Shift+A was "Ask the Agent" and the list's Invert Selection."""
    pane = win._active_pane
    shared = {key: owners for key, owners in _window_shortcuts(win, pane).items()
              if _pane_consumes(pane, key)}
    same = _same_command(win)
    collisions = {key: [type(o).__name__ + ":" + (o.text() if hasattr(o, "text") else "")
                        for o in owners]
                  for key, owners in shared.items()
                  if key not in same or owners != [same[key]]}
    assert collisions == {}, collisions


def test_happy_ctrl_shift_a_in_the_file_list_inverts_the_selection(win):
    pane = win._active_pane
    table = pane._table
    table.setFocus()
    _pump()
    pane._select_all()
    _pump()
    table.clearSelection()
    first = next(i for i in range(pane._proxy.rowCount())
                 if pane._proxy.index(i, 0).data() == "a.txt")
    table.selectRow(first)
    _pump()
    assert [Path(p).name for p in pane.selected_items()] == ["a.txt"]
    QTest.keyClick(table, Qt.Key.Key_A,
                   Qt.KeyboardModifier.ControlModifier | Qt.KeyboardModifier.ShiftModifier)
    _pump(0.3)
    assert sorted(Path(p).name for p in pane.selected_items()) == ["b.txt", "c.txt"]
    assert not win._agent_dock.isVisible()


def test_happy_ask_the_agent_is_ctrl_shift_k_and_listed(win):
    from ui.shortcuts_dialog import SHORTCUTS

    owners = _window_shortcuts(win, win._active_pane)
    assert owners.get("Ctrl+Shift+K") == [win._focus_agent_action]
    assert "Ctrl+Shift+A" not in owners
    listed = {k: d for _s, keys, d in SHORTCUTS for k in keys}
    assert "Agent" in listed["Ctrl+Shift+K"]
    assert listed["Ctrl+Shift+A"] == "Invert selection"


# -- sad -----------------------------------------------------------------------


def test_sad_the_probe_sees_a_collision(win):
    """The check above would catch one: a window action on Ctrl+Shift+A."""
    pane = win._active_pane
    assert "Ctrl+Shift+A" not in _window_shortcuts(win, pane)  # free before the clash
    clash = QAction("clash", win)
    clash.setShortcut(QKeySequence("Ctrl+Shift+A"))
    win.addAction(clash)
    try:
        owners = _window_shortcuts(win, pane)
        assert clash in owners["Ctrl+Shift+A"]
        assert _pane_consumes(pane, "Ctrl+Shift+A")
    finally:
        win.removeAction(clash)
        clash.deleteLater()


# -- edge ----------------------------------------------------------------------


def test_edge_a_key_the_list_ignores_is_free_for_the_window(win):
    """Ctrl+Shift+K and the area keys are no list keys: the window gets them."""
    pane = win._active_pane
    owners = _window_shortcuts(win, pane)
    for key, action in (("Ctrl+Shift+K", win._focus_agent_action),
                        ("Ctrl+F6", win._next_area_action),
                        ("Ctrl+Shift+F6", win._prev_area_action)):
        assert not _pane_consumes(pane, key), key
        assert owners.get(key) == [action], key
    assert _pane_consumes(pane, "F2")  # and the probe does see the list's own keys
