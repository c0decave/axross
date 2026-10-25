"""Every feature is reachable from the menu bar.

Operator: "alle tools und features die wir haben auch zugreifbar haben
wenigstens in den menus". Before, about thirty right-click entries
(Rename, Permissions, Checksum, Pack, Encrypt, FUSE, ...) and five toolbar
buttons (Shell, Bookmarks, Copy/Move to Target, Refresh) had no menu entry.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QEvent, QItemSelectionModel  # noqa: E402
from PyQt6.QtGui import QAction  # noqa: E402
from PyQt6.QtWidgets import QApplication, QMenu, QToolBar  # noqa: E402

APP = QApplication.instance() or QApplication([])


def pump(seconds: float = 0.05) -> None:
    end = time.time() + seconds
    while time.time() < end:
        APP.processEvents()
        time.sleep(0.01)


@pytest.fixture
def window(tmp_path):
    from ui.main_window import MainWindow

    folder = tmp_path / "data"
    folder.mkdir()
    (folder / "notes.txt").write_text("x")
    (folder / "pack.zip").write_bytes(b"PK\x05\x06" + b"\0" * 18)
    (folder / "sub").mkdir()
    win = MainWindow()
    win._reconnect_timer.stop()
    win.show()
    win._active_pane.navigate(str(folder))
    pump()
    yield win
    win.close()
    win.deleteLater()
    # processEvents() never runs DeferredDelete: without this every window
    # lives on and each new one's stylesheet repolishes all of them.
    APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    pump()


def _select(pane, name: str) -> None:
    proxy = pane._table.model()
    sel = pane._table.selectionModel()
    sel.clearSelection()
    for row in range(proxy.rowCount()):
        if proxy.index(row, 0).data() == name:
            sel.select(
                proxy.index(row, 0),
                QItemSelectionModel.SelectionFlag.Select | QItemSelectionModel.SelectionFlag.Rows,
            )


def _labels(menu: QMenu) -> list[str]:
    # "&" marks the mnemonic letter; the label is what is left.
    return [a.text().replace("&", "") for a in menu.actions() if not a.isSeparator()]


def _menubar_menu(window, text: str) -> QMenu:
    return next(a.menu() for a in window.menuBar().actions() if a.text() == text)


def _all_menu_actions(window) -> set[int]:
    seen: set[int] = set()

    def walk(menu: QMenu) -> None:
        menu.aboutToShow.emit()
        for action in menu.actions():
            seen.add(id(action))
            if action.menu() is not None:
                walk(action.menu())

    for top in window.menuBar().actions():
        walk(top.menu())
    return seen


# --- happy -----------------------------------------------------------------


def test_happy_the_actions_menu_sits_after_edit(window) -> None:
    texts = [a.text() for a in window.menuBar().actions()]
    assert texts.index("&Actions") == texts.index("&Edit") + 1


@pytest.mark.parametrize("name", ["notes.txt", "sub", "pack.zip", None])
def test_happy_the_actions_menu_mirrors_the_right_click_menu(window, name) -> None:
    pane = window._active_pane
    if name is None:
        pane._table.clearSelection()
    else:
        _select(pane, name)
    context = _labels(pane._build_context_menu())
    actions_menu = _menubar_menu(window, "&Actions")
    actions_menu.aboutToShow.emit()
    mirrored = _labels(actions_menu)
    missing = [label for label in context if label not in mirrored and label != "Refresh"]
    assert missing == [], missing


def test_happy_toolbar_buttons_are_in_the_menus_as_the_same_action(window) -> None:
    in_menus = _all_menu_actions(window)
    bars = [tb for tb in window.findChildren(QToolBar) if tb.windowTitle() in ("Main", "Tools")]
    missing = [
        a.text()
        for toolbar in bars
        for a in toolbar.actions()
        if a.text() and not a.isSeparator() and id(a) not in in_menus
        and a.text() not in _menu_texts(window)
    ]
    assert missing == [], missing


def _menu_texts(window) -> set[str]:
    texts: set[str] = set()

    def walk(menu: QMenu) -> None:
        for action in menu.actions():
            texts.add(action.text().replace("&", "").split("\t")[0].rstrip(".…"))
            if action.menu() is not None:
                walk(action.menu())

    for top in window.menuBar().actions():
        walk(top.menu())
    return texts


# --- sad -------------------------------------------------------------------


def test_sad_no_shortcut_is_bound_twice(window) -> None:
    # Two actions with one shortcut make Qt fire neither ("ambiguous"). A
    # right-click entry only shows its key: Qt.WidgetShortcut on a menu that
    # never takes focus is no owner (tests/test_pane_context_menu_layout.py
    # presses every such key and counts one trigger).
    from PyQt6.QtCore import Qt

    _all_menu_actions(window)
    owners: dict[str, set[int]] = {}
    for action in window.findChildren(QAction):
        if action.shortcutContext() == Qt.ShortcutContext.WidgetShortcut:
            continue
        for seq in action.shortcuts():
            key = seq.toString()
            if key:
                owners.setdefault(key, set()).add(id(action))
    doubles = {k: len(v) for k, v in owners.items() if len(v) > 1}
    assert doubles == {}, doubles


def test_sad_no_german_label_in_the_english_right_click_menu(window) -> None:
    pane = window._active_pane
    _select(pane, "pack.zip")
    labels = _labels(pane._build_context_menu())
    assert "Preview Archive" in labels and "Extract…" in labels
    assert not {"Vorschau", "Entpacken…"} & set(labels)


# --- edge ------------------------------------------------------------------


def test_edge_the_mirror_follows_the_active_pane_and_runs_the_same_code(window, tmp_path) -> None:
    pane = window._active_pane
    _select(pane, "notes.txt")
    actions_menu = _menubar_menu(window, "&Actions")
    actions_menu.aboutToShow.emit()
    assert "Rename" in _labels(actions_menu)
    pane._table.clearSelection()
    actions_menu.aboutToShow.emit()
    assert "Rename" not in _labels(actions_menu)  # rebuilt for the new state


def test_edge_without_a_file_pane_the_actions_menu_says_so(window) -> None:
    window._active_pane = None
    actions_menu = _menubar_menu(window, "&Actions")
    actions_menu.aboutToShow.emit()
    labels = _labels(actions_menu)
    assert "No file pane is active" in labels


def test_edge_view_menu_has_shell_and_bookmarks(window) -> None:
    view = _labels(_menubar_menu(window, "&View"))
    assert "Shell" in view and "Bookmarks" in view


def _mnemonic(text: str) -> str:
    """The letter after a single "&" ("&&" is a literal ampersand)."""
    i = 0
    while i < len(text) - 1:
        if text[i] == "&":
            if text[i + 1] != "&":
                return text[i + 1].lower()
            i += 1
        i += 1
    return ""


@pytest.mark.parametrize("cut", [False, True])
@pytest.mark.parametrize("language", ["en", "de"])
def test_sad_no_mnemonic_is_used_twice_in_one_menu(language, cut, monkeypatch) -> None:
    # Alt+letter with two owners in one menu only cycles between them instead
    # of triggering: every letter belongs to one entry per menu. German is
    # the one catalogue that translates the menus, so it is checked too.
    from core import i18n
    from ui.main_window import MainWindow

    monkeypatch.setattr(i18n, "_ACTIVE", i18n.Translator(language))
    from ui.cut_clipboard import cut_clipboard

    win = MainWindow()
    win._reconnect_timer.stop()
    if cut:  # a pending Cut puts Paste into the Actions menu
        pane = win._active_pane
        cut_clipboard().cut(pane, pane.backend, pane.current_path,
                            [pane.backend.join(pane.current_path, "x")])
        win._active_pane._table.clearSelection()
    doubles = []

    def check(title: str, actions) -> None:
        owners: dict[str, list[str]] = {}
        for action in actions:
            if action.isSeparator() or not action.isVisible():
                continue
            letter = _mnemonic(action.text())
            if letter:
                owners.setdefault(letter, []).append(action.text())
        doubles.extend((title, k, v) for k, v in owners.items() if len(v) > 1)

    def walk(title: str, menu: QMenu) -> None:
        menu.aboutToShow.emit()
        check(title, menu.actions())
        for action in menu.actions():
            if action.menu() is not None:
                walk(f"{title} > {action.text()}", action.menu())

    try:
        check("menu bar", win.menuBar().actions())
        for top in win.menuBar().actions():
            walk(top.text(), top.menu())
        if language == "de":  # the catalogue really is in use
            assert any(a.text() == "&Datei" for a in win.menuBar().actions())
    finally:
        if cut:
            assert any(a.property("axCommand") == "paste" for a in win.actions_menu.actions())
        cut_clipboard().clear()
        win.close()
        win.deleteLater()
        APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    assert doubles == [], doubles


def test_edge_mnemonic_reads_double_ampersands_literally() -> None:
    assert _mnemonic("&Network && Proxy") == "n"
    assert _mnemonic("Save && &Quit") == "q"
    assert _mnemonic("Plain") == "" and _mnemonic("Trailing&") == ""
