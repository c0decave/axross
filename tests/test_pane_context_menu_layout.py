"""The file pane's right-click menu: icons, groups, keys and mnemonics.

Operator (punch list 32): "in der rechten maustaste ansicht, ebenfalls icons
zu den aktionen, zumindest von denen, von denen wir an anderer stelle schon
icons haben, außerdem passend alles sortieren und wenn es shortcuts gibt
z.b. durch bold des buchstabens anzeigen".

Before: a flat list without icons, Refresh first, Rename and Delete below
Copy to Target, and no key shown except a hand-typed "\\tAlt+Enter".
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

from PyQt6.QtCore import (  # noqa: E402
    QEvent,
    QItemSelectionModel,
    Qt,
    QTimer,
    qInstallMessageHandler,
)
from PyQt6.QtGui import QAction, QKeySequence  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication, QMenu, QToolBar  # noqa: E402

APP = QApplication.instance() or QApplication([])

#: Toolbar commands that act on the window, not on a folder or selection,
#: so the right-click menu has no counterpart. Keyed by their icon name.
WINDOW_ONLY = {
    "quick-connect", "connection-manager", "shell", "bookmark", "split-h", "split-v",
    "close-pane", "toggle-layout", "equalize", "extract-pane", "find-index", "compare",
    "disk-usage", "extensions",
    # The tool group (window tools, no file in question).
    "agent", "analysis", "terminal", "find-files", "scripts", "console", "tag", "media-player",
    "audio-settings", "treemap",
    "drives", "settings", "features",
}

#: The key each entry shows, as the pane's eventFilter or a window QAction
#: binds it (file_pane.eventFilter, main_window._setup_toolbar/_setup_menubar).
EXPECTED_KEYS = {
    "rename": "F2",
    "copy-path": "Ctrl+C",
    "cut": "Ctrl+X",
    "paste": "Ctrl+V",
    "copy-to-target": "F5",
    "move-to-target": "F6",
    "new-folder": "F7",
    "delete": "Del",
    "properties": "Alt+Return",
    "refresh": "Ctrl+R",
    "duplicates": "Ctrl+Shift+D",
    "view-mode": "Ctrl+Shift+G",
    "bookmark": "Ctrl+D",
}

STATES = [None, "notes.txt", "sub", "pack.zip", ("notes.txt", "sub")]


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
    win.activateWindow()
    win._active_pane.navigate(str(folder))
    pump()
    yield win
    from ui.cut_clipboard import cut_clipboard

    cut_clipboard().clear()
    win.close()
    win.deleteLater()
    # processEvents() never runs DeferredDelete: without this every window
    # lives on and the next one's stylesheet repolishes all of them.
    APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    pump()


def _select(pane, names) -> None:
    if isinstance(names, str):
        names = (names,)
    proxy = pane._table.model()
    sel = pane._table.selectionModel()
    sel.clearSelection()
    for row in range(proxy.rowCount()):
        if proxy.index(row, 0).data() in (names or ()):
            sel.select(
                proxy.index(row, 0),
                QItemSelectionModel.SelectionFlag.Select | QItemSelectionModel.SelectionFlag.Rows,
            )


def _plain(text: str) -> str:
    return text.replace("&&", "\0").replace("&", "").replace("\0", "&")


def _mnemonic(text: str) -> str | None:
    i = text.replace("&&", "").find("&")
    stripped = text.replace("&&", "")
    return stripped[i + 1].lower() if 0 <= i < len(stripped) - 1 else None


def _cut_pending(pane) -> None:
    """A Cut waits for a Paste: the menus then offer Paste too."""
    from ui.cut_clipboard import cut_clipboard

    folder = pane.current_path
    cut_clipboard().cut(pane, pane.backend, folder, [os.path.join(folder, "notes.txt")])


def _menu(pane, state) -> QMenu:
    if state is None:
        pane._table.clearSelection()
    else:
        _select(pane, state)
    return pane._build_context_menu()


def _by_command(menu: QMenu) -> dict[str, QAction]:
    return {
        str(a.property("axCommand")): a
        for a in menu.actions()
        if a.property("axCommand")
    }


def _groups(menu: QMenu) -> list[list[str]]:
    groups: list[list[str]] = [[]]
    for action in menu.actions():
        if action.isSeparator():
            groups.append([])
        else:
            groups[-1].append(str(action.property("axCommand") or _plain(action.text())))
    return groups


# --- happy -----------------------------------------------------------------


def test_happy_every_toolbar_icon_is_on_its_right_click_entry_too(window) -> None:
    pane = window._active_pane
    context: dict[str, QAction] = {}
    for state in STATES:
        context.update(_by_command(_menu(pane, state)))
    bars = [tb for tb in window.findChildren(QToolBar) if tb.windowTitle() in ("Main", "Tools")]
    checked = 0
    for action in [a for toolbar in bars for a in toolbar.actions()]:
        icon_name = action.property("axIcon")
        if not icon_name:
            continue
        command = action.property("axCommand")
        if command is None:
            assert icon_name in WINDOW_ONLY, (icon_name, _plain(action.text()))
            continue
        assert command in context, (command, sorted(context))
        entry = context[command]
        assert entry.property("axIcon") == icon_name, command
        assert not entry.icon().isNull(), command
        checked += 1
    # refresh, copy/move to target, duplicates, view mode, media, metadata, pack
    assert checked >= 8


def test_happy_keys_are_shown_and_are_the_ones_the_help_lists(window) -> None:
    from ui.shortcuts_dialog import SHORTCUTS

    listed = {k for _s, keys, _d in SHORTCUTS for k in keys}
    pane = window._active_pane
    _cut_pending(pane)  # Paste (Ctrl+V) is offered only then
    seen: dict[str, str] = {}
    for state in STATES:
        for command, action in _by_command(_menu(pane, state)).items():
            key = action.shortcut().toString(QKeySequence.SequenceFormat.PortableText)
            if key:
                seen[command] = key
                assert action.isShortcutVisibleInContextMenu(), command
                assert key in listed, (command, key)
    assert seen == EXPECTED_KEYS


def test_happy_entries_are_grouped_in_a_fixed_order(window) -> None:
    pane = window._active_pane
    groups = _groups(_menu(pane, "notes.txt"))

    def group_of(command: str) -> int:
        return next(i for i, g in enumerate(groups) if command in g)

    order = [
        "open-text", "rename", "copy-to-target", "trash", "new-folder",
        "properties", "refresh", "send-to-agent",
    ]
    positions = [group_of(c) for c in order]
    assert positions == sorted(positions) and len(set(positions)) == len(positions), groups
    assert group_of("copy-path") == group_of("rename") == group_of("cut")
    assert group_of("move-to-target") == group_of("copy-to-target") == group_of("pack")
    assert group_of("delete") == group_of("trash")


@pytest.mark.parametrize("cut", [False, True])
def test_happy_mnemonics_are_unique_within_each_menu(window, cut) -> None:
    pane = window._active_pane
    if cut:
        _cut_pending(pane)
    for state in STATES:
        letters = [
            _mnemonic(a.text()) for a in _menu(pane, state).actions() if not a.isSeparator()
        ]
        used = [m for m in letters if m]
        assert len(used) == len(set(used)), (state, sorted(used))
    commands = _by_command(_menu(pane, "notes.txt"))
    for command in ("rename", "copy-to-target", "new-folder", "properties", "refresh", "delete"):
        assert _mnemonic(commands[command].text()), command


def test_happy_e2e_a_mnemonic_in_the_open_menu_runs_its_entry(window) -> None:
    pane = window._active_pane
    _select(pane, "notes.txt")
    calls: list[str] = []
    pane._rename_selected = lambda *a: calls.append("rename")
    rename_letter = _mnemonic(_by_command(pane._build_context_menu())["rename"].text())

    def press() -> None:
        popup = QApplication.activePopupWidget()
        if popup is None:
            QTimer.singleShot(20, press)
            return
        QTest.keyClick(popup, rename_letter)

    def close_left_open() -> None:
        popup = QApplication.activePopupWidget()
        if popup is not None:
            popup.close()

    QTimer.singleShot(50, press)
    QTimer.singleShot(3000, close_left_open)
    pane._show_context_menu(None)
    pump()
    assert calls == ["rename"]


def _all_with_key(window, key: str) -> list[QAction]:
    seq = QKeySequence(key)
    return [a for a in window.findChildren(QAction) if seq in a.shortcuts()]


@pytest.mark.parametrize(
    ("key", "pane_method"),
    [
        ("F2", "_rename_selected"),
        ("Ctrl+C", "_copy_paths_to_clipboard"),
        ("Ctrl+X", "cut_selected"),
        ("Ctrl+V", "paste_cut"),
        ("F7", "_create_folder"),
        ("Del", "_delete_selected"),
        ("Ctrl+D", "_add_bookmark"),
        ("Alt+Return", "_show_properties"),
        ("F5", "_copy_to_target"),
        ("F6", "_move_to_target"),
        ("Ctrl+R", "refresh_async"),
        ("Ctrl+Shift+G", None),
        ("Ctrl+Shift+D", None),
    ],
)
def test_happy_e2e_each_key_still_fires_exactly_once(window, key, pane_method) -> None:
    """The right-click entries carry the keys too, so Qt must not see two
    owners (it would fire neither and log "Ambiguous shortcut")."""
    pane = window._active_pane
    _cut_pending(pane)  # so the menus carry Paste (Ctrl+V) as well
    _select(pane, "notes.txt")
    keep = pane._build_context_menu()  # a live right-click menu with the keys
    actions_menu = next(
        a.menu() for a in window.menuBar().actions() if _plain(a.text()) == "Actions"
    )
    actions_menu.aboutToShow.emit()  # and the menu bar's mirror of it
    fired: list[str] = []
    for action in _all_with_key(window, key) + keep.actions():
        if QKeySequence(key) in action.shortcuts():
            action.triggered.disconnect()
            action.triggered.connect(lambda _c=False, a=action: fired.append(_plain(a.text())))
    if pane_method is not None:
        setattr(pane, pane_method, lambda *a, **k: fired.append(pane_method))
    warnings: list[str] = []
    previous = qInstallMessageHandler(lambda _t, _c, msg: warnings.append(msg))
    try:
        pane._table.setFocus()
        pump()
        seq = QKeySequence(key)[0]
        QTest.keyClick(pane._table, seq.key(), seq.keyboardModifiers())
        pump()
    finally:
        qInstallMessageHandler(previous)
    assert len(fired) == 1, (key, fired)
    assert not [w for w in warnings if "Ambiguous" in w], warnings
    del keep


# --- sad -------------------------------------------------------------------


def test_sad_right_click_entries_never_own_a_key(window) -> None:
    pane = window._active_pane
    for state in STATES:
        for action in _menu(pane, state).actions():
            if not action.shortcut().isEmpty():
                assert action.shortcutContext() == Qt.ShortcutContext.WidgetShortcut


def test_sad_no_entry_shows_the_unknown_placeholder(window) -> None:
    from ui.icon_provider import has_icon

    pane = window._active_pane
    for state in STATES:
        for action in _menu(pane, state).actions():
            name = action.property("axIcon")
            if name:
                assert has_icon(str(name)) and name != "unknown", name


def test_sad_a_hostile_single_name_offers_no_file_actions(window) -> None:
    pane = window._active_pane
    _select(pane, "notes.txt")
    pane._safe_item_path = lambda item, warn=True: None
    commands = _by_command(pane._build_context_menu())
    for command in ("open-text", "open-hex", "rename", "cut", "trash", "delete", "checksum"):
        assert command not in commands, command
    assert "refresh" in commands and "new-folder" in commands  # the folder entries stay


# --- edge ------------------------------------------------------------------


def test_edge_no_leading_trailing_or_double_separators(window) -> None:
    pane = window._active_pane
    for state in STATES:
        groups = _groups(_menu(pane, state))
        assert all(groups), (state, groups)


def test_edge_icons_follow_the_theme_tint(window) -> None:
    from ui import icon_provider

    pane = window._active_pane
    before = _by_command(_menu(pane, None))["refresh"].icon().cacheKey()
    icon_provider.set_tint("#00ff00")
    try:
        after = _by_command(_menu(pane, None))["refresh"].icon().cacheKey()
        assert after == icon_provider.icon("refresh").cacheKey()
        assert after != before
    finally:
        icon_provider.set_tint(None)


def test_edge_the_actions_menu_still_lists_refresh_once(window) -> None:
    pane = window._active_pane
    _select(pane, "notes.txt")
    actions_menu = next(
        a.menu() for a in window.menuBar().actions() if _plain(a.text()) == "Actions"
    )
    actions_menu.aboutToShow.emit()
    commands = [a.property("axCommand") for a in actions_menu.actions()]
    assert commands.count("refresh") == 1 and commands.count("metadata") == 1
    assert "rename" in commands


def test_edge_the_extract_entry_stays_bold_and_gets_a_theme_icon(window) -> None:
    pane = window._active_pane
    extract = _by_command(_menu(pane, "pack.zip"))["extract"]
    assert extract.font().bold()
    assert extract.property("axIcon") and not extract.icon().isNull()


def test_edge_german_mnemonic_entries_carry_exactly_one_ampersand() -> None:
    import json

    path = Path(__file__).resolve().parent.parent / "resources/i18n/de.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    for source, text in data.items():
        if source.replace("&&", "").count("&") == 1:
            assert text.replace("&&", "").count("&") == 1, (source, text)


# --- round-2 verification: the entries added by the integration, German -----------


def _with_disk_image(window) -> None:
    pane = window._active_pane
    folder = Path(pane.current_path)
    (folder / "disk.img").write_bytes(b"\0" * 1024)
    pane.navigate(str(folder))
    pump()


def test_happy_the_integrated_entries_sit_in_the_grouped_menu(window) -> None:
    """Disk Image…, Find in This Folder… and Tags ▸ - re-added when the
    features were merged - are there, each in a fitting group: Tags acts on
    the selection and is not part of the agent's group."""
    _with_disk_image(window)
    pane = window._active_pane
    groups = _groups(_menu(pane, "disk.img"))

    def group_of(name: str) -> int:
        return next(i for i, g in enumerate(groups) if name in g)

    assert group_of("disk-image") == group_of("properties"), groups
    assert group_of("find-files") == group_of("duplicates"), groups
    assert group_of("Tags") != group_of("send-to-agent"), groups
    assert group_of("Tags") < group_of("send-to-agent"), groups


def test_edge_mnemonics_stay_unique_with_a_disk_image_selected(window) -> None:
    _with_disk_image(window)
    pane = window._active_pane
    for state in (*STATES, "disk.img"):
        letters = [_mnemonic(a.text()) for a in _menu(pane, state).actions()
                   if not a.isSeparator()]
        used = [m for m in letters if m]
        assert len(used) == len(set(used)), (state, sorted(used))


def test_edge_german_mnemonics_are_unique_within_each_menu(window, monkeypatch) -> None:
    """The German catalogue moves letters (Refresh -> &Aktualisieren) while
    untranslated entries keep theirs: no letter may then be used twice."""
    from core import i18n

    _with_disk_image(window)
    pane = window._active_pane
    german = i18n.Translator("de")
    assert german.tr("R&efresh") != "R&efresh"  # the catalogue is really read
    monkeypatch.setattr(i18n, "_ACTIVE", german)  # the previous one comes back after
    _cut_pending(pane)  # Cut and Paste are in the menu too
    for state in (*STATES, "disk.img"):
        texts = [a.text() for a in _menu(pane, state).actions() if not a.isSeparator()]
        used = [m for m in map(_mnemonic, texts) if m]
        dupes = sorted({m for m in used if used.count(m) > 1})
        assert not dupes, (state, dupes, [t for t in texts if _mnemonic(t) in dupes])
