"""Icons, grouping and mnemonics in the archive and bookmark right-click menus
(wish-list item 32).

Operator: *„in der rechten maustaste ansicht, ebenfalls icons zu den
aktionen, zumindest von denen, von denen wir an anderer stelle schon icons
haben, außerdem passend alles sortieren und wenn es shortcuts gibt z.b.
durch bold des buchstabens anzeigen"*. The file pane menu had all three
(ui/file_pane.py CONTEXT_COMMANDS); the archive pane menu had no icons, the
bookmark sidebar menu neither icons nor "&" mnemonics. An entry here takes
the icon its command has in the file pane menu (the same name from
ui.icon_provider), so a command looks the same everywhere.
"""

from __future__ import annotations

import io
import os
import sys
import time
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QItemSelectionModel, Qt, QTimer  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication, QMenu  # noqa: E402

import core.bookmarks as BM  # noqa: E402
from core.bookmarks import Bookmark, BookmarkManager  # noqa: E402

APP = QApplication.instance() or QApplication([])


def pump(seconds: float = 0.05) -> None:
    end = time.time() + seconds
    while time.time() < end:
        APP.processEvents()
        time.sleep(0.01)


def _mnemonic(text: str) -> str:
    from tests.test_menu_audit import _mnemonic as letter

    return letter(text)


def _entries(menu: QMenu) -> list:
    return [a for a in menu.actions() if not a.isSeparator()]


def _layout(menu: QMenu) -> list[str]:
    """Labels without "&", "|" for a separator: the menu's order and groups."""
    return ["|" if a.isSeparator() else a.text().replace("&", "") for a in menu.actions()]


def _assert_unique_mnemonics(menu: QMenu) -> None:
    letters = [_mnemonic(a.text()) for a in _entries(menu)]
    used = [m for m in letters if m]
    assert len(used) == len(set(used)), [a.text() for a in _entries(menu)]
    for action in _entries(menu):
        if action.menu() is not None:
            _assert_unique_mnemonics(action.menu())


# -- archive pane -------------------------------------------------------------------------


@pytest.fixture
def archive(tmp_path):
    from ui.archive_pane import ArchivePaneWidget

    path = tmp_path / "a.zip"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("readme.txt", b"x")
        zf.writestr("inner.zip", b"PK\x05\x06" + b"\0" * 18)
        zf.writestr("docs/note.txt", b"y")
    path.write_bytes(buf.getvalue())
    pane = ArchivePaneWidget(str(path))
    pane.resize(600, 400)
    pane.show()
    pump()
    yield pane
    pane.close()
    pane.deleteLater()
    pump()


def _select(pane, *members: str) -> None:
    model = pane._tree.model()
    sel = pane._tree.selectionModel()
    sel.clearSelection()
    pane._tree.expandAll()
    stack = [model.invisibleRootItem()]
    while stack:
        parent = stack.pop()
        for row in range(parent.rowCount()):
            item = parent.child(row, 0)
            if item.data(Qt.ItemDataRole.UserRole) in members:
                sel.select(item.index(), QItemSelectionModel.SelectionFlag.Select
                           | QItemSelectionModel.SelectionFlag.Rows)
            stack.append(item)
    pump()


def test_happy_every_archive_entry_has_the_file_pane_icon_of_its_command(archive):
    from ui.file_pane import CONTEXT_COMMANDS

    _select(archive, "readme.txt")
    menu = archive.build_context_menu()
    icons = {a.property("axCommand"): a.property("axIcon") for a in _entries(menu)}
    assert icons == {
        "open": CONTEXT_COMMANDS["open-text"][0],
        "extract-selected": CONTEXT_COMMANDS["extract"][0],
        "extract-selected-to": CONTEXT_COMMANDS["extract"][0],
        "extract-all": CONTEXT_COMMANDS["extract"][0],
        "extract-to": CONTEXT_COMMANDS["extract"][0],
        "properties": CONTEXT_COMMANDS["properties"][0],
    }
    assert all(not a.icon().isNull() for a in _entries(menu))


def test_sad_without_a_selection_only_the_whole_archive_entries_show_with_icons(archive):
    _select(archive)
    menu = archive.build_context_menu()
    assert _layout(menu) == ["Extract All", "Extract All To…"]
    assert all(not a.icon().isNull() for a in _entries(menu))


def test_edge_an_archive_member_opens_with_the_archive_icon(archive):
    from ui.file_pane import CONTEXT_COMMANDS

    _select(archive, "inner.zip")
    menu = archive.build_context_menu()
    opener = next(a for a in _entries(menu) if a.property("axCommand") == "open")
    assert opener.text().replace("&", "") == "Open Archive"
    assert opener.property("axIcon") == CONTEXT_COMMANDS["preview-archive"][0]
    _assert_unique_mnemonics(menu)
    assert _layout(menu) == ["Open Archive", "|", "Extract Selected", "Extract Selected To…", "|",
                             "Extract All", "Extract All To…", "|", "Properties…"]


# -- bookmark sidebar ---------------------------------------------------------------------


@pytest.fixture
def side(tmp_path, monkeypatch):
    from ui.bookmark_sidebar import BookmarkSidebar

    monkeypatch.setattr(BM, "BOOKMARKS_FILE", tmp_path / "bookmarks.json")
    manager = BookmarkManager()
    work = manager.add_group("Work", icon_name="briefcase")
    manager.add(Bookmark("logs", "/var/log"), group=work)
    manager.add(Bookmark("home", "/home"))
    manager.add(Bookmark("tmp", "/tmp"))
    widget = BookmarkSidebar(manager)
    widget.resize(300, 500)
    widget.show()
    pump()
    widget.manager = manager
    widget.work = work
    yield widget
    widget.close()
    widget.deleteLater()
    pump()


def _bookmark(side, name):
    return next(n for n in side.manager.tree() if getattr(n, "name", "") == name)


def test_happy_bookmark_menu_has_icons_mnemonics_and_groups(side):
    menu = side._build_menu(_bookmark(side, "home"))
    assert _layout(menu) == ["Edit…", "|", "Move Up", "Move Down", "Move to Top", "Move to Group",
                             "|", "Delete"]
    by_label = {a.text().replace("&", ""): a for a in _entries(menu)}
    assert by_label["Edit…"].property("axIcon") == "edit"
    assert by_label["Delete"].property("axIcon") == "x"
    assert all(_mnemonic(a.text()) for a in _entries(menu))
    _assert_unique_mnemonics(menu)


def test_happy_group_menu_has_icons_mnemonics_and_groups(side):
    menu = side._build_menu(side.work)
    assert _layout(menu) == ["New Group Inside", "New Terminal Bookmark…", "|", "Edit…", "|",
                             "Move Up", "Move Down", "Move to Top", "Move to Group", "Sort", "|",
                             "Delete Group"]
    icons = {a.text().replace("&", ""): a.property("axIcon") for a in _entries(menu)}
    assert icons["New Group Inside"] == "folder" and icons["New Terminal Bookmark…"] == "terminal"
    assert icons["Edit…"] == "edit" and icons["Delete Group"] == "x"
    assert all(_mnemonic(a.text()) for a in _entries(menu))
    _assert_unique_mnemonics(menu)


def test_sad_entries_without_an_icon_elsewhere_get_none(side):
    """Move Up/Down/Top and Sort have no icon anywhere in axross: none is
    made up for them (the operator asked for the ones that exist)."""
    menu = side._build_menu(_bookmark(side, "home"))
    by_label = {a.text().replace("&", ""): a for a in _entries(menu)}
    for label in ("Move Up", "Move Down", "Move to Top"):
        assert by_label[label].icon().isNull(), label


def test_edge_empty_area_and_multi_selection_menus(side):
    empty = side._build_menu(None)
    assert _layout(empty) == ["New Group", "New Terminal Bookmark…", "|", "Sort"]
    _assert_unique_mnemonics(empty)
    assert all(_mnemonic(a.text()) for a in _entries(empty))
    nodes = [_bookmark(side, "home"), _bookmark(side, "tmp")]
    side._selection_for = lambda _node: nodes
    multi = side._build_menu(nodes[0])
    assert _layout(multi) == ["Move to Group", "|", "Delete 2 Selected…"]
    assert _entries(multi)[-1].property("axIcon") == "x"
    _assert_unique_mnemonics(multi)


def test_edge_group_names_in_move_to_group_stay_literal(side):
    side.manager.add_group("R&D")
    menu = side._build_menu(_bookmark(side, "home"))
    sub = next(a.menu() for a in _entries(menu) if a.menu() is not None
               and a.text().replace("&", "") == "Move to Group")
    assert any(a.text().strip() == "R&&D" for a in sub.actions())


def test_e2e_a_mnemonic_in_the_open_bookmark_menu_runs_its_entry(side):
    """Right-click on a bookmark row, press the underlined letter of Edit…
    in the real popup: the edit runs for that bookmark."""
    calls = []
    side._edit_node = lambda node: calls.append(node.name)
    item = side._tree.findItems("home", Qt.MatchFlag.MatchRecursive | Qt.MatchFlag.MatchExactly)[0]
    letter = _mnemonic(next(a.text() for a in _entries(side._build_menu(_bookmark(side, "home")))
                            if a.text().replace("&", "") == "Edit…"))
    assert letter  # an empty key would abort QTest

    def press() -> None:
        popup = QApplication.activePopupWidget()
        if popup is None:
            QTimer.singleShot(20, press)
            return
        QTest.keyClick(popup, letter)

    def close_left_open() -> None:
        popup = QApplication.activePopupWidget()
        if popup is not None:
            popup.close()

    QTimer.singleShot(50, press)
    QTimer.singleShot(3000, close_left_open)
    side._show_context_menu(side._tree.visualItemRect(item).center())
    pump()
    assert calls == ["home"]


def test_e2e_a_mnemonic_in_the_open_archive_menu_runs_its_entry(archive):
    _select(archive, "readme.txt")
    emitted = []
    archive.extract_all.connect(lambda: emitted.append("all"))
    letter = _mnemonic(next(a.text() for a in _entries(archive.build_context_menu())
                            if a.property("axCommand") == "extract-all"))

    def press() -> None:
        popup = QApplication.activePopupWidget()
        if popup is None:
            QTimer.singleShot(20, press)
            return
        QTest.keyClick(popup, letter)

    def close_left_open() -> None:
        popup = QApplication.activePopupWidget()
        if popup is not None:
            popup.close()

    QTimer.singleShot(50, press)
    QTimer.singleShot(3000, close_left_open)
    archive._show_context_menu(archive._tree.visualRect(archive._tree.currentIndex()).center())
    pump()
    assert emitted == ["all"]


def test_edge_fusion_underlines_the_mnemonic_without_alt():
    """Every theme but Classic runs on Fusion (ui/main_window.py
    _apply_theme); Fusion draws the "&" letter underlined at all times, not
    only while Alt is held - so no proxy style is needed. Classic keeps the
    desktop's own style and with it the desktop's choice."""
    from PyQt6.QtWidgets import QStyle, QStyleFactory

    fusion = QStyleFactory.create("Fusion")
    assert fusion.styleHint(QStyle.StyleHint.SH_UnderlineShortcut) == 1
