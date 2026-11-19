"""Bookmarks, tags and workspaces show a name as the file pane does.

Found in review (round 2 of the 2026-11 reviews, UI shell): a bookmark
takes the folder's name, and a folder on a server can be named
``inv<RLO>fdp.exe`` - the sidebar, its tooltip, the Bookmarks menu and
the Bookmark Manager showed the bidi override as it is (the name read
"invexe.pdf"), as did a tag in Tagged Files and a workspace's tab. The
Bookmark Manager's Location tooltip also took a path holding ``<b>`` for
markup, and Delete's question rendered a name with markup.

Now each shows a bidi override, control or invisible character as
U+FFFD; what is stored, renamed and navigated to is the name itself.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtWidgets import QApplication, QMenu, QMessageBox, QTreeWidgetItemIterator  # noqa: E402

import core.bookmarks as BM  # noqa: E402
from core.bookmarks import Bookmark, BookmarkManager  # noqa: E402

APP = QApplication.instance() or QApplication([])
RLO = "\u202e"
BAD = f"inv{RLO}fdp.exe"
SHOWN = "inv\ufffdfdp.exe"


def pump(seconds: float = 0.03) -> None:
    end = time.time() + seconds
    while time.time() < end:
        APP.processEvents()
        time.sleep(0.005)


@pytest.fixture
def mgr(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    assert BM.BOOKMARKS_FILE == BM._DEFAULT_BOOKMARKS_FILE
    m = BookmarkManager()
    group = m.add_group(f"grp{RLO}x")
    m.add(Bookmark(BAD, f"/srv/{BAD}"), group=group)
    m.add(Bookmark("plain", "/srv/<b>bold"))
    return m


def _texts(tree, column: int = 0) -> list[str]:
    out, it = [], QTreeWidgetItemIterator(tree)
    while it.value():
        out.append(it.value().text(column))
        out.append(it.value().toolTip(column))
        it += 1
    return out


def test_happy_a_plain_name_is_shown_as_it_is(mgr):
    from ui.bookmark_sidebar import BookmarkSidebar

    side = BookmarkSidebar(mgr)
    assert "plain" in _texts(side._tree)
    side.deleteLater()


def test_sad_the_sidebar_shows_the_override_as_u_fffd(mgr):
    from ui.bookmark_sidebar import BookmarkSidebar

    side = BookmarkSidebar(mgr)
    texts = _texts(side._tree)
    assert SHOWN in texts and "grp\ufffdx" in texts
    assert not any(RLO in t for t in texts)
    side.deleteLater()


def test_sad_the_bookmark_manager_shows_the_override_and_no_markup(mgr):
    from ui.bookmark_manager_dialog import COL_LOCATION, BookmarkManagerDialog

    dlg = BookmarkManagerDialog(mgr)
    texts = _texts(dlg._tree) + _texts(dlg._tree, COL_LOCATION)
    assert f"/srv/{SHOWN}" in texts
    assert not any(RLO in t for t in texts)
    tips = [t for t in _texts(dlg._tree, COL_LOCATION) if "bold" in t]
    assert tips and all("<b>" not in t for t in tips if t.startswith("<qt"))
    dlg.deleteLater()


def test_sad_the_bookmarks_menu_shows_the_override_as_u_fffd(mgr):
    from ui.main_window import MainWindow

    class Window:  # the two methods the menu needs
        _add_bookmark_nodes = MainWindow._add_bookmark_nodes

        def _navigate_bookmark(self, bookmark) -> None:
            pass

    menu = QMenu()
    Window()._add_bookmark_nodes(menu, mgr.tree())
    labels = [a.text() for a in menu.actions()]
    labels += [a.text() for a in menu.actions()[0].menu().actions()] if menu.actions()[0].menu() else []
    assert any(SHOWN in t for t in labels) and not any(RLO in t for t in labels)
    menu.deleteLater()


def test_edge_delete_asks_with_the_name_as_text(mgr):
    from ui.bookmark_manager_dialog import BookmarkManagerDialog

    dlg = BookmarkManagerDialog(mgr)
    asked = []
    with mock.patch("ui.bookmark_sidebar.QMessageBox.question",
                    lambda *a, **k: asked.append(a[2]) or QMessageBox.StandardButton.No):
        node = next(n for n in mgr.tree() if getattr(n, "name", "") == "plain")
        dlg._delete_node(node)
    assert len(asked) == 1
    assert asked[0].startswith("<qt") and "/srv/&lt;b&gt;bold" in asked[0]
    dlg.deleteLater()


def test_edge_tags_and_workspace_tabs():
    from ui.workspaces import tab_label

    assert tab_label(f"R&D{RLO}x") == "R&&D\ufffdx"
