"""Sorting the bookmarks of a group from its right-click menu.

Operator punch list item 23: "bookmarks support auf gruppe rechte maustaste
und sorting von bookmarks in der gruppe nach, name, alter, reverse,
kombinationen name+pfad".

A group's menu sorts its direct entries by name, by path, by name + path or
by age (when the bookmark was created), each also reversed. The sort is the
stored order. Groups stay in front of the bookmarks, by name. Bookmarks from
before the creation time was recorded load as undated and sort last.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtWidgets import QApplication  # noqa: E402

import core.bookmarks as BM  # noqa: E402
from core.bookmarks import Bookmark, BookmarkManager  # noqa: E402

APP = QApplication.instance() or QApplication([])


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    assert BM.BOOKMARKS_FILE == BM._DEFAULT_BOOKMARKS_FILE
    return tmp_path / ".config" / "axross" / "bookmarks.json"


@pytest.fixture
def mgr(home, monkeypatch):
    from types import SimpleNamespace

    clock = iter(range(1000, 2000, 10))
    # Only the store's own clock: the module-level name, not time.time itself.
    monkeypatch.setattr(
        BM, "time", SimpleNamespace(time=lambda: float(next(clock)), strftime=time.strftime)
    )
    m = BookmarkManager()
    grp = m.add_group("G")
    # created in this order: 1000, 1010, 1020, 1030
    for name, path in (("beta", "/z/b"), ("Alpha", "/y/a"), ("gamma", "/x/c"), ("alpha", "/w/a")):
        m.add(Bookmark(name, path), group=grp)
    m.add_group("zeta", parent=grp)
    m.add_group("Eta", parent=grp)
    return m


def _names(nodes) -> list[str]:
    return [n.name for n in nodes]


def _group(m, name="G"):
    return next(g for _d, g in m.groups() if g.name == name)


def _stored_children(home) -> list[str]:
    return [c["name"] for c in json.loads(home.read_text(encoding="utf-8"))[0]["children"]]


# --- happy -----------------------------------------------------------------


def test_happy_a_new_bookmark_records_when_it_was_created(home) -> None:
    before = time.time()
    m = BookmarkManager()
    m.add(Bookmark("x", "/x"))
    stamp = m.all()[0].created
    assert before <= stamp <= time.time()
    assert json.loads(home.read_text(encoding="utf-8"))[0]["created"] == stamp


def test_happy_sort_by_name_and_reverse_groups_first(mgr, home) -> None:
    grp = _group(mgr)
    assert mgr.sort_children(grp, "name") is True
    # case-insensitive; equal folded names keep a fixed order (upper first)
    assert _names(grp.children) == ["Eta", "zeta", "Alpha", "alpha", "beta", "gamma"]
    assert _stored_children(home) == _names(grp.children)
    mgr.sort_children(grp, "name", reverse=True)
    assert _names(grp.children) == ["zeta", "Eta", "gamma", "beta", "alpha", "Alpha"]
    assert _names(_group(BookmarkManager()).children) == _names(grp.children)


def test_happy_sort_by_path(mgr) -> None:
    grp = _group(mgr)
    mgr.sort_children(grp, "path")
    assert _names(grp.children)[2:] == ["alpha", "gamma", "Alpha", "beta"]  # /w /x /y /z


def test_happy_sort_by_name_then_path(mgr) -> None:
    grp = _group(mgr)
    mgr.sort_children(grp, "name_path")
    marks = [(n.name, n.path) for n in grp.children[2:]]
    # the two "alpha"s (case folded) ordered by path: /w/a before /y/a
    assert marks[:2] == [("alpha", "/w/a"), ("Alpha", "/y/a")]
    mgr.sort_children(grp, "name_path", reverse=True)
    marks = [(n.name, n.path) for n in grp.children[2:]]
    assert marks[-2:] == [("Alpha", "/y/a"), ("alpha", "/w/a")]


def test_happy_sort_by_age_oldest_and_newest_first(mgr) -> None:
    grp = _group(mgr)
    mgr.sort_children(grp, "name")
    mgr.sort_children(grp, "age")
    assert _names(grp.children)[2:] == ["beta", "Alpha", "gamma", "alpha"]
    mgr.sort_children(grp, "age", reverse=True)
    assert _names(grp.children)[2:] == ["alpha", "gamma", "Alpha", "beta"]


@pytest.mark.parametrize("key", ["age", "path"])
def test_happy_groups_stay_a_to_z_when_age_or_path_is_reversed(mgr, key) -> None:
    # A group has no age and no path: reversing those orders must not
    # flip the groups (the docstring promises them by name).
    grp = _group(mgr)
    mgr.sort_children(grp, key, reverse=True)
    assert _names(grp.children)[:2] == ["Eta", "zeta"]
    mgr.sort_children(grp, key)
    assert _names(grp.children)[:2] == ["Eta", "zeta"]


@pytest.mark.parametrize("key", ["name", "name_path"])
def test_happy_name_orders_reverse_the_groups_too(mgr, key) -> None:
    # Name (Reverse) is Z-A for everything named, groups included; they
    # still come before the bookmarks.
    grp = _group(mgr)
    mgr.sort_children(grp, key, reverse=True)
    assert _names(grp.children)[:2] == ["zeta", "Eta"]


def test_happy_the_docstring_states_the_group_rule() -> None:
    doc = " ".join(BookmarkManager.sort_children.__doc__.split())
    assert "Groups always come first" in doc
    assert "name keys reverse them too" in doc


def test_happy_the_group_menu_sorts_through_the_real_sidebar(mgr, home) -> None:
    from ui.bookmark_sidebar import BookmarkSidebar

    side = BookmarkSidebar(mgr)
    try:
        grp = _group(mgr)
        menu = side._build_menu(grp)
        sort_menu = next(a.menu() for a in menu.actions() if a.text().replace("&", "") == "Sort")
        labels = [a.text() for a in sort_menu.actions() if not a.isSeparator()]
        assert labels == [
            "By Name",
            "By Name (Reverse)",
            "By Path",
            "By Path (Reverse)",
            "By Name + Path",
            "By Name + Path (Reverse)",
            "By Age (Oldest First)",
            "By Age (Newest First)",
        ]
        changed = []
        side.changed.connect(lambda: changed.append(1))
        next(a for a in sort_menu.actions() if a.text() == "By Age (Newest First)").trigger()
        # Groups stay A-Z: an age order says nothing about a group.
        assert _stored_children(home) == ["Eta", "zeta", "alpha", "gamma", "Alpha", "beta"]
        assert changed == [1]
        g_item = side._tree.topLevelItem(0)
        assert [g_item.child(i).text(0) for i in range(g_item.childCount())] == _stored_children(
            home
        )
    finally:
        side.deleteLater()


# --- sad -------------------------------------------------------------------


def test_sad_an_unknown_sort_key_changes_nothing(mgr, home) -> None:
    grp = _group(mgr)
    before = _stored_children(home)
    with pytest.raises(ValueError):
        mgr.sort_children(grp, "size")
    assert _stored_children(home) == before


def test_sad_a_group_not_in_the_tree_is_refused(mgr) -> None:
    from core.bookmarks import BookmarkGroup

    with pytest.raises(KeyError):
        mgr.sort_children(BookmarkGroup("stranger"), "name")


def test_sad_old_bookmarks_without_a_date_load_and_sort_last(home) -> None:
    home.parent.mkdir(parents=True)
    home.write_text(
        json.dumps(
            [
                {"name": "old", "path": "/old", "backend_name": "Local"},
                {"name": "new", "path": "/new", "backend_name": "Local", "created": 50.0},
                {"name": "older", "path": "/older", "backend_name": "Local"},
                {"name": "newer", "path": "/newer", "backend_name": "Local", "created": 60},
            ]
        ),
        encoding="utf-8",
    )
    m = BookmarkManager()
    assert [b.created for b in m.all()] == [0.0, 50.0, 0.0, 60.0]
    m.sort_children(None, "age")
    assert _names(m.tree()) == ["new", "newer", "old", "older"]
    m.sort_children(None, "age", reverse=True)
    assert _names(m.tree()) == ["newer", "new", "old", "older"]  # undated stay last


def test_sad_a_hostile_created_value_is_treated_as_undated(home) -> None:
    home.parent.mkdir(parents=True)
    raw = [
        {"name": n, "path": f"/{n}", "created": v}
        for n, v in (("s", "yesterday"), ("neg", -5), ("inf", 1e400), ("b", True), ("nan", None))
    ]
    home.write_text(json.dumps(raw).replace("Infinity", "1e400"), encoding="utf-8")
    m = BookmarkManager()
    assert _names(m.all()) == ["s", "neg", "inf", "b", "nan"]
    assert all(b.created == 0.0 for b in m.all())


# --- edge ------------------------------------------------------------------


def test_edge_sorting_an_already_sorted_group_does_not_write(mgr, home) -> None:
    grp = _group(mgr)
    mgr.sort_children(grp, "name")
    stamp = home.stat().st_mtime_ns
    time.sleep(0.01)
    assert mgr.sort_children(grp, "name") is False
    assert home.stat().st_mtime_ns == stamp


def test_edge_an_empty_group_sorts_to_nothing(mgr) -> None:
    empty = _group(mgr, "zeta")
    assert mgr.sort_children(empty, "age") is False


def test_edge_editing_a_bookmark_keeps_its_creation_time(mgr) -> None:
    from ui.bookmark_edit_dialog import BookmarkEditDialog

    grp = _group(mgr)
    beta = next(n for n in grp.children if n.name == "beta")
    dialog = BookmarkEditDialog(beta)
    dialog._name_edit.setText("beta2")
    mgr.update_bookmark(beta, dialog.result_bookmark())
    dialog.deleteLater()
    edited = next(n for n in _group(BookmarkManager()).children if n.name == "beta2")
    assert edited.created == 1000.0


def test_edge_top_level_sort_from_the_empty_space_menu(mgr) -> None:
    from ui.bookmark_sidebar import BookmarkSidebar

    mgr.add(Bookmark("b-top", "/btop"))
    mgr.add(Bookmark("a-top", "/atop"))
    side = BookmarkSidebar(mgr)
    try:
        menu = side._build_menu(None)
        sort_menu = next(a.menu() for a in menu.actions() if a.text().replace("&", "") == "Sort")
        next(a for a in sort_menu.actions() if a.text() == "By Name").trigger()
        assert _names(mgr.tree()) == ["G", "a-top", "b-top"]
    finally:
        side.deleteLater()


def test_edge_the_group_reversing_keys_are_known_sort_keys() -> None:
    # Derived, not typed twice: a renamed key must not silently stop
    # reversing the groups.
    assert BM._GROUP_REVERSING_KEYS <= set(BM.SORT_KEYS)
    assert {"name", "name_path"} == set(BM._GROUP_REVERSING_KEYS)
