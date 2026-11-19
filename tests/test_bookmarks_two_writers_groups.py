"""Two BookmarkManagers on one file (two axross windows, a script) keep
each other's group changes.

Reproduced 2026-11-19 (independent review): the save's merge took the
other writer's bookmark additions, removals and edits, but of the groups
only the ones it added. A group removed, renamed or recoloured in window
A, or a bookmark moved into a group there, was undone by the next save of
window B. Now the merge is three-way for groups too: what B did not change
since it last read the file takes A's version - removals, renames (a new
group the bookmarks moved into), moves between groups, group attributes
and the order within a group.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import bookmarks as B  # noqa: E402


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    monkeypatch.setattr(B, "_bookmarks_file", lambda: tmp_path / "bookmarks.json")
    return tmp_path


def names(mgr):
    def walk(nodes):
        out = []
        for n in nodes:
            if isinstance(n, B.BookmarkGroup):
                out.append((n.name, walk(n.children)))
            else:
                out.append(n.name)
        return out
    return walk(mgr.tree())


def _group(mgr, name):
    return next(g for _d, g in mgr.groups() if g.name == name)


def test_happy_a_group_removed_in_one_window_stays_removed(home):
    a = B.BookmarkManager()
    a.add(B.Bookmark(name="x", path="/x"))
    g = a.add_group("Work")
    a.add(B.Bookmark(name="w", path="/w"), group=g)
    b = B.BookmarkManager()
    a.remove_group(g)  # its bookmarks move up into its place
    b.add(B.Bookmark(name="y", path="/y"))
    assert names(B.BookmarkManager()) == ["x", "w", "y"]


def test_happy_a_move_into_a_group_is_kept(home):
    a = B.BookmarkManager()
    x = B.Bookmark(name="x", path="/x")
    a.add(x)
    g = a.add_group("Work")
    b = B.BookmarkManager()
    a.move(x, g)
    b.add(B.Bookmark(name="y", path="/y"))
    assert names(B.BookmarkManager()) == [("Work", ["x"]), "y"]


def test_happy_a_group_rename_is_kept_in_its_place(home):
    a = B.BookmarkManager()
    a.add(B.Bookmark(name="first", path="/f"))
    g = a.add_group("Work")
    a.add(B.Bookmark(name="w", path="/w"), group=g)
    a.add(B.Bookmark(name="last", path="/l"))
    b = B.BookmarkManager()
    a.update_group(g, name="Job")
    b.add(B.Bookmark(name="y", path="/y"))
    assert names(B.BookmarkManager()) == ["first", ("Job", ["w"]), "last", "y"]


def test_happy_group_attributes_from_the_other_window_are_kept(home):
    a = B.BookmarkManager()
    g = a.add_group("Work")
    b = B.BookmarkManager()
    a.update_group(g, color="#ff0000", icon_name="star")
    b.add(B.Bookmark(name="y", path="/y"))
    fresh = _group(B.BookmarkManager(), "Work")
    assert (fresh.color, fresh.icon_name) == ("#ff0000", "star")


def test_happy_a_sort_in_the_other_window_is_kept(home):
    a = B.BookmarkManager()
    g = a.add_group("Work")
    for name in ("c", "a", "b"):
        a.add(B.Bookmark(name=name, path=f"/{name}"), group=g)
    b = B.BookmarkManager()
    a.sort_children(g, "name")
    b.add(B.Bookmark(name="y", path="/y"))
    assert names(B.BookmarkManager()) == [("Work", ["a", "b", "c"]), "y"]


def test_sad_this_windows_own_group_change_wins(home):
    """Both changed the same group: this manager's version is written."""
    a = B.BookmarkManager()
    g = a.add_group("Work")
    b = B.BookmarkManager()
    a.update_group(g, color="#ff0000")
    b.update_group(_group(b, "Work"), color="#00ff00")
    assert _group(B.BookmarkManager(), "Work").color == "#00ff00"


def test_sad_a_group_removed_there_but_added_to_here_is_kept(home):
    """Window A removed an empty group while window B put a bookmark into
    it: B's bookmark is not lost, the group stays."""
    a = B.BookmarkManager()
    g = a.add_group("Inbox")
    b = B.BookmarkManager()
    a.remove_group(g)
    b.add(B.Bookmark(name="new", path="/new"), group=_group(b, "Inbox"))
    assert names(B.BookmarkManager()) == [("Inbox", ["new"])]


def test_edge_a_move_here_beats_a_move_there(home):
    a = B.BookmarkManager()
    x = B.Bookmark(name="x", path="/x")
    a.add(x)
    one, two = a.add_group("One"), a.add_group("Two")
    b = B.BookmarkManager()
    a.move(x, one)
    b.move(next(m for m in b.all() if m.name == "x"), _group(b, "Two"))
    assert names(B.BookmarkManager()) == [("One", []), ("Two", ["x"])]


def test_edge_a_nested_group_removed_there_lifts_its_bookmarks(home):
    a = B.BookmarkManager()
    outer = a.add_group("Outer")
    inner = a.add_group("Inner", parent=outer)
    a.add(B.Bookmark(name="i", path="/i"), group=inner)
    b = B.BookmarkManager()
    a.remove_group(inner)
    b.add(B.Bookmark(name="y", path="/y"))
    assert names(B.BookmarkManager()) == [("Outer", ["i"]), "y"]
