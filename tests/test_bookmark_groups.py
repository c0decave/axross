"""Bookmark tree: groups, ordering, colours, persistence."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import core.bookmarks as BM
from core.bookmarks import Bookmark, BookmarkGroup, BookmarkManager


class _Base(unittest.TestCase):
    def setUp(self) -> None:
        self._orig = BM.BOOKMARKS_FILE
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.file = Path(self._tmp.name) / "bookmarks.json"
        BM.BOOKMARKS_FILE = self.file
        self.addCleanup(setattr, BM, "BOOKMARKS_FILE", self._orig)
        self.m = BookmarkManager()

    def bm(self, name: str, path: str | None = None, **kw) -> Bookmark:
        return Bookmark(name=name, path=path or f"/{name}", **kw)

    def names(self, nodes) -> list[str]:
        return [n.name for n in nodes]

    def reload(self) -> BookmarkManager:
        return BookmarkManager()


class GroupBasicsTest(_Base):
    def test_group_holds_bookmarks_and_keeps_flat_all_in_tree_order(self) -> None:
        g = self.m.add_group("Work")
        self.m.add(self.bm("a"))
        self.m.add(self.bm("b"), group=g)
        self.m.add(self.bm("c"))
        self.assertEqual(self.names(self.m.tree()), ["Work", "a", "c"])
        self.assertEqual(self.names(g.children), ["b"])
        self.assertEqual(self.names(self.m.all()), ["b", "a", "c"])

    def test_duplicates_are_detected_across_groups(self) -> None:
        g = self.m.add_group("G")
        self.m.add(self.bm("a", "/x"), group=g)
        self.m.add(self.bm("again", "/x"))
        self.assertEqual(len(self.m.all()), 1)

    def test_find_returns_the_bookmark_add_would_call_a_duplicate(self) -> None:
        g = self.m.add_group("G")
        self.m.add(self.bm("a", "/x"), group=g)
        found = self.m.find("/x", "Local")
        self.assertIs(found, g.children[0])
        self.assertFalse(self.m.add(self.bm("again", "/x")))

    def test_find_returns_none_for_a_path_never_bookmarked(self) -> None:
        self.m.add(self.bm("a", "/x"))
        self.assertIsNone(self.m.find("/y", "Local"))
        self.assertIsNone(BookmarkManager().find("", ""))

    def test_find_tells_the_same_path_on_another_backend_apart(self) -> None:
        self.m.add(self.bm("a", "/x"))
        self.assertIsNone(self.m.find("/x", "u@host"))
        self.assertTrue(self.m.add(self.bm("remote", "/x", backend_name="u@host")))
        self.assertEqual(self.m.find("/x", "u@host").name, "remote")

    def test_groups_nest_without_limit_in_the_api(self) -> None:
        g1 = self.m.add_group("A")
        g2 = self.m.add_group("B", parent=g1)
        g3 = self.m.add_group("C", parent=g2)
        self.assertEqual([(d, g.name) for d, g in self.m.groups()], [(0, "A"), (1, "B"), (2, "C")])
        self.assertIs(self.m.parent_of(g3), g2)
        self.assertIsNone(self.m.parent_of(g1))

    def test_flat_index_api_still_works(self) -> None:
        g = self.m.add_group("G")
        self.m.add(self.bm("a"), group=g)
        self.m.add(self.bm("b"))
        self.m.update(1, self.bm("b2", "/b2"))
        self.assertEqual(self.names(self.m.all()), ["a", "b2"])
        self.m.remove(0)
        self.assertEqual(self.names(self.m.all()), ["b2"])
        self.assertEqual(self.names(g.children), [])

    def test_bookmarks_property_is_the_flat_list(self) -> None:
        g = self.m.add_group("G")
        self.m.add(self.bm("a"), group=g)
        self.assertEqual(self.names(self.m._bookmarks), ["a"])  # noqa: SLF001

    def test_update_bookmark_keeps_position_and_can_change_group(self) -> None:
        g = self.m.add_group("G")
        a, b = self.bm("a"), self.bm("b")
        self.m.add(a)
        self.m.add(b)
        self.m.update_bookmark(a, self.bm("a2", "/a2"))
        self.assertEqual(self.names(self.m.tree()[1:]), ["a2", "b"])
        new = self.m.tree()[1]
        self.m.update_bookmark(new, self.bm("a3", "/a3"), group=g)
        self.assertEqual(self.names(g.children), ["a3"])
        self.assertEqual(self.names(self.m.tree()), ["G", "b"])

    def test_update_unknown_bookmark_raises(self) -> None:
        with self.assertRaises(KeyError):
            self.m.update_bookmark(self.bm("ghost"), self.bm("x"))

    def test_update_group_changes_name_icon_colour(self) -> None:
        g = self.m.add_group("G")
        self.m.update_group(g, name="H", icon_name="star", color="#ff0000")
        again = self.reload().tree()[0]
        self.assertEqual((again.name, again.icon_name, again.color), ("H", "star", "#ff0000"))

    def test_update_group_rejects_a_bad_colour(self) -> None:
        g = self.m.add_group("G")
        self.m.update_group(g, color="red; DROP")
        self.assertEqual(g.color, "")


class MoveTest(_Base):
    def setUp(self) -> None:
        super().setUp()
        self.a, self.b, self.c = self.bm("a"), self.bm("b"), self.bm("c")
        for x in (self.a, self.b, self.c):
            self.m.add(x)

    def test_move_by_up_and_down(self) -> None:
        self.assertTrue(self.m.move_by(self.c, -1))
        self.assertEqual(self.names(self.m.tree()), ["a", "c", "b"])
        self.assertTrue(self.m.move_by(self.a, +1))
        self.assertEqual(self.names(self.m.tree()), ["c", "a", "b"])

    def test_move_by_at_the_edges_is_a_noop(self) -> None:
        self.assertFalse(self.m.move_by(self.a, -1))
        self.assertFalse(self.m.move_by(self.c, +1))
        self.assertEqual(self.names(self.m.tree()), ["a", "b", "c"])

    def test_move_to_top(self) -> None:
        self.m.move_to_top(self.c)
        self.assertEqual(self.names(self.m.tree()), ["c", "a", "b"])

    def test_move_into_a_group_and_out_again(self) -> None:
        g = self.m.add_group("G")
        self.m.move(self.b, g)
        self.assertEqual(self.names(g.children), ["b"])
        self.m.move(self.b, None, 0)
        self.assertEqual(self.names(self.m.tree()), ["b", "a", "c", "G"])

    def test_move_index_is_relative_to_the_list_before_the_move(self) -> None:
        # a b c -> drop a "below c" (index 3): a ends up last
        self.m.move(self.a, None, 3)
        self.assertEqual(self.names(self.m.tree()), ["b", "c", "a"])
        # drop c "above b" (index 0)
        self.m.move(self.c, None, 0)
        self.assertEqual(self.names(self.m.tree()), ["c", "b", "a"])

    def test_move_to_own_slot_changes_nothing(self) -> None:
        self.m.move(self.b, None, 1)
        self.m.move(self.b, None, 2)
        self.assertEqual(self.names(self.m.tree()), ["a", "b", "c"])

    def test_a_group_cannot_move_into_itself_or_a_descendant(self) -> None:
        g1 = self.m.add_group("A")
        g2 = self.m.add_group("B", parent=g1)
        with self.assertRaises(ValueError):
            self.m.move(g1, g1)
        with self.assertRaises(ValueError):
            self.m.move(g1, g2)
        self.assertIs(self.m.parent_of(g2), g1)

    def test_move_of_an_unknown_node_raises(self) -> None:
        with self.assertRaises(KeyError):
            self.m.move(self.bm("ghost"), None)

    def test_out_of_range_index_clamps(self) -> None:
        self.m.move(self.a, None, 99)
        self.assertEqual(self.names(self.m.tree()), ["b", "c", "a"])
        self.m.move(self.a, None, -5)
        self.assertEqual(self.names(self.m.tree()), ["a", "b", "c"])

    def test_groups_move_with_their_content(self) -> None:
        g = self.m.add_group("G")
        self.m.move(self.a, g)
        self.m.move(g, None, 0)
        self.assertEqual(self.names(self.m.tree()), ["G", "b", "c"])
        self.assertEqual(self.names(g.children), ["a"])


class RemoveGroupTest(_Base):
    def test_children_move_up_into_the_groups_slot(self) -> None:
        a, b = self.bm("a"), self.bm("b")
        self.m.add(a)
        g = self.m.add_group("G")
        self.m.add(self.bm("in1"), group=g)
        inner = self.m.add_group("Inner", parent=g)
        self.m.add(self.bm("in2"), group=g)
        self.m.add(b)
        self.m.remove_group(g)
        self.assertEqual(self.names(self.m.tree()), ["a", "in1", "Inner", "in2", "b"])
        self.assertIs(self.m.parent_of(inner), None)

    def test_nested_group_removal_lifts_into_the_parent_group(self) -> None:
        g = self.m.add_group("G")
        inner = self.m.add_group("Inner", parent=g)
        self.m.add(self.bm("deep"), group=inner)
        self.m.remove_group(inner)
        self.assertEqual(self.names(g.children), ["deep"])

    def test_removing_an_unknown_group_raises(self) -> None:
        with self.assertRaises(KeyError):
            self.m.remove_group(BookmarkGroup(name="ghost"))


class PersistenceTest(_Base):
    def test_roundtrip_keeps_structure_order_icons_colours_and_state(self) -> None:
        g = self.m.add_group("Work", icon_name="briefcase", color="#3498db")
        inner = self.m.add_group("Prod", parent=g)
        self.m.add(self.bm("logs", icon_name="server", color="#e74c3c"), group=inner)
        self.m.add(self.bm("home"))
        self.m.set_expanded(g, False)
        again = self.reload()
        top = again.tree()
        self.assertEqual(self.names(top), ["Work", "home"])
        work = top[0]
        self.assertEqual(
            (work.icon_name, work.color, work.expanded), ("briefcase", "#3498db", False)
        )
        self.assertEqual(self.names(work.children), ["Prod"])
        logs = work.children[0].children[0]
        self.assertEqual((logs.icon_name, logs.color), ("server", "#e74c3c"))

    def test_old_flat_files_still_load(self) -> None:
        self.file.write_text(
            json.dumps([{"name": "a", "path": "/a", "icon_name": "star"}]), encoding="utf-8"
        )
        m = self.reload()
        self.assertEqual(self.names(m.all()), ["a"])
        self.assertEqual(m.all()[0].color, "")

    def test_new_files_do_not_break_the_old_loader_shape_for_plain_bookmarks(self) -> None:
        self.m.add(self.bm("a"))
        raw = json.loads(self.file.read_text())
        self.assertEqual(raw[0]["name"], "a")
        self.assertNotIn("type", raw[0])

    def test_hostile_colour_and_icon_values_are_sanitised(self) -> None:
        self.file.write_text(
            json.dumps(
                [
                    {"name": "a", "path": "/a", "color": "red\nx", "icon_name": "../../x"},
                    {"type": "group", "name": "g", "color": 5, "icon_name": "<b>", "children": []},
                ]
            ),
            encoding="utf-8",
        )
        m = self.reload()
        bm = m.all()[0]
        self.assertEqual(bm.color, "")
        self.assertEqual(bm.icon_name, "x")
        g = m.tree()[1]
        self.assertEqual(g.color, "")
        self.assertEqual(g.icon_name, "b")

    def test_malformed_group_entries_are_dropped_not_fatal(self) -> None:
        self.file.write_text(
            json.dumps(
                [
                    {"type": "group", "children": []},
                    {"type": "group", "name": 5, "children": []},
                    {"type": "group", "name": "ok", "children": "nope"},
                    "junk",
                    {"name": "a", "path": "/a"},
                ]
            ),
            encoding="utf-8",
        )
        m = self.reload()
        self.assertEqual(self.names(m.tree()), ["ok", "a"])
        self.assertEqual(m.tree()[0].children, [])

    def test_absurd_nesting_is_cut_off(self) -> None:
        node: dict = {"type": "group", "name": "leaf", "children": []}
        for i in range(200):
            node = {"type": "group", "name": f"g{i}", "children": [node]}
        self.file.write_text(json.dumps([node]), encoding="utf-8")
        m = self.reload()
        depth, cur = 0, m.tree()[0]
        while cur.children:
            cur = cur.children[0]
            depth += 1
        self.assertLessEqual(depth, 32)

    def test_file_stays_private(self) -> None:
        self.m.add(self.bm("a"))
        self.assertEqual(self.file.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
