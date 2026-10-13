"""Bookmark sidebar as a tree: groups, ordering, drag & drop, colours."""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import core.bookmarks as BM  # noqa: E402
from core.bookmarks import Bookmark, BookmarkManager  # noqa: E402


def _close(a: str, b: str, tol: int = 4) -> bool:
    """Colours equal within *tol* per channel (pixmaps get resampled)."""
    ca = [int(a[i : i + 2], 16) for i in (1, 3, 5)]
    cb = [int(b[i : i + 2], 16) for i in (1, 3, 5)]
    return all(abs(x - y) <= tol for x, y in zip(ca, cb, strict=True))


def _dominant(pixmap) -> str:
    img = pixmap.toImage()
    counts: dict[str, int] = {}
    for x in range(img.width()):
        for y in range(img.height()):
            c = img.pixelColor(x, y)
            if c.alpha() > 200:
                counts[c.name()] = counts.get(c.name(), 0) + 1
    return max(counts, key=counts.get) if counts else ""


class _Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            from PyQt6.QtWidgets import QApplication
        except ImportError:
            raise unittest.SkipTest("PyQt6 not installed")
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        self._orig = BM.BOOKMARKS_FILE
        self._tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self._tmp, ignore_errors=True)
        BM.BOOKMARKS_FILE = Path(self._tmp) / "bookmarks.json"
        self.addCleanup(setattr, BM, "BOOKMARKS_FILE", self._orig)
        self.m = BookmarkManager()
        self.work = self.m.add_group("Work", icon_name="briefcase", color="#3498db")
        self.m.add(
            Bookmark("logs", "/var/log", icon_name="server", color="#e74c3c"), group=self.work
        )
        self.m.add(Bookmark("etc", "/etc"), group=self.work)
        self.m.add(Bookmark("home", "/home"))
        self.m.add(Bookmark("tmp", "/tmp"))
        from ui.bookmark_sidebar import BookmarkSidebar

        self.side = BookmarkSidebar(self.m)
        self.addCleanup(self.side.deleteLater)
        self.side.resize(300, 500)
        self.side.show()
        self.app.processEvents()
        self.tree = self.side._tree
        self.nav: list = []
        self.side.navigate_requested.connect(self.nav.append)
        self.changed = 0
        self.side.changed.connect(lambda: setattr(self, "changed", self.changed + 1))

    def names(self, nodes) -> list[str]:
        return [n.name for n in nodes]

    def item(self, name: str):
        from PyQt6.QtCore import Qt
        from PyQt6.QtWidgets import QTreeWidgetItemIterator

        it = QTreeWidgetItemIterator(self.tree)
        while it.value():
            if it.value().text(0) == name:
                return it.value()
            it += 1
        self.fail(f"no item {name!r}")
        _ = Qt

    def click(self, item) -> None:
        from PyQt6.QtCore import Qt
        from PyQt6.QtTest import QTest

        QTest.mouseClick(
            self.tree.viewport(),
            Qt.MouseButton.LeftButton,
            Qt.KeyboardModifier.NoModifier,
            self.tree.visualItemRect(item).center()
            + __import__("PyQt6.QtCore", fromlist=["QPoint"]).QPoint(20, 0),
        )
        self.app.processEvents()


class StructureTest(_Base):
    def test_tree_mirrors_the_manager(self) -> None:
        top = [self.tree.topLevelItem(i).text(0) for i in range(self.tree.topLevelItemCount())]
        self.assertEqual(top, ["Work", "home", "tmp"])
        work = self.item("Work")
        self.assertEqual([work.child(i).text(0) for i in range(work.childCount())], ["logs", "etc"])

    def test_group_expanded_state_comes_from_the_model(self) -> None:
        self.assertTrue(self.item("Work").isExpanded())
        self.m.set_expanded(self.work, False)
        self.side.rebuild()
        self.assertFalse(self.item("Work").isExpanded())

    def test_icons_use_the_chosen_icon_and_colour(self) -> None:
        logs = self.item("logs").icon(0).pixmap(22, 22)
        self.assertTrue(_close(_dominant(logs), "#e74c3c"), _dominant(logs))
        grp = self.item("Work").icon(0).pixmap(22, 22)
        self.assertTrue(_close(_dominant(grp), "#3498db"), _dominant(grp))

    def test_markup_in_names_is_shown_literally_and_tooltips_are_escaped(self) -> None:
        self.m.add(
            Bookmark(
                "<b>x</b>",
                "/evil",
            )
        )
        self.side.rebuild()
        item = self.item("<b>x</b>")
        self.assertIn("&lt;b&gt;", item.toolTip(0))
        self.assertNotIn("<b>", item.toolTip(0))

    def test_empty_state_hint(self) -> None:
        for _d, g in list(self.m.groups()):
            self.m.remove_group(g)
        while self.m.all():
            self.m.remove(0)
        self.side.rebuild()
        self.assertTrue(self.side._hint.isVisible())
        self.assertFalse(self.tree.isVisible())
        self.m.add(Bookmark("a", "/a"))
        self.side.rebuild()
        self.assertFalse(self.side._hint.isVisible())


class ClickTest(_Base):
    def test_clicking_a_bookmark_navigates(self) -> None:
        self.click(self.item("home"))
        self.assertEqual(self.names(self.nav), ["home"])

    def test_clicking_a_group_toggles_it_and_remembers_the_state(self) -> None:
        work = self.item("Work")
        self.click(work)
        self.assertFalse(work.isExpanded())
        self.assertEqual(self.nav, [])
        self.assertFalse(BookmarkManager().tree()[0].expanded)
        self.click(self.item("Work"))
        self.assertTrue(BookmarkManager().tree()[0].expanded)

    def test_clicking_the_branch_arrow_toggles_exactly_once(self) -> None:
        from PyQt6.QtCore import QPoint, Qt
        from PyQt6.QtTest import QTest

        work = self.item("Work")
        rect = self.tree.visualItemRect(work)
        before = work.isExpanded()
        QTest.mouseClick(
            self.tree.viewport(),
            Qt.MouseButton.LeftButton,
            Qt.KeyboardModifier.NoModifier,
            QPoint(rect.left() + 6, rect.center().y()),
        )
        self.app.processEvents()
        self.assertNotEqual(self.item("Work").isExpanded(), before)

    def test_a_group_click_does_not_toggle_twice(self) -> None:
        work = self.item("Work")
        before = work.isExpanded()
        self.click(work)
        self.assertNotEqual(work.isExpanded(), before)


class MenuTest(_Base):
    def actions(self, menu) -> dict:
        return {a.text().replace("&", ""): a for a in menu.actions() if a.text()}

    def test_bookmark_menu(self) -> None:
        acts = self.actions(self.side._build_menu(self.m.all()[0]))
        for want in ("Edit…", "Move Up", "Move Down", "Move to Top", "Delete"):
            self.assertIn(want, acts)

    def test_group_menu(self) -> None:
        acts = self.actions(self.side._build_menu(self.work))
        for want in (
            "New Group Inside",
            "Edit…",
            "Move Up",
            "Move Down",
            "Move to Top",
            "Delete Group",
        ):
            self.assertIn(want, acts)

    def test_empty_area_menu(self) -> None:
        self.assertIn("New Group", self.actions(self.side._build_menu(None)))

    def test_move_entries_are_disabled_at_the_edges(self) -> None:
        first = self.actions(self.side._build_menu(self.work))
        self.assertFalse(first["Move Up"].isEnabled())
        self.assertFalse(first["Move to Top"].isEnabled())
        self.assertTrue(first["Move Down"].isEnabled())
        last = self.actions(self.side._build_menu(self.m.tree()[-1]))
        self.assertFalse(last["Move Down"].isEnabled())
        self.assertTrue(last["Move Up"].isEnabled())


class MoveTest(_Base):
    def test_move_up_and_down_reorder_and_notify(self) -> None:
        home = self.m.tree()[1]
        self.side._move_by(home, -1)
        self.assertEqual(self.names(self.m.tree()), ["home", "Work", "tmp"])
        self.assertEqual(self.item("home"), self.tree.topLevelItem(0))
        self.assertEqual(self.changed, 1)
        self.side._move_by(home, +1)
        self.assertEqual(self.names(self.m.tree()), ["Work", "home", "tmp"])

    def test_move_to_top(self) -> None:
        self.side._move_to_top(self.m.tree()[2])
        self.assertEqual(self.names(self.m.tree())[0], "tmp")

    def test_a_move_at_the_edge_changes_nothing_and_does_not_notify(self) -> None:
        self.side._move_by(self.m.tree()[0], -1)
        self.assertEqual(self.changed, 0)


class DragDropTest(_Base):
    def test_drop_into_a_group_appends(self) -> None:
        home = self.m.tree()[1]
        self.side._apply_drop(home, self.work, "into")
        self.assertEqual(self.names(self.work.children), ["logs", "etc", "home"])
        self.assertEqual(self.names(self.m.tree()), ["Work", "tmp"])
        self.assertEqual(self.changed, 1)

    def test_drop_above_and_below_a_sibling(self) -> None:
        tmp = self.m.tree()[2]
        self.side._apply_drop(tmp, self.m.tree()[0], "above")
        self.assertEqual(self.names(self.m.tree()), ["tmp", "Work", "home"])
        self.side._apply_drop(self.m.tree()[0], self.m.tree()[2], "below")
        self.assertEqual(self.names(self.m.tree()), ["Work", "home", "tmp"])

    def test_drop_inside_a_group_between_its_children(self) -> None:
        etc = self.work.children[1]
        logs = self.work.children[0]
        home = self.m.tree()[1]
        self.side._apply_drop(home, logs, "below")
        self.assertEqual(self.names(self.work.children), ["logs", "home", "etc"])
        self.side._apply_drop(etc, logs, "above")
        self.assertEqual(self.names(self.work.children), ["etc", "logs", "home"])

    def test_dropping_onto_a_bookmark_inserts_after_it(self) -> None:
        tmp = self.m.tree()[2]
        home = self.m.tree()[1]
        self.side._apply_drop(self.work.children[0], home, "into")
        self.assertEqual(self.names(self.m.tree()), ["Work", "home", "logs", "tmp"])
        _ = tmp

    def test_a_group_cannot_be_dropped_into_its_own_child(self) -> None:
        inner = self.m.add_group("Inner", parent=self.work)
        self.side.rebuild()
        self.side._apply_drop(self.work, inner, "into")  # must not raise or change
        self.assertIs(self.m.parent_of(inner), self.work)
        self.assertEqual(self.changed, 0)

    def test_dropping_a_node_onto_itself_is_a_noop(self) -> None:
        home = self.m.tree()[1]
        self.side._apply_drop(home, home, "above")
        self.side._apply_drop(home, home, "into")
        self.assertEqual(self.names(self.m.tree()), ["Work", "home", "tmp"])

    def test_a_drop_on_empty_space_moves_to_the_end_of_the_top_level(self) -> None:
        self.side._apply_drop(self.work.children[0], None, "into")
        self.assertEqual(self.names(self.m.tree())[-1], "logs")

    def test_a_real_drop_event_is_routed_to_the_manager(self) -> None:
        from PyQt6.QtCore import QEvent, QPoint, QPointF, Qt
        from PyQt6.QtGui import QDragMoveEvent, QDropEvent

        home_item = self.item("home")
        work_item = self.item("Work")
        mime = self.tree.mimeData([home_item])
        target = self.tree.visualItemRect(work_item).center()
        move = QDragMoveEvent(
            target,
            Qt.DropAction.MoveAction,
            mime,
            Qt.MouseButton.LeftButton,
            Qt.KeyboardModifier.NoModifier,
            QEvent.Type.DragMove,
        )
        self.tree.setCurrentItem(home_item)
        self.tree.dragMoveEvent(move)
        drop = QDropEvent(
            QPointF(target),
            Qt.DropAction.MoveAction,
            mime,
            Qt.MouseButton.LeftButton,
            Qt.KeyboardModifier.NoModifier,
        )
        self.tree.dropEvent(drop)
        self.app.processEvents()
        self.assertIn("home", self.names(self.work.children))
        _ = QPoint


class EditDeleteTest(_Base):
    def test_delete_bookmark_asks_and_removes(self) -> None:
        from PyQt6.QtWidgets import QMessageBox

        bm = self.m.tree()[1]
        with mock.patch("ui.bookmark_sidebar.QMessageBox.question") as ask:
            ask.return_value = QMessageBox.StandardButton.No
            self.side._delete_node(bm)
        self.assertIn("home", self.names(self.m.all()))
        with mock.patch("ui.bookmark_sidebar.QMessageBox.question") as ask:
            ask.return_value = QMessageBox.StandardButton.Yes
            self.side._delete_node(bm)
        self.assertNotIn("home", self.names(self.m.all()))
        self.assertEqual(self.changed, 1)

    def test_delete_group_keeps_the_children(self) -> None:
        from PyQt6.QtWidgets import QMessageBox

        with mock.patch("ui.bookmark_sidebar.QMessageBox.question") as ask:
            ask.return_value = QMessageBox.StandardButton.Yes
            self.side._delete_node(self.work)
        self.assertEqual(self.names(self.m.tree()), ["logs", "etc", "home", "tmp"])
        self.assertIn("2", ask.call_args[0][2])  # says how many bookmarks stay

    def test_edit_bookmark_applies_the_dialog_result(self) -> None:
        from PyQt6.QtWidgets import QDialog

        old = self.m.tree()[1]
        new = Bookmark("home2", "/home", icon_name="star", color="#ff0000")
        with mock.patch("ui.bookmark_sidebar.BookmarkEditDialog") as cls:
            cls.return_value.exec.return_value = QDialog.DialogCode.Accepted
            cls.return_value.result_bookmark.return_value = new
            cls.return_value.result_group.return_value = self.work
            self.side._edit_node(old)
        self.assertIn("home2", self.names(self.work.children))
        self.assertEqual(self.work.children[-1].color, "#ff0000")
        self.assertEqual(self.changed, 1)

    def test_cancelled_edit_changes_nothing(self) -> None:
        from PyQt6.QtWidgets import QDialog

        with mock.patch("ui.bookmark_sidebar.BookmarkEditDialog") as cls:
            cls.return_value.exec.return_value = QDialog.DialogCode.Rejected
            self.side._edit_node(self.m.tree()[1])
        self.assertEqual(self.changed, 0)

    def test_edit_group_applies_name_icon_colour(self) -> None:
        from PyQt6.QtWidgets import QDialog

        with mock.patch("ui.bookmark_sidebar.GroupEditDialog") as cls:
            cls.return_value.exec.return_value = QDialog.DialogCode.Accepted
            cls.return_value.result.return_value = ("Jobs", "star", "#00ff00")
            self.side._edit_node(self.work)
        self.assertEqual(
            (self.work.name, self.work.icon_name, self.work.color), ("Jobs", "star", "#00ff00")
        )

    def test_new_group_at_top_level_and_inside(self) -> None:
        from PyQt6.QtWidgets import QDialog

        with mock.patch("ui.bookmark_sidebar.GroupEditDialog") as cls:
            cls.return_value.exec.return_value = QDialog.DialogCode.Accepted
            cls.return_value.result.return_value = ("Fresh", "folder", "")
            self.side._new_group(None)
            self.side._new_group(self.work)
        self.assertEqual(self.names(self.m.tree())[-1], "Fresh")
        self.assertEqual(self.names(self.work.children)[-1], "Fresh")

    def test_new_group_button_exists(self) -> None:
        self.assertTrue(self.side._new_group_btn.isVisible())


if __name__ == "__main__":
    unittest.main()
