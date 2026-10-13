"""Bookmark / group dialogs and the main window's bookmark wiring."""

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
from core.bookmarks import Bookmark, BookmarkGroup  # noqa: E402


def _dominant(pixmap) -> str:
    img = pixmap.toImage()
    counts: dict[str, int] = {}
    for x in range(img.width()):
        for y in range(img.height()):
            c = img.pixelColor(x, y)
            if c.alpha() > 200:
                counts[c.name()] = counts.get(c.name(), 0) + 1
    return max(counts, key=counts.get) if counts else ""


class _Qt(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            from PyQt6.QtWidgets import QApplication
        except ImportError:
            raise unittest.SkipTest("PyQt6 not installed")
        cls.app = QApplication.instance() or QApplication([])


class BookmarkDialogTest(_Qt):
    def _groups(self):
        a = BookmarkGroup("A")
        b = BookmarkGroup("B")
        return a, b, [(0, a), (1, b)]

    def _dlg(self, **kw):
        from ui.bookmark_edit_dialog import BookmarkEditDialog

        bm = kw.pop("bookmark", Bookmark("n", "/p"))
        dlg = BookmarkEditDialog(bm, **kw)
        self.addCleanup(dlg.deleteLater)
        return dlg

    def test_colour_defaults_to_none_and_roundtrips(self) -> None:
        dlg = self._dlg()
        self.assertEqual(dlg._colors.selected_color, "")
        self.assertEqual(dlg.result_bookmark().color, "")

    def test_picking_a_swatch_sets_the_colour(self) -> None:
        dlg = self._dlg()
        btn = dlg.findChild(
            __import__("PyQt6.QtWidgets", fromlist=["QPushButton"]).QPushButton, "axSwatch_Red"
        )
        btn.click()
        self.assertEqual(dlg.result_bookmark().color, "#e74c3c")
        self.assertTrue(btn.isChecked())

    def test_an_existing_colour_is_preselected_and_can_be_cleared(self) -> None:
        dlg = self._dlg(bookmark=Bookmark("n", "/p", color="#3498db"))
        self.assertEqual(dlg._colors.selected_color, "#3498db")
        dlg._colors._buttons[""].click()
        self.assertEqual(dlg.result_bookmark().color, "")

    def test_only_one_swatch_is_checked_at_a_time(self) -> None:
        dlg = self._dlg()
        dlg._colors._buttons["#e74c3c"].click()
        dlg._colors._buttons["#2ecc71"].click()
        checked = [h for h, b in dlg._colors._buttons.items() if b.isChecked()]
        self.assertEqual(checked, ["#2ecc71"])

    def test_the_icon_grid_previews_the_chosen_colour(self) -> None:
        dlg = self._dlg()
        dlg._colors._buttons["#9b59b6"].click()
        px = dlg._picker._buttons["star"].icon().pixmap(32, 32)
        self.assertEqual(_dominant(px).lower(), "#9b59b6")

    def test_the_icon_grid_offers_the_new_emoji_icons(self) -> None:
        dlg = self._dlg()
        for name in ("rocket", "flame", "smile", "ghost"):
            self.assertIn(name, dlg._picker._buttons)

    def test_group_chooser_lists_groups_indented_and_preselects_the_current(self) -> None:
        a, b, groups = self._groups()
        dlg = self._dlg(groups=groups, current_group=b)
        combo = dlg._group_combo
        self.assertEqual(
            [combo.itemText(i) for i in range(combo.count())], ["(top level)", "A", "    B"]
        )
        self.assertIs(dlg.result_group(), b)

    def test_group_chooser_can_pick_another_group_or_top_level(self) -> None:
        a, b, groups = self._groups()
        dlg = self._dlg(groups=groups, current_group=None)
        self.assertIsNone(dlg.result_group())
        dlg._group_combo.setCurrentIndex(1)
        self.assertIs(dlg.result_group(), a)
        dlg._group_combo.setCurrentIndex(0)
        self.assertIsNone(dlg.result_group())

    def test_without_a_group_list_there_is_no_chooser_and_the_group_is_kept(self) -> None:
        a, _b, _g = self._groups()
        dlg = self._dlg(current_group=a)
        self.assertFalse(hasattr(dlg, "_group_combo"))
        self.assertIs(dlg.result_group(), a)

    def test_new_flag_sets_the_title_even_with_a_prefilled_bookmark(self) -> None:
        self.assertEqual(self._dlg(new=True).windowTitle(), "New Bookmark")
        self.assertEqual(self._dlg().windowTitle(), "Edit Bookmark")

    def test_result_keeps_backend_and_profile(self) -> None:
        dlg = self._dlg(bookmark=Bookmark("n", "/p", backend_name="u@h", profile_name="prof"))
        res = dlg.result_bookmark()
        self.assertEqual((res.backend_name, res.profile_name), ("u@h", "prof"))


class GroupDialogTest(_Qt):
    def _dlg(self, group=None):
        from ui.bookmark_edit_dialog import GroupEditDialog

        dlg = GroupEditDialog(group)
        self.addCleanup(dlg.deleteLater)
        return dlg

    def test_new_group_defaults(self) -> None:
        dlg = self._dlg()
        self.assertEqual(dlg.windowTitle(), "New Group")
        self.assertEqual(dlg.result(), ("New Group", "folder", ""))

    def test_values_roundtrip(self) -> None:
        dlg = self._dlg()
        dlg._name_edit.setText("  Servers ")
        dlg._colors._buttons["#e67e22"].click()
        dlg._picker._on_pick("server")
        self.assertEqual(dlg.result(), ("Servers", "server", "#e67e22"))

    def test_editing_prefills_and_an_empty_name_keeps_the_old_one(self) -> None:
        g = BookmarkGroup("Keep", icon_name="star", color="#2ecc71")
        dlg = self._dlg(g)
        self.assertEqual(dlg.windowTitle(), "Edit Group")
        dlg._name_edit.setText("   ")
        self.assertEqual(dlg.result(), ("Keep", "star", "#2ecc71"))


class MainWindowTest(_Qt):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls._home = tempfile.mkdtemp()
        cls._patch = mock.patch("pathlib.Path.home", return_value=Path(cls._home))
        cls._patch.start()
        from ui.main_window import MainWindow

        cls._orig = BM.BOOKMARKS_FILE
        BM.BOOKMARKS_FILE = Path(cls._home) / "bookmarks.json"
        cls.win = MainWindow()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.win.deleteLater()
        BM.BOOKMARKS_FILE = cls._orig
        cls._patch.stop()
        shutil.rmtree(cls._home, ignore_errors=True)

    def setUp(self) -> None:
        mgr = self.win._bookmark_manager
        for _d, g in list(mgr.groups()):
            mgr.remove_group(g)
        while mgr.all():
            mgr.remove(0)
        self.win._rebuild_bookmarks_menu()

    def _entries(self, menu):
        return [a for a in menu.actions() if not a.isSeparator()]

    def test_the_menu_nests_groups_as_submenus_with_their_bookmarks(self) -> None:
        mgr = self.win._bookmark_manager
        g = mgr.add_group("Work", color="#3498db")
        inner = mgr.add_group("Prod", parent=g)
        mgr.add(Bookmark("logs", "/var/log", color="#e74c3c"), group=inner)
        mgr.add(Bookmark("home", "/home"))
        self.win._rebuild_bookmarks_menu()
        entries = {a.text().replace("&&", "&"): a for a in self._entries(self.win._bookmarks_menu)}
        work = next(a for t, a in entries.items() if t == "Work")
        self.assertIsNotNone(work.menu())
        self.assertFalse(work.icon().isNull())
        sub = [a.text() for a in self._entries(work.menu())]
        self.assertEqual(sub, ["Prod"])
        prod = self._entries(work.menu())[0]
        self.assertTrue(any("logs" in a.text() for a in self._entries(prod.menu())))
        self.assertTrue(any("home" in t for t in entries))

    def test_an_empty_group_shows_a_disabled_placeholder(self) -> None:
        self.win._bookmark_manager.add_group("Empty")
        self.win._rebuild_bookmarks_menu()
        work = next(a for a in self._entries(self.win._bookmarks_menu) if a.text() == "Empty")
        kids = self._entries(work.menu())
        self.assertEqual(len(kids), 1)
        self.assertFalse(kids[0].isEnabled())

    def test_menu_labels_cannot_inject_markup(self) -> None:
        self.win._bookmark_manager.add(Bookmark("<u>fake</u>", "/x"))
        self.win._rebuild_bookmarks_menu()
        texts = [a.text() for a in self._entries(self.win._bookmarks_menu)]
        self.assertTrue(any("ufake/u" in t for t in texts))
        self.assertFalse(any("<u>" in t for t in texts))

    def test_triggering_a_bookmark_in_a_group_navigates(self) -> None:
        mgr = self.win._bookmark_manager
        g = mgr.add_group("G")
        mgr.add(Bookmark("tmp", "/tmp"), group=g)
        self.win._rebuild_bookmarks_menu()
        grp = next(a for a in self._entries(self.win._bookmarks_menu) if a.text() == "G")
        with mock.patch.object(self.win, "_navigate_bookmark") as nav:
            self._entries(grp.menu())[0].trigger()
        nav.assert_called_once()
        self.assertEqual(nav.call_args[0][0].path, "/tmp")

    def test_adding_a_bookmark_opens_the_dialog_with_icon_colour_and_group(self) -> None:
        from PyQt6.QtWidgets import QDialog

        mgr = self.win._bookmark_manager
        g = mgr.add_group("Dest")
        chosen = Bookmark("proj", "/srv/proj", icon_name="rocket", color="#e74c3c")
        with mock.patch("ui.main_window.BookmarkEditDialog") as cls:
            cls.return_value.exec.return_value = QDialog.DialogCode.Accepted
            cls.return_value.result_bookmark.return_value = chosen
            cls.return_value.result_group.return_value = g
            self.win._on_bookmark_request("/srv/proj", "Local")
        kwargs = cls.call_args.kwargs
        self.assertTrue(kwargs["new"])
        self.assertEqual(cls.call_args.args[0].path, "/srv/proj")
        self.assertEqual(cls.call_args.args[0].name, "proj")
        self.assertIn((0, g), kwargs["groups"])
        self.assertEqual([b.name for b in g.children], ["proj"])
        self.assertEqual(g.children[0].icon_name, "rocket")

    def test_cancelling_the_add_dialog_adds_nothing(self) -> None:
        from PyQt6.QtWidgets import QDialog

        with mock.patch("ui.main_window.BookmarkEditDialog") as cls:
            cls.return_value.exec.return_value = QDialog.DialogCode.Rejected
            self.win._on_bookmark_request("/srv/x", "Local")
        self.assertEqual(self.win._bookmark_manager.all(), [])

    def test_the_add_dialog_carries_the_profile_of_the_source_pane(self) -> None:
        from PyQt6.QtWidgets import QDialog

        with mock.patch("ui.main_window.BookmarkEditDialog") as cls:
            cls.return_value.exec.return_value = QDialog.DialogCode.Rejected
            self.win._on_bookmark_request("/a", "u@host")
        self.assertEqual(cls.call_args.args[0].backend_name, "u@host")

    def test_sidebar_changes_refresh_the_menu(self) -> None:
        mgr = self.win._bookmark_manager
        mgr.add(Bookmark("one", "/one"))
        self.win._rebuild_bookmarks_menu()
        self.win._bookmark_sidebar._move_by(mgr.tree()[0], -1)  # no-op: edge
        mgr.add(Bookmark("two", "/two"))
        self.win._bookmark_sidebar._move_by(mgr.tree()[1], -1)
        texts = [a.text() for a in self._entries(self.win._bookmarks_menu)]
        names = [t for t in texts if t.startswith(("one", "two"))]
        self.assertEqual([n.split("  ")[0] for n in names], ["two", "one"])

    def test_the_sidebar_shows_the_same_tree(self) -> None:
        mgr = self.win._bookmark_manager
        g = mgr.add_group("Side")
        mgr.add(Bookmark("x", "/x"), group=g)
        self.win._rebuild_bookmarks_menu()
        tree = self.win._bookmark_sidebar._tree
        self.assertEqual(tree.topLevelItemCount(), 1)
        self.assertEqual(tree.topLevelItem(0).text(0), "Side")
        self.assertEqual(tree.topLevelItem(0).child(0).text(0), "x")


if __name__ == "__main__":
    unittest.main()
