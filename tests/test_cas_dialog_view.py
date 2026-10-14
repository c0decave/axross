"""Duplicate Finder dialog: readable rows, a useful context menu, and a
delete that goes through the verified, reversible path.

Reported by the operator: file names were cut off, the right mouse button
offered nothing, and it was unclear what "delete" would remove.
"""

from __future__ import annotations

import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import cas as CAS  # noqa: E402
from core import trash as T  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402

BID = "LocalFS:Local"


def _app():
    from PyQt6.QtWidgets import QApplication

    return QApplication.instance() or QApplication([])


class _Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            cls.app = _app()
        except ImportError:
            raise unittest.SkipTest("PyQt6 not installed")

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.tree = self.tmp / "a rather long folder name that would push the file name out"
        self.tree.mkdir()
        self.db = self.tmp / "cas.sqlite"
        p = mock.patch.object(CAS, "_DEFAULT_DB", self.db)
        p.start()
        self.addCleanup(p.stop)
        self.fs = LocalFS()
        # Keep the trash inside the temp dir, not in the real home.
        h = mock.patch.object(LocalFS, "home", lambda _self: str(self.tmp))
        h.start()
        self.addCleanup(h.stop)
        q = mock.patch("ui.cas_dialog.QMessageBox.question")
        self.ask = q.start()
        self.addCleanup(q.stop)
        from PyQt6.QtWidgets import QMessageBox

        self.ask.return_value = QMessageBox.StandardButton.Yes
        for name in ("information", "warning"):
            m = mock.patch(f"ui.cas_dialog.QMessageBox.{name}")
            setattr(self, f"_{name}", m.start())
            self.addCleanup(m.stop)

    def _write(self, name: str, data: bytes = b"same content\n") -> Path:
        p = self.tree / name
        p.write_bytes(data)
        return p

    def _dialog(self, *, rebuild: bool = True):
        if rebuild:
            CAS.rebuild(self.fs, str(self.tree), backend_id=BID)
        fs = self.fs

        class _Pane:
            backend = fs
            current_path = str(self.tree)

        from ui.cas_dialog import CasDuplicatesDialog

        dlg = CasDuplicatesDialog(_Pane())
        self.addCleanup(dlg.deleteLater)
        return dlg

    def _row(self, dlg, path: Path):
        from ui.cas_dialog import COL_NAME

        tree = dlg._tree
        for i in range(tree.topLevelItemCount()):
            group = tree.topLevelItem(i)
            for j in range(group.childCount()):
                child = group.child(j)
                if child.toolTip(COL_NAME) == str(path):
                    return child
        raise AssertionError(f"no row for {path}")

    def _actions(self, menu) -> dict:
        return {a.text().replace("&", ""): a for a in menu.actions() if not a.isSeparator()}

    def _wait(self, cond, timeout: float = 5.0) -> bool:
        end = time.time() + timeout
        while time.time() < end:
            self.app.processEvents()
            if cond():
                return True
            time.sleep(0.01)
        return False


# --------------------------------------------------------------------------
# Rows: the file name is always readable
# --------------------------------------------------------------------------


class RowTest(_Base):
    def test_the_file_name_has_its_own_column_and_the_full_path_is_the_tooltip(self) -> None:
        from ui.cas_dialog import COL_FOLDER, COL_NAME

        a = self._write("quarterly-report-final-v2.pdf")
        self._write("copy.pdf")
        row = self._row(self._dialog(), a)
        self.assertEqual(row.text(COL_NAME), "quarterly-report-final-v2.pdf")
        self.assertEqual(row.text(COL_FOLDER), str(self.tree))
        self.assertEqual(row.toolTip(COL_FOLDER), str(a))

    def test_long_text_is_elided_in_the_middle_not_at_the_end(self) -> None:
        from PyQt6.QtCore import Qt

        self._write("a"), self._write("b")
        self.assertEqual(self._dialog()._tree.textElideMode(), Qt.TextElideMode.ElideMiddle)

    def test_the_hash_column_does_not_grow_to_the_full_digest(self) -> None:
        from PyQt6.QtWidgets import QHeaderView

        from ui.cas_dialog import COL_HASH

        self._write("a"), self._write("b")
        header = self._dialog()._tree.header()
        self.assertEqual(header.sectionResizeMode(COL_HASH), QHeaderView.ResizeMode.Interactive)

    def test_edge_a_path_without_a_folder_still_shows_its_name(self) -> None:
        from ui.cas_dialog import _split_path

        self.assertEqual(_split_path("/x"), ("/", "x"))
        self.assertEqual(_split_path("x"), ("", "x"))
        self.assertEqual(_split_path("C:\\dir\\x.txt"), ("C:\\dir", "x.txt"))
        self.assertEqual(_split_path("/a/b/"), ("/a", "b"))


# --------------------------------------------------------------------------
# Context menu
# --------------------------------------------------------------------------


class ContextMenuTest(_Base):
    def setUp(self) -> None:
        super().setUp()
        self.a, self.b, self.c = self._write("a.txt"), self._write("b.txt"), self._write("c.txt")
        self.dlg = self._dialog()

    def test_a_file_row_offers_the_useful_actions(self) -> None:
        menu = self.dlg.build_context_menu(self._row(self.dlg, self.a))
        names = set(self._actions(menu))
        for expected in (
            "Open Containing Folder",
            "Keep This Copy, Select the Others",
            "Copy Path",
            "Copy File Name",
            "Copy ax-cas URL",
            "Move Selected to Trash…",
            "Remove Selected from Index",
            "Select Duplicates in Every Group (keep one)",
        ):
            self.assertIn(expected, names)

    def test_keep_this_copy_selects_exactly_the_other_copies(self) -> None:
        row = self._row(self.dlg, self.b)
        self._actions(self.dlg.build_context_menu(row))[
            "Keep This Copy, Select the Others"
        ].trigger()
        picked = sorted(e.path for e in self.dlg.selected_entries())
        self.assertEqual(picked, [str(self.a), str(self.c)])

    def test_select_duplicates_in_every_group_keeps_one_per_group(self) -> None:
        self._write("x1", b"other\n"), self._write("x2", b"other\n")
        dlg = self._dialog()
        menu = dlg.build_context_menu(None)
        self._actions(menu)["Select Duplicates in Every Group (keep one)"].trigger()
        picked = dlg.selected_entries()
        self.assertEqual(len(picked), 3)  # 3-of-a-kind keeps 1, pair keeps 1
        from ui.cas_dialog import plan_deletion

        self.assertEqual(plan_deletion(picked, dlg._groups).refused_groups, [])

    def test_copy_path_and_file_name_land_on_the_clipboard(self) -> None:
        from PyQt6.QtGui import QGuiApplication

        acts = self._actions(self.dlg.build_context_menu(self._row(self.dlg, self.a)))
        acts["Copy Path"].trigger()
        self.assertEqual(QGuiApplication.clipboard().text(), str(self.a))
        acts["Copy File Name"].trigger()
        self.assertEqual(QGuiApplication.clipboard().text(), "a.txt")

    def test_open_containing_folder_asks_the_main_window_to_navigate(self) -> None:
        seen = []
        self.dlg.open_requested.connect(lambda bid, path: seen.append((bid, path)))
        row = self._row(self.dlg, self.a)
        self._actions(self.dlg.build_context_menu(row))["Open Containing Folder"].trigger()
        self.assertEqual(seen, [(BID, str(self.a))])

    def test_remove_from_index_forgets_the_row_but_keeps_the_file(self) -> None:
        row = self._row(self.dlg, self.a)
        self.dlg._tree.clearSelection()
        row.setSelected(True)
        acts = self._actions(self.dlg.build_context_menu(row))
        acts["Remove Selected from Index"].trigger()
        self.assertTrue(self.a.exists())
        indexed = [e.path for e in CAS.list_for_backend(None, BID)]
        self.assertNotIn(str(self.a), indexed)

    def test_sad_destructive_entries_are_disabled_without_a_file_selection(self) -> None:
        self.dlg._tree.clearSelection()
        acts = self._actions(self.dlg.build_context_menu(None))
        self.assertFalse(acts["Move Selected to Trash…"].isEnabled())
        self.assertFalse(acts["Remove Selected from Index"].isEnabled())

    def test_edge_a_group_row_offers_group_actions(self) -> None:
        group = self.dlg._tree.topLevelItem(0)
        acts = self._actions(self.dlg.build_context_menu(group))
        self.assertIn("Select All but One", acts)
        self.assertIn("Copy ax-cas URL", acts)
        self.assertNotIn("Copy File Name", acts)
        acts["Select All but One"].trigger()
        self.assertEqual(len(self.dlg.selected_entries()), 2)

    def test_edge_the_menu_is_wired_to_the_right_mouse_button(self) -> None:
        from PyQt6.QtCore import Qt

        self.assertEqual(self.dlg._tree.contextMenuPolicy(), Qt.ContextMenuPolicy.CustomContextMenu)


# --------------------------------------------------------------------------
# Delete: verified, reversible, and only what was selected
# --------------------------------------------------------------------------


class DeleteFlowTest(_Base):
    def _run_delete(self, dlg) -> None:
        dlg._delete_selected()
        self.assertTrue(self._wait(lambda: not dlg._job.running), "delete job never finished")
        self.app.processEvents()

    def test_only_the_selected_copy_goes_to_the_trash(self) -> None:
        a, b, c = self._write("a.txt"), self._write("b.txt"), self._write("c.txt")
        dlg = self._dialog()
        dlg._tree.clearSelection()
        self._row(dlg, a).setSelected(True)
        self._run_delete(dlg)
        self.assertFalse(a.exists())
        self.assertTrue(b.exists() and c.exists())
        trashed = [e.original_path for e in T.list_trash(self.fs)]
        self.assertEqual(trashed, [str(a)])
        self.assertIn("trash", self.ask.call_args[0][2].lower())

    def test_sad_a_symlink_pair_from_an_old_index_is_refused_and_explained(self) -> None:
        real = self._write("real.txt")
        (self.tree / "link.txt").symlink_to("real.txt")
        value = self.fs.checksum(str(real)).split(":", 1)[1]
        for p in (real, self.tree / "link.txt"):
            CAS.upsert(None, BID, str(p), "sha256", value, 13)
        dlg = self._dialog(rebuild=False)
        dlg._tree.clearSelection()
        self._row(dlg, real).setSelected(True)
        self._run_delete(dlg)
        self.assertEqual(real.read_bytes(), b"same content\n")
        shown = " ".join(str(c) for c in self._warning.call_args_list)
        self.assertIn("no other verified copy", shown)

    def test_sad_declining_the_confirmation_touches_nothing(self) -> None:
        from PyQt6.QtWidgets import QMessageBox

        a, _b = self._write("a.txt"), self._write("b.txt")
        dlg = self._dialog()
        dlg._tree.clearSelection()
        self._row(dlg, a).setSelected(True)
        self.ask.return_value = QMessageBox.StandardButton.No
        dlg._delete_selected()
        self.assertFalse(dlg._job.running)
        self.assertTrue(a.exists())

    def test_edge_a_selected_group_row_alone_deletes_nothing(self) -> None:
        a, b = self._write("a.txt"), self._write("b.txt")
        dlg = self._dialog()
        dlg._tree.clearSelection()
        dlg._tree.topLevelItem(0).setSelected(True)
        dlg._delete_selected()
        self.ask.assert_not_called()
        self.assertTrue(a.exists() and b.exists())

    def test_edge_the_delete_key_triggers_the_same_flow(self) -> None:
        from PyQt6.QtCore import Qt
        from PyQt6.QtTest import QTest

        a, _b = self._write("a.txt"), self._write("b.txt")
        dlg = self._dialog()
        dlg.show()
        dlg.activateWindow()
        dlg._tree.setFocus()
        self._wait(lambda: dlg._tree.hasFocus(), timeout=1.0)
        dlg._tree.clearSelection()
        self._row(dlg, a).setSelected(True)
        QTest.keyClick(dlg._tree, Qt.Key.Key_Delete)
        self.assertTrue(self._wait(lambda: not dlg._job.running))
        self.assertEqual(self.ask.call_count, 1)  # the same confirmation as the button
        self.assertFalse(a.exists())


if __name__ == "__main__":
    unittest.main()
