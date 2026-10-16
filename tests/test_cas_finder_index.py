"""Duplicate Finder: "Mark All Duplicates (keep first)", select-all delete,
the scope filter, and the separate Index / History view.

Operator request: the finder's cache and history must be reachable on their
own; selecting everything and deleting must remove only the duplicates (the
first copy of each group stays), and there must be a "mark all duplicates"
that keeps the first.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core import cas as CAS  # noqa: E402
from core import trash as T  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402

BID = "LocalFS:Local"


class _Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            from PyQt6.QtWidgets import QApplication
        except ImportError:
            raise unittest.SkipTest("PyQt6 not installed")
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.root = self.tmp / "tree"
        self.root.mkdir()
        self.db = self.tmp / "cas.sqlite"
        p = mock.patch.object(CAS, "_DEFAULT_DB", self.db)
        p.start()
        self.addCleanup(p.stop)
        h = mock.patch.object(LocalFS, "home", lambda _self: str(self.tmp))
        h.start()
        self.addCleanup(h.stop)
        self.fs = LocalFS()
        from PyQt6.QtWidgets import QMessageBox

        # Both dialogs use the one QMessageBox class: patch it once.
        self.mb = {}
        for name in ("question", "information", "warning"):
            m = mock.patch.object(QMessageBox, name)
            started = m.start()
            self.addCleanup(m.stop)
            for module in ("ui.cas_dialog", "ui.cas_history_dialog"):
                self.mb[(module, name)] = started
        self.mb[("ui.cas_dialog", "question")].return_value = QMessageBox.StandardButton.Yes

    def ask(self, module: str = "ui.cas_dialog"):
        return self.mb[(module, "question")]

    def _write(self, rel: str, mtime: float, data: bytes) -> Path:
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        os.utime(p, (mtime, mtime))
        return p

    def _pane(self, path: Path | None = None):
        fs = self.fs
        where = str(path or self.root)

        class _Pane:
            backend = fs
            current_path = where

        return _Pane()

    def _finder(self, **kw):
        from ui.cas_dialog import CasDuplicatesDialog

        dlg = CasDuplicatesDialog(self._pane(), **kw)
        self.addCleanup(dlg.deleteLater)
        self.addCleanup(dlg._job.abandon)
        return dlg

    def _group_paths(self, dlg) -> list[list[str]]:
        from PyQt6.QtCore import Qt

        from ui.cas_dialog import COL_NAME

        out = []
        tree = dlg._tree
        for i in range(tree.topLevelItemCount()):
            group = tree.topLevelItem(i)
            rows = []
            for j in range(group.childCount()):
                rows.append(group.child(j).data(COL_NAME, Qt.ItemDataRole.UserRole)[1].path)
            out.append(rows)
        return out

    def _wait(self, cond, timeout: float = 5.0) -> bool:
        end = time.time() + timeout
        while time.time() < end:
            self.app.processEvents()
            if cond():
                return True
            time.sleep(0.01)
        return False

    def _three_groups(self) -> dict[str, Path]:
        files = {
            "a_old": self._write("x/a.txt", 1_000.0, b"alpha\n"),
            "a_new": self._write("a.txt", 9_000.0, b"alpha\n"),
            "a_mid": self._write("y/a.txt", 5_000.0, b"alpha\n"),
            "b_old": self._write("b-old.txt", 2_000.0, b"beta\n"),
            "b_new": self._write("b.txt", 3_000.0, b"beta\n"),
            "unique": self._write("u.txt", 3_000.0, b"gamma\n"),
        }
        CAS.rebuild(self.fs, str(self.root), backend_id=BID)
        return files


# --------------------------------------------------------------------------
# Rows in survivor order; Mark All Duplicates keeps the first
# --------------------------------------------------------------------------


class MarkAllTest(_Base):
    def test_happy_the_first_row_of_every_group_is_the_oldest(self) -> None:
        f = self._three_groups()
        groups = sorted(self._group_paths(self._finder()), key=len)
        self.assertEqual(groups[0], [str(f["b_old"]), str(f["b_new"])])
        self.assertEqual(groups[1], [str(f["a_old"]), str(f["a_mid"]), str(f["a_new"])])

    def test_happy_the_button_marks_all_but_the_first_of_each_group(self) -> None:
        f = self._three_groups()
        dlg = self._finder()
        self.assertEqual(dlg._mark_all_btn.text(), "Mark All Duplicates (keep first)")
        self.assertTrue(dlg._mark_all_btn.isVisibleTo(dlg))
        dlg._mark_all_btn.click()
        picked = sorted(e.path for e in dlg.selected_entries())
        self.assertEqual(picked, sorted(str(f[k]) for k in ("a_new", "a_mid", "b_new")))

    def test_happy_the_context_menu_entry_does_the_same(self) -> None:
        f = self._three_groups()
        dlg = self._finder()
        acts = {a.text(): a for a in dlg.build_context_menu(None).actions()}
        acts["Mark All Duplicates (keep first)"].trigger()
        picked = sorted(e.path for e in dlg.selected_entries())
        self.assertEqual(picked, sorted(str(f[k]) for k in ("a_new", "a_mid", "b_new")))

    def test_edge_the_modified_column_and_the_survivor_hint(self) -> None:
        from ui.cas_dialog import COL_MODIFIED

        self._three_groups()
        dlg = self._finder()
        first = dlg._tree.topLevelItem(0).child(0)
        self.assertTrue(first.text(COL_MODIFIED))
        self.assertTrue(first.font(COL_MODIFIED).bold())
        self.assertIn("kept", first.toolTip(COL_MODIFIED).lower())
        self.assertFalse(dlg._tree.topLevelItem(0).child(1).font(COL_MODIFIED).bold())

    def test_sad_copies_without_mtime_are_explained(self) -> None:
        CAS.upsert(None, BID, "/no/time/a", "sha256", "v", 1)
        CAS.upsert(None, BID, "/no/time/b", "sha256", "v", 1)
        dlg = self._finder()
        self.assertTrue(dlg._undated_label.isVisibleTo(dlg))
        self.assertIn("modification time", dlg._undated_label.text())
        self.assertEqual(self._group_paths(dlg), [["/no/time/a", "/no/time/b"]])

    def test_edge_dated_groups_show_no_notice(self) -> None:
        self._three_groups()
        dlg = self._finder()
        self.assertFalse(dlg._undated_label.isVisibleTo(dlg))


# --------------------------------------------------------------------------
# Select all (Ctrl+A), delete: only the duplicates go
# --------------------------------------------------------------------------


class SelectAllDeleteTest(_Base):
    def _run_delete(self, dlg) -> None:
        dlg._delete_selected()
        self.assertTrue(self._wait(lambda: not dlg._job.running), "delete never finished")
        self.app.processEvents()

    def test_happy_ctrl_a_then_delete_keeps_the_first_of_each_group(self) -> None:
        from PyQt6.QtCore import Qt
        from PyQt6.QtTest import QTest

        f = self._three_groups()
        dlg = self._finder()
        dlg.show()
        dlg._tree.setFocus()
        QTest.keyClick(dlg._tree, Qt.Key.Key_A, Qt.KeyboardModifier.ControlModifier)
        self.assertEqual(len(dlg.selected_entries()), 5)
        self._run_delete(dlg)
        text = self.ask().call_args[0][2]
        self.assertIn("3 file(s)", text)
        self.assertIn("2 copies are kept", text)
        for keep in ("a_old", "b_old", "unique"):
            self.assertTrue(f[keep].exists(), keep)
        for gone in ("a_new", "a_mid", "b_new"):
            self.assertFalse(f[gone].exists(), gone)
        trashed = sorted(e.original_path for e in T.list_trash(self.fs))
        self.assertEqual(trashed, sorted(str(f[k]) for k in ("a_new", "a_mid", "b_new")))
        warned = self.mb[("ui.cas_dialog", "warning")]
        self.assertFalse(any("ALL their copies" in str(c) for c in warned.call_args_list))

    def test_happy_a_partial_selection_removes_exactly_that(self) -> None:
        f = self._three_groups()
        dlg = self._finder()
        dlg._tree.clearSelection()
        # Remove the OLDEST copy on purpose: a partial choice is honoured.
        for i in range(dlg._tree.topLevelItemCount()):
            group = dlg._tree.topLevelItem(i)
            if group.childCount() == 2:
                group.child(0).setSelected(True)
        self._run_delete(dlg)
        self.assertFalse(f["b_old"].exists())
        self.assertTrue(f["b_new"].exists() and f["a_old"].exists())

    def test_sad_a_vanished_survivor_keeps_the_whole_group(self) -> None:
        f = self._three_groups()
        dlg = self._finder()
        f["b_old"].unlink()  # after indexing, before deleting
        dlg._tree.selectAll()
        self._run_delete(dlg)
        self.assertTrue(f["b_new"].exists())
        shown = " ".join(str(c) for c in self.mb[("ui.cas_dialog", "warning")].call_args_list)
        self.assertIn("no other verified copy", shown)

    def test_edge_declining_touches_nothing(self) -> None:
        from PyQt6.QtWidgets import QMessageBox

        f = self._three_groups()
        dlg = self._finder()
        dlg._tree.selectAll()
        self.ask().return_value = QMessageBox.StandardButton.No
        dlg._delete_selected()
        self.assertFalse(dlg._job.running)
        self.assertTrue(all(p.exists() for p in f.values()))


# --------------------------------------------------------------------------
# Scope filter: all scans / one scan / inside a folder
# --------------------------------------------------------------------------


class ScopeFilterTest(_Base):
    def setUp(self) -> None:
        super().setUp()
        self._write("one/a", 1.0e6, b"one"), self._write("one/b", 2.0e6, b"one")
        self._write("two/c", 1.0e6, b"two"), self._write("two/d", 2.0e6, b"two")
        CAS.rebuild(self.fs, str(self.root / "one"), backend_id=BID)
        CAS.rebuild(self.fs, str(self.root / "two"), backend_id=BID)
        self.second, self.first = CAS.list_scans(None)

    def _scope_texts(self, dlg) -> list[str]:
        return [dlg._scope_combo.itemText(i) for i in range(dlg._scope_combo.count())]

    def test_happy_the_combo_offers_all_each_scan_and_a_folder(self) -> None:
        dlg = self._finder()
        texts = self._scope_texts(dlg)
        self.assertEqual(texts[0], "All scans")
        self.assertTrue(any(f"#{self.first.scan_id}" in t for t in texts))
        self.assertTrue(any(f"#{self.second.scan_id}" in t for t in texts))
        self.assertTrue(any(t.startswith("Only inside folder") for t in texts))
        self.assertEqual(len(self._group_paths(dlg)), 2)

    def test_happy_one_scan(self) -> None:
        dlg = self._finder()
        dlg.set_scope("scan", self.first.scan_id)
        paths = self._group_paths(dlg)
        self.assertEqual(len(paths), 1)
        self.assertTrue(paths[0][0].startswith(str(self.root / "one")))
        self.assertEqual(dlg.scope(), ("scan", self.first.scan_id))

    def test_happy_inside_a_folder_via_the_combo(self) -> None:
        dlg = self._finder()
        idx = next(
            i
            for i in range(dlg._scope_combo.count())
            if dlg._scope_combo.itemText(i).startswith("Only inside folder")
        )
        with mock.patch(
            "ui.cas_dialog.QInputDialog.getText", return_value=(str(self.root / "two"), True)
        ):
            dlg._scope_combo.setCurrentIndex(idx)
        paths = self._group_paths(dlg)
        self.assertEqual(len(paths), 1)
        self.assertTrue(paths[0][0].startswith(str(self.root / "two")))
        self.assertIn(str(self.root / "two"), dlg._scope_combo.currentText())

    def test_sad_cancelling_the_folder_prompt_keeps_the_previous_scope(self) -> None:
        dlg = self._finder()
        idx = next(
            i
            for i in range(dlg._scope_combo.count())
            if dlg._scope_combo.itemText(i).startswith("Only inside folder")
        )
        with mock.patch("ui.cas_dialog.QInputDialog.getText", return_value=("", False)):
            dlg._scope_combo.setCurrentIndex(idx)
        self.assertEqual(dlg.scope(), ("all", None))
        self.assertEqual(dlg._scope_combo.currentText(), "All scans")
        self.assertEqual(len(self._group_paths(dlg)), 2)

    def test_edge_opening_the_finder_on_a_scan(self) -> None:
        dlg = self._finder(scan_id=self.second.scan_id)
        self.assertEqual(dlg.scope(), ("scan", self.second.scan_id))
        self.assertEqual(len(self._group_paths(dlg)), 1)


# --------------------------------------------------------------------------
# The Index / History view
# --------------------------------------------------------------------------


class HistoryDialogTest(_Base):
    def setUp(self) -> None:
        super().setUp()
        self._write("one/a", 1.0e6, b"one"), self._write("one/b", 2.0e6, b"one")
        self._write("two/c", 1.0e6, b"two"), self._write("two/d", 2.0e6, b"two")
        CAS.rebuild(self.fs, str(self.root / "one"), backend_id=BID)
        seen = []
        CAS.rebuild(
            self.fs,
            str(self.root / "two"),
            backend_id=BID,
            cancel=lambda: len(seen) >= 1,
            progress=lambda *a: seen.append(a),
        )
        self.cancelled, self.complete = CAS.list_scans(None)

    def _history(self, **kw):
        from ui.cas_history_dialog import CasHistoryDialog

        dlg = CasHistoryDialog(backends={BID: self.fs}, **kw)
        self.addCleanup(dlg.deleteLater)
        self.addCleanup(dlg._job.abandon)
        return dlg

    def _select(self, dlg, scan_id: int) -> None:
        tree = dlg._tree
        for i in range(tree.topLevelItemCount()):
            item = tree.topLevelItem(i)
            if dlg.scan_of(item).scan_id == scan_id:
                tree.setCurrentItem(item)
                return
        raise AssertionError(f"no row for scan {scan_id}")

    def test_happy_every_scan_is_listed_with_its_facts(self) -> None:
        from ui.cas_history_dialog import COLUMNS

        dlg = self._history()
        self.assertEqual(dlg._tree.topLevelItemCount(), 2)
        headers = [dlg._tree.headerItem().text(i) for i in range(dlg._tree.columnCount())]
        self.assertEqual(headers, list(COLUMNS))
        for needed in ("Root", "Backend", "Started", "Finished", "Files", "Duplicate groups"):
            self.assertIn(needed, headers)
        statuses = {dlg._tree.topLevelItem(i).text(headers.index("Status")) for i in range(2)}
        self.assertEqual(statuses, {"complete", "cancelled"})

    def test_happy_show_duplicates_asks_for_that_scan(self) -> None:
        dlg = self._history()
        seen = []
        dlg.show_duplicates_requested.connect(seen.append)
        self._select(dlg, self.complete.scan_id)
        dlg._show_btn.click()
        self.assertEqual(seen, [self.complete.scan_id])

    def test_happy_remove_from_index_forgets_that_scan_only(self) -> None:
        dlg = self._history()
        changed = []
        dlg.index_changed.connect(lambda: changed.append(1))
        self._select(dlg, self.complete.scan_id)
        dlg._remove_btn.click()
        self.assertEqual([s.scan_id for s in CAS.list_scans(None)], [self.cancelled.scan_id])
        self.assertEqual(dlg._tree.topLevelItemCount(), 1)
        self.assertEqual(changed, [1])
        self.assertTrue((self.root / "one" / "a").exists())

    def test_happy_rescan_runs_in_the_background_and_records_a_new_scan(self) -> None:
        dlg = self._history()
        self._select(dlg, self.cancelled.scan_id)
        dlg._rescan_btn.click()
        self.assertTrue(self._wait(lambda: not dlg._job.running))
        self.app.processEvents()
        newest = CAS.list_scans(None)[0]
        self.assertEqual((newest.root, newest.status), (str(self.root / "two"), "complete"))
        self.assertEqual(dlg._tree.topLevelItemCount(), 3)

    def test_sad_clear_whole_index_asks_first_and_declining_keeps_it(self) -> None:
        from PyQt6.QtWidgets import QMessageBox

        dlg = self._history()
        ask = self.ask("ui.cas_history_dialog")
        ask.return_value = QMessageBox.StandardButton.No
        dlg._clear_btn.click()
        self.assertEqual(len(CAS.list_scans(None)), 2)
        ask.return_value = QMessageBox.StandardButton.Yes
        dlg._clear_btn.click()
        self.assertEqual(CAS.list_scans(None), [])
        self.assertEqual(CAS.duplicates(None, None), [])
        self.assertEqual(dlg._tree.topLevelItemCount(), 0)

    def test_sad_rescan_without_a_connected_backend_explains(self) -> None:
        from ui.cas_history_dialog import CasHistoryDialog

        dlg = CasHistoryDialog(backends={})
        self.addCleanup(dlg.deleteLater)
        self._select(dlg, self.complete.scan_id)
        dlg._rescan_btn.click()
        self.assertFalse(dlg._job.running)
        info = self.mb[("ui.cas_history_dialog", "information")]
        self.assertIn(BID, str(info.call_args))

    def test_edge_the_earlier_scans_pseudo_entry_cannot_be_rescanned(self) -> None:
        CAS.upsert(None, "Other:x", "/o/a", "md5", "abc", 1)
        dlg = self._history()
        self._select(dlg, CAS.EARLIER_SCANS)
        self.assertFalse(dlg._rescan_btn.isEnabled())
        self.assertTrue(dlg._remove_btn.isEnabled())
        dlg._remove_btn.click()
        self.assertNotIn(CAS.EARLIER_SCANS, [s.scan_id for s in CAS.list_scans(None)])

    def test_edge_the_finder_opens_the_history_and_follows_it(self) -> None:
        finder = self._finder()
        finder._history_btn.click()
        history = finder._history_dialog
        self.assertIsNotNone(history)
        self._select(history, self.complete.scan_id)
        history._show_btn.click()
        self.assertEqual(finder.scope(), ("scan", self.complete.scan_id))
        self._select(history, self.complete.scan_id)
        history._remove_btn.click()  # the finder reloads with the index
        self.assertEqual(self._group_paths(finder), [])
        history.reject()


if __name__ == "__main__":
    unittest.main()
