"""Duplicate Finder end to end in the real main window.

Index a folder whose duplicates have different modification times, open
the finder with its hotkey, Mark All Duplicates, Move to Trash: the oldest
copy of each group remains, the others sit in the axross trash and can be
restored. Also: the hotkey collides with nothing, the toolbar has a button
for it, and the Index / History view has its own menu entry.
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

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import core.bookmarks as BM  # noqa: E402
from core import cas as CAS  # noqa: E402
from core import trash as T  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402

HOTKEY = "Ctrl+Shift+D"


class _Window(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            from PyQt6.QtWidgets import QApplication
        except ImportError:
            raise unittest.SkipTest("PyQt6 not installed")
        cls.app = QApplication.instance() or QApplication([])
        cls._home = tempfile.mkdtemp()
        cls._patch = mock.patch("pathlib.Path.home", return_value=Path(cls._home))
        cls._patch.start()
        cls._orig = BM.BOOKMARKS_FILE
        BM.BOOKMARKS_FILE = Path(cls._home) / "bookmarks.json"
        from ui.main_window import MainWindow

        cls.win = MainWindow()
        cls.win.show()
        cls.app.processEvents()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.win.close()
        cls.win.deleteLater()
        BM.BOOKMARKS_FILE = cls._orig
        cls._patch.stop()
        shutil.rmtree(cls._home, ignore_errors=True)

    def _wait(self, cond, timeout: float = 10.0) -> bool:
        end = time.time() + timeout
        while time.time() < end:
            self.app.processEvents()
            if cond():
                return True
            time.sleep(0.01)
        return False

    def _finders(self):
        from ui.cas_dialog import CasDuplicatesDialog

        return [d for d in self.win.findChildren(CasDuplicatesDialog) if d.isVisible()]

    def _close_finders(self) -> None:
        for d in self._finders():
            d.reject()
        self.app.processEvents()


class HotkeyTest(_Window):
    def _bindings(self) -> list[str]:
        from PyQt6.QtGui import QAction, QKeySequence

        fmt = QKeySequence.SequenceFormat.PortableText
        return [ks.toString(fmt) for a in self.win.findChildren(QAction) for ks in a.shortcuts()]

    def test_happy_the_hotkey_is_bound_exactly_once_and_listed_in_f1(self) -> None:
        from ui.shortcuts_dialog import SHORTCUTS

        self.assertEqual(self._bindings().count(HOTKEY), 1)
        listed = [d for _s, keys, d in SHORTCUTS if HOTKEY in keys]
        self.assertEqual(listed, ["Duplicate Finder"])

    def test_sad_no_other_f1_entry_or_pane_key_uses_it(self) -> None:
        from ui.shortcuts_dialog import SHORTCUTS

        users = [d for _s, keys, d in SHORTCUTS for k in keys if k == HOTKEY]
        self.assertEqual(len(users), 1)
        source = (Path(__file__).resolve().parents[1] / "ui" / "file_pane.py").read_text()
        self.assertNotIn(HOTKEY, source)

    def test_edge_toolbar_button_and_history_menu_entry(self) -> None:
        from PyQt6.QtWidgets import QToolBar

        toolbar = self.win.findChild(QToolBar)
        tips = [a.toolTip() for a in toolbar.actions()]
        self.assertTrue(any(t.startswith("Duplicate Finder") and HOTKEY in t for t in tips))
        from PyQt6.QtGui import QAction

        def plain(text: str) -> str:  # "&&" is a literal ampersand, "&x" a mnemonic
            return text.replace("&&", "\0").replace("&", "").replace("\0", "&")

        names = [plain(a.text()) for a in self.win.findChildren(QAction)]
        self.assertIn("Duplicate Index & History…", names)


class EndToEndTest(_Window):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.addCleanup(self._close_finders)
        p = mock.patch.object(CAS, "_DEFAULT_DB", self.tmp / "cas.sqlite")
        p.start()
        self.addCleanup(p.stop)
        h = mock.patch.object(LocalFS, "home", lambda _self: str(self.tmp))
        h.start()
        self.addCleanup(h.stop)
        from PyQt6.QtWidgets import QMessageBox

        for name in ("question", "information", "warning"):
            m = mock.patch(f"ui.cas_dialog.QMessageBox.{name}")
            setattr(self, name, m.start())
            self.addCleanup(m.stop)
        self.question.return_value = QMessageBox.StandardButton.Yes
        self.root = self.tmp / "photos"
        self.files = {
            "a_old": self._write("2019/a.jpg", 1_500_000_000.0, b"A" * 64),
            "a_new": self._write("inbox/a.jpg", 1_700_000_000.0, b"A" * 64),
            "a_mid": self._write("backup/a.jpg", 1_600_000_000.0, b"A" * 64),
            "b_old": self._write("b.jpg", 1_400_000_000.0, b"B" * 64),
            "b_new": self._write("copy of b.jpg", 1_450_000_000.0, b"B" * 64),
            "solo": self._write("solo.jpg", 1_450_000_000.0, b"C" * 64),
        }

    def _write(self, rel: str, mtime: float, data: bytes) -> Path:
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        os.utime(p, (mtime, mtime))
        return p

    def test_happy_hotkey_rebuild_mark_all_trash_restore(self) -> None:
        from PyQt6.QtCore import Qt
        from PyQt6.QtTest import QTest

        pane = self.win._active_pane
        self.assertIsInstance(pane.backend, LocalFS)
        pane.navigate(str(self.root))
        self.assertTrue(self._wait(lambda: pane.current_path == str(self.root)))

        self.win.activateWindow()
        pane._table.setFocus()
        self.app.processEvents()
        QTest.keyClick(
            pane._table,
            Qt.Key.Key_D,
            Qt.KeyboardModifier.ControlModifier | Qt.KeyboardModifier.ShiftModifier,
        )
        # The hotkey opens a window before QTest lets the modifiers go, and
        # QApplication then kept Shift as held: every later test's
        # selectRow() became a Shift-range selection that selected nothing.
        QTest.keyRelease(pane._table, Qt.Key.Key_Shift)
        QTest.keyRelease(pane._table, Qt.Key.Key_Control)
        self.assertTrue(self._wait(lambda: bool(self._finders())), "hotkey opened no finder")
        (finder,) = self._finders()

        finder._rebuild_btn.click()
        self.assertTrue(self._wait(lambda: not finder._job.running), "rebuild never finished")
        self.app.processEvents()
        (scan,) = CAS.list_scans(None)
        self.assertEqual((scan.root, scan.status), (str(self.root), "complete"))

        finder._mark_all_btn.click()
        self.assertEqual(len(finder.selected_entries()), 3)
        finder._delete_btn.click()
        self.assertTrue(self._wait(lambda: not finder._job.running), "delete never finished")
        self.app.processEvents()

        f = self.files
        for keep in ("a_old", "b_old", "solo"):
            self.assertTrue(f[keep].exists(), keep)
        for gone in ("a_new", "a_mid", "b_new"):
            self.assertFalse(f[gone].exists(), gone)
        trash = {e.original_path: e for e in T.list_trash(pane.backend)}
        self.assertEqual(sorted(trash), sorted(str(f[k]) for k in ("a_new", "a_mid", "b_new")))
        T.restore(pane.backend, trash[str(f["a_new"])].trash_id)
        self.assertEqual(f["a_new"].read_bytes(), b"A" * 64)
        self.warning.assert_not_called()


if __name__ == "__main__":
    unittest.main()
