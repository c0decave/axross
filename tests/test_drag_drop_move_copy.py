"""Drag & drop moves by default and copies with Ctrl, between panes and
inside one pane onto a folder.

Before: no modifier copied and Ctrl moved (the reverse of the operator's
"wenn strg gedrückt wird wird kopiert ansonsten verschoben"), a drag that
started in the same pane was ignored outright, and a drop always landed in
the target pane's current folder even when it was released on a subfolder.
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


class _Panes(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            from PyQt6.QtWidgets import QApplication
        except ImportError:
            raise unittest.SkipTest("PyQt6 not installed")
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        from ui import column_prefs as CP
        from ui import main_window as MW

        self.MW = MW
        self.tmp = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        env = mock.patch.dict(
            os.environ, {"AXROSS_OPERATION_JOURNAL": str(self.tmp / "operations.jsonl")}
        )
        env.start()
        self.addCleanup(env.stop)
        p = mock.patch.object(CP, "DEFAULT_PATH", self.tmp / "cols.json")
        p.start()
        self.addCleanup(p.stop)
        home = self.tmp / "home"
        home.mkdir()
        with mock.patch("pathlib.Path.home", return_value=home):
            self.win = MW.MainWindow()
        self.addCleanup(self.win.deleteLater)
        self.addCleanup(self.win.close)
        self.win._reconnect_timer.stop()
        self.win.resize(1200, 700)
        self.win.show()
        for pane in list(self.win._panes)[1:]:
            self.win._close_pane(pane)
        self.a = self.tmp / "a"
        self.b = self.tmp / "b"
        (self.a / "sub").mkdir(parents=True)
        (self.b / "inbox").mkdir(parents=True)
        (self.a / "f.txt").write_text("payload")
        self.left = self.win._panes[0]
        self.left.navigate(str(self.a))
        self.right = self.win._add_pane_to_splitter(
            self.win._root_splitter, type(self.left.backend)()
        )
        self.right.navigate(str(self.b))
        self.assertTrue(self.wait_for(lambda: self.row_of(self.left, "f.txt") is not None))
        self.assertTrue(self.wait_for(lambda: self.row_of(self.right, "inbox") is not None))
        self.asked: list = []
        p = mock.patch.object(
            self.MW.MainWindow,
            "_ask_transfer_conflict",
            lambda _w, conflict, remaining: self.asked.append(conflict.name),
            create=True,
        )
        p.start()
        self.addCleanup(p.stop)

    # -- helpers -------------------------------------------------------------
    def wait_for(self, predicate, timeout: float = 10.0) -> bool:
        end = time.time() + timeout
        while time.time() < end:
            self.app.processEvents()
            if predicate():
                return True
            time.sleep(0.01)
        return False

    def settle(self) -> None:
        from core.transfer_worker import TransferStatus

        def idle() -> bool:
            if getattr(self.win, "_conflict_checks", None):
                return False
            jobs = list(self.win._transfer_manager._jobs.values())
            return all(
                j.status not in (TransferStatus.PENDING, TransferStatus.ACTIVE) for j in jobs
            )

        self.assertTrue(self.wait_for(idle))
        self.wait_for(lambda: False, timeout=0.2)
        self.assertTrue(self.wait_for(idle))

    @staticmethod
    def row_of(pane, name: str):
        proxy = pane._table.model()
        for row in range(proxy.rowCount()):
            if proxy.index(row, 0).data() == name:
                return row
        return None

    def mime_from(self, pane, *paths):
        from PyQt6.QtCore import QMimeData

        from ui.file_pane import TRANSFER_MIME_TYPE

        mime = QMimeData()
        mime.setData(TRANSFER_MIME_TYPE, pane._encode_transfer_payload([str(p) for p in paths]))
        return mime

    def point(self, pane, name: str | None):
        """Viewport position on the row *name*, or below every row."""
        from PyQt6.QtCore import QPoint

        view = pane._table
        if name is None:
            return QPoint(10, view.viewport().height() - 3)
        row = self.row_of(pane, name)
        self.assertIsNotNone(row, name)
        return view.visualRect(view.model().index(row, 0)).center()

    def drop(self, pane, mime, at, *, ctrl: bool = False) -> bool:
        """Deliver drag-move then drop to *pane*'s table; True when accepted."""
        from PyQt6.QtCore import QPointF, Qt
        from PyQt6.QtGui import QDragMoveEvent, QDropEvent

        mods = (
            Qt.KeyboardModifier.ControlModifier if ctrl else Qt.KeyboardModifier.NoModifier
        )
        actions = Qt.DropAction.CopyAction | Qt.DropAction.MoveAction
        view = pane._table
        move = QDragMoveEvent(at, actions, mime, Qt.MouseButton.LeftButton, mods)
        view.dragMoveEvent(move)
        if not move.isAccepted():
            return False
        drop = QDropEvent(QPointF(at), actions, mime, Qt.MouseButton.LeftButton, mods)
        drop.setDropAction(move.dropAction())
        view.dropEvent(drop)
        self.settle()
        return drop.isAccepted()


class BetweenPanesTest(_Panes):
    def test_happy_a_plain_drop_moves(self) -> None:
        self.assertTrue(self.drop(self.right, self.mime_from(self.left, self.a / "f.txt"),
                                  self.point(self.right, None)))
        self.assertFalse((self.a / "f.txt").exists())
        self.assertEqual((self.b / "f.txt").read_text(), "payload")

    def test_happy_ctrl_copies(self) -> None:
        self.assertTrue(self.drop(self.right, self.mime_from(self.left, self.a / "f.txt"),
                                  self.point(self.right, None), ctrl=True))
        self.assertEqual((self.a / "f.txt").read_text(), "payload")
        self.assertEqual((self.b / "f.txt").read_text(), "payload")

    def test_edge_a_drop_on_a_folder_row_lands_in_that_folder(self) -> None:
        self.drop(self.right, self.mime_from(self.left, self.a / "f.txt"),
                  self.point(self.right, "inbox"))
        self.assertEqual((self.b / "inbox" / "f.txt").read_text(), "payload")
        self.assertFalse((self.b / "f.txt").exists())

    def test_edge_the_drag_proposes_move_as_the_default_action(self) -> None:
        from PyQt6.QtCore import Qt

        self.left._table.selectRow(self.row_of(self.left, "f.txt"))
        with mock.patch("ui.file_pane.QDrag.exec", return_value=Qt.DropAction.IgnoreAction) as ex:
            self.left._start_drag()
        self.assertEqual(ex.call_args.args[1], Qt.DropAction.MoveAction)

    def test_sad_a_drop_into_an_existing_name_still_asks(self) -> None:
        (self.b / "inbox" / "f.txt").write_text("old")
        self.drop(self.right, self.mime_from(self.left, self.a / "f.txt"),
                  self.point(self.right, "inbox"))
        self.assertEqual(self.asked, ["f.txt"])
        self.assertEqual((self.b / "inbox" / "f.txt").read_text(), "old")
        self.assertTrue((self.a / "f.txt").exists())


class InsideOnePaneTest(_Panes):
    def test_happy_a_drop_on_a_subfolder_moves_into_it(self) -> None:
        self.assertTrue(self.drop(self.left, self.mime_from(self.left, self.a / "f.txt"),
                                  self.point(self.left, "sub")))
        self.assertFalse((self.a / "f.txt").exists())
        self.assertEqual((self.a / "sub" / "f.txt").read_text(), "payload")

    def test_happy_ctrl_copies_into_the_subfolder(self) -> None:
        self.drop(self.left, self.mime_from(self.left, self.a / "f.txt"),
                  self.point(self.left, "sub"), ctrl=True)
        self.assertEqual((self.a / "f.txt").read_text(), "payload")
        self.assertEqual((self.a / "sub" / "f.txt").read_text(), "payload")

    def test_sad_a_drop_on_empty_space_or_on_a_file_does_nothing(self) -> None:
        mime = self.mime_from(self.left, self.a / "sub")
        self.assertFalse(self.drop(self.left, mime, self.point(self.left, None)))
        self.assertFalse(self.drop(self.left, mime, self.point(self.left, "f.txt")))
        self.assertTrue((self.a / "sub").is_dir())
        self.assertEqual(self.win._transfer_manager.all_jobs(), [])

    def test_sad_a_folder_dropped_on_itself_does_nothing(self) -> None:
        self.assertFalse(self.drop(self.left, self.mime_from(self.left, self.a / "sub"),
                                   self.point(self.left, "sub")))
        self.assertTrue((self.a / "sub").is_dir())
        self.assertEqual(self.win._transfer_manager.all_jobs(), [])

    def test_edge_a_drop_on_dotdot_moves_to_the_parent_folder(self) -> None:
        (self.a / "sub" / "g.txt").write_text("deep")
        self.left.navigate(str(self.a / "sub"))
        self.assertTrue(self.wait_for(lambda: self.row_of(self.left, "g.txt") is not None))
        self.drop(self.left, self.mime_from(self.left, self.a / "sub" / "g.txt"),
                  self.point(self.left, ".."))
        self.assertEqual((self.a / "g.txt").read_text(), "deep")
        self.assertFalse((self.a / "sub" / "g.txt").exists())


if __name__ == "__main__":
    unittest.main()
