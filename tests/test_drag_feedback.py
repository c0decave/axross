"""A drag shows what moves and where it goes.

Reported: a file moved onto another pane "never arrived"
and was gone from its own pane. It had been released on that pane's ".."
row, which moves into the folder above (test_drag_drop_move_copy) - and
nothing on screen said so: the drag carried no image (QDrag without a
pixmap shows only the cursor) and the target pane marked nothing.

Now the drag carries a picture of what it moves (name, icon, "+N more")
that follows the mouse, and the pane under the cursor frames the row the
drop goes into and says "Move to <folder>" / "Copy to <folder>" beside
the cursor - for "..", the folder above, by its path.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from tests.test_drag_drop_move_copy import _Panes  # noqa: E402


class DropHintTest(_Panes):
    def hover(self, pane, mime, at, *, ctrl=False):
        from PyQt6.QtCore import Qt
        from PyQt6.QtGui import QDragMoveEvent

        mods = Qt.KeyboardModifier.ControlModifier if ctrl else Qt.KeyboardModifier.NoModifier
        actions = Qt.DropAction.CopyAction | Qt.DropAction.MoveAction
        event = QDragMoveEvent(at, actions, mime, Qt.MouseButton.LeftButton, mods)
        pane._table.dragMoveEvent(event)
        self.app.processEvents()
        return event.isAccepted()

    def leave(self, pane):
        from PyQt6.QtGui import QDragLeaveEvent

        pane._table.dragLeaveEvent(QDragLeaveEvent())
        self.app.processEvents()

    def row_rect(self, pane, name):
        view = pane._table
        row = self.row_of(pane, name)
        return view.visualRect(view.model().index(row, 0))

    # -- happy -----------------------------------------------------------------

    def test_happy_dotdot_says_move_to_the_folder_above_and_frames_the_row(self) -> None:
        mime = self.mime_from(self.left, self.a / "f.txt")
        self.assertTrue(self.hover(self.right, mime, self.point(self.right, "..")))
        hint = self.right._drop_hint
        self.assertTrue(hint.isVisible())
        self.assertIn("Move to", hint.text())
        self.assertIn(str(self.b.parent), hint.text())
        self.assertIn("one folder up", hint.text())
        marker = self.right._drop_row_marker
        self.assertTrue(marker.isVisible())
        self.assertTrue(marker.geometry().intersects(self.row_rect(self.right, "..")))

    def test_happy_ctrl_says_copy_and_a_folder_row_names_that_folder(self) -> None:
        mime = self.mime_from(self.left, self.a / "f.txt")
        self.hover(self.right, mime, self.point(self.right, "inbox"), ctrl=True)
        text = self.right._drop_hint.text()
        self.assertIn("Copy to", text)
        self.assertIn(str(self.b / "inbox"), text)

    def test_happy_the_drag_carries_a_picture_that_follows_the_mouse(self) -> None:
        from PyQt6.QtCore import Qt
        from PyQt6.QtGui import QDrag

        seen = {}

        def fake_exec(drag, *args, **kwargs):
            seen["pixmap"] = drag.pixmap()
            seen["hot"] = drag.hotSpot()
            return Qt.DropAction.IgnoreAction

        row = self.row_of(self.left, "f.txt")
        self.left._table.selectRow(row)
        with mock.patch.object(QDrag, "exec", fake_exec):
            self.left._start_drag()
        pix = seen["pixmap"]
        self.assertFalse(pix.isNull())
        self.assertTrue(0 <= seen["hot"].x() < pix.width() / pix.devicePixelRatio())

    # -- sad -------------------------------------------------------------------

    def test_sad_a_drop_that_would_do_nothing_shows_no_hint(self) -> None:
        mime = self.mime_from(self.left, self.a / "sub")
        self.assertFalse(self.hover(self.left, mime, self.point(self.left, "sub")))
        self.assertFalse(self.left._drop_hint.isVisible())
        self.assertFalse(self.left._drop_row_marker.isVisible())

    def test_sad_leaving_or_dropping_takes_the_hint_away(self) -> None:
        mime = self.mime_from(self.left, self.a / "f.txt")
        self.hover(self.right, mime, self.point(self.right, ".."))
        self.leave(self.right)
        self.assertFalse(self.right._drop_hint.isVisible())
        self.assertFalse(self.right._drop_row_marker.isVisible())
        self.assertTrue(self.drop(self.right, mime, self.point(self.right, None)))
        self.assertFalse(self.right._drop_hint.isVisible())
        self.assertEqual((self.b / "f.txt").read_text(), "payload")

    # -- edge ------------------------------------------------------------------

    def test_edge_empty_space_names_the_pane_folder_without_a_row_frame(self) -> None:
        mime = self.mime_from(self.left, self.a / "f.txt")
        self.hover(self.right, mime, self.point(self.right, None))
        self.assertIn(str(self.b), self.right._drop_hint.text())
        self.assertNotIn(str(self.b / "inbox"), self.right._drop_hint.text())
        self.assertFalse(self.right._drop_row_marker.isVisible())

    def test_edge_moving_from_dotdot_to_a_folder_updates_the_hint(self) -> None:
        mime = self.mime_from(self.left, self.a / "f.txt")
        self.hover(self.right, mime, self.point(self.right, ".."))
        self.hover(self.right, mime, self.point(self.right, "inbox"))
        self.assertIn(str(self.b / "inbox"), self.right._drop_hint.text())
        self.assertNotIn("one folder up", self.right._drop_hint.text())
        self.assertTrue(self.right._drop_row_marker.geometry().intersects(
            self.row_rect(self.right, "inbox")))

    def test_edge_the_picture_counts_several_items(self) -> None:
        from ui.file_pane import drag_pixmap

        one = drag_pixmap(["f.txt"], dirs=0)
        three = drag_pixmap(["f.txt", "g.txt", "sub"], dirs=1)
        long = drag_pixmap(["x" * 500], dirs=0)
        self.assertFalse(one.isNull() or three.isNull())
        self.assertNotEqual(one.toImage(), three.toImage())
        self.assertLessEqual(long.width() / long.devicePixelRatio(), 360)


if __name__ == "__main__":
    import unittest

    unittest.main()
