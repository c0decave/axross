"""Delete and drag-out in the image and the media viewer.

Requested: in the image / media viewer Delete should work,
and dragging the shown file onto a pane should move it there, or copy it
with Ctrl held - like a drag between panes. The drag carries the pane
transfer payload of the pane the viewer was opened from, so the drop
goes through the same move / copy path (conflict check, journal,
verify-before-delete) as a drag that started in that pane.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import QEvent, QPointF, Qt  # noqa: E402
from PyQt6.QtGui import QDrag, QMouseEvent  # noqa: E402
from PyQt6.QtWidgets import QApplication, QLayout, QMessageBox  # noqa: E402

import ui.main_window  # noqa: E402,F401 - see test_viewer_window_state
from core import i18n  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402
from tests.media_testkit import write_image  # noqa: E402
from ui import media_viewer as MV  # noqa: E402
from ui.file_pane import TRANSFER_MIME_TYPE, FilePaneWidget  # noqa: E402
from ui.image_viewer import ImageViewerDialog  # noqa: E402

APP = QApplication.instance() or QApplication([])


def wait_until(cond, timeout: float = 15.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        APP.processEvents()
        if cond():
            return True
        time.sleep(0.005)
    APP.processEvents()
    return cond()


@pytest.fixture(autouse=True)
def _settings(tmp_path, monkeypatch):
    monkeypatch.setattr(i18n, "SETTINGS_FILE", tmp_path / "cfg" / "session.json")


@pytest.fixture
def pics(tmp_path) -> list[Path]:
    return [write_image(tmp_path / "pics" / f"{n}.png", size=(60, 40)) for n in ("a", "b")]


@pytest.fixture
def pane(tmp_path):
    p = FilePaneWidget(LocalFS())
    p.navigate(str(tmp_path / "pics"))
    yield p
    p.deleteLater()


def _image_viewer(pics, pane=None, current=0):
    paths = [str(p) for p in pics]
    dlg = ImageViewerDialog(LocalFS(), paths[current], siblings=paths, parent=pane)
    dlg.show()
    assert wait_until(dlg.isVisible)
    return dlg


def _media_dialog(folder: Path, pane=None):
    options = MV.MediaViewOptions(kinds=frozenset({MV.MC.IMAGE}), recursive=False)
    dlg = MV.MediaViewerDialog(LocalFS(), str(folder), options, source_pane=pane)
    dlg.layout().setSizeConstraint(QLayout.SizeConstraint.SetNoConstraint)
    dlg.setMinimumSize(0, 0)
    dlg.show()
    dlg.start()
    assert wait_until(lambda: dlg.scan_finished)
    return dlg


def _mouse_drag(widget, start=(20, 20), end=(80, 80)):
    """Press, move past the drag distance, release - on *widget*."""
    def send(kind, pos, buttons):
        button = Qt.MouseButton.LeftButton if kind != QEvent.Type.MouseMove else Qt.MouseButton.NoButton
        event = QMouseEvent(kind, QPointF(*pos), QPointF(widget.mapToGlobal(QPointF(*pos).toPoint())),
                            button, buttons, Qt.KeyboardModifier.NoModifier)
        QApplication.sendEvent(widget, event)

    L = Qt.MouseButton.LeftButton
    send(QEvent.Type.MouseButtonPress, start, L)
    steps = 6
    for i in range(1, steps + 1):
        x = start[0] + (end[0] - start[0]) * i / steps
        y = start[1] + (end[1] - start[1]) * i / steps
        send(QEvent.Type.MouseMove, (x, y), L)
    send(QEvent.Type.MouseButtonRelease, end, Qt.MouseButton.NoButton)


class _Exec:
    """Stands in for QDrag.exec: records the payload, returns *result*."""

    def __init__(self, result):
        self.result = result
        self.payloads = []

    def __call__(self, drag, *args, **kwargs):
        mime = drag.mimeData()
        self.payloads.append(json.loads(bytes(mime.data(TRANSFER_MIME_TYPE)).decode()))
        assert not drag.pixmap().isNull()
        return self.result

    def patch(self):
        # A function, so QDrag.exec binds the drag as its first argument.
        return mock.patch.object(QDrag, "exec", lambda drag, *a, **k: self(drag, *a, **k))


# -- happy ---------------------------------------------------------------------


def test_happy_delete_in_the_image_viewer_removes_the_file_and_shows_the_next(pics, pane):
    dlg = _image_viewer(pics, pane)
    with mock.patch.object(QMessageBox, "question", return_value=QMessageBox.StandardButton.Yes):
        dlg.delete_current()
    assert not pics[0].exists() and pics[1].exists()
    assert dlg.current_path() == str(pics[1])
    dlg.reject()


def test_happy_dragging_the_image_out_moves_it_through_the_pane_payload(pics, pane):
    dlg = _image_viewer(pics, pane)
    fake = _Exec(Qt.DropAction.MoveAction)
    with fake.patch():
        _mouse_drag(dlg.drag_surface())
    assert fake.payloads == [{"paths": [str(pics[0])], "source_pane_id": str(id(pane)), "dirs": []}]
    # A move took the file away: the viewer goes on with the next one.
    assert dlg.current_path() == str(pics[1])
    dlg.reject()


def test_happy_the_media_viewer_deletes_and_drags_out_too(pics, pane):
    dlg = _media_dialog(pics[0].parent, pane)
    dlg.open_viewer(0)
    first = dlg.viewer.current_item().path
    with mock.patch.object(QMessageBox, "question", return_value=QMessageBox.StandardButton.Yes):
        dlg.delete_current()
    assert not Path(first).exists()
    assert [i.path for i in dlg.model.items()] == [p for p in map(str, pics) if p != first]
    assert dlg.viewer.current_item().path != first
    fake = _Exec(Qt.DropAction.CopyAction)
    with fake.patch():
        _mouse_drag(dlg.drag_surface())
    left = dlg.viewer.current_item().path
    assert fake.payloads and fake.payloads[0]["paths"] == [left]
    assert [i.path for i in dlg.model.items()] == [left]  # a copy keeps it
    dlg.reject()


def test_happy_a_tile_of_the_overview_drags_and_deletes(pics, pane):
    dlg = _media_dialog(pics[0].parent, pane)
    view = dlg.overview.view
    tile = view.visualRect(dlg.overview.proxy.index(1, 0)).center()
    fake = _Exec(Qt.DropAction.MoveAction)
    with fake.patch():
        _mouse_drag(view.viewport(), (tile.x(), tile.y()), (tile.x() + 60, tile.y() + 60))
    assert fake.payloads and len(fake.payloads[0]["paths"]) == 1
    moved = fake.payloads[0]["paths"][0]
    assert moved not in [i.path for i in dlg.model.items()]
    view.setCurrentIndex(dlg.overview.proxy.index(0, 0))
    with mock.patch.object(QMessageBox, "question", return_value=QMessageBox.StandardButton.Yes):
        dlg.delete_current()
    assert dlg.model.items() == []
    dlg.reject()


# -- sad -----------------------------------------------------------------------


def test_sad_no_answers_no_and_a_failing_remove_keep_the_file(pics, pane):
    dlg = _image_viewer(pics, pane)
    with mock.patch.object(QMessageBox, "question", return_value=QMessageBox.StandardButton.No):
        dlg.delete_current()
    assert pics[0].exists() and dlg.current_path() == str(pics[0])
    with (
        mock.patch.object(QMessageBox, "question", return_value=QMessageBox.StandardButton.Yes),
        mock.patch.object(LocalFS, "remove", side_effect=PermissionError("read-only")),
        mock.patch.object(QMessageBox, "warning") as warned,
    ):
        dlg.delete_current()
    assert pics[0].exists() and dlg.current_path() == str(pics[0])
    assert "read-only" in str(warned.call_args)
    dlg.reject()


def test_sad_without_a_pane_there_is_no_drag(pics):
    dlg = _image_viewer(pics, None)
    fake = _Exec(Qt.DropAction.MoveAction)
    with fake.patch():
        _mouse_drag(dlg.drag_surface())
    assert fake.payloads == []
    assert dlg.current_path() == str(pics[0])
    dlg.reject()


def test_sad_a_refused_drop_keeps_the_item(pics, pane):
    dlg = _image_viewer(pics, pane)
    with _Exec(Qt.DropAction.IgnoreAction).patch():
        _mouse_drag(dlg.drag_surface())
    assert dlg.current_path() == str(pics[0])
    dlg.reject()


# -- edge ----------------------------------------------------------------------


def test_edge_deleting_the_last_image_closes_the_viewer(pics, pane):
    dlg = _image_viewer(pics[:1], pane)
    with mock.patch.object(QMessageBox, "question", return_value=QMessageBox.StandardButton.Yes):
        dlg.delete_current()
    assert not pics[0].exists()
    assert wait_until(lambda: not dlg.isVisible())


def test_edge_a_zoomed_in_media_image_pans_instead_of_dragging(pics, pane):
    dlg = _media_dialog(pics[0].parent, pane)
    dlg.open_viewer(0)
    assert wait_until(lambda: dlg.viewer.mode == "image")
    dlg.viewer.image_view.zoom_by(40)
    APP.processEvents()
    fake = _Exec(Qt.DropAction.MoveAction)
    with fake.patch():
        _mouse_drag(dlg.drag_surface())
    assert fake.payloads == []
    dlg.reject()


def test_edge_the_delete_key_reaches_it(pics, pane):
    from PyQt6.QtGui import QKeySequence, QShortcut

    dlg = _image_viewer(pics, pane)
    keys = [s for s in dlg.findChildren(QShortcut) if s.key() == QKeySequence(QKeySequence.StandardKey.Delete)]
    assert len(keys) == 1
    media = _media_dialog(pics[0].parent, pane)
    keys = [s for s in media.findChildren(QShortcut) if s.key() == QKeySequence(QKeySequence.StandardKey.Delete)]
    assert len(keys) == 1
    dlg.reject()
    media.reject()


# -- end to end: the viewer's drag lands like a pane drag ------------------------

from tests.test_drag_drop_move_copy import _Panes  # noqa: E402


class ViewerDropOnPaneTest(_Panes):
    def viewer_mime(self, path):
        seen = {}

        def fake(drag, *args, **kwargs):
            seen["mime"] = drag.mimeData()
            return Qt.DropAction.IgnoreAction

        from ui import viewer_file_actions as VFA

        with mock.patch.object(QDrag, "exec", fake):
            VFA.start_file_drag(self.left._table, LocalFS(), str(path), self.left)
        return seen["mime"]

    def test_happy_a_plain_drop_moves_the_viewed_file_into_the_other_pane(self) -> None:
        mime = self.viewer_mime(self.a / "f.txt")
        self.assertTrue(self.drop(self.right, mime, self.point(self.right, None)))
        self.assertFalse((self.a / "f.txt").exists())
        self.assertEqual((self.b / "f.txt").read_text(), "payload")

    def test_edge_ctrl_copies_it(self) -> None:
        mime = self.viewer_mime(self.a / "f.txt")
        self.drop(self.right, mime, self.point(self.right, "inbox"), ctrl=True)
        self.assertEqual((self.a / "f.txt").read_text(), "payload")
        self.assertEqual((self.b / "inbox" / "f.txt").read_text(), "payload")
