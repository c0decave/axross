"""A viewer drops a dragged-out file only once the file is really gone.

Found in review (round 3, files; reproduced here): a pane accepts a drop
with MoveAction the moment it hands the paths to the main window
(FilePaneWidget.dropEvent). The move itself runs later: the destination
is checked on a background job, a conflict is put to the user, then the
transfer is queued. The image and media viewers took the drag's
MoveAction for a finished move and removed the image at once - cancelling
the conflict prompt (or a failed transfer) left the file where it was but
gone from the viewer.

The viewers now wait for the source pane's next listing (the main window
refreshes it when the move finished) and ask the backend whether the file
is still there.
"""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import Qt  # noqa: E402

from core.local_fs import LocalFS  # noqa: E402
from tests.test_viewer_file_actions import (  # noqa: E402,F401 - fixtures
    _Exec,
    _image_viewer,
    _media_dialog,
    _mouse_drag,
    _settings,
    pane,
    pics,
    wait_until,
)


def _move_away(path: Path, tmp_path: Path) -> None:
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir(exist_ok=True)
    shutil.move(str(path), str(elsewhere / path.name))


def _refresh(pane) -> None:
    pane.refresh_after_change()
    assert wait_until(lambda: not pane.is_loading)


def test_sad_move_cancelled_at_the_prompt_keeps_the_image(pics, pane):
    dlg = _image_viewer(pics, pane)
    with _Exec(Qt.DropAction.MoveAction).patch():
        _mouse_drag(dlg.drag_surface())
    # Nothing moved (the conflict prompt was cancelled); the pane refreshes.
    assert dlg.current_path() == str(pics[0])
    _refresh(pane)
    assert pics[0].exists()
    assert dlg.current_path() == str(pics[0])
    dlg.reject()


def test_happy_image_leaves_the_viewer_when_the_move_finished(pics, pane, tmp_path):
    dlg = _image_viewer(pics, pane)
    with _Exec(Qt.DropAction.MoveAction).patch():
        _mouse_drag(dlg.drag_surface())
    _move_away(pics[0], tmp_path)
    _refresh(pane)
    assert wait_until(lambda: dlg.current_path() == str(pics[1]))
    dlg.reject()


def test_happy_media_viewer_waits_for_the_move_too(pics, pane, tmp_path):
    dlg = _media_dialog(pics[0].parent, pane)
    dlg.open_viewer(0)
    first = dlg.viewer.current_item().path
    with _Exec(Qt.DropAction.MoveAction).patch():
        _mouse_drag(dlg.drag_surface())
    assert first in [i.path for i in dlg.model.items()]
    _refresh(pane)
    assert first in [i.path for i in dlg.model.items()]
    _move_away(Path(first), tmp_path)
    _refresh(pane)
    assert wait_until(lambda: first not in [i.path for i in dlg.model.items()])
    dlg.reject()


def test_edge_a_backend_error_while_checking_keeps_the_image(pics, pane):
    dlg = _image_viewer(pics, pane)
    with _Exec(Qt.DropAction.MoveAction).patch():
        _mouse_drag(dlg.drag_surface())
    with mock.patch.object(LocalFS, "exists", side_effect=OSError("connection lost")):
        _refresh(pane)
    assert dlg.current_path() == str(pics[0])
    dlg.reject()


def test_edge_a_copy_is_never_watched(pics, pane, tmp_path):
    """Only a move is followed: a copied file that vanishes later for
    another reason is the business of a fresh listing, not of the drag."""
    dlg = _image_viewer(pics, pane)
    with _Exec(Qt.DropAction.CopyAction).patch():
        _mouse_drag(dlg.drag_surface())
    _move_away(pics[0], tmp_path)
    _refresh(pane)
    assert dlg.current_path() == str(pics[0])
    dlg.reject()
