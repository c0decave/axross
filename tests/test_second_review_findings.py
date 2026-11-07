"""What the follow-up review of 0.14.177-0.14.181 found.

- An undo of a moved folder whose walk failed half way moved back what
  was found and was then recorded as undone - Ctrl+Z could not try the
  rest. It stays in the history now ("Partly undone"); a move whose walk
  failed half way no longer carries the folder's own tags along.
- The viewer's move watch could lose a re-check asked for while a check
  ran: its job's thread was still alive when its result came in.
- The image viewer waits for a decode in a nested event loop; a load
  asked for meanwhile (a confirmed move, removed metadata) ran inside it,
  and the outer one then put the old picture over the new one.
"""

from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QObject, QTimer, pyqtSignal  # noqa: E402
from PyQt6.QtGui import QColor, QImage  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core.local_fs import LocalFS  # noqa: E402

APP = QApplication.instance() or QApplication([])


def test_sad_a_partly_undone_move_stays_in_the_history():
    from ui.main_window import MainWindow

    finished: list = []

    class Window:
        _await_undo_jobs = MainWindow._await_undo_jobs
        _on_undo_job_finished = MainWindow._on_undo_job_finished

        def __init__(self) -> None:
            self._undo_waits = []
            self._panes = []
            self.status = mock.MagicMock()

        def statusBar(self):  # noqa: N802 - Qt name
            return self.status

        def _finish_undo(self, plan, pane, jobs=()):
            finished.append(plan)

    from core.transfer_worker import TransferStatus

    window = Window()
    plan = SimpleNamespace(reason="move back photos")
    job = SimpleNamespace(job_id="j1", status=TransferStatus.PENDING)
    window._await_undo_jobs(plan, [job], None, record=False)
    window._on_undo_job_finished("j1")
    assert finished == []  # not recorded: Ctrl+Z can try the rest
    assert "Partly undone" in window.status.showMessage.call_args.args[0]
    window._await_undo_jobs(plan, [SimpleNamespace(job_id="j2", status=TransferStatus.PENDING)],
                            None)
    window._on_undo_job_finished("j2")
    assert finished == [plan]  # a whole one still is


def test_sad_the_walk_error_comes_before_the_jobs():
    """So a caller knows the walk was partial before it acts on the jobs."""
    from core import transfer_manager as TM

    order: list[str] = []
    mgr = TM.TransferManager(max_parallel=1)

    def fails(*a, **k):
        raise OSError("link down")

    mgr.transfer_files = fails
    try:
        mgr.transfer_files_in_background(
            LocalFS(), LocalFS(), ["/x"], "/y",
            on_done=lambda jobs: order.append("done"), on_error=lambda e: order.append("error"))
        deadline = time.monotonic() + 5
        while len(order) < 2 and time.monotonic() < deadline:
            APP.processEvents()
            time.sleep(0.01)
    finally:
        mgr.shutdown()
    assert order == ["error", "done"]


def test_sad_a_recheck_asked_for_during_a_check_is_not_lost():
    from ui.viewer_file_actions import MoveWatch

    class Pane(QObject):
        path_changed = pyqtSignal(str)

    rounds: list[int] = []
    asked_again = threading.Event()

    class Backend:
        """The first check sees the file (and lasts until the second ask);
        the re-check sees it gone."""

        def exists(self, path):
            rounds.append(1)
            if len(rounds) == 1:
                asked_again.wait(2)
                time.sleep(0.05)
                return True
            return False

    owner, pane = QObject(), Pane()
    gone: list[str] = []
    watch = MoveWatch(owner, Backend(), pane, gone.append)
    watch.watch("/x/a.jpg")
    pane.path_changed.emit("/x")  # a check starts: the file is still there
    pane.path_changed.emit("/x")  # asked again while it runs
    asked_again.set()
    deadline = time.monotonic() + 5
    while not gone and time.monotonic() < deadline:
        APP.processEvents()
        time.sleep(0.01)
    assert gone == ["/x/a.jpg"] and len(rounds) == 2


def test_sad_a_load_asked_for_during_a_decode_wins(tmp_path):
    from core import previews as P
    from ui.image_viewer import ImageViewerDialog

    paths = []
    for i, colour in enumerate(("red", "blue")):
        image = QImage(64, 48, QImage.Format.Format_RGB32)
        image.fill(QColor(colour))
        path = tmp_path / f"p{i}.png"
        image.save(str(path))
        paths.append(str(path))
    dlg = ImageViewerDialog(LocalFS(), paths[0], siblings=list(paths))
    real = P.decode_image

    def slow(backend, path, **kw):
        time.sleep(0.3)
        return real(backend, path, **kw)

    def drop_current():  # a confirmed move of the shown file, during the decode
        dlg._siblings.pop(0)
        dlg._idx = 0
        dlg._load_current()

    try:
        with mock.patch.object(P, "decode_image", slow):
            QTimer.singleShot(100, drop_current)
            dlg._load_current()
        assert dlg._siblings == [paths[1]]
        assert dlg._original.pixelColor(0, 0) == QColor("blue")
    finally:
        dlg.close()
        dlg.deleteLater()


def test_sad_the_partial_undo_watches_its_jobs_before_it_warns():
    """Found by the final review: the warning about a half-read folder
    opened before the jobs were watched; its dialog's event loop delivered
    the finished jobs, and the undo never completed."""
    from PyQt6.QtWidgets import QMessageBox

    from core.transfer_worker import TransferStatus
    from ui.main_window import MainWindow

    class Window:
        _undo_jobs_queued = MainWindow._undo_jobs_queued
        _await_undo_jobs = MainWindow._await_undo_jobs

        def __init__(self) -> None:
            self._undo_waits = []

        def statusBar(self):  # noqa: N802 - Qt name
            return mock.MagicMock()

    window = Window()
    plan = SimpleNamespace(reason="move back photos", source="/x/photos")
    job = SimpleNamespace(job_id="j1", status=TransferStatus.PENDING)
    watched_when_warned: list[int] = []
    with mock.patch.object(QMessageBox, "warning",
                           lambda *a, **k: watched_when_warned.append(len(window._undo_waits))):
        window._undo_jobs_queued(plan, None, [OSError("denied")], [job])
    assert watched_when_warned == [1]  # watched before the dialog
    assert window._undo_waits[0]["record"] is False

    window._undo_waits.clear()
    said: list[str] = []
    with mock.patch.object(QMessageBox, "warning", lambda *a, **k: said.append(a[1])):
        window._undo_jobs_queued(plan, None, [OSError("denied")], [])
    assert said == ["Undo failed"]  # one message, not two
