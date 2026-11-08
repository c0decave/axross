"""The Transfers dock: a right-click menu per job, and Clear Finished
mid-batch.

* The tour ("a right click on a job offers Cancel, Retry and Open
  destination folder") and the handbook promised a context menu on a
  transfer job; the table had none - a right click did nothing.
* Clear Finished while a batch still ran dropped the overall progress bar
  to 0 %: the finished jobs left the manager's list, and with them their
  share of the batch.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QObject, QPoint, QTimer, pyqtSignal  # noqa: E402
from PyQt6.QtGui import QContextMenuEvent  # noqa: E402
from PyQt6.QtWidgets import QApplication, QMenu, QWidget  # noqa: E402

from core.transfer_worker import TransferJob, TransferStatus  # noqa: E402

APP = QApplication.instance() or QApplication([])


class FakeManager(QObject):
    job_added = pyqtSignal(object)
    job_updated = pyqtSignal(str)
    job_finished = pyqtSignal(str)
    job_error = pyqtSignal(str, str)
    jobs_trimmed = pyqtSignal(list)

    def __init__(self):
        super().__init__()
        self.jobs: dict[str, TransferJob] = {}
        self.calls: list = []

    def all_jobs(self):
        return list(self.jobs.values())

    def clear_finished(self):
        for key in [k for k, j in self.jobs.items()
                    if j.status not in (TransferStatus.ACTIVE, TransferStatus.PENDING)]:
            del self.jobs[key]

    def cancel_job(self, job_id):
        self.calls.append(("cancel", job_id))

    def retry_job(self, job_id):
        self.calls.append(("retry", job_id))
        return None


class Window(QWidget):
    def __init__(self):
        super().__init__()
        self.revealed: list = []

    def _reveal_found(self, backend, path):
        self.revealed.append((backend, path))


@pytest.fixture
def dock():
    from ui.transfer_dock import TransferDock

    window = Window()
    manager = FakeManager()
    dock = TransferDock(manager, window)
    dock.resize(800, 300)
    dock.show()
    yield dock
    dock.close()
    window.deleteLater()


def _add(dock, status, name="f", backend=None):
    job = TransferJob(source_path=f"/s/{name}", dest_path=f"/d/{name}",
                      total_bytes=1000, filename=name)
    job.status = status
    job.dest_backend = backend
    dock._manager.jobs[job.job_id] = job
    dock._manager.job_added.emit(job)
    return job


def _actions(menu) -> dict:
    return {a.objectName(): a for a in menu.actions() if a.objectName()}


def test_happy_a_right_click_on_a_job_opens_its_menu(dock):
    _add(dock, TransferStatus.ACTIVE)
    APP.processEvents()
    table = dock._table
    seen: list = []

    def look():
        for menu in APP.topLevelWidgets():
            if isinstance(menu, QMenu) and menu.isVisible():
                seen.append([a.text() for a in menu.actions() if not a.isSeparator()])
                menu.close()

    QTimer.singleShot(100, look)
    pos = table.visualRect(dock._model.index(0, 0)).center()
    APP.sendEvent(table.viewport(), QContextMenuEvent(QContextMenuEvent.Reason.Mouse, pos))
    APP.processEvents()
    assert seen == [["Cancel", "Retry", "Open destination folder"]]


def test_happy_cancel_acts_on_the_one_job_and_retry_on_a_failed_one(dock):
    running = _add(dock, TransferStatus.ACTIVE, "run")
    failed = _add(dock, TransferStatus.ERROR, "bad")
    menu = dock.build_job_menu(running)
    acts = _actions(menu)
    assert acts["axTransferJobCancel"].isEnabled()
    assert not acts["axTransferJobRetry"].isEnabled()
    acts["axTransferJobCancel"].trigger()
    menu = dock.build_job_menu(failed)
    acts = _actions(menu)
    assert not acts["axTransferJobCancel"].isEnabled()
    assert acts["axTransferJobRetry"].isEnabled()
    acts["axTransferJobRetry"].trigger()
    assert dock._manager.calls == [("cancel", running.job_id), ("retry", failed.job_id)]


def test_edge_a_retried_or_done_job_offers_no_retry_and_no_row_offers_nothing(dock):
    done = _add(dock, TransferStatus.DONE)
    retried = _add(dock, TransferStatus.CANCELLED)
    retried.retried = True
    for job in (done, retried):
        acts = _actions(dock.build_job_menu(job))
        assert not acts["axTransferJobRetry"].isEnabled()
        assert not acts["axTransferJobCancel"].isEnabled()
    acts = _actions(dock.build_job_menu(None))
    assert not any(a.isEnabled() for a in acts.values())
    assert dock._job_at(QPoint(5, 290)) is None


def test_happy_open_destination_folder_reveals_it_in_a_pane(dock):
    backend = object()
    job = _add(dock, TransferStatus.DONE, "x", backend)
    _actions(dock.build_job_menu(job))["axTransferJobReveal"].trigger()
    assert dock.parent().revealed == [(backend, "/d/x")]


def test_sad_clear_finished_mid_batch_keeps_the_overall_progress(dock):
    jobs = [_add(dock, TransferStatus.PENDING, f"f{i}") for i in range(10)]
    for job in jobs[:9]:
        job.status = TransferStatus.DONE
        job.transferred_bytes = 1000
    jobs[9].status = TransferStatus.ACTIVE
    dock._update_overall()
    assert dock._overall_progress.value() == 90
    dock._clear_finished()
    assert dock._overall_progress.value() == 90
    jobs[9].transferred_bytes = 500
    dock._update_overall()
    assert dock._overall_progress.value() == 95
