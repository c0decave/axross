"""A moved file's tags follow even when the finished job left the
transfer list before the tags were applied.

Found by the review of 0.14.154: the tags are applied in batches up to
250 ms after a job ends (later when the GUI thread is busy) and looked
the job up then - but the bounded history (MAX_DONE_KEPT) may have
dropped it meanwhile, which counted as a failed move: the tags stayed at
the old path. The outcome is read when the job ends now.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtWidgets import QApplication  # noqa: E402

from core.transfer_worker import TransferStatus  # noqa: E402

APP = QApplication.instance() or QApplication([])


def test_happy_tags_follow_a_job_dropped_before_the_flush():
    from core import tags as TG
    from ui.main_window import MainWindow

    jobs = {"j1": SimpleNamespace(status=TransferStatus.DONE, skipped=False)}

    class Window:
        TAG_FLUSH_GAP_MS = MainWindow.TAG_FLUSH_GAP_MS
        _queue_tag_job = MainWindow._queue_tag_job
        _flush_tag_jobs = MainWindow._flush_tag_jobs
        _tags_job_finished = MainWindow._tags_job_finished
        _tags_folder_progress = MainWindow._tags_folder_progress
        _job_done_well = MainWindow._job_done_well

        def __init__(self) -> None:
            self._tag_moves = {"j1": ("src", "dst", "prof", "/a/old.txt", "/b/old.txt")}
            self._tag_folder_moves = []
            self._tag_job_queue = []
            self._tag_last_flush = 0.0
            self._transfer_manager = SimpleNamespace(get_job=jobs.get)

    moved: list = []

    class Store:
        def batch(self):
            import contextlib

            return contextlib.nullcontext()

        def move_path(self, src, old, new, **kw):
            moved.append((old, new))

    window = Window()
    with mock.patch.object(TG, "store", lambda: Store()):
        window._queue_tag_job("j1", None)  # in job_finished: the job is there
        jobs.clear()  # the history trim drops it before the flush
        window._flush_tag_jobs()
    assert moved == [("/a/old.txt", "/b/old.txt")]
