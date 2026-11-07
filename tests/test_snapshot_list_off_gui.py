"""The versions browser opens at once and lists the versions off the GUI
thread.

Audit (feedback: no blocked windows): the dialog asked the server for
the versions (list_versions) in its constructor on the GUI thread, under
a wait cursor - the window froze, and the dialog did not appear, until
the server answered. It opens now with "listing versions…" and its
buttons off; the table fills when the answer is in; an error is shown in
the dialog instead of escaping from its constructor.
"""

from __future__ import annotations

import os
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtWidgets import QApplication  # noqa: E402

from models.file_version import FileVersion  # noqa: E402
from tests.off_gui_wait import _drain_scan_job  # noqa: E402

APP = QApplication.instance() or QApplication([])


class VersionedBackend:
    name = "s3"
    supports_versioning = True

    def __init__(self, delay=0.4, fail=None, gate: threading.Event | None = None):
        self.delay, self.fail, self.gate = delay, fail, gate
        self.threads: list[str] = []
        self.answered = False

    def list_versions(self, path):
        self.threads.append(threading.current_thread().name)
        if self.gate is not None:
            self.gate.wait(10)
        time.sleep(self.delay)
        self.answered = True
        if self.fail:
            raise self.fail
        when = datetime(2026, 10, 1, tzinfo=timezone.utc)
        return [FileVersion(version_id="v2", modified=when, size=10, is_current=True),
                FileVersion(version_id="v1", modified=when, size=8)]


def test_happy_the_dialog_opens_at_once_and_fills_later():
    from ui.snapshot_browser_dialog import SnapshotBrowserDialog

    # The server answers only when the test lets it: the dialog is there
    # before that. (A wall-clock bound on the constructor, 0.2 s against a
    # 0.4 s answer, failed on a busy host with the listing off the thread.)
    gate = threading.Event()
    backend = VersionedBackend(delay=0, gate=gate)
    dlg = SnapshotBrowserDialog(backend, "/docs/report.txt")
    try:
        assert not backend.answered
        assert "listing versions" in dlg._info.text()
        assert not dlg._save_btn.isEnabled() and not dlg._restore_btn.isEnabled()
        gate.set()
        assert _drain_scan_job(dlg._list_job)
        assert dlg._table.rowCount() == 2
        assert dlg._info.text().endswith("2 versions")
        assert dlg._save_btn.isEnabled()
        assert backend.threads and "MainThread" not in backend.threads
    finally:
        gate.set()
        dlg.reject()
        dlg.deleteLater()


def test_sad_a_server_error_leaves_an_empty_list_as_before():
    """core.snapshot_browser.browse logs a failing list_versions and
    answers [] - the dialog says 0 versions, nothing escapes."""
    from ui.snapshot_browser_dialog import SnapshotBrowserDialog

    dlg = SnapshotBrowserDialog(VersionedBackend(delay=0.05, fail=OSError("bucket gone")),
                                "/docs/report.txt")
    try:
        assert _drain_scan_job(dlg._list_job)
        assert dlg._info.text().endswith("0 versions")
        assert dlg._table.rowCount() == 0 and not dlg._save_btn.isEnabled()
    finally:
        dlg.reject()
        dlg.deleteLater()


def test_edge_closing_while_it_lists_drops_the_answer():
    from ui.snapshot_browser_dialog import SnapshotBrowserDialog

    dlg = SnapshotBrowserDialog(VersionedBackend(delay=0.3), "/docs/report.txt")
    dlg.reject()
    time.sleep(0.5)
    APP.processEvents()
    assert dlg._table.rowCount() == 0
    dlg.deleteLater()
