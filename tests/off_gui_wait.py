"""Waiting in tests for work that runs off the GUI thread.

Shared by the tests of the background jobs (ui.scan_job.ScanJob): Show
Checksum, New Folder / New File / Rename (FilePaneWidget._run_op), the
versions browser, snapshots. A test has to drain the job while its
QMessageBox mock is still active - the finish handler reports through a
message box, and its result is what gets asserted.
"""

from __future__ import annotations

import time


def _drain_scan_job(job, timeout: float = 10.0) -> bool:
    """Pump the Qt event loop until *job* (a ui.scan_job.ScanJob) is idle.

    Snapshot save/restore, the CAS rebuild and the metadata index run as
    background ScanJobs. A test has to drain the
    job while its QMessageBox mock is still active: the finish handler
    reports through a message box, and its result is what gets asserted.
    Returns whether the job finished within *timeout*.
    """
    from PyQt6.QtWidgets import QApplication

    deadline = time.monotonic() + timeout
    while job.running and time.monotonic() < deadline:
        QApplication.processEvents()
        time.sleep(0.01)
    QApplication.processEvents()
    return not job.running


def _drain_checksum(pane, timeout: float = 10.0) -> bool:
    """Show Checksum runs on the pane's ScanJob, in up to two jobs (the
    backend's checksum, then the stream hash the user agreed to): pump
    until neither runs."""
    from PyQt6.QtWidgets import QApplication

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        job = pane._checksum_job
        if job is None:
            return True
        _drain_scan_job(job, max(0.0, deadline - time.monotonic()))
        QApplication.processEvents()
        if not job.running:
            return True
    return False


def _drain_op(pane, timeout: float = 10.0) -> bool:
    """New Folder, New File and Rename run their backend calls on the
    pane's op job (0.14.160), Rename in two steps: pump until it is idle."""
    from PyQt6.QtWidgets import QApplication

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        job = pane._op_job
        if job is None:
            return True
        _drain_scan_job(job, max(0.0, deadline - time.monotonic()))
        QApplication.processEvents()
        if not job.running and pane._op_then[0] is None:
            return True
    return False
