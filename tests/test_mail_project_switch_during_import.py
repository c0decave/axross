"""Opening another mail project (or closing the window) during an import.

Before: ``MailProjectDialog.open_project`` closed the old project's SQLite
connection while an import still wrote to it, and ``done()`` did the
same. Every message left failed with "Cannot operate on a closed
database", the import wrote no row to its log, and the message file
written just before the close stayed in messages/ without an index row.

Now the running imports are cancelled and the old project is closed only
once the last import writing to it ended (on the import's own thread, so
also after the window was closed and deleted).
"""

from __future__ import annotations

import os
import sqlite3
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import mail_project as CMP  # noqa: E402
from ui.mail_project import MailProjectDialog  # noqa: E402

APP = QApplication.instance() or QApplication([])


def _wait(cond, timeout: float = 60.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        APP.processEvents()
        if cond():
            return True
        time.sleep(0.01)
    return cond()


@pytest.fixture
def slow_source(tmp_path, monkeypatch):
    """200 messages, each analysed a little slowly: the import is still
    running when the test acts."""
    src = tmp_path / "src"
    src.mkdir()
    for i in range(200):
        (src / f"m{i}.eml").write_text(
            f"From: a{i}@example.org\nTo: b@example.org\nSubject: s{i}\nMessage-ID: <{i}@x>\n\nbody {i}\n")
    real = CMP.analyse

    def slow(msg):
        time.sleep(0.01)
        return real(msg)

    monkeypatch.setattr(CMP, "analyse", slow)
    return src


def _counts(folder: Path) -> tuple[int, int, int]:
    files = len(list((folder / "messages").iterdir()))
    db = sqlite3.connect(str(folder / "index.sqlite"))
    try:
        rows = db.execute("select count(*) from messages").fetchone()[0]
        logged = db.execute("select count(*) from imports").fetchone()[0]
    finally:
        db.close()
    return files, rows, logged


def _closed(project) -> bool:
    try:
        project._db.execute("select 1")
    except sqlite3.ProgrammingError:
        return True
    return False


def _start(dlg, src):
    project = dlg.project
    dlg._run_import("src", lambda cancel: project.import_paths([str(src)], cancel=cancel))
    assert _wait(lambda: _counts(project.folder)[1] > 0, timeout=30), "the import did not start"
    return project


def _import_threads() -> list[threading.Thread]:
    return [t for t in threading.enumerate() if t.name == "mail-import"]


def test_happy_opening_another_project_cancels_the_import_and_closes_the_old_one_after_it(
        tmp_path, slow_source):
    dlg = MailProjectDialog(folder=str(tmp_path / "A"))
    old = _start(dlg, slow_source)
    dlg.open_project(str(tmp_path / "B"))
    assert dlg.project is not old
    assert _wait(lambda: not dlg._imports), "the import did not end"
    status = dlg.status.text()
    assert "closed database" not in status, status
    assert "cancelled" in status, status
    files, rows, logged = _counts(tmp_path / "A")
    assert logged == 1, "the import wrote no row to its log"
    assert files == rows, f"{files} message files, {rows} indexed: an orphaned file"
    assert rows < 200                                    # it was cancelled, not run to the end
    assert _wait(lambda: _closed(old), timeout=5)        # closed once the import ended
    assert not _closed(dlg.project)
    assert dlg.project.messages() == []                  # the new one is open and usable
    dlg.done(0)


def test_sad_closing_the_window_during_an_import_logs_it_and_closes_the_project(
        tmp_path, slow_source):
    dlg = MailProjectDialog(folder=str(tmp_path / "A"))
    old = _start(dlg, slow_source)
    dlg.done(0)
    dlg.deleteLater()                                    # as WA_DeleteOnClose does
    from PyQt6.QtCore import QEvent

    APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    assert _wait(lambda: not _import_threads(), timeout=60), "the import did not end"
    files, rows, logged = _counts(tmp_path / "A")
    assert logged == 1, "the import wrote no row to its log"
    assert files == rows
    assert _closed(old), "the project stayed open after the window and its import were gone"


def test_edge_two_imports_then_another_project_then_the_window_closed(tmp_path, slow_source):
    dlg = MailProjectDialog(folder=str(tmp_path / "A"))
    old = _start(dlg, slow_source)
    second = slow_source.parent / "src2"
    second.mkdir()
    (second / "x.eml").write_text("From: x@example.org\nSubject: x\nMessage-ID: <x@x>\n\nx\n")
    dlg._run_import("src2", lambda cancel: (time.sleep(0.3), old.import_paths([str(second)],
                                                                              cancel=cancel))[1])
    dlg.open_project(str(tmp_path / "B"))
    new = dlg.project
    dlg.done(0)                                          # B: no import, closed at once
    assert _closed(new) and dlg.project is None
    assert _wait(lambda: not _import_threads(), timeout=60), "the imports did not end"
    files, rows, logged = _counts(tmp_path / "A")
    assert logged == 2, f"{logged} of the 2 imports logged"
    assert files == rows
    assert _closed(old)
