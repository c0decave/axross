"""A folder that cannot be created or read is described like a file error.

UX review round 5 (major): copying a folder into a read-only place showed
"Fehler: cannot create the folder, its contents were not copied: [Errno 30]
Read-only file system: '/usr/share/Documents'" in the German Transfers panel,
while the file next to it got a German sentence. The refused folder row did
not keep its exception, so core.user_errors.describe() had nothing to say.

Now the row keeps the exception: its Status cell says what happened in the
interface language, the raw text stays in the tooltip (and the log).
"""

from __future__ import annotations

import errno
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import Qt  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core.local_fs import LocalFS  # noqa: E402
from core.transfer_worker import TransferStatus  # noqa: E402

APP = QApplication.instance() or QApplication([])


class _ReadOnlyDest(LocalFS):
    """A destination whose folders cannot be made (a read-only mount)."""

    def mkdir(self, path: str) -> None:
        raise OSError(errno.EROFS, "Read-only file system", path)


class _UnlistableSource(LocalFS):
    def list_dir(self, path: str):
        raise PermissionError(errno.EACCES, "Permission denied", path)


@pytest.fixture
def setup():
    from core.transfer_manager import TransferManager

    tmp = Path(tempfile.mkdtemp())
    (tmp / "Documents").mkdir()
    (tmp / "Documents" / "a.txt").write_text("a")
    (tmp / "dst").mkdir()
    mgr = TransferManager()
    yield tmp, mgr
    mgr.shutdown()
    shutil.rmtree(tmp, ignore_errors=True)


@pytest.fixture
def german(monkeypatch):
    from core import i18n

    monkeypatch.setattr(i18n, "_ACTIVE", i18n.Translator("de"))


def _run(mgr, source, dest, src, dst):
    jobs = mgr.transfer_files(source, dest, [src], dst)
    deadline = time.monotonic() + 10
    while any(j.status in (TransferStatus.PENDING, TransferStatus.ACTIVE) for j in jobs):
        APP.processEvents()
        assert time.monotonic() < deadline
        time.sleep(0.01)
    return [j for j in jobs if j.status == TransferStatus.ERROR]


def _cells(job):
    from models.transfer_model import COL_STATUS, TransferModel

    model = TransferModel()
    model.add_job(job)
    index = model.index(0, COL_STATUS)
    return index.data(Qt.ItemDataRole.DisplayRole), index.data(Qt.ItemDataRole.ToolTipRole)


def test_happy_a_folder_that_cannot_be_created_is_said_in_german(setup, german):
    tmp, mgr = setup
    [row] = _run(mgr, LocalFS(), _ReadOnlyDest(), str(tmp / "Documents"), str(tmp / "dst"))
    assert isinstance(row.error, OSError) and row.error.errno == errno.EROFS
    status, tip = _cells(row)
    assert status.startswith("Fehler: Der Ordner ließ sich nicht anlegen, sein Inhalt wurde "
                             "daher nicht kopiert:"), status
    assert "[Errno" not in status and "cannot create" not in status
    assert "Read-only file system" in tip  # the raw text stays reachable


def test_sad_an_unreadable_folder_is_said_in_german_too(setup, german):
    tmp, mgr = setup
    [row] = _run(mgr, _UnlistableSource(), LocalFS(), str(tmp / "Documents"), str(tmp / "dst"))
    status, _tip = _cells(row)
    assert status.startswith("Fehler: Der Ordner ließ sich nicht lesen"), status
    assert "[Errno" not in status


def test_edge_english_keeps_the_raw_reason_in_the_tooltip(setup):
    tmp, mgr = setup
    [row] = _run(mgr, LocalFS(), _ReadOnlyDest(), str(tmp / "Documents"), str(tmp / "dst"))
    status, tip = _cells(row)
    assert status.startswith("error: The folder could not be created"), status
    assert "cannot create the folder, its contents were not copied" in row.error_message
    assert row.error_message in tip
