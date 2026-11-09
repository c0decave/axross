"""A cancelled copy says what it left behind; errors name the destination.

UX review round 6:

* M4 - cancelling a copy left a hidden ``.big.iso.part-…`` (216 MB) and the
  status said only "0 kopiert, 2 abgebrochen". The partial is kept on
  purpose - Retry Failed resumes it while the source is unchanged - so the
  status now says so, and Clear Finished removes the partials of the rows
  it clears (TransferManager.partial_kept / clear_finished).
* M5 - a failed copy named the internal temp file ("Fehler:
  /usr/share/.todo.txt.part-c71d0b6a-58df0d1a liegt auf einem
  schreibgeschützten Dateisystem") and the tooltip repeated the raw English
  errno line. Now the destination's name is shown and the raw text stays in
  the log.
* L8 - the Transfers buttons were enabled over an empty list.
* L12 - a local-to-local copy showed the download arrow.
"""

from __future__ import annotations

import errno
import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import Qt  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import i18n  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402
from core.transfer_worker import (  # noqa: E402
    CHUNK_SIZE,
    PARTIAL_MARK,
    TransferDirection,
    TransferJob,
    TransferStatus,
)

APP = QApplication.instance() or QApplication([])


class _SlowRead:
    def __init__(self, inner) -> None:
        self._inner = inner

    def read(self, size=-1):
        time.sleep(0.05)
        return self._inner.read(size)

    def close(self):
        self._inner.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False

    def __getattr__(self, name):
        return getattr(self._inner, name)


class SlowSource(LocalFS):
    """Reads a chunk every 50 ms: a copy can be cancelled half-way."""

    def open_read(self, path, *args, **kwargs):
        return _SlowRead(super().open_read(path, *args, **kwargs))


@pytest.fixture
def manager():
    from core.transfer_manager import TransferManager

    mgr = TransferManager()
    yield mgr
    mgr.shutdown()


def _wait(predicate, timeout: float = 15.0) -> None:
    end = time.monotonic() + timeout
    while not predicate():
        APP.processEvents()
        assert time.monotonic() < end, "timed out"
        time.sleep(0.01)
    for _ in range(5):
        APP.processEvents()


def _partials(folder: Path) -> list[Path]:
    return [p for p in folder.iterdir() if PARTIAL_MARK in p.name]


def _cancelled_half_way(manager, tmp_path):
    src, dst = tmp_path / "src", tmp_path / "dst"
    src.mkdir()
    dst.mkdir()
    (src / "big.iso").write_bytes(os.urandom(CHUNK_SIZE) * 12)
    [job] = manager.transfer_files(SlowSource(), LocalFS(), [str(src / "big.iso")], str(dst))
    _wait(lambda: job.transferred_bytes >= CHUNK_SIZE)
    manager.cancel_job(job.job_id)
    _wait(lambda: job.status not in (TransferStatus.PENDING, TransferStatus.ACTIVE))
    assert job.status is TransferStatus.CANCELLED
    return job, dst


# -- happy ------------------------------------------------------------------------------------


def test_happy_clear_finished_removes_the_partial_a_cancel_kept(manager, tmp_path):
    job, dst = _cancelled_half_way(manager, tmp_path)
    [partial] = _partials(dst)
    assert manager.partial_kept(job) == str(partial)
    assert not (dst / "big.iso").exists()
    manager.clear_finished()
    _wait(lambda: not _partials(dst), timeout=5)
    assert manager.all_jobs() == []


def test_happy_the_status_says_the_partial_is_kept_for_retry(manager, tmp_path, monkeypatch):
    from ui.main_window import MainWindow

    monkeypatch.setattr(i18n, "_ACTIVE", i18n.Translator("de"))
    job, _dst = _cancelled_half_way(manager, tmp_path)
    shown: list[str] = []

    class Bar:
        def showMessage(self, text, _ms=0):  # noqa: N802 - Qt name
            shown.append(text)

    class Window:
        statusBar = staticmethod(lambda: Bar())

    MainWindow._show_transfer_summary(Window(), {"jobs": [job], "move": False, "kept": 0})
    assert shown[0].startswith("0 kopiert, 1 abgebrochen – "), shown
    assert "„Fehlgeschlagene wiederholen“" in shown[0]
    assert "„Fertige entfernen“ löscht sie" in shown[0]


# -- sad --------------------------------------------------------------------------------------


def _failed_on_temp(tmp_path) -> TransferJob:
    dest = "/usr/share/todo.txt"
    temp = "/usr/share/.todo.txt.part-c71d0b6a-58df0d1a"
    error = OSError(errno.EROFS, "Read-only file system", temp)
    return TransferJob(source_path=str(tmp_path / "todo.txt"), dest_path=dest, temp_path=temp,
                       filename="todo.txt", status=TransferStatus.ERROR,
                       error_message=str(error), error=error)


@pytest.mark.parametrize("language", ["en", "de"])
def test_sad_an_error_names_the_destination_not_the_temp_file(tmp_path, monkeypatch, language):
    from models.transfer_model import COL_STATUS, TransferModel

    monkeypatch.setattr(i18n, "_ACTIVE", i18n.Translator(language))
    model = TransferModel()
    model.add_job(_failed_on_temp(tmp_path))
    cell = model.data(model.index(0, COL_STATUS))
    tip = model.data(model.index(0, COL_STATUS), Qt.ItemDataRole.ToolTipRole)
    for text in (cell, tip):
        assert "/usr/share/todo.txt" in text, text
        assert PARTIAL_MARK not in text and ".todo.txt" not in text, text
        assert "[Errno" not in text, text


def test_sad_clearing_never_removes_a_name_that_is_no_partial(tmp_path):
    from core.transfer_manager import TransferManager

    keep = tmp_path / "keep.txt"
    keep.write_text("mine")
    assert TransferManager._remove_partials([(LocalFS(), str(keep))]) is None
    assert keep.exists()


# -- edge -------------------------------------------------------------------------------------


def test_edge_a_running_retry_keeps_its_partial_when_the_old_row_is_cleared(manager, tmp_path):
    partial = tmp_path / ".x.part-aaaa-bbbb"
    partial.write_bytes(b"half")
    old = TransferJob(dest_path=str(tmp_path / "x"), temp_path=str(partial),
                      transferred_bytes=4, status=TransferStatus.CANCELLED)
    old.dest_backend = LocalFS()
    retry = TransferJob(dest_path=str(tmp_path / "x"), temp_path=str(partial),
                        status=TransferStatus.ACTIVE, resume=True)
    retry.dest_backend = old.dest_backend
    manager._jobs[old.job_id] = old
    manager._jobs[retry.job_id] = retry
    assert manager.partial_kept(old) == str(partial)
    manager.clear_finished()
    time.sleep(0.2)
    assert partial.exists()
    assert manager.all_jobs() == [retry]
    del manager._jobs[retry.job_id]


def test_edge_the_dock_buttons_wait_for_something_to_act_on(manager, tmp_path):
    from ui.transfer_dock import TransferDock

    dock = TransferDock(manager)
    try:
        for button in (dock._btn_retry, dock._btn_cancel, dock._btn_clear):
            assert not button.isEnabled(), button.text()
        _job, _dst = _cancelled_half_way(manager, tmp_path)
        dock._update_overall()
        assert dock._btn_retry.isEnabled() and dock._btn_clear.isEnabled()
        assert not dock._btn_cancel.isEnabled()
        dock._clear_finished()
        for button in (dock._btn_retry, dock._btn_cancel, dock._btn_clear):
            assert not button.isEnabled(), button.text()
    finally:
        dock.deleteLater()


def test_edge_a_local_to_local_copy_shows_a_neutral_arrow():
    from models.transfer_model import COL_DIR, TransferModel

    job = TransferJob(direction=TransferDirection.DOWNLOAD, filename="a")
    job.source_backend = LocalFS()
    job.dest_backend = LocalFS()
    model = TransferModel()
    model.add_job(job)
    assert model.data(model.index(0, COL_DIR)) == "→"
