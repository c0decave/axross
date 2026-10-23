"""A move never deletes its source after a copy that came out short.

Found by the audit of 2026-10-22: before removing the source, a move only
checked that the source's size had not changed. It never compared what
was written with that size. A source stream that ends early without an
error, towards a destination without a comparable checksum (FTP offers
none), ended "done": the 4 MiB source was deleted, the destination held
2 MiB. Now a move keeps its source and fails when fewer bytes were
written than the source had.
"""

from __future__ import annotations

import io
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core.local_fs import LocalFS  # noqa: E402
from core.transfer_worker import TransferJob, TransferStatus, TransferWorker  # noqa: E402

SIZE = 4 * 1024 * 1024


class _ShortRead(LocalFS):
    """open_read returns only the first half of a file, without an error."""

    def open_read(self, path):
        with open(path, "rb") as fh:
            data = fh.read()
        return io.BytesIO(data[: len(data) // 2])


class _NoHash(LocalFS):
    """A destination with no checksum to compare (like FTP)."""

    def checksum(self, path, algorithm="sha256"):
        return ""


class _ZeroSize(LocalFS):
    """A source backend that reports 0 for every file size."""

    def stat(self, path):
        import dataclasses

        return dataclasses.replace(super().stat(path), size=0)


@pytest.fixture(scope="module", autouse=True)
def _app():
    from PyQt6.QtCore import QCoreApplication

    yield QCoreApplication.instance() or QCoreApplication([])


def _move(tmp_path, source_backend, dest_backend=None, *, size=SIZE):
    src, dst = tmp_path / "src.bin", tmp_path / "dst.bin"
    src.write_bytes(os.urandom(size))
    job = TransferJob(source_path=str(src), dest_path=str(dst), filename="src.bin",
                      total_bytes=size, source_backend=source_backend,
                      dest_backend=dest_backend or _NoHash(), move=True)
    TransferWorker()._process_job(job)
    return job, src, dst


def test_happy_a_complete_move_removes_the_source(tmp_path):
    job, src, dst = _move(tmp_path, LocalFS())
    assert job.status == TransferStatus.DONE, job.error_message
    assert not src.exists() and dst.stat().st_size == SIZE


def test_sad_a_short_copy_keeps_the_source_and_fails(tmp_path):
    job, src, dst = _move(tmp_path, _ShortRead())
    assert job.status == TransferStatus.ERROR
    assert src.exists() and src.stat().st_size == SIZE
    assert str(SIZE // 2) in job.error_message and str(SIZE) in job.error_message
    assert "kept" in job.error_message


def test_edge_a_source_that_reports_size_zero_still_moves(tmp_path):
    # More written than the listing said is not a short copy; such
    # backends must not lose the ability to move.
    job, src, dst = _move(tmp_path, _ZeroSize(), size=1024)
    assert job.status == TransferStatus.DONE, job.error_message
    assert not src.exists() and dst.stat().st_size == 1024


def test_edge_an_empty_file_moves(tmp_path):
    job, src, dst = _move(tmp_path, LocalFS(), size=0)
    assert job.status == TransferStatus.DONE, job.error_message
    assert not src.exists() and dst.exists()
