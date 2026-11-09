"""Overwriting a file on a backend without temp file + rename.

Measured before (review round 6, repro snap/snapshot_overwrite.py): an
FTP upload over an existing 400 MiB file first downloaded the whole old
file (no progress, Cancel not checked, spooled in /tmp); a Cancel 0.3 s in
then waited 1.2 s for that read-back and another 2.3 s while the rollback
uploaded the old file again - though the spooling writer had not sent a
byte. Now:

* a writer that spools until close() (FTP, WebDAV, SCP, Telnet, ADB, a DB
  row) gets its safety copy right before that close(): a copy cancelled
  or failed before it reads back nothing and restores nothing;
* where the backend copies on the server (cp, WebDAV COPY, a DB row) the
  safety copy is made there - no byte through this machine;
* the read-back checks Cancel per chunk, spools in the spool folder, and
  checks the free space first.

The guarantee stays: a write that fails after it touched the destination
puts the old file back.
"""

from __future__ import annotations

import errno
import io
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import test_backend_conformance as C  # noqa: E402

from core import server_ops  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402
from core.transfer_worker import TransferJob, TransferStatus, TransferWorker  # noqa: E402

OLD = b"old content " * 1000
NEW = b"N" * (3 * 1024 * 1024)


@pytest.fixture
def ftp(tmp_path):
    t = C.MAKERS["ftp"](tmp_path)
    (t.local_dir / "big.iso").write_bytes(OLD)
    yield t
    for done in t.cleanup:
        try:
            done()
        except Exception:  # noqa: BLE001 - cleanup only
            pass


@pytest.fixture
def read_backs(monkeypatch):
    seen = []
    real = server_ops.read_destination_snapshot

    def spy(backend, dst, **kw):
        seen.append(dst)
        return real(backend, dst, **kw)

    monkeypatch.setattr(server_ops, "read_destination_snapshot", spy)
    return seen



def _job(src_backend, src, dest_backend, dst, size=len(NEW)):
    return TransferJob(source_path=src, dest_path=dst, filename=os.path.basename(dst),
                       total_bytes=size, source_backend=src_backend,
                       dest_backend=dest_backend, use_temp_file=False)


class _CancelAfterFirstChunk(io.BytesIO):
    def __init__(self, data, job_box):
        super().__init__(data)
        self._box = job_box

    def read(self, n=-1):
        chunk = super().read(n)
        if self.tell() > 0:
            self._box[0].cancel_event.set()
        return chunk


class _Source(LocalFS):
    """A local file whose read cancels the job (or fails) after one chunk."""

    def __init__(self, box, mode):
        super().__init__()
        self._box, self._mode = box, mode

    def open_read(self, path, mode="rb"):
        data = Path(path).read_bytes()
        if self._mode == "cancel":
            return _CancelAfterFirstChunk(data, self._box)

        class _Failing(io.BytesIO):
            def read(inner, n=-1):
                if inner.tell() > 0:
                    raise OSError(errno.EIO, "source read failed")
                return super().read(n)

        return _Failing(data)


@pytest.mark.parametrize("mode", ["cancel", "read-error"])
def test_sad_a_copy_stopped_before_close_reads_back_and_restores_nothing(
        ftp, tmp_path, read_backs, monkeypatch, mode):
    src = tmp_path / "new.iso"
    src.write_bytes(NEW)
    restored = []
    monkeypatch.setattr(server_ops, "_restore_direct_destination",
                        lambda *a, **k: restored.append(a))
    box = [None]
    job = _job(_Source(box, mode), str(src), ftp.backend, "/big.iso")
    box[0] = job
    TransferWorker()._process_job(job)
    expected = TransferStatus.CANCELLED if mode == "cancel" else TransferStatus.ERROR
    assert job.status is expected, job.error_message
    assert read_backs == []   # no read-back of the old file
    assert restored == []     # and no upload of it again
    assert (ftp.local_dir / "big.iso").read_bytes() == OLD


def test_happy_a_successful_overwrite_still_writes_the_new_file(ftp, tmp_path, read_backs):
    src = tmp_path / "new.iso"
    src.write_bytes(NEW)
    job = _job(LocalFS(), str(src), ftp.backend, "/big.iso")
    TransferWorker()._process_job(job)
    assert job.status is TransferStatus.DONE, job.error_message
    assert (ftp.local_dir / "big.iso").read_bytes() == NEW
    assert read_backs == ["/big.iso"]  # taken right before the upload


def test_sad_an_upload_that_fails_after_it_started_puts_the_old_file_back(
        ftp, tmp_path, monkeypatch):
    from core import ftp_client

    src = tmp_path / "new.iso"
    src.write_bytes(NEW)
    real_store = ftp_client.FtpSession._store
    calls = []

    def store(self, command, fileobj):
        calls.append(command)
        if len(calls) == 1:  # the upload: half the file arrives, then it breaks
            (ftp.local_dir / "big.iso").write_bytes(NEW[: len(NEW) // 2])
            raise OSError(errno.ECONNRESET, "connection reset during STOR")
        return real_store(self, command, fileobj)

    monkeypatch.setattr(ftp_client.FtpSession, "_store", store)
    job = _job(LocalFS(), str(src), ftp.backend, "/big.iso")
    TransferWorker()._process_job(job)
    assert job.status is TransferStatus.ERROR
    assert len(calls) == 2  # the upload, then the restore
    assert (ftp.local_dir / "big.iso").read_bytes() == OLD


def test_sad_no_room_for_the_safety_copy_fails_before_anything_is_sent(
        ftp, tmp_path, monkeypatch):
    from core import posix_compat, read_spool

    monkeypatch.setattr(read_spool, "READ_SPOOL_MAX", 1024)
    monkeypatch.setattr(posix_compat, "disk_usage", lambda path: (10, 10, 0))
    src = tmp_path / "new.iso"
    src.write_bytes(NEW)
    job = _job(LocalFS(), str(src), ftp.backend, "/big.iso")
    TransferWorker()._process_job(job)
    assert job.status is TransferStatus.ERROR
    assert "free space" in job.error_message
    assert (ftp.local_dir / "big.iso").read_bytes() == OLD


def test_edge_the_read_back_checks_cancel_per_chunk(tmp_path):
    big = tmp_path / "big.bin"
    big.write_bytes(b"x" * (3 * 1024 * 1024))
    chunks = []

    def check():
        chunks.append(1)
        if len(chunks) > 1:
            raise InterruptedError("Transfer cancelled")

    with pytest.raises(InterruptedError):
        server_ops.read_destination_snapshot(LocalFS(), str(big), check=check)
    assert len(chunks) == 2  # stopped after the first MiB, not after all of it


# ------------------------------------------------- a server-side safety copy
@pytest.fixture
def sqlite(tmp_path):
    t = C.MAKERS["sqlite"](tmp_path)
    with t.backend.open_write("/f.bin") as fh:
        fh.write(OLD)
    yield t
    for done in t.cleanup:
        try:
            done()
        except Exception:  # noqa: BLE001 - cleanup only
            pass


def test_happy_a_backend_that_copies_on_the_server_reads_nothing_back(
        sqlite, tmp_path, read_backs):
    src = tmp_path / "new.bin"
    src.write_bytes(NEW)
    job = _job(LocalFS(), str(src), sqlite.backend, "/f.bin")
    TransferWorker()._process_job(job)
    assert job.status is TransferStatus.DONE, job.error_message
    assert read_backs == []
    with sqlite.backend.open_read("/f.bin") as fh:
        assert fh.read() == NEW
    assert [i.name for i in sqlite.backend.list_dir("/")] == ["f.bin"]  # copy dropped


def test_sad_a_failed_commit_is_undone_from_the_server_side_copy(
        sqlite, tmp_path, read_backs, monkeypatch):
    from core import db_fs_base

    real_commit = db_fs_base._DbWriter._commit
    calls = []

    def commit(self):
        calls.append(self._path)
        if len(calls) == 1:
            real_commit(self)  # the new bytes are in - then it fails
            raise OSError(errno.EIO, "commit failed")
        return real_commit(self)

    monkeypatch.setattr(db_fs_base._DbWriter, "_commit", commit)
    src = tmp_path / "new.bin"
    src.write_bytes(NEW)
    job = _job(LocalFS(), str(src), sqlite.backend, "/f.bin")
    TransferWorker()._process_job(job)
    assert job.status is TransferStatus.ERROR
    assert read_backs == []
    with sqlite.backend.open_read("/f.bin") as fh:
        assert fh.read() == OLD
    assert [i.name for i in sqlite.backend.list_dir("/")] == ["f.bin"]
