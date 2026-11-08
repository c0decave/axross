"""A failed integrity check keeps the original destination.

The checksum was compared only after the temp file had been renamed over
the destination: overwriting ``dst.txt`` with ``verify_checksum`` on and
corrupted bytes reported "Integrity FAIL", but ``dst.txt`` already held the
corrupt bytes and the original was gone. Now the temp file is checked
before the rename and removed on a mismatch; a direct write is checked
while its rollback snapshot is still held, and a mismatch restores it.
"""

from __future__ import annotations

import os

import pytest

from core.local_fs import LocalFS
from core.transfer_worker import TransferJob, TransferStatus, TransferWorker

ORIGINAL = b"ORIGINAL PRECIOUS DEST"
NEW = b"NEW CONTENT"


class _Corrupting(LocalFS):
    """Flips the first byte of each write of the copy (bad RAM, a broken
    link); a later write - the rollback putting the original back - is
    left alone."""

    def __init__(self) -> None:
        super().__init__()
        self.corrupted = False

    def open_write(self, path, append=False):
        f = super().open_write(path, append)
        if self.corrupted:
            return f
        self.corrupted = True
        real = f.write

        def write(b):
            b = bytearray(b)
            b[0] ^= 0xFF
            return real(bytes(b))

        f.write = write
        return f


def _run(tmp_path, dest_backend, *, temp: bool, dest_exists: bool = True) -> TransferJob:
    src = tmp_path / "src.txt"
    src.write_bytes(NEW)
    dst = tmp_path / "dst.txt"
    if dest_exists:
        dst.write_bytes(ORIGINAL)
    job = TransferJob(source_path=str(src), dest_path=str(dst), filename="src.txt",
                      total_bytes=len(NEW), use_temp_file=temp, verify_checksum=True)
    job.source_backend = LocalFS()
    job.dest_backend = dest_backend
    TransferWorker()._process_job(job)
    return job


@pytest.mark.parametrize("temp", [True, False], ids=["temp-file", "direct"])
def test_sad_a_failed_check_keeps_the_original_destination(tmp_path, temp):
    job = _run(tmp_path, _Corrupting(), temp=temp)
    assert job.status == TransferStatus.ERROR
    assert "Integrity FAIL" in job.error_message
    assert (tmp_path / "dst.txt").read_bytes() == ORIGINAL
    assert sorted(os.listdir(tmp_path)) == ["dst.txt", "src.txt"]  # no temp file left


@pytest.mark.parametrize("temp", [True, False], ids=["temp-file", "direct"])
def test_sad_a_failed_check_onto_a_free_name_leaves_no_corrupt_file(tmp_path, temp):
    job = _run(tmp_path, _Corrupting(), temp=temp, dest_exists=False)
    assert job.status == TransferStatus.ERROR
    assert sorted(os.listdir(tmp_path)) == ["src.txt"]


def test_sad_a_failed_check_of_a_move_keeps_both_files(tmp_path):
    src = tmp_path / "src.txt"
    src.write_bytes(NEW)
    dst = tmp_path / "out" / "src.txt"
    dst.parent.mkdir()
    dst.write_bytes(ORIGINAL)
    job = TransferJob(source_path=str(src), dest_path=str(dst), filename="src.txt",
                      total_bytes=len(NEW), move=True, verify_checksum=True)
    job.source_backend = LocalFS()
    job.dest_backend = _Corrupting()
    TransferWorker()._process_job(job)
    assert job.status == TransferStatus.ERROR
    assert src.read_bytes() == NEW and dst.read_bytes() == ORIGINAL


def test_sad_a_resumed_complete_partial_is_checked_before_the_rename(tmp_path, monkeypatch):
    src = tmp_path / "src.txt"
    src.write_bytes(NEW)
    dst = tmp_path / "dst.txt"
    dst.write_bytes(ORIGINAL)
    job = TransferJob(source_path=str(src), dest_path=str(dst), filename="src.txt",
                      total_bytes=len(NEW), verify_checksum=True, resume=True)
    job.source_backend = job.dest_backend = LocalFS()
    temp = TransferWorker._temp_destination_path(job)
    with open(temp, "wb") as f:  # complete in size, wrong in content
        f.write(b"X" + NEW[1:])
    # The window compare would refuse this partial; the check behind it is
    # what this test is about.
    monkeypatch.setattr(TransferWorker, "_partial_matches_source", staticmethod(lambda *a: True))
    TransferWorker()._process_job(job)
    assert job.status == TransferStatus.ERROR
    assert "Integrity FAIL" in job.error_message
    assert dst.read_bytes() == ORIGINAL
    assert not os.path.exists(temp)


@pytest.mark.parametrize("temp", [True, False], ids=["temp-file", "direct"])
def test_happy_a_passing_check_replaces_the_destination(tmp_path, temp):
    job = _run(tmp_path, LocalFS(), temp=temp)
    assert job.status == TransferStatus.DONE, job.error_message
    assert (tmp_path / "dst.txt").read_bytes() == NEW
    assert sorted(os.listdir(tmp_path)) == ["dst.txt", "src.txt"]
