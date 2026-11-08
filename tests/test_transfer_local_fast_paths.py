"""Local transfers do less work.

A move between two folders of one local file system renames the file (as
``mv`` does) instead of copying it, hashing both sides and deleting the
source. A copy from a local file hashes the bytes as it reads them, so the
integrity check reads only the destination again, not the source too.
"""

from __future__ import annotations

import errno
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core import transfer_worker as TW  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402


def _job(src: Path, dst: Path, **kw) -> TW.TransferJob:
    return TW.TransferJob(source_path=str(src), dest_path=str(dst),
                          total_bytes=src.lstat().st_size if src.exists() else 0,
                          filename=src.name, source_backend=LocalFS(), dest_backend=LocalFS(),
                          **kw)


@pytest.fixture
def tree(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    src = tmp_path / "a" / "f.bin"
    src.write_bytes(b"payload" * 1000)
    os.utime(src, (1_000_000, 1_000_000))
    return tmp_path, src


def _no_copy(monkeypatch):
    def refuse(*a, **k):
        raise AssertionError("the move copied the file")

    monkeypatch.setattr(TW.TransferWorker, "_do_transfer", refuse)


def test_happy_a_move_on_one_file_system_renames(tree, monkeypatch):
    tmp, src = tree
    inode = src.stat().st_ino
    dst = tmp / "b" / "f.bin"
    _no_copy(monkeypatch)
    job = _job(src, dst, move=True, if_exists="fail")
    TW.TransferWorker()._process_job(job)
    assert job.status == TW.TransferStatus.DONE, job.error_message
    assert not src.exists()
    assert dst.stat().st_ino == inode  # the same file, not a copy
    assert dst.stat().st_mtime == 1_000_000
    assert job.transferred_bytes == job.total_bytes == 7000


def test_sad_a_rename_move_does_not_replace_a_file_that_appeared(tree, monkeypatch):
    tmp, src = tree
    dst = tmp / "b" / "f.bin"
    dst.write_bytes(b"theirs")
    _no_copy(monkeypatch)
    job = _job(src, dst, move=True, if_exists="fail")
    TW.TransferWorker()._process_job(job)
    assert job.status == TW.TransferStatus.ERROR
    assert dst.read_bytes() == b"theirs" and src.exists()


def test_sad_link_refused_between_check_and_link_keeps_both(tree, monkeypatch):
    """The no-clobber name comes from link(): a file appearing after the
    check still makes it fail instead of being replaced."""
    tmp, src = tree
    dst = tmp / "b" / "f.bin"
    real_link = os.link

    def racing_link(a, b, **kw):
        Path(b).write_bytes(b"raced")
        return real_link(a, b, **kw)

    monkeypatch.setattr(TW.os, "link", racing_link)
    _no_copy(monkeypatch)
    job = _job(src, dst, move=True, if_exists="fail")
    TW.TransferWorker()._process_job(job)
    assert job.status == TW.TransferStatus.ERROR
    assert dst.read_bytes() == b"raced" and src.exists()


def test_happy_overwrite_replaces_by_rename(tree, monkeypatch):
    tmp, src = tree
    dst = tmp / "b" / "f.bin"
    dst.write_bytes(b"old")
    _no_copy(monkeypatch)
    job = _job(src, dst, move=True, if_exists="overwrite")
    TW.TransferWorker()._process_job(job)
    assert job.status == TW.TransferStatus.DONE, job.error_message
    assert dst.read_bytes() == b"payload" * 1000 and not src.exists()


def test_sad_source_that_cannot_be_unlinked_leaves_everything_as_it_was(tree, monkeypatch):
    """Feedback item 6 (Errno 13 removing the source): no second copy is
    left behind, the job fails with the reason."""
    tmp, src = tree
    dst = tmp / "b" / "f.bin"
    real_unlink = os.unlink

    def unlink(path, *a, **k):
        if str(path) == str(src):
            raise PermissionError(errno.EACCES, "Permission denied", str(path))
        return real_unlink(path, *a, **k)

    monkeypatch.setattr(TW.os, "unlink", unlink)
    _no_copy(monkeypatch)
    job = _job(src, dst, move=True, if_exists="fail")
    TW.TransferWorker()._process_job(job)
    assert job.status == TW.TransferStatus.ERROR
    assert "Permission denied" in job.error_message
    assert src.exists() and not dst.exists()


@pytest.mark.parametrize("err", [errno.EXDEV, errno.EPERM, errno.EOPNOTSUPP])
def test_edge_no_rename_there_falls_back_to_the_copy(tree, monkeypatch, err):
    tmp, src = tree
    dst = tmp / "b" / "f.bin"

    def link(*a, **k):
        raise OSError(err, os.strerror(err))

    monkeypatch.setattr(TW.os, "link", link)
    job = _job(src, dst, move=True, if_exists="fail")
    TW.TransferWorker()._process_job(job)
    assert job.status == TW.TransferStatus.DONE, job.error_message
    assert dst.read_bytes() == b"payload" * 1000 and not src.exists()


def test_edge_a_copy_is_never_a_rename(tree):
    tmp, src = tree
    dst = tmp / "b" / "f.bin"
    job = _job(src, dst)
    TW.TransferWorker()._process_job(job)
    assert job.status == TW.TransferStatus.DONE
    assert src.exists() and dst.stat().st_ino != src.stat().st_ino


# -- the copy hashes its source while reading it ----------------------------------------------


def _count_source_hashes(monkeypatch, src: Path) -> list[str]:
    hashed: list[str] = []
    real = LocalFS.checksum

    def checksum(self, path, algorithm="sha256"):
        hashed.append(path)
        return real(self, path, algorithm)

    monkeypatch.setattr(LocalFS, "checksum", checksum)
    monkeypatch.setattr(TW, "_hashes_whole_local_file", lambda b: isinstance(b, LocalFS))
    return hashed


@pytest.mark.parametrize("temp", [True, False], ids=["temp-file", "direct"])
def test_happy_a_local_copy_reads_its_source_once(tree, monkeypatch, temp):
    tmp, src = tree
    dst = tmp / "b" / "f.bin"
    hashed = _count_source_hashes(monkeypatch, src)
    job = _job(src, dst, use_temp_file=temp)
    TW.TransferWorker()._process_job(job)
    assert job.status == TW.TransferStatus.DONE, job.error_message
    # The destination only: on the temp-file route its temp file, checked
    # before it replaces the destination.
    assert hashed == [job.temp_path if temp else str(dst)]
    assert job.streamed_source_checksum.startswith("sha256:")


def test_sad_a_source_changed_after_the_read_is_hashed_again(tree, monkeypatch):
    """Same size, new bytes: only the mtime tells. The check then reads the
    source again and reports the mismatch, as before."""
    tmp, src = tree
    dst = tmp / "b" / "f.bin"
    hashed = _count_source_hashes(monkeypatch, src)
    real_refuse = TW.TransferWorker._refuse_aliased_source

    def refuse(job, temp_path):  # runs after the read, right before the check
        real_refuse(job, temp_path)
        src.write_bytes(b"PAYLOAD" * 1000)
        os.utime(src, (2_000_000, 2_000_000))

    monkeypatch.setattr(TW.TransferWorker, "_refuse_aliased_source", staticmethod(refuse))
    job = _job(src, dst)
    TW.TransferWorker()._process_job(job)
    assert str(src) in hashed
    assert job.status == TW.TransferStatus.ERROR
    assert "Integrity" in job.error_message


def test_edge_only_regular_files_are_renamed(tree, monkeypatch):
    """A FIFO, a device or a link goes the copy's way, which refuses the
    first two and follows a link to its content - a rename would move
    them as they are."""
    tmp, src = tree
    link = tmp / "a" / "link"
    link.symlink_to(src)
    calls = []
    monkeypatch.setattr(TW.os, "rename", lambda *a: calls.append(a))
    monkeypatch.setattr(TW.os, "link", lambda *a, **k: calls.append(a))
    job = _job(link, tmp / "b" / "link", move=True, if_exists="fail")
    assert TW.TransferWorker._move_by_rename(job) is None
    assert calls == []


def test_happy_an_unreadable_file_is_moved_by_rename(tree):
    """mv needs no read permission on one file system; neither does this."""
    tmp, src = tree
    os.chmod(src, 0)
    try:
        job = _job(src, tmp / "b" / "f.bin", move=True, if_exists="fail")
        TW.TransferWorker()._process_job(job)
        assert job.status == TW.TransferStatus.DONE, job.error_message
        assert (tmp / "b" / "f.bin").exists() and not src.exists()
    finally:
        for p in (src, tmp / "b" / "f.bin"):
            if p.exists():
                os.chmod(p, 0o600)
