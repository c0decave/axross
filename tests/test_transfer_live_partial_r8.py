"""Partials another transfer may still write, decoys, and short moves.

Measured before (review round 8):

* A second copy of a file queued while the first ran (a second F5, a
  second axross) adopted the first job's live partial by its name and
  appended to it: with an SFTP destination job A reported DONE with a
  4.8-4.98 MB file for a 4.0 MB source, and a move then deleted the source.
* A user's file named like a partial (``.video.mp4.part-1-notes``) was
  adopted as one: the worker removed it, and so did Clear Finished.
* A local source that came out short during a move: the job failed and
  kept the source, but left the short copy under the destination's name.

Now the probe adopts only an idle partial of axross's exact shape that no
job of this process writes, the worker claims it by a no-replace rename
before it appends, compares the temp file's size with what it wrote
before the rename, a move compares the destination's size with the
source's before it deletes the source, and a short move is not committed.
"""

from __future__ import annotations

import errno
import io
import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core import transfer_worker as TW  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402
from core.transfer_worker import TransferJob, TransferStatus, TransferWorker  # noqa: E402

KIB = 1024
_APP = None


@pytest.fixture(autouse=True)
def _journal(tmp_path, monkeypatch):
    monkeypatch.setenv("AXROSS_OPERATION_JOURNAL", str(tmp_path / "ops.jsonl"))


def _app():
    global _APP
    from PyQt6.QtWidgets import QApplication

    _APP = QApplication.instance() or QApplication([])
    return _APP


class _NoChecksumFS(LocalFS):
    """A destination without a comparable checksum (as SFTP without
    sha256sum, SMB): the integrity check cannot see wrong bytes."""

    def checksum(self, path, algorithm="sha256"):
        return ""


class _SlowFS(_NoChecksumFS):
    def open_read(self, path):
        handle = super().open_read(path)
        real = handle.read

        def read(n=-1):
            time.sleep(0.01)
            return real(64 * KIB)

        handle.read = read
        return handle


def _job(src: Path, dest: Path, source_backend, dest_backend, **kw) -> TransferJob:
    st = src.stat()
    job = TransferJob(source_path=str(src), dest_path=str(dest), filename=src.name,
                      total_bytes=st.st_size, source_mtime=st.st_mtime, **kw)
    job.source_backend = source_backend
    job.dest_backend = dest_backend
    return job


def _wait(mgrs, timeout=30.0) -> None:
    app = _app()
    deadline = time.monotonic() + timeout
    while any(j.status in (TransferStatus.PENDING, TransferStatus.ACTIVE)
              for m in mgrs for j in m.all_jobs()):
        app.processEvents()
        assert time.monotonic() < deadline, "transfers did not finish"
        time.sleep(0.01)


def _age(path: Path, seconds: float = 3600) -> None:
    stamp = time.time() - seconds
    os.utime(path, (stamp, stamp))


def _partials(folder: Path) -> list[str]:
    return sorted(p.name for p in folder.iterdir() if TW.PARTIAL_MARK in p.name)


# -- happy ---------------------------------------------------------------------------------


@pytest.mark.parametrize("two_managers", [False, True])
def test_happy_a_second_copy_does_not_adopt_the_first_ones_live_partial(tmp_path, two_managers):
    from core.transfer_manager import TransferManager

    _app()
    (tmp_path / "src").mkdir()
    (tmp_path / "dst").mkdir()
    data = os.urandom(1536 * KIB)
    src = tmp_path / "src" / "big.bin"
    src.write_bytes(data)
    m1 = TransferManager(max_parallel=2)
    m2 = TransferManager(max_parallel=2) if two_managers else m1
    try:
        a = m1.transfer_files(_SlowFS(), _NoChecksumFS(), [str(src)], str(tmp_path / "dst"))
        deadline = time.monotonic() + 10
        while not [p for p in (tmp_path / "dst").iterdir()
                   if TW.PARTIAL_MARK in p.name and p.stat().st_size > 0]:
            _app().processEvents()
            assert time.monotonic() < deadline, "job A wrote nothing"
            time.sleep(0.01)
        b = m2.transfer_files(_SlowFS(), _NoChecksumFS(), [str(src)], str(tmp_path / "dst"))
        assert not b[0].resume and not b[0].temp_path
        _wait({m1, m2})
        assert [j.status for j in a + b] == [TransferStatus.DONE] * 2, \
            [j.error_message for j in a + b]
        assert (tmp_path / "dst" / "big.bin").read_bytes() == data
        assert _partials(tmp_path / "dst") == []
    finally:
        m1.shutdown()
        if m2 is not m1:
            m2.shutdown()


def test_happy_a_resumed_partial_is_claimed_by_a_rename_first(tmp_path, monkeypatch):
    """Renamed to this job's own name before a byte is appended: another
    process still writing the old name then fails at its own rename."""
    from core import server_ops

    data = os.urandom(600 * KIB)
    src = tmp_path / "f.bin"
    src.write_bytes(data)
    (tmp_path / "out").mkdir()
    fp = TW.source_fingerprint(LocalFS().stat(str(src)))
    left = tmp_path / "out" / TW.partial_name("f.bin", "0123abcd", fp)
    left.write_bytes(data[: 200 * KIB])
    renames: list[tuple[str, str, int]] = []
    real = server_ops.rename_no_replace

    def recording(backend, old, new):
        renames.append((Path(old).name, Path(new).name, Path(old).stat().st_size))
        return real(backend, old, new)

    monkeypatch.setattr(server_ops, "rename_no_replace", recording)
    job = _job(src, tmp_path / "out" / "f.bin", LocalFS(), _NoChecksumFS(),
               resume=True, temp_path=str(left), source_fingerprint=fp)
    TransferWorker()._process_job(job)
    assert job.status is TransferStatus.DONE, job.error_message
    assert (tmp_path / "out" / "f.bin").read_bytes() == data
    # Claimed while it still held only the old bytes, under this job's id.
    assert renames[0] == (left.name, TW.partial_name("f.bin", job.job_id, fp), 200 * KIB)
    assert sorted(p.name for p in (tmp_path / "out").iterdir()) == ["f.bin"]


# -- sad -----------------------------------------------------------------------------------


def test_sad_a_partial_another_writer_appends_to_is_not_committed(tmp_path):
    """Another process appends to the partial while this job writes it:
    the size this job wrote no longer matches, nothing is committed."""
    data = os.urandom(3 * 1024 * KIB)
    src = tmp_path / "f.bin"
    src.write_bytes(data)
    (tmp_path / "out").mkdir()
    out = tmp_path / "out"

    class _Intruded(LocalFS):
        def open_read(self, path):
            handle = super().open_read(path)
            real = handle.read

            def read(n=-1):
                chunk = real(n)
                if not chunk:  # the other writer appended meanwhile
                    for p in out.iterdir():
                        if TW.PARTIAL_MARK in p.name:
                            with open(p, "ab") as fh:
                                fh.write(b"\0" * (300 * KIB))
                return chunk

            handle.read = read
            return handle

    (out / "f.bin").write_bytes(b"OLD")
    job = _job(src, out / "f.bin", _Intruded(), _NoChecksumFS(), use_temp_file=True)
    TransferWorker()._process_job(job)
    assert job.status is TransferStatus.ERROR
    assert "another transfer wrote to it" in job.error_message
    assert (out / "f.bin").read_bytes() == b"OLD"
    assert _partials(out) == []  # wrong bytes: not kept for a resume


def test_sad_a_move_keeps_its_source_when_the_destination_is_not_as_long(tmp_path):
    """The committed destination has another size than the source: the
    source is not deleted."""
    data = os.urandom(300 * KIB)
    src = tmp_path / "f.bin"
    src.write_bytes(data)
    (tmp_path / "out").mkdir()

    class _GrowsAfterRename(_NoChecksumFS):
        def rename(self, old, new):
            super().rename(old, new)
            with open(new, "ab") as fh:  # another writer, right after the commit
                fh.write(b"tail")

    job = _job(src, tmp_path / "out" / "f.bin", _NoChecksumFS(), _GrowsAfterRename(),
               use_temp_file=True, move=True)
    TransferWorker()._process_job(job)
    assert job.status is TransferStatus.ERROR
    assert "the source was kept" in job.error_message
    assert src.read_bytes() == data


def test_sad_a_partial_a_job_of_this_process_writes_is_left_alone(tmp_path):
    data = os.urandom(300 * KIB)
    src = tmp_path / "f.bin"
    src.write_bytes(data)
    (tmp_path / "out").mkdir()
    fp = TW.source_fingerprint(LocalFS().stat(str(src)))
    live = tmp_path / "out" / TW.partial_name("f.bin", "0123abcd", fp)
    live.write_bytes(data[: 100 * KIB])
    assert TW._claim_live_partial(str(live))
    try:
        job = _job(src, tmp_path / "out" / "f.bin", LocalFS(), _NoChecksumFS(),
                   resume=True, temp_path=str(live), source_fingerprint=fp)
        TransferWorker()._process_job(job)
    finally:
        TW._release_live_partials([str(live)])
    assert job.status is TransferStatus.DONE, job.error_message
    assert (tmp_path / "out" / "f.bin").read_bytes() == data
    assert live.read_bytes() == data[: 100 * KIB]  # neither appended to nor removed


@pytest.mark.parametrize("fails", [False, True])
def test_sad_a_users_file_named_like_a_partial_survives(tmp_path, fails):
    """Copied next to it, and the failed job cleared with Clear Finished."""
    from core.transfer_manager import TransferManager

    _app()
    (tmp_path / "src").mkdir()
    (tmp_path / "dst").mkdir()
    (tmp_path / "src" / "video.mp4").write_bytes(os.urandom(200 * KIB))
    users = tmp_path / "dst" / ".video.mp4.part-1-notes"
    users.write_bytes(b"my notes about part 1 of the video")
    _age(users)

    class _Failing(LocalFS):
        def open_read(self, path):
            raise OSError(errno.EIO, "I/O error reading the source")

    mgr = TransferManager(max_parallel=1)
    try:
        jobs = mgr.transfer_files(_Failing() if fails else LocalFS(), LocalFS(),
                                  [str(tmp_path / "src" / "video.mp4")], str(tmp_path / "dst"))
        assert not jobs[0].resume
        _wait({mgr})
        assert jobs[0].status is (TransferStatus.ERROR if fails else TransferStatus.DONE)
        thread = mgr._remove_partials([(LocalFS(), str(users))])
        assert thread is None  # not a name the worker gives a partial
        mgr.clear_finished()
        time.sleep(0.3)
    finally:
        mgr.shutdown()
    assert users.read_bytes() == b"my notes about part 1 of the video"


def test_sad_a_short_local_source_on_a_move_is_not_committed(tmp_path):
    """The source's read ends early (it was truncated meanwhile): the move
    fails, keeps its source and leaves no short file under the name."""
    data = os.urandom(300 * KIB)
    src = tmp_path / "f.bin"
    src.write_bytes(data)
    (tmp_path / "out").mkdir()

    class _Short(LocalFS):
        def open_read(self, path):
            handle = super().open_read(path)
            return io.BytesIO(handle.read(100 * KIB))

    for use_temp in (True, False):
        job = _job(src, tmp_path / "out" / "f.bin", _Short(), LocalFS(),
                   use_temp_file=use_temp, move=True)
        TransferWorker()._process_job(job)
        assert job.status is TransferStatus.ERROR, use_temp
        assert str(100 * KIB) in job.error_message, job.error_message
        assert "source was kept" in job.error_message
        assert src.read_bytes() == data
        assert not (tmp_path / "out" / "f.bin").exists(), use_temp


# -- edge ----------------------------------------------------------------------------------


def test_edge_a_claim_that_fails_starts_afresh_and_leaves_the_partial(tmp_path, monkeypatch):
    from core import server_ops

    data = os.urandom(300 * KIB)
    src = tmp_path / "f.bin"
    src.write_bytes(data)
    (tmp_path / "out").mkdir()
    fp = TW.source_fingerprint(LocalFS().stat(str(src)))
    left = tmp_path / "out" / TW.partial_name("f.bin", "0123abcd", fp)
    left.write_bytes(data[: 100 * KIB])

    def taken(backend, old, new):
        raise FileNotFoundError(errno.ENOENT, "claimed by another process", old)

    monkeypatch.setattr(server_ops, "rename_no_replace", taken)
    job = _job(src, tmp_path / "out" / "f.bin", LocalFS(), _NoChecksumFS(),
               resume=True, temp_path=str(left), source_fingerprint=fp)
    TransferWorker()._process_job(job)
    assert job.status is TransferStatus.DONE, job.error_message
    assert (tmp_path / "out" / "f.bin").read_bytes() == data
    assert left.read_bytes() == data[: 100 * KIB]


def test_edge_a_checked_temp_file_needs_no_extra_stat(tmp_path):
    """The integrity check compared the bytes: no second look at the
    temp file's size (one round trip per file on a remote destination)."""
    src = tmp_path / "f.bin"
    src.write_bytes(b"x" * 4096)
    (tmp_path / "out").mkdir()
    stats: list[str] = []

    class _Counting(LocalFS):
        def stat(self, path):
            stats.append(path)
            return super().stat(path)

    job = _job(src, tmp_path / "out" / "f.bin", LocalFS(), _Counting(), use_temp_file=True)
    TransferWorker()._process_job(job)
    assert job.status is TransferStatus.DONE, job.error_message
    assert job.integrity_compared
    assert stats == []


def test_edge_a_short_move_under_a_dev_folder_of_a_server_is_refused_too():
    """Only a kernel file on a whole machine's root (local, SFTP ...) listed
    with such a file's size reads short without loss; a "/dev" folder on
    another server is an ordinary one."""

    class _FtpLike:
        pass

    job = TransferJob(source_path="/dev/backup.tar", dest_path="/x/backup.tar", move=True)
    job.source_backend = _FtpLike()
    job.move_source_size = 4096
    with pytest.raises(OSError, match="only 100 of 4096 bytes"):
        TransferWorker._refuse_short_move(job, 100)
    job.source_backend = LocalFS()
    job.source_path = "/sys/class/net/lo/mtu"
    TransferWorker._refuse_short_move(job, 6)  # sysfs: listed 4096, reads a few
    job.move_source_size = 3 * 1024 * 1024  # not a kernel file's size
    with pytest.raises(OSError, match="were copied"):
        TransferWorker._refuse_short_move(job, 100)
