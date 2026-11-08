"""Round trips and local work per transferred file.

Measured before (lab, 20 ms latency relay, 500 x 4 KiB): an SFTP upload
asked per file exists(temp) + open + checksum + chmod + rename + set the
time (294 ms/file against 77 ms for plain paramiko); a WebDAV upload sent a
PROPFIND for a checksum that could only be an ETag, which is never
compared; S3 a HEAD for an ETag that cannot match a local SHA-256; and a
WebDAV / S3 upload into a folder the copy itself had just made asked per
file whether something was there to snapshot.

Now: a temp name made by the job is not looked for, mode and time go in
one SETSTAT before the rename, a backend that can only answer a storage
fingerprint (``checksum_kinds``) is not asked, and a direct write in
"overwrite" mode into a folder this batch made takes the name as free.

What must not change, and is held here: a temp name brought along (a
retry) is still cleared, a refused SETSTAT falls back to chmod and time,
forced verification still streams both sides, "fail" still looks right
before writing (a file that appeared after the walk is kept), and a
writer that commits only at close and never got there removes nothing.
"""

from __future__ import annotations

import collections
import io
import os
import stat
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core.local_fs import LocalFS  # noqa: E402
from core.transfer_worker import (  # noqa: E402
    TransferJob,
    TransferStatus,
    TransferWorker,
    _may_compare,
)

MTIME = 1_700_000_000.0


class CountingFS(LocalFS):
    """A local folder that counts what is asked of it, standing in for a
    remote temp-file backend; ``set_attributes`` as SFTP has it."""

    COUNTED = ("exists", "stat", "open_write", "open_read", "chmod", "set_modified",
               "rename", "remove", "checksum", "set_attributes")

    def __init__(self, *, refuse_set_attributes: bool = False) -> None:
        super().__init__()
        self.calls: collections.Counter = collections.Counter()
        self.paths: list[tuple[str, str]] = []
        self.refuse_set_attributes = refuse_set_attributes
        for name in self.COUNTED:
            self._count(name)

    def _count(self, name: str) -> None:
        real = getattr(self, name)

        def counted(*args, **kwargs):
            self.calls[name] += 1
            self.paths.append((name, str(args[0]) if args else ""))
            return real(*args, **kwargs)

        # On the instance: the class keeps LocalFS.checksum, so the
        # integrity check still reads the temp file as a local one.
        setattr(self, name, counted)

    def set_attributes(self, path, *, mode=None, mtime=None):
        if self.refuse_set_attributes:
            raise OSError(1, "SETSTAT refused")
        if mode is not None:
            os.chmod(path, mode)
        if mtime is not None:
            os.utime(path, (time.time(), mtime))


def _source(tmp_path, name="f.bin", data=b"x" * 4096, mode=0o640) -> Path:
    src = tmp_path / "src"
    src.mkdir(exist_ok=True)
    path = src / name
    path.write_bytes(data)
    path.chmod(mode)
    os.utime(path, (MTIME, MTIME))
    return path


def _job(src: Path, dest: Path, dest_backend, **kw) -> TransferJob:
    st = src.stat()
    job = TransferJob(source_path=str(src), dest_path=str(dest), filename=src.name,
                      total_bytes=st.st_size, source_mode=st.st_mode,
                      source_mtime=st.st_mtime, **kw)
    job.source_backend = LocalFS()
    job.dest_backend = dest_backend
    return job


def _run(job: TransferJob) -> TransferJob:
    TransferWorker()._process_job(job)
    return job


@pytest.fixture(autouse=True)
def _umask():
    old = os.umask(0o022)
    yield
    os.umask(old)


# -- happy ---------------------------------------------------------------------------------


def test_happy_a_temp_route_upload_asks_four_things_per_file(tmp_path):
    """The regression guard: open, checksum (read back), one SETSTAT, rename."""
    src = _source(tmp_path, mode=0o755)
    (tmp_path / "dst").mkdir()
    fs = CountingFS()
    job = _run(_job(src, tmp_path / "dst" / "f.bin", fs, use_temp_file=True))
    assert job.status == TransferStatus.DONE, job.error_message
    assert dict(fs.calls) == {"open_write": 1, "checksum": 1, "set_attributes": 1, "rename": 1}
    out = tmp_path / "dst" / "f.bin"
    assert stat.S_IMODE(out.stat().st_mode) == 0o755
    assert int(out.stat().st_mtime) == int(MTIME)
    # The time went onto the temp file, before the rename.
    order = [name for name, _p in fs.paths]
    assert order.index("set_attributes") < order.index("rename")


def test_edge_a_private_mode_is_set_before_the_data_and_the_time_after(tmp_path):
    """A 0640 source: the temp file gets its mode before any byte (as
    before); the SETSTAT then carries only the time."""
    src = _source(tmp_path, mode=0o640)
    (tmp_path / "dst").mkdir()
    fs = CountingFS()
    calls = []
    fs.set_attributes = lambda path, *, mode=None, mtime=None: calls.append((mode, mtime)) or (
        CountingFS.set_attributes(fs, path, mode=mode, mtime=mtime))
    job = _run(_job(src, tmp_path / "dst" / "f.bin", fs, use_temp_file=True))
    assert job.status == TransferStatus.DONE, job.error_message
    order = [name for name, _p in fs.paths]
    assert order[:3] == ["open_write", "chmod", "open_write"]  # precreated 0640 | owner-w
    assert calls == [(None, MTIME)]
    out = tmp_path / "dst" / "f.bin"
    assert stat.S_IMODE(out.stat().st_mode) == 0o640
    assert int(out.stat().st_mtime) == int(MTIME)


def test_happy_fail_mode_adds_only_the_check_before_the_rename(tmp_path):
    src = _source(tmp_path)
    (tmp_path / "dst").mkdir()
    fs = CountingFS()
    job = _run(_job(src, tmp_path / "dst" / "f.bin", fs, use_temp_file=True, if_exists="fail"))
    assert job.status == TransferStatus.DONE, job.error_message
    assert fs.calls["exists"] == 1
    assert ("exists", str(tmp_path / "dst" / "f.bin")) in fs.paths


def test_happy_a_small_file_sends_one_progress_signal(tmp_path):
    src = _source(tmp_path)
    (tmp_path / "dst").mkdir()
    worker = TransferWorker()
    progress, speeds = [], []
    worker.progress.connect(lambda *a: progress.append(a[1:]))
    worker.speed_update.connect(lambda *a: speeds.append(a))
    job = _job(src, tmp_path / "dst" / "f.bin", LocalFS(), use_temp_file=True)
    worker._process_job(job)
    assert job.status == TransferStatus.DONE
    assert progress == [(4096, 4096)]
    assert speeds == []  # a single chunk has no speed to report


def test_happy_a_fingerprint_only_backend_is_not_asked_for_its_checksum(tmp_path):
    class Fingerprints(CountingFS):
        def checksum_kinds(self, path="", *, written=False):
            return frozenset({"etag"})

    src = _source(tmp_path)
    (tmp_path / "dst").mkdir()
    fs = Fingerprints()
    job = _run(_job(src, tmp_path / "dst" / "f.bin", fs, use_temp_file=True))
    assert job.status == TransferStatus.DONE
    assert fs.calls["checksum"] == 0


def test_happy_s3_kinds_rule_out_a_local_source_but_not_another_store():
    from core.s3_client import S3Session

    s3 = S3Session.__new__(S3Session)
    assert not _may_compare(s3, "k", LocalFS(), written=True)
    assert _may_compare(s3, "k", object(), written=True)  # md5 against another store
    assert not _may_compare(s3, "k", object(), written=True, against="sha256:ab")
    assert _may_compare(s3, "k", object(), written=True, against="md5:ab")
    assert _may_compare(object(), "k", LocalFS(), written=True)  # says nothing: asked


# -- sad -----------------------------------------------------------------------------------


def test_sad_a_temp_name_brought_along_is_still_cleared(tmp_path):
    """A retry's job carries the old temp path: a leftover there is removed
    before the write, not appended to or renamed in."""
    src = _source(tmp_path, data=b"NEW" * 100)
    (tmp_path / "dst").mkdir()
    stale = tmp_path / "dst" / ".f.bin.part-old"
    stale.write_bytes(b"STALE" * 1000)
    fs = CountingFS()
    job = _job(src, tmp_path / "dst" / "f.bin", fs, use_temp_file=True)
    job.temp_path = str(stale)
    _run(job)
    assert job.status == TransferStatus.DONE, job.error_message
    assert ("exists", str(stale)) in fs.paths
    assert (tmp_path / "dst" / "f.bin").read_bytes() == b"NEW" * 100


def test_sad_a_refused_setstat_falls_back_to_chmod_and_time(tmp_path):
    src = _source(tmp_path)
    (tmp_path / "dst").mkdir()
    fs = CountingFS(refuse_set_attributes=True)
    job = _run(_job(src, tmp_path / "dst" / "f.bin", fs, use_temp_file=True))
    assert job.status == TransferStatus.DONE, job.error_message
    assert fs.calls["chmod"] == 1 and fs.calls["set_modified"] == 1
    out = tmp_path / "dst" / "f.bin"
    assert stat.S_IMODE(out.stat().st_mode) == 0o640
    assert int(out.stat().st_mtime) == int(MTIME)


def test_sad_forced_verification_still_streams_a_fingerprint_only_destination(tmp_path):
    class Fingerprints(CountingFS):
        def checksum_kinds(self, path="", *, written=False):
            return frozenset({"etag"})

    src = _source(tmp_path)
    (tmp_path / "dst").mkdir()
    fs = Fingerprints()
    job = _run(_job(src, tmp_path / "dst" / "f.bin", fs, use_temp_file=True,
                    verify_checksum=True))
    assert job.status == TransferStatus.DONE
    assert fs.calls["checksum"] == 0
    assert fs.calls["open_read"] == 1  # the temp file, streamed for the check


# -- the direct route (WebDAV, S3, ...) ----------------------------------------------------


class DirectFS(CountingFS):
    """A backend without a usable rename: the direct route, as WebDAV."""

    def rename(self, src, dst):  # noqa: D401 - never used by the direct route
        raise OSError("no rename here")


def test_happy_a_new_folder_in_overwrite_mode_asks_no_existence(tmp_path):
    src = _source(tmp_path)
    (tmp_path / "dst").mkdir()
    fs = DirectFS()
    job = _run(_job(src, tmp_path / "dst" / "f.bin", fs, use_temp_file=False,
                    dest_folder_new=True))
    assert job.status == TransferStatus.DONE, job.error_message
    assert fs.calls["exists"] == 0
    assert (tmp_path / "dst" / "f.bin").read_bytes() == b"x" * 4096


def test_sad_fail_mode_in_a_new_folder_still_finds_a_file_that_appeared(tmp_path):
    """The walk made the folder; someone put a file in it before the job
    ran. "fail" looks right before the write and keeps it."""
    src = _source(tmp_path)
    (tmp_path / "dst").mkdir()
    (tmp_path / "dst" / "f.bin").write_bytes(b"THEIRS")
    fs = DirectFS()
    job = _run(_job(src, tmp_path / "dst" / "f.bin", fs, use_temp_file=False,
                    dest_folder_new=True, if_exists="fail"))
    assert job.status == TransferStatus.ERROR
    assert (tmp_path / "dst" / "f.bin").read_bytes() == b"THEIRS"


def test_edge_a_folder_not_made_by_the_batch_is_still_asked(tmp_path):
    src = _source(tmp_path)
    (tmp_path / "dst").mkdir()
    fs = DirectFS()
    job = _run(_job(src, tmp_path / "dst" / "f.bin", fs, use_temp_file=False))
    assert job.status == TransferStatus.DONE
    assert fs.calls["exists"] >= 1


def test_edge_a_commit_at_close_writer_that_never_got_there_removes_nothing(
        tmp_path, monkeypatch):
    """S3 / Azure Blob commit the object at close. A transfer that fails
    before (the source breaks off) left nothing of its own: a file now
    under the name is someone else's and stays."""
    import core.server_ops as SO

    monkeypatch.setattr(SO, "write_traits",
                        lambda backend: SO.WriteTraits(commits_on_close=True, real_append=False))
    dest = tmp_path / "dst" / "f.bin"
    (tmp_path / "dst").mkdir()

    class Spooling(DirectFS):
        def open_write(self, path, append=False):
            return io.BytesIO()  # commits nothing: the store is the real file

    class BrokenSource(LocalFS):
        def open_read(self, path):
            class Reader(io.BytesIO):
                def read(self, n=-1):
                    dest.write_bytes(b"THEIRS")  # appears while the job runs
                    raise OSError(5, "read failed")
            return Reader()

    src = _source(tmp_path)
    fs = Spooling()
    job = _job(src, dest, fs, use_temp_file=False, dest_folder_new=True)
    job.source_backend = BrokenSource()
    _run(job)
    assert job.status == TransferStatus.ERROR
    assert dest.read_bytes() == b"THEIRS"
    assert fs.calls["remove"] == 0


def test_edge_the_walk_marks_jobs_into_a_folder_it_made(tmp_path):
    """Only direct-route jobs in "overwrite" mode into a folder the walk
    created carry dest_folder_new."""
    from PyQt6.QtWidgets import QApplication

    app = QApplication.instance() or QApplication([])
    from core.transfer_conflicts import ConflictPlan
    from core.transfer_manager import TransferManager
    from core.transfer_worker import TransferDirection

    src = tmp_path / "src" / "tree"
    src.mkdir(parents=True)
    (src / "a.bin").write_bytes(b"a")
    (tmp_path / "out").mkdir()
    (tmp_path / "out2").mkdir()
    (tmp_path / "out2" / "tree").mkdir()  # there already: not made by the walk
    manager = TransferManager(max_parallel=1)
    try:
        direct = DirectFS()
        made = manager.transfer_files(LocalFS(), direct, [str(src)], str(tmp_path / "out"),
                                      TransferDirection.UPLOAD)
        kept = manager.transfer_files(LocalFS(), direct, [str(src)], str(tmp_path / "out2"),
                                      TransferDirection.UPLOAD)
        plan = ConflictPlan.never_replace(direct)
        planned = manager.transfer_files(LocalFS(), direct, [str(src)], str(tmp_path / "out3"),
                                         TransferDirection.UPLOAD, conflict_plan=plan)
        temp_route = manager.transfer_files(LocalFS(), LocalFS(), [str(src)],
                                            str(tmp_path / "out4"), TransferDirection.UPLOAD)
        assert [j.dest_folder_new for j in made] == [True]
        assert [j.dest_folder_new for j in kept] == [False]
        assert [j.dest_folder_new for j in planned] == [False]
        assert [j.dest_folder_new for j in temp_route] == [False]
        deadline = time.monotonic() + 30
        while manager.unfinished() and time.monotonic() < deadline:
            app.processEvents()
            time.sleep(0.01)
    finally:
        manager.shutdown()


# -- SETSTAT and rename in one round trip (SFTP) -------------------------------------------


class CombinedFS(CountingFS):
    """``rename_with_attributes`` as SSHSession has it; *answer*: what it
    returns (attributes set?), or an exception to raise."""

    def __init__(self, answer=True) -> None:
        super().__init__()
        self.answer = answer
        self._count("rename_with_attributes")

    def rename_with_attributes(self, src, dst, *, mode=None, mtime=None):
        if isinstance(self.answer, Exception):
            raise self.answer
        if self.answer:
            CountingFS.set_attributes(self, src, mode=mode, mtime=mtime)
        os.rename(src, dst)
        return self.answer


def test_happy_one_request_sets_mode_and_time_and_renames(tmp_path):
    src = _source(tmp_path, mode=0o755)
    (tmp_path / "dst").mkdir()
    fs = CombinedFS()
    job = _run(_job(src, tmp_path / "dst" / "f.bin", fs, use_temp_file=True))
    assert job.status == TransferStatus.DONE, job.error_message
    assert dict(fs.calls) == {"open_write": 1, "checksum": 1, "rename_with_attributes": 1}
    out = tmp_path / "dst" / "f.bin"
    assert stat.S_IMODE(out.stat().st_mode) == 0o755
    assert int(out.stat().st_mtime) == int(MTIME)


def test_sad_attributes_refused_with_the_rename_are_set_on_the_destination(tmp_path):
    src = _source(tmp_path, mode=0o755)
    (tmp_path / "dst").mkdir()
    fs = CombinedFS(answer=False)
    job = _run(_job(src, tmp_path / "dst" / "f.bin", fs, use_temp_file=True))
    assert job.status == TransferStatus.DONE, job.error_message
    out = str(tmp_path / "dst" / "f.bin")
    assert ("chmod", out) in fs.paths and ("set_modified", out) in fs.paths
    assert stat.S_IMODE(os.stat(out).st_mode) == 0o755
    assert int(os.stat(out).st_mtime) == int(MTIME)


def test_sad_a_failed_combined_rename_falls_back_to_the_finalize(tmp_path):
    src = _source(tmp_path, mode=0o755)
    (tmp_path / "dst").mkdir()
    fs = CombinedFS(answer=OSError(95, "posix-rename unsupported"))
    job = _run(_job(src, tmp_path / "dst" / "f.bin", fs, use_temp_file=True))
    assert job.status == TransferStatus.DONE, job.error_message
    assert fs.calls["set_attributes"] == 1 and fs.calls["rename"] == 1
    out = tmp_path / "dst" / "f.bin"
    assert out.read_bytes() == b"x" * 4096
    assert int(out.stat().st_mtime) == int(MTIME)


def test_edge_fail_mode_looks_before_the_combined_rename(tmp_path):
    """The destination appeared while the file was written: refused before
    the rename, the temp file goes, the newcomer stays."""
    src = _source(tmp_path)
    (tmp_path / "dst").mkdir()
    dest = tmp_path / "dst" / "f.bin"

    class Late(CombinedFS):
        def checksum(self, path, algorithm="sha256"):
            dest.write_bytes(b"THEIRS")  # appears during the check
            return LocalFS.checksum(self, path, algorithm)

    fs = Late()
    job = _run(_job(src, dest, fs, use_temp_file=True, if_exists="fail"))
    assert job.status == TransferStatus.ERROR
    assert dest.read_bytes() == b"THEIRS"
    assert fs.calls["rename_with_attributes"] == 0
    assert [p.name for p in (tmp_path / "dst").iterdir()] == ["f.bin"]
