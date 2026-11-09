"""Downloads stream, sizes may be estimates, and nothing stays behind.

Measured before (review round 7, repros ftp/, mail/ and the spool sites):

* N2 - an FTP download of a file that grew between SIZE and the end of
  RETR (a log being written) failed: "ended after 1500 of 1000 bytes".
  Only fewer bytes than announced are a cut connection now; the engine's
  check against the live size decides about the rest;
* N3 - POP3 sizes were taken as exact: Exchange / Microsoft 365 report
  estimates (EnableExactRFC822Size off), every copy failed as "only 5078
  of 5215 bytes" and left a .part. POP3 and NNTP are exact_size=False,
  like IMAP;
* N4 - a download from FTP, S3, Azure, WebDAV (Dropbox, OneDrive) spooled
  the whole body next to its local destination before the copy, so the
  free-space check asked for twice the file: 20 MiB was refused with 90
  MiB free. The engine reads front to back, so the body now streams
  (core.read_spool.sequential_reads) and the room is needed once;
* N5 - writer and pull spools went to the temp folder (a tmpfs), ADB's
  delete=False files stayed when a writer was dropped or open() failed;
* L3 - a sysfs file on a remote machine (listed 4096, read 5 bytes) was
  refused as a short read; /sys, /proc and /dev are exempt everywhere;
* L4 - a refused short read (or Cancel) of a source a resume cannot read
  from an offset kept its hidden .part for a resume that saves nothing;
* L6 - a failed server-side safety copy (disk full) left its partial
  ``.previous-*`` file.
"""

from __future__ import annotations

import dataclasses
import errno
import gc
import io
import os
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import test_backend_conformance as C  # noqa: E402
from ftp_fuzz_server import FakeFtpServer  # noqa: E402

from core import ftp_client as FC  # noqa: E402
from core import posix_compat, read_spool, server_ops  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402
from core.ram_fs import RamFsSession  # noqa: E402
from core.transfer_worker import TransferJob, TransferStatus, TransferWorker  # noqa: E402

FEAT = b"211-Features:\r\n SIZE\r\n211 End\r\n"
MiB = 1024 * 1024


@pytest.fixture
def spool_env(monkeypatch, tmp_path):
    monkeypatch.setenv(read_spool.SPOOL_DIR_ENV, str(tmp_path / "spool"))
    read_spool.set_spool_dir(None)
    yield tmp_path / "spool"
    read_spool.set_spool_dir(None)


def _job(src_backend, src, dest_backend, dst, size, *, temp=True):
    return TransferJob(source_path=src, dest_path=dst, filename=os.path.basename(dst),
                       total_bytes=size, source_backend=src_backend,
                       dest_backend=dest_backend, use_temp_file=temp)


def _cleanup(target):
    for done in target.cleanup:
        try:
            done()
        except Exception:  # noqa: BLE001 - cleanup only
            pass


# ------------------------------------------------------------------ N2
@pytest.mark.parametrize("shared", [False, True], ids=["own-connection", "shared"])
def test_happy_ftp_download_of_a_file_that_grew_reads_it_whole(shared):
    sent = b"x" * 1500
    srv = FakeFtpServer(replies={"FEAT": FEAT, "SIZE": b"213 1000\r\n"}, data={"RETR": sent})
    with srv:
        s = FC.FtpSession(srv.host, srv.port, "u", "p")
        try:
            if shared:
                s._separate_transfers = False
            with s.open_read("/var/log/app.log") as fh:
                assert fh.read() == sent
        finally:
            s.close()


@pytest.mark.parametrize("shared", [False, True], ids=["own-connection", "shared"])
def test_sad_ftp_download_shorter_than_size_still_fails(shared):
    srv = FakeFtpServer(replies={"FEAT": FEAT, "SIZE": b"213 1000\r\n"},
                        data={"RETR": b"x" * 400})
    with srv:
        s = FC.FtpSession(srv.host, srv.port, "u", "p")
        try:
            if shared:
                s._separate_transfers = False
            with pytest.raises(OSError, match="400 of 1000 bytes"):
                with s.open_read("/f") as fh:
                    fh.read()
        finally:
            s.close()


# ------------------------------------------------------------------ N3
def test_happy_pop3_and_nntp_sizes_are_estimates():
    from core.nntp_client import NntpSession
    from core.pop3_client import Pop3Session

    for cls in (Pop3Session, NntpSession):
        backend = cls.__new__(cls)
        assert server_ops.write_traits(backend).exact_size is False, cls.__name__
        assert server_ops.source_size(backend, "/x") is None


@pytest.mark.parametrize("temp", [True, False], ids=["temp-file", "direct"])
def test_happy_pop3_message_with_an_estimated_size_downloads(tmp_path, monkeypatch, temp):
    from test_pop3_reconnect_and_lost_deletes import Pop3d

    from core import pop3_client as P

    srv = Pop3d([("u1", "hello", "\r\n".join(["a" * 70] * 70))])
    s = P.Pop3Session("127.0.0.1", srv.port, "u", "p", use_ssl=False)
    try:
        item = s.list_dir("/")[0]
        real = len(Pop3d.raw(srv.msgs[0]))
        estimate = real + 137  # Exchange: EnableExactRFC822Size off
        stat = P.Pop3Session.stat

        def estimated(self, path):
            return dataclasses.replace(stat(self, path), size=estimate)

        monkeypatch.setattr(P.Pop3Session, "stat", estimated)
        dst = tmp_path / "m.eml"
        job = _job(s, "/" + item.name, LocalFS(), str(dst), estimate, temp=temp)
        TransferWorker()._process_job(job)
        assert job.status is TransferStatus.DONE, job.error_message
        assert dst.stat().st_size == real
        assert sorted(p.name for p in tmp_path.iterdir()) == ["m.eml"]
    finally:
        s.close()
        srv.close()


# ------------------------------------------------------------------ N4
SIZE_N4 = 12 * MiB  # over READ_SPOOL_MAX: the free space is checked
#: Room for the file once (+ the reserve) but not twice.
FREE_N4 = SIZE_N4 + read_spool.SPOOL_RESERVE + 6 * MiB


@pytest.mark.parametrize("temp", [True, False], ids=["temp-file", "direct"])
def test_happy_ftp_download_needs_the_room_once_not_twice(tmp_path, monkeypatch, temp):
    data = os.urandom(SIZE_N4)
    monkeypatch.setattr(posix_compat, "disk_usage",
                        lambda path: (1 << 40, (1 << 40) - FREE_N4, FREE_N4))
    srv = FakeFtpServer(replies={"FEAT": FEAT, "SIZE": f"213 {len(data)}\r\n".encode()},
                        data={"RETR": data})
    with srv:
        s = FC.FtpSession(srv.host, srv.port, "u", "p")
        try:
            dst = tmp_path / "big.iso"
            job = _job(s, "/big.iso", LocalFS(), str(dst), len(data), temp=temp)
            TransferWorker()._process_job(job)
            assert job.status is TransferStatus.DONE, job.error_message
            assert dst.read_bytes() == data
        finally:
            s.close()
            dst.unlink(missing_ok=True)


def test_sad_ftp_download_without_room_once_is_still_refused(tmp_path, monkeypatch):
    free = SIZE_N4  # less than the file + the reserve
    monkeypatch.setattr(posix_compat, "disk_usage", lambda path: (1 << 40, 0, free))
    srv = FakeFtpServer(replies={"FEAT": FEAT, "SIZE": f"213 {SIZE_N4}\r\n".encode()},
                        data={"RETR": b"never sent"})
    with srv:
        s = FC.FtpSession(srv.host, srv.port, "u", "p")
        try:
            job = _job(s, "/big.iso", LocalFS(), str(tmp_path / "big.iso"), SIZE_N4)
            TransferWorker()._process_job(job)
            assert job.status is TransferStatus.ERROR
            assert "Not enough free space" in job.error_message
            assert not any(c.startswith("RETR") for c in srv.commands)
        finally:
            s.close()
    assert list(tmp_path.iterdir()) == []


STREAMED = ("ftp", "s3", "azure_blob", "webdav", "onedrive", "dropbox")


@pytest.mark.parametrize("name", STREAMED)
@pytest.mark.parametrize("temp", [True, False], ids=["temp-file", "direct"])
def test_happy_a_transfer_download_streams_without_a_spool(name, temp, tmp_path, monkeypatch):
    t = C.MAKERS[name](tmp_path)
    try:
        data = os.urandom(3 * MiB + 17)
        C._write(t, t.J("f.bin"), data)
        spools = []
        real = read_spool.new_spool

        def counting(*a, **kw):
            spools.append(a)
            return real(*a, **kw)

        monkeypatch.setattr(read_spool, "new_spool", counting)
        out = tmp_path / "out"
        out.mkdir()
        dst = out / "f.bin"
        job = _job(t.backend, t.J("f.bin"), LocalFS(), str(dst), len(data), temp=temp)
        TransferWorker()._process_job(job)
        assert job.status is TransferStatus.DONE, job.error_message
        assert dst.read_bytes() == data
        assert spools == []  # no spool beside the copy
        assert sorted(p.name for p in out.iterdir()) == ["f.bin"]
    finally:
        _cleanup(t)


@pytest.mark.parametrize("name", STREAMED)
def test_edge_outside_a_transfer_a_download_still_seeks(name, tmp_path):
    """FUSE, previews and archives seek: they keep the spool."""
    t = C.MAKERS[name](tmp_path)
    try:
        C._write(t, t.J("f.bin"), b"0123456789")
        with t.backend.open_read(t.J("f.bin")) as fh:
            assert fh.read(4) == b"0123"
            fh.seek(2)
            assert fh.read() == b"23456789"
    finally:
        _cleanup(t)


def test_sad_a_streamed_body_shorter_than_announced_is_an_oserror():
    closed = []
    body = read_spool.StreamedBody(iter([b"abc", b"de"]), expected_size=9, what="Cannot read /x",
                                   close=lambda: closed.append(1))
    assert body.read(3) == b"abc"
    assert body.read(10) == b"de"
    with pytest.raises(OSError, match="received 5 bytes, the server announced 9"):
        body.read(10)
    body.close()
    body.close()
    assert closed == [1]


def test_sad_a_library_error_while_streaming_is_an_oserror():
    class LibraryError(Exception):
        pass

    def chunks():
        yield b"abc"
        raise LibraryError("connection broken: IncompleteRead")

    body = read_spool.StreamedBody(chunks(), what="Cannot read /x")
    assert body.read(3) == b"abc"
    with pytest.raises(OSError, match="Cannot read /x: connection broken"):
        body.read(3)
    assert not body.seekable()


def test_edge_streaming_only_inside_sequential_reads():
    assert read_spool.streaming_wanted() is False
    with read_spool.sequential_reads():
        assert read_spool.streaming_wanted() is True
        with read_spool.sequential_reads(False):
            assert read_spool.streaming_wanted() is False
    assert read_spool.streaming_wanted() is False


# ------------------------------------------------------------------ N5
_SPOOL_CALL = re.compile(r"\b(SpooledTemporaryFile|NamedTemporaryFile|TemporaryFile)\(")


def test_sad_no_backend_spools_in_the_temp_folder():
    """Every spool of a protocol client goes through core.read_spool (the
    spool folder, its free-space check and cleanup), not tempfile's
    default folder - often a tmpfs of half the RAM."""
    core = Path(__file__).resolve().parents[1] / "core"
    found = []
    for path in sorted(core.glob("*_client.py")):
        for no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if _SPOOL_CALL.search(line) and "dir=" not in line:
                found.append(f"{path.name}:{no}: {line.strip()}")
    assert found == []


@pytest.fixture
def adb(tmp_path):
    t = C.MAKERS["adb"](tmp_path)
    yield t
    _cleanup(t)


def test_happy_an_adb_writer_spools_in_the_spool_folder_and_cleans_up(adb, spool_env):
    w = adb.backend.open_write(adb.J("x.bin"))
    w.write(b"data")
    assert Path(w._tmp_path).parent == spool_env
    w.close()
    assert list(spool_env.iterdir()) == []
    assert C._read(adb, adb.J("x.bin")) == b"data"


def test_sad_an_adb_writer_dropped_without_close_leaves_no_file(adb, spool_env):
    w = adb.backend.open_write(adb.J("x.bin"))
    w.write(b"data")
    path = Path(w._tmp_path)
    assert path.parent == spool_env and path.exists()
    w._tmp.close()
    del w
    gc.collect()
    assert not path.exists()


def test_sad_an_adb_read_leaves_no_file_even_unclosed(adb, spool_env):
    C._write(adb, adb.J("r.bin"), b"payload")
    fh = adb.backend.open_read(adb.J("r.bin"))
    try:
        path = Path(fh._tmp_path)
        assert path.parent == spool_env
        if os.name == "posix":
            assert not path.exists()  # the open handle holds the bytes
        assert fh.read() == b"payload"
    finally:
        fh.close()
    assert not path.exists()


def test_sad_a_failed_adb_pull_leaves_no_file(adb, spool_env):
    with pytest.raises(OSError):
        adb.backend.open_read(adb.J("missing.bin"))
    assert list(spool_env.iterdir()) == []


# ------------------------------------------------------------------ L3
class _SysfsHost(RamFsSession):
    """A remote machine's /sys: listed 4096 bytes, a few read."""

    def stat(self, path):
        item = RamFsSession.stat(self, path)
        return dataclasses.replace(item, size=4096) if not item.is_dir else item


@pytest.mark.parametrize("folder", ["/sys/class/net/eth0", "/proc/1", "/dev/x"])
def test_happy_a_remote_pseudo_file_is_not_refused_as_short(tmp_path, folder):
    src = _SysfsHost(f"sysfs-{os.getpid()}-{id(tmp_path)}")
    try:
        parts = folder.strip("/").split("/")
        for i in range(1, len(parts) + 1):
            p = "/" + "/".join(parts[:i])
            if not src.exists(p):
                src.mkdir(p)
        with src.open_write(folder + "/address") as fh:
            fh.write(b"aa:bb\n")
        dst = tmp_path / "address"
        job = _job(src, folder + "/address", LocalFS(), str(dst), 4096)
        TransferWorker()._process_job(job)
        assert job.status is TransferStatus.DONE, job.error_message
        assert dst.read_bytes() == b"aa:bb\n"
    finally:
        src.disconnect()


def test_sad_an_ordinary_remote_file_read_short_is_still_refused(tmp_path):
    src = _SysfsHost(f"sysfs-plain-{os.getpid()}-{id(tmp_path)}")
    try:
        src.mkdir("/data")
        with src.open_write("/data/address") as fh:
            fh.write(b"aa:bb\n")
        job = _job(src, "/data/address", LocalFS(), str(tmp_path / "address"), 4096)
        TransferWorker()._process_job(job)
        assert job.status is TransferStatus.ERROR
        assert "were read" in job.error_message
    finally:
        src.disconnect()


# ------------------------------------------------------------------ L4
@pytest.fixture
def ftp(tmp_path):
    t = C.MAKERS["ftp"](tmp_path)
    yield t
    _cleanup(t)


def test_sad_a_refused_short_read_of_an_unresumable_source_leaves_no_partial(ftp, tmp_path):
    whole = os.urandom(300_000)
    (ftp.local_dir / "f.bin").write_bytes(whole)
    # The data connection ended early, the server said "226" all the same
    # (no SIZE known): the engine's check finds the source longer.
    ftp.backend.open_read = lambda path: io.BytesIO(whole[:100_000])
    out = tmp_path / "out"
    out.mkdir()
    job = _job(ftp.backend, "/f.bin", LocalFS(), str(out / "f.bin"), len(whole))
    TransferWorker()._process_job(job)
    assert job.status is TransferStatus.ERROR
    assert "100000 of 300000 bytes" in job.error_message
    assert list(out.iterdir()) == []


def test_happy_a_refused_short_read_of_a_seekable_source_keeps_its_partial(tmp_path):
    src = RamFsSession(f"short-{os.getpid()}-{id(tmp_path)}")
    try:
        with src.open_write("/f.bin") as fh:
            fh.write(b"x" * 300_000)
        src.open_read = lambda path: io.BytesIO(b"x" * 100_000)
        out = tmp_path / "out"
        out.mkdir()
        job = _job(src, "/f.bin", LocalFS(), str(out / "f.bin"), 300_000)
        TransferWorker()._process_job(job)
        assert job.status is TransferStatus.ERROR
        kept = [p.name for p in out.iterdir()]
        assert len(kept) == 1 and kept[0].startswith(".f.bin.part-")  # for a resume
    finally:
        src.disconnect()


# ------------------------------------------------------------------ L6
class _FullDisk(RamFsSession):
    """copy() writes half of the copy, then the disk is full."""

    def copy(self, src, dst):
        with self.open_write(dst) as fh:
            fh.write(b"half")
        raise OSError(errno.ENOSPC, "No space left on device")


def test_sad_a_failed_server_side_safety_copy_leaves_no_partial():
    dest = _FullDisk(f"fulldisk-{os.getpid()}")
    try:
        with dest.open_write("/f.bin") as fh:
            fh.write(b"old")
        job = _job(RamFsSession(f"src-{os.getpid()}"), "/f.bin", dest, "/f.bin", 3, temp=False)
        with pytest.raises(OSError, match="nothing was replaced"):
            TransferWorker._back_up_committed_destination(job)
        assert [i.name for i in dest.list_dir("/")] == ["f.bin"]
    finally:
        dest.disconnect()


def test_sad_a_snapshot_that_cannot_be_kept_locally_leaves_no_file(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))

    class _Broken(io.BytesIO):
        def read(self, n=-1):
            if self.tell() >= 4:
                raise OSError(errno.ENOSPC, "No space left on device")
            return super().read(4)

    assert server_ops._keep_snapshot_locally("/x/f.bin", _Broken(b"old content")) is None
    kept = tmp_path / "state" / "axross" / "kept"
    assert not kept.exists() or list(kept.iterdir()) == []
