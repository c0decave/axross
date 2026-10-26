"""The FUSE mount end to end: a real kernel mount of a backend, driven
with ordinary file calls.

The other FUSE tests call ``BackendFuseFS`` methods directly (or mount
only to read). Here every write path goes through the kernel: write and
read back, truncate (path and descriptor, shrink and zero-filled grow),
append, a partial overwrite in the middle of a file and a file of several
MiB. Each runs against LocalFS, against an SFTP session to the test kit's
paramiko server, and against the lab's OpenSSH server (ssh-alpha) when it
is reachable (``podman unshare --rootless-netns``).

The write-back counts: committing a file and pre-fetching one for an edit
move it in pieces of ``core.fuse_mount.IO_CHUNK`` (the 1 MiB that
``atomic_write_stream`` and the transfer queue use), not 64 KiB - on a
remote backend each piece can be a request of its own.
"""

from __future__ import annotations

import hashlib
import inspect
import math
import os
import shutil
import socket
import subprocess
import sys
import time
import uuid
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import fuse_mount as FM  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402

MIB = 1024 * 1024
LAB_HOST, LAB_PORT, LAB_USER, LAB_PASS = "10.99.0.10", 22, "alpha", "alpha123"


def _fusermount() -> str | None:
    return shutil.which("fusermount3") or shutil.which("fusermount")


def _fuse_usable() -> bool:
    return FM.FUSE_AVAILABLE and os.path.exists("/dev/fuse") and _fusermount() is not None


def _lab_up() -> bool:
    try:
        with socket.create_connection((LAB_HOST, LAB_PORT), timeout=0.5):
            return True
    except OSError:
        return False


pytestmark = pytest.mark.skipif(not _fuse_usable(), reason="needs FUSE (fusepy, /dev/fuse, "
                                                         "fusermount)")


# -- counting the backend's I/O calls ---------------------------------------------------


class _CountingHandle:
    def __init__(self, inner, tally: dict, key: str) -> None:
        self._inner, self._tally, self._key = inner, tally, key

    def read(self, *args):
        data = self._inner.read(*args)
        self._tally[self._key] += 1
        return data

    def write(self, data):
        self._tally[self._key] += 1
        return self._inner.write(data)

    def __getattr__(self, name):
        return getattr(self._inner, name)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self._inner.close()
        return False


class _Tally(dict):
    """``reads`` / ``writes``: read() and write() calls on the handles the
    backend's open_read / open_write returned; ``*_opens`` per call."""

    def __init__(self) -> None:
        super().__init__(reads=0, writes=0, read_opens=0, write_opens=0)

    def reset(self) -> None:
        for key in self:
            self[key] = 0


def _count_io(backend) -> _Tally:
    tally = _Tally()
    open_read, open_write = backend.open_read, backend.open_write

    def counted_read(path, *args, **kwargs):
        tally["read_opens"] += 1
        return _CountingHandle(open_read(path, *args, **kwargs), tally, "reads")

    def counted_write(path, *args, **kwargs):
        tally["write_opens"] += 1
        return _CountingHandle(open_write(path, *args, **kwargs), tally, "writes")

    backend.open_read = counted_read
    backend.open_write = counted_write
    return tally


# -- backends ----------------------------------------------------------------------------


class _Side:
    """A backend to mount (``backend`` at ``root``) and an independent way
    to read what landed on it (``stored(name)``), plus how to put a file
    there without the mount (``seed``)."""

    def __init__(self, backend, root, stored, seed, cleanup=lambda: None) -> None:
        self.backend, self.root = backend, root
        self.stored, self.seed, self.cleanup = stored, seed, cleanup


def _local_side(tmp_path: Path) -> _Side:
    src = tmp_path / "src"
    src.mkdir()
    return _Side(LocalFS(), str(src), lambda n: (src / n).read_bytes(),
                 lambda n, data: (src / n).write_bytes(data))


def _sftp_kit_side(tmp_path: Path, monkeypatch) -> _Side:
    from sftp_testkit import SftpServer

    from core.profiles import ConnectionProfile
    from core.ssh_client import SSHSession

    src = tmp_path / "srv"
    src.mkdir()
    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True)
    monkeypatch.setattr(Path, "home", lambda: home)
    server = SftpServer(str(src))
    session = SSHSession(ConnectionProfile(name="t", protocol="sftp", host="127.0.0.1",
                                           port=server.port, username="u"))
    session.connect(password="x", on_unknown_host=lambda _e: True)

    def cleanup() -> None:
        session.disconnect()
        server.close()

    return _Side(session, "/", lambda n: (src / n).read_bytes(),
                 lambda n, data: (src / n).write_bytes(data), cleanup)


def _lab_session(tmp_path: Path, label: str):
    from core.profiles import ConnectionProfile
    from core.ssh_client import SSHSession

    session = SSHSession(ConnectionProfile(name=label, protocol="sftp", host=LAB_HOST,
                                           port=LAB_PORT, username=LAB_USER,
                                           auth_type="password"))
    session._known_hosts_path = tmp_path / f"known_hosts_{label}"
    session.connect(password=LAB_PASS, on_unknown_host=lambda _e: True)
    return session


def _lab_side(tmp_path: Path) -> _Side:
    mounted = _lab_session(tmp_path, "fuse")
    # Checks and seeds go over a session of their own: the mount's session
    # is busy on the FUSE thread.
    check = _lab_session(tmp_path, "check")
    folder = check.join(check.home(), f"axross-fuse-{uuid.uuid4().hex[:10]}")
    check.mkdir(folder)

    def stored(name: str) -> bytes:
        with check.open_read(check.join(folder, name)) as fh:
            return fh.read()

    def seed(name: str, data: bytes) -> None:
        with check.open_write(check.join(folder, name)) as fh:
            fh.write(data)

    def cleanup() -> None:
        try:
            check.remove(folder, recursive=True)
        finally:
            check.disconnect()
            mounted.disconnect()

    return _Side(mounted, folder, stored, seed, cleanup)


@pytest.fixture(params=["local", "sftp_kit", "sftp_lab"])
def side(request, tmp_path, monkeypatch):
    if request.param == "local":
        s = _local_side(tmp_path)
    elif request.param == "sftp_kit":
        s = _sftp_kit_side(tmp_path, monkeypatch)
    else:
        if not _lab_up():
            pytest.skip("ssh-alpha lab container not reachable")
        s = _lab_side(tmp_path)
    try:
        yield s
    finally:
        s.cleanup()


def _unmount_for_sure(mnt: Path, handle) -> None:
    try:
        handle.unmount()
    finally:
        if os.path.ismount(mnt):
            subprocess.run([_fusermount(), "-u", "-z", str(mnt)], capture_output=True,
                           timeout=10, check=False)
    assert not os.path.ismount(mnt), f"FUSE mount left behind at {mnt}"


@pytest.fixture
def mounted(side, tmp_path):
    """(mount point, side, tally): *side*'s backend mounted writeable,
    its open_read / open_write counted."""
    tally = _count_io(side.backend)
    mnt = tmp_path / "mnt"
    mnt.mkdir()
    handle = FM.mount(side.backend, str(mnt), root=side.root, writeable=True,
                      ttl_stat=0.0, ttl_listing=0.0)
    try:
        for _ in range(100):
            if os.path.ismount(mnt):
                break
            time.sleep(0.05)
        if not os.path.ismount(mnt):
            pytest.fail("FUSE mount did not come up")
        yield mnt, side, tally
    finally:
        _unmount_for_sure(mnt, handle)


def _payload(size: int, seed: int = 0) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < size:
        out += hashlib.sha256(f"{seed}:{counter}".encode()).digest()
        counter += 1
    return bytes(out[:size])


# -- happy -----------------------------------------------------------------------------------


def test_happy_write_and_read_back(mounted):
    mnt, side, _tally = mounted
    data = _payload(200_000, 1)
    (mnt / "a.bin").write_bytes(data)
    assert side.stored("a.bin") == data
    assert (mnt / "a.bin").read_bytes() == data
    assert os.path.getsize(mnt / "a.bin") == len(data)


def test_happy_a_file_of_several_mib(mounted):
    mnt, side, _tally = mounted
    data = _payload(5 * MIB + 12345, 2)
    with open(mnt / "big.bin", "wb") as fh:
        for start in range(0, len(data), 300_000):  # not chunk-aligned writes
            fh.write(data[start : start + 300_000])
    assert side.stored("big.bin") == data
    assert (mnt / "big.bin").read_bytes() == data


def test_happy_append(mounted):
    mnt, side, _tally = mounted
    head = _payload(3 * MIB + 7, 3)
    side.seed("log.bin", head)
    with open(mnt / "log.bin", "ab") as fh:
        fh.write(b"tail-1\n")
        fh.write(b"tail-2\n")
    assert side.stored("log.bin") == head + b"tail-1\ntail-2\n"
    assert (mnt / "log.bin").read_bytes() == head + b"tail-1\ntail-2\n"


def test_happy_partial_overwrite_in_the_middle(mounted):
    mnt, side, _tally = mounted
    data = bytearray(_payload(4 * MIB + 99, 4))
    side.seed("edit.bin", bytes(data))
    middle = 2 * MIB - 10  # across the first MiB boundary of the commit
    patch = b"P" * 70_000
    with open(mnt / "edit.bin", "r+b") as fh:
        fh.seek(middle)
        fh.write(patch)
    data[middle : middle + len(patch)] = patch
    assert side.stored("edit.bin") == bytes(data)
    assert (mnt / "edit.bin").read_bytes() == bytes(data)


# -- truncate ----------------------------------------------------------------------------------


def test_happy_truncate_by_path_shrinks(mounted):
    mnt, side, _tally = mounted
    data = _payload(3 * MIB + 5, 5)
    side.seed("t.bin", data)
    os.truncate(mnt / "t.bin", MIB + 3)
    assert side.stored("t.bin") == data[: MIB + 3]
    assert (mnt / "t.bin").read_bytes() == data[: MIB + 3]


def test_edge_truncate_by_path_grows_with_zeros(mounted):
    mnt, side, _tally = mounted
    data = _payload(100_000, 6)
    side.seed("g.bin", data)
    os.truncate(mnt / "g.bin", 2 * MIB)
    assert side.stored("g.bin") == data + bytes(2 * MIB - len(data))


def test_edge_truncate_to_zero(mounted):
    mnt, side, _tally = mounted
    side.seed("z.bin", _payload(10_000, 7))
    os.truncate(mnt / "z.bin", 0)
    assert side.stored("z.bin") == b""


def test_happy_truncate_an_open_descriptor(mounted):
    mnt, side, _tally = mounted
    data = _payload(2 * MIB + 1, 8)
    side.seed("fd.bin", data)
    fd = os.open(mnt / "fd.bin", os.O_RDWR)
    try:
        os.ftruncate(fd, 1000)
        os.lseek(fd, 0, os.SEEK_END)
        os.write(fd, b"!")
    finally:
        os.close(fd)
    assert side.stored("fd.bin") == data[:1000] + b"!"


def test_edge_an_empty_new_file(mounted):
    mnt, side, _tally = mounted
    (mnt / "empty.bin").write_bytes(b"")
    assert side.stored("empty.bin") == b""
    assert (mnt / "empty.bin").read_bytes() == b""


# -- sad ---------------------------------------------------------------------------------------


def test_sad_a_refused_commit_is_an_error_of_close(mounted):
    mnt, side, _tally = mounted
    side.seed("keep.bin", b"original")
    real_open_write = side.backend.open_write

    def refuse(path, *args, **kwargs):
        raise PermissionError(13, "Permission denied", path)

    side.backend.open_write = refuse
    try:
        fh = open(mnt / "keep.bin", "r+b")
        fh.write(b"CHANGED!")
        with pytest.raises(OSError):
            fh.close()
    finally:
        side.backend.open_write = real_open_write
    assert side.stored("keep.bin") == b"original"


# -- the write-back moves IO_CHUNK pieces ------------------------------------------------------


def test_happy_io_chunk_is_atomic_write_streams_default():
    from core.atomic_io import atomic_write_stream

    default = inspect.signature(atomic_write_stream).parameters["chunk_size"].default
    assert FM.IO_CHUNK == default == MIB


def test_happy_commit_writes_whole_mib_pieces(mounted):
    mnt, side, tally = mounted
    size = 5 * MIB + 1
    with open(mnt / "w.bin", "wb") as fh:
        tally.reset()
        fh.write(_payload(size, 9))
    assert tally["write_opens"] == 1
    assert tally["writes"] == math.ceil(size / MIB)


def test_happy_edit_prefetch_reads_whole_mib_pieces(mounted):
    mnt, side, tally = mounted
    size = 5 * MIB + 1
    side.seed("r.bin", _payload(size, 10))
    tally.reset()
    with open(mnt / "r.bin", "r+b") as fh:
        fh.seek(10)
        fh.write(b"x")
    # The pre-fetch reads the file to its end (one empty read says so),
    # the commit writes it back.
    assert tally["read_opens"] == 1
    assert tally["reads"] <= math.ceil(size / MIB) + 1
    assert tally["writes"] == math.ceil(size / MIB)


def test_happy_truncate_prefetch_reads_whole_mib_pieces(mounted):
    mnt, side, tally = mounted
    side.seed("tr.bin", _payload(5 * MIB, 11))
    keep = 3 * MIB + 5
    tally.reset()
    os.truncate(mnt / "tr.bin", keep)
    assert tally["reads"] <= math.ceil(keep / MIB)
    assert tally["writes"] == math.ceil(keep / MIB)
