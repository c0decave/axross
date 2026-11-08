"""A stat failure without an errno is EIO on a FUSE mount, not ENOENT.

core.fuse_mount._stat_errno mapped every OSError without errno to ENOENT
("several backends say not found that way"). Most backends raise exactly
that for a 429 / 503, a dropped connection or a refused reply (OneDrive,
Google Drive, Dropbox, SMB, FTP), and ENOENT lets the kernel O_CREAT the
name: ``echo x >> log.txt`` during one such hiccup went to create(),
whose empty buffer was committed over the existing file - the log was
replaced by "x". Now only a FileNotFoundError / ENOENT (or ENOTDIR) is
ENOENT; an untyped error is EIO unless the backend's exists() confirms
that nothing is there.
"""

from __future__ import annotations

import errno
import os

import pytest

from core import fuse_mount as FM
from core.ram_fs import RamFsSession


class _Hiccup(RamFsSession):
    """stat() of log.txt fails once with a bare OSError, as a cloud
    client does for a 429."""

    def __init__(self, label: str, exc: OSError, *, exists_fails: bool = False) -> None:
        super().__init__(label)
        self.exc, self.left, self.exists_fails = exc, 1, exists_fails

    def stat(self, path):
        if path.endswith("log.txt") and self.left:
            self.left -= 1
            raise self.exc
        return super().stat(path)

    def exists(self, path):
        if self.exists_fails:
            raise OSError("503 Service Unavailable")
        return super().exists(path)


def _kernel_append(fs: FM.BackendFuseFS, path: str, data: bytes) -> None:
    """What the VFS does for open(path, O_WRONLY | O_CREAT | O_APPEND)."""
    try:
        fs.getattr(path)
    except OSError as exc:
        if exc.errno != errno.ENOENT:
            raise
        fh = fs.create(path, 0o644)
        fs.write(path, data, 0, fh)
    else:
        fh = fs.open(path, os.O_WRONLY | os.O_APPEND)
        fs.write(path, data, fs.getattr(path, fh)["st_size"], fh)
    fs.flush(path, fh)
    fs.release(path, fh)


@pytest.fixture
def backend(request):
    made = []

    def make(exc, **kw):
        b = _Hiccup(f"fuse-hiccup-{len(made)}-{os.getpid()}-{id(request)}", exc, **kw)
        made.append(b)
        with b.open_write("/log.txt") as fh:
            fh.write(b"line1\nIMPORTANT\n")
        return b

    yield make
    for b in made:
        b.disconnect()


def _read(b) -> bytes:
    with b.open_read("/log.txt") as fh:
        return fh.read()


def test_sad_an_append_during_an_untyped_stat_error_keeps_the_file(backend):
    b = backend(OSError("Cannot stat /log.txt: 429 Too Many Requests"))
    fs = FM.BackendFuseFS(b, "/", writeable=True, ttl_stat=0, ttl_listing=0)
    with pytest.raises(OSError) as ctx:
        _kernel_append(fs, "/log.txt", b"appended\n")
    assert ctx.value.errno == errno.EIO
    assert _read(b) == b"line1\nIMPORTANT\n"


def test_sad_exists_that_cannot_answer_confirms_nothing(backend):
    b = backend(OSError("Cannot stat /log.txt: connection closed"), exists_fails=True)
    fs = FM.BackendFuseFS(b, "/", writeable=True, ttl_stat=0, ttl_listing=0)
    with pytest.raises(OSError) as ctx:
        fs.getattr("/log.txt")
    assert ctx.value.errno == errno.EIO


def test_happy_an_untyped_not_found_still_lets_a_new_file_be_created(backend):
    """A backend that says "not found" with a bare OSError: exists()
    confirms it, so the kernel may create the name."""
    b = backend(OSError("404"))
    b.left = 0

    def bare_not_found(path, _orig=b.stat):
        if path.endswith("new.txt"):
            raise OSError(f"Cannot stat {path}: 404 Not Found")
        return _orig(path)

    b.stat = bare_not_found
    fs = FM.BackendFuseFS(b, "/", writeable=True, ttl_stat=0, ttl_listing=0)
    with pytest.raises(OSError) as ctx:
        fs.getattr("/new.txt")
    assert ctx.value.errno == errno.ENOENT


@pytest.mark.parametrize(
    "exc, code",
    [
        (OSError("no errno"), errno.EIO),
        (OSError(None, "errno None"), errno.EIO),
        (FileNotFoundError("typed, no errno"), errno.ENOENT),
        (FileNotFoundError(errno.ENOENT, "typed"), errno.ENOENT),
        (NotADirectoryError("a file on the way"), errno.ENOENT),
        (OSError(errno.ENOTDIR, "a file on the way"), errno.ENOENT),
        (PermissionError("denied"), errno.EACCES),
        (OSError(errno.EPERM, "not permitted"), errno.EACCES),
        (ConnectionResetError("reset"), errno.EIO),
        (TimeoutError("timed out"), errno.EIO),
        (OSError(errno.ELOOP, "loop"), errno.ELOOP),
        (OSError(errno.ENAMETOOLONG, "long"), errno.ENAMETOOLONG),
        (OSError(errno.EEXIST, "odd for a stat"), errno.EIO),
    ],
    ids=lambda v: v if isinstance(v, int) else type(v).__name__ + ":" + str(v)[:20],
)
def test_edge_stat_errno_mapping(exc, code):
    assert FM._stat_errno(exc) == code
