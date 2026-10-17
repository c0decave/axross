"""A refused rmdir / unlink / mkdir / rename on the mount reports why.

Measured before: every backend error of these operations became EIO, so
``rmdir`` of a non-empty folder said "Input/output error" instead of
"Directory not empty", a refused permission was no EACCES, and
``mkdir -p`` of an existing folder failed with EIO instead of EEXIST,
which it skips. The backend's errno now reaches the kernel; only an
error without one is EIO.

Driven at the operations level - no kernel mount needed.
"""

from __future__ import annotations

import errno
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.fuse_mount import BackendFuseFS, FuseOSError  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402


class _RefusingFS(LocalFS):
    """Every mutation raises ``error``."""

    def __init__(self, error: BaseException) -> None:
        super().__init__()
        self.error = error

    def remove(self, path, recursive=False):
        raise self.error

    def mkdir(self, path):
        raise self.error

    def rename(self, src, dst):
        raise self.error


def _fs(backend, root) -> BackendFuseFS:
    return BackendFuseFS(backend, str(root), writeable=True)


def _errno_of(call) -> int:
    with pytest.raises(FuseOSError) as info:
        call()
    return info.value.errno


# ------------------------------------------------------------------ happy
def test_happy_rmdir_of_a_non_empty_folder_is_enotempty(tmp_path):
    (tmp_path / "d").mkdir()
    (tmp_path / "d" / "f").write_text("x")
    assert _errno_of(lambda: _fs(LocalFS(), tmp_path).rmdir("/d")) == errno.ENOTEMPTY
    assert (tmp_path / "d" / "f").exists()


def test_happy_rmdir_of_an_empty_folder_still_works(tmp_path):
    (tmp_path / "d").mkdir()
    _fs(LocalFS(), tmp_path).rmdir("/d")
    assert not (tmp_path / "d").exists()


def test_happy_unlink_and_mkdir_still_work(tmp_path):
    (tmp_path / "f").write_text("x")
    fs = _fs(LocalFS(), tmp_path)
    fs.unlink("/f")
    fs.mkdir("/d", 0o755)
    assert not (tmp_path / "f").exists() and (tmp_path / "d").is_dir()


def test_happy_unlink_of_a_missing_file_is_enoent(tmp_path):
    assert _errno_of(lambda: _fs(LocalFS(), tmp_path).unlink("/nope")) == errno.ENOENT


# ------------------------------------------------------------------ sad
@pytest.mark.parametrize(
    "error, expected",
    [
        (OSError(errno.ENOTEMPTY, "Directory not empty"), errno.ENOTEMPTY),
        (PermissionError(errno.EACCES, "Permission denied"), errno.EACCES),
        (PermissionError(errno.EPERM, "Operation not permitted"), errno.EPERM),
        (FileNotFoundError(errno.ENOENT, "No such file"), errno.ENOENT),
        (PermissionError("denied by the server"), errno.EACCES),
        (FileNotFoundError("gone"), errno.ENOENT),
        (FileExistsError("already there"), errno.EEXIST),
        (OSError("550 Remove directory operation failed"), errno.EIO),
        (OSError(errno.ETIMEDOUT, "Connection timed out"), errno.ETIMEDOUT),
    ],
    ids=[
        "enotempty",
        "eacces",
        "eperm",
        "enoent",
        "permission-no-errno",
        "not-found-no-errno",
        "exists-no-errno",
        "plain-no-errno",
        "etimedout",
    ],
)
@pytest.mark.parametrize("op", ["rmdir", "unlink", "mkdir", "rename"])
def test_sad_backend_errno_reaches_the_kernel(tmp_path, op, error, expected):
    fs = _fs(_RefusingFS(error), tmp_path)
    calls = {
        "rmdir": lambda: fs.rmdir("/d"),
        "unlink": lambda: fs.unlink("/f"),
        "mkdir": lambda: fs.mkdir("/d", 0o755),
        "rename": lambda: fs.rename("/a", "/b"),
    }
    assert _errno_of(calls[op]) == expected


# ------------------------------------------------------------------ edge
@pytest.mark.parametrize("code", [0, -5, 10**9])
def test_edge_an_errno_that_is_no_errno_is_eio(tmp_path, code):
    fs = _fs(_RefusingFS(OSError(code, "odd")), tmp_path)
    assert _errno_of(lambda: fs.rmdir("/d")) == errno.EIO


def test_edge_read_only_mount_still_answers_erofs(tmp_path):
    fs = BackendFuseFS(_RefusingFS(OSError(errno.ENOTEMPTY, "x")), str(tmp_path))
    assert _errno_of(lambda: fs.rmdir("/d")) == errno.EROFS
