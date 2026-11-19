"""A move to another file system keeps a folder's named pipes and sockets.

Review: Move to Trash of a folder on another file system (a USB stick,
/tmp on tmpfs) failed when the folder held a FIFO or a socket: the move
falls back to copy + remove (EXDEV), and shutil's copy refuses a named
pipe ("is a named pipe") and cannot open a socket. Now they are made
again at the destination, as mv does: a pipe or a socket is a name, it
holds no data. A device node is made again where this process may make
one; where not, the move stops with nothing moved.
"""

from __future__ import annotations

import errno
import os
import socket
import stat
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import server_ops as SO  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402

pytestmark = pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX FIFOs")


def _folder_with_specials(base: Path) -> Path:
    folder = base / "project"
    folder.mkdir()
    (folder / "a.txt").write_text("a")
    os.mkfifo(folder / "build.fifo", 0o640)
    sub = folder / "run"
    sub.mkdir()
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.bind(str(sub / "app.sock"))
    finally:
        sock.close()
    return folder


def test_happy_a_folder_with_a_fifo_and_a_socket_moves_across_devices(tmp_path):
    folder = _folder_with_specials(tmp_path)
    dst = tmp_path / "elsewhere" / "project"
    dst.parent.mkdir()
    SO._move_across_devices(str(folder), str(dst), OSError(errno.EXDEV, "cross-device"))
    assert not folder.exists()
    assert (dst / "a.txt").read_text() == "a"
    fifo = os.lstat(dst / "build.fifo")
    assert stat.S_ISFIFO(fifo.st_mode) and stat.S_IMODE(fifo.st_mode) == 0o640
    assert stat.S_ISSOCK(os.lstat(dst / "run" / "app.sock").st_mode)


def test_happy_move_to_trash_across_devices_keeps_the_pipe(tmp_path, monkeypatch):
    from core import trash as T

    monkeypatch.setenv("AXROSS_OPERATION_JOURNAL", str(tmp_path / "ops.jsonl"))
    folder = _folder_with_specials(tmp_path)
    real_rename = os.rename

    def cross_device(src, dst, *a, **k):
        if os.path.basename(str(src)) == "project":
            raise OSError(errno.EXDEV, os.strerror(errno.EXDEV), str(src))
        return real_rename(src, dst, *a, **k)

    monkeypatch.setattr(os, "rename", cross_device)
    fs = LocalFS()
    monkeypatch.setattr(LocalFS, "rename_no_replace", None, raising=False)
    trash_root = tmp_path / "home" / ".axross-trash"
    T.trash(fs, str(folder), root=str(trash_root))
    assert not folder.exists()
    entry, = [e for e in T.list_trash(fs, root=str(trash_root))]
    moved = Path(trash_root) / entry.trash_id
    assert stat.S_ISFIFO(os.lstat(moved / "build.fifo").st_mode)
