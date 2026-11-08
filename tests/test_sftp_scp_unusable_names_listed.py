"""SFTP and SCP listings show names with a backslash, control characters
or bidi overrides instead of dropping them.

list_dir passed its entries through ``drop_unsafe_names``, which removed
every name that is not safe on EVERY backend: ``C:\\temp\\log.txt`` (a
legal POSIX name), ``bad\\x01name``, ``report\\u202efdp.exe``. The folder
copy never saw them, so it reported success while the copy was
incomplete, and the transfer manager's "name not usable here" row
(``_unsafe_name_job``) never appeared - against the "shown, never
dropped" rule local_fs keeps. Now only names no POSIX folder can hold go
(empty, ``/`` or NUL inside, ``.`` / ``..``); the rest is listed, the
transfer list refuses it visibly, and the pane shows it escaped.
"""

from __future__ import annotations

import os
import stat
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

paramiko = pytest.importorskip("paramiko")

from core import path_policy  # noqa: E402
from core.scp_client import SCPSession, _Capabilities  # noqa: E402
from core.ssh_client import SSHSession  # noqa: E402
from models.file_item import FileItem  # noqa: E402

UNUSABLE = ["C:\\temp\\log.txt", "bad\x01name", "report\u202efdp.exe"]
IMPOSSIBLE = ["../escape", "a/b", "", "nul\x00name"]


def _attr(name: str, mode: int = stat.S_IFREG | 0o644):
    a = paramiko.SFTPAttributes()
    a.filename = name
    a.st_mode = mode
    a.st_size = 3
    a.st_mtime = a.st_atime = int(time.time())
    a.st_uid = a.st_gid = 0
    return a


class _FakeSftp:
    def __init__(self, names):
        self.names = names

    def listdir_attr(self, path):
        return [_attr(n) for n in self.names]

    def lstat(self, path):
        return _attr("dir", stat.S_IFDIR | 0o755)


def _sftp(names) -> SSHSession:
    s = SSHSession.__new__(SSHSession)
    s._get_sftp_client = lambda: _FakeSftp(names)
    return s


def test_sad_sftp_lists_names_another_backend_cannot_take():
    names = [i.name for i in _sftp(["ok.txt", *UNUSABLE]).list_dir("/remote/dir")]
    assert names == ["ok.txt", *UNUSABLE]


def test_edge_sftp_still_drops_names_no_posix_folder_holds():
    names = [i.name for i in _sftp(["ok.txt", *IMPOSSIBLE, ".", ".."]).list_dir("/r")]
    assert names == ["ok.txt"]


def _scp(output: str) -> SCPSession:
    s = SCPSession.__new__(SCPSession)
    s._lock = threading.Lock()
    s._caps = _Capabilities()
    s._exec = lambda cmd, *a, **k: output
    return s


def test_sad_scp_lists_names_another_backend_cannot_take():
    lines = ["total 8", "drwxr-xr-x 2 u u 4096 Jan  1 12:00 .",
             "drwxr-xr-x 3 u u 4096 Jan  1 12:00 ..",
             "-rw-r--r-- 1 u u 3 Jan  1 12:00 ok.txt"]
    lines += [f"-rw-r--r-- 1 u u 3 Jan  1 12:00 {n}" for n in UNUSABLE]
    names = [i.name for i in _scp("\n".join(lines) + "\n").list_dir("/remote/dir")]
    assert [n for n in names if n not in (".", "..")] == ["ok.txt", *UNUSABLE]


def test_happy_the_folder_copy_shows_a_refused_row_per_unusable_name(tmp_path):
    from PyQt6.QtCore import QCoreApplication

    QCoreApplication.instance() or QCoreApplication([])
    from core.local_fs import LocalFS
    from core.transfer_manager import TransferManager
    from core.transfer_worker import TransferDirection

    mgr = TransferManager(max_parallel=1)
    try:
        mgr._worker.enqueue = lambda job: None  # look at what the walk queues only
        jobs = mgr._transfer_directory(
            _sftp(["ok.txt", *UNUSABLE]), LocalFS(), "/remote/dir",
            os.path.join(str(tmp_path), "dir"), TransferDirection.DOWNLOAD,
        )
    finally:
        mgr.shutdown()
    refused = sorted(os.path.basename(j.source_path) for j in jobs if j.error_message)
    assert refused == sorted(UNUSABLE)
    assert all("not usable" in j.error_message for j in jobs if j.error_message)
    assert [os.path.basename(j.source_path) for j in jobs if not j.error_message] == ["ok.txt"]


def test_edge_the_pane_shows_such_names_escaped():
    from models.file_table_model import COL_NAME, FileTableModel

    model = FileTableModel()
    for name in UNUSABLE[1:]:
        shown = model.display_text(FileItem(name=name), COL_NAME)
        assert "\x01" not in shown and "\u202e" not in shown


def test_happy_drop_impossible_names_keeps_dots_on_request():
    items = [FileItem(name=n) for n in (".", "..", "x", "a/b")]
    kept = path_policy.drop_impossible_names(items, keep_dots=True)
    assert [i.name for i in kept] == [".", "..", "x"]
