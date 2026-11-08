"""FTP without MLSD: a folder that may be entered but not read is an
error, never an empty folder.

vsftpd answers NLST (and LIST) of a 0711 folder with "150", no data and
"226 Transfer done (but failed to open directory).". ftplib's nlst()
drops that final reply, so list_dir saw a 2xx and no names; since CWD
into the folder works, the empty listing was accepted - a tree copy or
move skipped everything inside without a word. Now an empty NLST is
checked with LIST: failure wording on its final reply (or a refusal) is a
PermissionError, and entries LIST shows that NLST did not are an OSError.
"""

from __future__ import annotations

import errno
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import ftp_client as FC  # noqa: E402
from tests.test_ftp_symlink_delete import _DirFtpServer  # noqa: E402


class _Vsftpd(_DirFtpServer):
    """vsftpd's answer to a listing of a folder it cannot open."""

    unreadable = ("/secret",)

    def _send_data(self, conn, data_l, lines):
        arg = self.commands[-1].partition(" ")[2]
        if arg.startswith("-a "):
            arg = arg[3:]
        if arg.rstrip("/") in self.unreadable:
            conn.sendall(b"150 Here comes the directory listing.\r\n")
            d, _ = data_l.accept()
            d.close()
            data_l.close()
            conn.sendall(b"226 Transfer done (but failed to open directory).\r\n")
            return
        super()._send_data(conn, data_l, lines)


@pytest.fixture
def ftp(tmp_path):
    root = tmp_path / "srv"
    (root / "secret").mkdir(parents=True)
    (root / "secret" / "a.txt").write_text("a")
    (root / "empty").mkdir()
    (root / "open").mkdir()
    (root / "open" / "b.txt").write_text("b")
    srv = _Vsftpd(root, mlsd="none", missing_listing="empty")
    s = FC.FtpSession("127.0.0.1", srv.port, "u", "p")
    yield s
    s.disconnect()
    srv.close()


def test_sad_a_folder_that_cannot_be_read_is_a_permission_error(ftp):
    with pytest.raises(PermissionError) as info:
        ftp.list_dir("/secret")
    assert info.value.errno == errno.EACCES
    assert "failed to open directory" in str(info.value)


def test_happy_an_empty_folder_is_empty(ftp):
    assert ftp.list_dir("/empty") == []


def test_happy_a_readable_folder_lists(ftp):
    assert [i.name for i in ftp.list_dir("/open")] == ["b.txt"]


def test_edge_a_missing_folder_is_still_not_found(ftp):
    with pytest.raises(FileNotFoundError):
        ftp.list_dir("/nowhere")


class _NlstHidesEverything:
    """NLST answers with nothing, LIST names an entry."""

    def nlst(self, path):
        return []

    def pwd(self):
        return "/"

    def cwd(self, path):
        return "250 ok"

    def retrlines(self, cmd, cb):
        cb("-rw-r--r-- 1 u u 3 Jan  1 12:00 .hidden-but-there")
        return "226 Transfer complete."


def test_sad_entries_list_shows_and_nlst_does_not_are_an_error():
    s = FC.FtpSession.__new__(FC.FtpSession)
    s._has_mlsd = False
    fake = _NlstHidesEverything()
    s._ensure_connected = lambda: fake
    with pytest.raises(OSError, match="LIST shows 1"):
        s.list_dir("/x")
