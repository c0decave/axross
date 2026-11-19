"""A server-side checksum (HASH / XSHA256) may take longer than an
ordinary reply: the server reads the whole file before it answers.

The reply was read with the control connection's time-out
(SOCKET_TIMEOUT, 15 s), so a server hashing a file of a few GB never
answered in time: checksum() gave "" (the transfer check then had to read
the file back), and the timed-out connection had to log in again. The
checksum reply now gets CHECKSUM_TIMEOUT; the connection's own time-out is
restored after it. Driven against tests/ftp_fs_server.py with a HASH that
answers after a delay.
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ftp_fs_server import FtpFsServer  # noqa: E402

from core import ftp_client as FC  # noqa: E402


def test_slow_hash_reply_is_waited_for(tmp_path, monkeypatch):
    (tmp_path / "a.bin").write_bytes(b"hello")
    monkeypatch.setattr(FC, "SOCKET_TIMEOUT", 0.3)
    monkeypatch.setattr(FC, "CHECKSUM_TIMEOUT", 5.0)
    srv = FtpFsServer(str(tmp_path), hash_cmds=True, delay={"HASH": 0.8})
    try:
        sess = FC.FtpSession("127.0.0.1", srv.port, "u", "p")
        try:
            assert sess.checksum("/a.bin") == "sha256:" + hashlib.sha256(b"hello").hexdigest()
            # The connection's own time-out is back, and it still works.
            assert sess._ftp.sock.gettimeout() == 0.3
            assert [i.name for i in sess.list_dir("/")] == ["a.bin"]
            assert srv.logins == 1
        finally:
            sess.close()
    finally:
        srv.close()
