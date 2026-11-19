"""SFTP: a channel of a thread that has ended is let go (review round 2).

Each thread gets its own SFTP channel on the session's transport, kept in
a table by thread id. Transfer workers and MCP calls come and go; their
channels stayed open for the life of the session, and after ten of them
OpenSSH (MaxSessions 10) refused every new pane, terminal and transfer
on the host. A new channel now drops those of threads that are gone from
the table; paramiko closes a channel nothing refers to any more, so a
file such a thread opened and handed on still reads to its end.
"""

from __future__ import annotations

import gc
import sys
import threading
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.profiles import ConnectionProfile  # noqa: E402
from core.ssh_client import SSHSession  # noqa: E402
from tests.sftp_testkit import SftpServer  # noqa: E402


def _open_channels(session) -> int:
    gc.collect()
    return sum(1 for ch in list(session._transport._channels.values()) if not ch.closed)


def _connected(tmp_path):
    root = tmp_path / "sftp"
    root.mkdir()
    (root / "f.txt").write_bytes(b"x" * 100_000)
    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True)
    patch = mock.patch("pathlib.Path.home", return_value=home)
    patch.start()
    server = SftpServer(str(root))
    s = SSHSession(ConnectionProfile(name="t", protocol="sftp", host="127.0.0.1",
                                     port=server.port, username="u"))
    s.connect(password="x", on_unknown_host=lambda _e: True)
    return s, server, patch


def test_sad_channels_of_ended_threads_are_let_go(tmp_path) -> None:
    s, server, patch = _connected(tmp_path)
    try:
        for _ in range(12):
            t = threading.Thread(target=lambda: s.list_dir("/"))
            t.start()
            t.join()
        s.list_dir("/")
        assert _open_channels(s) <= 2
        assert len(s._thread_sftp) <= 2
    finally:
        s.disconnect()
        server.close()
        patch.stop()


def test_happy_a_file_opened_by_an_ended_thread_still_reads(tmp_path) -> None:
    s, server, patch = _connected(tmp_path)
    try:
        handed = []
        t = threading.Thread(target=lambda: handed.append(s.open_read("/f.txt")))
        t.start()
        t.join()
        s.list_dir("/")  # a new channel: the ended thread's is dropped
        with handed.pop() as fh:
            assert len(fh.read()) == 100_000
    finally:
        s.disconnect()
        server.close()
        patch.stop()
