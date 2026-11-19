"""SFTP and SCP: an operation on a connection the server dropped says the
connection is gone, and the session reports itself disconnected.

After a drop the pane showed "Not connected" (SFTP) or "SCP
list_dir(/x): Command execution failed: SSH session not active" (SCP):
library words, and no hint that a reconnect is what helps. Both now
raise ConnectionAbortedError, which core.user_errors.describe turns
into "The connection was closed by the other side. Reconnect and try
again."; ``connected`` turns False, so the connection manager opens a new
session instead of handing out the dead one.

End to end against tests/ssh_shell_testkit.py; SshShellServer.drop()
cuts the TCP connections.
"""

from __future__ import annotations

import time

import pytest

from core.scp_client import SCPSession
from core.ssh_client import SSHSession
from core.user_errors import describe
from tests.ssh_shell_testkit import SshShellServer, connect, profile


@pytest.fixture(params=["sftp", "scp"])
def dropped(request, tmp_path):
    root = tmp_path / "srv"
    root.mkdir()
    (root / "f.txt").write_text("x")
    srv = SshShellServer(str(root))
    cls = SSHSession if request.param == "sftp" else SCPSession
    s = connect(cls(profile(srv, request.param)), known_hosts=tmp_path / "known_hosts")
    folder = "/" if request.param == "sftp" else str(root)
    assert s.list_dir(folder)
    srv.drop()
    deadline = time.monotonic() + 10
    while s.connected and time.monotonic() < deadline:
        time.sleep(0.05)
    yield s, folder, root
    s.disconnect()
    srv.close()


def test_happy_the_session_reports_the_drop(dropped):
    s, _, _ = dropped
    assert not s.connected


def test_sad_a_listing_says_the_connection_is_gone(dropped):
    s, folder, _ = dropped
    with pytest.raises(ConnectionAbortedError) as info:
        s.list_dir(folder)
    assert "closed by the other side" in describe(info.value)


def test_edge_stat_and_read_say_so_too(dropped):
    s, folder, root = dropped
    path = folder.rstrip("/") + "/f.txt"
    for call in (lambda: s.stat(path), lambda: s.open_read(path).read()):
        with pytest.raises(ConnectionAbortedError) as info:
            call()
        assert "Reconnect" in describe(info.value)
