"""A dead SFTP channel does not poison a live SSH session.

Reported: after something went wrong with a channel, no connect to that
host worked any more although it was reachable; once every pane on it was
closed, connecting worked again. SSHSession cached one SFTP client per
thread and never looked at its channel, while ``connected`` only asked the
transport - the connection manager kept handing the session with the dead
channel to every new pane until the last one released it.

Also: a server that refuses the SFTP subsystem (a NAS with SFTP switched
off while SSH and SCP work) is named as such, not as "Channel closed".
"""

from __future__ import annotations

import shutil
import sys
import tempfile
import threading
from pathlib import Path
from unittest import mock

import paramiko
import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.profiles import ConnectionProfile  # noqa: E402
from core.ssh_client import SSHSession  # noqa: E402
from tests.sftp_testkit import SftpServer  # noqa: E402


class _NoSftpServer(SftpServer):
    """Accepts SSH sessions but has no SFTP subsystem."""

    def _serve(self) -> None:
        from tests import sftp_testkit as K

        while True:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            t = paramiko.Transport(conn)
            t.add_server_key(K._host_key())
            t.start_server(server=K._Auth())
            self._transports.append(t)


@pytest.fixture
def env():
    tmp = Path(tempfile.mkdtemp()).resolve()
    root = tmp / "srv"
    root.mkdir()
    (root / "a.txt").write_bytes(b"a")
    home = tmp / "home"
    (home / ".ssh").mkdir(parents=True)
    patcher = mock.patch("pathlib.Path.home", return_value=home)
    patcher.start()
    servers = []

    def server(cls=SftpServer):
        srv = cls(str(root))
        servers.append(srv)
        return srv

    yield root, server
    for srv in servers:
        srv.close()
    patcher.stop()
    shutil.rmtree(tmp, ignore_errors=True)


def _profile(port: int) -> ConnectionProfile:
    return ConnectionProfile(name="t", protocol="sftp", host="127.0.0.1", port=port, username="u")


def _session(port: int) -> SSHSession:
    s = SSHSession(_profile(port))
    s.connect(password="x", on_unknown_host=lambda _e: True)
    return s


def test_happy_a_closed_sftp_channel_is_reopened(env):
    root, server = env
    s = _session(server().port)
    try:
        assert [i.name for i in s.list_dir("/")] == ["a.txt"]
        s.sftp.close()  # the channel of this thread dies
        assert s.connected  # the transport is fine
        assert [i.name for i in s.list_dir("/")] == ["a.txt"]
    finally:
        s.disconnect()


def test_happy_a_channel_closed_under_another_thread_is_reopened_there(env):
    root, server = env
    s = _session(server().port)
    out: list = []

    def worker() -> None:
        s.list_dir("/")
        s.sftp.get_channel().close()
        out.append([i.name for i in s.list_dir("/")])

    try:
        t = threading.Thread(target=worker)
        t.start()
        t.join(10)
        assert out == [["a.txt"]]
        assert [i.name for i in s.list_dir("/")] == ["a.txt"]
    finally:
        s.disconnect()


def test_edge_the_connection_manager_hands_out_a_working_session(env):
    """A second pane on the host gets the shared session; its first
    listing must work although the shared channel died."""
    from core.connection_manager import ConnectionManager

    root, server = env
    srv = server()
    cm = ConnectionManager()
    profile = _profile(srv.port)
    first = cm.connect(profile, password="x", on_unknown_host=lambda _e: True)
    try:
        first.sftp.close()
        second = cm.connect(profile, password="x", on_unknown_host=lambda _e: True)
        assert second is first  # shared, as before
        assert [i.name for i in second.list_dir("/")] == ["a.txt"]
    finally:
        cm.disconnect_all()


def test_sad_a_dead_transport_is_still_an_error(env):
    root, server = env
    s = _session(server().port)
    s.transport.close()
    assert not s.connected
    with pytest.raises((OSError, ConnectionError)):
        s.list_dir("/")
    s.disconnect()


def test_sad_a_server_without_sftp_says_so(env):
    root, server = env
    srv = server(_NoSftpServer)
    s = SSHSession(_profile(srv.port))
    with pytest.raises(OSError) as info:
        s.connect(password="x", on_unknown_host=lambda _e: True)
    text = str(info.value)
    assert "SFTP subsystem" in text
    assert "SCP" in text
    assert not s.connected


class _NoChannelServer(SftpServer):
    """Authenticates, then refuses every new channel - as OpenSSH does once
    MaxSessions (default 10) channels are open on the connection."""

    def _serve(self) -> None:
        from tests import sftp_testkit as K

        class _Refusing(K._Auth):
            def check_channel_request(self, kind, chanid):
                return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

        while True:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            t = paramiko.Transport(conn)
            t.add_server_key(K._host_key())
            t.start_server(server=_Refusing())
            self._transports.append(t)


def test_sad_a_refused_channel_is_not_called_switched_off_sftp(env):
    # The audit of 2026-10-22: ChannelException is an SSHException, so a
    # server at its channel limit was reported as "SFTP is probably switched
    # off, use SCP" - wrong advice for the "no connect until every pane is
    # closed" case.
    root, server = env
    srv = server(_NoChannelServer)
    s = SSHSession(_profile(srv.port))
    with pytest.raises(OSError) as info:
        s.connect(password="x", on_unknown_host=lambda _e: True)
    text = str(info.value)
    assert "refused to open" in text and "channel" in text
    assert "MaxSessions" in text
    assert "switched off" not in text and "Synology" not in text
    assert not s.connected
