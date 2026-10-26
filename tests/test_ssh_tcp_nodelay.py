"""SSH and SCP sessions switch off Nagle's algorithm on their TCP socket.

paramiko never sets TCP_NODELAY. With Nagle on, a small SSH packet sent
while an earlier one is still unacknowledged waits for that ACK, and the
server delays a lone ACK by 40 ms: measured on the lab, every SFTP request
after an exec channel (the checksum after each transfer) took 42.7 ms
instead of 0.5 ms, and a pipelined download ran at 42.7 MB/s instead of
190 MB/s. OpenSSH's own client sets TCP_NODELAY for an sftp session.
"""

from __future__ import annotations

import socket
import tempfile
from pathlib import Path

import pytest

from core.profiles import ConnectionProfile
from core.proxy import enable_tcp_nodelay


def _tcp_pair():
    """A connected TCP client socket (and the server side to close)."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    client = socket.create_connection(server.getsockname(), timeout=5)
    accepted, _ = server.accept()
    return client, accepted, server


def _nodelay(sock) -> int:
    return sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY)


# -- enable_tcp_nodelay --------------------------------------------------------


def test_nodelay_happy_tcp_socket_gets_the_option():
    client, accepted, server = _tcp_pair()
    try:
        assert _nodelay(client) == 0  # the kernel default this guards against
        assert enable_tcp_nodelay(client) is True
        assert _nodelay(client) != 0
    finally:
        for s in (client, accepted, server):
            s.close()


def test_nodelay_sad_unix_socket_is_left_alone():
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        assert enable_tcp_nodelay(a) is False
        a.sendall(b"still usable")
        assert b.recv(64) == b"still usable"
    finally:
        a.close()
        b.close()


def test_nodelay_sad_proxy_command_is_not_a_socket():
    class FakeProxyCommand:  # paramiko.ProxyCommand: a pipe to a process
        def send(self, data):
            return len(data)

    assert enable_tcp_nodelay(FakeProxyCommand()) is False


def test_nodelay_edge_closed_socket_does_not_raise():
    client, accepted, server = _tcp_pair()
    for s in (client, accepted, server):
        s.close()
    assert enable_tcp_nodelay(client) is False


def test_nodelay_edge_udp_socket_is_left_alone():
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        assert enable_tcp_nodelay(udp) is False
    finally:
        udp.close()


# -- the sessions hand paramiko a socket without Nagle -------------------------


class _Seen(Exception):
    pass


def _profile(protocol: str) -> ConnectionProfile:
    return ConnectionProfile(name="t", protocol=protocol, host="127.0.0.1", port=22,
                             username="u", auth_type="password")


def test_ssh_session_connect_hands_paramiko_a_nodelay_socket(monkeypatch):
    import core.ssh_client as SC

    client, accepted, server = _tcp_pair()
    seen = {}

    class FakeTransport:
        def __init__(self, sock):
            seen["nodelay"] = _nodelay(sock)
            raise _Seen()

    monkeypatch.setattr(SC, "create_direct_socket", lambda *a, **k: client)
    monkeypatch.setattr(SC.paramiko, "Transport", FakeTransport)
    session = SC.SSHSession(_profile("sftp"))
    try:
        with pytest.raises(_Seen):
            session.connect(password="x")
    finally:
        for s in (client, accepted, server):
            s.close()
    assert seen["nodelay"] != 0


def test_scp_session_connect_hands_paramiko_a_nodelay_socket(monkeypatch):
    import core.scp_client as SCP

    client, accepted, server = _tcp_pair()
    seen = {}

    class FakeSSHClient:
        def set_missing_host_key_policy(self, policy):
            pass

        def get_host_keys(self):
            return SCP.paramiko.HostKeys()

        def connect(self, host, port=22, sock=None, **kwargs):
            seen["nodelay"] = _nodelay(sock)
            raise _Seen()

        def close(self):
            pass

    monkeypatch.setattr(SCP, "create_direct_socket", lambda *a, **k: client)
    monkeypatch.setattr(SCP.paramiko, "SSHClient", FakeSSHClient)
    session = SCP.SCPSession(_profile("scp"))
    session._known_hosts_path = Path(tempfile.mkdtemp()) / "known_hosts"
    try:
        with pytest.raises(_Seen):
            session.connect(password="x")
    finally:
        for s in (client, accepted, server):
            s.close()
    assert seen["nodelay"] != 0


def test_ssh_session_connect_through_proxy_command_still_works(monkeypatch):
    """A ProxyCommand is a pipe, not a TCP socket: nothing to set, no error."""
    import core.ssh_client as SC

    seen = {}

    class FakeProxy:
        def __init__(self, cmd):
            self.cmd = cmd

        def close(self):
            pass

    class FakeTransport:
        def __init__(self, sock):
            seen["sock"] = sock
            raise _Seen()

    monkeypatch.setattr(SC, "CleanEnvProxyCommand", FakeProxy)
    monkeypatch.setattr(SC, "expand_proxy_command", lambda cmd, **k: cmd)
    monkeypatch.setattr(SC.paramiko, "Transport", FakeTransport)
    profile = _profile("sftp")
    profile.proxy_command = "nc %h %p"
    with pytest.raises(_Seen):
        SC.SSHSession(profile).connect(password="x")
    assert isinstance(seen["sock"], FakeProxy)


# -- live: the lab's sshd -------------------------------------------------------

_LAB_SSH = ("10.99.0.10", 22)


def _lab_ssh_up() -> bool:
    try:
        with socket.create_connection(_LAB_SSH, timeout=0.25):
            return True
    except OSError:
        return False


@pytest.mark.skipif(not _lab_ssh_up(), reason="lab ssh-alpha (10.99.0.10:22) not reachable")
def test_live_sftp_session_socket_has_nodelay_and_answers_after_exec():
    from core.ssh_client import SSHSession

    profile = ConnectionProfile(name="nodelay", protocol="sftp", host=_LAB_SSH[0],
                                port=_LAB_SSH[1], username="alpha", auth_type="password")
    session = SSHSession(profile)
    session._known_hosts_path = Path(tempfile.mkdtemp()) / "known_hosts"
    session.connect(password="alpha123", on_unknown_host=lambda _e: True)
    try:
        assert _nodelay(session.transport.sock) != 0
        path = session.join(session.home(), "nodelay-probe.txt")
        with session.open_write(path) as fh:
            fh.write(b"abc")
        try:
            # An exec channel, then an SFTP request: the sequence Nagle held.
            assert session.checksum(path).startswith("sha256:")
            assert session.exists(path)
            with session.open_read(path) as fh:
                assert fh.read() == b"abc"
        finally:
            session.remove(path)
    finally:
        session.disconnect()
