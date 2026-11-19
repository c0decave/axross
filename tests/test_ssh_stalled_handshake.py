"""SFTP and SCP: a server that stalls the SSH handshake fails the connect
in time.

The server sends its banner and then nothing (a tarpit, a stuck sshd, a
middlebox that drops the key exchange). SFTP gave up after 10 s; SCP's
paramiko SSHClient.connect waited for the key exchange without a limit
- Connect and Test Connection hung for ever. Both now give up after
``core.ssh_client.SSH_HANDSHAKE_TIMEOUT`` with the "did not finish the
SSH handshake in time" message.
"""

from __future__ import annotations

import socket
import threading
import time

import pytest

from core import ssh_client
from core.profiles import ConnectionProfile
from core.scp_client import SCPSession
from core.ssh_client import SSHSession
from core.user_errors import describe


@pytest.fixture
def stalled():
    srv = socket.create_server(("127.0.0.1", 0))
    conns = []

    def serve():
        while True:
            try:
                c, _ = srv.accept()
            except OSError:
                return
            conns.append(c)
            c.sendall(b"SSH-2.0-OpenSSH_9.6\r\n")  # and then nothing

    threading.Thread(target=serve, daemon=True).start()
    yield srv.getsockname()[1]
    srv.close()
    for c in conns:
        c.close()


@pytest.mark.parametrize("cls,proto", [(SSHSession, "sftp"), (SCPSession, "scp")])
def test_sad_a_stalled_key_exchange_fails_the_connect(cls, proto, stalled, monkeypatch, tmp_path):
    monkeypatch.setattr(ssh_client, "SSH_HANDSHAKE_TIMEOUT", 1.0, raising=False)
    s = cls(ConnectionProfile(name="t", protocol=proto, host="127.0.0.1", port=stalled,
                              username="u"))
    s._known_hosts_path = tmp_path / "known_hosts"
    box: dict = {}

    def run():
        start = time.monotonic()
        try:
            s.connect(password="pw", on_unknown_host=lambda e: True)
        except Exception as exc:  # noqa: BLE001 - checked below
            box["exc"] = exc
        box["took"] = time.monotonic() - start

    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(8)
    assert not t.is_alive(), "the connect hung"
    assert box["took"] < 6
    assert "handshake" in describe(box["exc"], "h"), describe(box["exc"], "h")
    assert not s.connected
