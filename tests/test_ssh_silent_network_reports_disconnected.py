"""SFTP and SCP: once a connection gone silent is found dead, the session
says it is disconnected - so a reconnect opens a new one.

A network that goes silent (Wi-Fi gone, a NAT entry dropped, a VPN down)
sends no FIN and no RST; paramiko's transport stays "active". SFTP found
out - the request's time-out, then a keepalive that got no answer - and
said "the network connection is probably lost. Reconnect and try again",
but ``connected`` stayed True: the connection manager's reconnect
(``_is_connected``) handed out the same dead session again, for as long as
the TCP stack took to give up (some 15 minutes). SCP said "Command
execution failed: Timeout opening channel." and stayed "connected" too.

Now ``connected`` turns False when the keepalive goes unanswered (and
stays so until a packet arrives again). A server that is only slow still
answers the keepalive and keeps its session; a network that comes back
keeps it working for whoever holds it (tests/test_sftp_silent_network.py).

A relay between client and server (tests/ssh_shell_testkit.FreezableRelay)
stops forwarding without closing anything.
"""

from __future__ import annotations

import time

import pytest

from core import scp_client
from core.scp_client import SCPSession
from core.ssh_client import SSHSession
from tests.ssh_shell_testkit import FreezableRelay, SshShellServer, connect, profile


@pytest.fixture(params=["sftp", "scp"])
def relayed(request, tmp_path, monkeypatch):
    root = tmp_path / "srv"
    root.mkdir()
    srv = SshShellServer(str(root))
    relay = FreezableRelay(srv.port)
    p = profile(srv, request.param, sftp_timeout=1)
    p.port = relay.port
    cls = SSHSession if request.param == "sftp" else SCPSession
    s = connect(cls(p), known_hosts=tmp_path / "known_hosts")
    monkeypatch.setattr(scp_client, "CMD_TIMEOUT", 1.0)
    monkeypatch.setattr(scp_client, "PROBE_TIMEOUT", 1.0)
    folder = "/" if request.param == "sftp" else str(root)
    yield s, relay, folder
    s.disconnect()
    relay.close()
    srv.close()


def test_happy_a_live_connection_stays_connected(relayed):
    s, _, folder = relayed
    s.list_dir(folder)
    assert s.connected


def test_sad_a_silent_network_ends_the_session(relayed):
    s, relay, folder = relayed
    relay.freeze()
    with pytest.raises(OSError):
        s.list_dir(folder)
    deadline = time.monotonic() + 5
    while s.connected and time.monotonic() < deadline:
        time.sleep(0.05)
    assert not s.connected


def test_edge_the_connection_manager_does_not_reuse_it(relayed):
    from core.connection_manager import ConnectionManager

    s, relay, folder = relayed
    assert ConnectionManager._is_connected(s)
    relay.freeze()
    with pytest.raises(OSError):
        s.list_dir(folder)
    assert not ConnectionManager._is_connected(s)
