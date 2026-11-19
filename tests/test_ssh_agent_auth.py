"""SFTP and SCP with "SSH agent" authentication.

* happy: the key the running ssh-agent holds logs in (a real ssh-agent
  and ssh-add, a loopback paramiko server that accepts that key);
* sad: without an agent (SSH_AUTH_SOCK unset or pointing nowhere) the
  message said "The server refused the login. Check the user name and
  the password or key" (SFTP: an AuthenticationException "No keys
  available from SSH agent") or "No authentication methods available"
  (SCP) - the server was never asked. Now both say that no agent
  answered and what to do;
* edge: an agent whose keys the server refuses still reads as a refused
  login.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess

import paramiko
import pytest

from core.scp_client import SCPSession
from core.ssh_client import SSHSession
from core.user_errors import describe
from tests.ssh_shell_testkit import SshShellServer, connect, profile

PROTOCOLS = {"sftp": SSHSession, "scp": SCPSession}


@pytest.fixture
def agent(tmp_path, monkeypatch):
    """A running ssh-agent holding one new ed25519 key; the key's public half."""
    if not all(shutil.which(t) for t in ("ssh-agent", "ssh-add", "ssh-keygen")):
        pytest.skip("needs ssh-agent, ssh-add and ssh-keygen")
    key_file = tmp_path / "id_ed25519"
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key_file)], check=True
    )
    sock = tmp_path / "agent.sock"
    out = subprocess.run(
        ["ssh-agent", "-s", "-a", str(sock)], check=True, capture_output=True, text=True
    ).stdout
    pid = int(re.search(r"SSH_AGENT_PID=(\d+)", out).group(1))
    monkeypatch.setenv("SSH_AUTH_SOCK", str(sock))
    try:
        subprocess.run(["ssh-add", "-q", str(key_file)], check=True, capture_output=True)
        yield paramiko.Ed25519Key.from_private_key_file(str(key_file))
    finally:
        os.kill(pid, 15)


@pytest.fixture
def server(tmp_path):
    root = tmp_path / "srv"
    root.mkdir()
    servers = []

    def start(keys):
        srv = SshShellServer(str(root), auths=("publickey",), authorized_keys=keys)
        servers.append(srv)
        return srv

    yield start
    for srv in servers:
        srv.close()


@pytest.mark.parametrize("proto", PROTOCOLS)
def test_happy_the_agent_key_logs_in(proto, agent, server, tmp_path):
    srv = server((agent,))
    s = PROTOCOLS[proto](profile(srv, proto, auth_type="agent"))
    connect(s, password="", known_hosts=tmp_path / "known_hosts")
    try:
        assert s.connected
    finally:
        s.disconnect()


@pytest.mark.parametrize("proto", PROTOCOLS)
@pytest.mark.parametrize("sock", ["unset", "nowhere"])
def test_sad_no_agent_says_so(proto, sock, server, tmp_path, monkeypatch):
    if sock == "unset":
        monkeypatch.delenv("SSH_AUTH_SOCK", raising=False)
    else:
        monkeypatch.setenv("SSH_AUTH_SOCK", str(tmp_path / "no-such.sock"))
    srv = server(())
    s = PROTOCOLS[proto](profile(srv, proto, auth_type="agent"))
    with pytest.raises(Exception) as info:
        connect(s, password="", known_hosts=tmp_path / "known_hosts")
    text = describe(info.value)
    assert "ssh-add" in text, text
    assert "refused the login" not in text
    assert not s.connected


@pytest.mark.parametrize("proto", PROTOCOLS)
def test_edge_agent_keys_the_server_refuses(proto, agent, server, tmp_path):
    srv = server((paramiko.Ed25519Key.generate() if hasattr(paramiko.Ed25519Key, "generate")
                  else paramiko.RSAKey.generate(1024),))
    s = PROTOCOLS[proto](profile(srv, proto, auth_type="agent"))
    with pytest.raises(Exception) as info:
        connect(s, password="", known_hosts=tmp_path / "known_hosts")
    assert "refused the login" in describe(info.value)
