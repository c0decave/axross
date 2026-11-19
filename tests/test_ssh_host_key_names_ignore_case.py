"""SFTP and SCP look up and store host keys under the host name in lower
case, as OpenSSH does.

ssh lower-cases the host name before it reads or writes known_hosts, so
``ssh Server.Example`` stores ``server.example``. axross looked the name
up as typed: a host already in known_hosts, typed with a capital letter
in the profile, was "a new host key that axross has not seen yet" - and
the user was asked to trust it again, the habit host key checks must not
teach. Entries axross wrote as typed are still found.

The server listens on ::1 for the name "LocalHost" (/etc/hosts: localhost).
"""

from __future__ import annotations

import socket

import pytest

from core.scp_client import SCPSession
from core.ssh_client import SSHSession, UnknownHostKeyError
from tests.sftp_testkit import _host_key
from tests.ssh_shell_testkit import PASSWORD, SshShellServer, profile

PROTOCOLS = {"sftp": SSHSession, "scp": SCPSession}


def _ipv6_localhost() -> bool:
    try:
        if not any(a[0] == socket.AF_INET6 for a in socket.getaddrinfo("localhost", 22)):
            return False
        socket.create_server(("::1", 0), family=socket.AF_INET6).close()
        return True
    except OSError:
        return False


pytestmark = pytest.mark.skipif(not _ipv6_localhost(), reason="localhost has no ::1")


@pytest.fixture
def server(tmp_path):
    srv = SshShellServer(str(tmp_path), bind="::1")
    yield srv
    srv.close()


def _session(proto, srv, known_hosts):
    p = profile(srv, proto, address_family="ipv6")
    p.host = "LocalHost"
    s = PROTOCOLS[proto](p)
    s._known_hosts_path = known_hosts
    return s


def _connect(proto, srv, known_hosts):
    s = _session(proto, srv, known_hosts)
    asked = []
    s.connect(password=PASSWORD, on_unknown_host=lambda e: asked.append(e) or False)
    return s, asked


@pytest.mark.parametrize("proto", PROTOCOLS)
def test_happy_a_lower_case_entry_matches_a_mixed_case_profile(proto, server, tmp_path):
    kh = tmp_path / "known_hosts"
    kh.write_text(f"[localhost]:{server.port} ssh-rsa {_host_key().get_base64()}\n")
    s, asked = _connect(proto, server, kh)
    try:
        assert s.connected and not asked
    finally:
        s.disconnect()


@pytest.mark.parametrize("proto", PROTOCOLS)
def test_sad_a_new_key_is_stored_in_lower_case(proto, server, tmp_path):
    kh = tmp_path / "known_hosts"
    s = _session(proto, server, kh)
    s.connect(password=PASSWORD, on_unknown_host=lambda e: True)
    s.disconnect()
    assert kh.read_text().startswith(f"[localhost]:{server.port} ")


@pytest.mark.parametrize("proto", PROTOCOLS)
def test_edge_an_entry_stored_as_typed_still_matches(proto, server, tmp_path):
    kh = tmp_path / "known_hosts"
    kh.write_text(f"[LocalHost]:{server.port} ssh-rsa {_host_key().get_base64()}\n")
    s, asked = _connect(proto, server, kh)
    try:
        assert s.connected and not asked
    finally:
        s.disconnect()
    with pytest.raises(UnknownHostKeyError):
        _connect(proto, server, tmp_path / "empty_known_hosts")
