"""An SFTP connect verifies the host key type known_hosts already holds.

A server usually has several host keys (RSA, ECDSA, Ed25519). paramiko's
default preference picks ECDSA/Ed25519 first, so with only the server's
(correct) RSA key in known_hosts the negotiated key was ECDSA and the
connect failed with a false "host key mismatch". OpenSSH and paramiko's
own SSHClient (the SCP path) offer the known key types first; SSHSession
now does the same. A key that really differs is still a mismatch.
"""

from __future__ import annotations

import paramiko
import pytest

from core.profiles import ConnectionProfile
from core.ssh_client import HostKeyMismatchError, SSHSession, UnknownHostKeyError
from tests.sftp_testkit import SftpServer, _host_key

_ECDSA = paramiko.ECDSAKey.generate()


@pytest.fixture
def server(tmp_path):
    (tmp_path / "srv").mkdir()
    srv = SftpServer(str(tmp_path / "srv"), extra_host_keys=(_ECDSA,))
    try:
        yield srv
    finally:
        srv.close()


def _alias(srv) -> str:
    return f"[127.0.0.1]:{srv.port}"


def _known_hosts(tmp_path, entries) -> object:
    path = tmp_path / "known_hosts"
    hk = paramiko.HostKeys()
    for host, key in entries:
        hk.add(host, key.get_name(), key)
    hk.save(str(path))
    return path


def _session(srv, known_hosts_path) -> SSHSession:
    prof = ConnectionProfile(
        name="t", protocol="sftp", host="127.0.0.1", port=srv.port, username="u"
    )
    sess = SSHSession(prof)
    sess._known_hosts_path = known_hosts_path
    return sess


def _connect(sess, *, trust=False):
    sess.connect(password="pw", on_unknown_host=lambda err: trust)
    return sess._transport.get_remote_server_key()


# -- happy -------------------------------------------------------------------


def test_happy_a_known_rsa_key_is_verified_although_ecdsa_is_preferred(server, tmp_path):
    sess = _session(server, _known_hosts(tmp_path, [(_alias(server), _host_key())]))
    try:
        assert _connect(sess) == _host_key()
    finally:
        sess.disconnect()


def test_happy_a_known_ecdsa_key_is_verified(server, tmp_path):
    sess = _session(server, _known_hosts(tmp_path, [(_alias(server), _ECDSA)]))
    try:
        assert _connect(sess) == _ECDSA
    finally:
        sess.disconnect()


# -- sad ---------------------------------------------------------------------


def test_sad_a_different_rsa_key_is_still_a_mismatch(server, tmp_path):
    other = paramiko.RSAKey.generate(1024)
    sess = _session(server, _known_hosts(tmp_path, [(_alias(server), other)]))
    with pytest.raises(HostKeyMismatchError):
        _connect(sess)


def test_sad_a_known_type_the_server_lacks_is_still_a_mismatch(server, tmp_path):
    # ecdsa-sha2-nistp384: a key type the server does not offer.
    other = paramiko.ECDSAKey.generate(bits=384)
    sess = _session(server, _known_hosts(tmp_path, [(_alias(server), other)]))
    with pytest.raises(HostKeyMismatchError):
        _connect(sess)


# -- edge --------------------------------------------------------------------


def test_edge_an_unknown_host_keeps_the_default_preference(server, tmp_path):
    path = _known_hosts(tmp_path, [("[127.0.0.1]:1", _host_key())])
    sess = _session(server, path)
    with pytest.raises(UnknownHostKeyError) as err:
        _connect(sess)
    assert err.value.key_type == _ECDSA.get_name()


def test_edge_a_hashed_known_hosts_entry_is_honoured(server, tmp_path):
    hashed = paramiko.HostKeys.hash_host(_alias(server))
    sess = _session(server, _known_hosts(tmp_path, [(hashed, _host_key())]))
    try:
        assert _connect(sess) == _host_key()
    finally:
        sess.disconnect()


def test_edge_without_a_known_hosts_file_the_host_is_unknown(server, tmp_path):
    sess = _session(server, tmp_path / "missing_known_hosts")
    with pytest.raises(UnknownHostKeyError):
        _connect(sess)
