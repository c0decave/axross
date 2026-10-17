"""known_hosts is read line by line and only ever appended to.

Two faults on a real-world ~/.ssh/known_hosts:

* A line with an OpenSSH marker (``@cert-authority`` / ``@revoked``)
  made paramiko's HostKeys.load raise InvalidHostKey, which neither
  SSHSession._load_host_keys nor SCPSession.connect caught: every
  connect failed. The markers are now understood: a ``@revoked`` key
  is refused for every host, ``@cert-authority`` lines are skipped
  (paramiko cannot check host certificates), a broken line is skipped.
* Trusting a new host rewrote the file through HostKeys.save(), which
  drops comments, marker lines, key types paramiko does not know
  (``sk-ssh-ed25519@openssh.com``) and resets the mode. Now exactly one
  line is appended, hashed when the file already hashes its host names.

Every test uses a temporary known_hosts file, never ~/.ssh.
"""

from __future__ import annotations

import os
import stat

import paramiko
import pytest

from core.profiles import ConnectionProfile
from core.scp_client import SCPSession
from core.ssh_client import HostKeyMismatchError, SSHSession, UnknownHostKeyError
from core.telnet_client import SHELL_ENV
from tests.sftp_testkit import SftpServer, _host_key

_OTHER = paramiko.ECDSAKey.generate()
_SK_LINE = (
    "sk.example sk-ssh-ed25519@openssh.com "
    "AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIDaS0XTuP+xY6GqYaDj0LcbQqsW5ZqvU9ohvRZsKz3Sg"
    "AAAABHNzaDo=\n"
)


@pytest.fixture
def server(tmp_path):
    (tmp_path / "srv").mkdir()
    srv = SftpServer(str(tmp_path / "srv"))
    try:
        yield srv
    finally:
        srv.close()


def _alias(srv) -> str:
    return f"[127.0.0.1]:{srv.port}"


def _line(host: str, key: paramiko.PKey) -> str:
    return f"{host} {key.get_name()} {key.get_base64()}\n"


def _profile(srv, protocol: str) -> ConnectionProfile:
    return ConnectionProfile(
        name="t", protocol=protocol, host="127.0.0.1", port=srv.port, username="u"
    )


def _sftp(srv, known_hosts, trust: bool):
    sess = SSHSession(_profile(srv, "sftp"))
    sess._known_hosts_path = known_hosts
    sess.connect(password="pw", on_unknown_host=lambda err: trust)
    sess.disconnect()


def _posix_shell(cmd, timeout=None, stdin_data=None):
    """Stand-in for the remote shell: the testkit server has no exec."""
    if cmd.startswith(SHELL_ENV + " "):
        cmd = cmd[len(SHELL_ENV) + 1 :]
    word = cmd.split()[0]
    if word == "echo":
        return "/home/u\n" if "$HOME" in cmd else cmd.split(" ", 1)[1], 0
    if word == "uname":
        return "Linux", 0
    return "", 0


def _scp(srv, known_hosts, trust: bool, monkeypatch):
    monkeypatch.setattr(SCPSession, "_exec_raw", lambda self, *a, **k: _posix_shell(*a, **k))
    sess = SCPSession(_profile(srv, "scp"))
    sess._known_hosts_path = known_hosts
    try:
        sess.connect(password="pw", on_unknown_host=lambda err: trust)
    finally:
        sess.disconnect()


def _connect(kind, srv, known_hosts, trust, monkeypatch):
    if kind == "sftp":
        _sftp(srv, known_hosts, trust)
    else:
        _scp(srv, known_hosts, trust, monkeypatch)


KINDS = ["sftp", "scp"]


# -- happy -------------------------------------------------------------------


@pytest.mark.parametrize("kind", KINDS)
def test_happy_trust_appends_one_line_and_keeps_the_rest(kind, server, tmp_path, monkeypatch):
    kh = tmp_path / "known_hosts"
    original = (
        "# managed by IT - do not remove\n"
        + _line("plain.example", _OTHER)
        + _SK_LINE
        + f"@cert-authority *.corp.example {_line('', _OTHER).strip()}\n"
    )
    kh.write_text(original)
    os.chmod(kh, 0o644)
    _connect(kind, server, kh, True, monkeypatch)
    after = kh.read_text()
    assert after.startswith(original)
    added = after[len(original) :]
    assert added == _line(_alias(server), _host_key())
    assert stat.S_IMODE(kh.stat().st_mode) == 0o644
    # The appended line is what the next connect verifies against.
    _connect(kind, server, kh, False, monkeypatch)
    assert kh.read_text() == after


@pytest.mark.parametrize("kind", KINDS)
def test_happy_cert_authority_line_does_not_break_a_known_host(
    kind, server, tmp_path, monkeypatch
):
    kh = tmp_path / "known_hosts"
    kh.write_text(
        f"@cert-authority *.corp.example {_line('', _OTHER).strip()}\n"
        + _line(_alias(server), _host_key())
    )
    _connect(kind, server, kh, False, monkeypatch)


# -- sad ---------------------------------------------------------------------


@pytest.mark.parametrize("kind", KINDS)
def test_sad_a_revoked_key_is_refused_even_when_trusted(kind, server, tmp_path, monkeypatch):
    kh = tmp_path / "known_hosts"
    content = f"@revoked * {_line('', _host_key()).strip()}\n" + _line(_alias(server), _host_key())
    kh.write_text(content)
    asked = []

    def trust(err):
        asked.append(err)
        return True

    with pytest.raises((HostKeyMismatchError, paramiko.BadHostKeyException)):
        if kind == "sftp":
            sess = SSHSession(_profile(server, "sftp"))
            sess._known_hosts_path = kh
            sess.connect(password="pw", on_unknown_host=trust)
        else:
            monkeypatch.setattr(
                SCPSession, "_exec_raw", lambda self, *a, **k: _posix_shell(*a, **k)
            )
            sess = SCPSession(_profile(server, "scp"))
            sess._known_hosts_path = kh
            sess.connect(password="pw", on_unknown_host=trust)
    assert asked == []
    assert kh.read_text() == content


@pytest.mark.parametrize("kind", KINDS)
def test_sad_a_revoked_unknown_key_is_not_offered_for_trust(kind, server, tmp_path, monkeypatch):
    kh = tmp_path / "known_hosts"
    content = f"@revoked bad.example {_line('', _host_key()).strip()}\n"
    kh.write_text(content)
    with pytest.raises(HostKeyMismatchError):
        _connect(kind, server, kh, True, monkeypatch)
    assert kh.read_text() == content


@pytest.mark.parametrize("kind", KINDS)
def test_sad_unknown_host_refused_leaves_the_file_alone(kind, server, tmp_path, monkeypatch):
    kh = tmp_path / "known_hosts"
    kh.write_text("# only a comment\n")
    with pytest.raises(UnknownHostKeyError):
        _connect(kind, server, kh, False, monkeypatch)
    assert kh.read_text() == "# only a comment\n"


# -- edge --------------------------------------------------------------------


@pytest.mark.parametrize("kind", KINDS)
def test_edge_hashed_file_gets_a_hashed_line(kind, server, tmp_path, monkeypatch):
    kh = tmp_path / "known_hosts"
    original = _line(paramiko.HostKeys.hash_host("plain.example"), _OTHER)
    kh.write_text(original)
    _connect(kind, server, kh, True, monkeypatch)
    added = kh.read_text()[len(original) :]
    host = added.split()[0]
    assert host.startswith("|1|")
    assert host == paramiko.HostKeys.hash_host(_alias(server), host)
    _connect(kind, server, kh, False, monkeypatch)


@pytest.mark.parametrize("kind", KINDS)
def test_edge_no_trailing_newline_and_no_file(kind, server, tmp_path, monkeypatch):
    kh = tmp_path / "known_hosts"
    kh.write_text("# no newline at the end")
    _connect(kind, server, kh, True, monkeypatch)
    assert kh.read_text() == "# no newline at the end\n" + _line(_alias(server), _host_key())

    fresh = tmp_path / "sub" / "known_hosts"
    _connect(kind, server, fresh, True, monkeypatch)
    assert fresh.read_text() == _line(_alias(server), _host_key())
    assert stat.S_IMODE(fresh.stat().st_mode) & 0o077 == 0


@pytest.mark.parametrize("kind", KINDS)
def test_edge_broken_lines_are_skipped(kind, server, tmp_path, monkeypatch):
    kh = tmp_path / "known_hosts"
    kh.write_text(
        "garbage\n"
        "host ssh-ed25519 !!!notbase64!!!\n"
        "@revoked\n"
        "@unknown-marker x ssh-ed25519 AAAA\n" + _line(_alias(server), _host_key())
    )
    _connect(kind, server, kh, False, monkeypatch)

