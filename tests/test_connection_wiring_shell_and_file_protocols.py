"""Connection wiring of the SSH / FTP / shell-family protocols.

Found in the connection-type review of 2026-11-18:

* rsh and WMI were offered in the protocol list but had no branch in
  ``ConnectionManager._create_session``: every Connect and Test Connection
  ended in "Unsupported protocol: rsh" / "... wmi".
* A profile imported without a port (profiles.json, an export, the MCP
  server) got port 22 whatever its protocol: an FTP, Telnet, rsync, TFTP,
  WinRM or rsh profile connected to the SSH port.
"""

from __future__ import annotations

from unittest import mock

import pytest

from core import connection_manager as CM
from core.backend_registry import init_registry
from core.profiles import ConnectionProfile

init_registry()


class _Recorder:
    """Stands in for a backend class: records how it was built."""

    calls: list[dict] = []

    def __init__(self, *args, **kwargs) -> None:
        type(self).calls.append({"args": args, **kwargs})

    connected = True


@pytest.fixture
def recorder(monkeypatch):
    _Recorder.calls = []
    monkeypatch.setattr(CM, "load_backend_class", lambda proto: _Recorder)
    return _Recorder


def _build(profile: ConnectionProfile, password: str = "pw"):
    with mock.patch("core.security_mode.require_protocol_allowed"):
        return CM.ConnectionManager()._create_session(profile, password, "", None)


def test_rsh_profile_reaches_the_rsh_backend(recorder):
    _build(ConnectionProfile(name="r", protocol="rsh", host="h", port=514, username="bob"))
    (call,) = recorder.calls
    assert call["host"] == "h"
    assert call["port"] == 514
    assert call["username"] == "bob"


def test_wmi_profile_reaches_the_wmi_backend_with_its_password(recorder):
    _build(ConnectionProfile(name="w", protocol="wmi", host="win", port=135, username="alice"),
           password="s3cret")
    (call,) = recorder.calls
    assert call["host"] == "win"
    assert call["username"] == "alice"
    assert call["password"] == "s3cret"
    assert call.get("domain", "") == ""


@pytest.mark.parametrize(
    "typed, user, domain",
    [("CORP\\alice", "alice", "CORP"), ("alice@corp.example", "alice", "corp.example")],
)
def test_wmi_domain_user_is_split_for_ntlm(recorder, typed, user, domain):
    _build(ConnectionProfile(name="w", protocol="wmi", host="win", port=135, username=typed))
    (call,) = recorder.calls
    assert (call["username"], call["domain"]) == (user, domain)


def test_wmi_needs_a_password_field():
    from core.profiles import SIMPLE_PASSWORD_PROTOCOLS, password_needed

    assert "wmi" in SIMPLE_PASSWORD_PROTOCOLS
    assert password_needed(ConnectionProfile(protocol="wmi", host="h", username="u"))


@pytest.mark.parametrize(
    "proto, port",
    [("ftp", 21), ("ftps", 21), ("telnet", 23), ("rsync", 873), ("tftp", 69),
     ("winrm", 5986), ("rsh", 514), ("wmi", 135), ("sftp", 22), ("scp", 22)],
)
def test_imported_profile_without_port_gets_the_protocols_port(proto, port):
    p = ConnectionProfile.from_dict({"name": "x", "protocol": proto, "host": "h"})
    assert p.port == port


def test_imported_profile_keeps_its_own_port():
    p = ConnectionProfile.from_dict({"name": "x", "protocol": "ftp", "host": "h", "port": 2121})
    assert p.port == 2121


def test_rsync_profile_hands_on_its_ip_version(recorder):
    _build(ConnectionProfile(name="r", protocol="rsync", host="h", port=873,
                             address_family="ipv6"))
    (call,) = recorder.calls
    assert call["address_family"] == "ipv6"


@pytest.mark.parametrize("proto", ["ftp", "ftps"])
def test_ftp_profile_hands_on_its_ip_version(recorder, proto):
    _build(ConnectionProfile(name="f", protocol=proto, host="h", port=21, username="u",
                             address_family="ipv4"))
    (call,) = recorder.calls
    assert call["address_family"] == "ipv4"


@pytest.mark.parametrize("proto", ["telnet", "cisco-telnet"])
def test_telnet_profile_hands_on_its_ip_version(recorder, proto):
    _build(ConnectionProfile(name="t", protocol=proto, host="h", port=23,
                             address_family="ipv6"))
    (call,) = recorder.calls
    assert call["address_family"] == "ipv6"


def test_a_wrong_key_passphrase_is_not_asked_for_again():
    import paramiko

    from core.user_errors import describe

    wrong = describe(paramiko.PasswordRequiredException("Wrong passphrase for the key /k"))
    assert "wrong" in wrong.lower()
    missing = describe(paramiko.PasswordRequiredException("private key file is encrypted"))
    assert "Enter the passphrase" in missing


def test_rsh_profile_hands_on_its_ip_version(recorder):
    _build(ConnectionProfile(name="r", protocol="rsh", host="h", port=514,
                             address_family="ipv4"))
    (call,) = recorder.calls
    assert call["address_family"] == "ipv4"
