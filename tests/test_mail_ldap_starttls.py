"""IMAP, POP3 and LDAP on their plain ports: STARTTLS before the login.

Before: a profile on 143, 110 or 389 sent the user name and password in
clear text - there was only implicit TLS or nothing. Now a profile has a TLS
mode: implicit TLS, STARTTLS (the default without implicit TLS) or plain
(only when the user chose it). STARTTLS checks the certificate like the
other TLS backends, and a server that does not offer it - or a man in the
middle that took it out of the capabilities or answers NO - gets no
password: the connect is refused.

Fake local servers (tests/starttls_servers.py) record every command and
whether it came over TLS.
"""

from __future__ import annotations

import ssl
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from fake_ircd import self_signed  # noqa: E402
from starttls_servers import (  # noqa: E402
    StartTlsImapServer,
    StartTlsLdapServer,
    StartTlsPop3Server,
    server_context,
)

from core import conn_security as CS  # noqa: E402
from core import imap_client as IC  # noqa: E402
from core import pop3_client as PC  # noqa: E402
from core import tls_context  # noqa: E402
from core.profiles import ConnectionProfile  # noqa: E402


@pytest.fixture
def cert(tmp_path):
    cert_path, key_path, _der = self_signed(tmp_path, "localhost")
    return cert_path, key_path


@pytest.fixture
def trusted(cert, monkeypatch):
    """The test certificate is trusted - with the hostname checked - as a
    CA-signed one would be; an untrusted one is the default context."""
    real = tls_context.client_tls_context

    def ctx(verify=True, *, label="TLS"):
        c = real(verify, label=label)
        if verify:
            c.load_verify_locations(cert[0])
        return c

    monkeypatch.setattr(tls_context, "client_tls_context", ctx)
    return cert


@pytest.fixture(autouse=True)
def _short_timeout(monkeypatch):
    monkeypatch.setattr(IC, "IMAP_TIMEOUT", 5.0)


def _no_login_in_clear(srv, *words):
    for word in words:
        assert not [c for c in srv.got(word) if not c[1]], srv.commands


# --- IMAP ---------------------------------------------------------------------------------------

def test_happy_imap_starttls_logs_in_over_tls(trusted):
    with StartTlsImapServer(server_context(*trusted)) as srv:
        s = IC.ImapSession("localhost", srv.port, "u", "secret", tls_mode="starttls")
        logins = srv.got("LOGIN")
        info = s.security_info()
        s.disconnect()
    assert logins and all(over_tls for _l, over_tls in logins)
    assert info.level == CS.LEVEL_TLS and info.negotiated
    assert "STARTTLS" in info.summary


@pytest.mark.parametrize("server", [
    {"offer": False},                 # the server (or a MITM) leaves STARTTLS out
    {"offer": True, "accept": False},  # offered, then answered NO
    {"preauth": True},                # PREAUTH on a plain connection
], ids=["not-offered-downgrade", "refused", "preauth"])
def test_sad_imap_without_starttls_sends_no_password(trusted, server):
    with StartTlsImapServer(server_context(*trusted), **server) as srv:
        with pytest.raises(ConnectionError, match="not sent in clear text"):
            IC.ImapSession("localhost", srv.port, "u", "secret", tls_mode="starttls")
        assert not srv.got("LOGIN") and not srv.got("AUTHENTICATE"), srv.commands


def test_sad_the_refusal_is_shown_as_it_is_not_as_a_refused_connection(trusted):
    """With ECONNREFUSED the message became "The server refused the
    connection. Check the host name and the port" - not why."""
    from core.user_errors import describe

    with StartTlsImapServer(server_context(*trusted), offer=False) as srv:
        with pytest.raises(ConnectionError) as info:
            IC.ImapSession("localhost", srv.port, "u", "secret", tls_mode="starttls")
    assert "STARTTLS" in describe(info.value)
    with StartTlsLdapServer(server_context(*trusted), accept=False) as srv:
        with pytest.raises(ConnectionError) as info:
            _ldap(srv.port, "starttls")
    assert "StartTLS" in describe(info.value)
    with StartTlsPop3Server(server_context(*trusted), offer=False) as srv:
        with pytest.raises(ConnectionError) as info:
            PC.Pop3Session("localhost", srv.port, "u", "secret", tls_mode="starttls")
    assert "STLS" in describe(info.value)


def test_sad_imap_starttls_checks_the_certificate(cert):
    """Not trusted (self-signed): refused like IMAPS would be, no LOGIN."""
    with StartTlsImapServer(server_context(*cert)) as srv:
        with pytest.raises(ConnectionError, match="TLS handshake failed"):
            IC.ImapSession("localhost", srv.port, "u", "secret", tls_mode="starttls")
        assert not srv.got("LOGIN")


def test_edge_imap_plain_is_the_explicit_choice(trusted):
    with StartTlsImapServer(server_context(*trusted), offer=False) as srv:
        s = IC.ImapSession("localhost", srv.port, "u", "secret", tls_mode="plain")
        info = s.security_info()
        s.disconnect()
        assert srv.got("LOGIN")
    assert info.level == CS.LEVEL_CLEARTEXT


def test_edge_imap_reconnect_upgrades_again(trusted):
    with StartTlsImapServer(server_context(*trusted)) as srv:
        s = IC.ImapSession("localhost", srv.port, "u", "secret", tls_mode="starttls")
        s._imap.shutdown()
        s._imap = None
        s._ensure_connected()
        s.disconnect()
        logins = srv.got("LOGIN")
    assert len(logins) == 2 and all(t for _l, t in logins)


# --- POP3 ---------------------------------------------------------------------------------------

def test_happy_pop3_stls_logs_in_over_tls(trusted):
    with StartTlsPop3Server(server_context(*trusted)) as srv:
        s = PC.Pop3Session("localhost", srv.port, "u", "secret", tls_mode="starttls")
        info = s.security_info()
        s.disconnect()
        passes = srv.got("PASS")
    assert passes and all(t for _l, t in passes)
    assert info.level == CS.LEVEL_TLS and "STLS" in info.summary


@pytest.mark.parametrize("server", [{"offer": False}, {"offer": True, "accept": False}],
                         ids=["not-offered-downgrade", "refused"])
def test_sad_pop3_without_stls_sends_no_password(trusted, server):
    with StartTlsPop3Server(server_context(*trusted), **server) as srv:
        with pytest.raises(ConnectionError, match="not sent in clear text"):
            PC.Pop3Session("localhost", srv.port, "u", "secret", tls_mode="starttls")
        assert not srv.got("USER") and not srv.got("PASS"), srv.commands


def test_sad_an_endless_capa_answer_is_cut_off_before_any_password(trusted, monkeypatch):
    """poplib's capa() (and stls(), which asks CAPA again) reads its answer
    without a limit: a server that never ends it grew memory for ever."""
    import socket as _socket

    from fuzz_testkit import ScriptedServer, recv_line

    got: list = []

    def endless(conn: _socket.socket) -> None:
        conn.sendall(b"+OK ready\r\n")
        while True:
            line = recv_line(conn)
            if not line:
                return
            got.append(line)
            if line.upper().startswith(b"CAPA"):
                conn.sendall(b"+OK\r\n")
                try:
                    for _ in range(100000):
                        conn.sendall(b"X-FILLER " + b"x" * 1000 + b"\r\n")
                except OSError:
                    return

    monkeypatch.setattr(PC, "MAX_CAPA_BYTES", 32 * 1024)
    srv = ScriptedServer(endless)
    try:
        with pytest.raises(OSError, match="exceeds"):
            PC.Pop3Session("localhost", srv.port, "u", "secret", tls_mode="starttls")
    finally:
        srv.close()
    assert not [g for g in got if g.upper().startswith((b"USER", b"PASS"))]


def test_sad_pop3_stls_checks_the_certificate(cert):
    with StartTlsPop3Server(server_context(*cert)) as srv:
        with pytest.raises(ConnectionError, match="TLS handshake failed"):
            PC.Pop3Session("localhost", srv.port, "u", "secret", tls_mode="starttls")
        assert not srv.got("PASS")


# --- LDAP ---------------------------------------------------------------------------------------

ldap3 = pytest.importorskip("ldap3")


def _ldap(port, mode):
    from core.ldap_fs_client import LdapFsSession

    return LdapFsSession("localhost", port, "cn=admin,dc=example", "secret", tls_mode=mode, timeout=5)


def test_happy_ldap_starttls_binds_over_tls(trusted, monkeypatch):
    # ldap3 builds its own context: trust the test certificate there.
    real = ssl.create_default_context

    def ctx(*a, **kw):
        c = real(*a, **kw)
        c.load_verify_locations(trusted[0])
        return c

    monkeypatch.setattr("ldap3.core.tls.create_default_context", ctx)
    with StartTlsLdapServer(server_context(*trusted)) as srv:
        s = _ldap(srv.port, "starttls")
        info = s.security_info()
        s.close()
        binds = srv.got("BIND")
    assert binds and all(t for _l, t in binds), srv.commands
    assert info.level == CS.LEVEL_TLS and "StartTLS" in info.summary


def test_sad_ldap_starttls_refused_sends_no_bind(trusted):
    with StartTlsLdapServer(server_context(*trusted), accept=False) as srv:
        with pytest.raises(ConnectionError, match="not sent in clear text"):
            _ldap(srv.port, "starttls")
        assert not srv.got("BIND"), srv.commands


def test_sad_ldap_starttls_checks_the_certificate(cert):
    with StartTlsLdapServer(server_context(*cert)) as srv:
        with pytest.raises(OSError):
            _ldap(srv.port, "starttls")
        assert not srv.got("BIND"), srv.commands


# --- profiles, connection manager, open_url, summary ----------------------------------------------

@pytest.mark.parametrize("proto", ["imap", "pop3", "ldap"])
def test_happy_a_profile_on_the_plain_port_defaults_to_starttls(proto):
    """Also one saved before STARTTLS existed (no *_starttls key)."""
    old = ConnectionProfile.from_dict({"name": "p", "protocol": proto, "host": "h",
                                       f"{proto}_ssl": False})
    assert old.tls_mode() == "starttls"
    info = CS.from_profile(old)
    assert info.level == CS.LEVEL_TLS and "TLS" in info.summary
    plain = ConnectionProfile.from_dict(old.to_dict() | {f"{proto}_starttls": False})
    assert plain.tls_mode() == "plain"
    assert CS.from_profile(plain).level == CS.LEVEL_CLEARTEXT
    again = ConnectionProfile.from_dict(plain.to_dict())
    assert again.tls_mode() == "plain"


@pytest.mark.parametrize("proto", ["imap", "pop3", "ldap"])
def test_happy_the_connection_manager_passes_the_mode(proto, monkeypatch):
    from core import connection_manager as CM

    seen = {}

    class Fake:
        def __init__(self, **kw):
            seen.update(kw)

    monkeypatch.setattr(CM, "load_backend_class", lambda _p: Fake)
    profile = ConnectionProfile(name="p", protocol=proto, host="h", port=1)
    setattr(profile, f"{proto}_ssl", False)
    CM.ConnectionManager()._create_session(profile, "pw", "", None)
    assert seen["tls_mode"] == "starttls"


@pytest.mark.parametrize("url, mode", [
    ("imap://u@h/", "starttls"), ("imap+starttls://u@h/", "starttls"),
    ("imap+plain://u@h/", "plain"), ("imaps://u@h/", "tls"),
    ("pop3://u@h/", "starttls"), ("pop3+plain://u@h/", "plain"), ("pop3s://u@h/", "tls"),
])
def test_happy_open_url_schemes_name_the_mode(url, mode, monkeypatch):
    from core import scripting
    from core.connection_manager import ConnectionManager

    seen = {}

    def connect(self, profile, **_kw):
        seen["mode"] = profile.tls_mode()
        raise ConnectionAbortedError("stop here")

    monkeypatch.setattr(ConnectionManager, "connect", connect)
    with pytest.raises(ConnectionAbortedError):
        scripting.open_url(url, password="x", proxy_type="none")
    assert seen["mode"] == mode


@pytest.mark.parametrize("url, mode, port", [
    ("ldap://h/", "starttls", 389), ("ldap+plain://h/", "plain", 389), ("ldaps://h/", "tls", 636),
])
def test_happy_open_url_ldap_schemes_name_the_mode(url, mode, port, monkeypatch):
    from core import ldap_fs_client, scripting

    seen = {}

    class Fake:
        def __init__(self, **kw):
            seen.update(kw)
            raise ConnectionAbortedError("stop here")

    monkeypatch.setattr(ldap_fs_client, "LdapFsSession", Fake)
    with pytest.raises(ConnectionAbortedError):
        scripting.open_url(url, proxy_type="none")
    assert seen["tls_mode"] == mode and seen["port"] == port
