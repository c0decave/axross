"""SMB redials with this session's credentials, proxy and workstation name.

smbclient's register_session - inside every smbclient call - dials a new
Connection and Session by itself when the pooled one is down (server
restart, Wi-Fi switch, NAT timeout). The calls passed only port and pool,
so that redial logged in with username=None (no login at all, or implicit
Kerberos as whoever holds the local ticket), went straight past the
SOCKS/HTTP proxy (the real address to the server and every observer) and
put the real hostname into NTLM. The proxy and hostname patches existed
only in SmbSession.__init__. The same for the server a DFS referral names.

Now the session's pool dials every connection itself, inside both patches
and with the session's credentials; after close() nothing dials again.

smbprotocol's Connection / Session are recorders (no SMB server here);
SmbSession.__init__ and smbclient's register_session run for real.
"""

from __future__ import annotations

import socket
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

SC = pytest.importorskip("core.smb_client")
pool = pytest.importorskip("smbclient._pool")

_REAL_CREATE = socket.create_connection
_REAL_HOSTNAME = socket.gethostname()


class _Transport:
    def __init__(self) -> None:
        self.connected = False


class _Connection:
    def __init__(self, guid, server, port, require_signing=True):
        self.server, self.port = server, port
        self.transport = _Transport()
        self.session_table: dict = {}

    def connect(self, timeout=60):
        _events.append(
            (
                "dial",
                self.server,
                self.port,
                socket.create_connection is not _REAL_CREATE,  # via the proxy
                socket.gethostname(),
            )
        )
        if _fail_dial:
            raise ConnectionRefusedError(111, "refused")
        self.transport.connected = True

    def disconnect(self, *a, **k):
        self.transport.connected = False


class _Session:
    def __init__(self, connection, username=None, password=None, **kw):
        self.connection, self.username, self.password = connection, username, password

    def connect(self):
        _events.append(("login", self.username, self.password, socket.gethostname()))
        self.connection.session_table[id(self)] = self


_events: list = []
_fail_dial = False


def _register(server, **kw):
    """What get_smb_tree hands register_session for an smbclient call."""
    allowed = {"username", "password", "port", "connection_cache"}
    return pool.register_session(server, **{k: v for k, v in kw.items() if k in allowed})


@pytest.fixture
def smb(monkeypatch):
    global _fail_dial
    _events.clear()
    _fail_dial = False
    monkeypatch.setattr(pool, "Connection", _Connection)
    monkeypatch.setattr(pool, "Session", _Session)
    monkeypatch.setattr("smbprotocol.connection.Connection", _Connection)
    monkeypatch.setattr(SC.smbclient, "listdir", lambda p, **kw: (_register(p.split("\\")[2], **kw), [])[1])
    monkeypatch.setattr(
        SC.smbclient.path, "lexists", lambda p, **kw: (_register(p.split("\\")[2], **kw), True)[1]
    )
    # The proxy is never really dialled: the recorder only checks that
    # socket.create_connection is the proxied one while it connects.
    monkeypatch.setattr("core.proxy.create_proxy_socket", lambda *a, **k: None)

    def make(port: int = 445) -> "SC.SmbSession":
        return SC.SmbSession(
            "fileserver.corp", "share", "alice", "s3cret", port=port,
            proxy_type="socks5", proxy_host="127.0.0.1", proxy_port=1080,
        )

    return make


def _drop(session) -> None:
    for connection in session._connections.values():
        connection.transport.connected = False


def _assert_private(events, server, port):
    dial = [e for e in events if e[0] == "dial"]
    login = [e for e in events if e[0] == "login"]
    assert dial and dial[-1][1:3] == (server, port)
    assert dial[-1][3] is True, "dialled past the proxy"
    assert dial[-1][4] == SC.SMB_CLIENT_NAME != _REAL_HOSTNAME
    assert login and login[-1] == ("login", "alice", "s3cret", SC.SMB_CLIENT_NAME)


# -- happy -------------------------------------------------------------------


def test_happy_the_first_connection_goes_through_proxy_with_credentials(smb):
    smb()
    _assert_private(_events, "fileserver.corp", 445)


def test_happy_after_a_drop_the_next_call_redials_as_the_same_user(smb):
    s = smb()
    _events.clear()
    _drop(s)
    assert s.exists("/report.docx") is True
    _assert_private(_events, "fileserver.corp", 445)
    assert len([e for e in _events if e[0] == "dial"]) == 1
    # The security badge follows the new session.
    assert s._smb_session.connection.transport.connected


# -- sad ---------------------------------------------------------------------


@pytest.mark.parametrize("port", [445, 4445])
def test_sad_a_dfs_referral_target_is_dialled_privately(smb, port):
    s = smb(port)
    _events.clear()
    # get_smb_tree for the server a referral names.
    _register("fs2.corp", **s._kw)
    _assert_private(_events, "fs2.corp", 445)


def test_sad_a_failed_redial_is_an_oserror_and_the_next_call_tries_again(smb):
    global _fail_dial
    s = smb()
    _drop(s)
    _fail_dial = True
    with pytest.raises(OSError):
        s.exists("/a")
    _fail_dial = False
    _events.clear()
    assert s.exists("/a") is True
    _assert_private(_events, "fileserver.corp", 445)


def test_sad_after_close_nothing_dials_again(smb):
    s = smb()
    s.close()
    _events.clear()
    with pytest.raises(OSError):
        s.exists("/a")
    assert s.connected is False
    assert _events == []


# -- edge --------------------------------------------------------------------


def test_edge_concurrent_calls_after_a_drop_dial_once(smb):
    s = smb()
    _drop(s)
    _events.clear()
    errors: list = []

    def call():
        try:
            s.exists("/a")
        except BaseException as exc:  # noqa: BLE001 - reported below
            errors.append(exc)

    threads = [threading.Thread(target=call) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(10)
    assert errors == []
    assert len([e for e in _events if e[0] == "dial"]) == 1


def test_edge_a_lost_login_on_a_live_connection_logs_in_again(smb):
    s = smb()
    for connection in s._connections.values():
        connection.session_table.clear()   # server expired the session
    _events.clear()
    assert s.exists("/a") is True
    assert [e[0] for e in _events] == ["login"]
    assert _events[0] == ("login", "alice", "s3cret", SC.SMB_CLIENT_NAME)
