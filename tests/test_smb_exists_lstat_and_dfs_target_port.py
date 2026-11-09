"""SMB: exists() asks about the entry itself; a DFS referral target is
dialled on 445, not on the namespace server's own port.

* ``exists()`` went through ``smbclient.path.exists``, which FOLLOWS a
  link: a dangling link, or one to another server, answered False
  although the entry is there - and server_side_copy(overwrite=False)
  takes False as the go-ahead to write over it. It is ``lexists`` now
  (lstat semantics, as on every other backend).
* smbclient opens every connection on the ``port`` of the call, also the
  one to the server a DFS referral names. A session to a namespace server
  on a non-default port thus dialled every referral target on that port.
  The session's connection pool now hands smbclient a 445 connection for
  any server but the original one.
"""

from __future__ import annotations

import stat as stat_module
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

pytest.importorskip("smbprotocol")
from smbprotocol.exceptions import NtStatus, SMBLinkRedirectionError, SMBOSError  # noqa: E402

from core import smb_client as SC  # noqa: E402

pool = pytest.importorskip("smbclient._pool")
PREFIX = "\\\\h\\s"


@pytest.fixture
def smb(monkeypatch):
    import smbclient.path as smb_path

    def stat(path, follow_symlinks=True, **kw):
        name = path.rsplit("\\", 1)[-1]
        if name == "missing":
            raise SMBOSError(NtStatus.STATUS_OBJECT_NAME_NOT_FOUND, path)
        if follow_symlinks and name == "to_other_server":
            raise SMBLinkRedirectionError("cannot redirect", path, "\\\\fs2\\data\\x")
        if follow_symlinks and name == "dangling":
            raise SMBOSError(NtStatus.STATUS_OBJECT_NAME_NOT_FOUND, path)
        mode = stat_module.S_IFLNK if name in ("to_other_server", "dangling") else stat_module.S_IFREG
        return SimpleNamespace(st_mode=mode | 0o644)

    monkeypatch.setattr(smb_path, "stat", stat)
    s = SC.SmbSession.__new__(SC.SmbSession)
    s._host, s._share, s._port = "h", "s", 445
    s._prefix = PREFIX
    return s


class _Connection:
    dialled: list = []

    def __init__(self, guid, server, port, require_signing=True):
        self.server, self.port = server, port
        self.session_table: dict = {}
        self.transport = SimpleNamespace(connected=False)

    def connect(self, timeout=60):
        _Connection.dialled.append((self.server, self.port))
        self.transport.connected = True

    def disconnect(self):
        self.transport.connected = False


class _Session:
    def __init__(self, connection, username=None, **kw):
        self.connection, self.username = connection, username

    def connect(self):
        self.connection.session_table[id(self)] = self


@pytest.fixture
def dialled(monkeypatch):
    """A real SmbSession on port 4445 whose pool dials recorders."""
    _Connection.dialled = []
    monkeypatch.setattr(pool, "Connection", _Connection)
    monkeypatch.setattr(pool, "Session", _Session)
    monkeypatch.setattr("smbprotocol.connection.Connection", _Connection)
    monkeypatch.setattr(SC.smbclient, "listdir", lambda *a, **k: [])
    session = SC.SmbSession(host="ns", share="dfs", username="u", password="p", port=4445)
    return session, _Connection.dialled


# -- happy -------------------------------------------------------------------


def test_happy_a_regular_file_and_a_missing_name(smb):
    assert smb.exists("/regular") is True
    assert smb.exists("/missing") is False


def test_happy_the_namespace_server_keeps_its_own_port(dialled):
    session, ports = dialled
    pool.register_session("ns", **{"username": "u", "password": "p", **session._kw})
    assert ports == [("ns", 4445)]


# -- sad ---------------------------------------------------------------------


@pytest.mark.parametrize("name", ["dangling", "to_other_server"])
def test_sad_a_link_whose_target_cannot_be_reached_still_exists(smb, name):
    assert smb.exists(f"/{name}") is True


def test_sad_a_referral_target_is_dialled_on_445(dialled):
    session, ports = dialled
    # What get_smb_tree does for the server a referral names.
    pool.register_session("fs2", **{"username": "u", "password": "p", **session._kw})
    assert ports[-1] == ("fs2", 445)


# -- edge --------------------------------------------------------------------


def test_edge_close_also_closes_the_referral_connections(dialled, monkeypatch):
    session, _ = dialled
    pool.register_session("fs2", **{"username": "u", "password": "p", **session._kw})
    monkeypatch.setattr(SC.smbclient, "delete_session", lambda *a, **k: None)
    session.close()
    assert all(k.startswith("ns:") for k in session._connections)


def test_edge_the_default_port_is_left_to_smbclient():
    cache = SC._ReferralPortCache("ns", 445)
    assert cache.get("fs2:445") is None


# -- the namespace server under another name ---------------------------------
#
# A referral may name the namespace server itself by another spelling: its
# FQDN where the user typed the short name, or its address. That compared
# as another server by string, and was dialled on 445 instead of the
# session's port. Names are compared by what they resolve to now.

_DNS = {
    "ns": frozenset({"10.0.0.5"}),
    "ns.corp.example": frozenset({"10.0.0.5"}),
    "10.0.0.5": frozenset({"10.0.0.5"}),
    "ns.other.example": frozenset({"10.9.9.9"}),
}


@pytest.fixture
def resolver(monkeypatch):
    monkeypatch.setattr(SC, "_addresses", lambda name: _DNS.get(name, frozenset()), raising=False)


@pytest.mark.parametrize("name", ["ns.corp.example", "NS.corp.example.", "10.0.0.5"])
def test_sad_the_namespace_server_by_another_name_keeps_its_port(resolver, dialled, name):
    """Was: (name, 445) - the namespace server on a port where it does not
    listen. A server whose first label matches but that resolves
    elsewhere is another one: 445."""
    session, ports = dialled
    pool.register_session(name, **{"username": "u", "password": "p", **session._kw})
    assert ports[-1] == (name.lower(), 4445)  # smbclient keys the pool in lower case
    pool.register_session("ns.other.example", **{"username": "u", "password": "p", **session._kw})
    assert ports[-1] == ("ns.other.example", 445)


def test_edge_behind_a_proxy_names_are_not_looked_up(monkeypatch):
    """A lookup here would send the names to the local resolver, past the
    proxy: a short name then matches the first label of a full one."""

    def no_lookup(name):
        raise AssertionError(f"looked up {name!r}")

    monkeypatch.setattr(SC, "_addresses", no_lookup)
    cache = SC._ReferralPortCache("ns", 4445, resolve=False)
    assert cache._is_origin("NS.Corp.Example.") is True
    assert cache._is_origin("fs2.corp.example") is False
    assert cache._is_origin("10.0.0.5") is False
    assert cache.get("ns.corp.example:4445") is None   # smbclient dials it on 4445
