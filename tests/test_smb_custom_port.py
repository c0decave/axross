"""SMB on a port other than 445 uses that port for every operation.

``SmbSession.__init__`` registered the session with ``port=port``, but
smbclient keys its connection pool by ``"host:port"`` and every later call
(``listdir``, ``scandir``, ``stat``, ``open_file``, ``SMBDirEntry.stat`` ...)
defaults to ``port=445`` (``smbclient/_pool.py`` ``get_smb_tree``). So the
very first probe after registering dialled 445 instead: a server on 4445
could not be used at all, and with something else listening on 445 the
operations went to the wrong server. ``close`` likewise deleted the
``host:445`` entry and leaked the real one.

Driven through the real smbclient functions down to the pool, where a
recorder stands in for ``register_session`` (the one place every smbclient
operation funnels through to pick its connection).
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

SC = pytest.importorskip("core.smb_client")
pool = pytest.importorskip("smbclient._pool")

PORT = 4445


class _Stop(OSError):
    pass


@pytest.fixture
def pool_ports(monkeypatch):
    """Record the port of every connection smbclient would open or reuse."""
    ports: list[int] = []
    deleted: list[int] = []

    def register(server, username=None, password=None, port=445, **kw):
        ports.append(port)
        if len(ports) == 1 and username == "u":
            return SimpleNamespace()  # SmbSession's own explicit registration
        raise _Stop(f"pool stop for {server}:{port}")

    def delete(server, port=445, **kw):
        deleted.append(port)

    monkeypatch.setattr(pool, "register_session", register)
    monkeypatch.setattr(SC.smbclient, "register_session", register)
    monkeypatch.setattr(SC.smbclient, "delete_session", delete)
    return SimpleNamespace(ports=ports, deleted=deleted)


def _session(port: int = PORT) -> "SC.SmbSession":
    s = object.__new__(SC.SmbSession)
    s._host, s._share, s._port = "srv", "share", port
    s._prefix = r"\\srv\share"
    return s


def test_happy_connect_probe_uses_the_configured_port(pool_ports):
    with pytest.raises(OSError):
        SC.SmbSession(host="srv", share="share", username="u", password="p", port=PORT)
    # Explicit registration, then the probe listdir.
    assert pool_ports.ports == [PORT, PORT]
    # The failed probe tears down the entry it registered, not srv:445.
    assert PORT in pool_ports.deleted and 445 not in pool_ports.deleted


@pytest.mark.parametrize(
    "op",
    [
        lambda s: s.list_dir("/d"),
        lambda s: s.stat("/f"),
        lambda s: s.mkdir("/d"),
        lambda s: s.rename("/a", "/b"),
        lambda s: s.open_read("/f"),
        lambda s: s.open_write("/f"),
        lambda s: s.remove("/f"),
    ],
    ids=["list_dir", "stat", "mkdir", "rename", "open_read", "open_write", "remove"],
)
def test_sad_every_operation_reaches_the_configured_port(pool_ports, op):
    with pytest.raises(OSError):
        op(_session())
    assert pool_ports.ports, "the operation never reached the pool"
    assert set(pool_ports.ports) == {PORT}


def test_sad_is_dir_and_exists_use_the_configured_port(pool_ports):
    s = _session()
    # The pool refuses the connection: an OSError, not "absent".
    with pytest.raises(OSError):
        s.is_dir("/d")
    with pytest.raises(OSError):
        s.exists("/d")
    assert pool_ports.ports and set(pool_ports.ports) == {PORT}


def test_sad_symlink_stat_in_a_listing_uses_the_configured_port(pool_ports, monkeypatch):
    # SMBDirEntry.stat() calls smbclient.stat(path) without any port.
    entry = SimpleNamespace(
        name="lnk",
        path=r"\\srv\share\d\lnk",
        is_symlink=lambda: True,
        stat=lambda follow_symlinks=True: pool.register_session("srv", port=445),
    )
    monkeypatch.setattr(SC.smbclient, "scandir", lambda path, **kw: iter([entry]))
    (item,) = _session().list_dir("/d")
    assert item.name == "lnk"
    assert pool_ports.ports == [PORT]


def test_edge_close_deletes_the_configured_ports_entry(pool_ports):
    _session().close()
    assert pool_ports.deleted == [PORT]


def test_edge_default_port_is_445(pool_ports):
    s = object.__new__(SC.SmbSession)
    s._host, s._share, s._prefix = "srv", "share", r"\\srv\share"
    with pytest.raises(OSError):
        s.stat("/f")
    assert pool_ports.ports == [445]
