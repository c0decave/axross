"""An SMB dial routes only its own connection, and its failures are typed.

Round 6 found (repro reconn/repro_smb_dial_global_patch.py,
repro_smb_redial_error_type.py):

* SmbSession._dial swapped ``socket.create_connection`` (the profile's
  SOCKS proxy) and ``socket.gethostname`` (the masked NTLM workstation)
  process-wide, under locks held across the up to 60 s connect: an
  unrelated direct connection of another thread went through the SMB
  profile's proxy, and a second SMB dial to another host waited 57.5 s;
* a dial to a server that is down raised OSError without errno (from
  smbprotocol's ValueError), a dropped socket SMBConnectionClosed (no
  OSError at all from an open file handle).

Now both are scoped to the dialling thread and the SMB libraries
(core.proxy.routed_create_connection, spnego's gethostname), and the
failures are ConnectionRefusedError / ConnectionResetError / TimeoutError
with their errno.
"""

from __future__ import annotations

import errno
import socket
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

SC = pytest.importorskip("core.smb_client")
pool = pytest.importorskip("smbclient._pool")
import core.proxy as proxy  # noqa: E402

_REAL_CREATE = socket.create_connection
_REAL_HOSTNAME = socket.gethostname()
_events: list = []
_in_slow_dial = threading.Event()
_release = threading.Event()


class _Transport:
    connected = False


class _Connection:
    def __init__(self, guid, server, port, require_signing=True):
        self.server, self.port = server, port
        self.transport = _Transport()
        self.session_table: dict = {}

    def connect(self, timeout=60):
        import smbprotocol.transport as transport
        import spnego._ntlm as ntlm

        _events.append((
            "dial", self.server, threading.get_ident(),
            proxy.routed_proxy() is not None
            and type(transport.socket).__name__ == "_RoutedSocketModule",
            ntlm.socket.gethostname(),
        ))
        if self.server == "slow.corp":
            _in_slow_dial.set()
            _release.wait(20)  # a black-holed server: the connect hangs
        self.transport.connected = True

    def disconnect(self, *a, **k):
        self.transport.connected = False


class _Session:
    def __init__(self, connection, username=None, password=None, **kw):
        self.connection, self.username, self.password = connection, username, password

    def connect(self):
        self.connection.session_table[id(self)] = self


def _register(server, **kw):
    allowed = {"username", "password", "port", "connection_cache"}
    return pool.register_session(server, **{k: v for k, v in kw.items() if k in allowed})


@pytest.fixture
def smb(monkeypatch):
    _events.clear()
    _in_slow_dial.clear()
    _release.clear()
    monkeypatch.setattr(pool, "Connection", _Connection)
    monkeypatch.setattr(pool, "Session", _Session)
    monkeypatch.setattr(
        SC.smbclient, "listdir", lambda p, **kw: (_register(p.split("\\")[2], **kw), [])[1]
    )
    monkeypatch.setattr("core.proxy.create_proxy_socket", lambda *a, **k: None)
    yield
    _release.set()


def test_happy_another_threads_connection_and_smb_dial_do_not_wait_or_use_the_proxy(smb):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(4)
    sessions: list = []

    def proxied_dial():
        sessions.append(SC.SmbSession(
            "slow.corp", "share", "alice", "pw",
            proxy_type="socks5", proxy_host="127.0.0.1", proxy_port=1080,
        ))

    worker = threading.Thread(target=proxied_dial, daemon=True)
    worker.start()
    try:
        assert _in_slow_dial.wait(10)
        # Meanwhile, in this thread: nothing process-wide changed ...
        assert socket.create_connection is _REAL_CREATE
        assert socket.gethostname() == _REAL_HOSTNAME
        # ... a direct connection goes direct (was: through the SOCKS proxy) ...
        conn = socket.create_connection(listener.getsockname(), timeout=5)
        assert conn.getpeername() == listener.getsockname()
        conn.close()
        # ... and another server's SMB dial does not wait (was: 57.5 s).
        t0 = time.monotonic()
        other = SC.SmbSession("other.corp", "share", "bob", "pw")
        assert time.monotonic() - t0 < 2
        dial = [e for e in _events if e[1] == "other.corp"][-1]
        assert dial[3] is False  # no proxy for this profile
        assert dial[4] == SC.SMB_CLIENT_NAME  # the masked name, in its own thread too
        other.close()
    finally:
        _release.set()
        worker.join(10)
        listener.close()
    slow = [e for e in _events if e[1] == "slow.corp"][-1]
    assert slow[3] is True and slow[4] == SC.SMB_CLIENT_NAME
    for s in sessions:
        s.close()


def test_sad_a_refused_dial_is_a_connection_refused_error():
    try:
        raise ValueError("Failed to connect to 'h:445': refused") from ConnectionRefusedError(
            errno.ECONNREFUSED, "Connection refused"
        )
    except ValueError as exc:
        err = SC._smb_error(exc, "Cannot list /", "/")
    assert isinstance(err, ConnectionRefusedError)  # was OSError, errno None
    assert err.errno == errno.ECONNREFUSED


def test_sad_a_dropped_and_a_silent_connection_get_their_errno():
    from smbprotocol.exceptions import SMBConnectionClosed, SMBException

    dropped = SC._smb_error(SMBConnectionClosed("SMB socket was closed"), "Cannot read /a", "/a")
    assert isinstance(dropped, ConnectionResetError) and dropped.errno == errno.ECONNRESET
    silent = SC._smb_error(
        SMBException("Connection timeout of 60 seconds exceeded while waiting for a message"),
        "Cannot list /", "/",
    )
    assert isinstance(silent, TimeoutError) and silent.errno == errno.ETIMEDOUT


class _DroppedHandle:
    closed = False

    def read(self, n=-1):
        from smbprotocol.exceptions import SMBConnectionClosed

        raise SMBConnectionClosed("SMB socket was closed")

    def close(self):
        self.closed = True

    def readable(self):
        return True


def test_edge_a_handle_open_across_a_drop_raises_an_oserror():
    fh = SC._SmbFile(_DroppedHandle(), "/a")
    with pytest.raises(ConnectionResetError):  # was SMBConnectionClosed: no OSError
        with fh:
            fh.read(10)
    assert fh.closed is True
    assert fh.readable() is True  # the rest is the handle's own


def test_edge_a_routed_module_is_direct_in_other_threads(monkeypatch):
    import types

    calls: list = []
    monkeypatch.setattr(proxy, "create_proxy_socket", lambda cfg, host, port, **k: calls.append(
        (host, port)) or "proxied")
    module = types.SimpleNamespace(socket=socket)
    cfg = proxy.ProxyConfig(proxy_type="socks5", host="127.0.0.1", port=1080)
    seen: list = []
    with proxy.routed_create_connection(module, cfg):
        assert module.socket.create_connection(("x.corp", 445)) == "proxied"
        t = threading.Thread(target=lambda: seen.append(proxy.routed_proxy()))
        t.start()
        t.join()
    assert calls == [("x.corp", 445)]
    assert seen == [None]
    assert proxy.routed_proxy() is None
    assert module.socket.gethostname() == _REAL_HOSTNAME
