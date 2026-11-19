"""Exchange and LDAP: throttling, a wrong password, the autodiscover cache,
search(), ``connected`` - and an LDAP referral that took the password
elsewhere.

Before:

* Exchange: FaultTolerance's ``max_wait`` bounds each single back-off, so
  a server that kept answering ErrorServerBusy with a back-off under a
  minute was retried for ever - the pane hung with no way out;
* it reads every HTTP 401 as throttling: a wrong password was sent four
  times (Active Directory locks accounts after five) over about 70 s, and
  the user read "Max timeout reached" instead of "wrong password";
* exchangelib's autodiscover cache is a pickle (shelve) file at a fixed
  name in /tmp: another local user who created it first chose what was
  unpickled - code run as this user - and where the credentials went;
* ``search()`` joined two QuerySets with ``|`` and always raised TypeError;
* there was no ``connected``: the connection manager counted a closed
  session as alive;
* LDAP: ldap3 follows a referral to any host it names and binds there
  with the same DN and password - directly, around the proxy, and over
  plain ldap:// even from an LDAPS session.
"""

from __future__ import annotations

import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

exchangelib = pytest.importorskip("exchangelib")

from core import exchange_client as EC  # noqa: E402

_BUSY = b"""<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><s:Fault>
<faultcode xmlns:a="http://schemas.microsoft.com/exchange/services/2006/types">a:ErrorServerBusy</faultcode>
<faultstring xml:lang="en-US">The server cannot service this request right now.</faultstring>
<detail><e:ResponseCode xmlns:e="http://schemas.microsoft.com/exchange/services/2006/errors">ErrorServerBusy</e:ResponseCode>
<e:Message xmlns:e="http://schemas.microsoft.com/exchange/services/2006/errors">busy</e:Message>
<t:MessageXml xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"><t:Value Name="BackOffMilliseconds">300</t:Value></t:MessageXml>
</detail></s:Fault></s:Body></s:Envelope>"""


def _ews(status: int, body: bytes = b""):
    hits: list[float] = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802 - http.server
            self.rfile.read(int(self.headers.get("Content-Length", 0)))
            hits.append(time.monotonic())
            self.send_response(status)
            if status == 401:
                self.send_header("WWW-Authenticate", 'Basic realm="ews"')
            self.send_header("Content-Type", "text/xml; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, hits


def _list_root(srv, auth_type):
    from exchangelib import DELEGATE, Account, Build, Configuration, Credentials, Version

    cfg = Configuration(
        service_endpoint=f"http://127.0.0.1:{srv.server_port}/EWS/Exchange.asmx",
        credentials=Credentials("u", "wrong"), auth_type=auth_type,
        version=Version(build=Build(15, 1)), retry_policy=EC._retry_policy())
    acct = Account("u@example.com", config=cfg, autodiscover=False, access_type=DELEGATE)
    list(acct.root.children)


def test_sad_a_server_that_stays_busy_is_given_up_in_time(monkeypatch):
    from exchangelib.transport import NOAUTH

    monkeypatch.setattr(EC, "EXCHANGE_RETRY_MAX_WAIT", 2)
    srv, hits = _ews(500, _BUSY)
    result: dict = {}

    def run():
        try:
            _list_root(srv, NOAUTH)
            result["r"] = "listed"
        except Exception as exc:  # noqa: BLE001
            result["r"] = exc

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    thread.join(20)
    srv.shutdown()
    assert not thread.is_alive(), f"still retrying after {len(hits)} requests"
    assert isinstance(result["r"], Exception)


def test_sad_a_wrong_password_is_sent_once_and_named():
    from exchangelib.errors import UnauthorizedError
    from exchangelib.transport import BASIC

    srv, hits = _ews(401)
    started = time.monotonic()
    try:
        with pytest.raises(UnauthorizedError):
            _list_root(srv, BASIC)
    finally:
        srv.shutdown()
    assert time.monotonic() - started < 10
    assert len(hits) <= 2


def test_happy_the_autodiscover_cache_is_private():
    import os
    import tempfile

    from exchangelib.autodiscover import cache

    where = Path(cache.AUTODISCOVER_PERSISTENT_STORAGE)
    assert where.parent != Path(tempfile.gettempdir())
    assert where.is_relative_to(Path.home())
    assert oct(os.stat(where.parent).st_mode & 0o777) == oct(0o700)


def test_happy_search_sends_one_filter_with_an_or():
    seen: list = []

    class QS(list):
        def order_by(self, *_a):
            return self

    class Folder:
        def filter(self, *args, **kwargs):
            seen.append((args, kwargs))
            return QS()

    s = object.__new__(EC.ExchangeSession)
    s._account = SimpleNamespace(inbox=Folder(), root=None)
    s._smtp = "u@example.com"
    assert s.search("report") == []
    assert len(seen) == 1 and isinstance(seen[0][0][0], exchangelib.Q)


def test_sad_a_closed_exchange_session_is_not_connected():
    from core.connection_manager import ConnectionManager

    s = object.__new__(EC.ExchangeSession)
    s._account = SimpleNamespace(protocol=None)
    s._smtp = "u@example.com"
    assert ConnectionManager._is_connected(s)
    s.close()
    assert not s.connected and not ConnectionManager._is_connected(s)


class _QS(list):
    def only(self, *_fields):
        return self


class _Mailfolder:
    def __init__(self, name, children=(), messages=()):
        self.name, self.children, self.messages = name, list(children), list(messages)
        self.id = "F-" + name

    def __truediv__(self, other):
        for child in self.children:
            if child.name.lower() == other.lower():
                return child
        raise exchangelib.errors.ErrorFolderNotFound(other)

    def filter(self, **kw):
        return _QS(m for m in self.messages if m.id == kw.get("id"))

    def all(self):
        return _QS(self.messages)


def test_happy_a_forwarded_mail_attached_as_an_item_downloads_as_its_source():
    """An ItemAttachment has no ``content``: it was read as 0 bytes while
    the listing showed its size."""
    from datetime import datetime, timezone

    mime = b"Subject: meeting\r\nFrom: a@example.org\r\n\r\nSee you.\r\n"
    att = exchangelib.ItemAttachment(name="Fwd meeting", size=len(mime),
                                     item=exchangelib.Message(mime_content=mime))
    msg = SimpleNamespace(id="AAA1", subject="s", attachments=[att], has_attachments=True,
                          datetime_received=datetime(2026, 1, 2, tzinfo=timezone.utc))
    s = object.__new__(EC.ExchangeSession)
    s._account = SimpleNamespace(root=_Mailfolder("root", [_Mailfolder("Inbox", messages=[msg])]),
                                 trash=None)
    s._smtp = "u@example.com"
    name = s.list_dir("/Inbox/AAA1")[0].name
    assert s.open_read(f"/Inbox/AAA1/{name}").read() == mime


# ------------------------------------------------------------------ LDAP

ldap3 = pytest.importorskip("ldap3")

import ldap_fuzz_server as L  # noqa: E402
from fuzz_testkit import ScriptedServer  # noqa: E402

from core import ldap_fs_client as M  # noqa: E402

BASE = "dc=example,dc=com"


class _Referring(L.FakeLdapServer):
    """namingContexts at the root; a search under ou=branch is answered
    with a referral to *referral*."""

    referral = b""

    def search_answer(self, msgid, base=b"", scope=1):
        if base == b"":
            ent = L.search_entry("", {"namingContexts": [BASE], "supportedLDAPVersion": ["3"]})
            return L.message(msgid, ent) + L.message(msgid, L.ldap_result(0x65))
        if self.referral and base.lower().startswith(b"ou=branch"):
            res = (L.tlv(0x0A, bytes([10])) + L.octets(b"") + L.octets(b"")
                   + L.tlv(0xA3, L.octets(self.referral)))
            return L.message(msgid, L.tlv(0x65, res))
        return super().search_answer(msgid, base, scope)


class _Recorder:
    """The host the referral names: records every bind it gets."""

    def __init__(self):
        self.binds: list = []
        self.server = ScriptedServer(self._handle)
        self.port = self.server.port

    def _handle(self, conn):
        conn.settimeout(10)
        buf = bytearray()
        while True:
            el = L._read_tlv(conn, buf)
            if el is None:
                return
            hdr = 2 if el[1] < 0x80 else 2 + (el[1] & 0x7F)
            parts = L._split(el[hdr:])
            msgid = int.from_bytes(parts[0][1], "big", signed=True)
            if parts[1][0] == 0x60:
                fields = L._split(parts[1][1])
                self.binds.append((fields[1][1].decode(), fields[2][1].decode()))
                conn.sendall(L.message(msgid, L.ldap_result(0x61)))
            elif parts[1][0] == 0x63:
                conn.sendall(L.message(msgid, L.ldap_result(0x65)))
            else:
                return


def test_sad_a_referral_never_gets_the_bind_password():
    rec = _Recorder()
    srv = _Referring()
    srv.referral = f"ldap://127.0.0.1:{rec.port}/ou=branch,{BASE}".encode()
    try:
        s = M.LdapFsSession(host="127.0.0.1", port=srv.port,
                            username="cn=admin," + BASE, password="S3cret!", timeout=5)
        try:
            s.list_dir(f"/{BASE}/ou=branch")
        except OSError:
            pass  # a referral is no listing
        time.sleep(0.3)
        assert rec.binds == []
    finally:
        srv.close()
        rec.server.close()
