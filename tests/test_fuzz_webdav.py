"""Fuzz: WebDavSession against a hostile WebDAV server.

PROPFIND answers are XML from a server we do not control: malformed XML,
XXE, billion-laughs, deep nesting, lying sizes and dates must end in sane
items or an OSError - never ParseError (a SyntaxError), defusedxml's
ValueError subclasses, or a hang.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fuzz_testkit import check_contract, iterations, mutants  # noqa: E402
from http_fuzz_server import STALL, FakeHttpServer, response  # noqa: E402

from core import webdav_client as W  # noqa: E402

MULTISTATUS = b"""<?xml version="1.0" encoding="utf-8"?>
<d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns">
 <d:response><d:href>/dav/</d:href><d:propstat><d:prop>
  <d:resourcetype><d:collection/></d:resourcetype></d:prop>
  <d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>
 <d:response><d:href>/dav/a%20file.txt</d:href><d:propstat><d:prop>
  <d:displayname>a file.txt</d:displayname>
  <d:getcontentlength>1234</d:getcontentlength>
  <d:getlastmodified>Tue, 01 Jan 2026 10:00:00 GMT</d:getlastmodified>
  <d:getetag>"abc"</d:getetag>
  <oc:checksums><oc:checksum>SHA1:deadbeef</oc:checksum></oc:checksums>
  <d:resourcetype/></d:prop>
  <d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>
 <d:response><d:href>/dav/sub/</d:href><d:propstat><d:prop>
  <d:resourcetype><d:collection/></d:resourcetype></d:prop>
  <d:status>HTTP/1.1 200 OK</d:status></d:propstat>
  <d:propstat><d:prop><d:getcontentlength/></d:prop>
  <d:status>HTTP/1.1 404 Not Found</d:status></d:propstat></d:response>
</d:multistatus>"""

QUOTA = (
    b'<?xml version="1.0"?><d:multistatus xmlns:d="DAV:"><d:response><d:href>/dav/</d:href>'
    b"<d:propstat><d:prop><d:quota-available-bytes>100</d:quota-available-bytes>"
    b"<d:quota-used-bytes>20</d:quota-used-bytes></d:prop>"
    b"<d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"
)


class DavServer:
    """Answers PROPFIND with ``self.propfind`` (raw body or full response)."""

    def __init__(self) -> None:
        self.propfind: bytes = MULTISTATUS
        self.raw: bytes | None = None
        self.get: bytes = response(200, b"content")
        self.http = FakeHttpServer(self._respond)

    def _respond(self, method, path, headers, body):
        if self.raw is not None and method != "GET":
            return self.raw
        if method == "PROPFIND":
            payload = QUOTA if b"quota" in body else self.propfind
            return response(207, payload, {"Content-Type": "application/xml"})
        if method == "GET":
            return self.get
        return response(201)

    def close(self) -> None:
        self.http.close()


@pytest.fixture
def dav():
    srv = DavServer()
    yield srv
    srv.close()


def _session(srv: DavServer) -> W.WebDavSession:
    s = W.WebDavSession(srv.http.url + "/dav")
    s._client._timeout = 0.3
    return s


def _ops(s):
    return {
        "list_dir": lambda: s.list_dir("/"),
        "stat": lambda: s.stat("/a file.txt"),
        "is_dir": lambda: s.is_dir("/sub"),
        "exists": lambda: s.exists("/a file.txt"),
        "checksum": lambda: s.checksum("/a file.txt", "sha1"),
        "disk_usage": lambda: s.disk_usage("/"),
    }


def _all_ops(s, ctx):
    for name, op in _ops(s).items():
        result = check_contract(op, (OSError,), timeout=15.0, context=f"{ctx} {name}")
        if name == "list_dir" and not isinstance(result, OSError):
            for item in result:
                assert isinstance(item.name, str) and item.name
                assert isinstance(item.size, int)


def test_happy_listing(dav):
    items = _session(dav).list_dir("/")
    assert sorted(i.name for i in items) == ["a file.txt", "sub"]
    assert _session(dav).disk_usage("/") == (120, 20, 100)


XXE = (
    b'<?xml version="1.0"?>\n'
    b'<!DOCTYPE d [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>\n'
    b'<d:multistatus xmlns:d="DAV:"><d:response><d:href>/dav/&xxe;</d:href>'
    b"</d:response></d:multistatus>"
)

LAUGHS = (
    b'<?xml version="1.0"?><!DOCTYPE l [<!ENTITY a "aaaaaaaaaa">'
    + b"".join(
        f'<!ENTITY {chr(98 + i)} "{("&" + chr(97 + i) + ";") * 10}">'.encode() for i in range(9)
    )
    + b']><d:multistatus xmlns:d="DAV:">&j;</d:multistatus>'
)

DEEP = (
    b'<d:multistatus xmlns:d="DAV:">'
    + b"<d:x>" * 100_000
    + b"</d:x>" * 100_000
    + b"</d:multistatus>"
)


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"not xml at all",
        b"<d:multistatus xmlns:d='DAV:'><d:response>",  # truncated
        b"\xff\xfe<\x00",
        XXE,
        LAUGHS,
        DEEP,
        b'<?xml version="1.0" encoding="bogus-enc"?><a/>',
        b"<d:multistatus xmlns:d='DAV:'><d:response><d:href>/dav/x</d:href><d:propstat>"
        b"<d:prop><d:getcontentlength>-5</d:getcontentlength></d:prop>"
        b"<d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>",
        b"<d:multistatus xmlns:d='DAV:'><d:response><d:href>/dav/../../etc/passwd</d:href>"
        b"<d:propstat><d:prop><d:displayname>../../x</d:displayname></d:prop>"
        b"<d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>",
        b"<other xmlns='urn:x'/>",
    ],
    ids=[
        "empty",
        "text",
        "truncated",
        "garbage",
        "xxe",
        "laughs",
        "deep",
        "badenc",
        "negsize",
        "traversal",
        "foreign-root",
    ],
)
def test_sad_hostile_propfind_bodies(dav, payload):
    s = _session(dav)
    dav.propfind = payload
    _all_ops(s, repr(payload[:60]))


@pytest.mark.parametrize(
    "raw",
    [
        b"HTTP/1.1 207 Multi\r\nContent-Length: 999\r\n\r\n<d:multi",  # body shorter than announced
        b"HTTP/1.1 207 Multi\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n",
        b"HTTP/1.1 207 Multi\r\nContent-Length: abc\r\n\r\n",
        b"garbage\r\n\r\n",
        b"HTTP/1.1 999 What\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 207 x\r\n" + b"X-Big: " + b"a" * 200_000 + b"\r\nContent-Length: 0\r\n\r\n",
        STALL,
        None,
    ],
    ids=[
        "short-body",
        "bad-chunk",
        "bad-length",
        "garbage",
        "status999",
        "huge-header",
        "stall",
        "hangup",
    ],
)
def test_sad_hostile_http_framing(dav, raw):
    s = _session(dav)
    dav.raw = raw
    _all_ops(s, repr(raw)[:60])


def test_sad_get_body_shorter_than_announced(dav):
    s = _session(dav)
    dav.get = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nabc"
    check_contract(lambda: s.open_read("/f"), (OSError,), timeout=15.0, context="short GET")


def test_edge_traversal_names_are_dropped_before_download(dav):
    from core.path_policy import drop_unsafe_names

    dav.propfind = (
        b"<d:multistatus xmlns:d='DAV:'>"
        + b"".join(
            b"<d:response><d:href>/dav/" + href + b"</d:href><d:propstat><d:prop>"
            b"<d:displayname>" + name + b"</d:displayname></d:prop>"
            b"<d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"
            for href, name in (
                (b"x", b"../../escape"),
                (b"y", b"/etc/passwd"),
                (b"z", b"a/b"),
                (b"ok.txt", b"ok.txt"),
            )
        )
        + b"</d:multistatus>"
    )
    items = _session(dav).list_dir("/")
    assert [i.name for i in drop_unsafe_names(items)] == ["ok.txt"]


def test_fuzz_propfind_mutants(dav):
    s = _session(dav)
    for n, payload in enumerate(mutants([MULTISTATUS], seed=0xDA7, per_entry=iterations(60))):
        dav.propfind = payload
        _all_ops(s, f"PROPFIND mutant #{n}: {payload[:100]!r}")


def test_fuzz_parse_propfind_direct():
    client = W._WebDavClient("http://127.0.0.1:1/dav", "", "")
    for payload in mutants([MULTISTATUS, QUOTA], seed=0xDA8, per_entry=iterations(400)):
        check_contract(
            lambda: client._parse_propfind(payload), (OSError,), context=f"{payload[:100]!r}"
        )
