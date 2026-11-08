"""Reverse serve: what a GET or HEAD answers is exactly what it says.

Measured before (pre-release security and protocol reviews):

* GET sent ``Content-Length`` from the stat and then streamed all that
  ``open_read`` gave. A file appended to between the two (a log) sent its
  new bytes past the stated length; on a kept-alive connection the client
  read them as the answer to its NEXT request - a log line holding an HTTP
  response forged the content of another file (S3 GetObject and WebDAV GET).
  A backend whose stat has no size (Gopher, TFTP without tsize: 0) did the
  same with the whole file.
* GET ignored ``Range``: always 200 with the whole object. boto3 /
  aws-cli download objects above 8 MiB as ranged GETs and write each answer
  at its range's offset - the downloaded file was corrupt (37 MB for 20 MB).
* An error answer to HEAD carried its body; on a kept-alive connection it
  was the start of the next response (Go clients: rclone, restic).
* An aws-chunked body whose CR after a chunk was the last byte of a 1 MiB
  fill was refused (``_LineReader.read(2)`` gave one byte): every boto3
  put_object of 1048568 bytes failed with 400.
* A header line without a colon hid every header after it (the request's
  Content-Length too).
* 16 abandoned multipart uploads blocked multipart for an hour.
"""

from __future__ import annotations

import http.client
import io
import os
import socket
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import reverse_serve as RS  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402

OLD = b"old"
FORGED = b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nFORGED"
NS = "{http://s3.amazonaws.com/doc/2006-03-01/}"


class GrowingFS(LocalFS):
    """A file appended to while it is served (the stat comes first)."""

    def open_read(self, path, *a, **kw):
        if path.endswith("log"):
            with open(path, "ab") as fh:
                fh.write(FORGED)
        return super().open_read(path, *a, **kw)


class ShrinkingFS(LocalFS):
    """A file cut short between the stat and the read."""

    def open_read(self, path, *a, **kw):
        if path.endswith("log"):
            with open(path, "r+b") as fh:
                fh.truncate(2)
        return super().open_read(path, *a, **kw)


class SizelessFS(LocalFS):
    """A stat without a real size, as Gopher and TFTP report it."""

    def stat(self, path):
        import dataclasses

        item = super().stat(path)
        return dataclasses.replace(item, size=0) if path.endswith("log") else item


@pytest.fixture
def root(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    (tmp_path / "srv" / "b").mkdir(parents=True)
    (tmp_path / "srv" / "b" / "f").write_bytes(OLD)
    (tmp_path / "srv" / "b" / "log").write_bytes(b"line1\n")
    (tmp_path / "srv" / "b" / "digits").write_bytes(b"0123456789")
    return tmp_path / "srv"


def _serve(kind, root, backend=None):
    serve = RS.serve_s3 if kind == "s3" else RS.serve_webdav
    return serve(backend or LocalFS(), bind="127.0.0.1", port=0, root_path=str(root))


class _Stream:
    def __init__(self, data: bytes) -> None:
        self.f = io.BytesIO(data)
        self.f.close = lambda: None

    def makefile(self, *a, **k):
        return self.f


def _exchange(srv, raw: bytes) -> bytes:
    with socket.create_connection(("127.0.0.1", srv.port), timeout=10) as sock:
        sock.sendall(raw)
        sock.settimeout(5)
        data = b""
        try:
            while chunk := sock.recv(65536):
                data += chunk
        except socket.timeout:
            data += b"<<TIMEOUT>>"
    return data


def _request(srv, method: str, path: str, headers: str = "", close: bool = False) -> bytes:
    return (f"{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n"
            f"Authorization: Bearer {srv.auth_token}\r\n{headers}"
            + ("Connection: close\r\n" if close else "") + "\r\n").encode()


def _responses(data: bytes, methods: list[str]) -> list[tuple[int, dict, bytes]]:
    """The responses in *data*, read as a client reads one byte stream."""
    stream = _Stream(data)
    out = []
    for method in methods:
        resp = http.client.HTTPResponse(stream, method=method)
        try:
            resp.begin()
        except (http.client.RemoteDisconnected, http.client.BadStatusLine):
            break
        out.append((resp.status, {k.lower(): v for k, v in resp.getheaders()}, resp.read()))
    return out


# -- the length is the body's ---------------------------------------------------------------

@pytest.mark.parametrize("kind", ["s3", "webdav"])
def test_sad_a_file_grown_while_served_never_answers_the_next_request(root, kind):
    srv = _serve(kind, root, GrowingFS())
    try:
        raw = _exchange(srv, _request(srv, "GET", "/b/log") + _request(srv, "GET", "/b/f")
                        + _request(srv, "GET", "/b/f", close=True))
    finally:
        srv.shutdown()
    got = _responses(raw, ["GET", "GET", "GET"])
    assert got[0][0] == 200 and got[0][2] == b"line1\n"
    # The connection ends after the mismatch; whatever follows is real.
    for status, _headers, body in got[1:]:
        assert (status, body) == (200, OLD), got
    assert b"FORGED" not in b"".join(body for _s, _h, body in got)


@pytest.mark.parametrize("kind", ["s3", "webdav"])
def test_sad_a_file_cut_short_while_served_ends_the_connection(root, kind):
    srv = _serve(kind, root, ShrinkingFS())
    try:
        raw = _exchange(srv, _request(srv, "GET", "/b/log") + _request(srv, "GET", "/b/f"))
    finally:
        srv.shutdown()
    assert b"<<TIMEOUT>>" not in raw  # closed, not left waiting for the stated length
    head, _, body = raw.partition(b"\r\n\r\n")
    assert b"Content-Length: 6" in head and body == b"li"


def test_edge_a_stat_without_a_size_sends_a_chunked_body(root):
    srv = _serve("webdav", root, SizelessFS())
    try:
        (root / "b" / "log").write_bytes(FORGED)
        raw = _exchange(srv, _request(srv, "GET", "/b/log")
                        + _request(srv, "GET", "/b/f", close=True))
    finally:
        srv.shutdown()
    got = _responses(raw, ["GET", "GET"])
    assert got[0][0] == 200 and got[0][2] == FORGED
    assert got[0][1].get("transfer-encoding") == "chunked"
    assert got[1][0] == 200 and got[1][2] == OLD


# -- byte ranges ------------------------------------------------------------------------------

def _get(srv, path, headers: str = ""):
    raw = _exchange(srv, _request(srv, "GET", path, headers, close=True))
    return _responses(raw, ["GET"])[0]


@pytest.mark.parametrize("kind", ["s3", "webdav"])
def test_happy_a_single_range_is_answered_206(root, kind):
    srv = _serve(kind, root)
    try:
        cases = {
            "bytes=2-4": (b"234", "bytes 2-4/10"),
            "bytes=7-": (b"789", "bytes 7-9/10"),
            "bytes=-2": (b"89", "bytes 8-9/10"),
            "bytes=8-100": (b"89", "bytes 8-9/10"),
        }
        for value, (want, content_range) in cases.items():
            status, headers, body = _get(srv, "/b/digits", f"Range: {value}\r\n")
            assert (status, body, headers["content-range"]) == (206, want, content_range), value
            assert headers["content-length"] == str(len(want))
            assert headers["accept-ranges"] == "bytes"
    finally:
        srv.shutdown()


@pytest.mark.parametrize("kind", ["s3", "webdav"])
def test_sad_a_range_past_the_end_is_416(root, kind):
    srv = _serve(kind, root)
    try:
        status, headers, body = _get(srv, "/b/digits", "Range: bytes=10-20\r\n")
    finally:
        srv.shutdown()
    assert status == 416 and headers["content-range"] == "bytes */10" and body == b""


@pytest.mark.parametrize("kind", ["s3", "webdav"])
def test_edge_several_ranges_or_another_version_get_the_whole_object(root, kind):
    srv = _serve(kind, root)
    try:
        multi = _get(srv, "/b/digits", "Range: bytes=0-1,4-5\r\n")
        other = _get(srv, "/b/digits",
                     "Range: bytes=0-1\r\nIf-Range: Mon, 01 Jan 1990 00:00:00 GMT\r\n")
        head = _responses(_exchange(srv, _request(srv, "HEAD", "/b/digits", close=True)),
                          ["HEAD"])[0]
    finally:
        srv.shutdown()
    assert (multi[0], multi[2]) == (200, b"0123456789")
    assert (other[0], other[2]) == (200, b"0123456789")
    assert head[1].get("accept-ranges") == "bytes"


# -- HEAD errors have no body -----------------------------------------------------------------

@pytest.mark.parametrize("kind, path", [("s3", "/b/missing"), ("s3", "/nobucket"),
                                        ("webdav", "/b/%2e%2e/x")])
def test_sad_a_head_error_carries_no_body(root, kind, path):
    srv = _serve(kind, root)
    try:
        raw = _exchange(srv, _request(srv, "HEAD", path) + _request(srv, "GET", "/b/f", close=True))
    finally:
        srv.shutdown()
    got = _responses(raw, ["HEAD", "GET"])
    assert got[0][0] in (400, 404)
    assert len(got) == 2 and (got[1][0], got[1][2]) == (200, OLD), raw[:400]


# -- aws-chunked frames across a read boundary ------------------------------------------------

def test_sad_an_aws_chunked_cr_on_a_fill_boundary_is_accepted(root):
    data = os.urandom(1048568)  # 7-byte size line + data: the CR is byte 1048575
    inner = b"%x\r\n%s\r\n0\r\nx-amz-checksum-crc32:AAAAAA==\r\n\r\n" % (len(data), data)
    srv = _serve("s3", root)
    try:
        raw = _exchange(srv, (
            f"PUT /b/obj HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n"
            f"Authorization: Bearer {srv.auth_token}\r\nContent-Encoding: aws-chunked\r\n"
            f"X-Amz-Decoded-Content-Length: {len(data)}\r\nContent-Length: {len(inner)}\r\n\r\n"
        ).encode() + inner)
    finally:
        srv.shutdown()
    assert raw.startswith(b"HTTP/1.1 200"), raw[:300]
    assert (root / "b" / "obj").read_bytes() == data


# -- headers ----------------------------------------------------------------------------------

@pytest.mark.parametrize("kind", ["s3", "webdav"])
def test_sad_a_header_line_without_a_colon_is_refused(root, kind):
    srv = _serve(kind, root)
    try:
        raw = _exchange(srv, (
            f"PUT /b/f HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {srv.auth_token}\r\n"
            "Broken header line\r\nContent-Length: 3\r\n\r\nnew").encode())
    finally:
        srv.shutdown()
    assert raw.startswith(b"HTTP/1.1 400"), raw[:200]
    assert (root / "b" / "f").read_bytes() == OLD


# -- abandoned multipart uploads --------------------------------------------------------------

def test_edge_abandoned_multipart_uploads_make_room_for_a_new_one(root, monkeypatch):
    monkeypatch.setattr(RS, "MULTIPART_MAX_UPLOADS", 2)
    monkeypatch.setattr(RS, "MULTIPART_EVICT_IDLE_S", 0.0)
    srv = _serve("s3", root)
    try:
        ids = []
        for key in ("x1", "x2", "x3"):
            raw = _exchange(srv, _request(srv, "POST", f"/b/{key}?uploads",
                                          "Content-Length: 0\r\n", close=True))
            status, _h, body = _responses(raw, ["POST"])[0]
            assert status == 200, body
            ids.append(ET.fromstring(body).findtext(f"{NS}UploadId"))
        raw = _exchange(srv, _request(srv, "PUT", f"/b/x1?partNumber=1&uploadId={ids[0]}",
                                      "Content-Length: 1\r\n", close=True)[:-2] + b"\r\nx")
    finally:
        srv.shutdown()
    assert raw.startswith(b"HTTP/1.1 404"), raw[:200]  # the oldest one went
