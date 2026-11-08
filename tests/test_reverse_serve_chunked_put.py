"""Reverse-serve: a PUT without Content-Length never replaces a file with nothing.

``core/reverse_serve.py`` read every PUT body as ``Content-Length``
bytes, with a missing header taken as 0, and never looked at
``Transfer-Encoding``. ``curl -T -`` and ``rclone rcat`` send a stream as
``Transfer-Encoding: chunked`` without Content-Length: the WebDAV PUT
answered 201 (the S3 PUT 200) and the existing file was now 0 bytes.

Now a chunked body is decoded and streamed (bounded by the same
``MAX_BODY_BYTES`` cap); a PUT with neither header is 411 Length
Required; malformed chunked framing, both headers at once, or a transfer
coding other than chunked are refused - and in every refusal the old
file is left as it was.
"""

from __future__ import annotations

import socket
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import reverse_serve as RS  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402

OLD = b"precious old content"


@pytest.fixture(params=["webdav", "s3"])
def setup(request, tmp_path):
    (tmp_path / "b").mkdir()
    target = tmp_path / "b" / "f"
    target.write_bytes(OLD)
    serve = RS.serve_webdav if request.param == "webdav" else RS.serve_s3
    srv = serve(LocalFS(), bind="127.0.0.1", port=0, root_path=str(tmp_path))
    yield srv, target
    srv.shutdown()


def _put(srv, headers: bytes, body: bytes, path: bytes = b"/b/f") -> int:
    """A raw PUT (http.client would add a Content-Length itself)."""
    with socket.create_connection(("127.0.0.1", srv.port), timeout=10) as s:
        s.sendall(
            b"PUT " + path + b" HTTP/1.1\r\nHost: 127.0.0.1\r\n"
            b"Authorization: Bearer " + srv.auth_token.encode() + b"\r\n"
            + headers + b"\r\n" + body
        )
        s.shutdown(socket.SHUT_WR)
        reply = b""
        while chunk := s.recv(4096):
            reply += chunk
    return int(reply.split(b" ", 2)[1])


def _chunked(*parts: bytes) -> bytes:
    return b"".join(b"%x\r\n%s\r\n" % (len(p), p) for p in parts) + b"0\r\n\r\n"


TE = b"Transfer-Encoding: chunked\r\n"


# -- happy ---------------------------------------------------------------------------------


def test_happy_a_chunked_put_stores_the_decoded_body(setup):
    srv, target = setup
    assert _put(srv, TE, _chunked(b"new ", b"content", b"!")) in (200, 201)
    assert target.read_bytes() == b"new content!"
    # A Content-Length PUT on the same file is unchanged.
    assert _put(srv, b"Content-Length: 3\r\n", b"xyz") in (200, 201)
    assert target.read_bytes() == b"xyz"


def test_happy_chunk_extensions_and_trailers_are_skipped(setup):
    srv, target = setup
    body = b"3;name=value\r\nabc\r\n2 ; x\r\nde\r\n0\r\nX-Checksum: 1\r\n\r\n"
    assert _put(srv, TE, body) in (200, 201)
    assert target.read_bytes() == b"abcde"


# -- sad -----------------------------------------------------------------------------------


def test_sad_a_put_with_no_length_is_411_and_keeps_the_file(setup):
    srv, target = setup
    assert _put(srv, b"", b"") == 411
    assert target.read_bytes() == OLD


def test_sad_a_truncated_chunked_body_keeps_the_file(setup):
    srv, target = setup
    assert _put(srv, TE, b"10\r\nonly a part") == 400
    assert target.read_bytes() == OLD


def test_sad_a_chunked_body_without_its_last_chunk_keeps_the_file(setup):
    srv, target = setup
    assert _put(srv, TE, b"3\r\nabc\r\n") == 400
    assert target.read_bytes() == OLD


@pytest.mark.parametrize(
    "body",
    [
        b"zz\r\nabc\r\n0\r\n\r\n",  # not hex
        b"0x3\r\nabc\r\n0\r\n\r\n",  # int(.., 16) would take it
        b"-3\r\nabc\r\n0\r\n\r\n",
        b"3\r\nabcX\r\n0\r\n\r\n",  # data longer than its size
        b"3\nabc\n0\n\n",  # bare LF
    ],
)
def test_sad_malformed_chunked_framing_keeps_the_file(setup, body):
    srv, target = setup
    assert _put(srv, TE, body) == 400
    assert target.read_bytes() == OLD


def test_sad_both_transfer_encoding_and_content_length_is_refused(setup):
    srv, target = setup
    assert _put(srv, TE + b"Content-Length: 3\r\n", _chunked(b"abc")) == 400
    assert target.read_bytes() == OLD


def test_sad_an_unknown_transfer_coding_is_refused(setup):
    srv, target = setup
    assert _put(srv, b"Transfer-Encoding: gzip, chunked\r\n", _chunked(b"abc")) == 501
    assert _put(srv, b"Transfer-Encoding: gzip\r\n", b"abc") == 400
    assert target.read_bytes() == OLD


# -- edge ----------------------------------------------------------------------------------


def test_edge_a_chunked_body_over_the_cap_keeps_the_file(setup, monkeypatch):
    srv, target = setup
    monkeypatch.setattr(RS, "MAX_BODY_BYTES", 8)
    assert _put(srv, TE, _chunked(b"12345", b"6789")) == 400
    assert target.read_bytes() == OLD


def test_edge_an_empty_chunked_body_is_an_empty_file_but_no_length_is_none(setup):
    srv, target = setup
    assert _put(srv, b"", b"") == 411
    assert target.read_bytes() == OLD
    assert _put(srv, TE, b"0\r\n\r\n") in (200, 201)
    assert target.read_bytes() == b""


def test_edge_s3_folder_marker_without_length_still_creates_the_folder(tmp_path):
    (tmp_path / "b").mkdir()
    srv = RS.serve_s3(LocalFS(), bind="127.0.0.1", port=0, root_path=str(tmp_path))
    try:
        assert _put(srv, b"", b"", path=b"/b/dir/") == 200
        assert _put(srv, TE, b"0\r\n\r\n", path=b"/b/dir2/") == 200
        assert _put(srv, TE, _chunked(b"x"), path=b"/b/dir3/") == 400
    finally:
        srv.shutdown()
    assert (tmp_path / "b" / "dir").is_dir() and (tmp_path / "b" / "dir2").is_dir()
    assert not (tmp_path / "b" / "dir3").exists()
