"""Reverse serve: what an answer may say (security review round 5).

Measured before (rserve/v_xss_leak, v_range, v_writes):

* Error answers named the served folder's absolute local path
  (``[Errno 22] not a regular file ...: '/home/<user>/share/b/fifo'``, the
  temp file of a failed PUT, both paths of a failed MOVE), and the HTML
  index of a folder had it as its title and heading.
* ``Range: bytes=<5000 digits>-`` raised ValueError in int() (Python's
  4300-digit limit): a traceback and a dropped connection, no answer.
* ``Destination: http://evil.example/b/x`` and ``//evil.example/b/f2``
  were taken as paths of this server: a MOVE meant for another host
  renamed a file here.
"""

from __future__ import annotations

import http.client
import os
import socket
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import reverse_serve as RS  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402

TOKEN = "r5-replies-" + "t" * 24


@pytest.fixture
def root(tmp_path):
    served = tmp_path / "share-root"
    (served / "b" / "d").mkdir(parents=True)
    (served / "b" / "f").write_bytes(b"old")
    (served / "b" / "ten").write_bytes(b"0123456789")
    (served / "b" / "d" / "inner").write_bytes(b"x")
    if hasattr(os, "mkfifo"):
        os.mkfifo(served / "b" / "fifo")
    return served


def _serve(root, kind="webdav"):
    fn = RS.serve_s3 if kind == "s3" else RS.serve_webdav
    return fn(LocalFS(), bind="127.0.0.1", port=0, root_path=str(root), auth_token=TOKEN)


def _request(server, method, path, body=None, headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", server.port, timeout=10)
    try:
        hdrs = {"Authorization": f"Bearer {TOKEN}"}
        hdrs.update(headers or {})
        conn.request(method, path, body=body, headers=hdrs)
        resp = conn.getresponse()
        return resp.status, resp.read()
    finally:
        conn.close()


def _raw(server, data: bytes) -> bytes:
    with socket.create_connection(("127.0.0.1", server.port), timeout=10) as s:
        s.sendall(data)
        out = b""
        try:
            while chunk := s.recv(65536):
                out += chunk
        except (socket.timeout, ConnectionResetError):
            pass
    return out


def _leaks(body: bytes, root: Path) -> bool:
    text = body.decode("utf-8", "replace")
    return str(root) in text or os.path.realpath(root) in text or str(root.parent) in text


# -- sad: local paths ---------------------------------------------------------------------


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFOs")
@pytest.mark.parametrize("kind", ["webdav", "s3"])
def test_sad_an_error_answer_names_no_local_path(root, kind):
    server = _serve(root, kind)
    try:
        status, body = _request(server, "GET", "/b/fifo")
        assert status >= 400
        assert not _leaks(body, root)
        assert b"/b/fifo" in body  # the path as the client named it
        status, body = _request(server, "PUT", "/b/f/x", body=b"data")
        assert status >= 400 and not _leaks(body, root)
    finally:
        server.shutdown()


def test_sad_a_failed_move_or_copy_names_no_local_path(root):
    server = _serve(root)
    try:
        status, body = _request(server, "MOVE", "/b", headers={"Destination": "/b/d/inner2"})
        assert status >= 400 and not _leaks(body, root)
        status, body = _request(server, "COPY", "/b/d", headers={"Destination": "/b/d2"})
        assert status >= 400 and not _leaks(body, root)
    finally:
        server.shutdown()


def test_sad_the_folder_index_names_no_local_path(root):
    server = _serve(root)
    try:
        status, body = _request(server, "GET", "/b/d/")
        assert status == 200
        assert not _leaks(body, root)
        assert b"<title>/b/d</title>" in body
    finally:
        server.shutdown()


# -- sad: numbers ---------------------------------------------------------------------------


@pytest.mark.parametrize("kind", ["webdav", "s3"])
def test_sad_a_range_start_of_5000_digits_is_416(root, kind):
    server = _serve(root, kind)
    try:
        status, _ = _request(server, "GET", "/b/ten", headers={"Range": "bytes=" + "9" * 5000 + "-"})
        assert status == 416
    finally:
        server.shutdown()


def test_edge_a_content_length_of_5000_digits_is_refused_with_an_answer(root):
    server = _serve(root)
    try:
        out = _raw(server, b"PUT /b/new HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer "
                   + TOKEN.encode() + b"\r\nContent-Length: " + b"9" * 5000 + b"\r\n\r\n")
        assert out.startswith(b"HTTP/1.1 4")
        assert not (root / "b" / "new").exists()
    finally:
        server.shutdown()


def test_sad_an_s3_decoded_length_of_5000_digits_is_refused_with_an_answer(root):
    server = _serve(root, "s3")
    try:
        out = _raw(server, b"PUT /b/new HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer "
                   + TOKEN.encode() + b"\r\nContent-Encoding: aws-chunked\r\n"
                   b"x-amz-decoded-content-length: " + b"9" * 5000
                   + b"\r\nContent-Length: 5\r\n\r\n0\r\n\r\n")
        assert out.startswith(b"HTTP/1.1 4")
    finally:
        server.shutdown()


# -- sad: Destination ------------------------------------------------------------------------


@pytest.mark.parametrize("destination", [
    "http://evil.example/b/moved",
    "//evil.example/b/moved",
    "http://127.0.0.1:1/b/moved",
])
@pytest.mark.parametrize("method", ["MOVE", "COPY"])
def test_sad_a_destination_on_another_server_is_502(root, destination, method):
    server = _serve(root)
    try:
        status, _ = _request(server, method, "/b/f", headers={"Destination": destination})
        assert status == 502
        assert (root / "b" / "f").read_bytes() == b"old"
        assert not (root / "b" / "moved").exists()
    finally:
        server.shutdown()


# -- happy ----------------------------------------------------------------------------------


@pytest.mark.parametrize("destination", [
    "/b/moved",
    "http://127.0.0.1:{port}/b/moved",
])
def test_happy_a_destination_on_this_server_moves(root, destination):
    server = _serve(root)
    try:
        status, _ = _request(server, "MOVE", "/b/f",
                             headers={"Destination": destination.format(port=server.port)})
        assert status == 201
        assert (root / "b" / "moved").read_bytes() == b"old"
    finally:
        server.shutdown()


def test_happy_ranges_still_answer(root):
    server = _serve(root)
    try:
        assert _request(server, "GET", "/b/ten", headers={"Range": "bytes=2-4"}) == (206, b"234")
        assert _request(server, "GET", "/b/ten",
                        headers={"Range": "bytes=0-" + "9" * 5000}) == (206, b"0123456789")
        assert _request(server, "GET", "/b/ten",
                        headers={"Range": "bytes=-" + "9" * 5000}) == (206, b"0123456789")
    finally:
        server.shutdown()


# -- edge -----------------------------------------------------------------------------------


@pytest.mark.parametrize("header, expected", [
    ("bytes=" + "0" * 5000 + "1-2", (1, 2)),       # leading zeros are no huge number
    ("bytes=" + "9" * 30 + "-", "unsatisfiable"),
    ("bytes=1-2\x0b", None),                          # only blanks and tabs around it
    ("bytes=٣-٤", None),                    # ASCII digits only
])
def test_edge_single_range_parsing(header, expected):
    assert RS._single_range(header, 10) == expected


def test_edge_a_destination_with_the_default_port_is_this_server():
    class _H(RS._DAVHandler):
        config = RS.ServerConfig(backend=LocalFS(), bind="example.org", port=80)

        def __init__(self):  # no socket: only the authority check
            self.headers = {"Host": "example.org"}

    handler = _H()
    assert handler._same_authority("example.org:80")
    assert handler._same_authority("EXAMPLE.org")
    assert not handler._same_authority("example.org:8080")
    assert not handler._same_authority("evil.example")
