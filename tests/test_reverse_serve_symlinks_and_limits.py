"""Reverse-serve: symlinks out of the served root, connection and header
limits, strict request framing (security review round 3).

Measured before, on LocalFS with both flavours:

* A symlink in the served tree that points out of it was followed: GET
  of ``b/link.txt -> ../outside.txt`` returned the outside file, a PUT
  through ``b/dirlink -> ..`` wrote beside the root, a PUT onto the file
  link overwrote its target and a WebDAV DELETE through the folder link
  removed an outside file. The checks were lexical only
  (``_rooted_join``); S3 listings walked into symlinked folders.
* Every connection held a thread with no limit (400 half-open clients
  held 400 threads before sending a token), and a client sending a header
  byte now and then was never cut off: the timeout was per read.
* ``Content-Length`` went through ``int()`` (``+5``, ``1_0``), and of two
  that differ the first one framed the body.
* A NUL in the path (``%00``) raised inside the backend: no answer.
"""

from __future__ import annotations

import os
import socket
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import reverse_serve as RS  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402

TOKEN = "t" * 32


@pytest.fixture
def root(tmp_path):
    served = tmp_path / "root"
    (served / "b" / "sub").mkdir(parents=True)
    (served / "b" / "a.txt").write_bytes(b"inside")
    (served / "b" / "sub" / "s.txt").write_bytes(b"in sub")
    (tmp_path / "outside.txt").write_bytes(b"OUTSIDE-SECRET")
    os.symlink(str(tmp_path / "outside.txt"), str(served / "b" / "link.txt"))
    os.symlink(str(tmp_path), str(served / "b" / "dirlink"))
    os.symlink(str(served / "b" / "a.txt"), str(served / "b" / "inner.txt"))
    return served


def _serve(kind, root, **kw):
    fn = RS.serve_s3 if kind == "s3" else RS.serve_webdav
    return fn(LocalFS(), bind="127.0.0.1", port=0, root_path=str(root), auth_token=TOKEN, **kw)


def _raw(port, data: bytes, timeout: float = 5.0) -> bytes:
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as s:
        s.sendall(data)
        out = b""
        try:
            while chunk := s.recv(65536):
                out += chunk
        except (socket.timeout, ConnectionResetError):
            pass
    return out


def _request(port, method, path, body=b"", extra=""):
    head = (f"{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {TOKEN}\r\n"
            f"Content-Length: {len(body)}\r\nConnection: close\r\n{extra}\r\n")
    out = _raw(port, head.encode() + body)
    return int(out.split(b" ", 2)[1]), out


# -- sad: symlinks out of the root --------------------------------------------------------


@pytest.mark.parametrize("kind", ["s3", "webdav"])
def test_sad_a_symlink_out_of_the_served_root_is_refused(root, kind):
    server = _serve(kind, root)
    try:
        for path in ("/b/link.txt", "/b/dirlink/outside.txt"):
            status, out = _request(server.port, "GET", path)
            assert status >= 400 and b"OUTSIDE-SECRET" not in out, path
        status, _ = _request(server.port, "PUT", "/b/dirlink/planted.txt", b"PLANTED")
        assert status >= 400 and not (root.parent / "planted.txt").exists()
        status, _ = _request(server.port, "PUT", "/b/link.txt", b"OVERWRITTEN")
        assert status >= 400 and (root.parent / "outside.txt").read_bytes() == b"OUTSIDE-SECRET"
        status, _ = _request(server.port, "DELETE", "/b/dirlink/outside.txt")
        assert status >= 400 and (root.parent / "outside.txt").exists()
    finally:
        server.shutdown()


@pytest.mark.parametrize("kind", ["s3", "webdav"])
def test_happy_a_symlink_inside_the_root_is_served_and_a_link_is_deleted_itself(root, kind):
    server = _serve(kind, root)
    try:
        status, out = _request(server.port, "GET", "/b/inner.txt")
        assert status == 200 and out.endswith(b"inside")
        status, _ = _request(server.port, "DELETE", "/b/link.txt")  # the link, not its target
        assert status in (200, 204) and not os.path.lexists(root / "b" / "link.txt")
        assert (root.parent / "outside.txt").read_bytes() == b"OUTSIDE-SECRET"
    finally:
        server.shutdown()


def test_sad_a_webdav_move_through_a_folder_link_is_refused(root):
    server = _serve("webdav", root)
    try:
        status, _ = _request(server.port, "MOVE", "/b/dirlink/outside.txt",
                             extra="Destination: /b/stolen.txt\r\n")
        assert status >= 400 and not (root / "b" / "stolen.txt").exists()
        status, _ = _request(server.port, "MOVE", "/b/a.txt", extra="Destination: /b/dirlink/a.txt\r\n")
        assert status >= 400 and (root / "b" / "a.txt").exists()
    finally:
        server.shutdown()


class _LinkedFoldersFS(LocalFS):
    """Lists a symlinked folder as a folder that is a link - as SFTP and
    other backends do (LocalFS itself reports the link, not a folder)."""

    def list_dir(self, path):
        from dataclasses import replace

        return [replace(item, is_dir=True) if item.is_link and os.path.isdir(os.path.join(path, item.name))
                else item for item in super().list_dir(path)]


def test_edge_an_s3_listing_does_not_walk_into_a_symlinked_folder(root):
    server = RS.serve_s3(_LinkedFoldersFS(), bind="127.0.0.1", port=0, root_path=str(root),
                         auth_token=TOKEN)
    try:
        status, out = _request(server.port, "GET", "/b?list-type=2")
        assert status == 200
        assert b"<Key>sub/s.txt</Key>" in out and b"dirlink/" not in out
    finally:
        server.shutdown()


# -- sad: framing --------------------------------------------------------------------------


@pytest.mark.parametrize("kind", ["s3", "webdav"])
def test_sad_content_length_is_digits_and_one_value(root, kind):
    server = _serve(kind, root)
    try:
        head = (f"PUT /b/cl.txt HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {TOKEN}\r\n"
                "Connection: close\r\n")
        for lengths, body in ((["+5"], b"abcde"), (["1_0"], b"0123456789"), (["3", "10"], b"abcdefghij")):
            framing = "".join(f"Content-Length: {n}\r\n" for n in lengths)
            out = _raw(server.port, (head + framing + "\r\n").encode() + body)
            assert out.startswith(b"HTTP/1.0 400"), (lengths, out[:60])
            assert not (root / "b" / "cl.txt").exists()
        out = _raw(server.port, (head + "Content-Length: 5\r\nContent-Length: 5\r\n\r\n").encode() + b"abcde")
        assert out.split(b" ", 2)[1] in (b"200", b"201")
    finally:
        server.shutdown()


@pytest.mark.parametrize("kind", ["s3", "webdav"])
def test_sad_a_nul_in_the_path_is_a_400(root, kind):
    server = _serve(kind, root)
    try:
        status, _ = _request(server.port, "GET", "/b/a%00.txt")
        assert status == 400
    finally:
        server.shutdown()


# -- sad: limits ---------------------------------------------------------------------------


def test_sad_connections_beyond_the_limit_are_answered_503(root, monkeypatch):
    monkeypatch.setattr(RS, "MAX_CONNECTIONS", 4)
    server = _serve("webdav", root)
    held = []
    try:
        for _ in range(4):
            c = socket.create_connection(("127.0.0.1", server.port), timeout=5)
            c.sendall(b"GET / HTTP/1.1\r\n")  # never finishes its headers
            held.append(c)
        time.sleep(0.3)
        out = _raw(server.port, b"GET /b/a.txt HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        assert out.startswith(b"HTTP/1.1 503") or out == b""
        for c in held:
            c.close()
        held.clear()
        deadline = time.monotonic() + 5
        while True:  # the slots come back once the held connections end
            status, out = _request(server.port, "GET", "/b/a.txt")
            if status == 200 or time.monotonic() > deadline:
                break
            time.sleep(0.1)
        assert status == 200 and out.endswith(b"inside")
    finally:
        for c in held:
            c.close()
        server.shutdown()


def test_sad_a_client_trickling_its_headers_meets_the_deadline(root, monkeypatch):
    monkeypatch.setattr(RS, "HEADER_DEADLINE_S", 1.0)
    server = _serve("webdav", root)
    try:
        c = socket.create_connection(("127.0.0.1", server.port), timeout=5)
        c.sendall(b"GET /b/a.txt HTTP/1.1\r\n")
        start = time.monotonic()
        closed = False
        while time.monotonic() - start < 4:
            time.sleep(0.3)  # well inside the per-read timeout
            try:
                c.sendall(b"X-a: b\r\n")
                c.settimeout(0.05)
                if c.recv(10) == b"":
                    closed = True
                    break
            except socket.timeout:
                continue
            except OSError:
                closed = True
                break
        c.close()
        assert closed and time.monotonic() - start < 3
    finally:
        server.shutdown()
