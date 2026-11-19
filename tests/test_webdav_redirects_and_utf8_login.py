"""WebDAV: a redirect never turns a write into a "success", and a login
in UTF-8 works.

Protocol review (round 1):

* requests followed every redirect. A 302 (an SSO gateway whose session
  expired, a rewrite to a login page) turned PUT, DELETE, MOVE, MKCOL and
  PROPFIND into a GET of that page; its 200 was taken as success - an
  upload, delete, rename or mkdir reported done that never happened, a
  listing came back empty and exists() said False. A 307 to another
  host sent the file's content there.
* requests encodes Basic credentials as latin-1: a password with "€" or
  Cyrillic letters failed before any request, "café" went out as latin-1
  where Nextcloud / sabre expect UTF-8 (RFC 7617).

Now a method other than GET / HEAD follows a redirect only to the same
path on the same host (a trailing slash, http -> https), sending the
same request again; any other redirect is an error that names it.
"""

from __future__ import annotations

import base64
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

pytest.importorskip("requests")
pytest.importorskip("defusedxml")

from core.webdav_client import WebDavRequestError, WebDavSession  # noqa: E402

PROPFIND_OK = (b'<?xml version="1.0"?><d:multistatus xmlns:d="DAV:"><d:response>'
               b'<d:href>/dav/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/>'
               b'</d:resourcetype></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat>'
               b'</d:response></d:multistatus>')


class _Server:
    def __init__(self) -> None:
        self.mode = "ok"  # "ok" | "login" | "slash" | "other"
        self.log: list[tuple[str, str, bytes, str]] = []
        self.other_port = 0
        server = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _any(self):
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(n) if n else b""
                server.log.append((self.command, self.path, body,
                                   self.headers.get("Authorization", "")))
                if self.path.startswith("/login"):
                    return self._send(200, b"<html>Please log in</html>", "text/html")
                if server.mode == "login" and self.path.startswith("/dav"):
                    return self._redirect(302, "/login?next=x")
                if server.mode == "other" and self.path.startswith("/dav"):
                    return self._redirect(307, f"http://127.0.0.1:{server.other_port}/steal")
                if server.mode == "slash" and self.path == "/dav/folder":
                    return self._redirect(301, "/dav/folder/")
                if self.command == "PROPFIND":
                    return self._send(207, PROPFIND_OK, "application/xml")
                status = {"PUT": 201, "MKCOL": 201, "DELETE": 204, "MOVE": 201}.get(
                    self.command, 200)
                return self._send(status, b"", "text/plain")

            def _redirect(self, status, location):
                self.send_response(status)
                self.send_header("Location", location)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def _send(self, status, data, ctype):
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = do_PUT = do_DELETE = do_MOVE = do_MKCOL = do_PROPFIND = do_COPY = _any

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.httpd.server_port
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def servers():
    main, other = _Server(), _Server()
    main.other_port = other.port
    yield main, other
    main.close()
    other.close()


def _session(server, password="secret"):
    return WebDavSession(f"http://127.0.0.1:{server.port}/dav", "alice", password)


def _upload(s, path, data=b"x" * 1000):
    w = s.open_write(path)
    w.write(data)
    w.close()


@pytest.mark.parametrize("label", ["upload", "remove", "rename", "mkdir", "list_dir"])
def test_sad_a_redirect_to_a_login_page_is_no_success(servers, label):
    main, _other = servers
    s = _session(main)
    main.mode = "login"
    action = {
        "upload": lambda: _upload(s, "/file.bin"),
        "remove": lambda: s.remove("/file.bin"),
        "rename": lambda: s.rename("/a.txt", "/b.txt"),
        "mkdir": lambda: s.mkdir("/newdir"),
        "list_dir": lambda: s.list_dir("/"),
    }[label]
    with pytest.raises(OSError) as info:
        action()
    assert "redirect" in str(info.value).lower() or "login" in str(info.value).lower()
    assert not any(cmd == "GET" and path.startswith("/login") for cmd, path, *_ in main.log)


def test_sad_a_307_to_another_host_gets_no_file_content(servers):
    main, other = servers
    s = _session(main)
    main.mode = "other"
    with pytest.raises(WebDavRequestError):
        _upload(s, "/salaries.csv", b"name,salary\nbob,100000\n")
    assert other.log == []


def test_happy_same_path_redirect_is_followed_with_the_same_request(servers):
    main, _other = servers
    s = _session(main)
    main.mode = "slash"
    s.mkdir("/folder")
    sent = [(cmd, path) for cmd, path, *_ in main.log]
    assert ("MKCOL", "/dav/folder/") in sent
    assert all(cmd != "GET" for cmd, _ in sent)


def test_edge_a_utf8_password_logs_in_as_utf8(servers):
    main, _other = servers
    s = _session(main, password="café-€")
    assert s.exists("/")
    auth = [a for *_rest, a in main.log if a][-1]
    assert auth.startswith("Basic ")
    assert base64.b64decode(auth[6:]) == "alice:café-€".encode("utf-8")


def test_happy_plain_upload_still_works(servers):
    main, _other = servers
    s = _session(main)
    _upload(s, "/ok.bin", b"data")
    assert any(cmd == "PUT" and body == b"data" for cmd, _p, body, _a in main.log)
