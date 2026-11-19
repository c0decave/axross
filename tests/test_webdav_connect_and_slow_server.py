"""WebDAV: a refused login says so, and a server that works a while on a PUT,
MOVE, COPY or DELETE before it answers is waited for.

Measured with wsgidav and core.reverse_serve's WebDAV server:

* a wrong password: "Cannot connect to WebDAV server: WebDAV PROPFIND
  http://host/dav/: HTTP 401" - the raw request line;
* a closed port: "did not answer in time" (urllib3's NewConnectionError
  subclasses ConnectTimeoutError; fixed in core.user_errors);
* every request had one 30 s time-out, also for the answer to a PUT: a
  Nextcloud that assembles, scans or encrypts a large upload before it
  answers (or a MOVE / DELETE of a large folder on the server) failed the
  transfer with "did not answer in time" although the server finished it.
"""

from __future__ import annotations

import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

pytest.importorskip("requests")
pytest.importorskip("defusedxml")

from core import reverse_serve  # noqa: E402
from core.ram_fs import RamFsSession  # noqa: E402
from core.user_errors import describe  # noqa: E402
from core.webdav_client import WebDavSession, _WebDavClient  # noqa: E402

TOKEN = "token-of-the-test-0123456789"


@pytest.fixture(autouse=True)
def _no_proxy_env(monkeypatch):
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY",
                 "all_proxy"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def dav():
    ram = RamFsSession()
    server = reverse_serve.serve_webdav(ram, bind="127.0.0.1", port=0, auth_token=TOKEN)
    yield server
    server.shutdown()


def test_happy_the_right_password_connects(dav):
    session = WebDavSession(dav.base_url, "anyone", TOKEN)
    assert session.list_dir("/") == [] and session.connected


def test_sad_a_wrong_password_is_a_refused_login(dav):
    with pytest.raises(PermissionError) as info:
        WebDavSession(dav.base_url, "anyone", "wrong")
    text = describe(info.value)
    assert "refused the login" in text and "password" in text
    assert "HTTP 401" not in text and "PROPFIND" not in text


def test_sad_a_closed_port_is_a_refused_connection():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    with pytest.raises(OSError) as info:
        WebDavSession(f"http://127.0.0.1:{port}/dav", "u", "p")
    assert "refused the connection" in describe(info.value)


class _SlowServer(BaseHTTPRequestHandler):
    """PROPFIND answers at once; PUT / MOVE / COPY / DELETE take DELAY
    seconds - a server finishing a large upload or a folder move."""

    protocol_version = "HTTP/1.1"
    DELAY = 1.5

    def log_message(self, *_args) -> None:
        pass

    def _finish(self, status: int) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        elif self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            while True:
                size = int(self.rfile.readline().strip() or b"0", 16)
                self.rfile.read(size + 2)
                if size == 0:
                    break
        if self.command != "PROPFIND":
            time.sleep(self.DELAY)
        self.send_response(status)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_PROPFIND(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        body = (b'<?xml version="1.0"?><d:multistatus xmlns:d="DAV:"><d:response>'
                b"<d:href>/dav/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/>"
                b"</d:resourcetype></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat>"
                b"</d:response></d:multistatus>")
        self.send_response(207)
        self.send_header("Content-Type", "application/xml")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_PUT(self) -> None:  # noqa: N802
        self._finish(201)

    def do_MOVE(self) -> None:  # noqa: N802
        self._finish(201)

    def do_COPY(self) -> None:  # noqa: N802
        self._finish(201)

    def do_DELETE(self) -> None:  # noqa: N802
        self._finish(204)


@pytest.fixture
def slow():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _SlowServer)
    httpd.daemon_threads = True
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}/dav"
    httpd.shutdown()
    httpd.server_close()


def test_happy_a_server_that_works_on_a_put_before_it_answers_is_waited_for(slow):
    # The time-out of the connection and of every other answer: 1 s here
    # (30 s in the app), shorter than the server's work.
    client = _WebDavClient(slow, "u", "p", timeout=1.0)
    import io

    client.upload_from(io.BytesIO(b"x" * 1000), "/big.bin")
    client.move("/big.bin", "/moved.bin")
    client.copy("/moved.bin", "/copy.bin")
    client.delete("/copy.bin")


def test_sad_a_server_that_does_not_answer_a_listing_still_times_out(slow):
    client = _WebDavClient(slow, "u", "p", timeout=1.0)
    _SlowServer.DELAY = 1.5
    # PROPFIND answers at once here; the read time-out of a listing is the
    # short one (checked on the request's arguments).
    seen = {}
    real = client.session.request

    def spy(method, url, **kwargs):
        seen[method] = kwargs.get("timeout")
        return real(method, url, **kwargs)

    client.session.request = spy
    client.info("/")
    timeout = seen["PROPFIND"]
    assert (timeout if isinstance(timeout, (int, float)) else max(timeout)) <= 1.0
