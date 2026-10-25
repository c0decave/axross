"""A local fake of the three GitHub hosts the self-update talks to.

One ``http.server`` on loopback answers for every host and tells them apart
by the ``Host`` header, the way the real chain looks (measured 2026-10-25):

* ``api.github.com``  ``/repos/c0decave/axross/releases/latest`` - the JSON
* ``github.com``      ``/c0decave/axross/releases/download/vX/<name>`` -
  302 to the asset host
* ``release-assets.githubusercontent.com`` - the bytes

:class:`FakeHttpsHandler` makes urllib's ``https://`` requests reach this
server in plain HTTP, Host header unchanged, so the code under test keeps
its real https URLs, host checks and redirect handling. ``tls=`` serves the
same routes over real TLS (for the proxy test, through a CONNECT proxy).
"""

from __future__ import annotations

import hashlib
import http.client
import http.server
import json
import ssl
import threading
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

API_HOST = "api.github.com"
WEB_HOST = "github.com"
ASSET_HOST = "release-assets.githubusercontent.com"
REPO = "c0decave/axross"


@dataclass
class FakeRelease:
    version: str
    files: dict[str, bytes] = field(default_factory=dict)
    prerelease: bool = False
    draft: bool = False
    notes: str = "## What is new\n\n- faster\n"
    #: name -> the SHA256SUMS line's hash (None: computed); a name mapped to
    #: "" is left out of SHA256SUMS.
    sums_override: dict[str, str] = field(default_factory=dict)
    #: Leave the SHA256SUMS asset out of the release.
    without_sums: bool = False
    #: name -> the API's "digest" ("" leaves it out; None: computed).
    digest_override: dict[str, str] = field(default_factory=dict)
    #: name -> the size the API states (None: the real size).
    size_override: dict[str, int] = field(default_factory=dict)

    @property
    def tag(self) -> str:
        return f"v{self.version}"

    def sums_text(self) -> str:
        lines = []
        for name, data in self.files.items():
            digest = self.sums_override.get(name)
            if digest == "":
                continue
            lines.append(f"{digest or hashlib.sha256(data).hexdigest()}  {name}")
        return "\n".join(lines) + "\n"

    def all_files(self) -> dict[str, bytes]:
        files = dict(self.files)
        if not self.without_sums:
            files["SHA256SUMS"] = self.sums_text().encode()
        return files

    def json(self) -> dict:
        assets = []
        for name, data in self.all_files().items():
            digest = self.digest_override.get(name)
            entry = {
                "name": name,
                "size": self.size_override.get(name, len(data)),
                "browser_download_url":
                    f"https://{WEB_HOST}/{REPO}/releases/download/{self.tag}/{name}",
                "content_type": "application/octet-stream",
            }
            if digest != "":
                entry["digest"] = f"sha256:{digest or hashlib.sha256(data).hexdigest()}"
            assets.append(entry)
        return {
            "tag_name": self.tag,
            "name": f"axross {self.version}",
            "html_url": f"https://{WEB_HOST}/{REPO}/releases/tag/{self.tag}",
            "draft": self.draft,
            "prerelease": self.prerelease,
            "body": self.notes,
            "assets": assets,
        }


class _QuietServer(http.server.ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        """A client that hangs up early (a refused oversized answer, a
        cancel) is what several tests do on purpose: no traceback."""
        import sys

        if not isinstance(sys.exc_info()[1], (BrokenPipeError, ConnectionResetError)):
            super().handle_error(request, client_address)


class FakeGitHub:
    """The server. ``release`` is what releases/latest answers; the other
    attributes change how it answers (status, raw body, redirects, ...)."""

    def __init__(self, release: FakeRelease | None = None, *,
                 tls: tuple[str, str] | None = None) -> None:
        self.release = release
        self.requests: list[tuple[str, str]] = []  # (host, path) in order
        self.api_status = 200
        self.api_headers: dict[str, str] = {}
        self.api_body: bytes | None = None  # raw body instead of the JSON
        self.api_delay = 0.0
        self.redirect_to = f"https://{ASSET_HOST}"  # where github.com sends a download
        self.redirect_loop = False
        self.asset_status = 200
        #: name -> bytes served instead of the real file (wrong content).
        self.served_override: dict[str, bytes] = {}
        #: name -> stop after this many bytes and close (a cut connection).
        self.cut_after: dict[str, int] = {}
        #: Called with the byte count as an asset is served (for cancel tests).
        self.on_chunk = None
        self._lock = threading.Lock()
        handler = self._handler_class()
        self.server = _QuietServer(("127.0.0.1", 0), handler)
        self.server.daemon_threads = True
        if tls is not None:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(*tls)
            self.server.socket = ctx.wrap_socket(self.server.socket, server_side=True)
        self.port = self.server.server_address[1]
        self._thread = threading.Thread(target=self.server.serve_forever,
                                        kwargs={"poll_interval": 0.02}, daemon=True)
        self._thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def hosts(self) -> list[str]:
        with self._lock:
            return [h for h, _ in self.requests]

    def api_requests(self) -> int:
        return self.hosts().count(API_HOST)

    # -- serving -------------------------------------------------------------
    def _handler_class(self):
        fake = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):  # noqa: D401 - silence
                pass

            def do_GET(self):  # noqa: N802 - http.server API
                host = (self.headers.get("Host") or "").split(":")[0]
                with fake._lock:
                    fake.requests.append((host, self.path))
                path = urllib.parse.urlsplit(self.path).path
                if host == API_HOST:
                    return self._api(path)
                if host == WEB_HOST:
                    return self._web(path)
                if host in (ASSET_HOST, "objects.githubusercontent.com"):
                    return self._asset(path)
                self._send(404, b"unknown host")

            def _send(self, status, body=b"", headers=None, ctype="application/octet-stream"):
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                if body:
                    self.wfile.write(body)

            def _api(self, path):
                if fake.api_delay:
                    time.sleep(fake.api_delay)
                if path != f"/repos/{REPO}/releases/latest":
                    return self._send(404, b'{"message": "Not Found"}')
                if fake.api_status != 200:
                    return self._send(fake.api_status, b'{"message": "API rate limit exceeded"}',
                                      fake.api_headers, "application/json")
                if fake.api_body is not None:
                    body = fake.api_body
                elif fake.release is None:
                    return self._send(404, b'{"message": "Not Found"}')
                else:
                    body = json.dumps(fake.release.json()).encode()
                self._send(200, body, fake.api_headers, "application/json; charset=utf-8")

            def _web(self, path):
                prefix = f"/{REPO}/releases/download/"
                if not path.startswith(prefix) or fake.release is None:
                    return self._send(404)
                tag, _, name = path[len(prefix):].partition("/")
                if tag != fake.release.tag or name not in fake.release.all_files():
                    return self._send(404)
                if fake.redirect_loop:
                    location = f"https://{WEB_HOST}{path}"
                else:
                    location = (f"{fake.redirect_to}/github-production-release-asset/1/{name}"
                                f"?sig=abc&rscd=attachment%3B+filename%3D{name}")
                self._send(302, b"", {"Location": location})

            def _asset(self, path):
                name = path.rsplit("/", 1)[-1]
                files = fake.release.all_files() if fake.release else {}
                if fake.asset_status != 200:
                    return self._send(fake.asset_status)
                if name not in files:
                    return self._send(404)
                data = fake.served_override.get(name, files[name])
                cut = fake.cut_after.get(name)
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                sent = 0
                step = 65536
                while sent < len(data):
                    end = min(len(data), sent + step)
                    if cut is not None and end > cut:
                        self.wfile.write(data[sent:cut])
                        self.wfile.flush()
                        self.close_connection = True
                        return
                    self.wfile.write(data[sent:end])
                    sent = end
                    if fake.on_chunk is not None:
                        fake.on_chunk(sent)

        return Handler


class FakeHttpsHandler(urllib.request.HTTPSHandler):
    """urllib's https handler, but every https request goes to the fake in
    plain HTTP. The URL, and with it the Host header, stays the real one."""

    def __init__(self, port: int) -> None:
        super().__init__()
        self._port = port

    def https_open(self, req):
        port = self._port

        def connect(host, timeout=None, **_kwargs):
            return http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)

        return self.do_open(connect, req)


def newer_than(version: str, step: int = 1) -> str:
    major, minor, patch = (int(p) for p in version.split("."))
    return f"{major}.{minor}.{patch + step}"


def older_than(version: str) -> str:
    major, minor, patch = (int(p) for p in version.split("."))
    if patch:
        return f"{major}.{minor}.{patch - 1}"
    return f"{major}.{minor - 1}.0" if minor else f"{major - 1}.0.0"
