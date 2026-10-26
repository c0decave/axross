"""WebDAV: every thread talks over a requests.Session of its own.

Before: one ``requests.Session`` carried every call of a WebDavSession, from
every thread (core/webdav_client.py ``_WebDavClient.session``). requests
never promised that a Session is thread safe (psf/requests#2766 names the
cookie jar), so the transfer scheduler carried one job at a time per
WebDAV session. Now each thread gets a Session of its own, built exactly
as the single one was (locked to the profile proxy, the axross
User-Agent), reused for every later call of that thread, closed when the
thread ends or the session disconnects.

Driven against a small threaded WebDAV server on 127.0.0.1.
"""

from __future__ import annotations

import gc
import hashlib
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

pytest.importorskip("requests")
pytest.importorskip("defusedxml")

from core import webdav_client as W  # noqa: E402
from core.client_identity import HTTP_USER_AGENT  # noqa: E402


class _Dav:
    """PROPFIND (Depth 0 on anything), GET, PUT; a PUT to a path in
    ``refuse`` gets 403."""

    def __init__(self, refuse=()):
        self.files: dict[str, bytes] = {}
        self.refuse = set(refuse)
        self.lock = threading.Lock()
        self.options = 0
        self.options_status = 200
        dav = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):
                pass

            def _reply(self, code, body=b"", ctype="application/octet-stream"):
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_PROPFIND(self):  # noqa: N802 - http.server naming
                length = int(self.headers.get("Content-Length") or 0)
                self.rfile.read(length)
                body = (
                    '<?xml version="1.0"?><d:multistatus xmlns:d="DAV:"><d:response>'
                    f"<d:href>{self.path}</d:href><d:propstat><d:prop>"
                    "<d:resourcetype><d:collection/></d:resourcetype>"
                    "</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat>"
                    "</d:response></d:multistatus>"
                ).encode()
                self._reply(207, body, "application/xml")

            def do_OPTIONS(self):  # noqa: N802
                dav.options += 1
                self._reply(dav.options_status)

            def do_GET(self):  # noqa: N802
                with dav.lock:
                    data = dav.files.get(self.path)
                if data is None:
                    self._reply(404)
                else:
                    self._reply(200, data)

            def do_PUT(self):  # noqa: N802
                length = int(self.headers.get("Content-Length") or 0)
                data = self.rfile.read(length)
                if self.path in dav.refuse:
                    self._reply(403)
                    return
                with dav.lock:
                    dav.files[self.path] = data
                self._reply(201)

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.httpd.daemon_threads = True
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()


def _in_threads(count, target, timeout=30.0):
    threads = [threading.Thread(target=target, args=(i,), daemon=True) for i in range(count)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout)
        assert not t.is_alive()


def _counting(client):
    """Count the Sessions *client* builds from now on, and their close()."""
    made = []
    real = client._new_session

    def new_session():
        session = real()
        session.closed_count = 0
        close = session.close

        def counted_close():
            session.closed_count += 1
            close()

        session.close = counted_close
        made.append(session)
        return session

    client._new_session = new_session
    return made


def _data(i: int) -> bytes:
    return hashlib.sha256(str(i).encode()).digest() * (1 + i % 50)


# ---------------------------------------------------------------- happy path


def test_happy_threads_put_and_get_byte_exact_on_one_session():
    with _Dav() as dav:
        s = W.WebDavSession(dav.url)
        made = _counting(s._client)
        errors = []

        def work(t):
            try:
                for r in range(10):
                    path = f"/t{t}-{r}.bin"
                    with s.open_write(path) as fh:
                        fh.write(_data(t * 100 + r))
                    with s.open_read(path) as fh:
                        if fh.read() != _data(t * 100 + r):
                            errors.append(path)
            except Exception as exc:  # noqa: BLE001
                errors.append(repr(exc))

        _in_threads(8, work)
        assert errors == []
        assert len(dav.files) == 80
        # One Session per thread, reused for its 20 requests.
        assert len(made) == 8
        s.close()


# ------------------------------------------------------------------ sad path


def test_sad_a_refused_put_in_one_thread_leaves_the_others_intact():
    with _Dav(refuse={"/bad"}) as dav:
        s = W.WebDavSession(dav.url)
        errors = {}

        def work(t):
            path = "/bad" if t == 2 else f"/ok{t}"
            try:
                with s.open_write(path) as fh:
                    fh.write(_data(t))
            except Exception as exc:  # noqa: BLE001
                errors[path] = exc

        _in_threads(5, work)
        assert list(errors) == ["/bad"]
        assert isinstance(errors["/bad"], OSError)
        assert all(dav.files[f"/ok{t}"] == _data(t) for t in (0, 1, 3, 4))
        s.close()


def test_sad_close_closes_every_thread_s_session():
    with _Dav() as dav:
        s = W.WebDavSession(dav.url)
        made = _counting(s._client)
        release = threading.Event()
        ready = threading.Barrier(4)

        def hold(t):
            s.stat("/")
            ready.wait(10)
            release.wait(10)  # the thread (and its Session) stays alive

        threads = [threading.Thread(target=hold, args=(i,), daemon=True) for i in range(3)]
        for t in threads:
            t.start()
        ready.wait(10)
        assert len(made) == 3
        s.close()
        assert [m.closed_count for m in made] == [1, 1, 1]
        release.set()
        for t in threads:
            t.join(10)
        # After a close a thread gets a fresh Session, not a closed one.
        s.stat("/")
        assert len(made) == 4
        s.close()


# ---------------------------------------------------------------- edge cases


def test_edge_each_thread_has_its_own_session_and_reuses_it():
    with _Dav() as dav:
        s = W.WebDavSession(dav.url)
        seen: dict[int, list[int]] = {}

        def work(t):
            ids = []
            for _ in range(3):
                s.stat("/")
                ids.append(id(s._client.session))
            seen[t] = ids

        _in_threads(4, work)
        assert all(len(set(ids)) == 1 for ids in seen.values())  # reused
        assert len({ids[0] for ids in seen.values()}) == 4  # one per thread
        s.close()


def test_edge_every_thread_session_is_locked_to_the_profile_proxy(monkeypatch):
    # An environment proxy must not leak into any thread's Session.
    monkeypatch.setenv("HTTP_PROXY", "http://env-proxy.invalid:1")
    monkeypatch.setenv("HTTPS_PROXY", "http://env-proxy.invalid:1")
    proxies = {"http": "http://u:p@proxy.example:3128", "https": "http://u:p@proxy.example:3128"}
    client = W._WebDavClient("http://dav.example/dav", "user", "pw", proxies=proxies)
    sessions = {}

    def grab(t):
        sessions[t] = client.session

    _in_threads(4, grab)
    sessions["main"] = client.session
    assert len({id(x) for x in sessions.values()}) == 5
    for session in sessions.values():
        assert session.trust_env is False
        assert session.proxies == proxies
        assert session.headers["User-Agent"] == HTTP_USER_AGENT
    client.close()


def test_edge_without_a_profile_proxy_no_thread_inherits_the_environment(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://env-proxy.invalid:1")
    client = W._WebDavClient("https://dav.example/dav", "", "")
    out = []
    _in_threads(3, lambda t: out.append(client.session))
    for session in out:
        assert session.trust_env is False
        assert not session.proxies
    client.close()


def test_edge_a_finished_thread_s_session_is_closed():
    with _Dav() as dav:
        s = W.WebDavSession(dav.url)
        made = _counting(s._client)
        _in_threads(2, lambda t: s.stat("/"))
        gc.collect()
        assert len(made) == 2
        assert [m.closed_count for m in made] == [1, 1]
        s.close()
        assert [m.closed_count for m in made] == [1, 1]  # not closed twice


def test_edge_auth_and_timeout_go_with_every_thread_s_requests():
    client = W._WebDavClient("http://dav.example/dav", "user", "pw", timeout=7.5)
    calls = []

    class _Fake:
        def request(self, method, url, **kwargs):
            calls.append((threading.get_ident(), kwargs["auth"], kwargs["timeout"]))
            return object()

        def close(self):
            pass

    client._new_session = _Fake
    _in_threads(3, lambda t: client._request("GET", "/x"))
    assert len({c[0] for c in calls}) == 3
    assert all(c[1:] == (("user", "pw"), 7.5) for c in calls)
    client.close()


def test_happy_the_health_probe_reaches_a_webdav_session():
    """core.conn_health probed WebDAV through ``session._session`` /
    ``session.session`` and ``_base_url``, none of which a WebDavSession
    has: the probe failed every time ("no requests.Session/url to
    probe"). It now asks the session's client, over the probing thread's
    own Session."""
    from core.conn_health import _probe_webdav

    with _Dav() as dav:
        s = W.WebDavSession(dav.url)
        made = _counting(s._client)
        _in_threads(1, lambda t: _probe_webdav(s))
        assert dav.options == 1
        assert len(made) == 1  # the probing thread's own Session
        s.close()


def test_sad_the_health_probe_reports_a_server_error():
    from core.conn_health import _probe_webdav

    with _Dav() as dav:
        s = W.WebDavSession(dav.url)
        dav.options_status = 503
        with pytest.raises(OSError, match="503"):
            _probe_webdav(s)
        s.close()
