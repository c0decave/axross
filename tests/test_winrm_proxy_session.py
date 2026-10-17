"""A WinRM profile with a proxy connects through it.

pywinrm builds its requests.Session lazily, on the first message.
WinRMSession looked for that session right after construction, found
None and - with a proxy configured - refused every connect ("did not
expose a requests-like session"); without a proxy the User-Agent and
the environment-proxy lock were silently never applied. The overrides
now run whenever pywinrm builds its session, and the proxy is handed to
pywinrm too, so even its first (encryption setup) request goes through
it. A loopback listener plays the HTTP proxy; nothing leaves 127.0.0.1.
"""

from __future__ import annotations

import socket
import threading

import pytest

pytest.importorskip("winrm")
from core import winrm_client as WC  # noqa: E402
from core.client_identity import HTTP_USER_AGENT  # noqa: E402


@pytest.fixture
def proxy(monkeypatch):
    monkeypatch.setenv("AXROSS_ALLOW_PRIVATE_PROXY", "1")
    for k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.delenv(k, raising=False)
    srv = socket.create_server(("127.0.0.1", 0))
    seen: list[bytes] = []

    def serve():
        while True:
            try:
                c, _ = srv.accept()
            except OSError:
                return
            with c:
                c.settimeout(2)
                try:
                    seen.append(c.recv(4096))
                    c.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                except OSError:
                    pass

    threading.Thread(target=serve, daemon=True).start()
    try:
        yield srv.getsockname()[1], seen
    finally:
        srv.close()


def _transport(s):
    return s._session.protocol.transport


def test_happy_proxy_profile_constructs_and_its_session_uses_the_proxy(proxy):
    port, _seen = proxy
    s = WC.WinRMSession(
        "win.example.test", "u", "p", proxy_type="http", proxy_host="127.0.0.1", proxy_port=port
    )
    req = _transport(s).build_session()
    assert req.proxies.get("https") == f"http://127.0.0.1:{port}"
    assert req.trust_env is False
    assert req.headers["User-Agent"] == HTTP_USER_AGENT


def test_sad_first_request_goes_to_the_proxy_not_the_host(proxy):
    port, seen = proxy
    s = WC.WinRMSession(
        "win.example.test",
        "u",
        "p",
        port=5985,
        use_https=False,
        proxy_type="http",
        proxy_host="127.0.0.1",
        proxy_port=port,
    )
    with pytest.raises(Exception):  # noqa: B017 - the fake proxy answers 502
        s._session.protocol.transport.send_message(b"<x/>")
    assert seen and seen[0].startswith(b"POST http://win.example.test:5985/wsman")


def test_edge_no_proxy_still_gets_the_overrides(proxy, monkeypatch):
    port, _seen = proxy
    monkeypatch.setenv("HTTPS_PROXY", f"http://127.0.0.1:{port}")
    s = WC.WinRMSession("win.example.test", "u", "p")
    req = _transport(s).build_session()
    assert req.headers["User-Agent"] == HTTP_USER_AGENT
    assert req.trust_env is False
    assert not req.proxies.get("https")
