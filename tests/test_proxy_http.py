"""HTTPS proxies, NTLM / Negotiate auth and the loopback shim."""

from __future__ import annotations

import socket
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import proxy  # noqa: E402
from core import proxy_http as PH  # noqa: E402
from tests.proxy_http_testkit import (  # noqa: E402
    FakeHttpProxy,
    OriginHttpServer,
    TestPki,
)
from tests.proxy_testkit import EchoServer, FakeSocks5Server, allow_loopback_proxy  # noqa: E402


def _cfg(port: int, ptype: str = "http", user: str = "", pw: str = "", ca: str = ""):
    return proxy.ProxyConfig(ptype, "127.0.0.1", port, user, pw, ca)


class ProxyTypeParsingTest(unittest.TestCase):
    def test_valid_kinds(self) -> None:
        for kind, want in (
            ("socks4", ("socks4", "")),
            ("socks5", ("socks5", "")),
            ("http", ("http", "")),
            ("https", ("https", "")),
            ("http+ntlm", ("http", "ntlm")),
            ("HTTPS+Negotiate", ("https", "negotiate")),
            ("http+kerberos", ("http", "kerberos")),
            ("https+basic", ("https", "basic")),
        ):
            self.assertEqual(proxy.parse_proxy_type(kind), want, kind)

    def test_invalid_kinds(self) -> None:
        for bad in ("", "ftp", "socks5+ntlm", "http+digest", "+ntlm", "https+", "http+ntlm+x"):
            with self.assertRaises(ValueError, msg=bad):
                proxy.parse_proxy_type(bad)

    def test_is_valid_proxy_type(self) -> None:
        self.assertTrue(proxy.is_valid_proxy_type("none"))
        self.assertTrue(proxy.is_valid_proxy_type("https+ntlm"))
        self.assertFalse(proxy.is_valid_proxy_type("carrier-pigeon"))

    def test_config_properties(self) -> None:
        c = proxy.ProxyConfig("https+ntlm", "p", 3128)
        self.assertEqual((c.transport, c.auth_scheme, c.needs_shim), ("https", "ntlm", True))
        c = proxy.ProxyConfig("http", "p", 3128, "u", "pw")
        self.assertEqual((c.transport, c.auth_scheme, c.needs_shim), ("http", "", False))
        c = proxy.ProxyConfig("socks5", "p", 1080)
        self.assertEqual((c.transport, c.needs_shim), ("socks5", True))
        self.assertEqual(proxy.ProxyConfig("none").transport, "none")

    def test_unknown_type_still_fails_closed_at_connect(self) -> None:
        with allow_loopback_proxy(), self.assertRaises(ValueError):
            proxy.create_proxy_socket(_cfg(9, "gopher"), "h", 1)


class HttpsProxyTest(unittest.TestCase):
    def setUp(self) -> None:
        self.pki = TestPki()
        self.echo = EchoServer()
        self.addCleanup(self.echo.close)
        self.routes = {("db.internal", 5432): ("127.0.0.1", self.echo.port)}
        patcher = allow_loopback_proxy()
        patcher.__enter__()
        self.addCleanup(patcher.__exit__, None, None, None)

    def _proxy(self, **kw) -> FakeHttpProxy:
        srv = FakeHttpProxy(self.routes, **kw)
        self.addCleanup(srv.close)
        return srv

    def _talk(self, cfg) -> bytes:
        s = proxy.create_proxy_socket(cfg, "db.internal", 5432, timeout=5)
        self.addCleanup(s.close)
        s.settimeout(5)
        banner = s.recv(6)
        s.sendall(b"ping")
        return banner + s.recv(4)

    def test_tls_to_the_proxy_with_a_pinned_ca(self) -> None:
        cert = self.pki.issue("127.0.0.1")
        srv = self._proxy(tls=cert)
        self.assertEqual(self._talk(_cfg(srv.port, "https", ca=self.pki.ca_file)), b"HELLO\nping")
        self.assertEqual(srv.connects, ["db.internal:5432"])

    def test_untrusted_proxy_certificate_is_refused(self) -> None:
        other = TestPki()
        srv = self._proxy(tls=other.issue("127.0.0.1"))
        with self.assertRaises(ConnectionError) as ctx:
            self._talk(_cfg(srv.port, "https", ca=self.pki.ca_file))
        self.assertIn("TLS to proxy", str(ctx.exception))
        self.assertEqual(srv.connects, [])

    def test_certificate_for_the_wrong_name_is_refused(self) -> None:
        srv = self._proxy(tls=self.pki.issue("proxy.example.org"))
        with self.assertRaises(ConnectionError):
            self._talk(_cfg(srv.port, "https", ca=self.pki.ca_file))

    def test_an_expired_certificate_is_refused(self) -> None:
        srv = self._proxy(tls=self.pki.issue("127.0.0.1", days=-2))
        with self.assertRaises(ConnectionError):
            self._talk(_cfg(srv.port, "https", ca=self.pki.ca_file))

    def test_plain_http_to_a_tls_proxy_fails_cleanly(self) -> None:
        srv = self._proxy(tls=self.pki.issue("127.0.0.1"))
        with self.assertRaises(ConnectionError):
            self._talk(_cfg(srv.port, "http"))

    def test_tls_to_a_plain_proxy_fails_cleanly(self) -> None:
        srv = self._proxy()
        with self.assertRaises(ConnectionError):
            self._talk(_cfg(srv.port, "https", ca=self.pki.ca_file))

    def test_system_store_is_used_without_a_ca_file(self) -> None:
        srv = self._proxy(tls=self.pki.issue("127.0.0.1"))
        with self.assertRaises(ConnectionError):  # test CA is not in the system store
            self._talk(_cfg(srv.port, "https"))

    def test_ca_file_falls_back_to_the_environment(self) -> None:
        srv = self._proxy(tls=self.pki.issue("127.0.0.1"))
        with mock.patch.dict("os.environ", {"AXROSS_PROXY_CA_FILE": self.pki.ca_file}):
            self.assertEqual(self._talk(_cfg(srv.port, "https")), b"HELLO\nping")

    def test_unreachable_proxy_is_a_connection_error(self) -> None:
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        with self.assertRaises(ConnectionError):
            self._talk(_cfg(port, "https", ca=self.pki.ca_file))

    def test_target_refused_by_the_proxy(self) -> None:
        srv = self._proxy(tls=self.pki.issue("127.0.0.1"))
        with self.assertRaises(ConnectionError):
            s = proxy.create_proxy_socket(
                _cfg(srv.port, "https", ca=self.pki.ca_file), "nope.internal", 1, timeout=5
            )
            s.close()


class AuthTest(unittest.TestCase):
    def setUp(self) -> None:
        self.pki = TestPki()
        self.echo = EchoServer()
        self.addCleanup(self.echo.close)
        self.routes = {("db.internal", 5432): ("127.0.0.1", self.echo.port)}
        patcher = allow_loopback_proxy()
        patcher.__enter__()
        self.addCleanup(patcher.__exit__, None, None, None)

    def _proxy(self, **kw) -> FakeHttpProxy:
        srv = FakeHttpProxy(self.routes, **kw)
        self.addCleanup(srv.close)
        return srv

    def _connect(self, cfg):
        s = proxy.create_proxy_socket(cfg, "db.internal", 5432, timeout=5)
        self.addCleanup(s.close)
        s.settimeout(5)
        return s

    # --- Basic --------------------------------------------------------------
    def test_basic_over_tls(self) -> None:
        srv = self._proxy(auth="basic", tls=self.pki.issue("127.0.0.1"))
        s = self._connect(_cfg(srv.port, "https", "alice", "s3cret", self.pki.ca_file))
        self.assertEqual(s.recv(6), b"HELLO\n")

    def test_basic_wrong_password(self) -> None:
        srv = self._proxy(auth="basic", tls=self.pki.issue("127.0.0.1"))
        with self.assertRaises(PH.ProxyAuthError) as ctx:
            self._connect(_cfg(srv.port, "https", "alice", "wrong", self.pki.ca_file))
        self.assertIn("407", str(ctx.exception))
        self.assertEqual(srv.connects, [])

    def test_proxy_wants_auth_but_none_configured(self) -> None:
        srv = self._proxy(auth="basic", tls=self.pki.issue("127.0.0.1"))
        with self.assertRaises(PH.ProxyAuthError) as ctx:
            self._connect(_cfg(srv.port, "https", ca=self.pki.ca_file))
        self.assertIn("requires authentication", str(ctx.exception))

    # --- NTLM ---------------------------------------------------------------
    def test_ntlm_plain_http_proxy(self) -> None:
        srv = self._proxy(auth="ntlm", users={"alice": "s3cret"})
        s = self._connect(_cfg(srv.port, "http+ntlm", "DOM\\alice", "s3cret"))
        self.assertEqual(s.recv(6), b"HELLO\n")
        self.assertEqual(srv.connects, ["db.internal:5432"])
        self.assertIn("ntlm", srv.legs)

    def test_ntlm_over_tls(self) -> None:
        srv = self._proxy(auth="ntlm", tls=self.pki.issue("127.0.0.1"))
        s = self._connect(_cfg(srv.port, "https+ntlm", "DOM\\alice", "s3cret", self.pki.ca_file))
        s.sendall(b"ok")
        self.assertEqual(s.recv(6), b"HELLO\n")

    def test_ntlm_wrong_password_is_rejected_by_the_server(self) -> None:
        srv = self._proxy(auth="ntlm")
        with self.assertRaises(PH.ProxyAuthError):
            self._connect(_cfg(srv.port, "http+ntlm", "DOM\\alice", "nope"))
        self.assertEqual(srv.connects, [])

    def test_ntlm_unknown_user(self) -> None:
        srv = self._proxy(auth="ntlm")
        with self.assertRaises(PH.ProxyAuthError):
            self._connect(_cfg(srv.port, "http+ntlm", "DOM\\mallory", "s3cret"))

    def test_ntlm_configured_but_proxy_only_offers_basic(self) -> None:
        srv = self._proxy(auth="basic")
        with self.assertRaises(PH.ProxyAuthError) as ctx:
            self._connect(_cfg(srv.port, "http+ntlm", "DOM\\alice", "s3cret"))
        self.assertIn("Basic", str(ctx.exception))

    def test_ntlm_needs_keepalive(self) -> None:
        srv = self._proxy(auth="ntlm", close_after_407=True)
        with self.assertRaises((PH.ProxyAuthError, ConnectionError)) as ctx:
            self._connect(_cfg(srv.port, "http+ntlm", "DOM\\alice", "s3cret"))
        self.assertTrue(str(ctx.exception))

    def test_password_is_not_logged(self) -> None:
        srv = self._proxy(auth="ntlm")
        with (
            self.assertLogs("core.proxy", level="DEBUG") as logs,
            self.assertLogs("core.proxy_http", level="DEBUG") as logs2,
        ):
            proxy.log.debug("marker")
            PH.log.debug("marker")
            self._connect(_cfg(srv.port, "http+ntlm", "DOM\\alice", "s3cret"))
        joined = "\n".join(logs.output + logs2.output)
        self.assertNotIn("s3cret", joined)

    # --- Negotiate ------------------------------------------------------------
    def test_negotiate_with_password_uses_ntlm_inside_spnego(self) -> None:
        srv = self._proxy(auth="negotiate")
        s = self._connect(_cfg(srv.port, "http+negotiate", "DOM\\alice", "s3cret"))
        self.assertEqual(s.recv(6), b"HELLO\n")
        self.assertIn("negotiate", srv.legs)

    def test_negotiate_wrong_password(self) -> None:
        srv = self._proxy(auth="negotiate")
        with self.assertRaises(PH.ProxyAuthError):
            self._connect(_cfg(srv.port, "http+negotiate", "DOM\\alice", "bad"))

    def test_kerberos_without_gssapi_fails_closed_with_a_hint(self) -> None:
        try:
            import gssapi  # noqa: F401

            self.skipTest("gssapi installed: covered by the container test bed")
        except ImportError:
            pass
        srv = self._proxy(auth="negotiate")
        with self.assertRaises(PH.ProxyAuthError) as ctx:
            self._connect(_cfg(srv.port, "http+kerberos", "alice@EXAMPLE.ORG", "s3cret"))
        self.assertIn("gssapi", str(ctx.exception).lower())
        self.assertEqual(srv.connects, [])

    def test_missing_spnego_is_a_clear_error(self) -> None:
        srv = self._proxy(auth="ntlm")
        with mock.patch.dict(sys.modules, {"spnego": None}), self.assertRaises(PH.ProxyAuthError):
            self._connect(_cfg(srv.port, "http+ntlm", "DOM\\alice", "s3cret"))


class GuardTest(unittest.TestCase):
    def test_loopback_https_proxy_is_refused_by_the_ssrf_guard(self) -> None:
        with self.assertRaises(ConnectionError) as ctx:
            proxy.create_proxy_socket(_cfg(1, "https"), "h", 1)
        self.assertIn("deny-by-default", str(ctx.exception))

    def test_metadata_address_is_refused_for_ntlm_too(self) -> None:
        cfg = proxy.ProxyConfig("http+ntlm", "169.254.169.254", 80, "u", "p")
        with self.assertRaises(ConnectionError):
            proxy.create_proxy_socket(cfg, "h", 1)

    def test_half_configured_advanced_proxy_fails_closed(self) -> None:
        with self.assertRaises(ValueError):
            proxy.ProxyConfig("https+ntlm", "").enabled  # noqa: B018


class ShimTest(unittest.TestCase):
    def setUp(self) -> None:
        self.pki = TestPki()
        self.echo = EchoServer()
        self.origin = OriginHttpServer()
        self.addCleanup(self.echo.close)
        self.addCleanup(self.origin.close)
        self.routes = {
            ("db.internal", 5432): ("127.0.0.1", self.echo.port),
            ("web.internal", 80): ("127.0.0.1", self.origin.port),
        }
        patcher = allow_loopback_proxy()
        patcher.__enter__()
        self.addCleanup(patcher.__exit__, None, None, None)
        self.addCleanup(PH.close_all_shims)

    def _shim(self, upstream_cfg) -> PH.LocalProxyShim:
        shim = PH.LocalProxyShim(upstream_cfg).start()
        self.addCleanup(shim.close)
        return shim

    def _connect_via(self, shim, host="db.internal", port=5432) -> socket.socket:
        s = socket.create_connection((shim.host, shim.port), timeout=5)
        self.addCleanup(s.close)
        s.sendall(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode())
        head = b""
        while b"\r\n\r\n" not in head:
            head += s.recv(1)
        s.settimeout(5)
        return s, head

    def test_connect_through_a_socks5_upstream(self) -> None:
        socks = FakeSocks5Server(self.routes)
        self.addCleanup(socks.close)
        shim = self._shim(_cfg(socks.port, "socks5"))
        s, head = self._connect_via(shim)
        self.assertTrue(head.startswith(b"HTTP/1.1 200"))
        self.assertEqual(s.recv(6), b"HELLO\n")
        self.assertEqual(socks.connects, [("db.internal", 5432)])

    def test_connect_through_an_ntlm_https_upstream(self) -> None:
        up = FakeHttpProxy(self.routes, auth="ntlm", tls=self.pki.issue("127.0.0.1"))
        self.addCleanup(up.close)
        shim = self._shim(_cfg(up.port, "https+ntlm", "DOM\\alice", "s3cret", self.pki.ca_file))
        s, head = self._connect_via(shim)
        self.assertTrue(head.startswith(b"HTTP/1.1 200"))
        s.sendall(b"abc")
        data = b""
        while len(data) < 9:
            data += s.recv(9 - len(data))
        self.assertEqual(data, b"HELLO\nabc")

    def test_upstream_refusal_becomes_502_with_the_reason(self) -> None:
        up = FakeHttpProxy(self.routes, auth="ntlm")
        self.addCleanup(up.close)
        shim = self._shim(_cfg(up.port, "http+ntlm", "DOM\\alice", "WRONG"))
        s = socket.create_connection((shim.host, shim.port), timeout=5)
        self.addCleanup(s.close)
        s.sendall(b"CONNECT db.internal:5432 HTTP/1.1\r\nHost: x\r\n\r\n")
        data = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
        self.assertTrue(data.startswith(b"HTTP/1.1 502"))
        self.assertIn(b"axross proxy", data)

    def test_garbage_request_gets_400(self) -> None:
        socks = FakeSocks5Server(self.routes)
        self.addCleanup(socks.close)
        shim = self._shim(_cfg(socks.port, "socks5"))
        s = socket.create_connection((shim.host, shim.port), timeout=5)
        self.addCleanup(s.close)
        s.sendall(b"NOT-HTTP\r\n\r\n")
        self.assertTrue(s.recv(100).startswith(b"HTTP/1.1 400"))

    def test_foreign_user_is_dropped(self) -> None:
        socks = FakeSocks5Server(self.routes)
        self.addCleanup(socks.close)
        shim = self._shim(_cfg(socks.port, "socks5"))
        with mock.patch.object(proxy, "_peer_is_same_user", return_value=False):
            s = socket.create_connection((shim.host, shim.port), timeout=5)
            self.addCleanup(s.close)
            s.sendall(b"CONNECT db.internal:5432 HTTP/1.1\r\n\r\n")
            s.settimeout(5)
            try:
                self.assertEqual(s.recv(100), b"")
            except ConnectionResetError:
                pass  # closed with unread data: the kernel reports a reset
        self.assertEqual(socks.connects, [])

    def test_shim_port_is_known_to_the_guard_only_while_alive(self) -> None:
        socks = FakeSocks5Server(self.routes)
        self.addCleanup(socks.close)
        shim = PH.LocalProxyShim(_cfg(socks.port, "socks5")).start()
        with mock.patch("core.proxy._assert_proxy_host_not_private", wraps=None):
            pass
        self.assertIn(shim.port, proxy._LIVE_SHIM_PORTS)
        shim.close()
        self.assertNotIn(shim.port, proxy._LIVE_SHIM_PORTS)

    # --- plain http requests through the shim ------------------------------
    def _requests_get(self, shim, path="/x", **kw):
        import requests

        s = requests.Session()
        s.trust_env = False
        s.proxies = {"http": shim.url, "https": shim.url}
        self.addCleanup(s.close)
        return s.request(kw.pop("method", "GET"), f"http://web.internal{path}", timeout=5, **kw)

    def test_plain_http_via_socks_upstream(self) -> None:
        socks = FakeSocks5Server(self.routes)
        self.addCleanup(socks.close)
        shim = self._shim(_cfg(socks.port, "socks5"))
        r = self._requests_get(shim)
        self.assertEqual((r.status_code, r.text), (200, "GET /x 0"))
        self.assertEqual(self.origin.requests[-1][:2], ("GET", "/x"))

    def test_plain_http_via_ntlm_upstream_get(self) -> None:
        up = FakeHttpProxy(self.routes, auth="ntlm")
        self.addCleanup(up.close)
        shim = self._shim(_cfg(up.port, "http+ntlm", "DOM\\alice", "s3cret"))
        r = self._requests_get(shim, "/ntlm?a=1")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.text, "GET /ntlm?a=1 0")
        self.assertEqual(up.plain_requests[-1][0], "GET")

    def test_plain_http_via_ntlm_upstream_post_body_arrives_intact(self) -> None:
        up = FakeHttpProxy(self.routes, auth="ntlm")
        self.addCleanup(up.close)
        shim = self._shim(_cfg(up.port, "http+ntlm", "DOM\\alice", "s3cret"))
        body = b"x" * 70000
        r = self._requests_get(shim, "/up", method="POST", data=body)
        self.assertEqual(r.text, "POST /up 70000")
        self.assertEqual(self.origin.requests[-1][2], body)

    def test_plain_http_via_basic_https_upstream(self) -> None:
        up = FakeHttpProxy(self.routes, auth="basic", tls=self.pki.issue("127.0.0.1"))
        self.addCleanup(up.close)
        shim = self._shim(_cfg(up.port, "https", "alice", "s3cret", self.pki.ca_file))
        r = self._requests_get(shim, "/b")
        self.assertEqual((r.status_code, r.text), (200, "GET /b 0"))

    def test_plain_http_via_ntlm_upstream_wrong_password_is_502(self) -> None:
        up = FakeHttpProxy(self.routes, auth="ntlm")
        self.addCleanup(up.close)
        shim = self._shim(_cfg(up.port, "http+ntlm", "DOM\\alice", "bad"))
        r = self._requests_get(shim)
        self.assertEqual(r.status_code, 502)
        self.assertEqual(self.origin.requests, [])

    def test_chunked_request_body_is_refused_not_mangled(self) -> None:
        up = FakeHttpProxy(self.routes, auth="ntlm")
        self.addCleanup(up.close)
        shim = self._shim(_cfg(up.port, "http+ntlm", "DOM\\alice", "s3cret"))

        def gen():
            yield b"abc"

        r = self._requests_get(shim, method="POST", data=gen())
        self.assertEqual(r.status_code, 501)

    def test_https_absolute_uri_is_not_forwarded_as_plain_http(self) -> None:
        socks = FakeSocks5Server(self.routes)
        self.addCleanup(socks.close)
        shim = self._shim(_cfg(socks.port, "socks5"))
        s = socket.create_connection((shim.host, shim.port), timeout=5)
        self.addCleanup(s.close)
        s.sendall(b"GET https://web.internal/ HTTP/1.1\r\nHost: web.internal\r\n\r\n")
        s.settimeout(5)
        self.assertTrue(s.recv(50).startswith(b"HTTP/1.1 400"))

    # --- the helpers that hand the shim to other libraries -------------------
    def test_build_requests_proxies_uses_the_shim_for_advanced_kinds(self) -> None:
        up = FakeHttpProxy(self.routes, auth="ntlm")
        self.addCleanup(up.close)
        proxies = proxy.build_requests_proxies(
            "http+ntlm", "127.0.0.1", up.port, "DOM\\alice", "s3cret"
        )
        self.assertTrue(proxies["https"].startswith("http://127.0.0.1:"))
        self.assertNotIn("s3cret", proxies["https"])
        self.assertNotIn("alice", proxies["https"])
        import requests

        s = requests.Session()
        s.trust_env = False
        s.proxies = proxies
        self.addCleanup(s.close)
        self.assertEqual(s.get("http://web.internal/z", timeout=5).text, "GET /z 0")

    def test_build_requests_proxies_keeps_native_urls_for_plain_kinds(self) -> None:
        self.assertEqual(
            proxy.build_requests_proxies("http", "127.0.0.1", 3128, "u", "p"),
            {"http": "http://u:p@127.0.0.1:3128", "https": "http://u:p@127.0.0.1:3128"},
        )
        self.assertTrue(
            proxy.build_requests_proxies("socks5", "127.0.0.1", 1080)["http"].startswith(
                "socks5h://"
            )
        )

    def test_effective_http_proxy(self) -> None:
        plain = proxy.ProxyConfig("http", "127.0.0.1", 3128, "u", "p")
        self.assertIs(proxy.effective_http_proxy(plain), plain)
        socks = FakeSocks5Server(self.routes)
        self.addCleanup(socks.close)
        eff = proxy.effective_http_proxy(_cfg(socks.port, "socks5"))
        self.assertEqual((eff.transport, eff.host, eff.username), ("http", "127.0.0.1", ""))
        self.assertIn(eff.port, proxy._LIVE_SHIM_PORTS)

    def test_one_shim_per_distinct_upstream(self) -> None:
        socks = FakeSocks5Server(self.routes)
        self.addCleanup(socks.close)
        a = PH.shim_for(_cfg(socks.port, "socks5"))
        b = PH.shim_for(_cfg(socks.port, "socks5"))
        c = PH.shim_for(_cfg(socks.port, "socks5", "u", "p"))
        self.assertIs(a, b)
        self.assertIsNot(a, c)

    def test_urllib3_manager_for_ntlm_goes_through_the_shim(self) -> None:
        up = FakeHttpProxy(self.routes, auth="ntlm")
        self.addCleanup(up.close)
        mgr = proxy.build_urllib3_proxy_manager(
            proxy.ProxyConfig("http+ntlm", "127.0.0.1", up.port, "DOM\\alice", "s3cret")
        )
        r = mgr.request("GET", "http://web.internal/u3")
        self.assertEqual(r.data, b"GET /u3 0")


class LegacyConnectAuthErrorTest(unittest.TestCase):
    """The plain-HTTP CONNECT path reports 407 as an authentication error
    (the probe's "auth" stage and the dialog's message depend on it)."""

    def setUp(self) -> None:
        guard = allow_loopback_proxy()
        guard.__enter__()
        self.addCleanup(guard.__exit__, None, None, None)
        self.echo = EchoServer(banner=b"")
        self.addCleanup(self.echo.close)
        self.srv = FakeHttpProxy(
            {("db.internal", 5432): ("127.0.0.1", self.echo.port)}, auth="basic"
        )
        self.addCleanup(self.srv.close)

    def _open(self, **kw):
        cfg = proxy.ProxyConfig("http", "127.0.0.1", self.srv.port, **kw)
        return proxy.create_proxy_socket(cfg, "db.internal", 5432, timeout=5)

    def test_missing_credentials_is_an_auth_error(self) -> None:
        with self.assertRaises(PH.ProxyAuthError) as ctx:
            self._open()
        self.assertIn("requires authentication", str(ctx.exception))

    def test_wrong_password_is_an_auth_error(self) -> None:
        with self.assertRaises(PH.ProxyAuthError) as ctx:
            self._open(username="alice", password="nope")
        self.assertIn("rejected", str(ctx.exception))

    def test_auth_error_is_still_a_connection_error(self) -> None:
        with self.assertRaises(ConnectionError):
            self._open(username="alice", password="nope")

    def test_correct_credentials_still_tunnel(self) -> None:
        sock = self._open(username="alice", password="s3cret")
        sock.close()

    def test_other_refusals_are_plain_connection_errors_without_duplicated_text(self) -> None:
        with self.assertRaises(ConnectionError) as ctx:
            proxy.create_proxy_socket(
                proxy.ProxyConfig("http", "127.0.0.1", self.srv.port, "alice", "s3cret"),
                "unrouted.internal",
                9,
                timeout=5,
            )
        self.assertNotIsInstance(ctx.exception, PH.ProxyAuthError)
        self.assertEqual(str(ctx.exception).count("HTTP CONNECT failed"), 1)


class Socks4RequestsSchemeTest(unittest.TestCase):
    def test_requests_use_socks4a_so_names_resolve_at_the_proxy(self) -> None:
        got = proxy.build_requests_proxies("socks4", "p.example", 1080)
        self.assertEqual(got["http"], "socks4a://p.example:1080")
        self.assertEqual(got["https"], "socks4a://p.example:1080")


if __name__ == "__main__":
    unittest.main()
