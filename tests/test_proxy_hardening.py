"""Proxy defects found in the 2026-10-14 review, each reproduced before it
was fixed.

* a saved ProxyCommand kept routing SSH through a jump host after the
  profile was switched to the default proxy — or to "none" (direct);
* a bypass entry with a port matched every target whose port was unknown,
  so traffic meant for the proxy went direct;
* the default proxy's credentials were attached to whichever proxy a PAC
  file named, even one fetched over plain http;
* the PAC string limit could be bypassed with ``+=``, ``join`` and
  ``replace``, and malformed scripts escaped as raw IndexError /
  RecursionError;
* the loopback shim authenticated only the first request on a kept-alive
  connection to a Basic upstream; later ones went out unauthenticated;
* Git over a plain ``http`` proxy never sent the proxy credentials
  (urllib3 ignores userinfo in the proxy URL);
* a ProxyCommand-only custom profile was saved as SOCKS5 without a host
  and could not connect;
* a default-proxy password typed without "save in keyring" was used by
  "Test proxy" but by no real connection;
* both relays tore down the whole connection when one side half-closed,
  dropping the other side's reply.
"""

from __future__ import annotations

import base64
import os
import shutil
import socket
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core import connection_manager as cm  # noqa: E402
from core import (
    pac,  # noqa: E402
    proxy,  # noqa: E402
)
from core import proxy_http as PH  # noqa: E402
from core import proxy_settings as PS  # noqa: E402
from core.profiles import ConnectionProfile  # noqa: E402
from tests.proxy_http_testkit import FakeHttpProxy, OriginHttpServer  # noqa: E402
from tests.proxy_testkit import allow_loopback_proxy  # noqa: E402


class _Isolated(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.path = self.tmp / "proxy.json"
        p = mock.patch.object(PS, "SETTINGS_PATH", self.path)
        p.start()
        self.addCleanup(p.stop)
        self.addCleanup(PS._PAC_CACHE.clear)
        self.addCleanup(PS.set_session_password, "")
        self.keyring = {"value": ""}
        for name, fn in (
            ("get_password", lambda: self.keyring["value"]),
            ("set_password", lambda v: self.keyring.__setitem__("value", v) or True),
        ):
            p = mock.patch.object(PS, name, fn)
            p.start()
            self.addCleanup(p.stop)


# --------------------------------------------------------------------------
# ProxyCommand vs. proxy modes
# --------------------------------------------------------------------------


class ProxyCommandModeTest(_Isolated):
    def _jump_profile(self, **kw) -> ConnectionProfile:
        base = dict(
            name="j",
            protocol="sftp",
            host="inner",
            port=22,
            username="u",
            proxy_command="ssh -W %h:%p jump",
        )
        base.update(kw)
        return ConnectionProfile(**base)

    def test_default_mode_drops_a_stale_proxy_command(self) -> None:
        PS.save(PS.ProxyDefaults(proxy_type="socks5", host="corp", port=1080))
        resolved = cm.effective_profile(self._jump_profile(proxy_mode="default"))
        self.assertEqual(resolved.proxy_command, "")
        self.assertEqual((resolved.proxy_type, resolved.proxy_host), ("socks5", "corp"))

    def test_none_mode_is_direct_even_with_a_stale_proxy_command(self) -> None:
        resolved = cm.effective_profile(self._jump_profile(proxy_mode="none"))
        self.assertEqual((resolved.proxy_type, resolved.proxy_command), ("none", ""))

    def test_custom_mode_keeps_its_proxy_command(self) -> None:
        profile = self._jump_profile()
        self.assertIs(cm.effective_profile(profile), profile)

    def test_use_for_all_profiles_leaves_jump_host_profiles_alone(self) -> None:
        jump = self._jump_profile()
        plain = ConnectionProfile(name="p", protocol="sftp", host="h")
        self.assertEqual(PS.adopt_default_proxy([jump, plain]), ["p"])
        self.assertEqual((jump.proxy_mode, jump.proxy_command), ("custom", "ssh -W %h:%p jump"))
        self.assertEqual(plain.proxy_mode, "default")


# --------------------------------------------------------------------------
# Bypass entries with a port
# --------------------------------------------------------------------------


class BypassPortTest(_Isolated):
    def test_sad_a_port_entry_does_not_match_an_unknown_port(self) -> None:
        self.assertFalse(PS.bypass_matches("intranet.corp", ["intranet.corp:8080"], None))
        self.assertFalse(PS.bypass_matches("any.example", ["*:443"], None))

    def test_happy_a_port_entry_matches_its_port(self) -> None:
        self.assertTrue(PS.bypass_matches("intranet.corp", ["intranet.corp:8080"], 8080))
        self.assertFalse(PS.bypass_matches("intranet.corp", ["intranet.corp:8080"], 22))

    def test_edge_an_entry_without_port_still_matches_an_unknown_port(self) -> None:
        self.assertTrue(PS.bypass_matches("intranet.corp", ["intranet.corp"], None))

    def test_a_profile_without_port_uses_the_protocol_default(self) -> None:
        profile = ConnectionProfile(name="s", protocol="sftp", host="files.corp", port=0)
        self.assertEqual(PS.target_of(profile), ("files.corp", 22))

    def test_default_port_profile_is_bypassed_only_by_a_matching_entry(self) -> None:
        PS.save(
            PS.ProxyDefaults(
                proxy_type="socks5", host="corp", port=1080, bypass=["files.corp:8080"]
            )
        )
        profile = ConnectionProfile(
            name="s", protocol="sftp", host="files.corp", port=0, proxy_mode="default"
        )
        res = PS.resolve_for_profile(profile)
        self.assertIsNotNone(res.config)  # still proxied, not direct


# --------------------------------------------------------------------------
# PAC: whose credentials go where
# --------------------------------------------------------------------------


class PacCredentialTest(_Isolated):
    SRC = 'function FindProxyForURL(url, host) { return "PROXY %s:3128"; }'

    def _resolve(self, pac_url: str, answer: str):
        PS.save(
            PS.ProxyDefaults(
                proxy_type="http",
                host="corp-proxy.example",
                port=3128,
                username="alice",
                store_password=True,
                pac_url=pac_url,
            )
        )
        self.keyring["value"] = "corp-secret"
        with mock.patch.object(PS, "pac_script", return_value=pac.PacScript(self.SRC % answer)):
            return PS.resolve("default", None, "target.example", 22, "sftp").config

    def test_sad_a_plain_http_pac_naming_another_proxy_gets_no_credentials(self) -> None:
        cfg = self._resolve("http://wpad.example/proxy.pac", "evil.example")
        self.assertEqual((cfg.host, cfg.username, cfg.password), ("evil.example", "", ""))

    def test_happy_an_https_pac_may_name_another_proxy(self) -> None:
        cfg = self._resolve("https://wpad.example/proxy.pac", "other.example")
        self.assertEqual((cfg.username, cfg.password), ("alice", "corp-secret"))

    def test_happy_a_local_pac_file_may_name_another_proxy(self) -> None:
        cfg = self._resolve(str(self.tmp / "proxy.pac"), "other.example")
        self.assertEqual((cfg.username, cfg.password), ("alice", "corp-secret"))

    def test_edge_a_plain_http_pac_naming_the_configured_proxy_keeps_them(self) -> None:
        cfg = self._resolve("http://wpad.example/proxy.pac", "corp-proxy.example")
        self.assertEqual((cfg.username, cfg.password), ("alice", "corp-secret"))

    def test_edge_host_comparison_ignores_case_and_a_trailing_dot(self) -> None:
        cfg = self._resolve("http://wpad.example/proxy.pac", "Corp-Proxy.Example.")
        self.assertEqual(cfg.password, "corp-secret")


# --------------------------------------------------------------------------
# PAC interpreter limits
# --------------------------------------------------------------------------


def _run(body: str):
    return pac.PacScript("function FindProxyForURL(url, host) {" + body + "}").find(
        "http://h/", "h"
    )


class PacLimitTest(unittest.TestCase):
    def test_sad_plus_equals_cannot_grow_past_the_limit(self) -> None:
        with self.assertRaises(pac.PacError):
            _run('var s="x"; for (var i=0;i<20;i++){ s += s; } return "PROXY a:1";')

    def test_sad_join_cannot_grow_past_the_limit(self) -> None:
        chunk = "y" * 2000
        items = ",".join(f'"{chunk}"' for _ in range(40))
        with self.assertRaises(pac.PacError):
            _run(f'var a=[{items}]; var j=a.join(""); return "PROXY a:1";')

    def test_sad_replace_cannot_double_past_the_limit(self) -> None:
        with self.assertRaises(pac.PacError):
            _run('var s="xx"; for (var i=0;i<20;i++){ s = s.replace("x", s); } return "PROXY a:1";')

    def test_sad_an_array_turned_into_a_string_is_capped(self) -> None:
        chunk = "z" * 2000
        items = ",".join(f'"{chunk}"' for _ in range(40))
        with self.assertRaises(pac.PacError):
            _run(f'var a=[{items}]; var s = "" + a; return "PROXY a:1";')

    def test_happy_strings_below_the_limit_still_work(self) -> None:
        got = _run(
            'var s="ab"; s += "cd"; var j=["p","q"].join("-"); '
            'return "PROXY " + s.replace("b", "B") + j + ":1";'
        )
        self.assertEqual((got[0].host, got[0].port), ("aBcdp-q", 1))

    def test_edge_exactly_the_limit_is_allowed(self) -> None:
        n = pac.MAX_STRING
        got = _run(
            f'var s=""; for (var i=0;i<{n // 1024};i++){{ s += "{"w" * 1024}"; }} '
            "return s.length == " + str(n) + ' ? "DIRECT" : "PROXY no:1";'
        )
        self.assertEqual(got[0].kind, "direct")

    def test_sad_a_truncated_script_is_a_pac_error(self) -> None:
        with self.assertRaises(pac.PacError):
            pac.PacScript("function FindProxyForURL(url, host) { for(var")

    def test_sad_absurd_nesting_is_a_pac_error(self) -> None:
        src = "function FindProxyForURL(u,h){ return " + "(" * 5000 + "1" + ")" * 5000 + "; }"
        with self.assertRaises(pac.PacError):
            pac.PacScript(src)

    def test_a_malformed_refresh_keeps_the_last_good_script(self) -> None:
        good = 'function FindProxyForURL(url, host) { return "DIRECT"; }'
        bad = "function FindProxyForURL(url, host) { for(var"
        with mock.patch.object(PS, "_fetch_pac_source", side_effect=[good, bad]):
            PS._PAC_CACHE.clear()
            self.addCleanup(PS._PAC_CACHE.clear)
            first = PS.pac_script("file:///x.pac")
            with mock.patch.object(PS.time, "monotonic", return_value=10**9):
                second = PS.pac_script("file:///x.pac")
        self.assertIs(second, first)


# --------------------------------------------------------------------------
# Shim: every request through a Basic upstream is authenticated
# --------------------------------------------------------------------------


class _KeepAliveBasicProxy:
    """Minimal forward proxy that keeps connections alive unless asked to
    close — the way squid behaves — and records whether each request
    carried valid Basic credentials."""

    def __init__(self) -> None:
        self.authorised: list[bool] = []
        self._want = "Basic " + base64.b64encode(b"alice:s3cret").decode()
        self._sock = socket.socket()
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(8)
        self.port = self._sock.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()

    def close(self) -> None:
        self._sock.close()

    def _serve(self) -> None:
        while True:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket) -> None:
        conn.settimeout(5)
        buf = b""
        try:
            while True:
                while b"\r\n\r\n" not in buf:
                    chunk = conn.recv(4096)
                    if not chunk:
                        return
                    buf += chunk
                head, _, buf = buf.partition(b"\r\n\r\n")
                lines = head.decode("latin-1").split("\r\n")
                hdrs = {
                    k.strip().lower(): v.strip()
                    for k, _, v in (x.partition(":") for x in lines[1:])
                }
                ok = hdrs.get("proxy-authorization") == self._want
                self.authorised.append(ok)
                status = "200 OK" if ok else "407 Proxy Authentication Required"
                body = b"ok" if ok else b"auth"
                close = (
                    "close"
                    in (hdrs.get("connection", "") + hdrs.get("proxy-connection", "")).lower()
                )
                conn.sendall(
                    f"HTTP/1.1 {status}\r\nContent-Length: {len(body)}\r\n".encode()
                    + (b"Connection: close\r\n" if close else b"")
                    + b"\r\n"
                    + body
                )
                if close:
                    return
        except OSError:
            pass
        finally:
            conn.close()


def _read_response(sock: socket.socket) -> bytes:
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            return data
        data += chunk
    head, _, body = data.partition(b"\r\n\r\n")
    length = 0
    for line in head.split(b"\r\n")[1:]:
        k, _, v = line.partition(b":")
        if k.strip().lower() == b"content-length":
            length = int(v)
    while len(body) < length:
        body += sock.recv(4096)
    return head.split(b"\r\n")[0]


class ShimKeepAliveTest(unittest.TestCase):
    def setUp(self) -> None:
        patcher = allow_loopback_proxy()
        patcher.__enter__()
        self.addCleanup(patcher.__exit__, None, None, None)
        self.addCleanup(PH.close_all_shims)
        self.up = _KeepAliveBasicProxy()
        self.addCleanup(self.up.close)
        cfg = proxy.ProxyConfig("https", "127.0.0.1", self.up.port, "alice", "s3cret")
        # Plain TCP stand-in for the TLS hop: what is under test is the
        # request stream the shim writes, not the TLS layer.
        p = mock.patch.object(
            PH,
            "connect_to_proxy",
            lambda c, t: socket.create_connection(("127.0.0.1", self.up.port), timeout=t),
        )
        p.start()
        self.addCleanup(p.stop)
        self.shim = PH.LocalProxyShim(cfg).start()
        self.addCleanup(self.shim.close)

    def test_a_second_request_on_the_same_connection_is_never_sent_unauthenticated(self) -> None:
        with socket.create_connection((self.shim.host, self.shim.port), timeout=5) as c:
            req = b"GET http://web.internal/a HTTP/1.1\r\nHost: web.internal\r\n\r\n"
            c.sendall(req)
            self.assertEqual(_read_response(c), b"HTTP/1.1 200 OK")
            try:
                c.sendall(req.replace(b"/a", b"/b"))
                second = _read_response(c)
            except OSError:
                second = b""
        self.assertNotIn(b"407", second)
        self.assertEqual(self.up.authorised, [True])

    def test_each_new_connection_authenticates(self) -> None:
        for path in (b"/a", b"/b"):
            with socket.create_connection((self.shim.host, self.shim.port), timeout=5) as c:
                c.sendall(
                    b"GET http://web.internal" + path + b" HTTP/1.1\r\nHost: web.internal\r\n\r\n"
                )
                self.assertEqual(_read_response(c), b"HTTP/1.1 200 OK")
        self.assertEqual(self.up.authorised, [True, True])


# --------------------------------------------------------------------------
# Git / urllib3 through a plain http proxy with credentials
# --------------------------------------------------------------------------


class Urllib3ProxyAuthTest(unittest.TestCase):
    def setUp(self) -> None:
        patcher = allow_loopback_proxy()
        patcher.__enter__()
        self.addCleanup(patcher.__exit__, None, None, None)

    def test_credentials_become_a_proxy_authorization_header(self) -> None:
        cfg = proxy.ProxyConfig("http", "127.0.0.1", 3128, "alice", "s3:cr@t")
        mgr = proxy.build_urllib3_proxy_manager(cfg)
        want = "Basic " + base64.b64encode(b"alice:s3:cr@t").decode()
        self.assertEqual(mgr.proxy_headers.get("proxy-authorization"), want)
        self.assertNotIn("s3", str(mgr.proxy))  # not in the URL any more

    def test_without_credentials_no_header(self) -> None:
        mgr = proxy.build_urllib3_proxy_manager(proxy.ProxyConfig("http", "127.0.0.1", 3128))
        self.assertNotIn("proxy-authorization", mgr.proxy_headers)

    def test_a_request_through_a_basic_proxy_succeeds(self) -> None:
        origin = OriginHttpServer()
        self.addCleanup(origin.close)
        up = FakeHttpProxy({("web.internal", 80): ("127.0.0.1", origin.port)}, auth="basic")
        self.addCleanup(up.close)
        mgr = proxy.build_urllib3_proxy_manager(
            proxy.ProxyConfig("http", "127.0.0.1", up.port, "alice", "s3cret")
        )
        r = mgr.request("GET", "http://web.internal/repo", retries=False)
        self.assertEqual((r.status, r.data), (200, b"GET /repo 0"))


# --------------------------------------------------------------------------
# Default proxy password without the keyring
# --------------------------------------------------------------------------


class SessionPasswordTest(_Isolated):
    def test_happy_a_session_password_is_used_by_real_connections(self) -> None:
        PS.save(PS.ProxyDefaults(proxy_type="http", host="p", port=3128, username="alice"))
        PS.set_session_password("typed")
        cfg = PS.resolve("default", None, "t.example", 22).config
        self.assertEqual(cfg.password, "typed")

    def test_keyring_wins_when_storing_is_enabled(self) -> None:
        PS.save(
            PS.ProxyDefaults(
                proxy_type="http", host="p", port=3128, username="alice", store_password=True
            )
        )
        self.keyring["value"] = "stored"
        PS.set_session_password("typed")
        self.assertEqual(PS.resolve("default", None, "t", 22).config.password, "stored")

    def test_edge_no_username_means_no_password(self) -> None:
        PS.save(PS.ProxyDefaults(proxy_type="http", host="p", port=3128))
        PS.set_session_password("typed")
        self.assertEqual(PS.resolve("default", None, "t", 22).config.password, "")


class _QtCase(_Isolated):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            from PyQt6.QtWidgets import QApplication
        except ImportError:
            raise unittest.SkipTest("PyQt6 not installed")
        cls.app = QApplication.instance() or QApplication([])


class NetworkDialogSessionPasswordTest(_QtCase):
    def test_saving_without_keyring_keeps_the_typed_password_for_this_session(self) -> None:
        from ui.network_proxy_dialog import NetworkProxyDialog

        dialog = NetworkProxyDialog(None, path=self.path)
        self.addCleanup(dialog.deleteLater)
        dialog._type.setCurrentIndex(2)  # HTTP
        dialog._host.setText("proxy.corp")
        dialog._username.setText("alice")
        dialog._password.setText("typed")
        dialog._store_pw.setChecked(False)
        dialog._save()
        self.assertEqual(self.keyring["value"], "")
        self.assertNotIn("typed", self.path.read_text())
        self.assertEqual(PS.resolve("default", None, "t", 22).config.password, "typed")


class ConnectionDialogProxyCommandTest(_QtCase):
    def test_a_proxy_command_only_profile_connects_without_a_proxy_type(self) -> None:
        from ui.connection_dialog import ConnectionDialog

        manager = mock.MagicMock()
        manager.list_names.return_value = []
        dialog = ConnectionDialog(manager)
        self.addCleanup(dialog.deleteLater)
        dialog._protocol_combo.setCurrentIndex(dialog._protocol_ids.index("sftp"))
        dialog._host.setText("inner")
        dialog._username.setText("u")
        dialog._proxy_group.setChecked(True)
        dialog._proxy_mode.setCurrentIndex(1)
        dialog._proxy_command.setText("ssh -W %h:%p jump")
        built = dialog._build_profile()
        self.assertEqual((built.proxy_type, built.proxy_command), ("none", "ssh -W %h:%p jump"))
        cm._validate_proxy_request(built)  # must not raise


# --------------------------------------------------------------------------
# Half-close through both relays
# --------------------------------------------------------------------------


class _ReplyAfterEof:
    """Reads until the client half-closes, then answers and closes —
    the shape of many request/response protocols."""

    def __init__(self) -> None:
        self._sock = socket.socket()
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(4)
        self.port = self._sock.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()

    def close(self) -> None:
        self._sock.close()

    def _serve(self) -> None:
        while True:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            with conn:
                conn.settimeout(5)
                got = b""
                try:
                    while chunk := conn.recv(4096):
                        got += chunk
                    import time

                    time.sleep(0.2)  # a reply that takes a moment
                    conn.sendall(b"GOT %d" % len(got))
                except OSError:
                    pass


def _direct(srv):
    return lambda *_a, **_k: socket.create_connection(("127.0.0.1", srv.port), timeout=5)


def _recv_all(sock: socket.socket) -> bytes:
    sock.settimeout(5)
    data = b""
    while chunk := sock.recv(4096):
        data += chunk
    return data


class HalfCloseTest(unittest.TestCase):
    def setUp(self) -> None:
        self.srv = _ReplyAfterEof()
        self.addCleanup(self.srv.close)
        patcher = allow_loopback_proxy()
        patcher.__enter__()
        self.addCleanup(patcher.__exit__, None, None, None)
        self.addCleanup(PH.close_all_shims)

    def test_tunnel_delivers_the_reply_after_the_client_half_closes(self) -> None:
        cfg = proxy.ProxyConfig("socks5", "127.0.0.1", 1080)
        with mock.patch.object(proxy, "create_proxy_socket", _direct(self.srv)):
            with proxy.LocalTunnel(cfg, "svc.internal", 7) as tunnel:
                with socket.create_connection((tunnel.host, tunnel.port), timeout=5) as c:
                    c.sendall(b"hello")
                    c.shutdown(socket.SHUT_WR)
                    self.assertEqual(_recv_all(c), b"GOT 5")

    def test_shim_connect_delivers_the_reply_after_the_client_half_closes(self) -> None:
        cfg = proxy.ProxyConfig("socks5", "127.0.0.1", 1080)
        with mock.patch.object(proxy, "create_proxy_socket", _direct(self.srv)):
            shim = PH.LocalProxyShim(cfg).start()
            self.addCleanup(shim.close)
            with socket.create_connection((shim.host, shim.port), timeout=5) as c:
                c.sendall(b"CONNECT svc.internal:7 HTTP/1.1\r\nHost: svc.internal:7\r\n\r\n")
                head = b""
                while b"\r\n\r\n" not in head:
                    head += c.recv(1)
                self.assertTrue(head.startswith(b"HTTP/1.1 200"))
                c.sendall(b"hello")
                c.shutdown(socket.SHUT_WR)
                self.assertEqual(_recv_all(c), b"GOT 5")

    def test_edge_a_server_that_closes_first_still_ends_the_relay(self) -> None:
        cfg = proxy.ProxyConfig("socks5", "127.0.0.1", 1080)
        with mock.patch.object(proxy, "create_proxy_socket", _direct(self.srv)):
            with proxy.LocalTunnel(cfg, "svc.internal", 7) as tunnel:
                with socket.create_connection((tunnel.host, tunnel.port), timeout=5) as c:
                    c.shutdown(socket.SHUT_WR)
                    self.assertEqual(_recv_all(c), b"GOT 0")
                    # the client sees EOF, so the relay is over on both sides
                    self.assertEqual(c.recv(1), b"")


if __name__ == "__main__":
    unittest.main()
