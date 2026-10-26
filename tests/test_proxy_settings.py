"""Global default proxy: persistence, bypass list, PAC, profile modes, probing."""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import connection_manager as cm  # noqa: E402
from core import proxy  # noqa: E402
from core import proxy_settings as PS
from core.profiles import ConnectionProfile  # noqa: E402
from tests.proxy_http_testkit import FakeHttpProxy, TestPki  # noqa: E402
from tests.proxy_testkit import EchoServer, FakeSocks5Server, allow_loopback_proxy  # noqa: E402


class _Isolated(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.path = self.tmp / "proxy.json"
        for target, value in ((PS, "SETTINGS_PATH"),):
            patcher = mock.patch.object(target, value, self.path)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.addCleanup(PS._PAC_CACHE.clear)
        pw = {"value": ""}
        self._pw = pw
        for name, fn in (
            ("get_password", lambda: pw["value"]),
            ("set_password", lambda v: pw.__setitem__("value", v) or True),
        ):
            p = mock.patch.object(PS, name, fn)
            p.start()
            self.addCleanup(p.stop)

    def write(self, **kw) -> None:
        base = {"proxy_type": "none", "host": "", "port": 0}
        base.update(kw)
        self.path.write_text(json.dumps(base), encoding="utf-8")


class StoreTest(_Isolated):
    def test_missing_file_means_no_default(self) -> None:
        d = PS.load()
        self.assertFalse(d.configured)
        self.assertEqual(d.bypass, list(PS.DEFAULT_BYPASS))

    def test_roundtrip(self) -> None:
        d = PS.ProxyDefaults(
            "https+ntlm", "proxy.example", 3128, "DOM\\u", True, ["*.corp", "10.0.0.0/8"], "", ""
        )
        PS.save(d)
        again = PS.load()
        self.assertEqual(
            (again.proxy_type, again.host, again.port, again.username, again.bypass),
            ("https+ntlm", "proxy.example", 3128, "DOM\\u", ["*.corp", "10.0.0.0/8"]),
        )
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def test_password_is_never_written_to_the_file(self) -> None:
        PS.save(PS.ProxyDefaults("http", "p", 3128, "u", True))
        PS.set_password("TOP-SECRET")
        self.assertNotIn("TOP-SECRET", self.path.read_text())

    def test_hostile_file_values_are_sanitised(self) -> None:
        self.write(
            proxy_type="carrier-pigeon",
            host="a\nb",
            port="80",
            bypass="x",
            pac_url=5,
            username="u\x00v",
        )
        d = PS.load()
        self.assertEqual((d.proxy_type, d.port, d.pac_url), ("none", 0, ""))
        self.assertEqual(d.host, "ab")
        self.assertEqual(d.username, "uv")
        self.assertEqual(d.bypass, list(PS.DEFAULT_BYPASS))

    def test_garbage_json(self) -> None:
        self.path.write_text("not json")
        self.assertFalse(PS.load().configured)
        self.path.write_text("[1,2]")
        self.assertFalse(PS.load().configured)

    def test_validation(self) -> None:
        for bad in (
            PS.ProxyDefaults("http", "", 3128),
            PS.ProxyDefaults("http", "p", 0),
            PS.ProxyDefaults("http", "p", 70000),
            PS.ProxyDefaults("bogus", "p", 1),
            PS.ProxyDefaults("none", pac_url="ftp://x/y.pac"),
            PS.ProxyDefaults("none", ca_file="/no/such/ca.pem"),
        ):
            with self.assertRaises(ValueError, msg=str(bad)):
                PS.save(bad)
        self.assertFalse(self.path.exists())

    def test_failed_save_leaves_the_old_file_intact(self) -> None:
        PS.save(PS.ProxyDefaults("http", "p", 3128))
        before = self.path.read_text()
        with self.assertRaises(ValueError):
            PS.save(PS.ProxyDefaults("http", "", 1))
        self.assertEqual(self.path.read_text(), before)

    def _copies(self) -> list[Path]:
        return sorted(self.tmp.glob("proxy.json.unreadable-*"))

    def test_sad_saving_over_an_unreadable_file_keeps_a_copy_of_it(self) -> None:
        """The dialog shows "no proxy" for an unreadable file; saving it
        must not erase the proxy the file held."""
        for content in (b'{"proxy_type": "socks5", "host": "10.9.9.9", "po', b"[1]", b"\xff"):
            with self.subTest(content=content):
                for old in self._copies():
                    old.unlink()
                self.path.write_bytes(content)
                PS.save(PS.ProxyDefaults("http", "new.proxy", 3128))
                self.assertEqual(PS.load().host, "new.proxy")
                self.assertEqual([p.read_bytes() for p in self._copies()], [content])

    def test_sad_no_save_when_the_unreadable_file_cannot_be_kept(self) -> None:
        self.path.write_bytes(b'{"proxy_type": "socks5", "host": "10.9.9.9", "po')
        with mock.patch.object(PS, "keep_unreadable_copy", return_value=False):
            with self.assertRaises(OSError):
                PS.save(PS.ProxyDefaults("http", "new.proxy", 3128))
        self.assertEqual(
            self.path.read_bytes(), b'{"proxy_type": "socks5", "host": "10.9.9.9", "po'
        )

    def test_edge_saving_over_a_readable_or_missing_file_keeps_no_copy(self) -> None:
        PS.save(PS.ProxyDefaults("http", "p", 3128))
        PS.save(PS.ProxyDefaults("http", "q", 3128))
        self.assertEqual(self._copies(), [])


class BypassTest(unittest.TestCase):
    def m(self, host, patterns, port=None):
        return PS.bypass_matches(host, patterns, port)

    def test_exact_and_domain(self) -> None:
        self.assertTrue(self.m("example.com", ["example.com"]))
        self.assertTrue(self.m("a.b.example.com", ["example.com"]))
        self.assertTrue(self.m("a.example.com", ["*.example.com"]))
        self.assertTrue(self.m("a.example.com", [".example.com"]))
        self.assertTrue(self.m("EXAMPLE.com", ["example.COM"]))

    def test_no_false_suffix_match(self) -> None:
        self.assertFalse(self.m("notexample.com", ["example.com"]))
        self.assertFalse(self.m("example.com.evil.org", ["example.com"]))

    def test_cidr_and_literals(self) -> None:
        self.assertTrue(self.m("10.1.2.3", ["10.0.0.0/8"]))
        self.assertFalse(self.m("11.1.2.3", ["10.0.0.0/8"]))
        self.assertTrue(self.m("::1", ["::1"]))
        self.assertTrue(self.m("fd00::5", ["fd00::/8"]))
        self.assertTrue(self.m("127.0.0.1", ["127.0.0.0/8"]))

    def test_hostnames_are_never_resolved_for_cidr(self) -> None:
        with mock.patch("socket.getaddrinfo") as dns, mock.patch("socket.gethostbyname") as dns2:
            self.assertFalse(self.m("intranet.example", ["10.0.0.0/8"]))
        dns.assert_not_called()
        dns2.assert_not_called()

    def test_local_and_star(self) -> None:
        self.assertTrue(self.m("intranet", ["<local>"]))
        self.assertFalse(self.m("a.b", ["<local>"]))
        self.assertFalse(self.m("10.0.0.1", ["<local>"]))
        self.assertTrue(self.m("anything.example", ["*"]))

    def test_port_qualified(self) -> None:
        self.assertTrue(self.m("example.com", ["example.com:8080"], 8080))
        self.assertFalse(self.m("example.com", ["example.com:8080"], 443))

    def test_ipv6_literal_with_brackets(self) -> None:
        self.assertTrue(self.m("[::1]", ["::1"]))

    def test_empty_and_bad_entries_are_ignored(self) -> None:
        self.assertFalse(self.m("example.com", ["", "  ", "10.0.0.0/99"]))
        self.assertFalse(self.m("", ["*"]))


class ResolveTest(_Isolated):
    def setUp(self) -> None:
        super().setUp()
        self.own = proxy.ProxyConfig("socks5", "own.proxy", 1080, "u", "p")

    def default(self, **kw):
        base = dict(
            proxy_type="http", host="def.proxy", port=3128, username="du", store_password=True
        )
        base.update(kw)
        PS.save(PS.ProxyDefaults(**base))
        self._pw["value"] = "dpw"

    def test_none_is_always_direct(self) -> None:
        self.default()
        r = PS.resolve("none", self.own, "example.com", 22)
        self.assertIsNone(r.config)

    def test_custom_uses_the_profiles_own_proxy(self) -> None:
        self.default()
        r = PS.resolve("custom", self.own, "example.com", 22)
        self.assertIs(r.config, self.own)
        self.assertEqual(r.source, "custom")

    def test_custom_without_a_proxy_is_direct(self) -> None:
        self.default()
        self.assertIsNone(PS.resolve("custom", None, "example.com", 22).config)

    def test_default_applies_with_credentials_from_the_keyring(self) -> None:
        self.default()
        r = PS.resolve("default", None, "example.com", 22)
        c = r.config
        self.assertEqual(
            (c.proxy_type, c.host, c.port, c.username, c.password),
            ("http", "def.proxy", 3128, "du", "dpw"),
        )
        self.assertEqual(r.source, "default")

    def test_default_without_a_configured_proxy_is_direct(self) -> None:
        r = PS.resolve("default", None, "example.com", 22)
        self.assertEqual((r.config, r.source), (None, "default-none"))

    def test_sad_an_unknown_proxy_type_fails_closed(self) -> None:
        """A hand-edited proxy_type axross does not know ("socks9", a typo,
        a number) read as "none" and connected directly; the user meant a
        proxy, so it fails closed like an unreadable file."""
        self.default()
        for value in ("socks9", "bogus", 7, True, ["socks5"]):
            with self.subTest(value=value):
                raw = json.loads(self.path.read_text())
                raw["proxy_type"] = value
                self.path.write_text(json.dumps(raw))
                with self.assertRaises(PS.ProxyResolutionError):
                    PS.resolve("default", None, "example.com", 22)
                # The Settings page still opens on it, showing no proxy.
                self.assertEqual(PS.load(self.path).proxy_type, "none")

    def test_edge_none_and_a_missing_type_still_connect_directly(self) -> None:
        for raw in ({"proxy_type": "none"}, {"proxy_type": None}, {}, {"proxy_type": " NONE "}):
            with self.subTest(raw=raw):
                self.path.write_text(json.dumps(raw))
                r = PS.resolve("default", None, "example.com", 22)
                self.assertEqual((r.config, r.source), (None, "default-none"))

    def test_sad_an_unreadable_default_fails_closed(self) -> None:
        """A truncated / non-UTF-8 / non-object proxy.json must not turn
        "use the default proxy" into a direct connection."""
        self.default()
        good = self.path.read_bytes()
        for content in (good[: len(good) // 2], b"\xff" + good, b"[]"):
            with self.subTest(content=content[:20]):
                self.path.write_bytes(content)
                with self.assertRaises(PS.ProxyResolutionError):
                    PS.resolve("default", None, "example.com", 22)
                with self.assertRaises(PS.ProxyResolutionError):
                    PS.default_proxy_kwargs("example.com", 22, "sftp")

    def test_sad_a_default_profile_does_not_connect_direct_over_an_unreadable_file(self) -> None:
        self.default()
        self.path.write_bytes(self.path.read_bytes()[:20])
        p = ConnectionProfile(name="x", host="db.example", proxy_mode="default")
        with self.assertRaises(ConnectionError):
            cm.effective_profile(p)

    def test_edge_an_unreadable_default_leaves_none_and_custom_modes_alone(self) -> None:
        self.path.write_bytes(b"{not json")
        self.assertIsNone(PS.resolve("none", self.own, "example.com", 22).config)
        self.assertIs(PS.resolve("custom", self.own, "example.com", 22).config, self.own)

    def test_bypass_wins_over_the_default(self) -> None:
        self.default(bypass=["*.corp.local"])
        r = PS.resolve("default", None, "db.corp.local", 5432)
        self.assertEqual((r.config, r.source), (None, "bypass"))

    def test_default_bypass_keeps_loopback_direct(self) -> None:
        self.default()
        self.assertIsNone(PS.resolve("default", None, "127.0.0.1", 22).config)
        self.assertIsNone(PS.resolve("default", None, "localhost", 22).config)

    def test_password_not_loaded_when_not_stored(self) -> None:
        self.default(store_password=False)
        self.assertEqual(PS.resolve("default", None, "example.com", 22).config.password, "")

    def test_description_never_contains_the_password(self) -> None:
        self.default()
        text = PS.resolve("default", None, "example.com", 22).description
        self.assertNotIn("dpw", text)
        self.assertIn("def.proxy:3128", text)

    def test_default_proxy_kwargs(self) -> None:
        self.default()
        kw = PS.default_proxy_kwargs("example.com", 22, "sftp")
        self.assertEqual(
            (kw["proxy_type"], kw["proxy_host"], kw["proxy_password"]), ("http", "def.proxy", "dpw")
        )
        self.assertEqual(PS.default_proxy_kwargs("127.0.0.1", 22, "sftp"), {})


class PacResolutionTest(_Isolated):
    PAC = """
    function FindProxyForURL(url, host) {
        if (dnsDomainIs(host, ".direct.example")) return "DIRECT";
        if (host == "viasocks.example") return "SOCKS5 socks.pac:1080";
        if (host == "tls.example") return "HTTPS tls.pac:8443";
        return "PROXY pac.proxy:3128; DIRECT";
    }
    """

    def setUp(self) -> None:
        super().setUp()
        self.pac_file = self.tmp / "proxy.pac"
        self.pac_file.write_text(self.PAC)

    def default(self, **kw):
        base = dict(
            proxy_type="http+ntlm",
            host="x",
            port=1,
            username="DOM\\u",
            store_password=True,
            pac_url=str(self.pac_file),
        )
        base.update(kw)
        PS.save(PS.ProxyDefaults(**base))
        self._pw["value"] = "pw"

    def test_proxy_answer_carries_the_defaults_credentials_and_auth(self) -> None:
        self.default()
        r = PS.resolve("default", None, "example.org", 443, "webdav")
        c = r.config
        self.assertEqual(
            (c.proxy_type, c.host, c.port, c.username, c.password),
            ("http+ntlm", "pac.proxy", 3128, "DOM\\u", "pw"),
        )
        self.assertEqual(r.source, "pac")

    def test_socks_answer_has_no_http_auth_suffix(self) -> None:
        self.default()
        c = PS.resolve("default", None, "viasocks.example", 22, "sftp").config
        self.assertEqual((c.proxy_type, c.host, c.port), ("socks5", "socks.pac", 1080))

    def test_https_answer(self) -> None:
        self.default()
        c = PS.resolve("default", None, "tls.example", 443, "webdav").config
        self.assertEqual((c.transport, c.auth_scheme, c.host), ("https", "ntlm", "tls.pac"))

    def test_direct_answer(self) -> None:
        self.default()
        r = PS.resolve("default", None, "a.direct.example", 22, "sftp")
        self.assertEqual((r.config, r.source), (None, "pac"))

    def test_bypass_is_checked_before_the_pac(self) -> None:
        self.default(bypass=["example.org"])
        self.assertEqual(PS.resolve("default", None, "example.org", 22).source, "bypass")

    def test_missing_pac_file_fails_closed(self) -> None:
        self.default(pac_url=str(self.tmp / "nope.pac"))
        with self.assertRaises(PS.ProxyResolutionError):
            PS.resolve("default", None, "example.org", 22)

    def test_broken_pac_fails_closed(self) -> None:
        self.pac_file.write_text("function FindProxyForURL(u,h){ return eval('x'); }")
        self.default()
        with self.assertRaises(PS.ProxyResolutionError):
            PS.resolve("default", None, "example.org", 22)

    def test_pac_runtime_error_fails_closed(self) -> None:
        self.pac_file.write_text("function FindProxyForURL(u,h){ return 'nonsense'; }")
        self.default()
        with self.assertRaises(PS.ProxyResolutionError):
            PS.resolve("default", None, "example.org", 22)

    def test_a_failed_refresh_keeps_the_last_good_script(self) -> None:
        self.default()
        PS.resolve("default", None, "example.org", 22)
        self.pac_file.unlink()
        for k in list(PS._PAC_CACHE):
            t, script = PS._PAC_CACHE[k]
            PS._PAC_CACHE[k] = (t - PS.PAC_TTL_SECONDS - 1, script)  # expire
        r = PS.resolve("default", None, "example.org", 22)
        self.assertEqual(r.config.host, "pac.proxy")

    def test_pac_is_cached_within_the_ttl(self) -> None:
        self.default()
        with mock.patch.object(PS, "_fetch_pac_source", wraps=PS._fetch_pac_source) as fetch:
            PS.resolve("default", None, "a.example", 22)
            PS.resolve("default", None, "b.example", 22)
        self.assertEqual(fetch.call_count, 1)

    def test_oversized_pac_is_refused(self) -> None:
        self.pac_file.write_text("//" + "x" * (PS.MAX_PAC_BYTES + 10))
        self.default()
        with self.assertRaises(PS.ProxyResolutionError):
            PS.resolve("default", None, "example.org", 22)

    def test_http_pac_is_fetched_without_environment_proxies(self) -> None:
        import threading
        from http.server import BaseHTTPRequestHandler, HTTPServer

        class H(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                body = PacResolutionTest.PAC.encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        srv = HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.shutdown)
        self.default(pac_url=f"http://127.0.0.1:{srv.server_port}/proxy.pac")
        with mock.patch.dict(os.environ, {"HTTP_PROXY": "http://203.0.113.9:1"}):
            c = PS.resolve("default", None, "example.org", 22).config
        self.assertEqual(c.host, "pac.proxy")


class ProfileModeTest(_Isolated):
    def default(self):
        PS.save(PS.ProxyDefaults("socks5", "def.proxy", 1080, "du", True))
        self._pw["value"] = "dpw"

    def test_legacy_profiles_stay_direct_and_serialise_without_the_new_key(self) -> None:
        p = ConnectionProfile(name="legacy", host="h")
        self.assertEqual(p.proxy_mode, "custom")
        self.assertNotIn("proxy_mode", p.to_dict())
        again = ConnectionProfile.from_dict(p.to_dict())
        self.assertEqual(again.proxy_mode, "custom")
        self.default()
        self.assertIs(cm.effective_profile(p), p)

    def test_mode_roundtrip_and_validation(self) -> None:
        p = ConnectionProfile(name="x", host="h", proxy_mode="default")
        self.assertEqual(p.to_dict()["proxy_mode"], "default")
        self.assertEqual(ConnectionProfile.from_dict(p.to_dict()).proxy_mode, "default")
        d = p.to_dict()
        d["proxy_mode"] = "banana"
        self.assertEqual(ConnectionProfile.from_dict(d).proxy_mode, "custom")

    def test_new_proxy_kinds_survive_the_profile_roundtrip(self) -> None:
        for kind in ("https", "http+ntlm", "https+negotiate", "http+kerberos"):
            p = ConnectionProfile(name="x", host="h", proxy_type=kind, proxy_host="p", proxy_port=1)
            self.assertEqual(ConnectionProfile.from_dict(p.to_dict()).proxy_type, kind)
        d = ConnectionProfile(
            name="x", host="h", proxy_type="socks5", proxy_host="p", proxy_port=1
        ).to_dict()
        d["proxy_type"] = "socks5+ntlm"
        self.assertEqual(ConnectionProfile.from_dict(d).proxy_type, "none")

    def test_default_mode_resolves_into_a_plain_profile(self) -> None:
        self.default()
        p = ConnectionProfile(name="x", host="db.example", proxy_mode="default")
        e = cm.effective_profile(p)
        self.assertEqual(
            (e.proxy_mode, e.proxy_type, e.proxy_host, e.proxy_port, e.proxy_username),
            ("custom", "socks5", "def.proxy", 1080, "du"),
        )
        self.assertEqual(e.get_proxy_password(), "dpw")
        self.assertEqual(p.proxy_type, "none", "the original profile must not be mutated")

    def test_bypassed_target_resolves_to_direct(self) -> None:
        self.default()
        p = ConnectionProfile(name="x", host="localhost", proxy_mode="default")
        self.assertEqual(cm.effective_profile(p).proxy_type, "none")

    def test_none_mode_ignores_even_its_own_fields(self) -> None:
        self.default()
        p = ConnectionProfile(
            name="x", host="h", proxy_mode="none", proxy_type="http", proxy_host="p", proxy_port=1
        )
        self.assertEqual(cm.effective_profile(p).proxy_type, "none")

    def test_proxy_kwargs_of_a_resolved_profile(self) -> None:
        self.default()
        e = cm.effective_profile(
            ConnectionProfile(name="x", host="h.example", proxy_mode="default")
        )
        kw = cm._proxy_kwargs(e)
        self.assertEqual(
            (kw["proxy_type"], kw["proxy_host"], kw["proxy_password"]),
            ("socks5", "def.proxy", "dpw"),
        )

    def test_session_key_follows_the_resolved_proxy(self) -> None:
        mgr = cm.ConnectionManager()
        p = ConnectionProfile(name="x", host="h.example", proxy_mode="default")
        k_none = mgr._session_key(p)
        self.default()
        k_proxy = mgr._session_key(p)
        self.assertNotEqual(k_none, k_proxy)

    def test_url_based_protocols_use_the_url_host_for_the_bypass(self) -> None:
        self.default()
        PS.save(PS.ProxyDefaults("socks5", "def.proxy", 1080, "du", True, ["*.corp.local"]))
        p = ConnectionProfile(
            name="x",
            protocol="webdav",
            host="ignored",
            webdav_url="https://cloud.corp.local/dav",
            proxy_mode="default",
        )
        self.assertEqual(cm.effective_profile(p).proxy_type, "none")
        p2 = ConnectionProfile(
            name="x",
            protocol="webdav",
            host="ignored",
            webdav_url="https://cloud.example.org/dav",
            proxy_mode="default",
        )
        self.assertEqual(cm.effective_profile(p2).proxy_type, "socks5")
        s3 = ConnectionProfile(name="x", protocol="s3", s3_bucket="b", proxy_mode="default")
        self.assertEqual(PS.target_of(s3), ("s3.amazonaws.com", 443))


class ScriptingDefaultTest(_Isolated):
    """axross.open_url uses the default unless the caller names a proxy."""

    def _capture(self, url: str, **kw):
        from core import scripting

        seen = {}

        def fake_cm(proto_id, parts, kwargs, original, proxy_kwargs, **rest):
            seen.update(proxy_kwargs)
            return object()

        with mock.patch.object(scripting, "_open_url_via_cm", fake_cm):
            scripting.open_url(url, **kw)
        return seen

    def test_default_is_applied_when_no_proxy_is_named(self) -> None:
        PS.save(PS.ProxyDefaults("socks5", "def.proxy", 1080))
        seen = self._capture("sftp://alice@db.example.org/")
        self.assertEqual((seen["proxy_type"], seen["proxy_host"]), ("socks5", "def.proxy"))

    def test_bypass_applies_to_scripts_too(self) -> None:
        PS.save(PS.ProxyDefaults("socks5", "def.proxy", 1080, bypass=["*.example.org"]))
        self.assertEqual(self._capture("sftp://alice@db.example.org/"), {})

    def test_explicit_none_stays_direct(self) -> None:
        PS.save(PS.ProxyDefaults("socks5", "def.proxy", 1080))
        self.assertEqual(
            self._capture("sftp://alice@db.example.org/", proxy_type="none")["proxy_type"], "none"
        )

    def test_explicit_proxy_wins_over_the_default(self) -> None:
        PS.save(PS.ProxyDefaults("socks5", "def.proxy", 1080))
        seen = self._capture(
            "sftp://alice@h.example.org/", proxy_type="http", proxy_host="mine", proxy_port=3128
        )
        self.assertEqual(seen["proxy_host"], "mine")

    def test_no_default_means_no_proxy(self) -> None:
        self.assertEqual(self._capture("sftp://alice@h.example.org/"), {})


class ProbeTest(_Isolated):
    def setUp(self) -> None:
        super().setUp()
        self.pki = TestPki()
        self.echo = EchoServer()
        self.addCleanup(self.echo.close)
        self.routes = {("db.internal", 5432): ("127.0.0.1", self.echo.port)}
        patcher = allow_loopback_proxy()
        patcher.__enter__()
        self.addCleanup(patcher.__exit__, None, None, None)

    def test_success(self) -> None:
        socks = FakeSocks5Server(self.routes)
        self.addCleanup(socks.close)
        r = PS.probe(proxy.ProxyConfig("socks5", "127.0.0.1", socks.port), "db.internal", 5432)
        self.assertTrue(r.ok)
        self.assertEqual(r.stage, "ok")

    def test_unreachable_proxy(self) -> None:
        import socket

        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        r = PS.probe(proxy.ProxyConfig("http", "127.0.0.1", port), "db.internal", 5432, timeout=2)
        self.assertFalse(r.ok)
        self.assertEqual(r.stage, "proxy")

    def test_tls_failure_is_reported_as_tls(self) -> None:
        srv = FakeHttpProxy(self.routes, tls=TestPki().issue("127.0.0.1"))
        self.addCleanup(srv.close)
        r = PS.probe(
            proxy.ProxyConfig("https", "127.0.0.1", srv.port, ca_file=self.pki.ca_file),
            "db.internal",
            5432,
        )
        self.assertEqual((r.ok, r.stage), (False, "tls"))

    def test_auth_failure_is_reported_as_auth(self) -> None:
        srv = FakeHttpProxy(self.routes, auth="ntlm")
        self.addCleanup(srv.close)
        r = PS.probe(
            proxy.ProxyConfig("http+ntlm", "127.0.0.1", srv.port, "DOM\\alice", "bad"),
            "db.internal",
            5432,
        )
        self.assertEqual((r.ok, r.stage), (False, "auth"))

    def test_target_refused_is_a_tunnel_failure(self) -> None:
        socks = FakeSocks5Server(self.routes)
        self.addCleanup(socks.close)
        r = PS.probe(proxy.ProxyConfig("socks5", "127.0.0.1", socks.port), "nope.internal", 1)
        self.assertFalse(r.ok)
        self.assertIn(r.stage, ("tunnel", "proxy"))

    def test_disabled_config(self) -> None:
        r = PS.probe(proxy.ProxyConfig("none"), "h", 1)
        self.assertEqual((r.ok, r.stage), (False, "config"))

    def test_the_result_never_contains_the_password(self) -> None:
        srv = FakeHttpProxy(self.routes, auth="basic")
        self.addCleanup(srv.close)
        r = PS.probe(
            proxy.ProxyConfig("http", "127.0.0.1", srv.port, "alice", "TOPSECRETPW"),
            "db.internal",
            5432,
        )
        self.assertNotIn("TOPSECRETPW", r.message)


class ComposeProxyTypeTest(unittest.TestCase):
    def test_roundtrip_with_parse(self) -> None:
        from core.proxy import compose_proxy_type, parse_proxy_type

        for kind in ("socks5", "socks4", "http", "https", "http+ntlm", "https+negotiate"):
            self.assertEqual(compose_proxy_type(*parse_proxy_type(kind)), kind)

    def test_empty_auth_is_the_bare_transport(self) -> None:
        from core.proxy import compose_proxy_type

        self.assertEqual(compose_proxy_type("https", ""), "https")

    def test_auth_on_socks_is_rejected(self) -> None:
        from core.proxy import compose_proxy_type

        with self.assertRaises(ValueError):
            compose_proxy_type("socks5", "ntlm")

    def test_unknown_parts_are_rejected(self) -> None:
        from core.proxy import compose_proxy_type

        for args in (("ftp", ""), ("http", "digest"), ("", "")):
            with self.assertRaises(ValueError):
                compose_proxy_type(*args)


class AdoptDefaultProxyTest(unittest.TestCase):
    def _profile(self, name: str, protocol: str, mode: str = "custom"):
        from core.profiles import ConnectionProfile

        return ConnectionProfile(name=name, protocol=protocol, host="h", proxy_mode=mode)

    def test_switches_proxy_capable_profiles(self) -> None:
        profiles = [self._profile("a", "sftp"), self._profile("b", "ftp", "none")]
        changed = PS.adopt_default_proxy(profiles)
        self.assertEqual(changed, ["a", "b"])
        self.assertEqual([p.proxy_mode for p in profiles], ["default", "default"])

    def test_skips_protocols_a_proxy_cannot_carry(self) -> None:
        profiles = [self._profile("r", "rsh"), self._profile("m", "ramfs")]
        self.assertEqual(PS.adopt_default_proxy(profiles), [])
        self.assertEqual({p.proxy_mode for p in profiles}, {"custom"})

    def test_already_default_profiles_are_not_reported(self) -> None:
        profiles = [self._profile("a", "sftp", "default")]
        self.assertEqual(PS.adopt_default_proxy(profiles), [])

    def test_empty_list(self) -> None:
        self.assertEqual(PS.adopt_default_proxy([]), [])


class PacWithoutFixedHostTest(unittest.TestCase):
    def test_pac_makes_host_and_port_optional(self) -> None:
        d = PS.ProxyDefaults(proxy_type="http+ntlm", pac_url="http://pac.example/wpad.dat")
        PS.validate(d)  # must not raise

    def test_without_pac_the_host_is_still_required(self) -> None:
        with self.assertRaises(ValueError):
            PS.validate(PS.ProxyDefaults(proxy_type="http+ntlm"))


if __name__ == "__main__":
    unittest.main()
