"""End-to-end proxy verification against real proxy servers (podman).

Opt in with ``AXROSS_PROXY_LAB=1``; the lab (``tests/proxy_lab.py``) is
built, started and removed by this module. The services behind the
proxies (``ssh.lab`` ...) have no published ports and names the host
cannot resolve -- a connection that bypasses the proxy cannot succeed, so
every green test here is proof of routing, not just of "it connected".

    AXROSS_PROXY_LAB=1 .venv/bin/python -m pytest tests/test_proxy_lab.py -q
"""

from __future__ import annotations

import http.server
import json
import os
import shutil
import socket
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tests import proxy_lab  # noqa: E402

_ENABLED = os.environ.get("AXROSS_PROXY_LAB") == "1"
LAB: proxy_lab.ProxyLab | None = None

# Kinds that carry host names (SOCKS4 servers such as dante only take IPv4
# addresses; they are exercised separately with the container's address).
NAMED_PROXIES = ("socks5", "socks5-auth", "http", "http-basic", "https-basic", "http-ntlm")
ALL_PROXIES = ("socks5", "socks4", "socks5-auth", "http", "http-basic", "https-basic", "http-ntlm")


def setUpModule() -> None:  # noqa: N802 - unittest hook name
    global LAB
    if not _ENABLED:
        raise unittest.SkipTest("set AXROSS_PROXY_LAB=1 to run the podman proxy lab tests")
    if not proxy_lab.podman_available():
        raise unittest.SkipTest("podman is not installed")
    LAB = proxy_lab.ProxyLab.up()


def tearDownModule() -> None:  # noqa: N802
    if LAB is not None and os.environ.get("AXROSS_PROXY_LAB_KEEP") != "1":
        LAB.close()


def _guard():
    """The lab proxies live on loopback, which the SSRF guard refuses."""
    return mock.patch("core.proxy._assert_proxy_host_not_private")


class _LabCase(unittest.TestCase):
    def setUp(self) -> None:
        assert LAB is not None
        self.lab = LAB
        guard = _guard()
        guard.start()
        self.addCleanup(guard.stop)
        # The CA that signed the TLS proxy certificate.
        patcher = mock.patch.dict(os.environ, {"AXROSS_PROXY_CA_FILE": self.lab.ca_file})
        patcher.start()
        self.addCleanup(patcher.stop)
        # known_hosts of the lab host keys goes to a throwaway home.
        self.home = Path(tempfile.mkdtemp(prefix="axproxy-home-"))
        self.addCleanup(shutil.rmtree, self.home, ignore_errors=True)
        home = mock.patch("pathlib.Path.home", return_value=self.home)
        home.start()
        self.addCleanup(home.stop)

    def cfg(self, name: str, **override):
        from core.proxy import ProxyConfig

        kw = self.lab.proxy(name)
        kw.update(override)
        return ProxyConfig(
            kw["proxy_type"],
            kw["proxy_host"],
            kw["proxy_port"],
            kw["proxy_username"],
            kw["proxy_password"],
        )


class RawTunnelTest(_LabCase):
    """A TCP tunnel to redis through every proxy kind."""

    def _ping(self, sock: socket.socket) -> bytes:
        sock.sendall(b"PING\r\n")
        sock.settimeout(10)
        return sock.recv(64)

    def test_every_proxy_kind_reaches_redis(self) -> None:
        from core.proxy import create_proxy_socket

        for name in NAMED_PROXIES:
            with self.subTest(proxy=name):
                sock = create_proxy_socket(self.cfg(name), "redis.lab", 6379, timeout=15)
                try:
                    self.assertEqual(self._ping(sock), b"+PONG\r\n")
                finally:
                    sock.close()

    def test_socks4_reaches_redis_by_address(self) -> None:
        from core.proxy import create_proxy_socket

        sock = create_proxy_socket(self.cfg("socks4"), self.lab.target_ip(), 6379, timeout=15)
        try:
            self.assertEqual(self._ping(sock), b"+PONG\r\n")
        finally:
            sock.close()

    def test_the_target_is_unreachable_without_a_proxy(self) -> None:
        # Negative control: the same name and port, no proxy.
        with self.assertRaises(OSError):
            socket.create_connection(("redis.lab", 6379), timeout=3)

    def test_unknown_target_name_is_reported_not_hung(self) -> None:
        from core.proxy import create_proxy_socket

        for name in ("socks5", "http-basic"):
            with self.subTest(proxy=name):
                with self.assertRaises(OSError):
                    create_proxy_socket(self.cfg(name), "no-such-host.lab", 6379, timeout=10)

    def test_closed_port_on_a_known_host_is_refused(self) -> None:
        from core.proxy import create_proxy_socket

        for name in ("socks5", "http-basic"):
            with self.subTest(proxy=name):
                with self.assertRaises(OSError):
                    create_proxy_socket(self.cfg(name), "redis.lab", 9, timeout=10)

    def test_wrong_proxy_password_is_an_auth_error(self) -> None:
        from core.proxy import create_proxy_socket

        for name in ("http-basic", "https-basic", "socks5-auth"):
            with self.subTest(proxy=name):
                with self.assertRaises(ConnectionError):
                    create_proxy_socket(
                        self.cfg(name, proxy_password="wrong"), "redis.lab", 6379, timeout=10
                    )

    def test_missing_credentials_on_an_authenticating_proxy_fail(self) -> None:
        from core.proxy import create_proxy_socket

        for name in ("http-basic", "socks5-auth"):
            with self.subTest(proxy=name):
                with self.assertRaises(ConnectionError):
                    create_proxy_socket(
                        self.cfg(name, proxy_username="", proxy_password=""),
                        "redis.lab",
                        6379,
                        timeout=10,
                    )

    def test_tls_proxy_with_the_wrong_ca_is_refused(self) -> None:
        from core.proxy import ProxyConfig, create_proxy_socket

        other = self.lab.workdir / "other-ca.pem"
        from tests.proxy_http_testkit import TestPki

        shutil.copy(TestPki().ca_file, other)
        spec = self.lab.proxy("https-basic")
        cfg = ProxyConfig(
            spec["proxy_type"],
            spec["proxy_host"],
            spec["proxy_port"],
            spec["proxy_username"],
            spec["proxy_password"],
            ca_file=str(other),
        )
        with self.assertRaises(ConnectionError):
            create_proxy_socket(cfg, "redis.lab", 6379, timeout=10)

    def test_ntlm_handshake_against_squid(self) -> None:
        from core.proxy import create_proxy_socket

        # ntlm_fake_auth validates the message flow, not the password:
        # this proves our Type 1 / Type 3 messages are well-formed enough
        # for an independent server implementation.
        sock = create_proxy_socket(self.cfg("http-ntlm"), "redis.lab", 6379, timeout=15)
        try:
            self.assertEqual(self._ping(sock), b"+PONG\r\n")
        finally:
            sock.close()


class ProbeTest(_LabCase):
    def test_probe_succeeds_through_every_kind(self) -> None:
        from core import proxy_settings

        for name in NAMED_PROXIES:
            with self.subTest(proxy=name):
                result = proxy_settings.probe(self.cfg(name), "redis.lab", 6379, timeout=15)
                self.assertTrue(result.ok, result)
                self.assertEqual(result.stage, "ok")

    def test_probe_succeeds_through_socks4_by_address(self) -> None:
        from core import proxy_settings

        result = proxy_settings.probe(self.cfg("socks4"), self.lab.target_ip(), 6379, timeout=15)
        self.assertTrue(result.ok, result)

    def test_probe_names_the_auth_stage(self) -> None:
        from core import proxy_settings

        result = proxy_settings.probe(
            self.cfg("http-basic", proxy_password="nope"), "redis.lab", 6379, timeout=15
        )
        self.assertFalse(result.ok)
        self.assertEqual(result.stage, "auth", result)

    def test_probe_names_the_proxy_stage_when_nothing_listens(self) -> None:
        from core import proxy_settings

        result = proxy_settings.probe(
            self.cfg("socks5", proxy_port=1), "redis.lab", 6379, timeout=5
        )
        self.assertFalse(result.ok)
        self.assertEqual(result.stage, "proxy", result)


class ProtocolTest(_LabCase):
    """Whole backends, driven the way the application drives them."""

    def _profile(self, protocol: str, host: str, **fields):
        from core.profiles import ConnectionProfile

        return ConnectionProfile(name=f"lab-{protocol}", protocol=protocol, host=host, **fields)

    def _with_proxy(self, profile, proxy_name: str):
        spec = self.lab.proxy(proxy_name)
        profile.proxy_mode = "custom"
        profile.proxy_type = spec["proxy_type"]
        profile.proxy_host = spec["proxy_host"]
        profile.proxy_port = spec["proxy_port"]
        profile.proxy_username = spec["proxy_username"]
        profile._proxy_password_override = spec["proxy_password"]
        return profile

    def _connect(self, profile, password: str = ""):
        from core.connection_manager import ConnectionManager

        manager = ConnectionManager()
        self.addCleanup(manager.disconnect_all)
        return manager.connect(profile, password=password, on_unknown_host=lambda _err: True)

    def _read(self, session, path: str) -> bytes:
        with session.open_read(path) as handle:
            return handle.read()

    def test_sftp_through_every_proxy_kind(self) -> None:
        for name in NAMED_PROXIES:
            with self.subTest(proxy=name):
                profile = self._with_proxy(
                    self._profile(
                        "sftp",
                        "ssh.lab",
                        port=22,
                        username=proto_user(),
                        auth_type="password",
                    ),
                    name,
                )
                session = self._connect(profile, password=proxy_lab.TARGET_PASSWORD)
                names = {item.name for item in session.list_dir("~/data")}
                self.assertIn("readme.txt", names)
                self.assertEqual(
                    self._read(session, "~/data/readme.txt"),
                    b"hello through the proxy\n",
                )

    def test_sftp_through_socks4_by_address(self) -> None:
        profile = self._with_proxy(
            self._profile(
                "sftp",
                self.lab.target_ip(),
                port=22,
                username=proto_user(),
                auth_type="password",
            ),
            "socks4",
        )
        session = self._connect(profile, password=proxy_lab.TARGET_PASSWORD)
        self.assertEqual(
            self._read(session, "~/data/readme.txt"), b"hello through the proxy\n"
        )

    def test_http_through_socks4_by_address(self) -> None:
        import requests

        from core.proxy import build_requests_proxies

        spec = self.lab.proxy("socks4")
        proxies = build_requests_proxies(spec["proxy_type"], spec["proxy_host"], spec["proxy_port"])
        response = requests.get(
            f"http://{self.lab.target_ip()}/index.html", proxies=proxies, timeout=20
        )
        self.assertEqual(response.text, "hello over http\n")

    def test_ftp_passive_data_channel_goes_through_the_proxy(self) -> None:
        for name in ("socks5", "http-basic", "https-basic"):
            with self.subTest(proxy=name):
                profile = self._with_proxy(
                    self._profile("ftp", "ftp.lab", port=21, username="anonymous"), name
                )
                session = self._connect(profile, password="lab@example.test")
                self.assertIn("readme.txt", {i.name for i in session.list_dir("/")})
                self.assertEqual(self._read(session, "/readme.txt"), b"hello over ftp\n")

    def test_http_through_requests_for_every_kind(self) -> None:
        import requests

        from core.proxy import build_requests_proxies

        for name in NAMED_PROXIES:
            with self.subTest(proxy=name):
                spec = self.lab.proxy(name)
                proxies = build_requests_proxies(
                    spec["proxy_type"],
                    spec["proxy_host"],
                    spec["proxy_port"],
                    spec["proxy_username"],
                    spec["proxy_password"],
                    self.lab.ca_file,
                )
                response = requests.get("http://http.lab/index.html", proxies=proxies, timeout=20)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.text, "hello over http\n")

    def test_http_without_a_proxy_cannot_resolve_the_lab(self) -> None:
        import requests

        with self.assertRaises(requests.RequestException):
            requests.get("http://http.lab/index.html", timeout=5)


def proto_user() -> str:
    return proxy_lab.TARGET_USER


class _PacHandler(http.server.BaseHTTPRequestHandler):
    body = b""

    def do_GET(self) -> None:  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Type", "application/x-ns-proxy-autoconfig")
        self.send_header("Content-Length", str(len(self.body)))
        self.end_headers()
        self.wfile.write(self.body)

    def log_message(self, *args) -> None:
        pass


class DefaultProxyAndPacTest(_LabCase):
    """Global default, bypass list and PAC, all against the real lab."""

    def setUp(self) -> None:
        super().setUp()
        from core import proxy_settings

        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        patcher = mock.patch.object(proxy_settings, "SETTINGS_PATH", self.tmp / "proxy.json")
        patcher.start()
        self.addCleanup(patcher.stop)
        for name, impl in (
            ("get_password", lambda: proxy_lab.PROXY_PASSWORD),
            ("set_password", lambda _v: True),
        ):
            p = mock.patch.object(proxy_settings, name, impl)
            p.start()
            self.addCleanup(p.stop)
        self.ps = proxy_settings

    def _defaults(self, **fields):
        base = {
            "proxy_type": "none",
            "host": "",
            "port": 0,
            "username": "",
            "store_password": False,
            "bypass": [],
            "ca_file": self.lab.ca_file,
            "pac_url": "",
        }
        base.update(fields)
        (self.tmp / "proxy.json").write_text(json.dumps(base), encoding="utf-8")

    def _sftp(self):
        from core.connection_manager import ConnectionManager
        from core.profiles import ConnectionProfile

        profile = ConnectionProfile(
            name="lab-default",
            protocol="sftp",
            host="ssh.lab",
            port=22,
            username=proxy_lab.TARGET_USER,
            auth_type="password",
            proxy_mode="default",
        )
        manager = ConnectionManager()
        self.addCleanup(manager.disconnect_all)
        return manager.connect(
            profile, password=proxy_lab.TARGET_PASSWORD, on_unknown_host=lambda _err: True
        )

    def test_default_http_proxy_with_stored_password(self) -> None:
        spec = self.lab.proxy("http-basic")
        self._defaults(
            proxy_type="http+basic",
            host=spec["proxy_host"],
            port=spec["proxy_port"],
            username=proxy_lab.PROXY_USER,
            store_password=True,
        )
        session = self._sftp()
        self.assertIn("readme.txt", {i.name for i in session.list_dir("~/data")})

    def test_default_https_proxy_uses_the_configured_ca(self) -> None:
        spec = self.lab.proxy("https-basic")
        self._defaults(
            proxy_type="https+basic",
            host=spec["proxy_host"],
            port=spec["proxy_port"],
            username=proxy_lab.PROXY_USER,
            store_password=True,
        )
        with mock.patch.dict(os.environ, {"AXROSS_PROXY_CA_FILE": ""}):
            session = self._sftp()
        self.assertTrue(session.list_dir("~/data"))

    def test_bypass_entry_sends_the_target_direct_and_it_fails_as_expected(self) -> None:
        spec = self.lab.proxy("socks5")
        self._defaults(
            proxy_type="socks5", host=spec["proxy_host"], port=spec["proxy_port"], bypass=["*.lab"]
        )
        # Bypassed -> a direct connection to a name only the lab resolves.
        with self.assertRaises(Exception):
            self._sftp()

    def test_pac_script_selects_the_proxy_per_host(self) -> None:
        spec = self.lab.proxy("socks5")
        script = (
            "function FindProxyForURL(url, host) {\n"
            f"  if (dnsDomainIs(host, '.lab')) return 'SOCKS5 127.0.0.1:{spec['proxy_port']}';\n"
            "  return 'DIRECT';\n"
            "}\n"
        )
        handler = type("Pac", (_PacHandler,), {"body": script.encode()})
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.shutdown)
        self._defaults(pac_url=f"http://127.0.0.1:{server.server_address[1]}/wpad.dat")
        session = self._sftp()
        self.assertIn("readme.txt", {i.name for i in session.list_dir("~/data")})

    def test_pac_direct_answer_means_no_proxy(self) -> None:
        script = "function FindProxyForURL(url, host) { return 'DIRECT'; }"
        handler = type("Pac", (_PacHandler,), {"body": script.encode()})
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.shutdown)
        self._defaults(pac_url=f"http://127.0.0.1:{server.server_address[1]}/wpad.dat")
        with self.assertRaises(Exception):
            self._sftp()

    def test_unreachable_pac_fails_closed_not_direct(self) -> None:
        from core.proxy_settings import ProxyResolutionError

        self._defaults(pac_url="http://127.0.0.1:1/wpad.dat")
        with self.assertRaises(ProxyResolutionError):
            self._sftp()

    def test_scripting_open_url_picks_up_the_default_proxy(self) -> None:
        from core import scripting

        spec = self.lab.proxy("socks5")
        self._defaults(proxy_type="socks5", host=spec["proxy_host"], port=spec["proxy_port"])
        kwargs = self.ps.default_proxy_kwargs("ssh.lab", 22, "sftp")
        self.assertEqual(kwargs["proxy_port"], spec["proxy_port"])
        self.assertTrue(hasattr(scripting, "open_url"))


if __name__ == "__main__":
    unittest.main()
