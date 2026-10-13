"""Backends that used to ignore the profile proxy now route through it.

Every test uses a loopback SOCKS5 fake that records the *requested*
target. The names used (``db.internal`` ...) do not resolve locally, so a
direct fallback could not succeed -- the recorded CONNECT proves routing.
"""
from __future__ import annotations

import os
import shutil
import socket
import tempfile
import threading
import unittest
from unittest import mock

from core import proxy
from tests.proxy_testkit import (
    EchoServer,
    FakeSocks5Server,
    UdpEchoServer,
    allow_loopback_proxy,
    socks_kwargs,
)


class _ProxyCase(unittest.TestCase):
    def setUp(self) -> None:
        guard = allow_loopback_proxy()
        guard.__enter__()
        self.addCleanup(guard.__exit__, None, None, None)
        self.echo = EchoServer(banner=b"")
        self.addCleanup(self.echo.close)

    def socks(self, routes) -> FakeSocks5Server:
        server = FakeSocks5Server(routes=routes)
        self.addCleanup(server.close)
        return server

    def route(self, host: str, port: int) -> FakeSocks5Server:
        return self.socks({(host, port): ("127.0.0.1", self.echo.port)})


# ---------------------------------------------------------------------------
# Redis
# ---------------------------------------------------------------------------


class _FakeRedis:
    """Answers PING with +PONG and every other command with +OK."""

    def __init__(self) -> None:
        self._listener = socket.socket()
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(8)
        self.port = self._listener.getsockname()[1]
        self.clients: list[tuple] = []
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self) -> None:
        while True:
            try:
                conn, addr = self._listener.accept()
            except OSError:
                return
            self.clients.append(addr)
            threading.Thread(target=self._client, args=(conn,), daemon=True).start()

    def _client(self, conn: socket.socket) -> None:
        reader = conn.makefile("rb")
        try:
            while True:
                head = reader.readline()
                if not head:
                    return
                count = int(head[1:])
                args = []
                for _ in range(count):
                    length = int(reader.readline()[1:])
                    args.append(reader.read(length + 2)[:-2])
                conn.sendall(b"+PONG\r\n" if args[0].upper() == b"PING" else b"+OK\r\n")
        except (OSError, ValueError):
            return
        finally:
            conn.close()

    def close(self) -> None:
        self._listener.close()


class RedisProxyTest(_ProxyCase):
    def setUp(self) -> None:
        super().setUp()
        self.fake = _FakeRedis()
        self.addCleanup(self.fake.close)

    def test_connection_goes_through_the_proxy(self) -> None:
        from core.redis_fs_client import RedisFsSession

        socks = self.socks({("redis.internal", 6379): ("127.0.0.1", self.fake.port)})
        session = RedisFsSession(host="redis.internal", port=6379, **socks_kwargs(socks))
        self.addCleanup(session.close)
        self.assertEqual(socks.connects[0], ("redis.internal", 6379))

    def test_refused_by_proxy_never_falls_back_to_direct(self) -> None:
        from core.redis_fs_client import RedisFsSession

        socks = self.socks({})
        with self.assertRaises(Exception):
            RedisFsSession(host="127.0.0.1", port=self.fake.port, **socks_kwargs(socks))
        # 127.0.0.1:<fake.port> is reachable directly -- it must not have been used.
        self.assertEqual(self.fake.clients, [])

    def test_no_proxy_connects_directly(self) -> None:
        from core.redis_fs_client import RedisFsSession

        session = RedisFsSession(host="127.0.0.1", port=self.fake.port)
        self.addCleanup(session.close)
        self.assertEqual(len(self.fake.clients), 1)

    def test_tls_connection_class_keeps_ssl_wrapping(self) -> None:
        import redis.connection as rc

        from core.redis_fs_client import _proxied_connection_class

        cfg = proxy.ProxyConfig("socks5", "127.0.0.1", 1)
        self.assertTrue(issubclass(_proxied_connection_class(cfg, True), rc.SSLConnection))
        self.assertFalse(issubclass(_proxied_connection_class(cfg, False), rc.SSLConnection))


# ---------------------------------------------------------------------------
# PostgreSQL
# ---------------------------------------------------------------------------


class PostgresProxyTest(_ProxyCase):
    def test_dsn_points_at_tunnel_but_keeps_real_host_for_tls(self) -> None:
        from core import postgres_fs_client as pg

        socks = self.route("pg.internal", 5432)
        captured = {}

        def fake_connect(dsn, **kw):
            captured["dsn"] = dsn
            return mock.MagicMock()

        with mock.patch.object(pg.psycopg, "connect", side_effect=fake_connect):
            session = pg.PostgresFsSession(
                host="pg.internal",
                database="d",
                username="u",
                password="p",
                **socks_kwargs(socks),
            )
        dsn = captured["dsn"]
        self.assertIn("host='pg.internal'", dsn)
        self.assertIn("hostaddr='127.0.0.1'", dsn)
        self.assertNotIn("port='5432'", dsn)
        tunnel_port = session._tunnel.port
        self.assertIn(f"port='{tunnel_port}'", dsn)
        session.close()
        with self.assertRaises(OSError):
            socket.create_connection(("127.0.0.1", tunnel_port), timeout=1)

    def test_real_psycopg_connect_is_routed_by_the_proxy(self) -> None:
        from core import postgres_fs_client as pg

        socks = self.route("pg.internal", 5432)
        with self.assertRaises(Exception):
            pg.PostgresFsSession(
                host="pg.internal", database="d", username="u", password="p",
                **socks_kwargs(socks),
            )
        self.assertEqual(socks.connects[0], ("pg.internal", 5432))

    def test_failed_connect_closes_the_tunnel(self) -> None:
        from core import postgres_fs_client as pg

        socks = self.route("pg.internal", 5432)
        seen = []
        real = proxy.open_tunnel

        def spy(*a, **k):
            tunnel = real(*a, **k)
            seen.append(tunnel)
            return tunnel

        with mock.patch.object(proxy, "open_tunnel", side_effect=spy):
            with mock.patch.object(pg.psycopg, "connect", side_effect=OSError("boom")):
                with self.assertRaises(OSError):
                    pg.PostgresFsSession(
                        host="pg.internal", database="d", **socks_kwargs(socks)
                    )
        with self.assertRaises(OSError):
            socket.create_connection(("127.0.0.1", seen[0].port), timeout=1)

    def test_dsn_values_are_quoted_against_parameter_injection(self) -> None:
        from core import postgres_fs_client as pg

        captured = {}
        with mock.patch.object(
            pg.psycopg, "connect",
            side_effect=lambda dsn, **kw: captured.setdefault("dsn", dsn) and mock.MagicMock(),
        ):
            pg.PostgresFsSession(
                host="h", database="d", username="u", password="x host=evil.example"
            )
        from psycopg.conninfo import conninfo_to_dict

        parsed = conninfo_to_dict(captured["dsn"])
        self.assertEqual(parsed["password"], "x host=evil.example")
        self.assertEqual(parsed["host"], "h")

    def test_quote_escapes_quote_and_backslash(self) -> None:
        from core.postgres_fs_client import _dsn_quote

        self.assertEqual(_dsn_quote("a'b\\c"), "'a\\'b\\\\c'")


# ---------------------------------------------------------------------------
# MongoDB
# ---------------------------------------------------------------------------


class MongoProxyTest(_ProxyCase):
    def _session(self, socks, **kw):
        from core import mongo_fs_client as mg

        client = mock.MagicMock()
        with mock.patch.object(mg.pymongo, "MongoClient", return_value=client) as ctor:
            with mock.patch.object(mg.gridfs, "GridFS"):
                session = mg.MongoFsSession(host="mongo.internal", port=27017, **kw)
        self.addCleanup(session.close)
        return session, ctor.call_args.kwargs

    def test_client_is_pointed_at_the_tunnel_with_direct_connection(self) -> None:
        socks = self.route("mongo.internal", 27017)
        session, kwargs = self._session(socks, **socks_kwargs(socks))
        self.assertEqual(kwargs["host"], "127.0.0.1")
        self.assertEqual(kwargs["port"], session._tunnel.port)
        # Without directConnection the driver would "discover" the real
        # replica-set member names and dial them directly, bypassing the proxy.
        self.assertTrue(kwargs["directConnection"])

    def test_no_proxy_is_unchanged(self) -> None:
        _session, kwargs = self._session(None)
        self.assertEqual((kwargs["host"], kwargs["port"]), ("mongo.internal", 27017))
        self.assertNotIn("directConnection", kwargs)


# ---------------------------------------------------------------------------
# LDAP
# ---------------------------------------------------------------------------


class LdapProxyTest(_ProxyCase):
    def _session(self, socks, **kw):
        from core import ldap_fs_client as lf

        with mock.patch.object(lf, "Server") as server, \
                mock.patch.object(lf, "Connection"), \
                mock.patch.object(lf, "Tls") as tls:
            session = lf.LdapFsSession(host="ldap.internal", port=636, **kw)
        self.addCleanup(session.close)
        return session, server.call_args, tls.call_args

    def test_plain_ldap_dials_the_tunnel(self) -> None:
        socks = self.route("ldap.internal", 389)
        from core import ldap_fs_client as lf

        with mock.patch.object(lf, "Server") as server, mock.patch.object(lf, "Connection"):
            session = lf.LdapFsSession(host="ldap.internal", port=389, **socks_kwargs(socks))
        self.addCleanup(session.close)
        args, kwargs = server.call_args
        self.assertEqual(args[0], "127.0.0.1")
        self.assertEqual(kwargs["port"], session._tunnel.port)

    def test_ldaps_still_verifies_against_the_real_hostname(self) -> None:
        socks = self.route("ldap.internal", 636)
        _session, server_call, tls_call = self._session(socks, use_tls=True, **socks_kwargs(socks))
        self.assertEqual(tls_call.kwargs["valid_names"], ["ldap.internal"])
        self.assertEqual(tls_call.kwargs["sni"], "ldap.internal")

    def test_real_ldap3_connect_is_routed_by_the_proxy(self) -> None:
        from core.ldap_fs_client import LdapFsSession

        socks = self.route("ldap.internal", 389)
        # The echo fake answers with the client's own bytes; ldap3 may reject
        # that with any exception type. Only the routing is under test.
        with self.assertRaises(Exception):
            LdapFsSession(
                host="ldap.internal", port=389, timeout=2.0, **socks_kwargs(socks)
            )
        self.assertEqual(socks.connects[0], ("ldap.internal", 389))


# ---------------------------------------------------------------------------
# Git
# ---------------------------------------------------------------------------


class GitProxyTest(_ProxyCase):
    def setUp(self) -> None:
        super().setUp()
        from core import git_fs_client as gf

        self.gf = gf
        self.cache = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.cache, True)
        for name, value in (
            ("CACHE_ROOT", __import__("pathlib").Path(self.cache)),
        ):
            patcher = mock.patch.object(gf, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        for method in ("_refresh_branch_tips", "_git_config_value"):
            patcher = mock.patch.object(gf.GitFsSession, method, return_value="")
            patcher.start()
            self.addCleanup(patcher.stop)

    def _clone_kwargs(self, url, socks_kw):
        with mock.patch.object(self.gf.porcelain, "clone", return_value=mock.MagicMock()) as clone:
            session = self.gf.GitFsSession(url=url, **socks_kw)
        self.addCleanup(session.close)
        return session, clone.call_args

    def test_https_remote_uses_a_proxy_pool_manager(self) -> None:
        socks = self.route("git.internal", 443)
        _s, call = self._clone_kwargs("https://git.internal/r.git", socks_kwargs(socks))
        manager = call.kwargs["pool_manager"]
        self.assertEqual(type(manager).__name__, "SOCKSProxyManager")

    def test_http_proxy_type_uses_proxy_manager(self) -> None:
        kw = {"proxy_type": "http", "proxy_host": "proxy.example", "proxy_port": 3128}
        with mock.patch.object(proxy, "_assert_proxy_host_not_private"):
            _s, call = self._clone_kwargs("https://git.internal/r.git", kw)
        self.assertEqual(type(call.kwargs["pool_manager"]).__name__, "ProxyManager")

    def test_ssh_remote_goes_through_a_tunnel_keeping_the_host_key_identity(self) -> None:
        socks = self.route("git.internal", 22)
        session, call = self._clone_kwargs("ssh://git@git.internal/r.git", socks_kwargs(socks))
        port = session._tunnels[0].port
        self.assertEqual(call.args[0], f"ssh://git@127.0.0.1:{port}/r.git")
        # known_hosts must still be checked under the real name.
        self.assertIn("HostKeyAlias=git.internal", call.kwargs["ssh_command"])

    def test_ssh_remote_keeps_a_custom_port(self) -> None:
        socks = self.route("git.internal", 2222)
        session, call = self._clone_kwargs("ssh://git.internal:2222/r.git", socks_kwargs(socks))
        self.assertEqual(session._tunnels[0]._target, ("git.internal", 2222))

    def test_scp_style_remote_goes_through_a_tunnel(self) -> None:
        socks = self.route("git.internal", 22)
        session, call = self._clone_kwargs("git@git.internal:team/r.git", socks_kwargs(socks))
        port = session._tunnels[0].port
        self.assertEqual(call.args[0], f"ssh://git@127.0.0.1:{port}/~/team/r.git")
        session2, call2 = self._clone_kwargs("git@git.internal:/srv/r.git", socks_kwargs(socks))
        self.assertEqual(call2.args[0], f"ssh://git@127.0.0.1:{session2._tunnels[0].port}/srv/r.git")

    def test_option_like_host_is_rejected(self) -> None:
        socks = self.route("x", 22)
        with self.assertRaises((OSError, ValueError)):
            self._clone_kwargs("ssh://-oProxyCommand=evil/r.git", socks_kwargs(socks))

    def test_git_protocol_remote_goes_through_a_tunnel(self) -> None:
        socks = self.route("git.internal", 9418)
        session, call = self._clone_kwargs("git://git.internal/r.git", socks_kwargs(socks))
        url = call.args[0]
        self.assertEqual(url, f"git://127.0.0.1:{session._tunnels[0].port}/r.git")

    def test_display_name_keeps_the_original_remote(self) -> None:
        socks = self.route("git.internal", 9418)
        session, _call = self._clone_kwargs("git://git.internal/r.git", socks_kwargs(socks))
        self.assertIn("git.internal", session.name)
        self.assertNotIn("127.0.0.1", session.name)

    def test_push_uses_the_same_transport(self) -> None:
        socks = self.route("git.internal", 443)
        session, _call = self._clone_kwargs("https://git.internal/r.git", socks_kwargs(socks))
        session._branch_tips = {"main": b"x"}
        with mock.patch.object(self.gf.porcelain, "push") as push:
            session.flush_push()
        self.assertEqual(type(push.call_args.kwargs["pool_manager"]).__name__, "SOCKSProxyManager")

    def test_fetch_of_cached_repo_uses_the_same_transport(self) -> None:
        socks = self.route("git.internal", 443)
        url = "https://git.internal/r.git"
        cache = self.gf._cache_dir_for(url)
        (cache / ".git").mkdir(parents=True)
        client = mock.MagicMock()
        transport = mock.patch.object(
            self.gf, "get_transport_and_path", return_value=(client, "/r.git")
        )
        with mock.patch.object(self.gf, "Repo", return_value=mock.MagicMock()), transport as gtp:
            session = self.gf.GitFsSession(url=url, **socks_kwargs(socks))
        self.addCleanup(session.close)
        self.assertEqual(type(gtp.call_args.kwargs["pool_manager"]).__name__, "SOCKSProxyManager")
        client.fetch.assert_called_once()

    def test_real_dulwich_https_clone_is_routed_by_the_proxy(self) -> None:
        socks = self.route("git.internal", 443)
        with self.assertRaises(Exception):
            self.gf.GitFsSession(url="https://git.internal/r.git", **socks_kwargs(socks))
        self.assertEqual(socks.connects[0], ("git.internal", 443))

    def test_no_proxy_passes_no_transport_kwargs(self) -> None:
        _s, call = self._clone_kwargs("https://git.example/r.git", {})
        self.assertNotIn("pool_manager", call.kwargs)
        self.assertNotIn("ssh_command", call.kwargs)


# ---------------------------------------------------------------------------
# Subversion
# ---------------------------------------------------------------------------

_SVN_INFO = (
    b'<?xml version="1.0"?><info><entry kind="dir" revision="1">'
    b"<repository><root>x</root></repository></entry></info>"
)


class SvnProxyTest(_ProxyCase):
    def _make(self, url, kw):
        from core import svn_fs_client as sv

        calls = []

        def fake_run(argv, **kwargs):
            calls.append((argv, kwargs.get("env") or {}))
            return mock.Mock(returncode=0, stdout=_SVN_INFO, stderr=b"")

        with mock.patch.object(sv, "_svn_available", return_value=True), \
                mock.patch.object(sv.subprocess, "run", side_effect=fake_run):
            session = sv.SvnFsSession(url=url, **kw)
        self.addCleanup(session.close)
        return session, calls

    def test_svn_protocol_goes_through_a_tunnel(self) -> None:
        socks = self.route("svn.internal", 3690)
        session, calls = self._make("svn://svn.internal/repo", socks_kwargs(socks))
        argv, _env = calls[0]
        self.assertIn(f"svn://127.0.0.1:{session._tunnel.port}/repo", argv)
        self.assertEqual(session.name, "SVN: svn://svn.internal/repo")

    def test_http_remote_with_http_proxy_uses_private_config_dir(self) -> None:
        kw = {"proxy_type": "http", "proxy_host": "proxy.example", "proxy_port": 3128,
              "proxy_username": "pu", "proxy_password": "s3cret"}
        with mock.patch.object(proxy, "_assert_proxy_host_not_private"):
            session, calls = self._make("https://svn.internal/repo", kw)
        argv, _env = calls[0]
        self.assertNotIn("s3cret", " ".join(argv))
        config_dir = argv[argv.index("--config-dir") + 1]
        servers = os.path.join(config_dir, "servers")
        self.assertEqual(os.stat(servers).st_mode & 0o777, 0o600)
        text = open(servers).read()
        self.assertIn("http-proxy-host = proxy.example", text)
        self.assertIn("http-proxy-password = s3cret", text)
        session.close()
        self.assertFalse(os.path.exists(config_dir))

    def test_http_remote_with_socks_proxy_goes_through_the_loopback_shim(self) -> None:
        from core import proxy_http

        socks = self.route("svn.internal", 443)
        self.addCleanup(proxy_http.close_all_shims)
        session, calls = self._make(
            "https://svn.internal/repo", socks_kwargs(socks, proxy_password="pw")
        )
        argv, _env = calls[0]
        servers = os.path.join(argv[argv.index("--config-dir") + 1], "servers")
        text = open(servers).read()
        # The svn client only ever sees the shim: no SOCKS host, no secret.
        self.assertIn("http-proxy-host = 127.0.0.1", text)
        self.assertNotIn(str(socks.port), text)
        self.assertNotIn("pw", text)
        self.assertNotIn("http-proxy-password", text)
        port = int(text.split("http-proxy-port = ")[1].split()[0])
        self.assertIn(port, proxy._LIVE_SHIM_PORTS)

    def test_svn_ssh_goes_through_a_tunnel_keeping_the_host_key_identity(self) -> None:
        socks = self.route("svn.internal", 22)
        session, calls = self._make("svn+ssh://svn.internal/repo", socks_kwargs(socks))
        argv, env = calls[0]
        self.assertIn(f"svn+ssh://127.0.0.1:{session._tunnel.port}/repo", argv)
        self.assertIn("HostKeyAlias=svn.internal", env["SVN_SSH"])

    def test_file_remote_is_not_proxied(self) -> None:
        socks = self.route("x", 1)
        session, calls = self._make("file:///srv/repo", socks_kwargs(socks))
        self.assertIsNone(session._tunnel)
        self.assertEqual(socks.connects, [])


# ---------------------------------------------------------------------------
# S3 (botocore speaks HTTP proxies only; SOCKS goes through the shim)
# ---------------------------------------------------------------------------


class S3SocksViaShimTest(_ProxyCase):
    def test_socks_proxy_reaches_the_endpoint_through_the_shim(self) -> None:
        from core import proxy_http
        from core.s3_client import S3Session
        from tests.proxy_http_testkit import OriginHttpServer

        origin = OriginHttpServer()
        socks = self.socks({("s3.internal", 9000): ("127.0.0.1", origin.port)})
        self.addCleanup(proxy_http.close_all_shims)
        session = S3Session(
            bucket="bucket-one",
            endpoint="http://s3.internal:9000",
            access_key="k",
            secret_key="s",
            region="us-east-1",
            **socks_kwargs(socks),
        )
        # The bucket probe crossed the SOCKS proxy to the requested name.
        self.assertIn(("s3.internal", 9000), socks.connects)
        self.assertTrue(any(m == "HEAD" for m, _p, _b in origin.requests))
        session.disconnect()


# ---------------------------------------------------------------------------
# SLP (TCP via CONNECT, UDP via SOCKS5 UDP ASSOCIATE)
# ---------------------------------------------------------------------------


class SlpProxyTest(_ProxyCase):
    def test_tcp_query_is_routed_by_the_proxy(self) -> None:
        from core import slp_lib

        socks = self.route("slp.internal", 427)
        cfg = proxy.proxy_config_from_kwargs(socks_kwargs(socks))
        self.echo.banner = b"REPLY"
        data = slp_lib.query_tcp("slp.internal", b"req", port=427, timeout=1, proxy=cfg)
        self.assertTrue(data.startswith(b"REPLY"))
        self.assertEqual(socks.connects, [("slp.internal", 427)])

    def test_udp_query_is_routed_by_socks5(self) -> None:
        from core import slp_lib

        udp = UdpEchoServer()
        self.addCleanup(udp.close)
        socks = self.socks({("10.9.9.9", 427): ("127.0.0.1", udp.port)})
        cfg = proxy.proxy_config_from_kwargs(socks_kwargs(socks))
        data = slp_lib.query_udp("10.9.9.9", b"req", port=427, timeout=3, proxy=cfg)
        self.assertEqual(data, b"ECHO:req")
        self.assertEqual(socks.udp_targets, [("10.9.9.9", 427)])

    def test_udp_query_does_not_resolve_the_target_locally(self) -> None:
        from core import slp_lib

        udp = UdpEchoServer()
        self.addCleanup(udp.close)
        socks = self.socks({("slp.internal", 427): ("127.0.0.1", udp.port)})
        cfg = proxy.proxy_config_from_kwargs(socks_kwargs(socks))
        real = socket.getaddrinfo
        seen = []

        def guarded(host, *a, **k):
            seen.append(host)
            return real(host, *a, **k)

        with mock.patch.object(socket, "getaddrinfo", side_effect=guarded):
            try:
                slp_lib.query_udp("slp.internal", b"req", port=427, timeout=3, proxy=cfg)
            except OSError:
                pass
        self.assertNotIn("slp.internal", seen)

    def test_udp_over_http_proxy_fails_closed(self) -> None:
        from core import slp_lib

        cfg = proxy.ProxyConfig("http", "127.0.0.1", 3128)
        with self.assertRaises(ConnectionError):
            slp_lib.query_udp("10.9.9.9", b"req", port=427, timeout=1, proxy=cfg)

    def test_session_probe_goes_through_the_proxy(self) -> None:
        from core.slp_client import SlpSession

        socks = self.route("slp.internal", 427)
        with self.assertRaises(OSError):
            SlpSession(host="slp.internal", use_tcp=True, timeout=1, **socks_kwargs(socks))
        self.assertEqual(socks.connects[0], ("slp.internal", 427))


# ---------------------------------------------------------------------------
# TFTP (UDP)
# ---------------------------------------------------------------------------


class _FakeTftpServer:
    """Answers one RRQ with a single DATA block from a fresh port (TID)."""

    def __init__(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.bind(("127.0.0.1", 0))
        self.port = self._sock.getsockname()[1]
        self.requests: list[bytes] = []
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self) -> None:
        while True:
            try:
                data, addr = self._sock.recvfrom(65535)
            except OSError:
                return
            self.requests.append(data)
            if data[:2] == b"\x00\x01":  # RRQ
                transfer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                transfer.settimeout(2)
                transfer.sendto(b"\x00\x03\x00\x01" + b"hello tftp", addr)
                try:
                    transfer.recvfrom(1024)  # ACK
                except OSError:
                    pass
                transfer.close()

    def close(self) -> None:
        self._sock.close()


class TftpProxyTest(_ProxyCase):
    def test_read_goes_through_socks5_udp(self) -> None:
        from core.tftp_client import TftpSession

        server = _FakeTftpServer()
        self.addCleanup(server.close)
        socks = self.socks({("10.9.9.9", 69): ("127.0.0.1", server.port)})
        session = TftpSession(host="10.9.9.9", port=69, timeout=3, retries=1, **socks_kwargs(socks))
        with session.open_read("/boot.img") as fh:
            self.assertEqual(fh.read(), b"hello tftp")
        self.assertEqual(socks.udp_targets[0], ("10.9.9.9", 69))

    def test_hostname_target_is_refused_instead_of_leaking_dns(self) -> None:
        from core.tftp_client import TftpSession

        socks = self.route("tftp.internal", 69)
        with self.assertRaises(proxy.ProxyUnsupportedError):
            TftpSession(host="tftp.internal", **socks_kwargs(socks))

    def test_non_socks5_proxy_is_refused(self) -> None:
        from core.tftp_client import TftpSession

        with self.assertRaises(proxy.ProxyUnsupportedError):
            TftpSession(host="10.9.9.9", proxy_type="http", proxy_host="p", proxy_port=3128)

    def test_upload_also_runs_inside_the_udp_scope(self) -> None:
        import tftpy
        import tftpy.TftpContexts as ctx

        from core.proxy import _SocketModuleShim
        from core.tftp_client import TftpSession

        socks = self.socks({})
        session = TftpSession(host="10.9.9.9", timeout=1, retries=1, **socks_kwargs(socks))
        seen = []

        class FakeClient:
            def __init__(self, *a, **k):
                pass

            def upload(self, *a, **k):
                seen.append(type(ctx.socket))

        with mock.patch.object(tftpy, "TftpClient", FakeClient):
            session._upload_bytes("up.bin", b"data")
        self.assertEqual(seen, [_SocketModuleShim])

    def test_socket_patch_is_restored_after_the_transfer(self) -> None:
        import tftpy.TftpContexts as ctx

        from core.tftp_client import TftpSession

        original = ctx.socket
        server = _FakeTftpServer()
        self.addCleanup(server.close)
        socks = self.socks({("10.9.9.9", 69): ("127.0.0.1", server.port)})
        session = TftpSession(host="10.9.9.9", timeout=3, retries=1, **socks_kwargs(socks))
        session.open_read("/x").close()
        self.assertIs(ctx.socket, original)


# ---------------------------------------------------------------------------
# Backends that cannot be proxied but DO touch the network: fail closed
# ---------------------------------------------------------------------------

_KW = {"proxy_type": "socks5", "proxy_host": "proxy.example", "proxy_port": 1080}


class FailClosedTest(unittest.TestCase):
    def test_rsh_refuses_before_spawning_anything(self) -> None:
        from core import rsh_client

        with mock.patch.object(rsh_client.subprocess, "run") as run:
            with self.assertRaises(proxy.ProxyUnsupportedError):
                rsh_client.RshSession("h", username="u", **_KW)
        run.assert_not_called()

    def test_wmi_refuses(self) -> None:
        from core import wmi_client

        with self.assertRaises(proxy.ProxyUnsupportedError):
            wmi_client.WMISession("h", "u", "p", **_KW)

    def test_nfs_v3_refuses_before_mounting(self) -> None:
        from core import nfs_client

        with mock.patch.object(nfs_client.subprocess, "run") as run:
            with self.assertRaises(proxy.ProxyUnsupportedError):
                nfs_client.NfsSession("h", "/export", version=3, **_KW)
        run.assert_not_called()

    def test_error_is_an_oserror_with_the_remedy(self) -> None:
        from core import nfs_client

        with self.assertRaises(OSError) as ctx:
            nfs_client.NfsSession("h", "/export", version=3, **_KW)
        self.assertIn("proxy", str(ctx.exception).lower())
        self.assertIn("remove", str(ctx.exception).lower())

    def test_no_proxy_configured_does_not_trip_the_guard(self) -> None:
        proxy.refuse_unsupported_proxy("NFS", "none", "", "x")
        proxy.refuse_unsupported_proxy("NFS", "", "", "x")

    def test_local_only_backends_still_just_warn(self) -> None:
        from core.ram_fs import RamFsSession

        RamFsSession(**_KW)  # must not raise


if __name__ == "__main__":
    unittest.main()
