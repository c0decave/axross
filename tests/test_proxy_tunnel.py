"""Proxy primitives: kwargs parsing, loopback tunnel, SOCKS5 UDP."""
from __future__ import annotations

import socket
import threading
import unittest
from unittest import mock

from core import proxy
from tests.proxy_testkit import (
    EchoServer,
    FakeSocks5Server,
    UdpEchoServer,
    allow_loopback_proxy,
)


def _cfg(server: FakeSocks5Server, **kw) -> proxy.ProxyConfig:
    return proxy.ProxyConfig("socks5", "127.0.0.1", server.port, **kw)


class ConfigFromKwargsTest(unittest.TestCase):
    def test_no_proxy_returns_none(self) -> None:
        self.assertIsNone(proxy.proxy_config_from_kwargs({}))
        self.assertIsNone(proxy.proxy_config_from_kwargs({"proxy_type": "none"}))

    def test_socks5_kwargs(self) -> None:
        cfg = proxy.proxy_config_from_kwargs(
            {
                "proxy_type": "SOCKS5",
                "proxy_host": "p.example",
                "proxy_port": 1080,
                "proxy_username": "u",
                "proxy_password": "pw",
            }
        )
        self.assertEqual((cfg.proxy_type, cfg.host, cfg.port, cfg.username, cfg.password),
                         ("socks5", "p.example", 1080, "u", "pw"))

    def test_half_configured_proxy_fails_closed(self) -> None:
        with self.assertRaises(ValueError):
            proxy.proxy_config_from_kwargs({"proxy_type": "socks5", "proxy_host": ""})


class LocalTunnelTest(unittest.TestCase):
    def setUp(self) -> None:
        self.echo = EchoServer()
        self.socks = FakeSocks5Server(routes={("db.internal", 5432): ("127.0.0.1", self.echo.port)})
        self.addCleanup(self.echo.close)
        self.addCleanup(self.socks.close)
        patcher = allow_loopback_proxy()
        patcher.__enter__()
        self.addCleanup(patcher.__exit__, None, None, None)

    def test_bytes_flow_through_the_proxy_to_the_requested_target(self) -> None:
        with proxy.LocalTunnel(_cfg(self.socks), "db.internal", 5432) as tunnel:
            self.assertEqual(tunnel.host, "127.0.0.1")
            with socket.create_connection((tunnel.host, tunnel.port), timeout=5) as c:
                self.assertEqual(c.recv(6), b"HELLO\n")
                c.sendall(b"ping")
                self.assertEqual(c.recv(4), b"ping")
        self.assertEqual(self.socks.connects, [("db.internal", 5432)])

    def test_proxy_credentials_are_used(self) -> None:
        socks = FakeSocks5Server(
            routes={("h", 1): ("127.0.0.1", self.echo.port)}, username="u", password="pw"
        )
        self.addCleanup(socks.close)
        cfg = proxy.ProxyConfig("socks5", "127.0.0.1", socks.port, "u", "pw")
        with proxy.LocalTunnel(cfg, "h", 1) as tunnel:
            with socket.create_connection((tunnel.host, tunnel.port), timeout=5) as c:
                self.assertEqual(c.recv(6), b"HELLO\n")
        self.assertEqual(socks.auth_seen, [("u", "pw")])

    def test_refused_by_proxy_closes_the_client_without_data(self) -> None:
        with proxy.LocalTunnel(_cfg(self.socks), "unrouted.example", 1) as tunnel:
            with socket.create_connection((tunnel.host, tunnel.port), timeout=5) as c:
                c.settimeout(5)
                self.assertEqual(c.recv(16), b"")

    def test_wrong_proxy_password_closes_the_client(self) -> None:
        socks = FakeSocks5Server(
            routes={("h", 1): ("127.0.0.1", self.echo.port)}, username="u", password="right"
        )
        self.addCleanup(socks.close)
        cfg = proxy.ProxyConfig("socks5", "127.0.0.1", socks.port, "u", "wrong")
        with proxy.LocalTunnel(cfg, "h", 1) as tunnel:
            with socket.create_connection((tunnel.host, tunnel.port), timeout=5) as c:
                c.settimeout(5)
                self.assertEqual(c.recv(16), b"")

    def test_many_parallel_connections(self) -> None:
        results: list[bytes] = []

        def worker(tunnel):
            with socket.create_connection((tunnel.host, tunnel.port), timeout=5) as c:
                results.append(c.recv(6))

        with proxy.LocalTunnel(_cfg(self.socks), "db.internal", 5432) as tunnel:
            threads = [threading.Thread(target=worker, args=(tunnel,)) for _ in range(8)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(10)
        self.assertEqual(results, [b"HELLO\n"] * 8)

    def test_close_stops_listening(self) -> None:
        tunnel = proxy.LocalTunnel(_cfg(self.socks), "db.internal", 5432).start()
        port = tunnel.port
        tunnel.close()
        with self.assertRaises(OSError):
            socket.create_connection(("127.0.0.1", port), timeout=1)

    def test_foreign_local_user_is_dropped_before_the_proxy_is_touched(self) -> None:
        with mock.patch.object(proxy, "_peer_is_same_user", return_value=False):
            with proxy.LocalTunnel(_cfg(self.socks), "db.internal", 5432) as tunnel:
                with socket.create_connection((tunnel.host, tunnel.port), timeout=5) as c:
                    c.settimeout(5)
                    self.assertEqual(c.recv(16), b"")
        self.assertEqual(self.socks.connects, [])

    def test_connection_cap(self) -> None:
        with proxy.LocalTunnel(_cfg(self.socks), "db.internal", 5432, max_connections=1) as tunnel:
            first = socket.create_connection((tunnel.host, tunnel.port), timeout=5)
            self.addCleanup(first.close)
            self.assertEqual(first.recv(6), b"HELLO\n")
            second = socket.create_connection((tunnel.host, tunnel.port), timeout=5)
            self.addCleanup(second.close)
            second.settimeout(5)
            self.assertEqual(second.recv(16), b"")

    def test_disabled_proxy_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            proxy.LocalTunnel(proxy.ProxyConfig("none"), "h", 1)

    def test_peer_uid_helper_accepts_own_socket(self) -> None:
        a = socket.socket()
        a.bind(("127.0.0.1", 0))
        a.listen(1)
        c = socket.create_connection(a.getsockname())
        s, peer = a.accept()
        self.addCleanup(lambda: [x.close() for x in (a, c, s)])
        self.assertTrue(proxy._peer_is_same_user(peer))


class UdpProxyTest(unittest.TestCase):
    def setUp(self) -> None:
        self.echo = UdpEchoServer()
        self.socks = FakeSocks5Server(routes={("tftp.internal", 69): ("127.0.0.1", self.echo.port)})
        self.addCleanup(self.echo.close)
        self.addCleanup(self.socks.close)
        patcher = allow_loopback_proxy()
        patcher.__enter__()
        self.addCleanup(patcher.__exit__, None, None, None)

    def test_datagram_roundtrip_through_socks5(self) -> None:
        sock = proxy.create_udp_proxy_socket(_cfg(self.socks), timeout=3)
        self.addCleanup(sock.close)
        sock.sendto(b"abc", ("tftp.internal", 69))
        data, _addr = sock.recvfrom(1024)
        self.assertEqual(data, b"ECHO:abc")
        self.assertEqual(self.socks.udp_targets, [("tftp.internal", 69)])

    def test_http_proxy_cannot_carry_udp(self) -> None:
        with self.assertRaises(ConnectionError):
            proxy.create_udp_proxy_socket(proxy.ProxyConfig("http", "127.0.0.1", 3128), timeout=1)

    def test_socks4_cannot_carry_udp(self) -> None:
        with self.assertRaises(ConnectionError):
            proxy.create_udp_proxy_socket(proxy.ProxyConfig("socks4", "127.0.0.1", 1080), timeout=1)


if __name__ == "__main__":
    unittest.main()
