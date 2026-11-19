"""Exchange: the first request goes through the profile's proxy too
(review round 2).

Only the pooled sessions and create_session() were moved onto the proxy.
exchangelib's first session asks for the server's auth type: a POST to
/EWS/Exchange.asmx through ``protocol.raw_session()``, a fresh requests
session with the environment's proxies - straight to the server, from
this machine's own address. Every session raw_session() makes is
locked to the profile proxy now.
"""

from __future__ import annotations

import socket
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

exchangelib = pytest.importorskip("exchangelib")

from core.exchange_client import ExchangeSession  # noqa: E402


class _Listener:
    """Accepts connections, counts them, answers 502 to anything."""

    def __init__(self) -> None:
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.hits = 0
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self) -> None:
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            self.hits += 1
            try:
                conn.settimeout(2)
                conn.recv(65536)
                conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n"
                             b"Connection: close\r\n\r\n")
            except OSError:
                pass
            conn.close()

    def close(self) -> None:
        self.sock.close()


def test_sad_the_auth_type_probe_goes_through_the_proxy() -> None:
    server, proxy = _Listener(), _Listener()
    try:
        from exchangelib import DELEGATE, Account, Configuration, Credentials

        creds = Credentials("u@example.org", "pw")
        config = Configuration(service_endpoint=f"http://127.0.0.1:{server.port}/EWS/Exchange.asmx",
                               credentials=creds)
        account = Account("u@example.org", config=config, autodiscover=False,
                          access_type=DELEGATE)
        proxies = {"http": f"http://127.0.0.1:{proxy.port}",
                   "https": f"http://127.0.0.1:{proxy.port}"}
        ExchangeSession._apply_protocol_proxy(account.protocol, proxies)
        try:
            account.protocol.get_session()
        except Exception:  # noqa: BLE001 - the 502 ends it; where it went counts
            pass
        assert server.hits == 0, "a request went to the server directly"
        assert proxy.hits >= 1
    finally:
        server.close()
        proxy.close()
