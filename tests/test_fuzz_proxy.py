"""Fuzz: proxy handshakes (SOCKS4, SOCKS5, HTTP CONNECT incl. NTLM) against a
hostile proxy.

``create_proxy_socket`` documents ConnectionError; every backend that dials
through a proxy handles OSError. A proxy answering garbage, lying about
lengths, stalling or hanging up must end in an OSError - never ValueError,
TypeError, struct.error or a hang.
"""

from __future__ import annotations

import base64
import socket
import sys
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fuzz_testkit import ScriptedServer, check_contract, iterations, mutants, stall  # noqa: E402

from core import proxy as P  # noqa: E402
from core import proxy_http as PH  # noqa: E402

STALL = object()


@pytest.fixture(autouse=True)
def _loopback_proxy_allowed():
    with mock.patch("core.proxy._assert_proxy_host_not_private"):
        yield


class ScriptedProxy:
    """Answers each client write with the next scripted chunk."""

    def __init__(self, script: list) -> None:
        self.script = script
        self.server = ScriptedServer(self._handle)

    def _handle(self, conn: socket.socket) -> None:
        conn.settimeout(2)
        for chunk in self.script:
            try:
                if not conn.recv(65536):
                    return
            except OSError:
                return
            if chunk is STALL:
                stall(conn, 10)
                return
            if chunk is None:
                return
            conn.sendall(chunk)
        stall(conn, 3)

    def close(self) -> None:
        self.server.close()


def _dial(kind: str, script: list, username: str = "", password: str = ""):
    srv = ScriptedProxy(script)
    cfg = P.ProxyConfig(kind, "127.0.0.1", srv.server.port, username, password)

    def call():
        sock = P.create_proxy_socket(cfg, "target.example", 443, timeout=0.4)
        sock.close()
        return "connected"

    try:
        return check_contract(call, (OSError,), timeout=15.0, context=f"{kind} {script!r}"[:400])
    finally:
        srv.close()


# --------------------------------------------------------------------- SOCKS5
SOCKS5_OK = [b"\x05\x00", b"\x05\x00\x00\x01\x7f\x00\x00\x01\x01\xbb"]


def test_happy_socks5_handshake():
    assert _dial("socks5", SOCKS5_OK) == "connected"


@pytest.mark.parametrize(
    "script",
    [
        [b"\x04\x00"],  # wrong version in the method reply
        [b"\x05\xff"],  # no acceptable method
        [b"\x05"],  # truncated
        [b""],
        [b"\x05\x00", b"\x05\x00\x00\x09" + b"\x00" * 6],  # unknown atyp
        [b"\x05\x00", b"\x05\x00\x00\x03\xff" + b"a" * 10],  # domain length lies
        [b"\x05\x00", b"\x05\x00\x00\x03\x00\x00\x50"],  # empty domain
        [b"\x05\x00", b"\x05\x00\x00\x04" + b"\x00" * 5],  # truncated IPv6
        [b"\x05\x00", b"\x05\x00\x00\x03\x05\xff\xfe\xfd\xfc\xfb\x00\x50"],  # non-UTF-8 name
        [b"\x05\x00", b"\x04\x00\x00\x01" + b"\x00" * 6],  # wrong version
        [b"\x05\x00", b"\x05\x7f\x00\x01" + b"\x00" * 6],  # unknown status
        [b"\x05\x00", STALL],
        [STALL],
        [b"\x05\x02", b"\x02\x00"],  # asks for auth nobody configured
    ],
)
def test_sad_socks5_hostile_replies(script):
    _dial("socks5", script)


def test_sad_socks5_auth_reply_garbage():
    for reply in (b"\x01", b"\x01\x01", b"\x09\x00", b""):
        _dial("socks5", [b"\x05\x02", reply], username="u", password="p")


def test_fuzz_socks5_reply_mutants():
    corpus = [SOCKS5_OK[0] + b"|" + SOCKS5_OK[1], b"\x05\x00|\x05\x00\x00\x03\x09localhost\x01\xbb"]
    for payload in mutants(corpus, seed=0x5005, per_entry=iterations(8)):
        _dial("socks5", [chunk for chunk in payload.split(b"|", 1)])


# --------------------------------------------------------------------- SOCKS4
def test_happy_socks4_handshake():
    with mock.patch("core.proxy._resolve_target_host", return_value="127.0.0.1"):
        assert _dial("socks4", [b"\x00\x5a\x01\xbb\x7f\x00\x00\x01"]) == "connected"


@pytest.mark.parametrize(
    "reply",
    [b"\x00\x5a", b"\x04\x5a\x00\x00\x00\x00\x00\x00", b"\x00\x5b" + b"\x00" * 6, b"", b"\xff" * 8],
)
def test_sad_socks4_hostile_replies(reply):
    _dial("socks4", [reply])


def test_fuzz_socks4_reply_mutants():
    for payload in mutants([b"\x00\x5a\x01\xbb\x7f\x00\x00\x01"], 0x5004, iterations(20)):
        _dial("socks4", [payload])


# ---------------------------------------------------------------- HTTP CONNECT
HTTP_OK = b"HTTP/1.1 200 Connection established\r\nProxy-Agent: fuzz\r\n\r\n"


def test_happy_http_connect():
    assert _dial("http", [HTTP_OK]) == "connected"


@pytest.mark.parametrize(
    "reply",
    [
        b"HTTP/1.1 \xb2\xb2\xb2 Weird\r\n\r\n",  # latin-1 superscript digits as status
        b"HTTP/1.1 200\r\n",  # never ends the head
        b"HTTP/1.1 407 Auth\r\nProxy-Authenticate: Basic\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHELLO",  # 200 with a body
        b"\xff\xfe\r\n\r\n",
        b"\r\n\r\n",
        b"HTTP/1.1 " + b"9" * 5000 + b"\r\n\r\n",
        b"HTTP/1.1 200 " + b"A" * 70000,  # oversized head, never terminated
    ],
)
def test_sad_http_connect_hostile_replies(reply):
    _dial("http", [reply])


def test_sad_http_connect_stall():
    _dial("http", [STALL])


def test_fuzz_http_connect_reply_mutants():
    for payload in mutants([HTTP_OK], 0x4770, iterations(25)):
        _dial("http", [payload])


# ------------------------------------------------- NTLM via proxy_http client
def _ntlm_challenge() -> bytes:
    """A syntactically valid NTLM CHALLENGE (type 2) message."""
    import struct

    target = "DOMAIN".encode("utf-16-le")
    payload_offset = 48
    return (
        b"NTLMSSP\x00"
        + struct.pack("<I", 2)
        + struct.pack("<HHI", len(target), len(target), payload_offset)
        + struct.pack("<I", 0xA2898205)
        + b"\x01\x23\x45\x67\x89\xab\xcd\xef"
        + b"\x00" * 8
        + struct.pack("<HHI", 0, 0, payload_offset + len(target))
        + target
    )


def _ntlm_407(token: bytes, extra: bytes = b"Content-Length: 0\r\n") -> bytes:
    return (
        b"HTTP/1.1 407 Proxy Authentication Required\r\n"
        b"Proxy-Authenticate: NTLM " + base64.b64encode(token) + b"\r\n" + extra + b"\r\n"
    )


@pytest.mark.parametrize(
    "first",
    [
        _ntlm_407(b"garbage"),
        _ntlm_407(b"NTLMSSP\x00\x02\x00\x00\x00"),  # truncated challenge
        _ntlm_407(_ntlm_challenge()[:-4]),
        b"HTTP/1.1 407 x\r\nProxy-Authenticate: NTLM !!!notbase64\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 407 x\r\nProxy-Authenticate: NTLM\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 407 x\r\nTransfer-Encoding: chunked\r\nProxy-Authenticate: NTLM\r\n\r\nzz\r\n",
        b"HTTP/1.1 407 x\r\nTransfer-Encoding: chunked\r\n\r\n-5\r\nabc\r\n0\r\n\r\n",
        b"HTTP/1.1 407 x\r\nTransfer-Encoding: chunked\r\n\r\nffffffffffffffffff\r\n",
        b"HTTP/1.1 407 x\r\nContent-Length: \xb2\r\n\r\n",
        b"HTTP/1.1 407 x\r\nContent-Length: 99999999999\r\nConnection: keep-alive\r\n\r\n",
        b"HTTP/1.1 407 x\r\nContent-Length: 10\r\n\r\nabc",  # body shorter than announced
        b"HTTP/1.1 \xb2\xb2\xb2 x\r\n\r\n",
        b"HTTP/1.1 407 x\r\nTransfer-Encoding: chunked\r\n\r\n" + b"1" * 5000 + b"\r\n",
    ],
)
def test_sad_ntlm_handshake_hostile_replies(first):
    _dial("http+ntlm", [first, HTTP_OK], username="u", password="p")


def test_fuzz_ntlm_challenge_mutants():
    corpus = [_ntlm_challenge()]
    for token in mutants(corpus, 0x7171, iterations(20)):
        _dial("http+ntlm", [_ntlm_407(token), HTTP_OK], username="u", password="p")


def test_fuzz_ntlm_407_head_mutants():
    corpus = [
        _ntlm_407(_ntlm_challenge(), b"Transfer-Encoding: chunked\r\n") + b"3\r\nabc\r\n0\r\n\r\n"
    ]
    for payload in mutants(corpus, 0x7172, iterations(25)):
        _dial("http+ntlm", [payload, HTTP_OK], username="u", password="p")


# -------------------------------------------------------- response helpers direct
def test_fuzz_parse_response_direct():
    corpus = [
        b"HTTP/1.1 407 Auth\r\nProxy-Authenticate: NTLM abc=\r\nConnection: close\r\n\r\n",
        HTTP_OK,
    ]
    for payload in mutants(corpus, 0x7173, iterations(500)):
        result = check_contract(
            lambda: PH._parse_response(payload), (OSError,), context=repr(payload)
        )
        if not isinstance(result, OSError):
            assert isinstance(result.status, int)
            PH._challenges(result, "ntlm")
            PH._offered(result)
