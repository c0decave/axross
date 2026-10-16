"""Telnet decodes UTF-8 across ``recv`` boundaries.

``_TelnetTransport._read_chunk`` decoded every 4 KiB ``recv`` on its own
with ``errors="replace"``: a multi-byte character whose bytes straddled a
boundary became two U+FFFD. ``ls -la`` output with a non-ASCII name then
produced a name that does not exist on the server, and every later
operation on it failed.

Driven end to end against a TCP server on 127.0.0.1.
"""

from __future__ import annotations

import socket
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import telnet_client as TC  # noqa: E402


def _serve(parts: list[bytes], pause: float = 0.0):
    srv = socket.create_server(("127.0.0.1", 0))
    port = srv.getsockname()[1]

    def run():
        conn, _ = srv.accept()
        srv.close()
        with conn:
            for part in parts:
                conn.sendall(part)
                time.sleep(pause)
            time.sleep(0.5)

    threading.Thread(target=run, daemon=True).start()
    return port


def _transport(port: int) -> "TC._TelnetTransport":
    t = TC._TelnetTransport("127.0.0.1", port, timeout=5)
    return t


def test_happy_character_split_at_the_4k_recv_boundary():
    # 4095 ASCII bytes, then "é" (2 bytes): recv(4096) ends between them.
    payload = b"a" * 4095 + "é-done\n".encode()
    t = _transport(_serve([payload]))
    try:
        text = t.read_until("-done", timeout=5)
    finally:
        t.close()
    assert text == "a" * 4095 + "é-done\n"
    assert "�" not in text


def test_sad_character_split_across_two_segments():
    name = "Bücher-€-𝄞.txt"
    raw = name.encode()
    cut = raw.index("𝄞".encode()) + 2  # inside the 4-byte character
    t = _transport(_serve([raw[:cut], raw[cut:] + b"\r\n$ "], pause=0.3))
    try:
        text = t.read_until("$ ", timeout=5)
    finally:
        t.close()
    assert text == name + "\n$ "


def test_edge_invalid_bytes_still_replace_and_ascii_is_unchanged():
    t = _transport(_serve([b"ok \xff\xff bad \xc3", b"(\r\n$ "], pause=0.3))
    try:
        text = t.read_until("$ ", timeout=5)
    finally:
        t.close()
    # 0xFF 0xFF is an escaped IAC (one 0xFF data byte): invalid UTF-8.
    # 0xC3 followed by "(" is an invalid sequence, not a pending one.
    assert text == "ok � bad �(\n$ "


def test_edge_iac_between_the_two_halves_of_a_character():
    iac_nop = bytes([TC.IAC, 241])  # IAC NOP is skipped by _negotiate
    t = _transport(_serve([b"x\xc3", iac_nop + b"\xa4y\n$ "], pause=0.3))
    try:
        text = t.read_until("$ ", timeout=5)
    finally:
        t.close()
    assert text == "xäy\n$ "


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
