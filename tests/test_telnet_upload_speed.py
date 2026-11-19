"""Telnet uploads are not slowed down by a fixed pause per 4 KiB.

The transport slept 10 ms after every 4 KiB it sent, "to pace large
sends": an upload ran at about 0.3 MB/s whatever the line could carry
(2 MiB: 7.6 s, of it 6 s asleep). Its socket is non-blocking, so the
pause also was the only thing that kept ``sendall`` from failing with
"Send failed" once the kernel's send buffer was full. Now the transport
waits until the socket can take more (and reads what the server says
meanwhile, so an echoing terminal cannot block both ends).

Against a real shell on a pty (tests/telnet_pty_server.py).
"""

from __future__ import annotations

import os
import socket
import sys
import threading
import time

import pytest

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="needs a pty")

from tests.telnet_pty_server import PtyTelnetServer  # noqa: E402

import core.telnet_client as tc  # noqa: E402


def test_an_upload_is_not_paced_by_sleeps(tmp_path, monkeypatch):
    with PtyTelnetServer(cwd=str(tmp_path)) as srv:
        s = tc.TelnetSession("127.0.0.1", srv.port, "u", "pw")
        try:
            pauses: list[float] = []
            real_sleep = time.sleep
            monkeypatch.setattr(tc.time, "sleep", lambda t: (pauses.append(t), real_sleep(t)))
            data = os.urandom(2 * 1024 * 1024)
            with s.open_write(str(tmp_path / "up.bin")) as fh:
                fh.write(data)
            monkeypatch.undo()
            assert (tmp_path / "up.bin").read_bytes() == data
            assert sum(pauses) < 0.5, f"{len(pauses)} pauses, {sum(pauses):.1f} s asleep"
        finally:
            s.close()


def test_a_full_send_buffer_waits_instead_of_failing(monkeypatch):
    """A peer that reads late: the send waits for room, and what the peer
    sends meanwhile is kept for the next read."""
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    got = bytearray()

    def peer():
        conn, _ = listener.accept()
        conn.sendall(b"hello while you send\r\n")
        time.sleep(1.5)  # the client's send buffer fills meanwhile
        while len(got) < 8 * 1024 * 1024:
            chunk = conn.recv(1 << 20)
            if not chunk:
                break
            got.extend(chunk)
        conn.close()

    t = threading.Thread(target=peer, daemon=True)
    t.start()
    transport = tc._TelnetTransport("127.0.0.1", listener.getsockname()[1])
    transport._sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 64 * 1024)
    payload = b"x" * (8 * 1024 * 1024)
    transport.send_raw(payload)
    t.join(30)
    assert bytes(got) == payload
    assert "hello while you send" in transport.read_some(timeout=1.0)
    transport.close()
    listener.close()
