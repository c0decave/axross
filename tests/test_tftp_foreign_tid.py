"""TFTP takes data only from the transfer's peer (RFC 1350 4, the TID).

Measured before (review round 6, repro gaps/tftp_wrong_tid.py): tftpy's
``TftpContext.cycle`` logs "Discarding" for a packet from a port other
than the transfer ID - and then processes it. A spoofed block 2 sent from
another port was written into the download (the file ended in b"EVIL"
instead of the server's b"good"): anyone who can send UDP to the client
could put bytes of their own into a firmware image. Now such a packet is
dropped and the client keeps waiting for the real one.
"""

from __future__ import annotations

import socket
import struct
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

pytest.importorskip("tftpy")

from core.tftp_client import TftpSession  # noqa: E402


def _udp(host="127.0.0.1"):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, 0))
    return sock


def _serve(evil_host="127.0.0.1", *, send_good=True):
    """A one-shot server: block 1 from its TID, then a spoofed block 2
    from another socket, then (after a pause) the real final block 2."""
    srv = _udp()
    port = srv.getsockname()[1]

    def run():
        _rrq, client = srv.recvfrom(2048)
        tid = _udp()
        tid.sendto(struct.pack("!HH", 3, 1) + b"A" * 512, client)
        tid.settimeout(5)
        tid.recvfrom(2048)  # ACK 1
        evil = _udp(evil_host)
        evil.sendto(struct.pack("!HH", 3, 2) + b"EVIL", client)
        time.sleep(0.3)
        if send_good:
            tid.sendto(struct.pack("!HH", 3, 2) + b"good", client)
            try:
                tid.recvfrom(2048)  # ACK 2
            except OSError:
                pass
        for s in (tid, evil, srv):
            s.close()

    threading.Thread(target=run, daemon=True).start()
    return port


@pytest.mark.parametrize("evil_host", ["127.0.0.1", "127.0.0.2"],
                         ids=["other-port", "other-host"])
def test_sad_a_block_from_another_sender_is_not_written(evil_host):
    port = _serve(evil_host)
    s = TftpSession(host="127.0.0.1", port=port, timeout=2, retries=1)
    data = s.open_read("f.bin").read()
    assert data == b"A" * 512 + b"good"


def test_happy_a_plain_download_from_the_peer_still_works():
    srv = _udp()
    port = srv.getsockname()[1]

    def run():
        _rrq, client = srv.recvfrom(2048)
        tid = _udp()
        tid.settimeout(5)
        tid.sendto(struct.pack("!HH", 3, 1) + b"hello", client)
        tid.recvfrom(2048)
        tid.close()
        srv.close()

    threading.Thread(target=run, daemon=True).start()
    s = TftpSession(host="127.0.0.1", port=port, timeout=2, retries=1)
    assert s.open_read("f.bin").read() == b"hello"


def test_edge_only_spoofed_packets_end_in_a_timeout_not_a_hang():
    port = _serve(send_good=False)
    s = TftpSession(host="127.0.0.1", port=port, timeout=1, retries=1)
    started = time.monotonic()
    with pytest.raises(OSError):
        s.open_read("f.bin").read()
    assert time.monotonic() - started < 15
