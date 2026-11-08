"""Closing the sift sandbox's socket relay ends its accept thread.

Before: ``SocketRelay.close`` closed the listening Unix socket without a
``shutdown(SHUT_RDWR)``. On Linux that does not wake the thread blocked
in ``accept()`` on it, so every sift worker restart left one more
``sift-relay`` thread behind, for the life of the process.

Now close() shuts the listener down first (as core.proxy's LocalTunnel
does), and the blocked accept() returns.
"""

from __future__ import annotations

import socket
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import analysis_sandbox as SB  # noqa: E402

pytestmark = pytest.mark.skipif(not hasattr(socket, "AF_UNIX"), reason="no Unix sockets")


def _relay_threads() -> list[threading.Thread]:
    return [t for t in threading.enumerate() if t.name == "sift-relay"]


def _wait_for(cond, timeout: float = 5.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if cond():
            return True
        time.sleep(0.01)
    return cond()


def _accepting(relay: SB.SocketRelay) -> bool:
    """The accept thread is blocked in accept() (a connection gets through)."""
    probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        probe.connect(relay.path)
        return True
    finally:
        probe.close()


def test_happy_close_ends_the_accept_thread():
    before = set(_relay_threads())
    relay = SB.SocketRelay({("example.org", 443)})
    mine = [t for t in _relay_threads() if t not in before]
    assert len(mine) == 1
    time.sleep(0.05)                        # blocked in accept() by now
    relay.close()
    assert _wait_for(lambda: not mine[0].is_alive()), "the accept thread is still blocked"


def test_sad_restarts_do_not_pile_up_relay_threads():
    before = set(_relay_threads())
    for _ in range(10):
        relay = SB.SocketRelay({("example.org", 443)})
        time.sleep(0.01)
        relay.close()
    assert _wait_for(lambda: not (set(_relay_threads()) - before)), \
        f"{len(set(_relay_threads()) - before)} sift-relay threads left behind"


def test_edge_closed_with_a_connection_open_twice_the_thread_ends_and_the_folder_is_gone():
    before = set(_relay_threads())
    relay = SB.SocketRelay({("example.org", 443)})
    mine = [t for t in _relay_threads() if t not in before]
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.connect(relay.path)              # served, saying nothing yet
    try:
        assert _wait_for(lambda: any(t.name == "sift-relay-conn" for t in threading.enumerate()))
        time.sleep(0.05)                    # the accept thread is back in accept()
        relay.close()
        relay.close()
        assert _wait_for(lambda: not mine[0].is_alive()), "the accept thread is still blocked"
        assert not Path(relay.folder).exists()
        with pytest.raises(OSError):
            _accepting(relay)
    finally:
        client.close()
