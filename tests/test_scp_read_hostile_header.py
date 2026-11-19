"""SCP read (scp -f): a size the header cannot mean (review round 2).

``C0644 -5 name``: int() took the minus, ``while left:`` never reached
zero, and the read took everything the server sent until the stream
ended - a hostile server could stream without end into the spool.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.scp_client import SCPSession  # noqa: E402


class _Chan:
    def __init__(self, data: bytes):
        self.data = data
        self.taken = 0

    def recv(self, n):
        if n < 0:
            n = 65536
        chunk, self.data = self.data[:n], self.data[n:]
        self.taken += len(chunk)
        return chunk

    def sendall(self, _b):
        pass

    def close(self):
        pass


@pytest.mark.parametrize("size", [b"-5", b"+5", b"5x", b"\xd9\xa5"])
def test_sad_a_size_that_is_no_size_is_refused(size) -> None:
    s = object.__new__(SCPSession)
    chan = _Chan(b"C0644 " + size + b" f\n" + b"x" * 200_000)
    s._require_active = lambda: None
    s._scp_channel = lambda cmd: chan
    with pytest.raises(OSError, match="bad SCP header"):
        s._scp_read("/f")
    assert chan.taken < 100
