"""The Azure Files writer hands upload_file the spool, not its bytes.

The spool rolls to disk at 8 MiB, but close() read the WHOLE file back
into one bytes object before ``upload_file`` - RAM equal to the file
size. It now passes the spool as a stream with its length, as the Blob
writer passes its spool to ``upload_blob``.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.azure_client import _ShareSpooledWriter  # noqa: E402


class _FileClient:
    def __init__(self, fail: Exception | None = None):
        self.fail = fail
        self.calls: list[tuple[type, int | None, bytes]] = []

    def upload_file(self, data, length=None, **kw):
        if self.fail is not None:
            raise self.fail
        body = data.read() if hasattr(data, "read") else data
        self.calls.append((type(data), length, body))


def test_happy_a_large_file_goes_up_as_a_stream_with_its_length():
    client = _FileClient()
    w = _ShareSpooledWriter(client)
    chunk = bytes(range(256)) * 4096  # 1 MiB
    for _ in range(12):
        w.write(chunk)
    assert w._buf._rolled  # past the 8 MiB the spool keeps in RAM
    w.close()
    [(kind, length, body)] = client.calls
    assert kind is not bytes
    assert length == 12 * len(chunk)
    assert body == chunk * 12


def test_sad_a_failed_upload_raises_and_releases_the_spool():
    client = _FileClient(fail=OSError("503 ServerBusy"))
    w = _ShareSpooledWriter(client)
    w.write(b"data")
    with pytest.raises(OSError, match="ServerBusy"):
        w.close()
    assert w._buf.closed


def test_edge_an_empty_and_a_small_file_stream_with_exact_lengths():
    for payload in (b"", b"small"):
        client = _FileClient()
        w = _ShareSpooledWriter(client)
        w.write(payload)
        w.close()
        [(kind, length, body)] = client.calls
        assert kind is not bytes
        assert (length, body) == (len(payload), payload)
