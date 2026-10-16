"""A READ answer longer than requested is an error, not shifted data.

ReadAheadRaw read its windows through paramiko's readv(), whose prefetch
bookkeeping keeps the excess of an over-long READ answer as the data of
the following offset (paramiko sftp_file._read_prefetch: ``if size <
len(prefetch): self._prefetch_data[self._realpos + size] = prefetch[size:]``).
A server answering each READ with a few bytes more than requested so
produced a complete, wrong download - padding bytes inside the file and
after its end (found by tests/test_fuzz_sftp.py). Windows are now read
with READ requests of our own whose every answer is checked.

Driven against a real paramiko SFTP server whose READ answers are scripted.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
from paramiko.sftp import SFTP_FAILURE

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sftp_hostile_kit import hostile_session  # noqa: E402

CONTENT = os.urandom(1024 * 1024 + 5)


def _read(hook=None) -> bytes:
    with hostile_session() as (script, s):
        script.data = CONTENT
        script.read_hook = hook
        return s.open_read("/a.txt").read()


def test_happy_exact_answers_read_back_identical():
    assert _read() == CONTENT


@pytest.mark.parametrize("extra", [b"\x00", b"\x00" * 7, b"x" * 4096], ids=["1", "7", "4096"])
def test_sad_answer_longer_than_requested_is_an_oserror(extra):
    def hook(off, n):
        return CONTENT[off : off + n] + extra if off < len(CONTENT) else b""

    with pytest.raises(OSError, match="more than requested"):
        _read(hook)


def test_sad_failure_status_mid_window_is_an_oserror():
    def hook(off, n):
        return SFTP_FAILURE if off >= 512 * 1024 else CONTENT[off : off + n]

    with pytest.raises(OSError):
        _read(hook)


def test_edge_short_answers_end_the_file_where_the_server_says():
    """A server whose file is shorter than its stat said: the bytes that
    exist arrive, nothing is invented, the read ends."""

    def hook(off, n):
        end = 300_000
        return CONTENT[off : min(off + n, end)] if off < end else b""

    assert _read(hook) == CONTENT[:300_000]
