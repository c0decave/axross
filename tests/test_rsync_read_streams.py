"""rsync open_read streams: the first bytes come while rsync still runs.

open_read ran rsync to the end before it returned: a large download showed
no progress until it was complete and could not be cancelled (the
transfer's Cancel is checked between reads, and there were none). rsync
now writes the file in place (--inplace) and the reader hands out what has
arrived; close() before the end stops rsync and removes the partial file.

A fake rsync binary (tests/rsync_fake_bin.py) plays the receiving side.
"""

from __future__ import annotations

import os
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from rsync_fake_bin import pattern  # noqa: E402

from core import rsync_client as RC  # noqa: E402

FAKE = Path(__file__).resolve().parent / "rsync_fake_bin.py"


@pytest.fixture
def session(tmp_path, monkeypatch):
    wrapper = tmp_path / "rsync"
    wrapper.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{FAKE}" "$@"\n')
    wrapper.chmod(wrapper.stat().st_mode | stat.S_IXUSR)
    spool = tmp_path / "spool"
    spool.mkdir(mode=0o700)
    monkeypatch.setattr("core.read_spool.named_spool_dir", lambda: str(spool))
    s = RC.RsyncSession.__new__(RC.RsyncSession)
    s._host, s._port, s._module = "srv", 873, "m"
    s._username, s._password = "", ""
    s._ssh_mode, s._ssh_key, s._preserve_metadata = False, "", False
    s._rsync_bin = str(wrapper)
    s._connected = True
    s.spool = spool
    return s


def _leftovers(spool: Path) -> list[str]:
    return [p.name for p in spool.iterdir()]


def test_happy_first_bytes_arrive_before_rsync_ends(session):
    size = 4 * 1024 * 1024
    fh = session.open_read("/big-%d-20.bin" % size)
    try:
        first = fh.read(65536)
        assert first == pattern(size)[:65536]
        assert fh._proc.poll() is None  # rsync still writing: this is a stream
        rest = fh.read()
    finally:
        fh.close()
    assert first + rest == pattern(size)
    assert _leftovers(session.spool) == []


def test_happy_reads_in_pieces_and_seeks(session):
    size = 300_000
    with session.open_read("/big-%d-3.bin" % size) as fh:
        fh.seek(299_990)
        assert fh.read(100) == pattern(size)[299_990:]
        assert fh.read(10) == b""


def test_sad_close_before_the_end_stops_rsync(session):
    fh = session.open_read("/big-%d-50.bin" % (5 * 1024 * 1024))
    fh.read(1000)
    proc = fh._proc
    t0 = time.monotonic()
    fh.close()
    assert proc.poll() is not None
    assert time.monotonic() - t0 < 3
    assert _leftovers(session.spool) == []


def test_sad_a_missing_file_fails_at_open(session):
    with pytest.raises(FileNotFoundError):
        session.open_read("/gone.txt")
    assert _leftovers(session.spool) == []


def test_sad_a_folder_is_not_a_regular_file(session):
    with pytest.raises(OSError, match="not a regular file"):
        session.open_read("/folder")
    assert _leftovers(session.spool) == []


def test_sad_rsync_failing_midway_is_an_error_not_a_short_file(session):
    # At open (rsync already ended) or at the read that reaches the end.
    with pytest.raises(OSError, match="code 12"):
        fh = session.open_read("/broken-200000.bin")
        try:
            while fh.read(4096):
                pass
        finally:
            fh.close()
    assert _leftovers(session.spool) == []


def test_edge_garbage_collected_reader_stops_rsync(session):
    fh = session.open_read("/big-%d-50.bin" % (5 * 1024 * 1024))
    proc = fh._proc
    del fh
    import gc

    gc.collect()
    deadline = time.monotonic() + 5
    while proc.poll() is None and time.monotonic() < deadline:
        time.sleep(0.05)
    assert proc.poll() is not None
    if proc.poll() is None:  # pragma: no cover - cleanup on failure
        proc.kill()


def test_edge_the_fake_refuses_without_the_flags(tmp_path):
    out = subprocess.run([sys.executable, str(FAKE), "src", str(tmp_path) + os.sep],
                         capture_output=True, text=True)
    assert out.returncode == 1
