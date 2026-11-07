"""RamFS reads the free memory once for many writes, not once per write.

Measured on 2026-11-02 (feedback: optimise everything, measured): copying
19 000 small files into RamFS read /proc/meminfo 19 000 times - the
system-pressure guard probed before every write, most of the copy's time.
A reading now stands for the checks after it, for at most PROBE_SECONDS and
only while it leaves PROBE_MARGIN_BYTES above the reserve after every byte
granted since; near the reserve every check reads afresh, as before. The
guard refuses as before.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import ram_fs as R  # noqa: E402
from core.ram_fs import RamFsCapacityError, RamFsSession  # noqa: E402

MIB = 1024 * 1024
RESERVE = 8 * MIB


class _Probe:
    """Stands for the system's free memory; counts the readings."""

    def __init__(self, available: int) -> None:
        self.available = available
        self.reads = 0

    def __call__(self) -> int:
        self.reads += 1
        return self.available


@pytest.fixture
def probe(monkeypatch):
    p = _Probe(4096 * MIB)
    monkeypatch.setattr(R, "_available_memory_bytes", p)
    monkeypatch.setattr(R, "_probe", dict(R._probe))  # no reading of another test
    return p


@pytest.fixture
def clock(monkeypatch):
    now = [1000.0]
    monkeypatch.setattr(R.time, "monotonic", lambda: now[0])
    return now


def _session() -> RamFsSession:
    return RamFsSession(label="probe", max_bytes=1024 * MIB, system_reserve_bytes=RESERVE)


def _write(fs, path: str, size: int) -> None:
    with fs.open_write(path) as fh:
        fh.write(b"x" * size)


def test_happy_many_small_writes_read_the_free_memory_once(probe, clock):
    fs = _session()
    for i in range(500):
        _write(fs, f"/f{i}", 100)
    assert probe.reads == 1
    assert len(fs.list_dir("/")) == 500


def test_happy_a_reading_is_made_again_after_its_time(probe, clock):
    fs = _session()
    _write(fs, "/a", 100)
    clock[0] += R.PROBE_SECONDS - 0.01
    _write(fs, "/b", 100)
    assert probe.reads == 1
    clock[0] += 0.02
    _write(fs, "/c", 100)
    assert probe.reads == 2


def test_sad_near_the_reserve_every_write_reads_afresh_and_is_refused_as_before(probe, clock):
    probe.available = RESERVE + R.PROBE_MARGIN_BYTES // 2
    fs = _session()
    for i in range(5):
        _write(fs, f"/f{i}", 100)
    assert probe.reads == 5
    probe.available = RESERVE + 50  # the next write would leave less than the reserve
    with pytest.raises(RamFsCapacityError):
        _write(fs, "/too-much", 100)


def test_sad_bytes_granted_since_the_reading_count_against_it(probe, clock):
    """What this process wrote since the reading is not free any more: once
    the reading less those bytes comes near the reserve, it is read again."""
    probe.available = RESERVE + R.PROBE_MARGIN_BYTES + 3 * MIB
    fs = _session()
    _write(fs, "/one", MIB)
    _write(fs, "/two", MIB)
    assert probe.reads == 1
    _write(fs, "/three", 2 * MIB)  # would leave less than the margin: read again
    assert probe.reads == 2


def test_edge_a_probe_patched_in_is_asked_at_once(clock):
    """Tests (and callers) replace _available_memory_bytes: the next check
    asks the new one, whatever an earlier reading said."""
    fs = _session()
    with mock.patch.object(R, "_available_memory_bytes", return_value=4096 * MIB):
        _write(fs, "/plenty", 100)
    with mock.patch.object(R, "_available_memory_bytes", return_value=RESERVE):
        with pytest.raises(RamFsCapacityError):
            _write(fs, "/none-left", 100)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="reads /proc/meminfo")
def test_edge_the_real_probe_is_read_rarely_on_a_long_copy(monkeypatch):
    reads = [0]
    real = R._read_proc_meminfo_available

    def counted():
        reads[0] += 1
        return real()

    monkeypatch.setattr(R, "_read_proc_meminfo_available", counted)
    monkeypatch.setattr(R, "_probe", dict(R._probe))
    fs = RamFsSession(label="real", max_bytes=1024 * MIB, system_reserve_bytes=0)
    for i in range(2000):
        _write(fs, f"/f{i}", 10)
    assert 1 <= reads[0] < 100, reads[0]
    assert len(fs.list_dir("/")) == 2000
