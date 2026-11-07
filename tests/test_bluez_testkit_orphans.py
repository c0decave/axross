"""A test process that dies leaves no dbus-daemon or fake BlueZ behind
(tests/bluez_testkit.py).

A pytest worker killed mid-test (the kernel's OOM killer picked the
largest processes of a loaded machine - the workers) runs no teardown:
each FakeBluezBus it held left its dbus-daemon and tests/fake_bluez.py
running, 30 pairs hours after the run. The children now die with the
process that started them.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

CHILD = """
import os, sys
sys.path.insert(0, {tests!r})
from PyQt6.QtCore import QCoreApplication
app = QCoreApplication([])
from bluez_testkit import FakeBluezBus
bus = FakeBluezBus()
print(bus.daemon.pid, bus.fake.pid, flush=True)
os._exit(0)  # no close(): as a worker killed mid-test
"""


def _alive(pid: int) -> bool:
    try:
        with open(f"/proc/{pid}/stat") as stat:
            return stat.read().split(")")[-1].split()[0] != "Z"
    except OSError:
        return False


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="PR_SET_PDEATHSIG is Linux")
def test_sad_a_test_process_that_dies_takes_its_bus_and_fake_bluez_along():
    if shutil.which("dbus-daemon") is None:
        pytest.skip("dbus-daemon is not installed")
    pytest.importorskip("jeepney", reason="jeepney is missing")
    pytest.importorskip("PyQt6.QtDBus", reason="PyQt6.QtDBus is missing")
    out = subprocess.run([sys.executable, "-c", CHILD.format(tests=str(ROOT / "tests"))],
                         capture_output=True, text=True, timeout=60,
                         env=dict(os.environ, QT_QPA_PLATFORM="offscreen"))
    pids = [int(p) for p in out.stdout.split()]
    assert len(pids) == 2, out.stderr[-2000:]
    try:
        end = time.monotonic() + 10
        while time.monotonic() < end and any(_alive(p) for p in pids):
            time.sleep(0.05)
        assert not any(_alive(p) for p in pids), "dbus-daemon or fake BlueZ outlived the test"
    finally:
        for pid in pids:
            if _alive(pid):
                os.kill(pid, 9)
