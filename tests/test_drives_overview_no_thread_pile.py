"""Drives Overview starts no second probe for a mount that still hangs
(review round 2).

Before: every refresh started one new probe thread per drive. A dead NFS
mount's statvfs never returns, so each refresh (the button, a mount
event) left one more thread hanging on it - they piled up for as long as
axross ran. Now a mount whose probe from an earlier refresh is still
running is skipped and shown as "not answering"; once that probe returns,
the mount is probed again.
"""

from __future__ import annotations

import os
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from tests.test_drives_overview import DO  # noqa: E402


def _probes() -> int:
    return sum(t.name == "axross-drive-probe" and t.is_alive() for t in threading.enumerate())


def test_sad_refreshes_do_not_pile_up_threads_on_a_dead_mount():
    hang = threading.Event()
    calls = []

    def usage(path):
        calls.append(path)
        if path == "/mnt/dead":
            hang.wait(30)
        return (100, 10, 90)

    drives = [DO.Drive("/", "/dev/sda1", "ext4", "local"),
              DO.Drive("/mnt/dead", "srv:/x", "nfs4", "network")]
    before = _probes()
    try:
        first = DO.measure(drives, usage=usage, timeout=0.2)
        for _ in range(4):
            again = DO.measure(drives, usage=usage, timeout=0.2)
        assert _probes() - before == 1, "one hanging probe per refresh"
        assert calls.count("/mnt/dead") == 1
        assert calls.count("/") == 5  # the live drive is measured every time
        assert "timed out" in first[1].error
        assert again[1].total is None and again[1].error == DO.tr("not answering")
        assert again[0].total == 100
    finally:
        hang.set()
    for thread in threading.enumerate():
        if thread.name == "axross-drive-probe":
            thread.join(5)
    # Its probe returned: the mount is asked again (and answers now).
    assert DO.measure(drives, usage=usage, timeout=2)[1].total == 100
    assert calls.count("/mnt/dead") == 2
