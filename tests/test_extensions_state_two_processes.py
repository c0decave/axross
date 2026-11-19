"""extensions.json keeps the change of another axross process.

Review 2026-11-20 (extensions round 2): switching an extension on or off,
pausing it and the startup guard's suspension read extensions.json,
changed one list and wrote the whole file back with no lock at all. Two
axross processes (a second window started, one start suspending an
extension while the other switches one on) each wrote what they had read
before: the first one's change was gone - an extension switched on that
was off again at the next start. The read-change-write now holds the
store's file lock (``extensions.json.lock``), which every process takes.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

pytestmark = pytest.mark.skipif(os.name != "posix", reason="flock")


def test_sad_a_switch_waits_for_the_other_process_and_keeps_its_change(tmp_path, monkeypatch):
    import fcntl

    from core import extensions as EX

    monkeypatch.setenv("HOME", str(tmp_path))
    path = EX.settings_file()
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({"enabled": ["user:a"]}), encoding="utf-8")

    other = os.open(str(path) + ".lock", os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(other, fcntl.LOCK_EX)  # the other process reads ...
    stale = json.loads(path.read_text(encoding="utf-8"))
    worker = threading.Thread(target=EX.set_enabled, args=("user:b", True))
    worker.start()
    try:
        time.sleep(0.3)
        stale["enabled"].append("user:c")  # ... switches c on and writes
        path.write_text(json.dumps(stale), encoding="utf-8")
    finally:
        fcntl.flock(other, fcntl.LOCK_UN)
        os.close(other)
    worker.join(10)
    assert not worker.is_alive()
    assert EX.enabled_ids() == {"user:a", "user:b", "user:c"}


def test_happy_switching_still_keeps_the_other_lists(tmp_path, monkeypatch):
    from core import extensions as EX

    monkeypatch.setenv("HOME", str(tmp_path))
    EX.set_enabled("user:a", True)
    EX.set_paused("user:a", True)
    EX.set_suspended("user:x", True)
    EX.set_enabled("user:x", True)  # clears the suspension
    assert EX.enabled_ids() == {"user:a", "user:x"}
    assert EX.paused_ids() == {"user:a"}
    assert EX.suspended_ids() == set()
    assert EX.settings_file().stat().st_mode & 0o777 == 0o600
