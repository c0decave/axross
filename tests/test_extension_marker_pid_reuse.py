"""A startup marker whose pid now belongs to another long-running process
does not keep its extension suspended for ever.

Measured before: where the start time of a process cannot be read (macOS,
Windows: no /proc), a marker left by a crashed axross whose pid was reused
by an unrelated process that still runs counted as "hung" at every start -
the marker was never removed, so the extension was suspended again after
each Try Again, until that other process ended. A marker older than any
activation can hang (MAX_MARKER_AGE_SECONDS) is now the one of a process
that is gone.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import extensions as EX  # noqa: E402


def _marker(started: float) -> Path:
    folder = EX.activation_dir()
    folder.mkdir(parents=True, exist_ok=True)
    pid = os.getppid()  # alive, not this process; its start time unknown
    path = folder / f"{pid}.json"
    path.write_text(json.dumps({"pid": pid, "ext_id": "user:x", "name": "X",
                                "started": started, "proc_start": None}))
    return path


def test_sad_an_old_marker_of_a_reused_pid_is_ended(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    path = _marker(time.time() - EX.MAX_MARKER_AGE_SECONDS - 60)
    found = EX.collect_stale_activations()
    assert [f["reason"] for f in found] == ["ended"]
    assert not path.exists()


def test_happy_a_recent_hung_marker_stays_hung(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    path = _marker(time.time() - EX.HUNG_ACTIVATION_SECONDS - 5)
    found = EX.collect_stale_activations()
    assert [f["reason"] for f in found] == ["hung"]
    assert path.exists()
