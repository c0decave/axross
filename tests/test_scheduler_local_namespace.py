"""The scheduler's "two jobs never write one path at once, nothing reads a
path another job writes" holds across panes: every pane has its own
LocalFS, and paths were keyed by the object - a copy into /backup/f
through one pane ran beside a move of /backup/f through another."""
from __future__ import annotations

import os
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core import transfer_pool as TP  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402
from core.transfer_worker import TransferJob  # noqa: E402


def _job(src, dst, sp, dp, move=False):
    j = TransferJob(source_path=sp, dest_path=dp, filename=os.path.basename(sp), move=move)
    j.source_backend, j.dest_backend = src, dst
    return j


def _take_now(sched, index):
    out, stop = [], threading.Event()
    t = threading.Thread(target=lambda: out.append(sched.take(index, stop.is_set)))
    t.start()
    t.join(0.2)
    if t.is_alive():
        stop.set()
        sched.wake()
        t.join(2)
        return None
    return out[0]


def test_edge_one_local_file_through_two_panes_is_one_path(tmp_path):
    pane_b, pane_c = LocalFS(), LocalFS()
    target = str(tmp_path / "backup" / "f")
    writer = _job(pane_b, pane_b, str(tmp_path / "src" / "f"), target)
    mover = _job(pane_c, pane_c, target, str(tmp_path / "other" / "f"), move=True)
    sched = TP.JobScheduler(4)
    sched.put(writer)
    sched.put(mover)
    assert sched.take(0, lambda: False)[0] is writer
    assert _take_now(sched, 1) is None  # waits for the writer
    sched.done(writer)
    assert sched.take(1, lambda: False)[0] is mover
