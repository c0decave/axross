"""The batch-begin marker of the operation journal.

Round-5 review: read_batch called a batch "whole" when its first event in
the rotated journal was at least 64 lines in. A big move whose start
events (and its first 100 files) were rotated away while another queued
copy's 100 start events opened the rotated file was called whole: Ctrl+Z
moved back 200 of 300 files and recorded the batch as undone. And a batch
that legitimately began within the first 64 lines of the rotated file was
refused.

Now each batch producer journals a ``batch_begin`` marker first
(core.operation_journal.begin_batch, journal_batch(begin=...)); a batch is
whole when that marker is its first surviving event. A journal without
markers keeps the old rule, and a finish whose start is gone refuses it.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core import operation_journal as OJ  # noqa: E402
from core.undo import (  # noqa: E402
    batch_transfer_pairs,
    complete_batch,
    pick_undoable,
    record_undone,
    undoable,
)

_DET = {"direction": "UPLOAD", "source_backend": "Local"}


def _ev(op, kind, batch, i, phase, src="/home/a/pics", dst="/srv/nas/pics"):
    kw = dict(source=f"{src}/f{i:04d}.jpg", dest=f"{dst}/f{i:04d}.jpg", backend="nas (SFTP)",
              bytes_total=10, details={**_DET, "batch": batch})
    if phase == "start":
        return OJ.start_operation(kind, **kw)
    if phase == "worker_start":
        return OJ.record_phase(op, "worker_start", kind, **kw)
    return OJ.finish_operation(op, kind, status="done", bytes_done=10, **kw)


def _move(batch, n, *, marker=True, src="/a", dst="/b", start=0):
    if marker:
        OJ.begin_batch(batch, "move", entries=n)
    for i in range(start, start + n):
        op = _ev(None, "move", batch, i, "start", src, dst)
        _ev(op, "move", batch, i, "worker_start", src, dst)
        _ev(op, "move", batch, i, "finish", src, dst)


def _plan_of(batch):
    return next(p for p in undoable(OJ.read_recent(limit=20_000)) if p.batch == batch)


def _rotate(journal: Path) -> None:
    OJ._FILE.close()
    OJ._rotate(str(journal))


def _lines(journal: Path) -> list[dict]:
    return [json.loads(line) for line in journal.read_text().splitlines()]


# -- happy --------------------------------------------------------------------------------------


def test_happy_a_batch_beginning_at_the_top_of_the_rotated_journal_is_whole(tmp_path,
                                                                           monkeypatch):
    """The old rule refused it (first event within 64 lines of .1)."""
    journal = tmp_path / "ops.jsonl"
    monkeypatch.setenv("AXROSS_OPERATION_JOURNAL", str(journal))
    batch = OJ.new_batch_id()
    _move(batch, 10)
    _rotate(journal)  # the marker is the first line of .1 now
    _move(batch, 5, marker=False, start=10)
    events, whole = OJ.read_batch(batch)
    assert whole
    plan = complete_batch(_plan_of(batch))
    assert plan.reversible and len(plan.parts) == 15


def test_happy_the_marker_is_ignored_by_the_undo_list_and_read_recent_consumers(tmp_path,
                                                                                monkeypatch):
    journal = tmp_path / "ops.jsonl"
    monkeypatch.setenv("AXROSS_OPERATION_JOURNAL", str(journal))
    batch = OJ.new_batch_id()
    OJ.begin_batch(batch, "transfer", entries=3)
    [marker] = OJ.read_recent(10)
    assert marker["phase"] == OJ.BATCH_BEGIN and marker["operation_id"] == batch
    assert marker["details"] == {"batch": batch, "entries": 3}
    assert undoable(OJ.read_recent(10)) == []


def test_happy_journal_batch_with_begin_writes_the_marker_first(tmp_path, monkeypatch):
    journal = tmp_path / "ops.jsonl"
    monkeypatch.setenv("AXROSS_OPERATION_JOURNAL", str(journal))
    batch = OJ.new_batch_id()
    with OJ.journal_batch(batch, begin="trash", entries=2):
        OJ.start_operation("trash", source="/x")
    first, second = _lines(journal)
    assert first["phase"] == "batch_begin" and first["operation"] == "trash"
    assert second["details"]["batch"] == batch


def test_happy_the_transfer_manager_opens_each_batch_with_a_marker(tmp_path, monkeypatch):
    from core.local_fs import LocalFS
    from core.transfer_manager import TransferManager
    from core.transfer_worker import TransferDirection

    journal = tmp_path / "ops.jsonl"
    monkeypatch.setenv("AXROSS_OPERATION_JOURNAL", str(journal))
    (tmp_path / "src").mkdir()
    (tmp_path / "dst").mkdir()
    for name in ("a.txt", "b.txt"):
        (tmp_path / "src" / name).write_text("x")
    manager = TransferManager.__new__(TransferManager)
    import threading

    manager._local = threading.local()
    batches = []
    manager._transfer_files = lambda *a, **k: batches.append(manager._local.batch_id) or []
    manager.transfer_files(LocalFS(), LocalFS(), [str(tmp_path / "src" / "a.txt"),
                                                 str(tmp_path / "src" / "b.txt")],
                           str(tmp_path / "dst"), TransferDirection.UPLOAD, move=True)
    [marker] = _lines(journal)
    assert marker["phase"] == "batch_begin" and marker["operation_id"] == batches[0]
    assert marker["operation"] == "move" and marker["details"]["entries"] == 2


# -- sad ----------------------------------------------------------------------------------------


def test_sad_a_batch_whose_start_was_rotated_away_behind_another_batch_is_refused(tmp_path,
                                                                                 monkeypatch):
    """repro_undo_rotation_edge.py: offered 200 of 300 files and recorded
    the move undone. A journal from before the marker (no marker at all)."""
    journal = tmp_path / "ops.jsonl"
    monkeypatch.setenv("AXROSS_OPERATION_JOURNAL", str(journal))
    b, c = OJ.new_batch_id(), OJ.new_batch_id()
    n = 300
    b_ops = [_ev(None, "move", b, i, "start") for i in range(n)]
    for i in range(100):
        _ev(b_ops[i], "move", b, i, "worker_start")
        _ev(b_ops[i], "move", b, i, "finish")
    _rotate(journal)
    for i in range(100):
        _ev(None, "transfer", c, i, "start", "/home/a/docs", "/mnt/usb")
    for i in range(100, n):
        _ev(b_ops[i], "move", b, i, "worker_start")
        _ev(b_ops[i], "move", b, i, "finish")
    _rotate(journal)  # the file with B's start is gone
    _ev(None, "transfer", c, 0, "start", "/x", "/y")
    _events, whole = OJ.read_batch(b)
    assert not whole
    plan = complete_batch(_plan_of(b))
    assert not plan.reversible and "too large to undo here" in plan.reason


def test_sad_a_marked_batch_whose_marker_was_rotated_away_is_refused(tmp_path, monkeypatch):
    journal = tmp_path / "ops.jsonl"
    monkeypatch.setenv("AXROSS_OPERATION_JOURNAL", str(journal))
    for i in range(80):  # other work first
        _ev(None, "copy", "", i, "start", "/o", "/p")
    batch = OJ.new_batch_id()
    _move(batch, 30)
    _rotate(journal)
    _move(batch, 30, marker=False, start=30)
    _rotate(journal)  # marker and first 30 files gone
    _move(batch, 30, marker=False, start=60)
    _events, whole = OJ.read_batch(batch)
    assert not whole
    assert not complete_batch(_plan_of(batch)).reversible
    assert not [e for e in _lines(journal) if e.get("operation") == "undo"]


# -- edge ---------------------------------------------------------------------------------------


def test_edge_events_of_the_batch_before_its_marker_mean_not_whole(tmp_path, monkeypatch):
    """An id reused by a second call: the surviving part of the first call
    precedes the second marker - its own start may be gone."""
    journal = tmp_path / "ops.jsonl"
    monkeypatch.setenv("AXROSS_OPERATION_JOURNAL", str(journal))
    batch = OJ.new_batch_id()
    _move(batch, 5, marker=False)
    _move(batch, 5, start=5)
    _events, whole = OJ.read_batch(batch)
    assert not whole


def test_edge_an_old_journal_batch_well_inside_dot_one_is_still_whole(tmp_path, monkeypatch):
    journal = tmp_path / "ops.jsonl"
    monkeypatch.setenv("AXROSS_OPERATION_JOURNAL", str(journal))
    for i in range(80):
        _ev(None, "copy", "", i, "start", "/o", "/p")
    batch = OJ.new_batch_id()
    _move(batch, 20, marker=False)
    _rotate(journal)
    _move(batch, 10, marker=False, start=20)
    plan = complete_batch(pick_undoable(undoable(OJ.read_recent(40)), {"nas (SFTP)"}))
    assert plan.reversible and len(batch_transfer_pairs(plan)) == 30
    record_undone(plan)
    assert [p for p in undoable(OJ.read_recent(20_000)) if p.batch == batch] == []


def test_edge_a_move_folder_entry_without_a_start_does_not_refuse_an_old_batch(tmp_path,
                                                                              monkeypatch):
    journal = tmp_path / "ops.jsonl"
    monkeypatch.setenv("AXROSS_OPERATION_JOURNAL", str(journal))
    for i in range(80):
        _ev(None, "copy", "", i, "start", "/o", "/p")
    batch = OJ.new_batch_id()
    _move(batch, 3, marker=False)
    OJ.finish_operation(OJ.new_operation_id(), "move_folder", status="done", source="/a",
                        dest="/b", backend="nas (SFTP)", details={**_DET, "batch": batch})
    _rotate(journal)
    _events, whole = OJ.read_batch(batch)
    assert whole
