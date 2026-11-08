"""Ctrl+Z of a batch larger than the journal window Ctrl+Z reads.

Found in the final review: a move of 8,000 files journals 24,000 events;
Ctrl+Z reads the newest 20,000 (and at most 4 MB of each journal file),
so it offered "move 3086 entries back", moved those back and recorded the
whole batch as undone - the other 4,914 files could never be undone.

Now the batch is read whole before it is undone
(core.operation_journal.read_batch, core.undo.complete_batch), within the
current journal and its rotated ``.1``; a batch whose first entries are no
longer there is refused with nothing changed. An undo record hides only
the entries it lists: one built from part of a batch leaves the rest.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core import operation_journal as OJ  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402
from core.undo import (  # noqa: E402
    batch_transfer_pairs,
    complete_batch,
    pick_undoable,
    record_undone,
    undoable,
)
from tests.test_undo_window_targets import _WindowBase  # noqa: E402

_DETAILS = {"direction": "DOWNLOAD", "source_backend": "Local"}


def _journal_move(n: int, batch: str, src="/a", dst="/b") -> None:
    """A move of *n* files journalled as the transfer engine does it."""
    for i in range(n):
        source, dest = f"{src}/f{i:05d}.txt", f"{dst}/f{i:05d}.txt"
        details = {**_DETAILS, "batch": batch}
        op = OJ.start_operation("move", source=source, dest=dest, backend="Local",
                                details=dict(details))
        OJ.record_phase(op, "worker_start", "move", source=source, dest=dest,
                        backend="Local", details=dict(details))
        OJ.finish_operation(op, "move", status="done", source=source, dest=dest,
                            backend="Local", details=dict(details))


def _journal_single_move(name: str) -> str:
    op = OJ.start_operation("move", source=f"/a/{name}", dest=f"/b/{name}", backend="Local",
                            details=dict(_DETAILS))
    OJ.finish_operation(op, "move", status="done", source=f"/a/{name}", dest=f"/b/{name}",
                        backend="Local", details=dict(_DETAILS))
    return op


def _batch_plans(events, batch):
    return [p for p in undoable(events) if p.batch == batch]


# -- happy --------------------------------------------------------------------------------------


def test_happy_a_batch_larger_than_the_window_is_read_whole_and_undone_whole(tmp_path,
                                                                            monkeypatch):
    monkeypatch.setenv("AXROSS_OPERATION_JOURNAL", str(tmp_path / "ops.jsonl"))
    before = _journal_single_move("older.txt")
    batch = OJ.new_batch_id()
    _journal_move(400, batch)  # 1,200 events
    window = OJ.read_recent(300)  # Ctrl+Z's window, made small
    seen = pick_undoable(undoable(window), {"Local"})
    assert seen.batch == batch and len(batch_transfer_pairs(seen)) < 400  # the bug's view
    plan = complete_batch(seen)
    assert plan.reversible and plan.action == "batch"
    assert len(batch_transfer_pairs(plan)) == 400
    assert "400" in plan.reason
    record_undone(plan)
    everything = OJ.read_recent(10_000)
    assert _batch_plans(everything, batch) == []
    assert pick_undoable(undoable(everything), {"Local"}).operation_id == before


def test_happy_a_normal_batch_still_undoes_fully(tmp_path, monkeypatch):
    monkeypatch.setenv("AXROSS_OPERATION_JOURNAL", str(tmp_path / "ops.jsonl"))
    batch = OJ.new_batch_id()
    _journal_move(5, batch)
    plan = pick_undoable(undoable(OJ.read_recent(20_000)), {"Local"})
    whole = complete_batch(plan)
    assert [p.operation_id for p in whole.parts] == [p.operation_id for p in plan.parts]
    assert whole.reason == plan.reason and len(batch_transfer_pairs(whole)) == 5
    record_undone(whole)
    assert _batch_plans(OJ.read_recent(20_000), batch) == []


def test_happy_a_batch_beginning_in_the_rotated_journal_is_read_from_there(tmp_path,
                                                                           monkeypatch):
    journal = tmp_path / "ops.jsonl"
    monkeypatch.setenv("AXROSS_OPERATION_JOURNAL", str(journal))
    for i in range(80):  # older operations first in what is now ".1"
        _journal_single_move(f"old{i}.txt")
    batch = OJ.new_batch_id()
    _journal_move(50, batch)
    OJ._FILE.close()
    os.replace(journal, str(journal) + ".1")
    _journal_move(30, batch, src="/a2", dst="/b2")  # the batch goes on after the rotation
    plan = complete_batch(pick_undoable(undoable(OJ.read_recent(40)), {"Local"}))
    assert plan.reversible and len(batch_transfer_pairs(plan)) == 80


# -- sad ----------------------------------------------------------------------------------------


def test_sad_a_batch_whose_first_entries_are_gone_is_refused_and_nothing_recorded(tmp_path,
                                                                                  monkeypatch):
    journal = tmp_path / "ops.jsonl"
    monkeypatch.setenv("AXROSS_OPERATION_JOURNAL", str(journal))
    batch = OJ.new_batch_id()
    _journal_move(60, batch)  # this file is the ".1" now: an older one held the start
    OJ._FILE.close()
    os.replace(journal, str(journal) + ".1")
    _journal_move(60, batch, src="/a2", dst="/b2")
    seen = pick_undoable(undoable(OJ.read_recent(100)), {"Local"})
    plan = complete_batch(seen)
    assert not plan.reversible
    assert "too large to undo here" in plan.reason and "Nothing was changed" in plan.reason
    lines = [json.loads(line) for line in journal.read_text().splitlines()]
    assert not [e for e in lines if e.get("operation") == "undo"]


def test_sad_an_undo_built_from_part_of_a_batch_hides_only_the_parts_it_lists(tmp_path,
                                                                            monkeypatch):
    """The old path: a plan built from the newest events, recorded undone.
    The entries it never saw stay in the history."""
    monkeypatch.setenv("AXROSS_OPERATION_JOURNAL", str(tmp_path / "ops.jsonl"))
    batch = OJ.new_batch_id()
    _journal_move(100, batch)
    partial = pick_undoable(undoable(OJ.read_recent(90)), {"Local"})
    reversed_parts = len(partial.parts)
    assert 0 < reversed_parts < 100
    record_undone(partial)
    [rest] = _batch_plans(OJ.read_recent(10_000), batch)
    assert rest.reversible and len(batch_transfer_pairs(rest)) == 100 - reversed_parts


def test_sad_the_refusal_is_translated():
    german = json.loads((Path(__file__).resolve().parent.parent / "resources" / "i18n"
                         / "de.json").read_text(encoding="utf-8"))
    for count in ("file", "files", "item", "items"):
        what = "move" if count.startswith("file") else "Move to Trash"
        key = (f"This {what} of more than {{n}} {count} is too large to undo here: the "
               "operation journal no longer holds its first entries. Nothing was changed.")
        assert "{n}" in german[key], key


# -- edge ---------------------------------------------------------------------------------------


def test_edge_a_failed_entry_of_an_undone_batch_stays_hidden(tmp_path, monkeypatch):
    monkeypatch.setenv("AXROSS_OPERATION_JOURNAL", str(tmp_path / "ops.jsonl"))
    batch = OJ.new_batch_id()
    _journal_move(3, batch)
    op = OJ.start_operation("move", source="/a/bad", dest="/b/bad", backend="Local",
                            details={**_DETAILS, "batch": batch})
    OJ.finish_operation(op, "move", status="error", source="/a/bad", dest="/b/bad",
                        backend="Local", details={**_DETAILS, "batch": batch})
    record_undone(complete_batch(pick_undoable(undoable(OJ.read_recent(500)), {"Local"})))
    assert _batch_plans(OJ.read_recent(500), batch) == []


# -- the window: Ctrl+Z --------------------------------------------------------------------------


class BigBatchUndoWindowTest(_WindowBase):
    def setUp(self) -> None:
        super().setUp()
        self.a, self.b = self.tmp / "a", self.tmp / "b"
        self.a.mkdir()
        self.b.mkdir()
        self.go(self.local, self.a)
        self.other = self.add_pane(LocalFS())
        self.go(self.other, self.b)

    def test_happy_ctrl_z_moves_every_file_back_when_the_window_holds_a_part(self) -> None:
        names = [f"f{i:02d}.txt" for i in range(12)]
        for name in names:
            (self.a / name).write_text(name)
        self.go(self.local, self.a)
        self.win._start_transfer_between(self.local, self.other,
                                         [str(self.a / n) for n in names], move=True)
        self.assertTrue(self.wait_for(
            lambda: not any((self.a / n).exists() for n in names) and self.transfers_idle()))
        with mock.patch("ui.main_window.UNDO_JOURNAL_EVENTS", 12):  # a few files' events
            _info, warn = self.undo()
        self.assertFalse(warn.called, warn.call_args)
        self.assertTrue(self.wait_for(lambda: all((self.a / n).exists() for n in names)))
        self.assertEqual(sorted(p.name for p in self.b.iterdir()), [])

    def test_sad_ctrl_z_refuses_a_batch_whose_start_is_gone_and_changes_nothing(self) -> None:
        batch = OJ.new_batch_id()
        for i in range(40):
            (self.b / f"g{i:02d}.txt").write_text("x")
        with OJ.journal_batch(batch):
            for i in range(20):
                OJ.finish_operation(OJ.new_operation_id(), "move", status="done",
                                    source=str(self.a / f"g{i:02d}.txt"),
                                    dest=str(self.b / f"g{i:02d}.txt"),
                                    backend="Local", details=dict(_DETAILS))
        OJ._FILE.close()
        os.replace(self.journal, str(self.journal) + ".1")
        with OJ.journal_batch(batch):
            for i in range(20, 40):
                OJ.finish_operation(OJ.new_operation_id(), "move", status="done",
                                    source=str(self.a / f"g{i:02d}.txt"),
                                    dest=str(self.b / f"g{i:02d}.txt"),
                                    backend="Local", details=dict(_DETAILS))
        info, warn = self.undo()
        self.assertFalse(warn.called, warn.call_args)
        self.assertTrue(info.called)
        self.assertIn("too large to undo here", str(info.call_args))
        self.assertEqual(len(list(self.b.iterdir())), 40)
        self.assertEqual(list(self.a.iterdir()), [])
        undo_rows = [line for line in self.journal.read_text().splitlines()
                     if '"operation":"undo"' in line]
        self.assertEqual(undo_rows, [])
