"""Undo finds an entry trashed into a trash folder of its own.

``core.trash.trash(..., root=...)`` - the agent's duplicate removal, a
script's ``axross.trash(path, root=...)`` - journaled only the trash id,
not the folder. Undo looked in the backend's default trash: the entry
counted as "gone", Ctrl+Z passed over it and quietly undid an older
operation instead, and undoing the entry itself failed with "trash entry
not found".
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import operation_journal as OJ  # noqa: E402
from core import trash as T  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402
from core.undo import apply_undo, gone_reason, pick_undoable, undoable  # noqa: E402


@pytest.fixture
def setup(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir()
    monkeypatch.setenv("AXROSS_OPERATION_JOURNAL", str(tmp_path / "journal.jsonl"))
    fs = LocalFS()
    work = tmp_path / "work"
    work.mkdir()
    older = work / "older.txt"
    newer = work / "newer.txt"
    older.write_text("A")
    newer.write_text("B")
    own_trash = str(tmp_path / "own-trash")
    T.trash(fs, str(older))  # the default trash
    T.trash(fs, str(newer), root=own_trash)
    return fs, older, newer, own_trash


def _pick(fs):
    return pick_undoable(
        undoable(OJ.read_recent(200)), {fs.name}, gone=lambda p: bool(gone_reason(p, fs))
    )


def test_happy_ctrl_z_restores_the_newest_entry_from_its_own_trash(setup):
    fs, older, newer, own_trash = setup
    plan = _pick(fs)
    assert plan.source == str(newer)
    assert plan.trash_root == own_trash
    assert gone_reason(plan, fs) == ""
    apply_undo(plan, fs)
    assert newer.read_text() == "B"
    assert not older.exists()  # the older operation was left alone


def test_sad_an_entry_gone_from_its_own_trash_is_passed_over(setup):
    fs, older, newer, own_trash = setup
    (entry,) = T.list_trash(fs, root=own_trash)
    T.restore(fs, entry.trash_id, root=own_trash)  # restored by hand
    plan = _pick(fs)
    assert plan.source == str(older)


def test_edge_the_default_trash_journals_no_folder(setup):
    fs, older, _newer, _own = setup
    plans = [p for p in undoable(OJ.read_recent(200)) if p.source == str(older)]
    assert plans and plans[0].trash_root == ""
