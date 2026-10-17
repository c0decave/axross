"""An undo entry that can no longer be carried out does not block the history.

Before: restoring an entry from Show Trash, deleting it there for good or
emptying the trash is not journaled. Ctrl+Z kept offering "restore X from
the trash" for an entry that was gone, failed with "trash entry not
found", and offered the same impossible entry on every later press: every
older operation was out of reach for good.

Now Ctrl+Z checks that what a trash undo would put back still exists
(``core.undo.gone_reason``) and passes over an entry whose trash entry is
gone, to the newest one that can still be carried out. The check reads
the trash itself, so it covers every way an entry disappears - the trash
window, another tool, a journal written before this fix.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import operation_journal as OJ  # noqa: E402
from core import trash as T  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402
from core.undo import apply_undo, gone_reason, pick_undoable, undoable  # noqa: E402

_APP = None


@pytest.fixture
def setup(tmp_path, monkeypatch):
    monkeypatch.setenv("AXROSS_OPERATION_JOURNAL", str(tmp_path / "journal.jsonl"))
    fs = LocalFS()
    older = tmp_path / "older.txt"
    newer = tmp_path / "newer.txt"
    older.write_text("A")
    newer.write_text("B")
    T.trash(fs, str(older))
    T.trash(fs, str(newer))
    return fs, older, newer


def _pick(fs):
    return pick_undoable(
        undoable(OJ.read_recent(200)), {fs.name}, gone=lambda p: bool(gone_reason(p, fs))
    )


def _entry(fs, path):
    return next(e for e in T.list_trash(fs) if e.original_path == str(path))


def test_happy_a_restored_entry_is_passed_over_for_the_older_one(setup):
    fs, older, newer = setup
    T.restore(fs, _entry(fs, newer).trash_id)  # Show Trash > Restore
    plan = _pick(fs)
    assert plan.source == str(older)
    apply_undo(plan, fs)
    assert older.read_text() == "A"


def test_happy_an_entry_that_still_exists_is_offered(setup):
    fs, _older, newer = setup
    plan = _pick(fs)
    assert plan.source == str(newer)
    assert gone_reason(plan, fs) == ""


def test_sad_an_emptied_trash_leaves_nothing_to_undo(setup):
    fs, _older, _newer = setup
    T.empty_trash(fs)
    assert _pick(fs) is None


def test_sad_the_reason_names_the_missing_trash_entry(setup):
    fs, _older, newer = setup
    T.discard(fs, _entry(fs, newer).trash_id)  # Show Trash > Delete Permanently
    plan = pick_undoable(undoable(OJ.read_recent(200)), {fs.name})
    assert "trash" in gone_reason(plan, fs)


def test_edge_without_a_check_the_old_choice_stays(setup):
    fs, _older, newer = setup
    T.restore(fs, _entry(fs, newer).trash_id)
    plan = pick_undoable(undoable(OJ.read_recent(200)), {fs.name})
    assert plan.source == str(newer)


def test_edge_a_backend_that_cannot_answer_does_not_hide_the_entry(setup):
    fs, _older, newer = setup
    plan = pick_undoable(undoable(OJ.read_recent(200)), {fs.name})

    class _Broken:
        name = fs.name

        def home(self):
            return str(Path.home())

        def join(self, *parts):
            return os.path.join(*parts)

        def separator(self):
            return "/"

        def exists(self, _path):
            raise OSError("connection lost")

    assert gone_reason(plan, _Broken()) == ""


def test_happy_ctrl_z_in_the_window_passes_over_a_restored_entry(setup, monkeypatch):
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PyQt6.QtWidgets import QApplication, QMessageBox

    global _APP  # a QApplication nobody references is collected at once
    _APP = QApplication.instance() or QApplication([])
    import ui.main_window as mw

    fs, older, newer = setup
    T.restore(fs, _entry(fs, newer).trash_id)
    newer.unlink()  # the restored file was used up meanwhile
    asked: list[str] = []
    monkeypatch.setattr(
        QMessageBox,
        "question",
        lambda *a, **k: asked.append(a[2]) or QMessageBox.StandardButton.Yes,
    )
    monkeypatch.setattr(QMessageBox, "information", lambda *a, **k: asked.append(a[2]))
    monkeypatch.setattr(QMessageBox, "warning", lambda *a, **k: asked.append(a[2]))

    class _Window:
        _undo_last_operation = mw.MainWindow._undo_last_operation
        _undo_refusal = staticmethod(mw.MainWindow._undo_refusal)
        _undo_source_backend = mw.MainWindow._undo_source_backend
        _panes: list = []

        def _backends_by_label(self):
            return {fs.name: (fs, None)}

        def _finish_undo(self, plan, pane, jobs=()):
            asked.append(f"done {plan.source}")

    _Window()._undo_last_operation()
    assert older.read_text() == "A"
    assert asked[-1] == f"done {older}"
    assert not newer.exists()
