"""Ctrl+Z after a move never moves a different file than the one the move
put there.

Review round 6 (N1): F6 of ``report.pdf`` from A to B, then in B the file
renamed to ``report-2025.pdf`` and a colleague's new ``report.pdf`` saved
there. Ctrl+Z asked "transfer B/report.pdf back to A/report.pdf" and moved
the colleague's file to A. Undo knew only the two paths.

Now a move's finish event records what it put there (kind, size, and on
this machine's disk mtime_ns, inode and device; elsewhere the mtime stat
reports), and undo compares before it moves anything back: an entry that
is not that file any more is refused with the reason. Entries journaled
before the identity was recorded still compare the size the move wrote.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core.local_fs import LocalFS  # noqa: E402
from core.undo import (  # noqa: E402
    apply_undo,
    entry_identity,
    plan_undo,
    unchanged_parts,
    undoable,
)
from tests.test_undo_window_targets import _WindowBase  # noqa: E402

_REASON = "is not the file the move put there"


def _event(src, dst, *, identity=None, bytes_total=0, direction="DOWNLOAD", batch=""):
    details = {"source_backend": "Local"} if direction else {}
    if direction:
        details["direction"] = direction
    if identity is not None:
        details["dest_identity"] = identity
    if batch:
        details["batch"] = batch
    return {"operation_id": f"op-{os.path.basename(dst)}", "phase": "finish",
            "operation": "move", "status": "done", "backend": "Local",
            "source": str(src), "dest": str(dst), "bytes_total": bytes_total,
            "details": details}


def _transfer_spy():
    calls = []

    def transfer(**kwargs):
        calls.append(kwargs)
        return kwargs["dst_path"]

    return calls, transfer


def _replace(path: Path, text: str) -> None:
    """Rename the moved file away and save a new one under its name."""
    path.rename(path.with_name("renamed-" + path.name))
    path.write_text(text)


# --- core.undo ---------------------------------------------------------------


def test_sad_transfer_back_refuses_a_file_saved_under_the_moved_name(tmp_path):
    fs = LocalFS()
    (tmp_path / "A").mkdir()
    (tmp_path / "B").mkdir()
    moved = tmp_path / "B" / "report.pdf"
    moved.write_text("the report the user moved")
    plan = plan_undo(_event(tmp_path / "A" / "report.pdf", moved,
                            identity=entry_identity(fs, str(moved))))
    _replace(moved, "the colleague's new report")
    calls, transfer = _transfer_spy()
    with pytest.raises(OSError, match=_REASON):
        apply_undo(plan, fs, source_backend=fs, transfer=transfer)
    assert calls == []
    assert moved.read_text() == "the colleague's new report"
    assert not (tmp_path / "A" / "report.pdf").exists()


def test_happy_an_unchanged_destination_goes_back(tmp_path):
    fs = LocalFS()
    moved = tmp_path / "report.pdf"
    moved.write_text("the report")
    plan = plan_undo(_event(tmp_path / "A" / "report.pdf", moved,
                            identity=entry_identity(fs, str(moved))))
    assert dict(plan.identity)["ino"] == os.stat(moved).st_ino
    calls, transfer = _transfer_spy()
    apply_undo(plan, fs, source_backend=fs, transfer=transfer)
    assert [c["src_path"] for c in calls] == [str(moved)]


def test_sad_same_backend_move_back_refuses_an_edited_file(tmp_path):
    fs = LocalFS()
    moved = tmp_path / "b.txt"
    moved.write_text("moved")
    plan = plan_undo(_event(tmp_path / "a.txt", moved, direction="",
                            identity=entry_identity(fs, str(moved))))
    assert plan.action == "move_back"
    moved.write_text("edited since, same name, other size")
    with pytest.raises(OSError, match=_REASON):
        apply_undo(plan, fs)
    assert moved.exists() and not (tmp_path / "a.txt").exists()


def test_edge_entry_without_identity_compares_the_size_it_wrote(tmp_path):
    fs = LocalFS()
    moved = tmp_path / "b.txt"
    moved.write_text("12345")
    calls, transfer = _transfer_spy()
    wrong = plan_undo(_event(tmp_path / "a.txt", moved, bytes_total=99))
    assert (wrong.identity, wrong.expected_size) == ((), 99)
    with pytest.raises(OSError, match=_REASON):
        apply_undo(wrong, fs, source_backend=fs, transfer=transfer)
    for total in (5, 0):  # the size it wrote, or none recorded: as before
        apply_undo(plan_undo(_event(tmp_path / "a.txt", moved, bytes_total=total)),
                   fs, source_backend=fs, transfer=transfer)
    assert len(calls) == 2


def test_edge_a_remote_backend_compares_what_stat_reports(tmp_path):
    from datetime import datetime

    from models.file_item import FileItem

    class Remote:
        def __init__(self, size, when):
            self.item = FileItem(name="f", size=size, modified=when)

        def stat(self, _path):
            return self.item

    first = Remote(10, datetime(2026, 1, 1, 12, 0, 0))
    identity = entry_identity(first, "/srv/f")
    assert set(identity) == {"kind", "size", "mtime"}
    plan = plan_undo(_event("/home/f", "/srv/f", identity=identity))
    from core.undo import replaced_reason

    assert replaced_reason(plan, first) == ""
    assert _REASON in replaced_reason(plan, Remote(10, datetime(2026, 1, 1, 12, 0, 5)))
    assert _REASON in replaced_reason(plan, Remote(11, datetime(2026, 1, 1, 12, 0, 0)))


def test_happy_a_batch_drops_only_the_replaced_part(tmp_path):
    fs = LocalFS()
    files = []
    for name in ("x.txt", "y.txt"):
        f = tmp_path / name
        f.write_text(name)
        files.append(f)
    events = [_event(tmp_path / "src" / f.name, f, batch="b1",
                     identity=entry_identity(fs, str(f))) for f in files]
    [plan] = undoable(events)
    assert plan.action == "batch"
    _replace(files[1], "another y")
    kept, failures = unchanged_parts(plan, fs)
    assert [p.dest for p in kept.parts] == [str(files[0])]
    assert len(failures) == 1 and _REASON in failures[0]


def test_edge_the_reason_is_translated():
    from core import i18n

    catalogue = json.loads((Path(i18n.__file__).resolve().parent.parent
                            / "resources" / "i18n" / "de.json").read_text("utf-8"))
    key = ("{name} is not the file the move put there – it was changed or "
           "replaced since")
    assert key in catalogue and "{name}" in catalogue[key]


# --- the window ----------------------------------------------------------------


class ReplacedDestinationWindowTest(_WindowBase):
    def setUp(self) -> None:
        super().setUp()
        self.a, self.b = self.tmp / "a", self.tmp / "b"
        self.a.mkdir()
        self.b.mkdir()
        self.go(self.local, self.a)
        self.other = self.add_pane(LocalFS())
        self.go(self.other, self.b)

    def finish_events(self):
        rows = [json.loads(line) for line in self.journal.read_text().splitlines() if line]
        return [r for r in rows if r.get("phase") == "finish" and r.get("operation") == "move"]

    def test_happy_a_move_journals_what_it_put_there(self) -> None:
        (self.a / "f.txt").write_text("data")
        self.move(self.local, self.other, self.a / "f.txt")
        [event] = self.finish_events()
        identity = event["details"]["dest_identity"]
        st = os.lstat(self.b / "f.txt")
        self.assertEqual((identity["ino"], identity["dev"], identity["size"],
                          identity["mtime_ns"], identity["kind"]),
                         (st.st_ino, st.st_dev, 4, st.st_mtime_ns, "file"))

    def test_sad_ctrl_z_leaves_a_file_saved_under_the_moved_name(self) -> None:
        (self.a / "report.pdf").write_text("the report the user moved")
        self.move(self.local, self.other, self.a / "report.pdf")
        _replace(self.b / "report.pdf", "the colleague's new report")
        _info, warn = self.undo()
        self.assertTrue(warn.called)
        self.assertIn(_REASON, str(warn.call_args))
        self.assertEqual(os.listdir(self.a), [])
        self.assertEqual((self.b / "report.pdf").read_text(), "the colleague's new report")
        self.assertEqual((self.b / "renamed-report.pdf").read_text(),
                         "the report the user moved")

    def test_sad_a_batch_undo_sends_back_the_rest_and_reports_the_replaced_one(self) -> None:
        proj = self.a / "proj"
        proj.mkdir()
        for name in ("x.txt", "y.txt"):
            (proj / name).write_text(name)
        self.win._start_transfer_between(self.local, self.other, [str(proj)], move=True)
        self.assertTrue(self.wait_for(lambda: not proj.exists() and self.transfers_idle()))
        _replace(self.b / "proj" / "y.txt", "another y")
        _info, warn = self.undo()
        self.assertTrue(self.wait_for(lambda: (proj / "x.txt").exists()))
        self.assertTrue(warn.called)
        self.assertIn(_REASON, str(warn.call_args))
        self.assertFalse((proj / "y.txt").exists())
        self.assertEqual((self.b / "proj" / "y.txt").read_text(), "another y")
