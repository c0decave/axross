"""Undoing a folder move puts its files back, and only a finished undo counts.

Measured before: moving folder ``x/photos`` removed the emptied source
folder afterwards. Ctrl+Z planned "transfer y/photos/a.jpg back to
x/photos/a.jpg" and queued that file into ``x/photos`` -- which no longer
existed, so the job failed. The window had already journaled the undo as
done and said "Undone" the moment the job was queued: the entry left the
undo history although nothing was restored.

Now apply_undo recreates the missing folders on the way back, the transfer
back refuses to replace a file that appeared in the meantime, and the
window records the undo only when every job of it finished.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest  # noqa: E402

from core.local_fs import LocalFS  # noqa: E402
from core.undo import UndoPlan, apply_undo  # noqa: E402
from tests.test_undo_window_targets import _WindowBase  # noqa: E402


def _plan(source: str, dest: str) -> UndoPlan:
    return UndoPlan(
        operation_id="op1",
        operation="move",
        reversible=True,
        action="transfer_back",
        reason=f"transfer {dest} back to {source}",
        source=source,
        dest=dest,
        backend="Local",
        direction="DOWNLOAD",
        source_backend="Local",
    )


# --------------------------------------------------------------------------
# core.undo.apply_undo
# --------------------------------------------------------------------------


def test_happy_transfer_back_recreates_the_removed_folders(tmp_path):
    (tmp_path / "y" / "photos").mkdir(parents=True)
    (tmp_path / "y" / "photos" / "a.jpg").write_bytes(b"JPEG")
    seen = {}

    def transfer(*, src_backend, src_path, dst_backend, dst_path):
        seen["parent_existed"] = os.path.isdir(os.path.dirname(dst_path))
        return dst_path

    source = tmp_path / "x" / "deep" / "photos" / "a.jpg"
    fs = LocalFS()
    result = apply_undo(
        _plan(str(source), str(tmp_path / "y" / "photos" / "a.jpg")),
        fs,
        source_backend=fs,
        transfer=transfer,
    )
    assert result == str(source)
    assert seen == {"parent_existed": True}


def test_sad_a_file_where_the_folder_was_refuses_before_transferring(tmp_path):
    (tmp_path / "x").mkdir()
    (tmp_path / "x" / "photos").write_text("a file took the folder's name")
    called = []
    fs = LocalFS()
    with pytest.raises(OSError):
        apply_undo(
            _plan(str(tmp_path / "x" / "photos" / "a.jpg"), str(tmp_path / "y" / "a.jpg")),
            fs,
            source_backend=fs,
            transfer=lambda **kw: called.append(kw),
        )
    assert called == []
    assert (tmp_path / "x" / "photos").read_text() == "a file took the folder's name"


def test_edge_a_folder_reached_through_a_symlink_is_accepted(tmp_path):
    (tmp_path / "data" / "pics").mkdir(parents=True)
    os.symlink(tmp_path / "data" / "pics", tmp_path / "Pictures")
    fs = LocalFS()
    result = apply_undo(
        _plan(str(tmp_path / "Pictures" / "a.jpg"), str(tmp_path / "y" / "a.jpg")),
        fs,
        source_backend=fs,
        transfer=lambda **kw: kw["dst_path"],
    )
    assert result == str(tmp_path / "Pictures" / "a.jpg")
    assert os.path.islink(tmp_path / "Pictures")


def test_edge_an_existing_folder_is_left_as_it_is(tmp_path):
    (tmp_path / "x" / "photos").mkdir(parents=True)
    (tmp_path / "x" / "photos" / "other.jpg").write_bytes(b"keep")
    fs = LocalFS()
    apply_undo(
        _plan(str(tmp_path / "x" / "photos" / "a.jpg"), str(tmp_path / "y" / "a.jpg")),
        fs,
        source_backend=fs,
        transfer=lambda **kw: kw["dst_path"],
    )
    assert (tmp_path / "x" / "photos" / "other.jpg").read_bytes() == b"keep"


# --------------------------------------------------------------------------
# The window: Ctrl+Z after a folder move
# --------------------------------------------------------------------------


class FolderMoveUndoTest(_WindowBase):
    def setUp(self) -> None:
        super().setUp()
        self.x = self.tmp / "x"
        self.y = self.tmp / "y"
        (self.x / "photos").mkdir(parents=True)
        self.y.mkdir()
        (self.x / "photos" / "a.jpg").write_bytes(b"JPEGDATA")
        self.go(self.local, self.x)
        self.other = self.add_pane(type(self.local.backend)())
        self.go(self.other, self.y)

    def move_folder(self) -> None:
        self.win._start_transfer_between(
            self.local, self.other, [str(self.x / "photos")], move=True
        )
        self.assertTrue(
            self.wait_for(lambda: not (self.x / "photos").exists() and self.transfers_idle())
        )
        self.assertEqual((self.y / "photos" / "a.jpg").read_bytes(), b"JPEGDATA")

    def undo_rows(self) -> list[dict]:
        rows = [json.loads(line) for line in self.journal.read_text().splitlines()]
        return [r for r in rows if r.get("operation") == "undo"]

    def test_happy_undo_puts_the_file_back_into_its_folder(self) -> None:
        self.move_folder()
        _info, warn = self.undo()
        self.assertFalse(warn.called, warn.call_args)
        self.assertEqual((self.x / "photos" / "a.jpg").read_bytes(), b"JPEGDATA")
        self.assertFalse((self.y / "photos" / "a.jpg").exists())
        self.assertEqual(len(self.undo_rows()), 1)

    def test_sad_a_failed_transfer_back_is_not_recorded_as_undone(self) -> None:
        self.move_folder()
        from core.transfer_worker import TransferWorker

        def refuse(job):
            raise OSError("simulated: connection dropped")

        with mock.patch.object(TransferWorker, "_check_existing_destination", side_effect=refuse):
            _info, warn = self.undo()
        self.assertTrue(warn.called)
        self.assertIn("connection dropped", str(warn.call_args))
        self.assertEqual(self.undo_rows(), [])
        self.assertEqual((self.y / "photos" / "a.jpg").read_bytes(), b"JPEGDATA")
        # Still offered: the next Ctrl+Z tries the same operation again.
        _info, warn = self.undo()
        self.assertFalse(warn.called, warn.call_args)
        self.assertEqual((self.x / "photos" / "a.jpg").read_bytes(), b"JPEGDATA")

    def test_edge_nothing_is_recorded_while_the_transfer_back_runs(self) -> None:
        from PyQt6.QtWidgets import QMessageBox

        self.move_folder()
        yes = QMessageBox.StandardButton.Yes
        with mock.patch("ui.main_window.QMessageBox.question", return_value=yes), \
                mock.patch("ui.main_window.QMessageBox.information"), \
                mock.patch("ui.main_window.QMessageBox.warning"):
            self.win._undo_last_operation()
            # Queued, not finished: the event loop has not run yet.
            self.assertEqual(self.undo_rows(), [])
            self.assertTrue(self.wait_for(lambda: len(self.undo_rows()) == 1))

    def test_edge_the_transfer_back_never_replaces_a_file(self) -> None:
        self.move_folder()
        calls = []
        real = self.win._transfer_manager.transfer_files

        def spy(**kw):
            calls.append(kw)
            return real(**kw)

        with mock.patch.object(self.win._transfer_manager, "transfer_files", side_effect=spy):
            self.undo()
        [kw] = calls
        plan = kw["conflict_plan"]
        self.assertIsNotNone(plan)
        self.assertEqual(plan.resolve(str(self.x / "photos" / "a.jpg"))[1], "fail")
