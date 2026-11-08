"""Undoing a move takes the moved entries' tags back with them.

Review round 3: tag ``report.txt`` "Important", move it with F6 into
another folder (the tag follows to ``b/report.txt``), then Ctrl+Z: the
file came back to ``a/report.txt``, the tag stayed on ``b/report.txt`` -
a path that no longer exists - and the restored row showed no tag.
``MainWindow._undo_transfer`` queued its jobs without ``_track_tag_moves``.

Now the undo goes through the same tag-follow hook with the pairs
reversed: a file's tags, a moved folder's own tags and those of the files
in it go back to the paths the entries return to - on another connection
too, and under the original name after a "Rename" answer.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QEvent, Qt  # noqa: E402
from PyQt6.QtWidgets import QApplication, QMessageBox  # noqa: E402

from core import tags as TG  # noqa: E402
from core import transfer_conflicts as TC  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402

APP = QApplication.instance() or QApplication([])


@pytest.fixture
def win(tmp_path, monkeypatch):
    from ui.main_window import MainWindow

    monkeypatch.setattr(TG, "tags_file", lambda: tmp_path / "tags.json")
    TG.reset_cache()
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("AXROSS_OPERATION_JOURNAL", str(tmp_path / "ops.jsonl"))
    window = MainWindow()
    window._reconnect_timer.stop()
    window._quit_with_transfers = True
    yield window
    _settle(lambda: window._transfer_manager.unfinished() == 0)
    window.close()
    window.deleteLater()
    APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    TG.reset_cache()


def _settle(done, timeout: float = 20.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        APP.processEvents()
        if done():
            return True
        time.sleep(0.01)
    return False


def _panes(win, src: Path, dst: Path, dst_backend=None):
    left = win._active_pane
    left.navigate(str(src))
    win._split_pane(Qt.Orientation.Horizontal)
    right = win._active_pane
    if dst_backend is not None:
        win._close_pane(right)
        right = win._add_pane_to_splitter(win._root_splitter, dst_backend)
    right.navigate(str(dst))
    win._set_active_pane(left)
    win._set_target_pane(right)
    return left, right


def _idle(win) -> bool:
    mgr = win._transfer_manager
    return not mgr._walks and mgr.unfinished() == 0 and not win._tag_job_queue


def _move(win, left, right, paths, plan=None):
    win._start_transfer_between(left, right, [str(p) for p in paths], move=True,
                                conflict_plan=plan)
    assert _settle(lambda: _idle(win) and not any(Path(p).exists() for p in paths)
                   if isinstance(paths[0], Path) else _idle(win))
    _settle(lambda: False, 0.4)  # the tag flush (TAG_FLUSH_GAP_MS)


def _undo(win):
    yes = QMessageBox.StandardButton.Yes
    with mock.patch("ui.main_window.QMessageBox.question", return_value=yes), \
            mock.patch("ui.main_window.QMessageBox.information"), \
            mock.patch("ui.main_window.QMessageBox.warning") as warn:
        win._undo_last_operation()
        assert _settle(lambda: not getattr(win, "_undo_busy", False))
        assert _settle(lambda: _idle(win) and not win._undo_waits)
        _settle(lambda: False, 0.4)
    assert not warn.called, warn.call_args


def _tagged(name: str, backend: str = "Local") -> list[str]:
    return sorted(i.path for i in TG.store().items_with(name) if i.backend_name == backend)


def test_happy_a_file_tag_goes_back_with_the_undone_move(win, tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir()
    b.mkdir()
    (a / "report.txt").write_text("r")
    TG.store().tag("Local", "", str(a / "report.txt"), "Important")
    left, right = _panes(win, a, b)
    _move(win, left, right, [a / "report.txt"])
    assert _tagged("Important") == [str(b / "report.txt")]
    _undo(win)
    assert (a / "report.txt").exists()
    assert _tagged("Important") == [str(a / "report.txt")]


def test_happy_a_folder_and_its_files_take_their_tags_back(win, tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    (a / "proj").mkdir(parents=True)
    b.mkdir()
    (a / "proj" / "x.txt").write_text("x")
    TG.store().define("Project", "#3366cc")
    TG.store().define("Draft", "#cc6633")
    TG.store().tag("Local", "", str(a / "proj"), "Project")
    TG.store().tag("Local", "", str(a / "proj" / "x.txt"), "Draft")
    left, right = _panes(win, a, b)
    _move(win, left, right, [a / "proj"])
    assert _tagged("Project") == [str(b / "proj")]
    _undo(win)
    assert (a / "proj" / "x.txt").exists() and not (b / "proj").exists()
    assert _tagged("Project") == [str(a / "proj")]
    assert _tagged("Draft") == [str(a / "proj" / "x.txt")]


def test_sad_a_renamed_move_takes_the_tag_back_to_the_original_name(win, tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir()
    b.mkdir()
    (a / "report.txt").write_text("mine")
    (b / "report.txt").write_text("theirs")
    TG.store().tag("Local", "", str(a / "report.txt"), "Important")
    fs = LocalFS()
    scan = TC.scan_conflicts(fs, fs, [str(a / "report.txt")], str(b))
    plan = TC.ConflictPlan(fs, scan)
    for conflict in scan.conflicts:
        plan.decide(conflict, TC.ConflictAction.RENAME)
    left, right = _panes(win, a, b)
    _move(win, left, right, [a / "report.txt"], plan)
    assert _tagged("Important") == [str(b / "report (1).txt")]
    _undo(win)
    assert (a / "report.txt").read_text() == "mine"
    assert _tagged("Important") == [str(a / "report.txt")]


def test_edge_a_move_to_another_connection_takes_the_tag_back_home(win, tmp_path):
    from core.ram_fs import RamFsSession

    a = tmp_path / "a"
    a.mkdir()
    (a / "photo.jpg").write_text("p")
    ram = RamFsSession()
    ram.mkdir("/dst")
    TG.store().tag("Local", "", str(a / "photo.jpg"), "Review later")
    left, right = _panes(win, a, "/dst", dst_backend=ram)
    _move(win, left, right, [a / "photo.jpg"])
    assert _tagged("Review later") == []
    _undo(win)
    assert (a / "photo.jpg").exists()
    assert _tagged("Review later") == [str(a / "photo.jpg")]
