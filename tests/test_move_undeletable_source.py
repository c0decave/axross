"""A move whose source cannot be removed afterwards is asked about first.

Reported: a move failed with ``[Errno 13] Permission denied`` when the
source was deleted - the copy was made, the source stayed, the same file
was in two places. Decided: check before the move whether every source
can be removed; if not, ask - move as administrator (pkexec mv, no
permission changed), copy only, or cancel.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import elevated_io as EIO  # noqa: E402
from core import move_permissions as MP  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402

APP = QApplication.instance() or QApplication([])


def _deny_write(monkeypatch, *folders: Path):
    denied = {str(f) for f in folders}
    real = os.access

    def access(path, mode, *a, **k):
        if str(path) in denied and mode & os.W_OK:
            return False
        return real(path, mode, *a, **k)

    monkeypatch.setattr(MP.os, "access", access)


# -- the check ---------------------------------------------------------------------------------


def test_happy_removable_sources_report_nothing(tmp_path):
    (tmp_path / "a.txt").write_text("a")
    (tmp_path / "d").mkdir()
    (tmp_path / "d" / "b.txt").write_text("b")
    assert MP.undeletable_sources(LocalFS(), [str(tmp_path / "a.txt"), str(tmp_path / "d")]) == []


def test_sad_a_source_in_a_read_only_folder_is_reported(tmp_path, monkeypatch):
    (tmp_path / "a.txt").write_text("a")
    _deny_write(monkeypatch, tmp_path)
    (problem,) = MP.undeletable_sources(LocalFS(), [str(tmp_path / "a.txt")])
    assert problem.path == str(tmp_path / "a.txt")
    assert "no write permission" in problem.reason


def test_sad_a_folder_below_that_may_not_be_emptied_is_reported(tmp_path, monkeypatch):
    inner = tmp_path / "d" / "inner"
    inner.mkdir(parents=True)
    (inner / "x").write_text("x")
    _deny_write(monkeypatch, inner)
    (problem,) = MP.undeletable_sources(LocalFS(), [str(tmp_path / "d")])
    assert problem.path == str(inner)


def test_edge_an_empty_read_only_folder_below_is_no_problem(tmp_path, monkeypatch):
    """An empty folder has nothing to let go; it is removed from its parent."""
    inner = tmp_path / "d" / "inner"
    inner.mkdir(parents=True)
    _deny_write(monkeypatch, inner)
    assert MP.undeletable_sources(LocalFS(), [str(tmp_path / "d")]) == []


def test_edge_a_remote_backend_is_not_checked(tmp_path, monkeypatch):
    class Remote(LocalFS):
        pass

    _deny_write(monkeypatch, tmp_path)
    (tmp_path / "a.txt").write_text("a")
    assert MP.undeletable_sources(Remote(), [str(tmp_path / "a.txt")]) == []


def test_edge_the_report_is_capped(tmp_path, monkeypatch):
    names = []
    for i in range(10):
        (tmp_path / f"f{i}").write_text("x")
        names.append(str(tmp_path / f"f{i}"))
    _deny_write(monkeypatch, tmp_path)
    assert len(MP.undeletable_sources(LocalFS(), names, limit=3)) == 3


# -- the move as root --------------------------------------------------------------------------


def test_happy_elevated_move_is_one_pkexec_mv_without_clobbering(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(EIO, "_resolve_helpers",
                        lambda: EIO._Pkexec(binary="/usr/bin/pkexec", helpers={}))
    monkeypatch.setattr(EIO, "_trusted_which", lambda name: f"/usr/bin/{name}")

    def run(argv, **kw):
        calls.append((argv, kw))
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    monkeypatch.setattr(EIO.subprocess, "run", run)
    EIO.elevated_move(LocalFS(), ["/srv/a", "/srv/b c"], "/home/u/dst")
    ((argv, kw),) = calls
    assert argv == ["/usr/bin/pkexec", "--disable-internal-agent", "/usr/bin/mv",
                    "--no-clobber", "--target-directory=/home/u/dst", "--", "/srv/a", "/srv/b c"]
    assert "shell" not in kw and kw["env"]["PATH"] == "/usr/bin:/bin"


def test_sad_elevated_move_refuses_relative_paths_and_remote_backends(monkeypatch):
    monkeypatch.setattr(EIO, "_resolve_helpers",
                        lambda: EIO._Pkexec(binary="/usr/bin/pkexec", helpers={}))
    monkeypatch.setattr(EIO, "_trusted_which", lambda name: f"/usr/bin/{name}")
    with pytest.raises(ValueError):
        EIO.elevated_move(LocalFS(), ["../etc/shadow"], "/tmp")
    with pytest.raises(ValueError):
        EIO.elevated_move(LocalFS(), ["/a/../etc/shadow"], "/tmp")

    class NotLocal:
        pass

    with pytest.raises(EIO.ElevatedNotAvailable):
        EIO.elevated_move(NotLocal(), ["/a"], "/tmp")


def test_sad_a_dismissed_password_prompt_is_a_cancel(monkeypatch):
    monkeypatch.setattr(EIO, "_resolve_helpers",
                        lambda: EIO._Pkexec(binary="/usr/bin/pkexec", helpers={}))
    monkeypatch.setattr(EIO, "_trusted_which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(EIO.subprocess, "run",
                        lambda argv, **kw: subprocess.CompletedProcess(argv, 126, b"", b""))
    with pytest.raises(EIO.ElevatedCancelled):
        EIO.elevated_move(LocalFS(), ["/a"], "/tmp")


# -- the window asks ---------------------------------------------------------------------------


@pytest.fixture
def win(tmp_path, monkeypatch):
    from ui.main_window import MainWindow

    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    window = MainWindow()
    window._reconnect_timer.stop()
    yield window
    # A test can end while its job still finishes (journal, signals): the
    # close would then ask whether to cancel it, a modal that hung the run.
    end = time.time() + 10
    while window._transfer_manager.unfinished() and time.time() < end:
        APP.processEvents()
        time.sleep(0.01)
    window._quit_with_transfers = True
    window.close()
    window.deleteLater()


def _pump(cond, timeout: float = 10.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        APP.processEvents()
        if cond():
            return True
        time.sleep(0.01)
    return cond()


def _setup(win, tmp_path, monkeypatch, choice, *, deny: bool = True):
    from PyQt6.QtCore import Qt

    src, dst = tmp_path / "src", tmp_path / "dst"
    src.mkdir()
    dst.mkdir()
    (src / "a.txt").write_text("a")
    left = win._active_pane
    left.navigate(str(src))
    win._split_pane(Qt.Orientation.Horizontal)
    right = win._active_pane
    right.navigate(str(dst))
    win._set_active_pane(left)
    win._set_target_pane(right)
    if deny:
        _deny_write(monkeypatch, src)
    asked = []

    def ask(undeletable):
        asked.append(list(undeletable))
        return choice

    monkeypatch.setattr(win, "_ask_undeletable_move", ask)
    return src, dst, left, right, asked


def test_happy_copy_only_copies_and_keeps_the_source(win, tmp_path, monkeypatch):
    src, dst, left, right, asked = _setup(win, tmp_path, monkeypatch, "copy")
    win._request_transfer(left, right, [str(src / "a.txt")], move=True)
    assert _pump(lambda: (dst / "a.txt").exists() and not win._transfer_manager.busy(left.backend))
    _pump(lambda: False, timeout=0.3)
    assert len(asked) == 1 and asked[0][0].path == str(src / "a.txt")
    assert (src / "a.txt").exists()
    assert all(not j.move for j in win._transfer_manager.all_jobs())


def test_sad_cancel_queues_nothing(win, tmp_path, monkeypatch):
    src, dst, left, right, asked = _setup(win, tmp_path, monkeypatch, "cancel")
    win._request_transfer(left, right, [str(src / "a.txt")], move=True)
    assert _pump(lambda: asked and not win._conflict_checks)
    _pump(lambda: False, timeout=0.3)
    assert win._transfer_manager.all_jobs() == []
    assert not (dst / "a.txt").exists()


def test_happy_elevated_moves_through_pkexec_once(win, tmp_path, monkeypatch):
    src, dst, left, right, asked = _setup(win, tmp_path, monkeypatch, "elevated")
    moved = []

    def elevated_move(backend, sources, dest_dir):
        moved.append((list(sources), dest_dir))
        for s in sources:
            os.rename(s, os.path.join(dest_dir, os.path.basename(s)))

    monkeypatch.setattr(EIO, "elevated_move", elevated_move)
    win._request_transfer(left, right, [str(src / "a.txt")], move=True)
    assert _pump(lambda: moved and not win._conflict_checks)
    assert moved == [([str(src / "a.txt")], str(dst))]
    assert (dst / "a.txt").exists() and not (src / "a.txt").exists()
    assert win._transfer_manager.all_jobs() == []


def test_edge_a_removable_move_is_not_asked_about(win, tmp_path, monkeypatch):
    src, dst, left, right, asked = _setup(win, tmp_path, monkeypatch, "cancel", deny=False)
    win._request_transfer(left, right, [str(src / "a.txt")], move=True)
    assert _pump(lambda: (dst / "a.txt").exists() and not (src / "a.txt").exists())
    assert asked == []


# -- a source that is not there any more (review round 6, N3) ----------------------------------
# A cut file removed or renamed before the paste was reported as "cannot be
# removed after the copy - you lack the permission: No such file or
# directory" with "Move as Administrator" offered. It is left out now, said
# so, and a Cut whose entries have all gone is dropped.


def test_sad_a_vanished_source_is_no_permission_problem(tmp_path):
    (tmp_path / "here.txt").write_text("x")
    missing: list = []
    found = MP.undeletable_sources(
        LocalFS(), [str(tmp_path / "gone.txt"), str(tmp_path / "here.txt")], missing=missing)
    assert found == []
    assert missing == [str(tmp_path / "gone.txt")]


def test_edge_a_vanished_cut_is_dropped_and_not_offered_as_administrator(
        win, tmp_path, monkeypatch):
    from ui.cut_clipboard import cut_clipboard
    from ui import main_window as MW

    src, dst, left, right, asked = _setup(win, tmp_path, monkeypatch, "cancel", deny=False)
    board = cut_clipboard()
    board.cut(left, left.backend, str(src), [str(src / "a.txt")])
    (src / "a.txt").unlink()
    told = []
    monkeypatch.setattr(MW.QMessageBox, "information", lambda *a, **k: told.append(a[2]))
    win._paste_cut_into(right)
    assert _pump(lambda: told and not win._conflict_checks)
    assert asked == []
    assert "no longer there" in told[0]
    assert board.pending is None
    assert win._transfer_manager.all_jobs() == []


def test_happy_the_entries_still_there_move_and_the_vanished_one_is_named(
        win, tmp_path, monkeypatch):
    src, dst, left, right, asked = _setup(win, tmp_path, monkeypatch, "cancel", deny=False)
    (src / "b.txt").write_text("b")
    shown: list = []
    win.statusBar().messageChanged.connect(shown.append)
    win._request_transfer(left, right, [str(src / "a.txt"), str(src / "b.txt")], move=True)
    (src / "b.txt").unlink()
    assert _pump(lambda: (dst / "a.txt").exists() and not (src / "a.txt").exists())
    assert asked == []
    assert any("1 item is no longer there" in m and "b.txt" in m for m in shown), shown
