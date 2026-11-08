"""An overwrite on, or a move into, a production pane asks the countdown.

Before: ``MainWindow._request_transfer`` asked the production gate only for
the *source* of a move. A copy (or move) that overwrote files in a pane
whose profile is flagged production went straight through, though the
profile, the tour ("the first delete, move or overwrite then waits with a
countdown") and the handbook promise the countdown for it.

Now the target pane is asked once per operation, after the conflict
answers are known: when the answered plan replaces a name there, or when
the operation moves into it. A copy whose plan replaces nothing asks
nothing.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QEvent, Qt  # noqa: E402
from PyQt6.QtWidgets import QApplication, QDialog  # noqa: E402

from core import safety_tarpit  # noqa: E402
from core.profiles import ConnectionProfile  # noqa: E402
from core.transfer_conflicts import ConflictAction  # noqa: E402
from ui import production_gate as PG  # noqa: E402

APP = QApplication.instance() or QApplication([])


@pytest.fixture(autouse=True)
def _fresh_tarpit(monkeypatch):
    monkeypatch.delenv(safety_tarpit.ENV_DISABLE, raising=False)
    safety_tarpit.reset_all()
    yield
    safety_tarpit.reset_all()


def _countdown(monkeypatch, answer: int) -> list[str]:
    shown: list[str] = []
    real_init = PG.ProductionCountdownDialog.__init__

    def init(self, label, op_desc, seconds, parent=None):
        real_init(self, label, op_desc, seconds, parent)
        shown.append(op_desc)

    monkeypatch.setattr(PG.ProductionCountdownDialog, "__init__", init)
    monkeypatch.setattr(PG.ProductionCountdownDialog, "exec", lambda self: answer)
    return shown


@pytest.fixture
def win(tmp_path, monkeypatch):
    from ui import main_window as MW
    from ui import scan_job

    home = tmp_path / "home"
    home.mkdir()
    with mock.patch("pathlib.Path.home", return_value=home):
        window = MW.MainWindow()
    window._quit_with_transfers = True
    src, dst = tmp_path / "src", tmp_path / "dst"
    src.mkdir()
    dst.mkdir()
    (src / "a.txt").write_text("NEW")
    (src / "fresh.txt").write_text("NEW")
    (dst / "a.txt").write_text("PRODUCTION DATA")
    window._split_pane(Qt.Orientation.Horizontal)
    a, b = window._panes[0], window._panes[1]
    a.navigate(str(src))
    b.navigate(str(dst))
    assert a.backend is not b.backend
    b.backend._axross_profile = ConnectionProfile(
        name="prod-box", protocol="sftp", host="prod.example", production=True)
    b.backend._axross_profile_key = f"key-{id(b.backend)}"
    a.backend._axross_profile = None

    # The destination check runs at once (no thread); the queueing is
    # recorded, not run.
    def start(self, work, **_kw):
        self.finished.emit("done", work(lambda: False, lambda *_a: None), False)
        return True

    monkeypatch.setattr(scan_job.ScanJob, "start", start)
    queued: list = []
    monkeypatch.setattr(window, "_start_transfer_between",
                        lambda *a, **k: queued.append((a, k)))
    window.test_ctx = {"a": a, "b": b, "src": src, "dst": dst, "queued": queued}
    yield window
    window.close()
    window.deleteLater()
    APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)


def _answer(window, action):
    window._ask_transfer_conflict = lambda conflict, remaining: (action, False)


def test_sad_overwriting_a_production_target_asks_and_a_cancel_queues_nothing(
        win, monkeypatch):
    ctx = win.test_ctx
    shown = _countdown(monkeypatch, QDialog.DialogCode.Rejected)
    _answer(win, ConflictAction.OVERWRITE)
    win._request_transfer(ctx["a"], ctx["b"], [str(ctx["src"] / "a.txt")], move=False)
    assert shown == ["overwrite 1 item(s)"]
    assert ctx["queued"] == []
    assert (ctx["dst"] / "a.txt").read_text() == "PRODUCTION DATA"


def test_happy_an_accepted_countdown_queues_the_overwrite_once(win, monkeypatch):
    ctx = win.test_ctx
    shown = _countdown(monkeypatch, QDialog.DialogCode.Accepted)
    _answer(win, ConflictAction.OVERWRITE)
    paths = [str(ctx["src"] / "a.txt"), str(ctx["src"] / "fresh.txt")]
    win._request_transfer(ctx["a"], ctx["b"], paths, move=False)
    assert shown == ["overwrite 1 item(s)"]  # one question for the operation
    assert len(ctx["queued"]) == 1


def test_edge_only_a_plan_that_replaces_something_asks(win, monkeypatch):
    """Skip and Rename replace nothing there: no countdown for those copies;
    the same copy answered Overwrite asks."""
    ctx = win.test_ctx
    shown = _countdown(monkeypatch, QDialog.DialogCode.Accepted)
    paths = [str(ctx["src"] / "a.txt"), str(ctx["src"] / "fresh.txt")]
    for action in (ConflictAction.SKIP, ConflictAction.RENAME):
        _answer(win, action)
        win._request_transfer(ctx["a"], ctx["b"], paths, move=False)
    assert shown == [] and len(ctx["queued"]) == 2
    newer = (ctx["dst"] / "a.txt").stat().st_mtime + 100
    os.utime(ctx["src"] / "a.txt", (newer, newer))  # "if newer" replaces it
    _answer(win, ConflictAction.OVERWRITE_IF_NEWER)
    win._request_transfer(ctx["a"], ctx["b"], paths, move=False)
    assert shown == ["overwrite 1 item(s)"] and len(ctx["queued"]) == 3


def test_sad_a_move_into_a_production_target_asks(win, monkeypatch):
    ctx = win.test_ctx
    shown = _countdown(monkeypatch, QDialog.DialogCode.Rejected)
    monkeypatch.setattr("core.move_permissions.undeletable_sources", lambda *a, **k: [])
    win._request_transfer(ctx["a"], ctx["b"], [str(ctx["src"] / "fresh.txt")], move=True)
    assert shown == ["move 1 item(s) here"]
    assert ctx["queued"] == []
