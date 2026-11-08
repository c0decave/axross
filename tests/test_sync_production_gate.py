"""Compare Panes -> Sync waits for the production countdown before it
overwrites a production pane.

Review round 3: F5 with "Overwrite" onto a production pane showed the
countdown ("overwrite 1 item(s)"), and Cancel there kept the file; Compare
Panes -> Sync with "Left side wins" onto the same pane replaced it with no
countdown at all. ``_apply_sync`` -> ``_queue_sync`` ->
``_transfer_compared`` never called the production gate.

Now every write path goes through one gate (``_production_gate_ok``, also
behind ``_target_production_ok``): a sync asks it for each side its plan
overwrites, before a folder is made or a copy queued, and a Cancel there
changes neither side.
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
from ui import production_gate as PG  # noqa: E402

APP = QApplication.instance() or QApplication([])


@pytest.fixture(autouse=True)
def _fresh_tarpit(monkeypatch):
    monkeypatch.delenv(safety_tarpit.ENV_DISABLE, raising=False)
    safety_tarpit.reset_all()
    yield
    safety_tarpit.reset_all()


def _make_production(fs) -> None:
    fs._axross_profile = ConnectionProfile(
        name="prod-box", protocol="sftp", host="prod.example", production=True
    )
    fs._axross_profile_key = f"key-{id(fs)}"


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

    home = tmp_path / "home"
    home.mkdir()
    with mock.patch("pathlib.Path.home", return_value=home):
        window = MW.MainWindow()
    window._quit_with_transfers = True
    left_dir, right_dir = tmp_path / "left", tmp_path / "right"
    left_dir.mkdir()
    right_dir.mkdir()
    window._split_pane(Qt.Orientation.Horizontal)
    left, right = window._panes[0], window._panes[1]
    left.navigate(str(left_dir))
    right.navigate(str(right_dir))
    queued: list = []
    monkeypatch.setattr(window, "_transfer_compared",
                        lambda source, target, pairs, **kw: queued.append((target, pairs, kw)))
    window.test_ctx = {"left": left, "right": right, "queued": queued,
                       "l": str(left_dir), "r": str(right_dir)}
    yield window
    window.close()
    window.deleteLater()
    APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)


def _copy(ctx, name, direction="to_right", overwrites=True):
    src, dst = (ctx["l"], ctx["r"]) if direction == "to_right" else (ctx["r"], ctx["l"])
    return {"rel_path": name, "kind": "copy", "direction": direction,
            "overwrites": overwrites, "newer_only": False,
            "source": f"{src}/{name}", "dest": f"{dst}/{name}"}


def test_sad_a_cancelled_countdown_stops_a_sync_that_overwrites_production(win, monkeypatch):
    ctx = win.test_ctx
    _make_production(ctx["right"].backend)
    shown = _countdown(monkeypatch, QDialog.DialogCode.Rejected)
    win._apply_sync(ctx["left"], ctx["right"],
                    [_copy(ctx, "cfg.txt"), _copy(ctx, "new.txt", overwrites=False)])
    assert shown == ["overwrite 1 item(s)"]
    assert ctx["queued"] == []  # not even the new file: nothing changes
    assert "Sync cancelled" in win.statusBar().currentMessage()


def test_happy_an_accepted_countdown_queues_the_sync(win, monkeypatch):
    ctx = win.test_ctx
    _make_production(ctx["right"].backend)
    shown = _countdown(monkeypatch, QDialog.DialogCode.Accepted)
    win._apply_sync(ctx["left"], ctx["right"], [_copy(ctx, "a.txt"), _copy(ctx, "b.txt")])
    assert shown == ["overwrite 2 item(s)"]
    assert [(t, len(p)) for t, p, _kw in ctx["queued"]] == [(ctx["right"], 2)]


def test_edge_only_the_side_the_plan_overwrites_is_asked(win, monkeypatch):
    """Production on the left: a plan that only adds files there asks
    nothing; one that overwrites there asks the left side's countdown."""
    ctx = win.test_ctx
    _make_production(ctx["left"].backend)
    shown = _countdown(monkeypatch, QDialog.DialogCode.Rejected)
    win._apply_sync(ctx["left"], ctx["right"],
                    [_copy(ctx, "a.txt"), _copy(ctx, "n.txt", "to_left", overwrites=False)])
    assert shown == []
    assert len(ctx["queued"]) == 2
    ctx["queued"].clear()
    win._apply_sync(ctx["left"], ctx["right"], [_copy(ctx, "o.txt", "to_left")])
    assert shown == ["overwrite 1 item(s)"]
    assert ctx["queued"] == []
