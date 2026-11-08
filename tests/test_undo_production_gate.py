"""Undo waits for the production countdown like the operation it reverses.

Found in review 1 (UI): every move now asks the countdown on a production
connection (F6, toolbar, drag & drop), but Edit > Undo Last Operation moved
or restored files there with no question. A move back changes both ends,
so both connections are asked.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets")

from ui import main_window as MW  # noqa: E402

PROD, OTHER = object(), object()


def _window(statuses):
    win = SimpleNamespace()
    win._undo_status = statuses.append
    win._undo_source_backend = lambda plan, by_label: by_label.get("other", (None,))[0]
    win._undo_step = mock.Mock()
    win._undo_transfer = mock.Mock()
    return win


def _plan(action="rename_back"):
    return SimpleNamespace(action=action, backend="prod", reason="move a.txt", source_backend="")


def test_sad_a_cancelled_countdown_undoes_nothing():
    statuses: list = []
    win = _window(statuses)
    with mock.patch("ui.production_gate.confirm_production", return_value=False) as gate, \
            mock.patch("core.undo.apply_undo") as apply:
        MW.MainWindow._undo_apply(win, _plan(), {"prod": (PROD, None)})
    gate.assert_called_once()
    assert gate.call_args.args[1] is PROD
    apply.assert_not_called()
    win._undo_step.assert_not_called()
    assert statuses == ["Undo cancelled"]


def test_happy_a_move_back_asks_both_connections():
    win = _window([])
    asked = []
    with mock.patch("ui.production_gate.confirm_production",
                    side_effect=lambda parent, backend, desc: asked.append(backend) or True), \
            mock.patch("core.undo.apply_undo"):
        MW.MainWindow._undo_apply(win, _plan("transfer_back"),
                                  {"prod": (PROD, None), "other": (OTHER, None)})
    assert asked == [PROD, OTHER]


def test_edge_an_allowed_undo_still_runs():
    win = _window([])
    with mock.patch("ui.production_gate.confirm_production", return_value=True):
        MW.MainWindow._undo_apply(win, _plan(), {"prod": (PROD, None)})
    win._undo_step.assert_called_once()
