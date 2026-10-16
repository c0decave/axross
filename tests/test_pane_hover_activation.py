"""A file pane becomes the active pane once the mouse rests in it.

View > Activate Pane: "On Click", or after 1, 2 or 3 seconds of hovering
(the default is 1 s). Stored as ``pane_activation`` in settings.json. The
hover activation never takes the keyboard away from a text field: it moves
keyboard focus only when that sat in another pane's file list.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core import open_limits as OL  # noqa: E402
from core import pane_activation as PA  # noqa: E402


@pytest.fixture(autouse=True)
def settings(tmp_path, monkeypatch):
    monkeypatch.setattr(OL, "SETTINGS_PATH", tmp_path / "settings.json")
    return tmp_path / "settings.json"


# --- the setting ----------------------------------------------------------


def test_happy_the_default_is_one_second_of_hovering():
    assert PA.activation_delay_ms() == 1000


def test_happy_each_choice_round_trips():
    for value, delay in ((1, 1000), (2, 2000), (3, 3000), (PA.CLICK, None)):
        PA.set_activation(value)
        assert PA.activation() == value
        assert PA.activation_delay_ms() == delay


def test_sad_a_hand_edited_value_falls_back_to_the_default(settings):
    for bad in (7, 0, -1, "x", True, 1.5, None, [1]):
        OL.write_setting(PA.SETTING, bad)
        assert PA.activation_delay_ms() == 1000, bad


def test_sad_an_invalid_choice_is_refused():
    for bad in (0, 4, "hover", True, 2.0):
        with pytest.raises(ValueError):
            PA.set_activation(bad)


# --- the pane -------------------------------------------------------------


@pytest.fixture
def app():
    from PyQt6.QtWidgets import QApplication

    return QApplication.instance() or QApplication([])


def _pump(app, seconds: float) -> None:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        app.processEvents()
        time.sleep(0.01)


def _pane(app):
    from core.local_fs import LocalFS
    from ui.file_pane import FilePaneWidget

    pane = FilePaneWidget(LocalFS())
    pane.resize(400, 300)
    pane.show()
    app.processEvents()
    hits = []
    pane.pane_focused.connect(lambda: hits.append(1))
    return pane, hits


def _enter(app, pane) -> None:
    from PyQt6.QtCore import QPointF
    from PyQt6.QtGui import QEnterEvent

    p = QPointF(10, 10)
    app.sendEvent(pane, QEnterEvent(p, p, p))


def _leave(app, pane) -> None:
    from PyQt6.QtCore import QEvent

    app.sendEvent(pane, QEvent(QEvent.Type.Leave))


def test_happy_resting_in_a_pane_activates_it(app, monkeypatch):
    monkeypatch.setattr(PA, "activation_delay_ms", lambda: 60)
    pane, hits = _pane(app)
    _enter(app, pane)
    _pump(app, 0.3)
    assert hits == [1]
    pane.deleteLater()


def test_sad_leaving_before_the_delay_does_not_activate(app, monkeypatch):
    monkeypatch.setattr(PA, "activation_delay_ms", lambda: 150)
    pane, hits = _pane(app)
    _enter(app, pane)
    _pump(app, 0.05)
    _leave(app, pane)
    _pump(app, 0.3)
    assert hits == []
    pane.deleteLater()


def test_edge_on_click_mode_hovering_does_nothing(app, monkeypatch):
    monkeypatch.setattr(PA, "activation_delay_ms", lambda: None)
    pane, hits = _pane(app)
    _enter(app, pane)
    _pump(app, 0.2)
    assert hits == []
    pane.deleteLater()


def test_edge_keyboard_focus_moves_from_another_list_not_from_a_text_field(app, monkeypatch):
    from PyQt6.QtWidgets import QHBoxLayout, QLineEdit, QWidget

    from core.local_fs import LocalFS
    from ui.file_pane import FilePaneWidget

    monkeypatch.setattr(PA, "activation_delay_ms", lambda: 40)
    host = QWidget()
    row = QHBoxLayout(host)
    a, b, field = FilePaneWidget(LocalFS()), FilePaneWidget(LocalFS()), QLineEdit()
    for w in (a, b, field):
        row.addWidget(w)
    host.resize(1200, 400)
    host.show()
    host.activateWindow()
    app.processEvents()

    a._table.setFocus()
    app.processEvents()
    _enter(app, b)
    _pump(app, 0.2)
    if app.focusWidget() is not None:  # offscreen may report no focus at all
        assert app.focusWidget() is b._table

    field.setFocus()
    app.processEvents()
    _enter(app, a)
    _pump(app, 0.2)
    if app.focusWidget() is not None:
        assert app.focusWidget() is field
    host.deleteLater()


# --- the menu -------------------------------------------------------------


def test_happy_the_view_menu_offers_click_and_one_to_three_seconds(app):
    from PyQt6.QtWidgets import QMenu

    from ui.main_window import MainWindow

    class Window:
        _build_pane_activation_menu = MainWindow._build_pane_activation_menu
        _set_pane_activation = MainWindow._set_pane_activation

    window, menu = Window(), QMenu()
    window._build_pane_activation_menu(menu)
    actions = window._pane_activation_actions
    assert list(actions) == [PA.CLICK, 1, 2, 3]
    assert actions[1].isChecked() and not actions[2].isChecked()  # the default
    actions[2].trigger()
    assert PA.activation() == 2
    assert actions[2].isChecked() and not actions[1].isChecked()
    actions[PA.CLICK].trigger()
    assert PA.activation_delay_ms() is None
