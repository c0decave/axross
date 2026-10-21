"""Maximize works where the window manager ignores it.

Reported on a Wayland tiling setup (sway): neither the maximize button nor
Ctrl+M did anything. Measured in a headless sway 1.7: ``showMaximized()``
on a floating dialog is ignored (isMaximized stays False, the size does
not change), while ``setGeometry(availableGeometry)`` fills the screen and
a later ``setGeometry`` brings the old size back. When the window manager
leaves a maximize request unanswered, axross fills the screen itself and
"restore" puts the old geometry back. A window manager that maximizes
keeps doing it.
"""

from __future__ import annotations

import os
import time

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets")
from PyQt6.QtCore import QRect  # noqa: E402
from PyQt6.QtWidgets import QApplication, QDialog, QLabel, QToolButton, QVBoxLayout  # noqa: E402

from ui import viewer_window as VW  # noqa: E402


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


def _pump(app, seconds=0.0):
    end = time.monotonic() + seconds
    while True:
        app.processEvents()
        if time.monotonic() >= end:
            break
        time.sleep(0.01)


def _ignoring_dialog(monkeypatch):
    """A dialog whose window manager ignores maximize requests."""
    dlg = QDialog()
    QVBoxLayout(dlg).addWidget(QLabel("content"))
    monkeypatch.setattr(dlg, "showMaximized", lambda: None)
    dlg.setGeometry(QRect(100, 100, 500, 300))
    dlg.show()
    return dlg


def _avail(dlg):
    return dlg.screen().availableGeometry()


def _fills(dlg) -> bool:
    return VW._fills(dlg, _avail(dlg))


def _near(a: QRect, b: QRect) -> bool:
    return all(
        abs(x - y) <= VW.FILL_TOLERANCE_PX
        for x, y in (
            (a.x(), b.x()),
            (a.y(), b.y()),
            (a.width(), b.width()),
            (a.height(), b.height()),
        )
    )


def test_happy_an_ignored_maximize_fills_the_screen(app, monkeypatch):
    dlg = _ignoring_dialog(monkeypatch)
    _pump(app)
    VW.toggle_maximized(dlg)
    _pump(app, VW.WM_GRACE_MS / 1000 + 0.3)
    assert _fills(dlg)
    assert VW.is_maximized(dlg)
    dlg.close()


def test_happy_restore_puts_the_old_geometry_back(app, monkeypatch):
    dlg = _ignoring_dialog(monkeypatch)
    _pump(app)
    VW.toggle_maximized(dlg)
    _pump(app, VW.WM_GRACE_MS / 1000 + 0.3)
    VW.toggle_maximized(dlg)
    _pump(app, 0.1)
    assert _near(dlg.geometry(), QRect(100, 100, 500, 300))
    assert not VW.is_maximized(dlg)
    dlg.close()


def test_happy_the_corner_button_follows_the_emulated_state(app, monkeypatch):
    from ui.close_corner import add_close_corner

    dlg = _ignoring_dialog(monkeypatch)
    add_close_corner(dlg)
    _pump(app)
    btn = dlg.findChild(QToolButton, "axMaximizeCorner")
    btn.click()
    _pump(app, VW.WM_GRACE_MS / 1000 + 0.3)
    assert btn.toolTip().startswith("Restore")
    btn.click()
    _pump(app, 0.1)
    assert btn.toolTip().startswith("Maximize")
    dlg.close()


def test_sad_a_window_manager_that_maximizes_is_left_alone(app):
    dlg = QDialog()
    QVBoxLayout(dlg).addWidget(QLabel("content"))
    dlg.setGeometry(QRect(100, 100, 500, 300))
    dlg.show()
    _pump(app)
    VW.toggle_maximized(dlg)
    _pump(app, VW.WM_GRACE_MS / 1000 + 0.3)
    assert dlg.isMaximized()
    assert dlg.property(VW.EMULATED_MAXIMIZE) in (None, QRect())
    VW.toggle_maximized(dlg)
    _pump(app, 0.1)
    assert not dlg.isMaximized()
    dlg.close()


def test_edge_resizing_by_hand_ends_the_emulated_state(app, monkeypatch):
    dlg = _ignoring_dialog(monkeypatch)
    _pump(app)
    VW.toggle_maximized(dlg)
    _pump(app, VW.WM_GRACE_MS / 1000 + 0.3)
    dlg.setGeometry(QRect(50, 50, 700, 400))  # the user dragged the window smaller
    _pump(app, 0.05)
    assert not VW.is_maximized(dlg)
    VW.toggle_maximized(dlg)  # maximizes again, no stale restore
    _pump(app, VW.WM_GRACE_MS / 1000 + 0.3)
    assert _fills(dlg)
    dlg.close()


def test_edge_a_window_closed_before_the_check_is_no_error(app, monkeypatch):
    dlg = _ignoring_dialog(monkeypatch)
    _pump(app)
    VW.toggle_maximized(dlg)
    dlg.close()
    dlg.deleteLater()
    _pump(app, VW.WM_GRACE_MS / 1000 + 0.3)


def test_edge_saving_an_emulated_maximized_window_keeps_its_normal_geometry(
    app, monkeypatch, tmp_path
):
    from core import i18n

    monkeypatch.setattr(i18n, "SETTINGS_FILE", tmp_path / "session.json")
    dlg = _ignoring_dialog(monkeypatch)
    _pump(app)
    VW.toggle_maximized(dlg)
    _pump(app, VW.WM_GRACE_MS / 1000 + 0.3)
    VW.save_window_state(dlg, "image")
    state = VW.load_state("image")
    assert state["maximized"] is True
    assert (state["x"], state["y"], state["width"], state["height"]) == (100, 100, 500, 300)
    dlg.close()


def test_happy_a_viewer_reopened_maximized_fills_the_screen(app, monkeypatch, tmp_path):
    from core import i18n

    monkeypatch.setattr(i18n, "SETTINGS_FILE", tmp_path / "session.json")
    first = _ignoring_dialog(monkeypatch)
    _pump(app)
    VW.toggle_maximized(first)
    _pump(app, VW.WM_GRACE_MS / 1000 + 0.3)
    VW.save_window_state(first, "media")
    first.close()

    again = QDialog()
    QVBoxLayout(again).addWidget(QLabel("content"))
    monkeypatch.setattr(again, "setWindowState", lambda _state: None)  # ignored
    monkeypatch.setattr(again, "showMaximized", lambda: None)
    VW.restore_window_state(again, "media")
    again.show()
    _pump(app, VW.WM_GRACE_MS / 1000 + 0.3)
    assert _fills(again)
    VW.toggle_maximized(again)
    _pump(app, 0.1)
    assert _near(again.geometry(), QRect(100, 100, 500, 300))
    again.close()
