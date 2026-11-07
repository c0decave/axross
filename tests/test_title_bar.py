"""axross's own title bars (ui.title_bar, ui.close_corner).

Feedback 2026-11-06: under a window manager that draws title bars, the
row with the name and ``_ [] x`` sat below its title bar as a second one;
on some windows the buttons overlapped the content (laid over a grid's
corner); some windows - the Arcade among them - had no buttons at all and
could not be closed. Now the row is the window's only title bar (the
window frameless), every window has it, and a setting gives the window
manager's title bar back.
"""

from __future__ import annotations

import ast
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets")

from PyQt6.QtCore import QPoint, QPointF, QRect, QSize, Qt  # noqa: E402
from PyQt6.QtGui import QMouseEvent  # noqa: E402
from PyQt6.QtWidgets import (  # noqa: E402
    QApplication,
    QDialog,
    QGridLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from ui import title_bar as TB  # noqa: E402
from ui import viewer_window as VW  # noqa: E402
from ui import window_prefs  # noqa: E402
from ui.close_corner import add_close_corner, add_title_bar  # noqa: E402

FRAMELESS = Qt.WindowType.FramelessWindowHint
CORNER = ("axDockCorner", "axMaximizeCorner", "axCloseCorner")


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


@pytest.fixture(autouse=True)
def own_mode():
    TB.set_own_title_bars(True)
    yield
    TB.set_own_title_bars(True)


def _buttons(window):
    return [window.findChild(QToolButton, name) for name in CORNER]


def _shown(app, window, w=520, h=320):
    window.resize(w, h)
    window.show()
    for _ in range(3):
        app.processEvents()
    return window


def _rect(widget, window) -> QRect:
    return QRect(widget.mapTo(window, QPoint(0, 0)), widget.size())


def test_happy_the_row_is_the_title_bar_and_the_window_frameless(app):
    dialog = QDialog()
    dialog.setWindowTitle("Mail Project")
    QVBoxLayout(dialog).addWidget(QLabel("content"))
    add_close_corner(dialog)
    _shown(app, dialog)
    assert dialog.windowFlags() & FRAMELESS
    row = dialog.findChild(QWidget, "axTitleRow")
    assert row is not None and row.isVisible()
    assert dialog.findChild(QLabel, "axCornerTitle").text() == "Mail Project"
    assert dialog.findChild(QLabel, "axTitleIcon") is not None
    for button in _buttons(dialog):
        assert button.parent() is row and button.isVisible()
    # The first row, at the top, nothing above it.
    assert _rect(row, dialog).top() <= TB.BORDER + 12
    dialog.deleteLater()


def test_happy_a_grid_dialog_gets_the_row_above_its_content_not_over_it(app):
    dialog = QDialog()
    grid = QGridLayout(dialog)
    corner_label = QLabel("top right")
    grid.addWidget(corner_label, 0, 1)
    grid.addWidget(QLineEdit(), 1, 0, 1, 2)
    add_close_corner(dialog)
    _shown(app, dialog)
    buttons = QRect()
    for button in _buttons(dialog):
        buttons = buttons.united(_rect(button, dialog))
    assert not buttons.intersects(_rect(corner_label, dialog))
    assert buttons.bottom() < _rect(corner_label, dialog).top()
    assert dialog.findChild(QWidget, "axWindowBody").layout() is grid
    dialog.deleteLater()


def test_happy_a_plain_window_without_reject_closes_by_its_x(app):
    window = QWidget(None, Qt.WindowType.Window)
    QVBoxLayout(window).addWidget(QLabel("game"))
    btn = add_close_corner(window)
    _shown(app, window)
    btn.click()
    app.processEvents()
    assert not window.isVisible()
    window.deleteLater()


def test_happy_the_setting_gives_the_window_managers_title_bar_back_and_again(app):
    dialog = QDialog()
    QVBoxLayout(dialog).addWidget(QLabel("content"))
    add_close_corner(dialog)
    _shown(app, dialog)
    assert TB.set_own_title_bars(False) >= 1
    app.processEvents()
    assert not dialog.windowFlags() & FRAMELESS
    assert dialog.isVisible()  # a flag change hides a window: shown again
    assert not dialog.findChild(QWidget, "axTitleRow").isVisible()
    assert not any(g.isVisible() for g in dialog.findChildren(QWidget, "axResizeGrip"))
    TB.set_own_title_bars(True)
    app.processEvents()
    assert dialog.windowFlags() & FRAMELESS and dialog.isVisible()
    assert dialog.findChild(QWidget, "axTitleRow").isVisible()
    dialog.deleteLater()


def test_happy_a_window_opened_in_the_window_manager_mode_has_its_frame(app):
    TB.set_own_title_bars(False)
    dialog = QDialog()
    QVBoxLayout(dialog).addWidget(QLabel("content"))
    add_close_corner(dialog)
    _shown(app, dialog)
    assert not dialog.windowFlags() & FRAMELESS
    assert not dialog.findChild(QWidget, "axTitleRow").isVisible()
    dialog.deleteLater()


def test_happy_a_double_click_on_the_title_maximizes_and_restores(app):
    dialog = QDialog()
    QVBoxLayout(dialog).addWidget(QLabel("content"))
    add_close_corner(dialog)
    _shown(app, dialog)
    title = dialog.findChild(QLabel, "axCornerTitle")
    pos = QPointF(title.mapTo(dialog, QPoint(2, 2)))

    def double_click():
        event = QMouseEvent(QMouseEvent.Type.MouseButtonDblClick, pos, dialog.mapToGlobal(pos),
                            Qt.MouseButton.LeftButton, Qt.MouseButton.LeftButton,
                            Qt.KeyboardModifier.NoModifier)
        QApplication.sendEvent(dialog, event)
        app.processEvents()

    double_click()
    assert VW.is_maximized(dialog)
    double_click()
    assert not VW.is_maximized(dialog)
    dialog.deleteLater()


def test_happy_the_grips_sit_on_the_edges_and_resize_by_hand(app):
    dialog = QDialog()
    QVBoxLayout(dialog).addWidget(QLabel("content"))
    add_close_corner(dialog)
    _shown(app, dialog, 400, 300)
    grips = dialog.findChildren(QWidget, "axResizeGrip")
    assert len(grips) == 8 and all(g.isVisible() for g in grips)
    right = next(g for g in grips if g.edges == Qt.Edge.RightEdge)
    assert _rect(right, dialog).right() == dialog.width() - 1
    origin = QRect(100, 100, 400, 300)
    grown = TB.resized(origin, Qt.Edge.RightEdge | Qt.Edge.BottomEdge, QPoint(50, 20), QSize(0, 0))
    assert grown == QRect(100, 100, 450, 320)
    shrunk = TB.resized(origin, Qt.Edge.LeftEdge, QPoint(390, 0), QSize(200, 100))
    assert shrunk.width() == 200 and shrunk.right() == origin.right()
    dialog.deleteLater()


def test_edge_full_screen_shows_no_title_row(app):
    window = QWidget(None, Qt.WindowType.Window)
    QVBoxLayout(window).addWidget(QLabel("visualizer"))
    add_close_corner(window)
    _shown(app, window)
    window.showFullScreen()
    app.processEvents()
    assert not window.findChild(QWidget, "axTitleRow").isVisible()
    window.showNormal()
    app.processEvents()
    assert window.findChild(QWidget, "axTitleRow").isVisible()
    window.deleteLater()


def test_happy_a_main_window_with_menus_carries_the_title_in_its_menu_bar(app):
    window = QMainWindow()
    window.setWindowTitle("Editor")
    window.menuBar().addMenu("File")
    window.setCentralWidget(QLabel("text"))
    add_title_bar(window)
    _shown(app, window)
    assert window.windowFlags() & FRAMELESS
    corner = window.menuBar().cornerWidget(Qt.Corner.TopRightCorner)
    for button in _buttons(window):
        assert corner.isAncestorOf(button) and button.isVisible()
    assert corner.findChild(QLabel, "axCornerTitle").text() == "Editor"
    TB.set_own_title_bars(False)
    app.processEvents()
    assert not corner.isVisible() and window.menuBar().isVisible()
    window.deleteLater()


def test_happy_a_main_window_without_menus_gets_a_title_row(app):
    window = QMainWindow()
    window.setWindowTitle("Workspace 2")
    window.setCentralWidget(QLabel("panes"))
    btn = add_title_bar(window)
    _shown(app, window)
    bar = window.menuBar()
    assert bar.isVisible()
    assert bar.cornerWidget(Qt.Corner.TopLeftCorner).findChild(QLabel, "axCornerTitle").text() \
        == "Workspace 2"
    TB.set_own_title_bars(False)
    app.processEvents()
    assert not bar.isVisible()  # nothing in it but the title row
    TB.set_own_title_bars(True)
    btn.click()
    app.processEvents()
    assert not window.isVisible()
    window.deleteLater()


def test_sad_installing_twice_keeps_one_title_bar(app):
    dialog = QDialog()
    QVBoxLayout(dialog).addWidget(QLabel("content"))
    first = add_close_corner(dialog)
    assert add_close_corner(dialog) is first
    assert len(dialog.findChildren(TB.TitleBar)) == 1
    assert len(dialog.findChildren(QWidget, "axTitleRow")) == 1
    dialog.deleteLater()


def test_happy_the_preference_is_on_unless_stored_off():
    assert window_prefs.parse({}).own_title_bars is True
    assert window_prefs.parse({"own_title_bars": "no"}).own_title_bars is True
    assert window_prefs.parse({"own_title_bars": False}).own_title_bars is False


def test_happy_the_arcade_can_be_closed(app, tmp_path):
    from ui.arcade_window import ArcadeWindow

    class Silent:
        def __getattr__(self, _name):
            return lambda *a, **k: None

    window = ArcadeWindow(scores=tmp_path / "s.json", progress=tmp_path / "p.json", audio=Silent())
    _shown(app, window)
    close = window.findChild(QToolButton, "axCloseCorner")
    assert close is not None and close.isVisible()
    close.click()
    app.processEvents()
    assert not window.isVisible()
    window.deleteLater()


# --- every window has it -------------------------------------------------------

#: Windows that have no title row on purpose (file::class -> why).
NO_TITLE_ROW = {
    "ui/main_window.py::MainWindow": "the application window keeps the window manager's frame",
}
TITLE_CALLS = {"add_close_corner", "add_title_bar", "_add_corner"}


def test_sad_no_window_class_is_left_without_its_title_row():
    from test_window_icons import _calls, _name, _trees, _window_classes

    classes = _window_classes(_trees())
    by_name = {cls.name: cls for _rel, cls in classes}

    def has_row(cls, seen=()):
        if {_name(c.func) for c in _calls(cls)} & TITLE_CALLS:
            return True
        return any(_name(b) in by_name and _name(b) not in seen
                   and has_row(by_name[_name(b)], seen + (_name(b),)) for b in cls.bases)

    missing = []
    for rel, cls in classes:
        key = f"{rel}::{cls.name}"
        bases = {_name(b) for b in cls.bases}
        if key in NO_TITLE_ROW or bases & {"QDockWidget", "ExtensionDock"}:
            continue  # a panel has its own title bar (ui.dock_titlebar)
        if not has_row(cls):
            missing.append(key)
    assert missing == [], "give these ui.close_corner.add_close_corner(self) / add_title_bar(self)"


def test_happy_the_meta_test_sees_the_windows_it_must():
    tree = ast.parse((Path(__file__).resolve().parent.parent / "ui" / "arcade_window.py")
                     .read_text(encoding="utf-8"))
    names = {n.name for n in ast.walk(tree) if isinstance(n, ast.ClassDef)}
    assert "ArcadeWindow" in names


def test_sad_switching_from_a_modal_dialog_does_not_close_it(app):
    """Settings is modal: a new window flag hides a window, and a hidden
    modal dialog ends its exec() - switching the title bars there closed
    and deleted Settings. It takes the switch when it closes."""
    from PyQt6.QtCore import QTimer

    dialog = QDialog()
    QVBoxLayout(dialog).addWidget(QLabel("Settings"))
    add_close_corner(dialog)
    seen = {}

    def switch():
        TB.set_own_title_bars(False)
        app.processEvents()
        seen["visible"] = dialog.isVisible()
        seen["frameless"] = bool(dialog.windowFlags() & FRAMELESS)
        dialog.accept()

    QTimer.singleShot(50, switch)
    assert dialog.exec() == QDialog.DialogCode.Accepted
    assert seen == {"visible": True, "frameless": True}   # untouched while open
    assert not dialog.windowFlags() & FRAMELESS             # switched once closed
    dialog.deleteLater()
