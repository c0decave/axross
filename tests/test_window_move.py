#!/usr/bin/env python3
"""Moving a detached window with a left drag on its top row.

Operator: *„kann es sein, dass man mit linker maustaste gedrückt detachted
fenster nicht bewegen kann oder liegt das an meinem WM, wenn ich den MOD
dazu drücke geht es aber einfach nur linke maustaste rücken auf der oberen
zeile tut nicht"* (spectrwm on X11; sway elsewhere).

Measured under Xvfb + spectrwm: a floating dock is a frameless Qt::Tool
window (flags 0x80b: our title bar replaces the window manager's), and Qt
moves it during a title-bar drag by ``QWidget::move()`` - a request the
window manager may refuse. spectrwm honours it for a free-floating window,
but in a workspace with the ``fullscreen`` layout (the operator's ws[2] and
ws[3]) it keeps the floating dock maximized (``windowState()`` =
WindowMaximized) and ignores the request: the drag did nothing, MOD+drag
(spectrwm's own move) worked. Wayland (sway) gives a client no say over its
window position at all. ``QWindow.startSystemMove()`` hands the move to the
window manager (``_NET_WM_MOVERESIZE`` on X11, xdg_toplevel.move on Wayland);
it moved the maximized window under spectrwm in the same setup.

Dialogs with the close corner have a top row too (the [max] [x] row):
spectrwm floats dialogs without a title bar, so that row is what a user
grabs.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QEvent, QObject, QPoint, QPointF, Qt  # noqa: E402
from PyQt6.QtGui import QGuiApplication, QMouseEvent, QWindow  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import (  # noqa: E402
    QApplication,
    QDialog,
    QDockWidget,
    QFormLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QToolButton,
    QVBoxLayout,
)

from ui import window_move as WM  # noqa: E402
from ui.close_corner import add_close_corner  # noqa: E402
from ui.dock_titlebar import DockTitleBar  # noqa: E402

APP = QApplication.instance() or QApplication([])
LEFT = Qt.MouseButton.LeftButton
NONE = Qt.MouseButton.NoButton


# -- helpers ----------------------------------------------------------------------------


class SystemMoveSpy:
    """Stands in for QWindow.startSystemMove: records the windows asked and
    answers *result* (True: the window manager took the move over)."""

    def __init__(self, result: bool) -> None:
        self.result = result
        self.windows: list[QWindow] = []

    def __call__(self, window: QWindow) -> bool:
        self.windows.append(window)
        return self.result


@pytest.fixture()
def system_move(monkeypatch):
    spy = SystemMoveSpy(True)
    monkeypatch.setattr(QWindow, "startSystemMove", lambda self: spy(self))
    return spy


def send(widget, kind: QEvent.Type, pos: QPoint, button, buttons,
         global_pos: QPoint | None = None) -> QMouseEvent:
    """A real mouse event to *widget* at *pos* (its coordinates), delivered
    through QApplication.notify, so a press the widget ignores travels up
    to its parents like a real one. *global_pos* defaults to *pos* on the
    screen now."""
    if global_pos is None:
        global_pos = widget.mapToGlobal(pos)
    event = QMouseEvent(kind, QPointF(pos), QPointF(global_pos), button, buttons,
                        Qt.KeyboardModifier.NoModifier)
    QApplication.sendEvent(widget, event)
    return event


def drag(widget, start: QPoint, delta: QPoint, steps: int = 4) -> None:
    """Press the left button on *widget* at *start*, move by *delta* in
    *steps*, release. The screen positions are those of the hand: they do
    not shift when the window moves under the pointer."""
    origin = widget.mapToGlobal(start)
    send(widget, QEvent.Type.MouseButtonPress, start, LEFT, LEFT, origin)
    for i in range(1, steps + 1):
        step = delta * i / steps
        send(widget, QEvent.Type.MouseMove, start + step, NONE, LEFT, origin + step)
    send(widget, QEvent.Type.MouseButtonRelease, start + delta, LEFT, NONE, origin + delta)


class PressRecorder(QObject):
    """Counts the mouse presses that reach the watched widget."""

    def __init__(self, widget) -> None:
        super().__init__(widget)
        self.presses = 0
        widget.installEventFilter(self)

    def eventFilter(self, watched, event) -> bool:  # noqa: N802 - Qt
        if event.type() == QEvent.Type.MouseButtonPress:
            self.presses += 1
        return False


def _dock_window():
    win = QMainWindow()
    win.resize(900, 600)
    dock = QDockWidget("Panel", win)
    dock.setObjectName("panel")
    dock.setWidget(QLabel("content", dock))
    bar = DockTitleBar("Panel", "inbox", dock)
    dock.setTitleBarWidget(bar)
    win.addDockWidget(Qt.DockWidgetArea.RightDockWidgetArea, dock)
    win.show()
    return win, dock, bar


@pytest.fixture()
def floating():
    """A floating dock with the axross title bar; the test decides whether
    the window manager keeps it maximized."""
    win, dock, bar = _dock_window()
    dock.setFloating(True)
    dock.resize(320, 220)
    dock.move(200, 150)
    dock.show()
    APP.processEvents()
    yield win, dock, bar
    win.close()
    win.deleteLater()
    APP.processEvents()


def title_point(bar: DockTitleBar) -> QPoint:
    """A point on the title text: no button there."""
    label = bar._title_label
    return label.mapTo(bar, QPoint(5, label.height() // 2))


def make_dialog(*, vbox: bool = True):
    dialog = QDialog()
    if vbox:
        layout = QVBoxLayout(dialog)
        layout.addWidget(QLabel("A dialog body"))
        layout.addWidget(QLineEdit())
    else:
        form = QFormLayout(dialog)
        form.addRow("Name", QLineEdit())
    add_close_corner(dialog)
    dialog.resize(420, 260)
    dialog.move(100, 100)
    dialog.show()
    APP.processEvents()
    return dialog


def corner_row_point(dialog) -> QPoint:
    """A point in the corner row left of the buttons, on no child widget."""
    maximize = dialog.findChild(QToolButton, "axMaximizeCorner")
    return QPoint(maximize.geometry().left() // 2, maximize.geometry().center().y())


# -- the decision: who moves the window ------------------------------------------------


def test_happy_wm_must_move_a_maximized_or_fullscreen_window():
    dialog = QDialog()
    try:
        dialog.setWindowState(Qt.WindowState.WindowMaximized)
        assert WM.wm_must_move(dialog)
        dialog.setWindowState(Qt.WindowState.WindowFullScreen)
        assert WM.wm_must_move(dialog)
        dialog.setWindowState(Qt.WindowState.WindowNoState)
        assert not WM.wm_must_move(dialog)
    finally:
        dialog.deleteLater()


def test_happy_wm_must_move_everything_on_wayland(monkeypatch):
    monkeypatch.setattr(QGuiApplication, "platformName", staticmethod(lambda: "wayland"))
    dialog = QDialog()
    try:
        assert WM.wm_must_move(dialog)
    finally:
        dialog.deleteLater()
    monkeypatch.setattr(QGuiApplication, "platformName", staticmethod(lambda: "wayland-egl"))
    assert WM.wm_must_move(QDialog())


def test_sad_start_system_move_without_a_native_window_is_refused():
    never_shown = QDialog()
    try:
        assert never_shown.windowHandle() is None
        assert WM.start_system_move(never_shown) is False
    finally:
        never_shown.deleteLater()


def test_edge_offscreen_has_no_system_move():
    """The offscreen platform cannot move windows for us: the drag falls
    back to moving the window itself (see the fallback tests)."""
    dialog = make_dialog()
    try:
        assert WM.start_system_move(dialog) is False
    finally:
        dialog.deleteLater()


# -- floating docks -------------------------------------------------------------------


def test_e2e_happy_maximized_floating_dock_moves_by_the_window_manager(floating, system_move):
    _win, dock, bar = floating
    dock.setWindowState(Qt.WindowState.WindowMaximized)
    drag(bar._title_label, QPoint(5, 5), QPoint(80, 40))
    assert system_move.windows == [dock.windowHandle()]


def test_e2e_happy_floating_dock_on_wayland_moves_by_the_window_manager(floating, system_move,
                                                                      monkeypatch):
    _win, dock, bar = floating
    monkeypatch.setattr(QGuiApplication, "platformName", staticmethod(lambda: "wayland"))
    drag(bar, title_point(bar), QPoint(60, 0))
    assert system_move.windows == [dock.windowHandle()]


def test_happy_free_floating_dock_keeps_qt_s_own_drag(floating, system_move):
    """Where the window manager honours a client's move (spectrwm's free
    floating, most X11 desktops), Qt's own drag stays: it moves the dock
    and docks it again when dropped on a dock area."""
    _win, dock, bar = floating
    reached = PressRecorder(dock)
    send(bar, QEvent.Type.MouseButtonPress, title_point(bar), LEFT, LEFT)
    send(bar, QEvent.Type.MouseButtonRelease, title_point(bar), LEFT, NONE)
    assert reached.presses == 1, "the press must travel on to QDockWidget"
    drag(bar, title_point(bar), QPoint(80, 40))
    assert system_move.windows == []


def test_e2e_happy_double_click_on_a_maximized_floating_title_docks_it_again(floating,
                                                                           system_move):
    win, dock, bar = floating
    dock.setWindowState(Qt.WindowState.WindowMaximized)
    QTest.mouseDClick(bar._title_label, LEFT, pos=QPoint(5, 5))
    APP.processEvents()
    assert not dock.isFloating()
    assert win.dockWidgetArea(dock) == Qt.DockWidgetArea.RightDockWidgetArea
    assert system_move.windows == []


def test_happy_double_click_on_a_free_floating_title_docks_it_again(floating, system_move):
    win, dock, bar = floating
    QTest.mouseDClick(bar._title_label, LEFT, pos=QPoint(5, 5))
    APP.processEvents()
    assert not dock.isFloating()
    assert win.dockWidgetArea(dock) == Qt.DockWidgetArea.RightDockWidgetArea
    assert system_move.windows == []


def test_e2e_happy_title_bar_buttons_still_work_while_the_wm_moves_the_dock(floating,
                                                                          system_move):
    _win, dock, bar = floating
    dock.setWindowState(Qt.WindowState.WindowMaximized)
    QTest.mouseClick(bar._float_btn, LEFT)
    APP.processEvents()
    assert not dock.isFloating(), "the float button docks it again"
    dock.setFloating(True)
    dock.setWindowState(Qt.WindowState.WindowMaximized)
    APP.processEvents()
    QTest.mouseClick(bar._close_btn, LEFT)
    APP.processEvents()
    assert not dock.isVisible()
    assert system_move.windows == []


def test_sad_without_system_move_the_dock_follows_the_mouse(floating, monkeypatch):
    _win, dock, bar = floating
    spy = SystemMoveSpy(False)
    monkeypatch.setattr(QWindow, "startSystemMove", lambda self: spy(self))
    monkeypatch.setattr(WM, "wm_must_move", lambda window: True)
    before = dock.pos()
    drag(bar, title_point(bar), QPoint(90, 30))
    assert len(spy.windows) == 1, "asked once, then moved by hand"
    assert dock.pos() == before + QPoint(90, 30)


def test_sad_a_right_button_drag_and_a_plain_click_do_not_move(floating, system_move):
    _win, dock, bar = floating
    dock.setWindowState(Qt.WindowState.WindowMaximized)
    start = title_point(bar)
    send(bar, QEvent.Type.MouseButtonPress, start, Qt.MouseButton.RightButton,
         Qt.MouseButton.RightButton)
    send(bar, QEvent.Type.MouseMove, start + QPoint(80, 0), NONE, Qt.MouseButton.RightButton)
    send(bar, QEvent.Type.MouseButtonRelease, start + QPoint(80, 0),
         Qt.MouseButton.RightButton, NONE)
    send(bar, QEvent.Type.MouseButtonPress, start, LEFT, LEFT)  # a plain click
    send(bar, QEvent.Type.MouseButtonRelease, start, LEFT, NONE)
    assert system_move.windows == []


def test_edge_a_move_shorter_than_the_drag_distance_stays_a_click(floating, system_move):
    _win, dock, bar = floating
    dock.setWindowState(Qt.WindowState.WindowMaximized)
    short = max(0, QApplication.startDragDistance() - 2)
    drag(bar, title_point(bar), QPoint(short // 2, short // 2 - 1 if short > 1 else 0))
    assert system_move.windows == []
    drag(bar, title_point(bar), QPoint(QApplication.startDragDistance() + 1, 0))
    assert len(system_move.windows) == 1


def test_edge_a_move_after_the_release_does_not_start_a_drag(floating, system_move):
    _win, dock, bar = floating
    dock.setWindowState(Qt.WindowState.WindowMaximized)
    start = title_point(bar)
    send(bar, QEvent.Type.MouseButtonPress, start, LEFT, LEFT)
    send(bar, QEvent.Type.MouseButtonRelease, start, LEFT, NONE)
    send(bar, QEvent.Type.MouseMove, start + QPoint(80, 0), NONE, LEFT)
    assert system_move.windows == []


def test_edge_a_docked_panel_is_never_moved_by_the_window_manager(system_move):
    """Docked, a title-bar drag is Qt's: it pulls the panel out (or moves
    it to another dock area)."""
    win, dock, bar = _dock_window()
    try:
        dock.setWindowState(Qt.WindowState.WindowMaximized)  # nonsense for a docked panel
        reached = PressRecorder(dock)
        send(bar, QEvent.Type.MouseButtonPress, title_point(bar), LEFT, LEFT)
        send(bar, QEvent.Type.MouseButtonRelease, title_point(bar), LEFT, NONE)
        assert reached.presses == 1, "the press must travel on to QDockWidget"
        assert system_move.windows == []
    finally:
        win.close()
        win.deleteLater()


# -- dialogs with the close corner ----------------------------------------------------


def test_e2e_happy_dragging_the_close_corner_row_moves_the_dialog(system_move):
    dialog = make_dialog()
    try:
        drag(dialog, corner_row_point(dialog), QPoint(60, 30))
        assert system_move.windows == [dialog.windowHandle()]
    finally:
        dialog.deleteLater()


def test_e2e_happy_dialog_without_a_vertical_layout_moves_by_its_top_strip(system_move):
    dialog = make_dialog(vbox=False)
    try:
        drag(dialog, corner_row_point(dialog), QPoint(60, 30))
        assert system_move.windows == [dialog.windowHandle()]
    finally:
        dialog.deleteLater()


def test_e2e_happy_a_real_axross_dialog_moves_by_its_top_row(system_move):
    from ui.shortcuts_dialog import ShortcutsDialog

    dialog = ShortcutsDialog()
    dialog.resize(600, 400)
    dialog.show()
    APP.processEvents()
    try:
        drag(dialog, corner_row_point(dialog), QPoint(40, 40))
        assert system_move.windows == [dialog.windowHandle()]
    finally:
        dialog.deleteLater()


def test_happy_the_corner_buttons_still_click(system_move):
    dialog = make_dialog()
    try:
        x_button = add_close_corner(dialog)
        QTest.mouseClick(x_button, LEFT)
        APP.processEvents()
        assert dialog.result() == QDialog.DialogCode.Rejected and not dialog.isVisible()
        assert system_move.windows == []
    finally:
        dialog.deleteLater()


def test_sad_without_system_move_the_dialog_follows_the_mouse(monkeypatch):
    spy = SystemMoveSpy(False)
    monkeypatch.setattr(QWindow, "startSystemMove", lambda self: spy(self))
    dialog = make_dialog()
    try:
        before = dialog.pos()
        drag(dialog, corner_row_point(dialog), QPoint(70, 20))
        assert len(spy.windows) == 1
        assert dialog.pos() == before + QPoint(70, 20)
    finally:
        dialog.deleteLater()


def test_edge_a_drag_below_the_top_row_does_not_move_the_dialog(system_move):
    dialog = make_dialog()
    try:
        below = QPoint(5, dialog.height() - 4)  # the dialog's own margin at the bottom
        drag(dialog, below, QPoint(60, -30))
        assert system_move.windows == []
    finally:
        dialog.deleteLater()


def test_edge_a_drag_in_a_child_that_takes_the_mouse_is_left_to_it(system_move):
    """A line edit selects text on a drag; it takes the press, so the
    dialog never sees it."""
    dialog = QDialog()
    layout = QVBoxLayout(dialog)
    edit = QLineEdit("some text to select")
    layout.addWidget(edit)
    add_close_corner(dialog)
    dialog.show()
    APP.processEvents()
    try:
        drag(edit, QPoint(3, edit.height() // 2), QPoint(60, 0))
        assert system_move.windows == []
        assert edit.selectedText() != ""
    finally:
        dialog.deleteLater()


def test_edge_installing_the_corner_twice_moves_once(system_move):
    dialog = make_dialog()
    try:
        add_close_corner(dialog)
        drag(dialog, corner_row_point(dialog), QPoint(60, 30))
        assert len(system_move.windows) == 1
    finally:
        dialog.deleteLater()


def test_edge_the_real_system_move_comes_back_after_the_spy():
    """The QWindow patch of the tests above is undone: the real call
    answers again (offscreen: False)."""
    dialog = make_dialog()
    try:
        assert dialog.windowHandle().startSystemMove() is False
    finally:
        dialog.deleteLater()


# -- the real main window -------------------------------------------------------------


def test_e2e_a_floated_main_window_panel_moves_by_the_window_manager(tmp_path, monkeypatch,
                                                                    system_move):
    (tmp_path / "home").mkdir()
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    from ui.main_window import MainWindow

    win = MainWindow()
    try:
        win._reconnect_timer.stop()
        win.show()
        dock = next(d for d in win.findChildren(QDockWidget)
                    if isinstance(d.titleBarWidget(), DockTitleBar))
        bar = dock.titleBarWidget()
        QTest.mouseClick(bar._float_btn, LEFT)
        APP.processEvents()
        assert dock.isFloating()
        dock.setWindowState(Qt.WindowState.WindowMaximized)  # spectrwm's fullscreen layout
        drag(bar, title_point(bar), QPoint(100, 50))
        assert system_move.windows == [dock.windowHandle()]
        QTest.mouseDClick(bar._title_label, LEFT, pos=QPoint(5, 5))
        APP.processEvents()
        assert not dock.isFloating(), "a double-click docks it again"
    finally:
        win.close()
        win.deleteLater()
        APP.processEvents()


# -- no reference cycle, no crash when the garbage collector takes a window ------------
#
# Found in the importer scope of the Agent dock work: three runs out of three
# aborted after all tests passed - "'TopRowMover' object has no attribute
# '_drag'" from inside gc.collect(). The mover held its window strongly
# (WindowDrag.window) while the window owns the mover: a reference cycle.
# Python's collector cleared the mover's attributes first, the window was
# destroyed after, and the events of its teardown (Hide, ChildRemoved) hit
# the filter - an exception inside a Qt virtual, which PyQt6 turns into an
# abort.

import gc  # noqa: E402
import subprocess  # noqa: E402
import textwrap  # noqa: E402
import weakref  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


def test_happy_the_mover_holds_no_strong_reference_to_its_window():
    from PyQt6.QtWidgets import QDialog

    from ui.close_corner import add_close_corner

    dlg = QDialog()
    add_close_corner(dlg)
    movers = dlg.findChildren(WM.TopRowMover)
    assert movers
    for mover in movers:
        assert all(v is not dlg for v in vars(mover).values())
        assert all(v is not dlg for v in vars(mover._drag).values())
        assert mover._drag.window is dlg


def test_sad_filters_whose_state_is_gone_let_the_events_pass():
    """Every event filter of the corner row and the mover, its Python
    state cleared as the collector does to an object in a cycle."""
    code = textwrap.dedent(f"""
        import sys
        sys.path.insert(0, {str(ROOT)!r})
        from PyQt6.QtCore import QEvent, QObject
        from PyQt6.QtWidgets import QApplication, QDialog
        app = QApplication([])
        from ui.close_corner import add_close_corner
        dlg = QDialog()
        add_close_corner(dlg)
        filters = [o for o in dlg.findChildren(QObject) if type(o).eventFilter is not QObject.eventFilter]
        print("filters", sorted(type(f).__name__ for f in filters))
        for f in filters:
            f.__dict__.clear()
        for kind in (QEvent.Type.Hide, QEvent.Type.Resize, QEvent.Type.Show,
                     QEvent.Type.WindowStateChange, QEvent.Type.WindowDeactivate):
            QApplication.sendEvent(dlg, QEvent(kind))
        print("alive")
    """)
    env = {**os.environ, "QT_QPA_PLATFORM": "offscreen"}
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                       timeout=60, env=env)
    assert r.returncode == 0, r.stderr[-800:]
    assert "alive" in r.stdout
    assert "TopRowMover" in r.stdout and "_FollowWindowState" in r.stdout


def test_edge_a_drag_whose_window_is_gone_does_nothing():
    from PyQt6.QtWidgets import QWidget

    from ui.window_move import WindowDrag

    win = QWidget()
    drag = WindowDrag(win)
    del win
    gc.collect()
    assert drag.window is None
    drag.press(QPoint(10, 10))
    drag.move(QPoint(100, 100))
    assert not drag.active
