"""Moving a window with a left drag on its top row.

A floating panel carries our own title bar, so the window manager draws
none (Qt makes it a frameless tool window), and spectrwm draws no title
bar on any window. The top row is what a user grabs - and Qt moves a
floating panel during a title-bar drag by ``QWidget::move()``, a request
the window manager may refuse: spectrwm does for a window it keeps
maximized (its ``fullscreen`` layout), Wayland gives a client no say over
where its window sits at all. Only MOD+drag, the window manager's own
move, worked there.

``QWindow.startSystemMove()`` hands the drag to the window manager
(``_NET_WM_MOVERESIZE`` on X11, ``xdg_toplevel.move`` on Wayland). Where
the platform cannot do that (no window handle yet, the offscreen platform,
a window manager without the request), the window follows the mouse by
itself.
"""

from __future__ import annotations

import weakref
from collections.abc import Callable

from PyQt6.QtCore import QEvent, QObject, QPoint, Qt
from PyQt6.QtGui import QGuiApplication
from PyQt6.QtWidgets import QApplication, QWidget


def wm_must_move(window: QWidget) -> bool:
    """Whether only the window manager can move *window*: on Wayland
    always; on X11 when the window manager keeps it maximized or full
    screen (it ignores the client's own move requests then)."""
    if QGuiApplication.platformName().startswith("wayland"):
        return True
    state = window.windowState()
    return bool(state & (Qt.WindowState.WindowMaximized | Qt.WindowState.WindowFullScreen))


def start_system_move(window: QWidget) -> bool:
    """Ask the window manager to move *window* with the mouse; False when
    it cannot (no native window yet, a platform without the request)."""
    handle = window.windowHandle()
    if handle is None:
        return False
    return bool(handle.startSystemMove())


class WindowDrag:
    """One left drag that moves *window*: once the mouse travelled the
    drag distance, the window manager takes over; where it cannot, the
    window follows the mouse by itself until the release."""

    def __init__(self, window: QWidget) -> None:
        # Weak: the window owns what drags it (a title bar, a TopRowMover);
        # a strong reference back made a cycle, and the collector cleared
        # a filter's state while its window was still sending events.
        self._window = weakref.ref(window)
        self._press: QPoint | None = None
        self._origin = QPoint()
        self._by_hand = False

    @property
    def window(self) -> QWidget | None:
        """The window this drag moves, or None once it is gone."""
        return self._window()

    @property
    def active(self) -> bool:
        """A press is being followed (not handed over, not released)."""
        return self._press is not None

    def press(self, global_pos: QPoint) -> None:
        window = self.window
        if window is None:
            self.release()
            return
        self._press = QPoint(global_pos)
        self._origin = window.pos()
        self._by_hand = False

    def move(self, global_pos: QPoint) -> None:
        window = self.window
        if self._press is None or window is None:
            self.release()
            return
        delta = global_pos - self._press
        if not self._by_hand:
            if delta.manhattanLength() < QApplication.startDragDistance():
                return  # still a click
            if start_system_move(window):
                self._press = None  # the window manager has the pointer now
                return
            self._by_hand = True
        window.move(self._origin + delta)

    def release(self) -> None:
        self._press = None
        self._by_hand = False


class TopRowMover(QObject):
    """Moves *window* on a left drag that starts on the window itself -
    a press no child widget took (empty space, a plain label) - above
    ``row_bottom()`` (window coordinates)."""

    def __init__(self, window: QWidget, row_bottom: Callable[[], int]) -> None:
        super().__init__(window)
        self._drag = WindowDrag(window)
        self._row_bottom = row_bottom
        window.installEventFilter(self)

    def eventFilter(self, watched, event) -> bool:  # noqa: N802 - Qt
        # A filter keeps getting events while Python tears it down: an
        # exception here would end the process (PyQt6 aborts on one).
        drag = self.__dict__.get("_drag")
        row_bottom = self.__dict__.get("_row_bottom")
        if drag is None or row_bottom is None or watched is not drag.window:
            return False
        kind = event.type()
        if kind == QEvent.Type.MouseButtonPress:
            if event.button() == Qt.MouseButton.LeftButton \
                    and event.position().y() <= row_bottom():
                drag.press(event.globalPosition().toPoint())
                event.accept()
                return True
            return False
        if not drag.active:
            return False
        if kind == QEvent.Type.MouseMove:
            if event.buttons() & Qt.MouseButton.LeftButton:
                drag.move(event.globalPosition().toPoint())
                event.accept()
                return True
            drag.release()  # the release went elsewhere
            return False
        if kind == QEvent.Type.MouseButtonRelease:
            drag.release()
            event.accept()
            return True
        return False


__all__ = ["TopRowMover", "WindowDrag", "start_system_move", "wm_must_move"]
