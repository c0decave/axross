"""axross's own title bar: a window's top row - its icon, its name and
``_ [] x`` (ui.close_corner) - is the only title bar it has.

Feedback: where the window manager draws a title bar of its own, our row
sat below it as a second one, the name and the buttons twice. Now the
window is frameless (the window manager draws nothing) and our row is the
title bar: a left drag on it moves the window, a double click maximizes or
restores it, and thin grips along the edges resize it - each handed to the
window manager (``QWindow.startSystemResize`` / ``startSystemMove``: X11's
``_NET_WM_MOVERESIZE``, Wayland's ``xdg_toplevel``), followed by hand where
it cannot take it.

Settings > Appearance > "axross's own title bars" switches back: the window
manager's title bar and buttons, and our row hidden. The switch applies to
open windows at once (``set_own_title_bars``).
"""

from __future__ import annotations

import weakref
from collections.abc import Callable

from PyQt6 import sip
from PyQt6.QtCore import QEvent, QObject, QPoint, QRect, QSize, Qt
from PyQt6.QtGui import QPainter, QPalette, QPen
from PyQt6.QtWidgets import QLabel, QWidget

from ui import viewer_window as VW

#: Width of the resize grips along the edges (window pixels).
BORDER = 4

_E = Qt.Edge
_GRIPS = (
    (_E.TopEdge | _E.LeftEdge, Qt.CursorShape.SizeFDiagCursor),
    (_E.TopEdge, Qt.CursorShape.SizeVerCursor),
    (_E.TopEdge | _E.RightEdge, Qt.CursorShape.SizeBDiagCursor),
    (_E.RightEdge, Qt.CursorShape.SizeHorCursor),
    (_E.BottomEdge | _E.RightEdge, Qt.CursorShape.SizeFDiagCursor),
    (_E.BottomEdge, Qt.CursorShape.SizeVerCursor),
    (_E.BottomEdge | _E.LeftEdge, Qt.CursorShape.SizeBDiagCursor),
    (_E.LeftEdge, Qt.CursorShape.SizeHorCursor),
)

_own = True
_windows: weakref.WeakSet = weakref.WeakSet()


def own_title_bars() -> bool:
    """Whether windows carry axross's own title bar (frameless)."""
    return _own


def set_own_title_bars(on: bool) -> int:
    """Switch every window with a title row, open ones included; returns
    how many were switched."""
    global _own
    _own = bool(on)
    count = 0
    for window in list(_windows):
        if sip.isdeleted(window):   # its C++ side is gone (deleteLater, a closed dialog)
            _windows.discard(window)
            continue
        bar = window.findChild(TitleBar, options=Qt.FindChildOption.FindDirectChildrenOnly)
        if bar is not None:
            bar.apply()
            count += 1
    return count


class _Grip(QWidget):
    """One edge or corner of a frameless window: resizes it, and draws
    that edge's line (the frame the window manager no longer draws)."""

    def __init__(self, window: QWidget, edges, cursor) -> None:
        super().__init__(window)
        self.setObjectName("axResizeGrip")
        self.edges = edges
        self.setCursor(cursor)
        self._press: QPoint | None = None
        self._origin = QRect()

    def mousePressEvent(self, event) -> None:  # noqa: N802 - Qt override
        if event.button() != Qt.MouseButton.LeftButton:
            return super().mousePressEvent(event)
        window = self.window()
        handle = window.windowHandle()
        if handle is not None and handle.startSystemResize(self.edges):
            return  # the window manager has the pointer now
        self._press = event.globalPosition().toPoint()
        self._origin = window.geometry()

    def mouseMoveEvent(self, event) -> None:  # noqa: N802 - Qt override
        if self._press is None:
            return super().mouseMoveEvent(event)
        window = self.window()
        delta = event.globalPosition().toPoint() - self._press
        window.setGeometry(resized(self._origin, self.edges, delta, window.minimumSize()))

    def mouseReleaseEvent(self, event) -> None:  # noqa: N802 - Qt override
        self._press = None
        super().mouseReleaseEvent(event)

    def paintEvent(self, _event) -> None:  # noqa: N802 - Qt override
        painter = QPainter(self)
        painter.setPen(QPen(self.palette().color(QPalette.ColorRole.Mid), 1))
        w, h = self.width() - 1, self.height() - 1
        if self.edges & _E.TopEdge:
            painter.drawLine(0, 0, w, 0)
        if self.edges & _E.BottomEdge:
            painter.drawLine(0, h, w, h)
        if self.edges & _E.LeftEdge:
            painter.drawLine(0, 0, 0, h)
        if self.edges & _E.RightEdge:
            painter.drawLine(w, 0, w, h)
        painter.end()


def resized(origin: QRect, edges, delta: QPoint, minimum: QSize) -> QRect:
    """*origin* with *edges* moved by *delta*, never below *minimum*."""
    g = QRect(origin)
    min_w, min_h = max(minimum.width(), 2 * BORDER + 40), max(minimum.height(), 2 * BORDER + 20)
    if edges & _E.LeftEdge:
        g.setLeft(min(origin.left() + delta.x(), origin.right() - min_w + 1))
    if edges & _E.RightEdge:
        g.setRight(max(origin.right() + delta.x(), origin.left() + min_w - 1))
    if edges & _E.TopEdge:
        g.setTop(min(origin.top() + delta.y(), origin.bottom() - min_h + 1))
    if edges & _E.BottomEdge:
        g.setBottom(max(origin.bottom() + delta.y(), origin.top() + min_h - 1))
    return g


class TitleIcon(QLabel):
    """The window's icon at the start of its title row, as a title bar has it."""

    def __init__(self, window: QWidget) -> None:
        super().__init__(window)
        self.setObjectName("axTitleIcon")
        self._window = weakref.ref(window)
        self.setFixedSize(QSize(18, 18))
        self.refresh()

    def refresh(self) -> None:
        window = self._window()
        if window is not None:
            self.setPixmap(window.windowIcon().pixmap(16, 16))


class TitleBar(QObject):
    """Makes *window* frameless with *parts* (its title row) as the title
    bar, or - in the window manager's mode - gives the frame back and
    hides *parts*. *row_bottom* is the row's lower edge in window
    coordinates (a double click above it maximizes)."""

    def __init__(self, window: QWidget, parts: list[QWidget],
                 row_bottom: Callable[[], int]) -> None:
        super().__init__(window)
        self._window = weakref.ref(window)
        self._parts = [weakref.ref(p) for p in parts]
        self._row_bottom = row_bottom
        self._margins = window.contentsMargins()
        #: A switch while a modal dialog was open: applied once it is hidden.
        self._pending = False
        self._grips = [_Grip(window, edges, cursor) for edges, cursor in _GRIPS]
        window.installEventFilter(self)
        _windows.add(window)
        self.apply()

    def apply(self) -> None:
        window = self._window()
        if window is None:
            return
        own = _own
        frameless = bool(window.windowFlags() & Qt.WindowType.FramelessWindowHint)
        if frameless != own and window.isVisible() and (
                window.isModal() or window.windowModality() != Qt.WindowModality.NonModal):
            # A new flag hides the window, and a hidden modal dialog ends its
            # exec(): switching from Settings closed (and deleted) Settings.
            # It takes the switch when it closes.
            self._pending = True
            return
        if frameless != own:
            # A new window flag hides a window that is on screen.
            visible = window.isVisible()
            VW.set_window_flag(window, Qt.WindowType.FramelessWindowHint, own)
            if visible:
                window.show()
        self._place()

    def _place(self) -> None:
        window = self._window()
        if window is None:
            return
        # Full screen (the visualizer, a viewer) shows no title row at all.
        full = bool(window.windowState() & Qt.WindowState.WindowFullScreen)
        for ref in self._parts:
            part = ref()
            if part is not None and part.isVisibleTo(window) != (_own and not full):
                part.setVisible(_own and not full)
        framed = _own and not full and not VW.is_maximized(window)
        m = self._margins
        if framed:
            window.setContentsMargins(m.left() + BORDER, m.top() + BORDER,
                                      m.right() + BORDER, m.bottom() + BORDER)
        else:
            window.setContentsMargins(m)
        w, h, b = window.width(), window.height(), BORDER
        spans = {
            _E.TopEdge | _E.LeftEdge: QRect(0, 0, b, b),
            _E.TopEdge: QRect(b, 0, w - 2 * b, b),
            _E.TopEdge | _E.RightEdge: QRect(w - b, 0, b, b),
            _E.RightEdge: QRect(w - b, b, b, h - 2 * b),
            _E.BottomEdge | _E.RightEdge: QRect(w - b, h - b, b, b),
            _E.BottomEdge: QRect(b, h - b, w - 2 * b, b),
            _E.BottomEdge | _E.LeftEdge: QRect(0, h - b, b, b),
            _E.LeftEdge: QRect(0, b, b, h - 2 * b),
        }
        for grip in self._grips:
            grip.setGeometry(spans[grip.edges])
            grip.setVisible(framed)
            if framed:
                grip.raise_()

    def eventFilter(self, watched, event) -> bool:  # noqa: N802 - Qt override
        # A filter keeps getting events while Python tears it down: an
        # exception here would end the process (PyQt6 aborts on one).
        ref = self.__dict__.get("_window")
        window = ref() if ref is not None else None
        if window is None or watched is not window:
            return False
        kind = event.type()
        if kind in (QEvent.Type.Resize, QEvent.Type.WindowStateChange, QEvent.Type.Show):
            self._place()
        elif kind == QEvent.Type.Hide and self.__dict__.get("_pending"):
            self._pending = False
            self.apply()
        elif kind == QEvent.Type.WindowIconChange:
            for icon in window.findChildren(TitleIcon):
                icon.refresh()
        elif kind == QEvent.Type.MouseButtonDblClick and _own \
                and event.button() == Qt.MouseButton.LeftButton \
                and event.position().y() <= self._row_bottom():
            VW.toggle_maximized(window)
            return True
        return False


def install(window: QWidget, parts: list[QWidget], row_bottom: Callable[[], int]) -> TitleBar:
    """Give *window* axross's title bar (once; a second call returns the first)."""
    existing = window.findChild(TitleBar, options=Qt.FindChildOption.FindDirectChildrenOnly)
    if existing is not None:
        return existing
    return TitleBar(window, parts, row_bottom)


__all__ = ["BORDER", "TitleBar", "TitleIcon", "install", "own_title_bars", "resized",
           "set_own_title_bars"]
