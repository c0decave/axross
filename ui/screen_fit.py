"""Windows and dialogs that fit the screen they open on.

A 1280x800 or 1366x768 laptop screen has about 760 px of height for a
window once its title bar is drawn: Connect to Server asked for 947 px
(OK and Cancel off-screen), the About box for 967 px, System Information
opened at 1180x800. These helpers cap a size at the available screen
geometry and give long content a scroll bar instead of a taller window.
"""

from __future__ import annotations

from PyQt6.QtCore import QRect, QSize, Qt
from PyQt6.QtGui import QGuiApplication
from PyQt6.QtWidgets import QFrame, QScrollArea, QWidget

#: What the window manager's title bar and frame take around a window.
FRAME_MARGIN_PX = 40


def available_geometry(widget: QWidget | None = None) -> QRect:
    """The available area of the screen *widget* (or its parent window)
    is on, else of the primary screen; an empty rect without a screen."""
    screen = None
    while widget is not None and screen is None:
        if widget.isWindow() or widget.parentWidget() is None:
            screen = widget.screen()
        widget = widget.parentWidget()
    if screen is None:
        screen = QGuiApplication.primaryScreen()
    return screen.availableGeometry() if screen is not None else QRect()


def max_window_size(widget: QWidget | None = None) -> QSize:
    """The largest client size a window can have and still show its frame
    on the screen; an invalid size without a screen."""
    avail = available_geometry(widget)
    if not avail.isValid():
        return QSize()
    return QSize(max(200, avail.width() - FRAME_MARGIN_PX),
                 max(200, avail.height() - FRAME_MARGIN_PX))


def fit_size(size: QSize | tuple[int, int], widget: QWidget | None = None) -> QSize:
    """*size* capped at max_window_size."""
    size = QSize(*size) if isinstance(size, tuple) else QSize(size)
    limit = max_window_size(widget)
    if limit.isValid():
        size = size.boundedTo(limit)
    return size


def fit_window(window: QWidget) -> None:
    """Shrink *window* to the screen if it is larger, and cap its minimum
    size there too (a minimum taller than the screen hides the buttons)."""
    limit = max_window_size(window)
    if not limit.isValid():
        return
    minimum = window.minimumSize()
    if minimum.width() > limit.width() or minimum.height() > limit.height():
        window.setMinimumSize(minimum.boundedTo(limit))
    size = window.size()
    if size.width() > limit.width() or size.height() > limit.height():
        window.resize(size.boundedTo(limit))


class FitScrollArea(QScrollArea):
    """A frameless scroll area that asks for its content's full size while
    the screen has room for it (a plain QScrollArea asks for at most 24
    lines), and scrolls once it does not. *reserve* is the height the rest
    of the window needs around it (title bar, buttons)."""

    def __init__(self, content: QWidget, *, reserve: int = 120,
                 parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._reserve = reserve
        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.Shape.NoFrame)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setWidget(content)

    def sizeHint(self) -> QSize:  # noqa: N802 - Qt
        content = self.widget()
        if content is None:
            return super().sizeHint()
        hint = content.sizeHint()
        bar = self.verticalScrollBar().sizeHint().width()
        limit = max_window_size(self)
        height = hint.height()
        if limit.isValid():
            height = min(height, max(120, limit.height() - self._reserve))
        return QSize(hint.width() + bar, height)

    def minimumSizeHint(self) -> QSize:  # noqa: N802 - Qt
        content = self.widget()
        width = content.minimumSizeHint().width() if content is not None else 0
        return QSize(width + self.verticalScrollBar().sizeHint().width(), 120)
