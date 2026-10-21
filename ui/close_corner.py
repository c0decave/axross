"""The [x] button in the top-right corner of editor dialogs, and the
maximize / restore button left of it.

Window managers without title-bar buttons (tiling setups, some
Wayland compositors) leave a dialog with no visible way to close it
besides the bottom button; this puts a conventional close control in
the corner. It calls the dialog's own close handler, so the
unsaved-changes prompt applies exactly as for the bottom Close button.

The maximize corner brings what the image and media viewer had alone:
the Maximize button in the title bar, Ctrl+M maximized <-> normal, and
a button whose icon shows which of the two a click goes to.
"""

from __future__ import annotations

from collections.abc import Callable

from PyQt6.QtCore import QEvent, QObject, QSize
from PyQt6.QtWidgets import QDialog, QHBoxLayout, QToolButton, QVBoxLayout, QWidget

from ui import viewer_window as VW

from ui.icon_provider import icon


def make_close_corner(parent: QWidget, handler: Callable[[], None]) -> QToolButton:
    """A flat, icon-only close button wired to *handler*."""
    btn = QToolButton(parent)
    btn.setObjectName("axCloseCorner")
    btn.setAutoRaise(True)
    btn.setIcon(icon("x", 16))
    btn.setIconSize(QSize(16, 16))
    btn.setToolTip("Close (Esc)")
    btn.setAccessibleName("Close")
    btn.clicked.connect(lambda _checked=False: handler())
    return btn


class _FollowWindowState(QObject):
    """Keeps the maximize corner's icon and tooltip on the window's state,
    whoever changed it: the button, Ctrl+M or the title bar."""

    def __init__(self, window: QWidget, button: QToolButton) -> None:
        super().__init__(button)
        self._window = window
        self._button = button
        window.installEventFilter(self)
        self.update()

    def update(self) -> None:
        if VW.is_maximized(self._window):
            name, tip = "window-restore", f"Restore ({VW.MAXIMIZE_KEY})"
        else:
            name, tip = "window-maximize", f"Maximize ({VW.MAXIMIZE_KEY})"
        self._button.setIcon(icon(name, 16))
        self._button.setToolTip(tip)
        self._button.setAccessibleName(tip.split(" ")[0])

    def eventFilter(self, watched, event) -> bool:
        # Resize too: axross maximizes by geometry where the window manager
        # ignores the request (no state change then).
        if watched is self._window and event.type() in (
            QEvent.Type.WindowStateChange,
            QEvent.Type.Resize,
        ):
            self.update()
        return False


def make_maximize_corner(window: QWidget) -> QToolButton:
    """A flat maximize / restore button for *window*; it also gives the
    window the Maximize button in its title bar and Ctrl+M. Calling it
    twice returns the first button."""
    existing = window.findChild(QToolButton, "axMaximizeCorner")
    if existing is not None:
        return existing
    # A new window flag hides a window that is on screen: show it again.
    visible = window.isVisible()
    VW.allow_maximize(window)
    if visible:
        window.show()
    VW.maximize_shortcut(window)
    btn = QToolButton(window)
    btn.setObjectName("axMaximizeCorner")
    btn.setAutoRaise(True)
    btn.setIconSize(QSize(16, 16))
    btn.clicked.connect(lambda _checked=False: VW.toggle_maximized(window))
    _FollowWindowState(window, btn)
    return btn


_CORNER_MARGIN = 4


class _KeepInCorner(QObject):
    """Keeps overlaid corner buttons at the dialog's top-right through
    resizes, the last one rightmost."""

    def __init__(self, dialog: QDialog, *buttons: QToolButton) -> None:
        super().__init__(dialog)
        self._buttons = buttons
        dialog.installEventFilter(self)
        self.place(dialog)

    def place(self, dialog: QDialog) -> None:
        right = dialog.width() - _CORNER_MARGIN
        for button in reversed(self._buttons):
            size = button.sizeHint()
            right -= size.width()
            button.setGeometry(right, _CORNER_MARGIN, size.width(), size.height())
            button.raise_()

    def eventFilter(self, watched, event) -> bool:
        if event.type() in (QEvent.Type.Resize, QEvent.Type.Show):
            self.place(watched)
        return False


def add_close_corner(dialog: QDialog) -> QToolButton | None:
    """Put the [x] at the top right of *dialog*, the maximize / restore
    button left of it (see ``make_maximize_corner``).

    With a ``QVBoxLayout`` they get a slim row of their own above the
    content; any other dialog gets them laid over its top-right corner and
    kept there on resize. The [x] calls ``dialog.reject`` (looked up when
    clicked, so a dialog that overrides ``reject`` to stop a running job
    gets that behaviour). Calling it twice is harmless. Returns the [x].
    """
    existing = dialog.findChild(QToolButton, "axCloseCorner")
    if existing is not None:
        return existing
    maximize = make_maximize_corner(dialog)
    layout = dialog.layout()
    if not isinstance(layout, QVBoxLayout):
        btn = make_close_corner(dialog, lambda: dialog.reject())
        _KeepInCorner(dialog, maximize, btn)
        return btn
    row = QHBoxLayout()
    row.setContentsMargins(0, 0, 0, 0)
    row.addStretch(1)
    btn = make_close_corner(dialog, lambda: dialog.reject())
    row.addWidget(maximize)
    row.addWidget(btn)
    layout.insertLayout(0, row)
    return btn


__all__ = ["add_close_corner", "make_close_corner", "make_maximize_corner"]
