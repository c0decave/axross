"""The [x] button in the top-right corner of editor dialogs.

Window managers without title-bar buttons (tiling setups, some
Wayland compositors) leave a dialog with no visible way to close it
besides the bottom button; this puts a conventional close control in
the corner. It calls the dialog's own close handler, so the
unsaved-changes prompt applies exactly as for the bottom Close button.
"""

from __future__ import annotations

from collections.abc import Callable

from PyQt6.QtCore import QEvent, QObject, QSize
from PyQt6.QtWidgets import QDialog, QHBoxLayout, QToolButton, QVBoxLayout, QWidget

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


_CORNER_MARGIN = 4


class _KeepInCorner(QObject):
    """Keeps an overlaid [x] at the dialog's top-right through resizes."""

    def __init__(self, dialog: QDialog, button: QToolButton) -> None:
        super().__init__(dialog)
        self._button = button
        dialog.installEventFilter(self)
        self.place(dialog)

    def place(self, dialog: QDialog) -> None:
        size = self._button.sizeHint()
        self._button.setGeometry(
            dialog.width() - size.width() - _CORNER_MARGIN,
            _CORNER_MARGIN,
            size.width(),
            size.height(),
        )
        self._button.raise_()

    def eventFilter(self, watched, event) -> bool:
        if event.type() in (QEvent.Type.Resize, QEvent.Type.Show):
            self.place(watched)
        return False


def add_close_corner(dialog: QDialog) -> QToolButton | None:
    """Put the [x] at the top right of *dialog*.

    With a ``QVBoxLayout`` it gets a slim row of its own above the content;
    any other dialog gets it laid over its top-right corner and kept there
    on resize. It calls ``dialog.reject`` (looked up when clicked, so a
    dialog that overrides ``reject`` to stop a running job gets that
    behaviour). Calling it twice is harmless.
    """
    existing = dialog.findChild(QToolButton, "axCloseCorner")
    if existing is not None:
        return existing
    layout = dialog.layout()
    if not isinstance(layout, QVBoxLayout):
        btn = make_close_corner(dialog, lambda: dialog.reject())
        _KeepInCorner(dialog, btn)
        return btn
    row = QHBoxLayout()
    row.setContentsMargins(0, 0, 0, 0)
    row.addStretch(1)
    btn = make_close_corner(dialog, lambda: dialog.reject())
    row.addWidget(btn)
    layout.insertLayout(0, row)
    return btn


__all__ = ["add_close_corner", "make_close_corner"]
