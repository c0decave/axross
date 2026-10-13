"""The [x] button in the top-right corner of editor dialogs.

Window managers without title-bar buttons (tiling setups, some
Wayland compositors) leave a dialog with no visible way to close it
besides the bottom button; this puts a conventional close control in
the corner. It calls the dialog's own close handler, so the
unsaved-changes prompt applies exactly as for the bottom Close button.
"""

from __future__ import annotations

from collections.abc import Callable

from PyQt6.QtCore import QSize
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


def add_close_corner(dialog: QDialog) -> QToolButton | None:
    """Put the [x] in a slim row at the top of *dialog*'s vertical layout.

    It calls ``dialog.reject`` (looked up when clicked, so a dialog that
    overrides ``reject`` to stop a running job gets that behaviour). Dialogs
    without a ``QVBoxLayout`` are left alone; calling it twice is harmless.
    """
    existing = dialog.findChild(QToolButton, "axCloseCorner")
    if existing is not None:
        return existing
    layout = dialog.layout()
    if not isinstance(layout, QVBoxLayout):
        return None
    row = QHBoxLayout()
    row.setContentsMargins(0, 0, 0, 0)
    row.addStretch(1)
    btn = make_close_corner(dialog, lambda: dialog.reject())
    row.addWidget(btn)
    layout.insertLayout(0, row)
    return btn


__all__ = ["add_close_corner", "make_close_corner"]
