"""Custom QDockWidget title bar with visible close + float buttons.

Why a custom widget instead of trusting Qt's default? Two reasons
seen in practice:

1. On some Linux desktop styles (GNOME/Adwaita, KDE/Breeze, i3/gtk)
   the default QDockWidget close and float buttons render as 6×6-px
   glyphs that are nearly invisible on a dark theme. Users then
   can't find them and think the panel can't be closed.
2. Our axross themes set ``titlebar-close-icon: none`` in one place
   which hid the close button entirely on the dark theme.

A custom title bar with our own SVG icons (via ``ui.icon_provider``)
is consistent across platforms and inherits the same colourful /
monochrome switching as every other icon in the app.
"""
from __future__ import annotations

from PyQt6.QtCore import QSize, Qt
from PyQt6.QtWidgets import (
    QDockWidget,
    QHBoxLayout,
    QLabel,
    QToolButton,
    QWidget,
)

from ui.icon_provider import icon


class DockTitleBar(QWidget):
    """Title bar installed on a QDockWidget via
    ``dock.setTitleBarWidget(DockTitleBar(...))``.

    Layout (left → right):

        [icon] [title text]                    [float] [close]

    The two right-hand buttons are always visible regardless of the
    active theme (they're real QToolButtons, not QSS pseudo-elements).
    Clicking:

    * **float** toggles the dock between docked and floating. Mirrors
      Qt's default ``DockWidgetFloatable`` feature.
    * **close** hides the dock. Same effect as ``DockWidgetClosable``
      — the dock stays in the widget tree so ``toggleViewAction()``
      can re-show it later.
    """

    def __init__(
        self,
        title: str,
        icon_name: str,
        dock: QDockWidget,
        parent=None,
    ) -> None:
        super().__init__(parent or dock)
        self._dock = dock
        layout = QHBoxLayout(self)
        layout.setContentsMargins(8, 3, 4, 3)
        layout.setSpacing(6)

        icon_label = QLabel(self)
        icon_label.setPixmap(icon(icon_name, 18).pixmap(18, 18))
        icon_label.setFixedSize(QSize(18, 18))
        layout.addWidget(icon_label)

        self._title_label = QLabel(title, self)
        self._title_label.setTextFormat(Qt.TextFormat.PlainText)
        layout.addWidget(self._title_label, stretch=1)

        # Float toggle. ``extract-pane`` reads well as "pop out".
        self._float_btn = QToolButton(self)
        self._float_btn.setIcon(icon("extract-pane", 16))
        self._float_btn.setIconSize(QSize(16, 16))
        self._float_btn.setToolTip("Float / dock this panel")
        self._float_btn.setAutoRaise(True)
        self._float_btn.setFixedSize(QSize(22, 22))
        self._float_btn.clicked.connect(self._toggle_float)
        layout.addWidget(self._float_btn)

        # Close button. ``close-pane`` (X inside a square) is our
        # universal close glyph.
        self._close_btn = QToolButton(self)
        self._close_btn.setIcon(icon("close-pane", 16))
        self._close_btn.setIconSize(QSize(16, 16))
        self._close_btn.setToolTip("Close this panel (reopen via View → Panels)")
        self._close_btn.setAutoRaise(True)
        self._close_btn.setFixedSize(QSize(22, 22))
        self._close_btn.clicked.connect(dock.close)
        layout.addWidget(self._close_btn)

    def _toggle_float(self) -> None:
        self._dock.setFloating(not self._dock.isFloating())

    def set_title(self, title: str) -> None:
        """Programmatic title update. The dock's
        ``windowTitle`` / ``setWindowTitle`` no longer drives the
        label once a custom title bar is installed — callers that
        previously flipped the title need to call this instead.
        """
        self._title_label.setText(title)


__all__ = ["DockTitleBar"]
