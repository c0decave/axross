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
    QMainWindow,
    QToolButton,
    QWidget,
)

from ui.icon_provider import icon


class DockTitleBar(QWidget):
    """Title bar installed on a QDockWidget via
    ``dock.setTitleBarWidget(DockTitleBar(...))``.

    Layout (left → right):

        [icon] [title text]              [float] [close] [close all]

    The right-hand buttons are always visible regardless of the active
    theme (they're real QToolButtons, not QSS pseudo-elements).
    Clicking:

    * **float** toggles the dock between docked and floating. Mirrors
      Qt's default ``DockWidgetFloatable`` feature.
    * **close** hides the dock. Same effect as ``DockWidgetClosable``
      — the dock stays in the widget tree so ``toggleViewAction()``
      can re-show it later.
    * **close all** hides every dock sharing this one's dock area. The
      bottom strip stacks four tabified panels, and because only the
      front tab shows a title bar, clearing them one at a time means
      four aimed clicks with the target moving after each. Scope is the
      dock AREA on purpose: pressing it on a bottom panel leaves the
      Bookmarks sidebar alone.
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

        # Close every panel in this dock area.
        self._close_all_btn = QToolButton(self)
        self._close_all_btn.setIcon(icon("close-all-panes", 16))
        self._close_all_btn.setIconSize(QSize(16, 16))
        self._close_all_btn.setToolTip(
            "Close all panels in this area (reopen via View → Panels)"
        )
        self._close_all_btn.setAutoRaise(True)
        self._close_all_btn.setFixedSize(QSize(22, 22))
        self._close_all_btn.clicked.connect(self._close_all)
        layout.addWidget(self._close_all_btn)

    def _toggle_float(self) -> None:
        self._dock.setFloating(not self._dock.isFloating())

    def sibling_docks(self) -> list[QDockWidget]:
        """Every dock sharing this dock's area, including this one.

        Falls back to ``[self._dock]`` when there is no area to
        enumerate — the dock is floating (the user detached it precisely
        to treat it separately) or it was never added to a QMainWindow
        (a title bar is constructible before the dock is placed).

        The ``isFloating()`` checks are load-bearing and not redundant:
        a floating dock keeps reporting its LAST area from
        ``dockWidgetArea()`` rather than ``NoDockWidgetArea`` (measured
        on PyQt6 — docked and floating both return
        ``BottomDockWidgetArea``). Filtering on the area alone would
        therefore let a detached panel drag its former neighbours shut.
        """
        window = self._dock.parent()
        if not isinstance(window, QMainWindow) or self._dock.isFloating():
            return [self._dock]
        area = window.dockWidgetArea(self._dock)
        if area == Qt.DockWidgetArea.NoDockWidgetArea:
            return [self._dock]
        return [
            dock
            for dock in window.findChildren(QDockWidget)
            if not dock.isFloating() and window.dockWidgetArea(dock) == area
        ]

    def _close_all(self) -> None:
        for dock in self.sibling_docks():
            dock.close()

    def set_title(self, title: str) -> None:
        """Programmatic title update. The dock's
        ``windowTitle`` / ``setWindowTitle`` no longer drives the
        label once a custom title bar is installed — callers that
        previously flipped the title need to call this instead.
        """
        self._title_label.setText(title)


__all__ = ["DockTitleBar"]
