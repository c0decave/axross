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

from ui import window_move
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
    * a left drag on the bar (not on a button) moves a floating panel.
      Qt does that itself by ``QWidget::move()`` and docks the panel again
      when it is dropped on a dock area; where the window manager refuses
      such a move (Wayland, a window it keeps maximized - spectrwm's
      ``fullscreen`` layout) the window manager moves it instead
      (:mod:`ui.window_move`). A double-click docks a floating panel
      again either way (Qt's QDockWidget behaviour).
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
        *,
        reopen_hint: str = "View → Panels",
    ) -> None:
        """*reopen_hint* names the menu whose toggle shows the panel again
        after a close (extension panels: the Extensions menu)."""
        super().__init__(parent or dock)
        self._dock = dock
        self._drag = window_move.WindowDrag(dock)
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
        self._close_btn.setToolTip(f"Close this panel (reopen via {reopen_hint})")
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

    def add_indicator(self, widget: QWidget) -> None:
        """Show *widget* (a status lamp) left of the buttons, after the
        title: the panel's state at a glance, in its top row."""
        widget.setParent(self)
        layout = self.layout()
        layout.insertWidget(layout.indexOf(self._float_btn), widget)
        widget.show()

    def enable_pause(self, on_toggle, *, paused: bool = False) -> None:
        """Add a Pause / Resume toggle left of the float button (extension
        panels: no pane events while paused). *on_toggle(paused)* runs on a
        click; :meth:`set_paused` shows the state."""
        from core.i18n import tr

        self._title = self._title_label.text()
        self._pause_btn = QToolButton(self)
        self._pause_btn.setCheckable(True)
        self._pause_btn.setIconSize(QSize(16, 16))
        self._pause_btn.setAutoRaise(True)
        self._pause_btn.setFixedSize(QSize(22, 22))
        self._pause_btn.setAccessibleName(tr("Pause"))
        self._pause_btn.clicked.connect(lambda checked: on_toggle(bool(checked)))
        layout = self.layout()
        layout.insertWidget(layout.indexOf(self._float_btn), self._pause_btn)
        self.set_paused(paused)

    def set_paused(self, paused: bool) -> None:
        """Show the pause state: the button's icon and tooltip, and
        "(Paused)" after the title."""
        from core.i18n import tr

        button = getattr(self, "_pause_btn", None)
        if button is None:
            return
        button.setChecked(paused)
        button.setIcon(icon("play" if paused else "pause", 16))
        button.setToolTip(
            tr("Resume: deliver folder and selection changes again")
            if paused
            else tr("Pause: stop reloading on folder and selection changes")
        )
        suffix = " " + tr("(Paused)") if paused else ""
        self._title_label.setText(self._title + suffix)

    # -- moving a floating panel ---------------------------------------------------------
    # A press the bar does not take travels on to QDockWidget, which then
    # drags the panel itself (undock, move, dock again). The bar takes it
    # only where that drag cannot move the window.

    def _wm_moves(self) -> bool:
        return self._dock.isFloating() and window_move.wm_must_move(self._dock)

    def mousePressEvent(self, event) -> None:  # noqa: N802 - Qt
        if event.button() == Qt.MouseButton.LeftButton and self._wm_moves():
            self._drag.press(event.globalPosition().toPoint())
            event.accept()
            return
        self._drag.release()
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event) -> None:  # noqa: N802 - Qt
        if self._drag.active:
            if event.buttons() & Qt.MouseButton.LeftButton:
                self._drag.move(event.globalPosition().toPoint())
                event.accept()
                return
            self._drag.release()
        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event) -> None:  # noqa: N802 - Qt
        if self._drag.active:
            self._drag.release()
            event.accept()
            return
        super().mouseReleaseEvent(event)

    def mouseDoubleClickEvent(self, event) -> None:  # noqa: N802 - Qt
        # QWidget's default hands a double-click to mousePressEvent, which
        # would take it while the window manager moves the panel: ignored,
        # it reaches QDockWidget, which floats / docks the panel.
        self._drag.release()
        event.ignore()

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
        self._title = title
        if getattr(self, "_pause_btn", None) is not None:
            self.set_paused(self._pause_btn.isChecked())
        else:
            self._title_label.setText(title)


__all__ = ["DockTitleBar"]
