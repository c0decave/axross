"""The dock bar: extra windows put away with their ``_`` button.

Feedback: a ``_`` button in the title row of the extra windows (the dialogs
with :func:`ui.close_corner.add_close_corner`) puts the window into a bar
at the bottom of the main window, above the status bar - like a task bar,
one button per window, shown only while one is there. A click on a name
brings that window back and takes it off the bar.

Not the window manager's minimize: tiling setups (spectrwm, i3) have none,
and a minimized dialog there is gone from sight with no way back.
"""

from __future__ import annotations

import logging

from PyQt6 import sip
from PyQt6.QtCore import QEvent, QObject, Qt
from PyQt6.QtWidgets import QApplication, QMainWindow, QToolBar, QToolButton, QWidget

log = logging.getLogger(__name__)

#: Longest text of a bar button; the full title is its tooltip.
MAX_LABEL = 32


class WindowDockBar(QToolBar):
    """The bar itself: a fixed tool bar in the main window's bottom area
    (Qt puts that area above the status bar)."""

    def __init__(self, main_window: QMainWindow) -> None:
        from core.i18n import tr

        super().__init__(tr("Docked Windows"), main_window)
        self.setObjectName("axWindowDockBar")
        self.setMovable(False)
        self.setFloatable(False)
        self.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self.toggleViewAction().setVisible(False)  # not a user tool bar
        main_window.addToolBar(Qt.ToolBarArea.BottomToolBarArea, self)
        self._entries: dict[int, tuple[QWidget, QToolButton, object]] = {}
        self.hide()

    # -- the windows ---------------------------------------------------------
    def windows(self) -> list[QWidget]:
        return [w for w, _b, _a in self._entries.values()]

    def dock(self, window: QWidget) -> QToolButton:
        """Hide *window* and give it a button on the bar."""
        key = id(window)
        if key in self._entries:
            window.hide()
            return self._entries[key][1]
        button = QToolButton(self)
        button.setAutoRaise(True)
        from core.i18n import tr

        title = window.windowTitle() or window.objectName() or tr("Window")
        button.setText(_short(title))
        button.setToolTip(title)
        if not window.windowIcon().isNull():
            button.setIcon(window.windowIcon())
        button.clicked.connect(lambda _checked=False, w=window: self.restore(w))
        action = self.addWidget(button)
        self._entries[key] = (window, button, action)
        if not window.property("axDockBarWired"):
            # Once per window: the connections outlive a restore.
            window.setProperty("axDockBarWired", True)
            window.destroyed.connect(lambda _obj=None, k=key: self._drop(k))
            window.windowTitleChanged.connect(lambda text, k=key: self._retitle(k, text))
        _Unhide(window, self)
        window.hide()
        self.show()
        log.debug("Docked %r into the bar", title)
        return button

    def _retitle(self, key: int, text: str) -> None:
        entry = self._entries.get(key)
        if entry is not None and not sip.isdeleted(entry[1]):
            entry[1].setText(_short(text))
            entry[1].setToolTip(text)

    def restore(self, window: QWidget) -> None:
        """Show *window* again where it was and take it off the bar."""
        self._drop(id(window))
        if sip.isdeleted(window):
            return
        window.show()
        window.raise_()
        window.activateWindow()

    def _drop(self, key: int) -> None:
        entry = self._entries.pop(key, None)
        if entry is not None:
            _window, button, action = entry
            if not sip.isdeleted(self):
                self.removeAction(action)
            if not sip.isdeleted(button):
                button.deleteLater()
        if not self._entries and not sip.isdeleted(self):
            self.hide()


class _Unhide(QObject):
    """A docked window shown by other means (its menu entry again, a
    shortcut) leaves the bar."""

    def __init__(self, window: QWidget, bar: WindowDockBar) -> None:
        super().__init__(window)
        self._bar = bar
        window.installEventFilter(self)

    def eventFilter(self, watched, event) -> bool:
        if "_bar" not in self.__dict__:  # torn down
            return False
        if event.type() == QEvent.Type.Show and not sip.isdeleted(self._bar):
            if id(watched) in self._bar._entries:
                self._bar._drop(id(watched))
            watched.removeEventFilter(self)
            self.deleteLater()
        return False


def _short(text: str) -> str:
    return text if len(text) <= MAX_LABEL else text[: MAX_LABEL - 1] + "…"


def bar_for(widget: QWidget | None) -> WindowDockBar | None:
    """The dock bar of the main window *widget* belongs to - its parent
    chain, else the application's (first) main window with one."""
    w = widget
    while w is not None:
        bar = getattr(w, "window_dock_bar", None)
        if isinstance(bar, WindowDockBar) and not sip.isdeleted(bar):
            return bar
        w = w.parentWidget()
    app = QApplication.instance()
    if app is None:
        return None
    for top in app.topLevelWidgets():
        bar = getattr(top, "window_dock_bar", None)
        if isinstance(bar, WindowDockBar) and not sip.isdeleted(bar):
            return bar
    return None


def install(main_window: QMainWindow) -> WindowDockBar:
    """Give *main_window* its dock bar (``main_window.window_dock_bar``)."""
    bar = getattr(main_window, "window_dock_bar", None)
    if isinstance(bar, WindowDockBar):
        return bar
    bar = WindowDockBar(main_window)
    main_window.window_dock_bar = bar
    return bar


__all__ = ["MAX_LABEL", "WindowDockBar", "bar_for", "install"]
