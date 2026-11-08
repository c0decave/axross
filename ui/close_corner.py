"""The [x] button in the top-right corner of editor dialogs, and the
maximize / restore button left of it.

Window managers without title-bar buttons (tiling setups, some
Wayland compositors) leave a dialog with no visible way to close it
besides the bottom button; this puts a conventional close control in
the corner. It calls the dialog's own close handler, so the
unsaved-changes prompt applies exactly as for the bottom Close button.

The row of the two buttons is also a handle: a left drag on it (not on a
button) moves the dialog - spectrwm floats dialogs without a title bar,
so that row is what a user grabs (see :mod:`ui.window_move`).

The row is the window's title bar: its icon and name, then ``_ [] x``.
With axross's own title bars (ui.title_bar, the default) the window is
frameless and that row is the only title bar it has - no second one below
the window manager's.

The maximize corner brings what the image and media viewer had alone:
the Maximize button in the title bar, Ctrl+M maximized <-> normal, and
a button whose icon shows which of the two a click goes to.
"""

from __future__ import annotations

from collections.abc import Callable

from PyQt6.QtCore import QEvent, QObject, QSize, Qt
from PyQt6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QLayout,
    QMainWindow,
    QMenuBar,
    QSizePolicy,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from ui import title_bar
from ui import viewer_window as VW
from ui import window_move

from ui.icon_provider import icon
from ui.plain_text import plain_tooltip
from core.i18n import tr, tr_keys


def make_close_corner(parent: QWidget, handler: Callable[[], None]) -> QToolButton:
    """A flat, icon-only close button wired to *handler*."""
    btn = QToolButton(parent)
    btn.setObjectName("axCloseCorner")
    btn.setAutoRaise(True)
    btn.setIcon(icon("x", 16))
    btn.setIconSize(QSize(16, 16))
    btn.setToolTip(tr("Close") + " (Esc)")
    btn.setAccessibleName(tr("Close"))
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
            name, label = "window-restore", tr("Restore")
        else:
            name, label = "window-maximize", tr("Maximize")
        self._button.setIcon(icon(name, 16))
        self._button.setToolTip(f"{label} ({tr_keys(VW.MAXIMIZE_KEY)})")
        self._button.setAccessibleName(label)

    def eventFilter(self, watched, event) -> bool:
        # A filter keeps getting events while Python tears it down (its
        # attributes already cleared): an exception here would end the
        # process, PyQt6 aborts on one.
        if "_window" not in self.__dict__:
            return False
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


def make_dock_corner(window: QWidget) -> QToolButton:
    """The ``_`` button: puts *window* into the main window's dock bar
    (ui.window_dock_bar); without one, the window manager minimizes it."""
    btn = QToolButton(window)
    btn.setObjectName("axDockCorner")
    btn.setAutoRaise(True)
    btn.setIcon(icon("window-dock", 16))
    btn.setIconSize(QSize(16, 16))
    btn.setToolTip(tr("Put into the dock bar (a click on its name there brings it back)"))
    btn.setAccessibleName(tr("Dock"))

    def dock() -> None:
        from ui.window_dock_bar import bar_for

        bar = bar_for(window)
        if bar is not None:
            bar.dock(window)
        else:
            window.showMinimized()

    btn.clicked.connect(lambda _checked=False: dock())
    return btn


class _TitleLabel(QLabel):
    """The window's title in its button row, elided to the room left."""

    def __init__(self, window: QWidget) -> None:
        super().__init__(window)
        self.setObjectName("axCornerTitle")
        # A window title often names a file or a device: text, like the
        # window manager shows it.
        self.setTextFormat(Qt.TextFormat.PlainText)
        self._full = ""
        font = self.font()
        font.setBold(True)
        self.setFont(font)
        self.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        self.setMinimumWidth(0)
        window.windowTitleChanged.connect(self.set_full)
        self.set_full(window.windowTitle())

    def set_full(self, text: str) -> None:
        self._full = text or ""
        self.setToolTip(plain_tooltip(self._full))
        self._elide()

    def resizeEvent(self, event) -> None:  # noqa: N802 - Qt override
        super().resizeEvent(event)
        self._elide()

    def _elide(self) -> None:
        self.setText(self.fontMetrics().elidedText(
            self._full, Qt.TextElideMode.ElideRight, max(0, self.width())))


class _SoftMinimum(QObject):
    """Feedback: an extra window may be made as small as its title row.
    The minimum size the dialog set for itself becomes the size it opens
    with; from then on only the button row is the minimum (the content is
    cut off below it, not squeezed)."""

    def __init__(self, dialog: QWidget, row_height) -> None:
        super().__init__(dialog)
        self._row_height = row_height
        self._done = False
        dialog.installEventFilter(self)

    def eventFilter(self, watched, event) -> bool:
        if "_row_height" not in self.__dict__:  # torn down
            return False
        if event.type() == QEvent.Type.Show and not self._done:
            self._done = True
            self.soften(watched)
        return False

    def soften(self, dialog: QWidget) -> None:
        layout = dialog.layout()
        wanted = dialog.minimumSize().expandedTo(
            layout.minimumSize() if layout is not None else QSize())
        if layout is not None:
            layout.setSizeConstraint(QLayout.SizeConstraint.SetNoConstraint)
        if wanted.width() > dialog.width() or wanted.height() > dialog.height():
            dialog.resize(dialog.size().expandedTo(wanted))
        dialog.setMinimumSize(QSize(120, self._row_height() + 2 * _CORNER_MARGIN))


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
        if "_buttons" not in self.__dict__:  # torn down (see _FollowWindowState)
            return False
        if event.type() in (QEvent.Type.Resize, QEvent.Type.Show):
            self.place(watched)
        return False


def _install_top_row_mover(dialog: QWidget, *buttons: QToolButton) -> None:
    """A left drag above the corner buttons' lower edge moves *dialog*."""
    window_move.TopRowMover(
        dialog, lambda: max(b.geometry().bottom() for b in buttons) + _CORNER_MARGIN)


def _close(window: QWidget) -> None:
    """What the [x] does: a dialog's ``reject`` (looked up when clicked, so
    an override that stops a running job applies), any other window's
    ``close``."""
    reject = getattr(window, "reject", None)
    (reject if callable(reject) else window.close)()


def _wrap_layout(dialog: QWidget, layout: QLayout) -> QVBoxLayout:
    """Put *dialog*'s layout (a grid, a form, a row) into a body widget
    under a new vertical layout, so the title row gets a row of its own
    above it. Feedback: laid over the top-right corner, the buttons covered
    whatever sat there."""
    margins = layout.contentsMargins()
    body = QWidget(dialog)
    body.setObjectName("axWindowBody")
    body.setLayout(layout)   # Qt takes it from the dialog
    layout.setContentsMargins(0, 0, 0, margins.bottom())
    outer = QVBoxLayout(dialog)
    outer.setContentsMargins(margins.left(), margins.top(), margins.right(), 0)
    outer.addWidget(body, 1)
    return outer


def _title_row(window: QWidget, *buttons: QToolButton) -> QWidget:
    """The window's icon and name, then ``_ [] x``: its title bar."""
    row = QWidget(window)
    row.setObjectName("axTitleRow")
    # Its own height only: extra room goes to the content, not the title.
    row.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed)
    box = QHBoxLayout(row)
    box.setContentsMargins(0, 0, 0, 0)
    box.addWidget(title_bar.TitleIcon(window))
    box.addWidget(_TitleLabel(window), 1)
    for button in buttons:
        box.addWidget(button)
    return row


def add_close_corner(dialog: QWidget, on_close: Callable[[], None] | None = None) -> QToolButton | None:
    """Give *dialog* (any window: a dialog, a ``Qt.WindowType.Window``
    widget) its title row - icon, name, then ``_ [] x`` - at the top; a left
    drag on the row moves the window, a double click maximizes it. With
    axross's own title bars (ui.title_bar, the default) the window is
    frameless and the row is its only title bar.

    A layout that is not a ``QVBoxLayout`` is put below the row in a body
    of its own; only a window without any layout gets the buttons laid over
    its top-right corner. The [x] calls ``dialog.reject`` - or ``close``
    where there is none (see ``_close``), or *on_close* when given.
    Calling it twice is harmless.
    Returns the [x].
    """
    existing = dialog.findChild(QToolButton, "axCloseCorner")
    if existing is not None:
        return existing
    maximize = make_maximize_corner(dialog)
    dock = make_dock_corner(dialog)
    btn = make_close_corner(dialog, on_close or (lambda: _close(dialog)))
    layout = dialog.layout()
    if layout is not None and not isinstance(layout, QVBoxLayout):
        layout = _wrap_layout(dialog, layout)
    if layout is None:
        _KeepInCorner(dialog, dock, maximize, btn)
        _install_top_row_mover(dialog, dock, maximize, btn)
        title_bar.install(dialog, [dock, maximize, btn],
                          lambda: btn.geometry().bottom() + _CORNER_MARGIN)
        return btn
    # One row: the window's name, then _ [] x (feedback: the buttons go
    # where the name is, not on a row of their own).
    row = _title_row(dialog, dock, maximize, btn)
    layout.insertWidget(0, row)
    _install_top_row_mover(dialog, dock, maximize, btn)
    _SoftMinimum(dialog, lambda: row.sizeHint().height())
    title_bar.install(dialog, [row], lambda: row.geometry().bottom())
    return btn


class _MenuBarMover(QObject):
    """A left drag on the menu bar's empty part moves the window, a double
    click there maximizes it: the menu bar is the title bar."""

    def __init__(self, window: QMainWindow, bar: QMenuBar) -> None:
        super().__init__(bar)
        self._drag = window_move.WindowDrag(window)
        self._bar = bar
        bar.installEventFilter(self)

    def eventFilter(self, watched, event) -> bool:  # noqa: N802 - Qt override
        drag = self.__dict__.get("_drag")
        bar = self.__dict__.get("_bar")
        if drag is None or watched is not bar or not title_bar.own_title_bars():
            return False
        kind = event.type()
        if kind in (QEvent.Type.MouseButtonPress, QEvent.Type.MouseButtonDblClick):
            if event.button() != Qt.MouseButton.LeftButton \
                    or bar.actionAt(event.position().toPoint()) is not None:
                return False
            window = drag.window
            if kind == QEvent.Type.MouseButtonDblClick:
                if window is not None:
                    VW.toggle_maximized(window)
                return True
            drag.press(event.globalPosition().toPoint())
            return True
        if not drag.active:
            return False
        if kind == QEvent.Type.MouseMove:
            drag.move(event.globalPosition().toPoint())
            return True
        if kind == QEvent.Type.MouseButtonRelease:
            drag.release()
            return True
        return False


def add_title_bar(window: QMainWindow) -> QToolButton:
    """The title row of a main window (an editor, a workspace): its menu bar
    becomes the title bar - icon and name, then ``_ [] x`` at its right end;
    a window without menus gets a menu bar for that. The [x] is ``close()``,
    so unsaved work asks as always. Calling it twice is harmless."""
    existing = window.findChild(QToolButton, "axCloseCorner")
    if existing is not None:
        return existing
    bar = window.menuBar()
    maximize = make_maximize_corner(window)
    dock = make_dock_corner(window)
    btn = make_close_corner(window, window.close)
    if bar.actions():
        # The menus on the left, the name and the buttons on the right.
        corner = _title_row(window, dock, maximize, btn)
        corner.findChild(QLabel, "axCornerTitle").setMinimumWidth(220)
        bar.setCornerWidget(corner, Qt.Corner.TopRightCorner)
        parts = [corner]
    else:
        left = QWidget(bar)
        box = QHBoxLayout(left)
        box.setContentsMargins(4, 0, 0, 0)
        box.addWidget(title_bar.TitleIcon(window))
        title = _TitleLabel(window)
        title.setMinimumWidth(120)
        box.addWidget(title, 1)
        right = QWidget(bar)
        box = QHBoxLayout(right)
        box.setContentsMargins(0, 0, 4, 0)
        box.setSpacing(0)
        for button in (dock, maximize, btn):
            box.addWidget(button)
        bar.setCornerWidget(left, Qt.Corner.TopLeftCorner)
        bar.setCornerWidget(right, Qt.Corner.TopRightCorner)
        parts = [bar]
    _MenuBarMover(window, bar)
    title_bar.install(window, parts, lambda: bar.geometry().bottom())
    return btn


__all__ = ["add_close_corner", "add_title_bar", "make_close_corner", "make_dock_corner",
           "make_maximize_corner"]
