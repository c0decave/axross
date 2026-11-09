"""Guided tours over the real window (Help > Tours…).

A tour is data (:class:`Tour`, ui.tours.TOURS): steps, each with a title, a
text and the widget it explains. The widget is looked up when the step is
shown - by objectName (a widget, a QAction shown on a toolbar or in the
menu bar, or a menu, whose title in the menu bar stands for it) or by a
function of the window - so a tour never holds a widget that may be gone.

While a tour runs (:class:`TourRunner`):

* a **spotlight** dims the window around the widget and frames it - a
  child widget of the window that lets every mouse event through, so the
  real widget can be used during its step;
* a **callout** beside it says "Step k of n", the title and the text,
  with Back, Next (Finish on the last step) and End Tour; it is a child
  widget too, never a window: no grab, no modality, nothing the window
  manager must place - offscreen and on Wayland alike;
* **Escape** in the window ends the tour (an application event filter
  that sees only the key events of the tour's window, while it runs);
* a step whose widget is **missing** - a feature or dock switched off, a
  pane closed, a toolbar hidden - is skipped, and the next step shown says
  which were skipped. A dock that is open but tabbed behind another is
  brought to the front (Qt parks such a dock outside the window and still
  calls it visible, so a widget counts as shown only when it lies inside
  the window); a closed one is opened for its step only when the step says
  ``reveal`` (and closed again when the tour ends);
* the widget's rectangle is **read afresh** every time the callout is
  placed - a dock just opened or raised is laid out a moment later, and a
  rectangle kept from the lookup framed its old, smaller size;
* a step may also **frame** a second area (``TourStep.frame``): the context
  of the widget it points at, such as both panes around the target pane's
  ◎ button. It is left undimmed and outlined more thinly.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass

from PyQt6 import sip
from PyQt6.QtCore import QEvent, QObject, QRect, QRectF, Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QAction, QColor, QPainter, QPainterPath, QPen
from PyQt6.QtWidgets import (
    QApplication,
    QDialog,
    QDialogButtonBox,
    QDockWidget,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMenu,
    QPushButton,
    QToolBar,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core.i18n import tr
from ui.close_corner import add_close_corner
from ui.icon_provider import set_window_icon

log = logging.getLogger(__name__)

#: A step's widget: an objectName, several (the first one shown wins: a
#: toolbar button, else the menu entry), or a function of the window that
#: returns a widget, ``(widget, rect in its coordinates)``, a QAction or None.
Target = str | tuple[str, ...] | Callable[[QWidget], object]

#: How often a running step follows its widget (moved, resized, gone).
FOLLOW_MS = 250
#: The callout's width (less on a narrower window).
CALLOUT_WIDTH = 360
#: Room between the widget and the callout, and the window's edge.
GAP = 12


@dataclass(frozen=True)
class TourStep:
    title: str
    text: str
    target: Target
    #: May be missing in a default window (a second pane, a toolbar the
    #: user hid): tests/test_tours.py accepts it missing.
    optional: bool = False
    #: A closed dock the step points at is opened for the step.
    reveal: bool = False
    #: A second area left undimmed around the widget, outlined more thinly
    #: (the same kinds of lookup as *target*; missing: nothing extra).
    frame: Target | None = None


@dataclass(frozen=True)
class Tour:
    id: str
    title: str
    summary: str
    steps: tuple[TourStep, ...]


# -- finding a step's widget ------------------------------------------------------------------


def _alive(obj) -> bool:
    return obj is not None and not sip.isdeleted(obj)


def _menu_title_spot(window: QWidget, menu: QMenu):
    bar = window.menuBar() if isinstance(window, QMainWindow) else None
    if bar is None or menu.menuAction() not in bar.actions():
        return None
    return bar, bar.actionGeometry(menu.menuAction())


def action_spot(window: QWidget, action: QAction):
    """Where *action* shows: its toolbar button, else the menu bar title of
    the menu it is in (or its own, for a menu's action); None if neither."""
    for bar in window.findChildren(QToolBar):
        if action in bar.actions() and bar.isVisible():
            button = bar.widgetForAction(action)
            if _alive(button) and button.isVisible():
                return button, button.rect()
    if isinstance(window, QMainWindow):
        menubar = window.menuBar()
        if action in menubar.actions():
            return menubar, menubar.actionGeometry(action)
        for owner in action.associatedObjects():
            if isinstance(owner, QMenu):
                top = owner
                while isinstance(top.parent(), QMenu) and top.menuAction() not in menubar.actions():
                    top = top.parent()
                spot = _menu_title_spot(window, top)
                if spot is not None:
                    return spot
    return None


def find_named(window: QWidget, name: str):
    """The widget, menu or action of objectName *name* in *window*."""
    widget = window.findChild(QWidget, name)
    if isinstance(widget, QMenu):
        return _menu_title_spot(window, widget)
    if widget is not None:
        return widget
    action = window.findChild(QAction, name)
    if action is not None:
        return action_spot(window, action)
    return None


def _as_spot(window: QWidget, found):
    """``(widget, rect)`` of a lookup's answer, or None."""
    if isinstance(found, QAction):
        found = action_spot(window, found)
    if isinstance(found, QWidget):
        return (found, found.rect()) if _alive(found) else None
    if isinstance(found, tuple) and len(found) == 2 and isinstance(found[0], QWidget):
        return found if _alive(found[0]) else None
    return None


def resolve(window: QWidget, target: Target):
    """``(widget, rect)`` of *target* in *window*, or None (never raises)."""
    if isinstance(target, tuple):
        spots = [resolve(window, name) for name in target]
        return next((spot for spot in spots if shown(spot)),
                    next((spot for spot in spots if spot is not None), None))
    try:
        found = target(window) if callable(target) else find_named(window, target)
        return _as_spot(window, found)
    except Exception:  # noqa: BLE001 - a broken lookup is a missing widget
        log.debug("tour: lookup of %r failed", target, exc_info=True)
        return None


def _dock_of(widget: QWidget) -> QDockWidget | None:
    while widget is not None:
        if isinstance(widget, QDockWidget):
            return widget
        widget = widget.parentWidget()
    return None


def window_rect(spot) -> QRect:
    """The spot's rectangle in the coordinates of its widget's window."""
    widget, rect = spot
    host = widget.window()
    return QRect(widget.mapTo(host, rect.topLeft()), rect.size())


def shown(spot) -> bool:
    """Whether a spot can be pointed at: visible, with a size, and inside its
    window. Qt parks a dock tabbed behind another outside the window and
    still calls it visible: the tour framed an empty corner for it."""
    if spot is None:
        return False
    widget, rect = spot
    if not (_alive(widget) and widget.isVisible() and widget.window().isVisible()
            and rect.width() > 0 and rect.height() > 0):
        return False
    box = window_rect(spot)
    area = widget.window().rect()
    inside = box.intersected(area)
    return inside.width() > 0 and inside.height() > 0 and area.contains(box.center())


# -- the spotlight and the callout -----------------------------------------------------------


class Spotlight(QWidget):
    """Dims the window around a rectangle and frames it; every mouse event
    goes through to the widgets below."""

    #: 90 was all but invisible on the dark theme (#1a1c22 -> #111318).
    DIM = QColor(0, 0, 0, 150)
    FRAME = QColor("#f39c12")

    def __init__(self, host: QWidget) -> None:
        super().__init__(host)
        self.setObjectName("axTourSpotlight")
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
        self.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.hole = QRect()
        #: The step's second area (TourStep.frame), or an empty rectangle.
        self.context = QRect()
        self.setGeometry(host.rect())

    def set_hole(self, rect: QRect, context: QRect | None = None) -> None:
        self.setGeometry(self.parentWidget().rect())
        self.hole = QRect(rect)
        self.context = QRect(context) if context is not None else QRect()
        self.update()

    def paintEvent(self, _event) -> None:  # noqa: N802 - Qt
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        hole = self.hole.adjusted(-4, -4, 4, 4)
        dim = QPainterPath()
        dim.addRect(QRectF(self.rect()))
        cut = QPainterPath()
        cut.addRoundedRect(QRectF(hole), 6, 6)
        context = self.context.adjusted(-2, -2, 2, 2) if not self.context.isEmpty() else None
        if context is not None:
            cut.addRoundedRect(QRectF(context), 6, 6)
            cut = cut.simplified()
        painter.fillPath(dim.subtracted(cut), self.DIM)
        if context is not None:
            painter.setPen(QPen(self.FRAME, 1.5, Qt.PenStyle.DashLine))
            painter.drawRoundedRect(context, 6, 6)
        painter.setPen(QPen(self.FRAME, 3))
        painter.drawRoundedRect(hole, 6, 6)
        painter.end()


class Callout(QFrame):
    """The step's box: Step k of n, title, text, skipped steps, buttons."""

    def __init__(self, host: QWidget) -> None:
        super().__init__(host)
        self.setObjectName("axTourCallout")
        self.setFrameShape(QFrame.Shape.StyledPanel)
        self.setAutoFillBackground(True)
        # With a style sheet Qt paints the frame itself: without a background
        # in it the box stayed transparent and its text ran over the widgets
        # below (autoFillBackground no longer applies).
        self.setStyleSheet(
            "#axTourCallout { border: 2px solid #f39c12; border-radius: 6px;"
            " background-color: palette(window); }")
        self.step_label = QLabel()
        self.step_label.setProperty("role", "muted")
        self.title_label = QLabel()
        self.title_label.setStyleSheet("font-weight: bold;")
        self.title_label.setWordWrap(True)
        self.text_label = QLabel()
        self.text_label.setWordWrap(True)
        self.text_label.setTextFormat(Qt.TextFormat.PlainText)
        self.skip_label = QLabel()
        self.skip_label.setWordWrap(True)
        self.skip_label.setTextFormat(Qt.TextFormat.PlainText)
        self.skip_label.setStyleSheet("font-style: italic;")
        self.skip_label.hide()
        for label in (self.title_label, self.text_label, self.skip_label):
            label.setTextFormat(Qt.TextFormat.PlainText)
        self.back_button = QPushButton(tr("Back"))
        self.next_button = QPushButton(tr("Next"))
        self.end_button = QPushButton(tr("End Tour"))
        self.end_button.setToolTip(tr("End the tour (Esc)"))
        row = QHBoxLayout()
        row.addWidget(self.back_button)
        row.addWidget(self.next_button)
        row.addStretch(1)
        row.addWidget(self.end_button)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.addWidget(self.step_label)
        layout.addWidget(self.title_label)
        layout.addWidget(self.text_label)
        layout.addWidget(self.skip_label)
        layout.addLayout(row)

    def fit_height(self, width: int) -> int:
        layout = self.layout()
        if layout.hasHeightForWidth():
            return layout.totalHeightForWidth(width)
        return self.sizeHint().height()


def place(box: QRect, size: tuple[int, int], area: QRect) -> QRect:
    """Where a callout of *size* goes in *area*: right of *box*, else left,
    below, above; else in the bottom right corner of *area*. Always inside
    *area* (as far as it is large enough)."""
    beside = place_beside(box, size, area)
    if beside is not None:
        return beside
    width, height = size
    inner = area.adjusted(GAP // 2, GAP // 2, -GAP // 2, -GAP // 2)
    corner = QRect(0, 0, min(width, inner.width()), min(height, inner.height()))
    corner.moveBottomRight(inner.bottomRight())
    return corner


def place_beside(box: QRect, size: tuple[int, int], area: QRect,
                 sides: str = "rlba") -> QRect | None:
    """:func:`place` without the corner: None when no side of *box* has room.
    *sides*: the sides tried, in order - right, left, below, above."""
    width, height = size
    by_side = {
        "r": QRect(box.right() + GAP, box.top(), width, height),
        "l": QRect(box.left() - GAP - width, box.top(), width, height),
        "b": QRect(box.left(), box.bottom() + GAP, width, height),
        "a": QRect(box.left(), box.top() - GAP - height, width, height),
    }
    candidates = [by_side[side] for side in sides]
    inner = area.adjusted(GAP // 2, GAP // 2, -GAP // 2, -GAP // 2)
    for rect in candidates:
        moved = QRect(rect)
        # slide along the side it is on, but never over the box
        if moved.left() >= inner.left() and moved.right() <= inner.right():
            if moved.bottom() > inner.bottom():
                moved.moveBottom(inner.bottom())
            if moved.top() < inner.top():
                moved.moveTop(inner.top())
        if moved.top() >= inner.top() and moved.bottom() <= inner.bottom():
            if moved.right() > inner.right():
                moved.moveRight(inner.right())
            if moved.left() < inner.left():
                moved.moveLeft(inner.left())
        if inner.contains(moved) and not moved.intersects(box):
            return moved
    return None


# -- running a tour ----------------------------------------------------------------------------


class TourRunner(QObject):
    """One running tour over *window*. ``finished(reason)``: "done" (past the
    last step), "ended" (End Tour), "escape", "nothing" (no step could be
    shown) or "replaced" (another tour started)."""

    finished = pyqtSignal(str)

    def __init__(self, window: QWidget, tour: Tour, parent: QObject | None = None) -> None:
        super().__init__(parent or window)
        self.window = window
        self.tour = tour
        self.index = -1
        #: Titles of the steps skipped on the way to the step shown.
        self.skipped: list[str] = []
        self.spot = None
        self.host: QWidget | None = None
        self.spotlight: Spotlight | None = None
        self.callout: Callout | None = None
        self.running = False
        self.reason = ""
        self._revealed: list[QDockWidget] = []
        #: The front dock of each tab group a step raised another dock in:
        #: in front again when the tour ends.
        self._fronts: list[QDockWidget] = []
        self._follow = QTimer(self)
        self._follow.setInterval(FOLLOW_MS)
        self._follow.timeout.connect(self._follow_step)

    # -- the public moves ------------------------------------------------------------------

    @property
    def step(self) -> TourStep | None:
        return self.tour.steps[self.index] if 0 <= self.index < len(self.tour.steps) else None

    def start(self) -> bool:
        """Show the first step there is; False when there is none."""
        if self.running:
            return True
        self.running = True
        app = QApplication.instance()
        if app is not None:
            app.installEventFilter(self)
        self._follow.start()
        log.info("tour %s started", self.tour.id)
        self._go(0, +1)
        return self.running

    def next(self) -> None:
        if self.running:
            self._go(self.index + 1, +1)

    def back(self) -> None:
        if self.running and self.index > 0:
            self._go(self.index - 1, -1)

    def end(self, reason: str = "ended") -> None:
        if not self.running:
            return
        self.running = False
        self.reason = reason
        self._follow.stop()
        app = QApplication.instance()
        if app is not None:
            app.removeEventFilter(self)
        for widget in (self.callout, self.spotlight):
            if _alive(widget):
                widget.hide()
                widget.deleteLater()
        self.callout = self.spotlight = None
        for dock in self._revealed:
            if _alive(dock):
                dock.close()
        self._revealed = []
        for dock in self._fronts:
            if _alive(dock) and not dock.isHidden():
                dock.raise_()
        self._fronts = []
        log.info("tour %s finished (%s) at step %d", self.tour.id, reason, self.index + 1)
        self._say_goodbye(reason)
        self.finished.emit(reason)

    # -- steps -----------------------------------------------------------------------------

    def locate(self, step: TourStep):
        """``(widget, rect)`` of *step* now, or None when it is not in the
        window. A dock tabbed behind another comes to the front; a closed
        one is opened when the step says ``reveal``."""
        spot = resolve(self.window, step.target)
        if spot is None:
            return None
        dock = _dock_of(spot[0])
        if dock is not None and not shown(spot):
            if dock.isHidden() and not dock.toggleViewAction().isChecked():
                if step.reveal:  # closed: opened for the step
                    dock.show()
                    dock.raise_()
                    self._revealed.append(dock)
            else:
                # Open but tabbed behind another dock: Qt keeps it "visible"
                # outside the window, so isVisible() alone missed it.
                self._remember_front(dock)
                dock.raise_()
            spot = resolve(self.window, step.target)
        return spot if shown(spot) else None

    def _remember_front(self, dock: QDockWidget) -> None:
        """Note the dock in front of *dock*'s tab group (once per group)."""
        window = self.window
        if not isinstance(window, QMainWindow):
            return
        group = [dock, *window.tabifiedDockWidgets(dock)]
        if any(front in group for front in self._fronts):
            return
        front = next((d for d in group if shown((d, d.rect()))), None)
        if front is not None and front is not dock:
            self._fronts.append(front)

    def _fresh_spot(self):
        """The current step's spot, looked up again (no dock is raised)."""
        step = self.step
        if step is None:
            return None
        spot = resolve(self.window, step.target)
        return spot if shown(spot) else None

    def _frame_rect(self) -> QRect | None:
        """The step's second area in the host's coordinates, or None."""
        step = self.step
        if step is None or step.frame is None or not _alive(self.host):
            return None
        spot = resolve(self.window, step.frame)
        if not shown(spot) or spot[0].window() is not self.host:
            return None
        widget, rect = spot
        box = QRect(widget.mapTo(self.host, rect.topLeft()), rect.size())
        box = box.intersected(self.host.rect())
        return box if not box.isEmpty() else None

    def _go(self, start: int, direction: int, skipped: list[str] | None = None) -> None:
        steps = self.tour.steps
        skipped = list(skipped or [])
        i = start
        while 0 <= i < len(steps):
            spot = self.locate(steps[i])
            if spot is not None:
                self._show(i, spot, skipped)
                return
            log.info("tour %s: step %d (%s) skipped, its widget is not in the window",
                     self.tour.id, i + 1, steps[i].title)
            skipped.append(tr(steps[i].title))
            i += direction
        if direction > 0:
            self.skipped = skipped
            self.end("done" if self.index >= 0 else "nothing")
        elif self.step is not None and self.spot is not None:
            # Nothing earlier to show: stay, and say why.
            self._show(self.index, self.spot, skipped)

    def _show(self, index: int, spot, skipped: list[str]) -> None:
        self.index = index
        self.spot = spot
        self.skipped = skipped
        host = spot[0].window()
        if host is not self.host or not _alive(self.callout):
            self._build(host)
        step = self.tour.steps[index]
        callout = self.callout
        callout.step_label.setText(
            tr("Step {k} of {n}").format(k=index + 1, n=len(self.tour.steps)))
        callout.title_label.setText(tr(step.title))
        callout.text_label.setText(tr(step.text))
        if skipped:
            callout.skip_label.setText(
                tr("Skipped, not in this window (switched off, closed or hidden): {steps}")
                .format(steps=", ".join(skipped)))
        callout.skip_label.setVisible(bool(skipped))
        callout.back_button.setEnabled(index > 0)
        last = index == len(self.tour.steps) - 1
        callout.next_button.setText(tr("Finish") if last else tr("Next"))
        self._place()
        callout.show()
        self.spotlight.show()
        callout.next_button.setFocus()
        # A dock just opened or raised is laid out a moment later: place again.
        QTimer.singleShot(0, self._place)

    def _build(self, host: QWidget) -> None:
        for widget in (self.callout, self.spotlight):
            if _alive(widget):
                widget.deleteLater()
        self.host = host
        self.spotlight = Spotlight(host)
        self.callout = Callout(host)
        self.callout.back_button.clicked.connect(lambda _c=False: self.back())
        self.callout.next_button.clicked.connect(lambda _c=False: self.next())
        self.callout.end_button.clicked.connect(lambda _c=False: self.end("ended"))

    def _target_rect(self) -> QRect:
        widget, rect = self.spot
        top_left = widget.mapTo(self.host, rect.topLeft())
        return QRect(top_left, rect.size()).intersected(self.host.rect())

    def _place(self) -> None:
        """Frame the step's widget and put the callout beside it - with the
        widget's rectangle read now, not the one of the lookup."""
        if not (self.running and _alive(self.host) and _alive(self.callout)):
            return
        fresh = self._fresh_spot()
        if fresh is not None and fresh[0].window() is self.host:
            self.spot = fresh
        elif not shown(self.spot):
            return  # gone: _follow_step moves on
        box = self._target_rect()
        context = self._frame_rect()
        area = self.host.rect()
        width = max(160, min(CALLOUT_WIDTH, area.width() - 2 * GAP))
        height = min(self.callout.fit_height(width), max(80, area.height() - GAP))
        size = (width, height)
        spot = None
        if context is not None:
            # Beside the whole framed area when there is room, so the callout
            # covers neither the widget nor its context; else below or above
            # the widget, off the row it sits in (a pane header's badges).
            spot = (place_beside(context.united(box), size, area)
                    or place_beside(box, size, area, "barl"))
        self.callout.setGeometry(spot if spot is not None else place(box, size, area))
        self.spotlight.set_hole(box, context)
        self.spotlight.raise_()
        self.callout.raise_()

    def _follow_step(self) -> None:
        """The widget moved, was resized - or went: then on to the next."""
        if not self.running or self.step is None:
            return
        if self._fresh_spot() is not None:
            self._place()
            return
        again = self.locate(self.step)
        if again is not None:
            self.spot = again
            self._place()
            return
        log.info("tour %s: the widget of step %d went away", self.tour.id, self.index + 1)
        self._go(self.index + 1, +1, [tr(self.step.title)])

    def _say_goodbye(self, reason: str) -> None:
        bar = getattr(self.window, "statusBar", None)
        bar = bar() if callable(bar) else None
        if bar is None:
            return
        if reason == "nothing":
            text = tr("The tour has nothing to show in this window: its parts are switched "
                      "off or closed.")
        elif reason == "done":
            text = tr("Tour finished – Help → Tours… has the others, F1 the handbook.")
        else:
            text = tr("Tour ended – Help → Tours… starts it again.")
        bar.showMessage(text, 8000)

    # -- events ----------------------------------------------------------------------------

    def _in_tour_window(self, obj) -> bool:
        host = self.host or self.window
        if isinstance(obj, QWidget):
            return _alive(obj) and obj.window() is host
        handle = host.windowHandle() if _alive(host) else None
        return handle is not None and obj is handle

    def eventFilter(self, obj, event) -> bool:  # noqa: N802 - Qt
        kind = event.type()
        if kind in (QEvent.Type.KeyPress, QEvent.Type.ShortcutOverride):
            if event.key() == Qt.Key.Key_Escape and self._in_tour_window(obj):
                if kind == QEvent.Type.ShortcutOverride:
                    event.accept()  # no shortcut takes Esc while the tour runs
                else:
                    self.end("escape")
                return True
        elif kind == QEvent.Type.Resize and obj is self.host:
            QTimer.singleShot(0, self._place)
        return False


# -- Help > Tours… ---------------------------------------------------------------------------


class ToursDialog(QDialog):
    """The tours, one line each; Start Tour (or a double click) starts one
    over *window* and closes the list."""

    def __init__(self, window: QWidget, tours: tuple[Tour, ...],
                 parent: QWidget | None = None) -> None:
        super().__init__(parent if parent is not None else window)
        set_window_icon(self, "compass")
        self.setWindowTitle(tr("Tours"))
        self._window = window
        self._tours = tours
        intro = QLabel(tr("Each tour points at the real parts of the window and says how to "
                          "use them well. Esc or End Tour stops it; F1 opens the handbook."))
        intro.setWordWrap(True)
        self.list = QTreeWidget()
        self.list.setColumnCount(2)
        self.list.setHeaderLabels([tr("Tour"), tr("What it shows")])
        self.list.setRootIsDecorated(False)
        self.list.setWordWrap(True)
        for tour in tours:
            item = QTreeWidgetItem([tr(tour.title), tr(tour.summary)])
            item.setData(0, Qt.ItemDataRole.UserRole, tour.id)
            item.setToolTip(1, tr(tour.summary))
            self.list.addTopLevelItem(item)
        if tours:
            self.list.setCurrentItem(self.list.topLevelItem(0))
        self.list.resizeColumnToContents(0)
        # itemActivated only: it comes with a double click as well (and with
        # Return); itemDoubleClicked on top of it started the tour twice.
        self.list.itemActivated.connect(lambda _item, _col=0: self.start_selected())

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        self.start_button = buttons.addButton(tr("Start Tour"),
                                              QDialogButtonBox.ButtonRole.AcceptRole)
        self.start_button.setDefault(True)
        buttons.accepted.connect(self.start_selected)
        # The narrated video of the selected tour (core.tour_videos): only
        # when this axross knows the videos' release.
        from core import tour_videos

        self.video_button = buttons.addButton(tr("Watch Video"),
                                              QDialogButtonBox.ButtonRole.ActionRole)
        self.video_button.setToolTip(tr("Download the narrated video of this tour once and "
                                        "play it in your video player"))
        self.video_button.clicked.connect(lambda _checked=False: self.watch_selected())
        self.video_button.setVisible(tour_videos.has_videos())
        self._video_fetch: _VideoFetch | None = None
        buttons.rejected.connect(self.reject)
        layout = QVBoxLayout(self)
        layout.addWidget(intro)
        layout.addWidget(self.list, 1)
        layout.addWidget(buttons)
        add_close_corner(self)
        # F1: its section of the handbook - the main window's F1 does not reach this window.
        from ui.handbook import install_help_key

        install_help_key(self, "handbook")
        self.resize(720, 360)

    def selected_id(self) -> str:
        item = self.list.currentItem()
        return item.data(0, Qt.ItemDataRole.UserRole) if item is not None else ""

    def watch_selected(self):
        """Fetch (or take from the cache) the selected tour's video in the
        interface language and open it with the system's video player.
        The fetch runs in a thread; the button shows its progress."""
        from core import tour_videos
        from core.i18n import active

        tour_id = self.selected_id()
        video = tour_videos.video_for(tour_id, active().language) if tour_id else None
        if video is None:
            self.video_button.setToolTip(tr("This tour has no video yet."))
            return None
        if self._video_fetch is not None:
            return self._video_fetch
        fetch = _VideoFetch(video)
        fetch.progress.connect(self._video_progress)
        fetch.finished_ok.connect(self._video_ready)
        fetch.failed.connect(self._video_failed)
        self._video_fetch = fetch
        self.video_button.setEnabled(False)
        fetch.start()
        return fetch

    def _video_progress(self, done: int, total: int) -> None:
        if total > 0:
            self.video_button.setText(tr("Downloading… {percent} %").format(
                percent=min(100, done * 100 // total)))

    def _video_done(self) -> None:
        self._video_fetch = None
        self.video_button.setEnabled(True)
        self.video_button.setText(tr("Watch Video"))

    def _video_ready(self, path: str) -> None:
        from core.desktop_open import open_url

        self._video_done()
        # core.desktop_open: the player starts with a clean environment
        # (no LD_LIBRARY_PATH of a one-file binary), like every other opener.
        if not open_url(path):
            self._video_failed(tr("No video player opened {path}.").format(path=path))

    def _video_failed(self, error) -> None:
        """A message in the interface language - "not published yet", the
        network sentence of core.user_errors, or a generic one with the
        detail - and Start Tour as the alternative: the tour shows the same
        steps in the app itself. The technical text is in the log."""
        from PyQt6.QtWidgets import QMessageBox

        self._video_done()
        sentence = error.user_text() if hasattr(error, "user_text") else str(error)
        # Information, not a warning: nothing is broken, the tour itself works.
        box = QMessageBox(QMessageBox.Icon.Information, tr("Tour video"), sentence,
                          QMessageBox.StandardButton.NoButton, self)
        box.setInformativeText(tr("Start Tour shows the same steps in axross itself."))
        start = box.addButton(tr("Start Tour"), QMessageBox.ButtonRole.AcceptRole)
        box.addButton(tr("Close"), QMessageBox.ButtonRole.RejectRole)
        box.setDefaultButton(start)
        try:
            box.exec()
            if box.clickedButton() is start and self.selected_id():
                self.start_selected()
        finally:
            box.deleteLater()

    def done(self, result: int) -> None:  # noqa: D401 - Qt
        if self._video_fetch is not None:
            self._video_fetch.cancel.set()
        super().done(result)

    def start_selected(self) -> TourRunner | None:
        tour_id = self.selected_id()
        if not tour_id:
            return None
        self.accept()
        starter = getattr(self._window, "start_tour", None)
        return starter(tour_id) if callable(starter) else None


class _VideoFetch(QObject):
    """core.tour_videos.fetch in a thread; the results come back as signals
    (queued to the dialog's thread)."""

    progress = pyqtSignal(object, object)  # byte counts: object, not a 32-bit int
    finished_ok = pyqtSignal(str)
    failed = pyqtSignal(object)  # a core.tour_videos.VideoError, or a sentence

    def __init__(self, video) -> None:
        # No Qt parent: the dialog (WA_DeleteOnClose) may be deleted while
        # the thread still runs, and an object deleted with it would be
        # emitted from. The thread holds this object until it ends; Qt
        # drops queued signals to a receiver that is gone.
        super().__init__()
        import threading

        self.video = video
        self.cancel = threading.Event()
        self._thread = threading.Thread(target=self._run, name="tour-video", daemon=True)

    def start(self) -> None:
        self._thread.start()

    def _run(self) -> None:
        from core import self_update, tour_videos

        try:
            path = tour_videos.fetch(self.video, progress=self._progress, cancel=self.cancel)
        except self_update.Cancelled:
            return
        except tour_videos.VideoError as exc:
            log.info("tour video %s: %s", self.video.name, exc)
            self._emit(self.failed, exc)
        except Exception as exc:  # noqa: BLE001 - a thread must report, not die silently
            log.exception("tour video fetch failed")
            self._emit(self.failed, tour_videos.VideoError(str(exc) or type(exc).__name__))
        else:
            self._emit(self.finished_ok, str(path))

    def _progress(self, done: int, total: int) -> None:
        self._emit(self.progress, done, total)

    def _emit(self, signal, *args) -> None:
        if not self.cancel.is_set():
            signal.emit(*args)


__all__ = [
    "Callout",
    "Spotlight",
    "Target",
    "Tour",
    "TourRunner",
    "TourStep",
    "ToursDialog",
    "action_spot",
    "find_named",
    "place",
    "place_beside",
    "resolve",
    "shown",
    "window_rect",
]
