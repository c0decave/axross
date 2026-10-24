"""The order of a toolbar's buttons: moved by drag and drop, kept across starts.

Each button's QAction carries a stable id in the ``axToolId`` property
(ui.main_window sets it when it builds the bars). A bar's order is the list
of those ids, with :data:`SEPARATOR` where a separator sits; session.json
keeps it per bar (``window`` -> :data:`ORDER_KEY` -> {bar object name: list}).

A stored order is merged with the bar's default (:func:`merge`): an id this
version does not have is ignored, and a tool the stored order does not name
(added by a later version) appears at its default place.

The drag (:class:`ToolbarReorder`) follows the mouse with an event filter on
the bar's buttons instead of a QDrag: a press, a move along the bar beyond
the drag distance, a release between two buttons. A plain click stays a
click; a drag never triggers the button.
"""

from __future__ import annotations

import logging

from PyQt6 import sip
from PyQt6.QtCore import QEvent, QObject, QPoint, Qt, QTimer, pyqtSignal
from PyQt6.QtWidgets import QApplication, QFrame, QToolBar, QToolButton

log = logging.getLogger(__name__)

#: Key of the stored orders in session.json's ``window`` object.
ORDER_KEY = "toolbar_order"
#: A separator in an order list.
SEPARATOR = "|"
#: The QAction property that holds a button's stable id.
TOOL_ID_PROPERTY = "axToolId"
#: Width of the drop indicator, in pixels.
INDICATOR_WIDTH = 2


def parse(value: object) -> dict[str, list[str]]:
    """The stored orders of *value* (session.json's ``toolbar_order``): only
    string keys with a list of strings survive; anything else reads as no
    stored order."""
    if not isinstance(value, dict):
        return {}
    out: dict[str, list[str]] = {}
    for bar, order in value.items():
        if isinstance(bar, str) and isinstance(order, list) and order \
                and all(isinstance(item, str) for item in order):
            out[bar] = list(order)
    return out


def _tidy(order: list[str]) -> list[str]:
    """No separator at either end, none twice in a row."""
    out: list[str] = []
    for item in order:
        if item == SEPARATOR and (not out or out[-1] == SEPARATOR):
            continue
        out.append(item)
    while out and out[-1] == SEPARATOR:
        out.pop()
    return out


def merge(saved: list | None, default: list[str]) -> list[str]:
    """*saved* brought to the tools of *default*: unknown and repeated ids
    dropped, each tool missing from *saved* placed right after the tool
    before it in *default* (first when none of those is present)."""
    known = {item for item in default if item != SEPARATOR}
    seen: set[str] = set()
    result: list[str] = []
    for item in saved or ():
        if item == SEPARATOR:
            result.append(item)
        elif isinstance(item, str) and item in known and item not in seen:
            seen.add(item)
            result.append(item)
    if not seen:
        return list(default)
    result = _tidy(result)
    for index, item in enumerate(default):
        if item == SEPARATOR or item in seen:
            continue
        previous = [p for p in default[:index] if p != SEPARATOR and p in seen]
        position = result.index(previous[-1]) + 1 if previous else 0
        result.insert(position, item)
        seen.add(item)
    return _tidy(result)


def tool_id(action) -> str | None:
    value = action.property(TOOL_ID_PROPERTY)
    return str(value) if value else None


def _raw_order(bar: QToolBar) -> list[str]:
    out: list[str] = []
    for action in bar.actions():
        if action.isSeparator():
            out.append(SEPARATOR)
        elif tool_id(action):
            out.append(tool_id(action))
    return out


def bar_order(bar: QToolBar) -> list[str]:
    """The ids of *bar*'s buttons in their order, separators included
    (buttons without an id are left out; no separator at an end or twice
    in a row)."""
    return _tidy(_raw_order(bar))


def apply_order(bar: QToolBar, order: list[str]) -> None:
    """Rearrange *bar*'s actions to *order* (a :func:`merge` result). Actions
    without an id keep their place at the end; separators are reused, and
    the ones left over are deleted."""
    if _raw_order(bar) == order:
        return
    by_id = {tool_id(a): a for a in bar.actions() if not a.isSeparator() and tool_id(a)}
    others = [a for a in bar.actions() if not a.isSeparator() and not tool_id(a)]
    separators = [a for a in bar.actions() if a.isSeparator()]
    for action in bar.actions():
        bar.removeAction(action)
    for item in order:
        if item == SEPARATOR:
            if separators:
                bar.addAction(separators.pop(0))
            else:
                bar.addSeparator()
        elif item in by_id:
            bar.addAction(by_id.pop(item))
    for action in list(by_id.values()) + others:  # not in *order*: kept, at the end
        bar.addAction(action)
    for action in separators:
        action.deleteLater()


#: The Python state of a ToolbarReorder; without it (torn down) it does nothing.
_STATE = frozenset({"_indicator", "_button", "_start", "_dragging"})


class ToolbarReorder(QObject):
    """Drag and drop of the buttons of one toolbar. ``reordered`` is emitted
    after a drop changed the order."""

    reordered = pyqtSignal(object)

    def __init__(self, bar: QToolBar) -> None:
        # The bar is this object's Qt parent and is never held in Python: the
        # bar owns the filter, and a reference back would be a cycle the
        # collector clears while the bar's teardown events still arrive here.
        super().__init__(bar)
        indicator = QFrame(bar)
        indicator.setObjectName("axToolbarDropIndicator")
        indicator.setFrameShape(QFrame.Shape.NoFrame)
        indicator.setAutoFillBackground(True)
        indicator.setStyleSheet("background: palette(highlight);")
        indicator.hide()
        self._indicator = indicator
        self._button: QToolButton | None = None
        self._start = QPoint()
        self._dragging = False
        bar.visibilityChanged.connect(self._follow_visibility)
        self.arm()

    @property
    def bar(self) -> QToolBar | None:
        parent = self.parent()
        return parent if isinstance(parent, QToolBar) else None

    @property
    def indicator(self) -> QFrame | None:
        """The line that shows where a drop lands (None once torn down)."""
        return self.__dict__.get("_indicator")

    # -- the buttons ------------------------------------------------------
    def arm(self) -> None:
        """Watch every button of the bar while it is shown (again after the
        bar rebuilt some: a moved action gets a new button). Installing
        twice is harmless; a hidden bar is left alone (see :meth:`disarm`)."""
        bar = self.bar
        if bar is None or not bar.isVisible():
            return
        for button in bar.findChildren(QToolButton):
            action = button.defaultAction()
            if action is not None and tool_id(action):
                button.installEventFilter(self)

    def _follow_visibility(self, visible: bool) -> None:
        if "_dragging" not in self.__dict__:
            return
        if visible:
            self.arm()
        else:
            self.disarm()

    def disarm(self) -> None:
        """Stop watching the buttons. The window calls it when it hides,
        which a close does before the window can be destroyed: a Python
        event filter must not get the Destroy events of half-destroyed
        buttons - PyQt crashed at exit then (4 of 10 runs of
        tests/test_media_viewer_e2e.py, tests/test_toolbar_reorder.py)."""
        bar = self.bar
        if bar is None:
            return
        indicator = self.indicator
        if indicator is not None:
            indicator.hide()
        if "_dragging" in self.__dict__:
            self._button, self._dragging = None, False
        for button in bar.findChildren(QToolButton):
            button.removeEventFilter(self)

    def eventFilter(self, obj, event) -> bool:  # noqa: N802 - Qt
        # A filter keeps getting events while Python tears it down: an
        # exception here would end the process (PyQt6 aborts on one).
        if not _STATE <= self.__dict__.keys():
            return False
        bar = self.bar
        if bar is None:
            return False
        kind = event.type()
        if kind == QEvent.Type.MouseButtonPress:
            if event.button() == Qt.MouseButton.LeftButton and isinstance(obj, QToolButton):
                self._button = obj
                self._start = event.globalPosition().toPoint()
                self._dragging = False
            return False
        if obj is not self._button:
            return False
        if kind == QEvent.Type.MouseMove:
            if not event.buttons() & Qt.MouseButton.LeftButton:
                return False
            point = event.globalPosition().toPoint()
            if not self._dragging:
                if (point - self._start).manhattanLength() < QApplication.startDragDistance():
                    return False
                self._dragging = True
                obj.setDown(False)
            self._show_indicator(bar.mapFromGlobal(point))
            return True
        if kind == QEvent.Type.MouseButtonRelease and event.button() == Qt.MouseButton.LeftButton:
            dragging, self._dragging, self._button = self._dragging, False, None
            if not dragging:
                return False
            self._indicator.hide()
            obj.setDown(False)
            action = obj.defaultAction()
            before = self.drop_target(bar.mapFromGlobal(event.globalPosition().toPoint()))
            # Later: moving the action deletes this button, which is still
            # inside its own event handler.
            QTimer.singleShot(0, lambda a=action, b=before: self._move(a, b))
            return True  # no click: the drag is not a press of the button
        return False

    # -- where a drop lands -----------------------------------------------
    @staticmethod
    def _horizontal(bar: QToolBar) -> bool:
        return bar.orientation() == Qt.Orientation.Horizontal

    @staticmethod
    def _shown(bar: QToolBar) -> list:
        return [a for a in bar.actions()
                if bar.widgetForAction(a) is not None and bar.widgetForAction(a).isVisible()]

    def drop_target(self, pos: QPoint):
        """The action a button dropped at *pos* (bar coordinates) goes in
        front of; None: the end of the bar."""
        bar = self.bar
        if bar is None:
            return None
        horizontal = self._horizontal(bar)
        coordinate = pos.x() if horizontal else pos.y()
        shown = self._shown(bar)
        for other in shown:
            centre = bar.widgetForAction(other).geometry().center()
            if coordinate < (centre.x() if horizontal else centre.y()):
                return other
        if not shown:
            return None
        actions = bar.actions()
        following = actions.index(shown[-1]) + 1
        return actions[following] if following < len(actions) else None

    def _show_indicator(self, pos: QPoint) -> None:
        bar, indicator = self.bar, self.indicator
        if bar is None or indicator is None:
            return
        horizontal = self._horizontal(bar)
        before = self.drop_target(pos)
        shown = self._shown(bar)
        if before is not None and before in shown:
            geo = bar.widgetForAction(before).geometry()
            at = geo.left() if horizontal else geo.top()
        elif shown:
            geo = bar.widgetForAction(shown[-1]).geometry()
            at = geo.right() + 1 if horizontal else geo.bottom() + 1
        else:
            return
        rect = bar.contentsRect()
        if horizontal:
            indicator.setGeometry(at - INDICATOR_WIDTH // 2, rect.top() + 2,
                                  INDICATOR_WIDTH, rect.height() - 4)
        else:
            indicator.setGeometry(rect.left() + 2, at - INDICATOR_WIDTH // 2,
                                  rect.width() - 4, INDICATOR_WIDTH)
        indicator.raise_()
        indicator.show()

    def _move(self, action, before) -> None:
        if sip.isdeleted(self) or sip.isdeleted(action):
            return  # the window went before the deferred move ran
        bar = self.bar
        if bar is None:
            return
        actions = bar.actions()
        if action not in actions or before is action:
            return
        index = actions.index(action)
        if index + 1 < len(actions) and actions[index + 1] is before:
            return  # dropped on its own place
        if before is None and actions[-1] is action:
            return
        bar.removeAction(action)
        if before is not None and before in bar.actions():
            bar.insertAction(before, action)
        else:
            bar.addAction(action)
        # A group dragged empty leaves two separators side by side.
        apply_order(bar, bar_order(bar))
        self.arm()
        log.debug("toolbar %s: %s moved", bar.objectName(), tool_id(action))
        self.reordered.emit(bar)


__all__ = [
    "INDICATOR_WIDTH",
    "ORDER_KEY",
    "SEPARATOR",
    "TOOL_ID_PROPERTY",
    "ToolbarReorder",
    "apply_order",
    "bar_order",
    "merge",
    "parse",
    "tool_id",
]
