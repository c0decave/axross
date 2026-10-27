"""Docks of a column that do not fit its height are tabbed together, and
stacked again when the room comes back.

QMainWindow stacks the docks of an area, whatever the area's size: five
docks on the right of a 1600x980 window got 86 px each (their title bar,
nothing of their content), and a window held smaller than the docks'
smallest sizes by a window manager (tiling, maximized) had them laid out
over each other. :class:`DockFit` watches the window and, per area, adds up
what the docks need - each a useful height of its content
(:data:`COMFORT_CONTENT_PX`, or all of it when it needs less), a tab group
the most any of its tabs needs plus the tab bar - and compares it with the
room the area has. When the docks need more, neighbouring docks are tabbed
together (:meth:`QMainWindow.tabifyDockWidget`) until they fit; when there
is room again, with :data:`UNTAB_MARGIN_PX` to spare so a window resized by
a pixel does not flip them back and forth, the docks this class tabbed go
back to being stacked where they were. Docks the user tabbed are never
taken apart, and a dock the user took out of an automatic tab group is not
tabbed again for comfort - only when the area could not even hold the
docks' title bars, which would make them overlap.

Left and right areas are columns (heights add up), top and bottom areas are
rows (widths add up). Floating docks and panels laid out on a workspace
(children of a splitter, not of the window) are not part of any area.
Nothing is changed while a mouse button is down - a separator, a dock or
the window may be in the middle of a drag - and the check runs
:data:`SETTLE_MS` after the last resize or layout change. Which tabs this
class made is kept in session.json (:meth:`session_state`) beside Qt's own
dock state, so they come apart again after a restart.
"""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass

from PyQt6 import sip
from PyQt6.QtCore import QEvent, QObject, QRect, Qt, QTimer
from PyQt6.QtWidgets import (
    QApplication,
    QDockWidget,
    QMainWindow,
    QStatusBar,
    QStyle,
    QTabBar,
    QTabWidget,
    QToolBar,
)

from ui.dock_frame import PanelFrame

log = logging.getLogger(__name__)

#: The content height (width in a row) a dock should show at least; a
#: content that needs less asks for what it needs.
COMFORT_CONTENT_PX = 200
#: Room needed beyond the stacked docks' needs before tabs come apart.
UNTAB_MARGIN_PX = 48
#: The check runs this long after the last resize or layout change.
SETTLE_MS = 150
#: At most this many automatic tabs are kept (session.json is untrusted).
MAX_RECORDS = 64
#: Longest object name taken from session.json.
MAX_NAME_CHARS = 256
#: The key in session.json's ``window`` object.
SESSION_KEY = "auto_tabbed_docks"

_A = Qt.DockWidgetArea
_AREAS = (_A.LeftDockWidgetArea, _A.RightDockWidgetArea, _A.TopDockWidgetArea,
          _A.BottomDockWidgetArea)
_COLUMNS = (_A.LeftDockWidgetArea, _A.RightDockWidgetArea)
#: Area -> (the corner at its start, the corner at its end) along its axis.
_END_CORNERS = {
    _A.LeftDockWidgetArea: (Qt.Corner.TopLeftCorner, Qt.Corner.BottomLeftCorner),
    _A.RightDockWidgetArea: (Qt.Corner.TopRightCorner, Qt.Corner.BottomRightCorner),
    _A.TopDockWidgetArea: (Qt.Corner.TopLeftCorner, Qt.Corner.TopRightCorner),
    _A.BottomDockWidgetArea: (Qt.Corner.BottomLeftCorner, Qt.Corner.BottomRightCorner),
}
#: Area -> (the area before it, the area after it) along its axis.
_NEIGHBOURS = {
    _A.LeftDockWidgetArea: (_A.TopDockWidgetArea, _A.BottomDockWidgetArea),
    _A.RightDockWidgetArea: (_A.TopDockWidgetArea, _A.BottomDockWidgetArea),
    _A.TopDockWidgetArea: (_A.LeftDockWidgetArea, _A.RightDockWidgetArea),
    _A.BottomDockWidgetArea: (_A.LeftDockWidgetArea, _A.RightDockWidgetArea),
}
_DIRECT = Qt.FindChildOption.FindDirectChildrenOnly


@dataclass
class _Record:
    """A tab this class made: *dock* went into *anchor*'s tab group; it was
    stacked right after *after* (None: first in its area), below the anchor
    when *below*."""

    dock: str
    anchor: str
    after: str | None
    below: bool


@dataclass
class _Slot:
    """One place in an area: a dock, or a tab group (the tab on top first)."""

    members: list[QDockWidget]
    rect: QRect

    @property
    def rep(self) -> QDockWidget:
        return self.members[0]


def _valid_name(value) -> bool:
    return isinstance(value, str) and 0 < len(value) <= MAX_NAME_CHARS


def _parse_records(value) -> list[_Record]:
    if not isinstance(value, list):
        return []
    records: list[_Record] = []
    seen: set[str] = set()
    for entry in value:
        if len(records) >= MAX_RECORDS:
            break
        if not isinstance(entry, dict):
            continue
        dock, anchor = entry.get("dock"), entry.get("anchor")
        after, below = entry.get("after"), entry.get("below", True)
        if not (_valid_name(dock) and _valid_name(anchor)) or dock == anchor or dock in seen:
            continue
        if after is not None and not _valid_name(after):
            continue
        if not isinstance(below, bool):
            continue
        seen.add(dock)
        records.append(_Record(dock, anchor, after, below))
    return records


class DockFit(QObject):
    """Keeps the docks of *window*'s areas inside their room by tabbing them
    together; see the module docstring."""

    def __init__(self, window: QMainWindow) -> None:
        super().__init__(window)
        self._window = window
        self._records: list[_Record] = []
        #: Docks the user took out of an automatic tab group.
        self._declined: set[str] = set()
        #: The docks each area held at the last check (a change rebalances).
        self._held: dict[_A, frozenset[str]] = {}
        self._busy = False
        #: Object name -> dock, for one check (None outside a check).
        self._names: dict[str, QDockWidget] | None = None
        self._tab_probe: int | None = None
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.setInterval(SETTLE_MS)
        self._timer.timeout.connect(self._on_timer)
        window.installEventFilter(self)
        self._watch_docks()

    # -- triggers ---------------------------------------------------------------------------

    def eventFilter(self, obj, event) -> bool:  # noqa: N802 - Qt override
        if obj is self._window:
            kind = event.type()
            if kind == QEvent.Type.Resize:
                self._timer.start()  # once the resizing settled
            elif kind in (QEvent.Type.LayoutRequest, QEvent.Type.Show, QEvent.Type.ChildAdded):
                self.schedule()
        return False

    def schedule(self) -> None:
        """Check soon (SETTLE_MS); a check already waiting is not pushed back."""
        if not self._busy and not self._timer.isActive():
            self._timer.start()

    def _on_timer(self) -> None:
        try:
            self.fit_now()
        except Exception:  # noqa: BLE001 - a layout check must never take the window down
            log.exception("Dock layout check failed")

    def _on_dock_signal(self, *_args) -> None:
        self.schedule()

    def _watch_docks(self) -> None:
        for dock in self._window.findChildren(QDockWidget, options=_DIRECT):
            if dock.property("axDockFitWatched"):
                continue
            dock.setProperty("axDockFitWatched", True)
            dock.dockLocationChanged.connect(self._on_dock_signal)
            dock.topLevelChanged.connect(self._on_dock_signal)
            dock.visibilityChanged.connect(self._on_dock_signal)

    def pointer_busy(self) -> bool:
        """A mouse button is down: a separator, a dock or the window may be
        in the middle of a drag."""
        return QApplication.mouseButtons() != Qt.MouseButton.NoButton

    # -- the check --------------------------------------------------------------------------

    def fit_now(self) -> bool:
        """Tab or stack docks so each area's docks fit its room. True when
        something was changed."""
        window = self._window
        if self._busy or sip.isdeleted(window) or not window.isVisible():
            return False
        if self.pointer_busy():
            self._timer.start()  # again once the button is up
            return False
        self._watch_docks()
        self._activate()
        changed = False
        self._busy = True
        self._names = self._name_map()
        try:
            self._validate()
            for area in _AREAS:
                changed |= self._fit_area(area)
        finally:
            self._busy = False
            self._names = None
        if changed:
            log.debug("Dock layout fitted; automatic tabs: %s", self.auto_tabbed())
        return changed

    def _fit_area(self, area: _A) -> bool:
        slots = self._slots(area)
        held = frozenset(d.objectName() for s in slots for d in s.members)
        before = self._held.get(area)
        if not slots:
            self._held[area] = held
            return False
        room = self.column_room(area)
        changed = self._untab(area, room) or self._tab(area, self._rows(area, slots), room)
        if changed:
            self._activate()
            held = frozenset(d.objectName() for s in self._slots(area) for d in s.members)
        if changed or (before is not None and held != before):
            self._rebalance(area, room)
        self._held[area] = held
        return changed

    def _activate(self) -> None:
        layout = self._window.layout()
        if layout is not None:
            layout.activate()

    # -- what is where ----------------------------------------------------------------------

    def _in_area(self, dock: QDockWidget) -> bool:
        window = self._window
        return (dock.parentWidget() is window and not dock.isFloating()
                and window.dockWidgetArea(dock) != _A.NoDockWidgetArea)

    def column_docks(self, area: _A) -> list[QDockWidget]:
        """The docks one sees in *area* (with the tabs behind another one):
        no floating dock, no panel laid out on a workspace."""
        window = self._window
        return [d for d in window.findChildren(QDockWidget, options=_DIRECT)
                if d.isVisible() and self._in_area(d) and window.dockWidgetArea(d) == area]

    def _name_map(self) -> dict[str, QDockWidget]:
        """The window's docks by object name; a search through the whole
        widget tree (docks laid out on a workspace) only when a record
        names a dock that is not the window's own."""
        names = {d.objectName(): d for d in self._window.findChildren(QDockWidget, options=_DIRECT)
                 if d.objectName()}
        wanted = {n for r in self._records for n in (r.dock, r.anchor, r.after) if n}
        if not wanted <= names.keys():
            for dock in self._window.findChildren(QDockWidget):
                names.setdefault(dock.objectName(), dock)
        return names

    def _find(self, name: str | None) -> QDockWidget | None:
        if not name:
            return None
        names = self._names if self._names is not None else self._name_map()
        dock = names.get(name)
        return None if dock is None or sip.isdeleted(dock) else dock

    def _slots(self, area: _A) -> list[_Slot]:
        window = self._window
        docks = self.column_docks(area)
        inside = window.rect()
        seen: set[int] = set()
        slots = []
        for dock in docks:
            if id(dock) in seen:
                continue
            group = [dock] + [t for t in window.tabifiedDockWidgets(dock) if t in docks]
            seen.update(id(m) for m in group)
            # The tab on top is the one Qt lays out in the window; the others
            # wait outside it.
            top = next((m for m in group if m.geometry().intersects(inside)), group[0])
            members = [top] + [m for m in group if m is not top]
            slots.append(_Slot(members, top.geometry()))
        return slots

    def _rows(self, area: _A, slots: list[_Slot]) -> list[list[_Slot]]:
        """*slots* in their order along the area's axis; slots side by side
        across it (a column the user split) share a row."""
        vertical = area in _COLUMNS

        def along(rect: QRect) -> tuple[int, int]:
            return (rect.top(), rect.bottom()) if vertical else (rect.left(), rect.right())

        def across(rect: QRect) -> tuple[int, int]:
            return (rect.left(), rect.right()) if vertical else (rect.top(), rect.bottom())

        rows: list[list[_Slot]] = []
        for slot in sorted(slots, key=lambda s: (along(s.rect)[0], across(s.rect)[0])):
            if rows:
                row = rows[-1]
                a0, a1 = along(slot.rect)
                c0, c1 = across(slot.rect)
                beside = all(c0 > across(o.rect)[1] or c1 < across(o.rect)[0] for o in row)
                level = any(a0 <= along(o.rect)[1] and a1 >= along(o.rect)[0] for o in row)
                if beside and level:
                    row.append(slot)
                    continue
            rows.append([slot])
        return rows

    # -- sizes ------------------------------------------------------------------------------

    def _separator(self) -> int:
        return self._window.style().pixelMetric(
            QStyle.PixelMetric.PM_DockWidgetSeparatorExtent, None, self._window)

    def _tab_extent(self, area: _A) -> int:
        """What a tab bar adds along *area*'s axis."""
        north_south = self._window.tabPosition(area) in (
            QTabWidget.TabPosition.North, QTabWidget.TabPosition.South)
        if north_south != (area in _COLUMNS):
            return 0
        bars = [b.sizeHint().height() for b in self._window.findChildren(QTabBar, options=_DIRECT)
                if b.isVisible() and b.count() > 0]
        if bars:
            return max(bars)
        if self._tab_probe is None:
            probe = QTabBar()
            probe.setFont(self._window.font())
            probe.setDocumentMode(self._window.documentMode())
            probe.addTab("Xg")
            self._tab_probe = probe.sizeHint().height()
            probe.deleteLater()
        return self._tab_probe

    def _dock_extent(self, dock: QDockWidget, vertical: bool, comfort: bool) -> int:
        """The smallest size of *dock* along the axis: Qt's minimum, or with
        *comfort* the size that shows a useful part of its content."""
        size = dock.minimumSizeHint().expandedTo(dock.minimumSize())
        hard = size.height() if vertical else size.width()
        if not comfort:
            return hard
        frame = dock.findChild(PanelFrame, "panelFrame", _DIRECT)
        if frame is None:
            return hard
        want = frame.content_minimum()
        smallest = frame.minimumSizeHint()
        content = min(want.height() if vertical else want.width(), COMFORT_CONTENT_PX)
        # The scroll bar across the axis takes its share when the content
        # does not fit across.
        view = frame.viewport()
        if vertical and want.width() > view.width():
            content += frame.horizontalScrollBar().sizeHint().height()
        elif not vertical and want.height() > view.height():
            content += frame.verticalScrollBar().sizeHint().width()
        overhead = hard - (smallest.height() if vertical else smallest.width())
        return max(hard, overhead + content)

    def _slot_extent(self, area: _A, members: list[QDockWidget], comfort: bool) -> int:
        vertical = area in _COLUMNS
        extent = max(self._dock_extent(m, vertical, comfort) for m in members)
        return extent + (self._tab_extent(area) if len(members) > 1 else 0)

    def _need(self, area: _A, rows: list[list[list[QDockWidget]]], comfort: bool) -> int:
        if not rows:
            return 0
        total = sum(max(self._slot_extent(area, slot, comfort) for slot in row) for row in rows)
        return total + self._separator() * (len(rows) - 1)

    @staticmethod
    def _model(rows: list[list[_Slot]]) -> list[list[list[QDockWidget]]]:
        return [[list(slot.members) for slot in row] for row in rows]

    def column_need(self, area: _A, *, stacked: bool = False, comfort: bool = True) -> int:
        """What *area*'s docks need along its axis as they are; *stacked*:
        with the docks this class tabbed stacked again; *comfort* False:
        Qt's minimum only."""
        model = self._model(self._rows(area, self._slots(area)))
        if stacked:
            for record in self._records:
                dock = self._find(record.dock)
                model = self._without(model, dock) if dock is not None else model
        return self._need(area, model, comfort)

    @staticmethod
    def _without(model, dock):
        """*model* with *dock* out of its tab group, in a row of its own."""
        for row in model:
            for slot in row:
                if dock in slot and len(slot) > 1:
                    slot.remove(dock)
                    model.append([[dock]])
                    return model
        return model

    def _region(self) -> QRect:
        """The part of the window the dock areas and the central widget
        share: without the menu bar, the tool bars and the status bar."""
        window = self._window
        rect = QRect(window.rect())
        menu = window.menuWidget()
        if menu is not None and menu.isVisible():
            rect.setTop(max(rect.top(), menu.geometry().bottom() + 1))
        status = window.findChild(QStatusBar, options=_DIRECT)
        if status is not None and status.isVisible():
            rect.setBottom(min(rect.bottom(), status.geometry().top() - 1))
        for bar in window.findChildren(QToolBar, options=_DIRECT):
            if not bar.isVisible() or bar.isFloating():
                continue
            geo = bar.geometry()
            where = window.toolBarArea(bar)
            if where == Qt.ToolBarArea.TopToolBarArea:
                rect.setTop(max(rect.top(), geo.bottom() + 1))
            elif where == Qt.ToolBarArea.BottomToolBarArea:
                rect.setBottom(min(rect.bottom(), geo.top() - 1))
            elif where == Qt.ToolBarArea.LeftToolBarArea:
                rect.setLeft(max(rect.left(), geo.right() + 1))
            elif where == Qt.ToolBarArea.RightToolBarArea:
                rect.setRight(min(rect.right(), geo.left() - 1))
        return rect

    def _area_thickness(self, area: _A, region: QRect) -> int:
        """How far *area* reaches into *region* (0 when it shows no dock)."""
        shown = [s.rect for s in self._slots(area)]
        if not shown:
            return 0
        if area == _A.TopDockWidgetArea:
            return max(r.bottom() for r in shown) - region.top() + 1
        if area == _A.BottomDockWidgetArea:
            return region.bottom() - min(r.top() for r in shown) + 1
        if area == _A.LeftDockWidgetArea:
            return max(r.right() for r in shown) - region.left() + 1
        return region.right() - min(r.left() for r in shown) + 1

    def column_room(self, area: _A) -> int:
        """The room *area* has along its axis: the dock region's height (a
        column) or width (a row), less the neighbouring areas that own the
        corners at its ends."""
        window = self._window
        region = self._region()
        vertical = area in _COLUMNS
        if vertical:
            start, end = region.top(), region.bottom()
        else:
            start, end = region.left(), region.right()
        sep = self._separator()
        for corner, neighbour, sign in zip(_END_CORNERS[area], _NEIGHBOURS[area], (1, -1)):
            if window.corner(corner) == area:
                continue
            thick = self._area_thickness(neighbour, region)
            if thick:
                if sign > 0:
                    start += thick + sep
                else:
                    end -= thick + sep
        return max(0, end - start + 1)

    # -- tabbing ----------------------------------------------------------------------------

    def _auto(self, name: str) -> bool:
        return any(r.dock == name for r in self._records)

    def _tab(self, area: _A, rows: list[list[_Slot]], room: int) -> bool:
        """Tab neighbouring docks together until the area's docks fit."""
        model = self._model(rows)
        sep = self._separator()
        changed = False
        for _ in range(MAX_RECORDS):
            if self._need(area, model, True) <= room:
                break
            # Docks the user stacked again are kept stacked unless the area
            # cannot even hold the title bars (the docks would overlap).
            forced = self._need(area, model, False) > room
            best = None
            for i in range(len(model) - 1):
                upper, lower = model[i], model[i + 1]
                if len(upper) != 1 or len(lower) != 1:
                    continue  # docks side by side stay as the user put them
                up, low = upper[0], lower[0]
                if not forced and any(m.objectName() in self._declined for m in up + low):
                    continue
                if len(low) == 1:
                    mover, anchor_slot, below = low[0], up, True
                elif len(up) == 1:
                    mover, anchor_slot, below = up[0], low, False
                else:
                    continue  # two tab groups: neither is taken apart
                pair = self._slot_extent(area, up, True) + self._slot_extent(area, low, True)
                merged = self._slot_extent(area, anchor_slot + [mover], True)
                if pair + sep - merged <= 0:
                    continue
                if best is None or pair < best[0]:
                    best = (pair, i, mover, anchor_slot, below)
            if best is None:
                break
            _, i, mover, anchor_slot, below = best
            if below:
                after = anchor_slot[0]
            else:
                after = model[i - 1][0][0] if i > 0 else None
            anchor = next((m for m in anchor_slot if not self._auto(m.objectName())),
                          anchor_slot[0])
            self._tabify(anchor, anchor_slot[0], mover)
            self._records = [r for r in self._records if r.dock != mover.objectName()]
            self._records.append(_Record(
                mover.objectName(), anchor.objectName(),
                after.objectName() if after is not None else None, below))
            model[i:i + 2] = [[anchor_slot + [mover]]]
            changed = True
        return changed

    def _tabify(self, anchor: QDockWidget, top: QDockWidget, mover: QDockWidget) -> None:
        focus = QApplication.focusWidget()
        keep = top if focus is not None and top.isAncestorOf(focus) else None
        self._window.tabifyDockWidget(anchor, mover)
        if keep is not None:
            keep.raise_()  # the dock being typed in stays on top

    # -- stacking again ---------------------------------------------------------------------

    def _validate(self) -> None:
        """Forget automatic tabs the user changed; keep those that wait (a
        closed or floating dock, a closed anchor, a dock not made yet)."""
        window = self._window
        kept = []
        for record in self._records:
            dock = self._find(record.dock)
            if dock is None:
                kept.append(record)  # not (yet) made: dropped when saving
                continue
            if not self._in_area(dock):
                if dock.isFloating() or dock.isHidden():
                    kept.append(record)
                continue  # laid out elsewhere (a workspace): not ours any more
            anchor = self._find(record.anchor)
            if anchor is None:
                partners = window.tabifiedDockWidgets(dock)
                if partners:
                    record.anchor = partners[0].objectName()
                    kept.append(record)
                continue
            if dock.isHidden() or anchor.isHidden() or not self._in_area(anchor):
                kept.append(record)
                continue
            if anchor in window.tabifiedDockWidgets(dock):
                kept.append(record)
                continue
            # The user took it out of the tab group (or the group apart).
            self._declined.add(record.dock)
        self._records = kept

    def _active(self, record: _Record, area: _A) -> QDockWidget | None:
        window = self._window
        dock, anchor = self._find(record.dock), self._find(record.anchor)
        if dock is None or anchor is None or not dock.isVisible() or not anchor.isVisible():
            return None
        if not self._in_area(dock) or window.dockWidgetArea(dock) != area:
            return None
        return dock if anchor in window.tabifiedDockWidgets(dock) else None

    def _untab(self, area: _A, room: int) -> bool:
        """Stack the docks this class tabbed, the last tabbed first, while
        the area keeps room for them with UNTAB_MARGIN_PX to spare."""
        changed = False
        for record in reversed(list(self._records)):
            dock = self._active(record, area)
            if dock is None:
                continue
            model = self._without(self._model(self._rows(area, self._slots(area))), dock)
            if self._need(area, model, True) + UNTAB_MARGIN_PX > room:
                break  # the earlier ones need at least as much
            self._place_back(area, record, dock)
            self._records.remove(record)
            changed = True
        return changed

    def _place_back(self, area: _A, record: _Record, dock: QDockWidget) -> None:
        window = self._window
        orientation = Qt.Orientation.Vertical if area in _COLUMNS else Qt.Orientation.Horizontal
        window.removeDockWidget(dock)
        window.addDockWidget(area, dock, orientation)
        dock.show()
        self._activate()
        after = self._find(record.after)
        if (after is not None and after is not dock and after.isVisible()
                and self._in_area(after) and window.dockWidgetArea(after) == area
                and not window.tabifiedDockWidgets(after)):
            window.splitDockWidget(after, dock, orientation)
            return
        # Next to a tab group (or first in the area): Qt only adds at the
        # end, so the docks that come after it move to the end behind it.
        rows = self._rows(area, self._slots(area))
        mine = next((i for i, row in enumerate(rows) if any(dock in s.members for s in row)), None)
        if mine is None:
            return
        others = [row for i, row in enumerate(rows) if i != mine]

        def index_of(target: QDockWidget | None) -> int | None:
            for i, row in enumerate(others):
                if any(target in s.members for s in row):
                    return i
            return None

        anchor = self._find(record.anchor)
        if after is not None and index_of(after) is not None:
            target = index_of(after)
        elif anchor is not None and index_of(anchor) is not None:
            target = index_of(anchor) - (0 if record.below else 1)
        else:
            return
        tail = others[target + 1:]
        if any(len(row) > 1 for row in tail):
            return  # docks side by side are not moved; it stays at the end
        for row in tail:
            self._move_to_end(area, row[0], orientation)

    def _move_to_end(self, area: _A, slot: _Slot, orientation: Qt.Orientation) -> None:
        window = self._window
        first, rest = slot.members[0], slot.members[1:]
        window.removeDockWidget(first)
        window.addDockWidget(area, first, orientation)
        first.show()
        for member in rest:
            window.tabifyDockWidget(first, member)
            member.show()
        first.raise_()

    def _rebalance(self, area: _A, room: int) -> None:
        """After the area changed: when a dock got less than its useful
        size although all of them fit, size the docks by what they need
        (Qt hands out the room by the docks' size hints, so one large
        panel could leave the others at their title bars)."""
        rows = self._rows(area, self._slots(area))
        if any(len(row) > 1 for row in rows):
            return
        if self._need(area, self._model(rows), True) > room:
            return
        vertical = area in _COLUMNS
        reps, sizes, starved = [], [], False
        for (slot,) in rows:
            want = max(self._dock_extent(m, vertical, True) for m in slot.members)
            have = slot.rect.height() if vertical else slot.rect.width()
            starved |= have < want
            reps.append(slot.rep)
            sizes.append(want)
        if starved and len(reps) > 1:
            orientation = Qt.Orientation.Vertical if vertical else Qt.Orientation.Horizontal
            self._window.resizeDocks(reps, sizes, orientation)
            self._activate()

    # -- session.json -----------------------------------------------------------------------

    def auto_tabbed(self) -> list[str]:
        """The object names of the docks this class tabbed, oldest first."""
        return [r.dock for r in self._records]

    def session_state(self) -> list[dict]:
        """The automatic tabs for session.json (docks that exist only)."""
        names = self._name_map()
        return [asdict(r) for r in self._records if r.dock in names and r.anchor in names]

    def load_session_state(self, value) -> None:
        """The automatic tabs from session.json; anything malformed is
        ignored. Checked against the layout at the next check."""
        self._records = _parse_records(value)
        self._declined.clear()
        self._held.clear()
        self.schedule()


__all__ = [
    "COMFORT_CONTENT_PX",
    "DockFit",
    "MAX_RECORDS",
    "SESSION_KEY",
    "SETTLE_MS",
    "UNTAB_MARGIN_PX",
]
