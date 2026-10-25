"""Table columns the user can always drag, laid out as if fitted.

Qt never lets a user drag a section in ``Stretch``, ``ResizeToContents`` or
``Fixed`` mode, and views that used them for a tidy layout had columns
nobody could resize. :class:`ColumnFitter` keeps every section
``Interactive`` and does the fitting itself: each column as wide as its
content and header, one *fill* column the rest of the viewport. A column
the user dragged keeps its width from then on; the fill column then takes
what is left (and the view scrolls when nothing is left).

In a narrow view the fill column gets its content (up to half the width)
first and the others share the rest in proportion to their content. A
*keep* column - the name that tells the rows apart, where the fill column
is a path or a description - gets its content (up to a third of the width)
before that share, so a long description or status never squeezes it to
an ellipsis (reported for the Extensions list).

The fit runs after the viewport is resized or shown and after the model
changes (rows, data, a new model), coalesced to one pass per event-loop
turn. ``QAbstractItemView.sizeHintForColumn`` reads at most the header's
``resizeContentsPrecision`` rows, so a large table costs no more than
``ResizeToContents`` did.

A table whose rows change all the time (the transfer queue: a dataChanged
per progress signal) passes ``cache_widths=True``: the fit then remembers
each cell's width and measures only the cells that changed, sampling the
same rows ``QTableView.sizeHintForColumn`` samples, so the widths are the
ones Qt gives. Without it a 2000-job queue spent ~300 ms per fit, a fit
per progress signal. Only for a QTableView without spans or persistent
editors, whose delegates size a cell from its data, the view's font and
style.
"""

from __future__ import annotations

from PyQt6 import sip
from PyQt6.QtCore import QEvent, QObject, QTimer
from PyQt6.QtWidgets import QAbstractItemView, QApplication, QHeaderView, QTableView

#: Model signals after which the content widths may have changed.
_MODEL_SIGNALS = (
    "modelReset",
    "layoutChanged",
    "rowsInserted",
    "rowsRemoved",
    "columnsInserted",
    "columnsRemoved",
    "dataChanged",
)


#: Model signals after which no remembered cell width can be trusted.
_FORGET_SIGNALS = ("modelReset", "layoutChanged", "rowsMoved", "columnsInserted",
                   "columnsRemoved", "columnsMoved")

#: A cell width not measured yet (a real one is never this small).
_UNKNOWN = -(1 << 62)

#: View events after which a cell may measure differently.
_RESTYLE_EVENTS = (QEvent.Type.FontChange, QEvent.Type.StyleChange)


def _address(obj) -> int:
    """The C++ object behind *obj* (0 for None): a Python wrapper's id()
    changes when PyQt hands out a new wrapper for the same object."""
    return 0 if obj is None else sip.unwrapinstance(obj)


def _header(view: QAbstractItemView) -> QHeaderView:
    return view.horizontalHeader() if hasattr(view, "horizontalHeader") else view.header()


class ColumnFitter(QObject):
    """Fit *view*'s columns, *fill* taking the free width; see the module."""

    def __init__(
        self,
        view: QAbstractItemView,
        fill: int = 0,
        keep: tuple[int, ...] = (),
        cache_widths: bool = False,
        data_delay_ms: int = 0,
    ) -> None:
        super().__init__(view)
        if data_delay_ms < 0:
            raise ValueError(f"data_delay_ms must not be negative: {data_delay_ms}")
        self._view = view
        self._fill = fill
        #: Columns that get their content before the others share the rest.
        self._keep = tuple(keep)
        self._fitting = False
        self._pending = False
        self._model = None
        #: Sections the user resized; the fit leaves them alone.
        self.user_sized: set[int] = set()
        #: Remember cell widths (see the module); only a table can.
        self._cache_widths = bool(cache_widths) and isinstance(view, QTableView)
        #: column -> the width of each row's size hint (_UNKNOWN: measure it).
        self._cell_widths: dict[int, list[int]] = {}
        #: What the remembered widths were measured with (_environment).
        self._cell_env: tuple | None = None
        #: A dataChanged is fitted at most this often (rows, resizes and
        #: resets at once): a progress signal per event-loop turn refitted
        #: the Transfers dock ~3 times per file copied.
        self._data_delay_ms = int(data_delay_ms)
        self._data_timer: QTimer | None = None
        if self._data_delay_ms:
            self._data_timer = QTimer(self)
            self._data_timer.setSingleShot(True)
            self._data_timer.setInterval(self._data_delay_ms)
            self._data_timer.timeout.connect(self._run)
        header = _header(view)
        header.setStretchLastSection(False)
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.sectionResized.connect(self._on_section_resized)
        header.sectionCountChanged.connect(lambda *_: self.schedule())
        view.viewport().installEventFilter(self)
        if self._cache_widths:
            view.installEventFilter(self)
        self._watch_model()
        self.schedule()

    # -- triggers ---------------------------------------------------------
    def eventFilter(self, obj, event) -> bool:  # noqa: N802 - Qt override
        kind = event.type()
        if obj is self._view:  # installed for the cell cache only
            if kind in _RESTYLE_EVENTS:
                self._forget_cells()
                self.schedule()
        elif kind in (QEvent.Type.Resize, QEvent.Type.Show):
            self.schedule()
        return False

    def _on_section_resized(self, index: int, _old: int, _new: int) -> None:
        if not self._fitting:
            self.user_sized.add(index)
            self.schedule()

    def _watch_model(self) -> None:
        model = self._view.model()
        if model is self._model:
            return
        if self._model is not None:
            for name, slot in self._model_slots():
                try:
                    getattr(self._model, name).disconnect(slot)
                except (TypeError, RuntimeError):
                    pass
        self._model = model
        self._forget_cells()
        if model is not None:
            for name, slot in self._model_slots():
                getattr(model, name).connect(slot)

    def _model_slots(self) -> list:
        delayed = self._data_timer is not None
        slots = [
            (name, self._schedule_data if delayed and name == "dataChanged" else self.schedule)
            for name in _MODEL_SIGNALS
        ]
        if self._cache_widths:
            slots += [(name, self._forget_cells) for name in _FORGET_SIGNALS]
            slots += [("dataChanged", self._cells_changed), ("rowsInserted", self._rows_inserted),
                      ("rowsRemoved", self._rows_removed)]
        return slots

    # -- the cell cache ---------------------------------------------------
    def _forget_cells(self, *_args) -> None:
        self._cell_widths = {}

    def _cells_changed(self, top_left, bottom_right, *_roles) -> None:
        if not (top_left.isValid() and bottom_right.isValid()):
            self._forget_cells()
            return
        r0, r1 = top_left.row(), bottom_right.row()
        for col in range(top_left.column(), bottom_right.column() + 1):
            widths = self._cell_widths.get(col)
            if widths is not None:
                lo, hi = max(0, r0), min(len(widths), r1 + 1)
                if lo < hi:
                    widths[lo:hi] = [_UNKNOWN] * (hi - lo)

    def _rows_inserted(self, parent, first: int, last: int) -> None:
        if parent.isValid():  # a table has no child rows; be safe
            self._forget_cells()
            return
        for widths in self._cell_widths.values():
            widths[first:first] = [_UNKNOWN] * (last - first + 1)

    def _rows_removed(self, parent, first: int, last: int) -> None:
        if parent.isValid():
            self._forget_cells()
            return
        for widths in self._cell_widths.values():
            del widths[first:last + 1]

    def _environment(self) -> tuple:
        """What a cell's size hint depends on besides its data: the font,
        the style and every style sheet that reaches the view, the icon
        size, wrapping and the delegates."""
        view = self._view
        sheets = []
        widget = view
        while widget is not None:
            sheets.append(widget.styleSheet())
            widget = widget.parentWidget()
        app = QApplication.instance()
        icon = view.iconSize()
        model = view.model()
        columns = model.columnCount(view.rootIndex()) if model is not None else 0
        return (
            view.font().key(),
            _address(view.style()),
            app.styleSheet() if app is not None else "",
            tuple(sheets),
            (icon.width(), icon.height()),
            view.wordWrap(),
            view.textElideMode(),
            _address(view.itemDelegate()),
            tuple(_address(view.itemDelegateForColumn(c)) for c in range(columns)),
        )

    def _check_environment(self) -> None:
        """Forget every width when what they were measured with changed."""
        self._watch_model()  # a model set since the last fit: its own cells
        self._view.ensurePolished()
        env = self._environment()
        if env != self._cell_env:
            self._cell_env = env
            self._forget_cells()

    def _sampled_rows(self) -> range | list[int]:
        """The logical rows QTableView.sizeHintForColumn (Qt 6) measures:
        the visible ones, then alternately below and above them until
        ``resizeContentsPrecision`` rows (0: the visible ones, -1: all).
        A ``range`` when no row is moved or hidden (always a run of rows)."""
        view = self._view
        vh = view.verticalHeader()
        precision = view.horizontalHeader().resizeContentsPrecision()
        count = view.model().rowCount(view.rootIndex())
        plain = not vh.sectionsMoved() and not vh.sectionsHidden()

        def logical(visual: int) -> int:
            """The logical row at *visual*, -1 for a hidden one."""
            if plain:
                return visual
            row = vh.logicalIndex(visual)
            return -1 if vh.isSectionHidden(row) else row

        top = max(0, vh.visualIndexAt(0))
        bottom = vh.visualIndexAt(view.viewport().height())
        if not view.isVisible() or bottom == -1:
            bottom = count - 1
        rows: list[int] = []
        processed = 0
        row = top
        if plain:
            # Every row counts: the loop below in arithmetic.
            last = min(bottom, count - 1)
            span = max(0, last - top + 1)
            if precision > 0 and span >= precision:
                return range(top, top + precision)
            processed = span
            row = last + 1 if span else top
        else:
            while row <= bottom:
                found = logical(row)
                if found >= 0:
                    rows.append(found)
                    processed += 1
                    if processed == precision:
                        break  # like Qt's for loop: the row counter stays here
                row += 1
        actual_bottom = count - 1
        idx_top, idx_bottom = top, row - 1
        if precision == 0 or actual_bottom < idx_top:
            processed = precision
        while processed != precision and (idx_top > 0 or idx_bottom < actual_bottom):
            found = -1
            if (processed % 2 and idx_top > 0) or idx_bottom == actual_bottom:
                while idx_top > 0:
                    idx_top -= 1
                    found = logical(idx_top)
                    if found >= 0:
                        break
            else:
                while idx_bottom < actual_bottom:
                    idx_bottom += 1
                    found = logical(idx_bottom)
                    if found >= 0:
                        break
            if found >= 0 and not plain:
                rows.append(found)
            processed += 1
        if plain:
            return range(idx_top, idx_bottom + 1) if processed or count else range(0)
        return rows

    def column_hint(self, col: int) -> int:
        """``view.sizeHintForColumn(col)``; from remembered cell widths when
        the cache is on."""
        view = self._view
        if not self._cache_widths or view.model() is None:
            return view.sizeHintForColumn(col)
        self._check_environment()
        return self._cached_hint(col, self._sampled_rows())

    def _cached_hint(self, col: int, rows: range | list[int]) -> int:
        """The widest of *rows* in *col*, measuring only unknown cells."""
        view = self._view
        model, root = view.model(), view.rootIndex()
        count = model.rowCount(root)
        widths = self._cell_widths.get(col)
        if widths is None or len(widths) != count:
            widths = self._cell_widths[col] = [_UNKNOWN] * count

        def measure(row: int) -> int:
            width = view.sizeHintForIndex(model.index(row, col, root)).width()
            widths[row] = width
            return width

        if isinstance(rows, range):
            part = widths[rows.start:rows.stop]
            if _UNKNOWN in part:
                for offset, width in enumerate(part):
                    if width == _UNKNOWN:
                        part[offset] = measure(rows.start + offset)
            hint = max(0, max(part, default=0))
        else:
            hint = 0
            for row in rows:
                width = widths[row]
                if width == _UNKNOWN:
                    width = measure(row)
                if width > hint:
                    hint = width
        return hint + 1 if view.showGrid() else hint

    def schedule(self, *_args) -> None:
        """Fit once the current burst of events is over."""
        if not self._pending:
            self._pending = True
            QTimer.singleShot(0, self._run)

    def _schedule_data(self, *_args) -> None:
        """A dataChanged: fit within data_delay_ms, once for all of them."""
        if not self._data_timer.isActive():
            self._data_timer.start()

    def _run(self) -> None:
        self._pending = False
        if self._data_timer is not None:
            self._data_timer.stop()  # this fit covers the data changes too
        try:
            self.fit()
        except RuntimeError:  # the view is gone
            pass

    # -- the fit ----------------------------------------------------------
    def fit(self) -> None:
        view = self._view
        self._watch_model()
        header = _header(view)
        count = header.count()
        if count == 0:
            return
        visible = [c for c in range(count) if not header.isSectionHidden(c)]
        minimum = header.minimumSectionSize()
        fill = self._fill
        viewport = view.viewport().width()
        fitted = [c for c in visible if c != fill and c not in self.user_sized]
        if self._cache_widths and view.model() is not None:
            self._check_environment()
            rows = self._sampled_rows()

            def hint(col: int) -> int:
                return self._cached_hint(col, rows)
        else:
            hint = view.sizeHintForColumn
        want = {c: max(hint(c), header.sectionSizeHint(c), minimum) for c in fitted}
        fill_free = fill in visible and fill not in self.user_sized
        if fill_free and viewport > 0:
            # A narrow view: the fill column (a name, a path) gets its
            # content, up to half the width, before the others get theirs;
            # they give up what they have beyond their header label, in
            # proportion. Without this a 320 px archive dock left Name 31 px.
            need = min(
                max(hint(fill), header.sectionSizeHint(fill), minimum),
                max(minimum, viewport // 2),
            )
            fixed = sum(header.sectionSize(c) for c in visible if c != fill and c not in want)
            # A kept column (the name, where a path or a description
            # fills): its content, up to a third of the width, before the
            # fill column and the others.
            kept = [c for c in self._keep if c in want]
            for c in kept:
                want[c] = min(want[c], max(minimum, viewport // 3))
            kept_width = sum(want[c] for c in kept)
            shared = [c for c in fitted if c not in kept]
            # What the others need to show their header label at least.
            floors = {c: min(want[c], max(minimum, header.sectionSizeHint(c))) for c in shared}
            if kept:
                # With kept columns the fill gives way down to what leaves
                # the others their labels (a long description took half the
                # width and left "Status" and "Version" as "…").
                need = min(need, max(minimum, viewport - fixed - kept_width - sum(floors.values())))
            room = max(0, viewport - fixed - need - kept_width)
            total = sum(want[c] for c in shared)
            if shared and total > room:
                spare = room - sum(floors.values())
                if spare >= 0:
                    # Each its header label, the rest in proportion to what
                    # it wants beyond that.
                    over = {c: want[c] - floors[c] for c in shared}
                    over_total = sum(over.values()) or 1
                    for c in shared:
                        want[c] = floors[c] + over[c] * spare // over_total
                else:
                    # Not even the labels fit: in proportion to what they
                    # want; an elided "Compr…" reads better than a name
                    # that is not there at all.
                    for c in shared:
                        want[c] = max(minimum, want[c] * room // total)
        self._fitting = True
        try:
            for col in fitted:
                if header.sectionSize(col) != want[col]:
                    header.resizeSection(col, want[col])
            if fill_free:
                others = sum(header.sectionSize(c) for c in visible if c != fill)
                width = max(minimum, viewport - others)
                if header.sectionSize(fill) != width:
                    header.resizeSection(fill, width)
        finally:
            self._fitting = False


__all__ = ["ColumnFitter"]
