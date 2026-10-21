"""Table columns the user can always drag, laid out as if fitted.

Qt never lets a user drag a section in ``Stretch``, ``ResizeToContents`` or
``Fixed`` mode, and views that used them for a tidy layout had columns
nobody could resize. :class:`ColumnFitter` keeps every section
``Interactive`` and does the fitting itself: each column as wide as its
content and header, one *fill* column the rest of the viewport. A column
the user dragged keeps its width from then on; the fill column then takes
what is left (and the view scrolls when nothing is left).

The fit runs after the viewport is resized or shown and after the model
changes (rows, data, a new model), coalesced to one pass per event-loop
turn. ``QAbstractItemView.sizeHintForColumn`` reads at most the header's
``resizeContentsPrecision`` rows, so a large table costs no more than
``ResizeToContents`` did.
"""

from __future__ import annotations

from PyQt6.QtCore import QEvent, QObject, QTimer
from PyQt6.QtWidgets import QAbstractItemView, QHeaderView

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


def _header(view: QAbstractItemView) -> QHeaderView:
    return view.horizontalHeader() if hasattr(view, "horizontalHeader") else view.header()


class ColumnFitter(QObject):
    """Fit *view*'s columns, *fill* taking the free width; see the module."""

    def __init__(self, view: QAbstractItemView, fill: int = 0) -> None:
        super().__init__(view)
        self._view = view
        self._fill = fill
        self._fitting = False
        self._pending = False
        self._model = None
        #: Sections the user resized; the fit leaves them alone.
        self.user_sized: set[int] = set()
        header = _header(view)
        header.setStretchLastSection(False)
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.sectionResized.connect(self._on_section_resized)
        header.sectionCountChanged.connect(lambda *_: self.schedule())
        view.viewport().installEventFilter(self)
        self._watch_model()
        self.schedule()

    # -- triggers ---------------------------------------------------------
    def eventFilter(self, obj, event) -> bool:  # noqa: N802 - Qt override
        if event.type() in (QEvent.Type.Resize, QEvent.Type.Show):
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
            for name in _MODEL_SIGNALS:
                try:
                    getattr(self._model, name).disconnect(self.schedule)
                except (TypeError, RuntimeError):
                    pass
        self._model = model
        if model is not None:
            for name in _MODEL_SIGNALS:
                getattr(model, name).connect(self.schedule)

    def schedule(self, *_args) -> None:
        """Fit once the current burst of events is over."""
        if not self._pending:
            self._pending = True
            QTimer.singleShot(0, self._run)

    def _run(self) -> None:
        self._pending = False
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
        want = {
            c: max(view.sizeHintForColumn(c), header.sectionSizeHint(c), minimum) for c in fitted
        }
        fill_free = fill in visible and fill not in self.user_sized
        if fill_free and viewport > 0:
            # A narrow view: the fill column (a name, a path) gets its
            # content, up to half the width, before the others get theirs;
            # they give up what they have beyond their header label, in
            # proportion. Without this a 320 px archive dock left Name 31 px.
            need = min(
                max(view.sizeHintForColumn(fill), header.sectionSizeHint(fill), minimum),
                max(minimum, viewport // 2),
            )
            fixed = sum(header.sectionSize(c) for c in visible if c != fill and c not in want)
            room = max(0, viewport - fixed - need)
            total = sum(want.values())
            if fitted and total > room:
                # The others share what is left in proportion to what they
                # want; an elided "Compr…" reads better than a name that is
                # not there at all.
                for c in fitted:
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
