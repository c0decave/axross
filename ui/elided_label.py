"""One-line labels that cut with "…" instead of mid-word, and a row layout
that keeps a message whole before a side note.

The pane footer cut its messages mid-word with no way to read the rest:
after Ctrl+C at 1024x600 it read "2 Pfade in die Zwische" and the free
space "Frei: 249,0 MB / 274,5" (UX review round 7, M2).

* :class:`ElidedLabel` paints its text cut with "…" when it does not fit;
  the whole text is then its tooltip. ``text()`` stays the whole text. An
  optional short form (``set_texts``) is shown before the long one is cut.
* :class:`MessageFirstRow` is a QHBoxLayout in which the *yielding* label
  (the free space) gives its width up first, so the *message* label keeps
  as much of the message as the row allows.
"""

from __future__ import annotations

from PyQt6.QtCore import QRect, QSize, Qt
from PyQt6.QtGui import QPainter
from PyQt6.QtWidgets import QHBoxLayout, QLabel, QSizePolicy, QWidget

ELLIPSIS = "…"
#: Fewer characters than this (the "…" included) are not worth showing.
MIN_SHOWN = 8


class ElidedLabel(QLabel):
    """A one-line QLabel cut with "…" when narrower than its text."""

    def __init__(self, text: str = "", parent: QWidget | None = None) -> None:
        super().__init__(text, parent)
        self._short = ""
        self._own_tip = ""
        self.setTextFormat(Qt.TextFormat.PlainText)
        self.setWordWrap(False)
        policy = self.sizePolicy()
        policy.setHorizontalPolicy(QSizePolicy.Policy.Preferred)
        self.setSizePolicy(policy)

    # --- text -----------------------------------------------------------
    def setText(self, text: str) -> None:  # noqa: N802 - Qt
        self._short = ""
        super().setText(text)
        self._refresh_tip()

    def set_texts(self, text: str, short: str = "") -> None:
        """*text*, and *short* to show when *text* does not fit."""
        super().setText(text)
        self._short = short if short and short != text else ""
        self.updateGeometry()
        self._refresh_tip()

    def setToolTip(self, tip: str) -> None:  # noqa: N802 - Qt
        """A tooltip of the caller's own, shown while the text fits."""
        self._own_tip = tip
        self._refresh_tip()

    def shown_text(self) -> str:
        """The text as painted at the current width."""
        return self._fit(self.contentsRect().width())

    def is_elided(self) -> bool:
        return self.shown_text() != self.text()

    def needed_width(self) -> int:
        """Width the whole text needs (contents margins included)."""
        m = self.contentsMargins()
        return self.fontMetrics().horizontalAdvance(self.text()) + m.left() + m.right() + 2

    def _fit(self, width: int) -> str:
        full = self.text()
        metrics = self.fontMetrics()
        if metrics.horizontalAdvance(full) <= width:
            return full
        if self._short and metrics.horizontalAdvance(self._short) <= width:
            return self._short
        shown = metrics.elidedText(self._short or full, Qt.TextElideMode.ElideRight, width)
        # A stub like "Fr…" says nothing: leave the space empty instead.
        return "" if len(shown) < MIN_SHOWN else shown

    def _refresh_tip(self) -> None:
        tip = self.text() if self.is_elided() else self._own_tip
        if super().toolTip() != tip:
            super().setToolTip(tip)

    # --- geometry and painting ----------------------------------------------
    def sizeHint(self) -> QSize:  # noqa: N802 - Qt
        hint = super().sizeHint()
        return QSize(self.needed_width(), hint.height())

    def minimumSizeHint(self) -> QSize:  # noqa: N802 - Qt
        return QSize(0, super().minimumSizeHint().height())

    def resizeEvent(self, event) -> None:  # noqa: N802 - Qt
        super().resizeEvent(event)
        self._refresh_tip()

    def paintEvent(self, _event) -> None:  # noqa: N802 - Qt
        rect: QRect = self.contentsRect()
        shown = self._fit(rect.width())
        if not shown:
            return
        painter = QPainter(self)
        align = self.alignment()
        if not align & Qt.AlignmentFlag.AlignVertical_Mask:
            align |= Qt.AlignmentFlag.AlignVCenter
        self.style().drawItemText(
            painter, rect, int(align), self.palette(), self.isEnabled(), shown,
            self.foregroundRole(),
        )


class MessageFirstRow(QHBoxLayout):
    """A row whose *yielding* label shrinks (short form, then "…", then
    nothing) before the *message* label is cut."""

    def __init__(self, message: ElidedLabel, yielding: ElidedLabel) -> None:
        super().__init__()
        self.message = message
        self.yielding = yielding
        message.setSizePolicy(QSizePolicy.Policy.Expanding, message.sizePolicy().verticalPolicy())

    def message_room(self, width: int | None = None) -> int:
        """Width the message may have in a row *width* wide (the current
        one by default) when the yielding label gives up all of its."""
        if width is None:
            width = self.geometry().width()
        margins = self.contentsMargins()
        room = width - margins.left() - margins.right()
        shown = 0
        for i in range(self.count()):
            item = self.itemAt(i)
            widget = item.widget()
            if widget is self.message or widget is self.yielding:
                continue
            if widget is not None and widget.isHidden():
                continue
            if item.spacerItem() is not None:
                continue
            room -= item.sizeHint().width()
            shown += 1
        # spacing between the shown items: message, the others, yielding
        room -= self.spacing() * (shown + 1)
        return max(0, room)

    def setGeometry(self, rect: QRect) -> None:  # noqa: N802 - Qt
        room = self.message_room(rect.width())
        need = self.message.needed_width() if self.message.text() else 0
        cap = max(0, room - need)
        cap = min(cap, self.yielding.needed_width())
        if self.yielding.maximumWidth() != cap:
            self.yielding.setMaximumWidth(cap)
        super().setGeometry(rect)
