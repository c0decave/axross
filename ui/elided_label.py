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
* :class:`WrapAnywhereLabel` shows a value from outside - a name, a path -
  whole: plain text, wrapped at blanks and, inside a word wider than the
  label, anywhere. A QLabel wraps at blanks only, so a long name or path
  either made its window wider than the screen or, held to the window's
  width, was cut off at its edge (round 3 of the 2026-11 reviews:
  Properties, Permissions, Show Checksum, File Already Exists).
"""

from __future__ import annotations

import math

from PyQt6.QtCore import QPointF, QRect, QSize, Qt
from PyQt6.QtGui import QGuiApplication, QPainter, QTextLayout, QTextOption
from PyQt6.QtWidgets import QHBoxLayout, QLabel, QMenu, QSizePolicy, QStatusBar, QWidget

from ui.plain_text import one_line

ELLIPSIS = "…"
#: Fewer characters than this (the "…" included) are not worth showing.
MIN_SHOWN = 8
#: The size hint asks for at most this many average characters: a status
#: quoting a 5000-character name asked for some 35 000 px, and every
#: layout and window sized from a hint took it (``needed_width`` still
#: tells the whole text's width).
MAX_HINT_CHARS = 100


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
        super().setText(one_line(text))
        self._refresh_tip()

    def set_texts(self, text: str, short: str = "") -> None:
        """*text*, and *short* to show when *text* does not fit."""
        text, short = one_line(text), one_line(short)
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
        m = self.contentsMargins()
        cap = self.fontMetrics().averageCharWidth() * MAX_HINT_CHARS + m.left() + m.right() + 2
        return QSize(min(self.needed_width(), cap), hint.height())

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


class OneLineStatusBar(QStatusBar):
    """The window's status bar: a message is shown as the file pane shows
    a name (:func:`ui.plain_text.one_line`) - a bidi override in a quoted
    name read the message reversed, a line break pushed it out of the bar."""

    def showMessage(self, text: str, timeout: int = 0) -> None:  # noqa: N802 - Qt
        super().showMessage(one_line(text), timeout)


class WrapAnywhereLabel(QWidget):
    """A value shown whole: plain text wrapped at blanks, and anywhere
    inside a word wider than the label. ``text()`` is the text as given;
    the context menu's Copy copies it."""

    #: The width it asks for at most, in average characters (it wraps below).
    HINT_CHARS = 60

    def __init__(self, text: str = "", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._text = ""
        policy = QSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Preferred)
        policy.setHeightForWidth(True)
        self.setSizePolicy(policy)
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.customContextMenuRequested.connect(self._menu)
        self.setText(text)

    def text(self) -> str:
        return self._text

    def textFormat(self) -> Qt.TextFormat:  # noqa: N802 - as QLabel's
        """Always plain text: nothing in it is markup."""
        return Qt.TextFormat.PlainText

    def wordWrap(self) -> bool:  # noqa: N802 - as QLabel's
        return True

    def setText(self, text: str) -> None:  # noqa: N802 - Qt
        self._text = text or ""
        self.updateGeometry()
        self.update()

    def _lines(self, width: int):
        """The laid-out QTextLayout at *width* and its height."""
        # (a line break of the text is a line separator for QTextLayout)
        layout = QTextLayout(self._text.replace("\r\n", "\n").replace("\n", "\u2028"),
                             self.font())
        option = QTextOption()
        option.setWrapMode(QTextOption.WrapMode.WrapAtWordBoundaryOrAnywhere)
        layout.setTextOption(option)
        layout.beginLayout()
        y = 0.0
        while True:
            line = layout.createLine()
            if not line.isValid():
                break
            line.setLineWidth(max(1, width))
            line.setPosition(QPointF(0, y))
            y += line.height()
        layout.endLayout()
        return layout, max(math.ceil(y), self.fontMetrics().height())

    def hasHeightForWidth(self) -> bool:  # noqa: N802 - Qt
        return True

    def heightForWidth(self, width: int) -> int:  # noqa: N802 - Qt
        m = self.contentsMargins()
        inner = width - m.left() - m.right()
        return self._lines(inner)[1] + m.top() + m.bottom()

    def sizeHint(self) -> QSize:  # noqa: N802 - Qt
        m = self.contentsMargins()
        metrics = self.fontMetrics()
        full = max((metrics.horizontalAdvance(line) for line in self._text.split("\n")),
                   default=0)
        width = min(full + 1, metrics.averageCharWidth() * self.HINT_CHARS)
        width += m.left() + m.right()
        return QSize(width, self.heightForWidth(width))

    def minimumSizeHint(self) -> QSize:  # noqa: N802 - Qt
        metrics = self.fontMetrics()
        m = self.contentsMargins()
        return QSize(metrics.averageCharWidth() * 8 + m.left() + m.right(),
                     metrics.height() + m.top() + m.bottom())

    def resizeEvent(self, event) -> None:  # noqa: N802 - Qt
        # A window's layout does not ask a child's height for its width:
        # the height the text needs at this width is the least it gets.
        super().resizeEvent(event)
        need = self.heightForWidth(self.width())
        if self.minimumHeight() != need:
            self.setMinimumHeight(need)

    def paintEvent(self, _event) -> None:  # noqa: N802 - Qt
        rect = self.contentsRect()
        layout, _height = self._lines(rect.width())
        painter = QPainter(self)
        painter.setPen(self.palette().color(self.foregroundRole()))
        layout.draw(painter, QPointF(rect.topLeft()))

    def _menu(self, pos) -> None:
        menu = QMenu(self)
        from core.i18n import tr

        menu.addAction(tr("Copy"), lambda: QGuiApplication.clipboard().setText(self._text))
        menu.exec(self.mapToGlobal(pos))
