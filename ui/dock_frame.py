"""The scroll area a panel's content sits in, so the panel's smallest size
is not its content's.

A QDockWidget is never smaller than its widget's minimum size. The dock
area stacks its panels and a workspace sets its panels beside its panes,
so those minimums add up: two detached Agent conversations (582x341 px
each), the Media Player (355x568 px) and the Agent dock (586x379 px) asked
for a window taller than most screens. A window manager that holds the
window at the screen's size (tiling, maximized) then made Qt lay the
panels over each other; one that does not left the window larger than the
screen. In a :class:`PanelFrame` the panel takes the space it is given and
its content scrolls when that is less than it needs - with room, the
content fills the panel as before.

The content sits in a plain holder widget, not directly in the scroll
area: the themes style a scroll area's own widget (``QScrollArea > QWidget
> QWidget``: transparent), which would have changed the look of a content
that is itself a styled widget (the Markdown Preview's QTextBrowser).
"""

from __future__ import annotations

from PyQt6 import sip
from PyQt6.QtCore import QSize, Qt
from PyQt6.QtWidgets import QFrame, QScrollArea, QVBoxLayout, QWidget


#: The height a bottom dock (Transfers, Terminal, Log, Console, Scripts -
#: one tab group) asks for at most. Qt opens a tab group at the largest size
#: hint of its tabs: Console (490 px) and Scripts (500 px) gave the bottom
#: area 464 of an 800 px window and the file panes 160. Transfers, Terminal
#: and Log ask for 253-259 px; tests/test_bottom_docks_leave_room.py holds
#: that this covers them.
BOTTOM_DOCK_HINT_PX = 260


def capped_hint(hint: QSize, minimum: QSize | None = None,
                cap: int = BOTTOM_DOCK_HINT_PX) -> QSize:
    """*hint* no taller than *cap*, never below *minimum*."""
    height = min(hint.height(), cap)
    if minimum is not None:
        height = max(height, minimum.height())
    return QSize(hint.width(), height)


class PanelFrame(QScrollArea):
    """A frameless scroll area whose content always gets the whole panel,
    never less than the content needs (then it scrolls)."""

    def __init__(self, parent: QWidget | None = None, *,
                 max_hint_height: int | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("panelFrame")
        #: The height the frame asks for at most (None: what the content
        #: asks): Qt sizes a dock - and a tab group by its tallest tab - by
        #: its content's size hint, not by QDockWidget.sizeHint().
        self._max_hint_height = max_hint_height
        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.Shape.NoFrame)
        # No Tab stop of its own (a scroll area is one): the keys go through
        # the content's widgets as they did without the frame.
        self.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        holder = QWidget()
        holder.setObjectName("panelFrameHolder")
        box = QVBoxLayout(holder)
        box.setContentsMargins(0, 0, 0, 0)
        box.setSpacing(0)
        self.setWidget(holder)
        # QScrollArea.setWidget switches the filling on: the panel's own
        # background shows through, as it did without the frame.
        holder.setAutoFillBackground(False)
        self._holder = holder
        self._content: QWidget | None = None

    def content(self) -> QWidget | None:
        """The panel's content; None when there is none (or it was moved
        elsewhere without take_content)."""
        content = self._content
        if content is None or sip.isdeleted(content) or content.parentWidget() is not self._holder:
            return None
        return content

    def set_content(self, widget: QWidget) -> QWidget | None:
        """*widget* becomes the content; the one it replaces is returned
        without a parent (None when there was none)."""
        if widget is self.content():
            return None
        old = self.take_content()
        self._holder.layout().addWidget(widget)
        self._content = widget
        return old

    def take_content(self) -> QWidget | None:
        """The content out of the frame, without a parent; None when there
        is none."""
        content = self.content()
        self._content = None
        if content is None:
            return None
        self._holder.layout().removeWidget(content)
        content.setParent(None)
        return content

    def content_minimum(self) -> QSize:
        """The smallest size the content asks for: what the panel needs to
        show it whole, without scrolling (ui.dock_fit reads it)."""
        holder = self._holder
        return holder.minimumSizeHint().expandedTo(holder.minimumSize())

    def sizeHint(self) -> QSize:  # noqa: N802 - Qt override
        # The size the content asks for, as when it was the panel's own
        # widget: QScrollArea caps its hint at 36x24 lines of text, which
        # opened a taller panel with a scroll bar where there was room.
        holder = self._holder
        hint = holder.sizeHint().expandedTo(holder.minimumSizeHint())
        frame = 2 * self.frameWidth()
        hint = QSize(hint.width() + frame, hint.height() + frame)
        if self._max_hint_height is not None:
            hint = capped_hint(hint, cap=self._max_hint_height)
        return hint


def framed(widget: QWidget, parent: QWidget | None = None, *,
           max_hint_height: int | None = None) -> PanelFrame:
    """*widget* in a new :class:`PanelFrame` - for a dock's setWidget."""
    frame = PanelFrame(parent, max_hint_height=max_hint_height)
    frame.set_content(widget)
    return frame


__all__ = ["PanelFrame", "framed"]
