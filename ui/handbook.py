"""Help > Handbook (F1): the user guide inside the app.

The guide is docs/USAGE.md or its translation for the interface language
(core.handbook finds the file, in a checkout, a wheel or the bundle). The
window has the guide's contents on the left, a find field (Return: next
match) and the text on the right, rendered safely (ui.guide_view: no
resource is loaded, no raw HTML, every link decided here).

**F1 opens the section of the area you are in.** A widget names its help
topic in the property :data:`HELP_TOPIC_PROPERTY` (or a ``help_topic()``
method, as Edit > Settings… does for its open page); :func:`help_topic_of`
walks up from the focused widget to the first one that has a topic, and
core.handbook.SECTIONS maps the topic to a heading. No topic - or a
heading the guide no longer has - opens the contents.

Modal dialogs (Connect to Server, Settings) take F1 themselves
(:func:`install_help_key`): the main window's shortcut does not reach
them. The handbook they open is their child, so it can be used while
they wait.
"""

from __future__ import annotations

import logging
from collections.abc import Callable

from PyQt6.QtCore import Qt, QUrl
from PyQt6.QtGui import QKeySequence, QShortcut
from PyQt6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSplitter,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core import handbook as H
from core.guide_text import github_slug, headings, plain_heading
from core.i18n import tr
from ui import guide_view
from ui.close_corner import add_close_corner
from ui.icon_provider import set_window_icon

log = logging.getLogger(__name__)

#: The widget property that names a help topic (a key of core.handbook.SECTIONS).
HELP_TOPIC_PROPERTY = "axHelpTopic"
#: The key of the handbook.
HELP_KEY = "F1"


def set_help_topic(widget: QWidget, topic: str) -> None:
    """F1 in *widget* (or anything inside it) opens the section of *topic*."""
    widget.setProperty(HELP_TOPIC_PROPERTY, topic)


def help_topic_of(widget: QWidget | None) -> str | None:
    """The help topic of *widget*: its own, else its nearest parent's."""
    while widget is not None:
        method = getattr(widget, "help_topic", None)
        if callable(method):
            try:
                topic = method()
            except Exception:  # noqa: BLE001 - help must open regardless
                log.debug("help topic of %r failed", widget, exc_info=True)
                topic = None
            if topic:
                return str(topic)
        topic = widget.property(HELP_TOPIC_PROPERTY)
        if isinstance(topic, str) and topic:
            return topic
        widget = widget.parentWidget()
    return None


class HandbookDialog(QDialog):
    """The handbook: contents, find field, the guide."""

    def __init__(self, parent: QWidget | None = None, *, language: str | None = None,
                 root: str | None = None) -> None:
        super().__init__(parent)
        set_window_icon(self, "book")
        self.setWindowTitle(tr("Handbook") + " — axross")
        self._root = root
        self.handbook: H.Handbook = H.load(language, root=root)

        self.view = guide_view.GuideBrowser()
        self.view.anchorClicked.connect(self.on_link)

        self.contents = QTreeWidget()
        self.contents.setHeaderHidden(True)
        self.contents.itemActivated.connect(self._go_to_item)
        self.contents.itemClicked.connect(self._go_to_item)
        split = QSplitter()
        split.addWidget(self.contents)
        split.addWidget(self.view)
        split.setStretchFactor(1, 1)
        split.setSizes([260, 760])

        self.search = QLineEdit()
        self.search.setPlaceholderText(tr("Find (Return: next match)"))
        self.search.setClearButtonEnabled(True)
        self.search.returnPressed.connect(self.find_next)
        self.search_hint = QLabel()
        find_row = QHBoxLayout()
        find_row.addWidget(self.search, 1)
        find_row.addWidget(self.search_hint)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        #: Help > Tours…, for a window that has tours (the main window).
        self.tours_button = QPushButton(tr("Tours…"))
        self.tours_button.setToolTip(tr("Guided tours over the window"))
        self.tours_button.clicked.connect(self._open_tours)
        buttons.addButton(self.tours_button, QDialogButtonBox.ButtonRole.ActionRole)
        self.tours_button.setVisible(callable(getattr(parent, "show_tours", None)))
        for button in buttons.buttons():  # Return in the find field must not close
            button.setAutoDefault(False)
            button.setDefault(False)

        layout = QVBoxLayout(self)
        layout.addLayout(find_row)
        layout.addWidget(split, 1)
        layout.addWidget(buttons)
        add_close_corner(self)
        self.resize(1060, 700)
        self._show(self.handbook)

    # -- the text --------------------------------------------------------------------------

    @property
    def source(self) -> str:
        return self.handbook.source

    def _show(self, handbook: H.Handbook) -> None:
        self.handbook = handbook
        self.view.set_guide_markdown(handbook.text)
        self._fill_contents()

    def _fill_contents(self) -> None:
        tree = self.contents
        tree.clear()
        parent = None
        for level, text in headings(self.handbook.text):
            if level not in (2, 3):
                continue
            item = QTreeWidgetItem([plain_heading(text)])
            item.setData(0, Qt.ItemDataRole.UserRole, plain_heading(text))
            if level == 2 or parent is None:
                tree.addTopLevelItem(item)
                parent = item
            else:
                parent.addChild(item)
        tree.expandAll()

    def section_names(self) -> list[str]:
        """The headings of the contents, in order."""
        return H.outline(self.handbook.text)

    # -- going places ----------------------------------------------------------------------

    def _go_to_item(self, item: QTreeWidgetItem, _column: int = 0) -> None:
        self.go_to_heading(item.data(0, Qt.ItemDataRole.UserRole))

    def _go(self, match: Callable[[str], bool]) -> bool:
        cursor = guide_view.heading_block(self.view, match)
        if cursor is None:
            self.search_hint.setText(tr("Not found"))
            return False
        self.search_hint.clear()
        guide_view.scroll_to(self.view, cursor)
        self._select_in_contents(cursor.block().text())
        return True

    def _select_in_contents(self, heading: str) -> None:
        found = self.contents.findItems(heading, Qt.MatchFlag.MatchExactly
                                        | Qt.MatchFlag.MatchRecursive)
        if found:
            self.contents.blockSignals(True)
            self.contents.setCurrentItem(found[0])
            self.contents.blockSignals(False)

    def go_to_heading(self, heading: str) -> bool:
        """Scroll to the heading *heading* (as rendered); False when the
        guide has none of that name."""
        wanted = plain_heading(heading or "")
        return bool(wanted) and self._go(lambda text: text == wanted)

    def current_heading(self) -> str:
        """The heading the text cursor stands in (the last one gone to)."""
        block = self.view.textCursor().block()
        while block.isValid() and block.blockFormat().headingLevel() == 0:
            block = block.previous()
        return block.text() if block.isValid() else ""

    def show_contents(self) -> None:
        """The start of the guide, the contents focused."""
        self.search_hint.clear()
        self.view.moveCursor(self.view.textCursor().MoveOperation.Start)
        self.view.verticalScrollBar().setValue(0)
        self.contents.setCurrentItem(None)
        self.contents.setFocus()

    def go_to_topic(self, topic: str | None) -> bool:
        """The section of help *topic*; the contents for an unknown topic or
        a section the guide does not have (then False)."""
        heading = H.section_for(topic, self.handbook, root=self._root)
        if heading is not None and self.go_to_heading(heading):
            return True
        if topic:
            log.info("handbook: no section for help topic %r, showing the contents", topic)
        self.show_contents()
        return False

    def set_language(self, language: str, fragment: str = "") -> bool:
        """Show the guide of *language* (the same folder); False when there
        is none."""
        other = H.sibling(self.handbook, language)
        if other is None:
            self.search_hint.setText(tr("Not found"))
            return False
        self._show(other)
        if fragment:
            self._go(lambda text: github_slug(text) == fragment)
        else:
            self.show_contents()
        return True

    def on_link(self, url: QUrl) -> None:
        """Every link: ``#section`` scrolls, ``USAGE_xx.md`` switches the
        language, another document of the repository and http(s) pages open
        in the browser (core.handbook.classify_link), the rest does nothing."""
        kind, value, fragment = H.classify_link(url.toString())
        if kind == "section":
            self._go(lambda text: github_slug(text) == fragment)
        elif kind == "language":
            self.set_language(value, fragment)
        elif kind == "web":
            from core import desktop_open

            desktop_open.open_url(QUrl(value))
        else:
            log.info("handbook: link not opened (%s): %s", value, url.toString()[:200])

    # -- find ------------------------------------------------------------------------------

    def find_next(self) -> bool:
        """Select the next match, wrapping at the end."""
        needle = self.search.text()
        self.search_hint.clear()
        if guide_view.find_next(self.view, needle):
            return True
        if needle:
            self.search_hint.setText(tr("Not found"))
        return False

    def _open_tours(self) -> None:
        opener = getattr(self.parent(), "show_tours", None)
        if callable(opener):
            opener()

    def keyPressEvent(self, event) -> None:  # noqa: N802 — Qt
        if event.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
            return  # no default button: Return never closes the handbook
        super().keyPressEvent(event)


def open_handbook_for(dialog: QWidget, topic: str | None) -> HandbookDialog:
    """A handbook as a child of *dialog* (a modal dialog's own: usable while
    it waits), at the section of *topic*; one per dialog, raised again."""
    book = getattr(dialog, "_ax_handbook", None)
    if book is None:
        book = HandbookDialog(dialog)
        book.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        book.destroyed.connect(lambda *_: setattr(dialog, "_ax_handbook", None))
        dialog._ax_handbook = book
    book.go_to_topic(topic)
    book.show()
    book.raise_()
    book.activateWindow()
    return book


def install_help_key(dialog: QWidget, topic: str | Callable[[], str | None]) -> QShortcut:
    """F1 in *dialog* opens the handbook at *topic* (a key of
    core.handbook.SECTIONS, or a function that answers one when F1 is
    pressed); the widget with the focus wins when it names a topic of its
    own."""
    if isinstance(topic, str):
        set_help_topic(dialog, topic)
    elif callable(topic) and not callable(getattr(dialog, "help_topic", None)):
        dialog.help_topic = topic  # what help_topic_of asks

    def opened() -> None:
        from PyQt6.QtWidgets import QApplication

        focus = QApplication.focusWidget()
        inside = focus is not None and (focus is dialog or dialog.isAncestorOf(focus))
        chosen = help_topic_of(focus) if inside else None
        if chosen is None:
            chosen = topic() if callable(topic) else topic
        open_handbook_for(dialog, chosen)

    shortcut = QShortcut(QKeySequence(HELP_KEY), dialog)
    shortcut.setContext(Qt.ShortcutContext.WidgetWithChildrenShortcut)
    shortcut.activated.connect(opened)
    return shortcut


__all__ = [
    "HELP_KEY",
    "HELP_TOPIC_PROPERTY",
    "HandbookDialog",
    "help_topic_of",
    "install_help_key",
    "open_handbook_for",
    "set_help_topic",
]
