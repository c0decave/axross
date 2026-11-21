"""The Markdown viewer window: a ``.md`` file of any connection rendered
(:mod:`ui.markdown_view`) with its outline, find, zoom, Reload and Edit.

Opened by F3 and a double-click on a Markdown file (F4 still edits it), and
for a Markdown member of an archive. The text is read on a worker thread
(at most :data:`ui.markdown_view.TEXT_LIMIT` bytes; a cut is said), so a
slow server holds up no window. A local file is shown anew when it changes
on disk (QFileSystemWatcher; where it was scrolled to stays).

Find (Ctrl+F) marks every match as it is typed and says which one of how
many is selected (Enter / F3 the next, Shift+Enter / Shift+F3 the one
before). Export (the menu): the page as HTML for a browser
(ui.markdown_html.export_html: its images in it, nothing it may load from
elsewhere), as PDF, or printed (Ctrl+P) - always in the light colours.

Links (the view hands every link that is not an anchor of the text here),
relative to this file's folder, on the same connection - each opens *in
this window*, Back / Forward (Alt+Left / Alt+Right, the mouse's buttons)
go through the files and places visited:

* another Markdown file, at the heading its ``#fragment`` names;
* a folder: its README (README.md, index.md) when it has one;
* a text file (LICENSE, a script): shown as its text, coloured by its kind;
* an image: shown at its own size (ui.markdown_view.ImageZoom);
* an ``http(s)`` link opens in the web browser - a ``mailto:`` one in the
  mail program - only when the security mode allows external viewers and
  after the user said yes to a question that shows the real address
  (:func:`ui.markdown_safe.ask_open_link`);
* anything else (``file:``, an absolute path, a file that is
  neither text nor an image, a secret file on this computer) is named in
  the status line, not opened.
"""

from __future__ import annotations

import logging
import posixpath
import re
import time

from PyQt6 import sip
from PyQt6.QtCore import QFileSystemWatcher, Qt, QTimer, QUrl
from PyQt6.QtGui import QColor, QKeySequence, QShortcut, QTextCharFormat, QTextCursor, QTextDocument
from PyQt6.QtWidgets import (
    QDialog,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMenu,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
)

from core.i18n import tr
from core.markdown_cli import FOLDER_PAGES  # (the names a folder's own page goes by: a link to it opens it)
from ui import markdown_view as MV
from ui import viewer_window as VW
from ui.close_corner import add_close_corner
from ui.icon_provider import set_window_icon

log = logging.getLogger(__name__)

#: The name the window's size and place are saved under.
#: A window narrower than this shows zoom and the find field under the buttons.
NARROW = 760
#: The narrowest the window may be.
MINIMUM_WIDTH = 440
#: A window narrower than this shows no outline (the Outline button shows it).
OUTLINE_WIDTH = 700
STATE_NAME = "markdown"
#: Matches find marks at most (and counts at most FIND_COUNT).
FIND_MARKS = 1000
FIND_COUNT = 10_000
#: Seconds a search's count and marks take at most in one turn (_mark_matches): past it, "N+" - 10,000
#: matches in a long page took 0.15 s at each Find Next.
FIND_TURN = 0.03
#: Images a link may name (shown at their own size).
IMAGE_SUFFIXES = (".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".svg", ".svgz", ".ico")
#: Places Back keeps.
HISTORY = 100


#: What a viewer without a file shows (the program axross-markdown started
#: without one).
WELCOME = """# Markdown Viewer

Open a Markdown file with **Open…** (Ctrl+O), or name files on the command line.

- the headings beside the text, a click goes there
- tables, task lists, strike-through, footnotes, highlighted code
- images beside the file; nothing is loaded from the network
- find (Ctrl+F), zoom (Ctrl+Plus / Ctrl+Minus / Ctrl+0), Reload (F5), Edit (F4), Back (Alt+Left)
- Export: HTML, PDF, Print (Ctrl+P); a file changed on disk is shown anew
"""


def unreadable_reason(error) -> str:
    """Why a file cannot be read, in words - not the system's error with its path again ("[Errno 2] No such
    file or directory: '/…/gone.md'")."""
    if isinstance(error, FileNotFoundError):
        return tr("it does not exist")
    if isinstance(error, PermissionError):
        return tr("you may not read it")
    if isinstance(error, IsADirectoryError):
        return tr("it is a folder without a README")
    if isinstance(error, OSError) and error.strerror:
        return error.strerror
    return str(error)


#: Blocks of a page past which the top of the view is looked for by halves (_first_shown).
HALVED_BLOCKS = 5000


def _first_shown(browser) -> QTextCursor:
    """A cursor at the top of what *browser* shows. On a long page found by halves over its blocks' places -
    Qt's own hit test walks every frame before it: at the end of 50,000 code blocks, 0.09 s a search."""
    document = browser.document()
    if document.blockCount() <= HALVED_BLOCKS:
        return browser.cursorForPosition(browser.viewport().rect().topLeft())
    layout, top = document.documentLayout(), browser.verticalScrollBar().value()
    low, high = 0, document.blockCount() - 1
    while low < high:
        middle = (low + high) // 2
        if layout.blockBoundingRect(document.findBlockByNumber(middle)).bottom() < top:
            low = middle + 1
        else:
            high = middle
    return QTextCursor(document.findBlockByNumber(low))


class MarkdownViewerDialog(QDialog):
    """The Markdown file *path* of *backend*, rendered. *source_pane*: the
    pane it was opened from (Edit opens the editor of its window).

    For a program of its own (ui.markdown_app): *opener(viewer)* adds Open…
    (Ctrl+O); *editor(backend, path)* is what Edit does; *view_menu(menu)*
    fills a View button's menu (the program's theme); an empty *path*
    shows :data:`WELCOME` until a file is opened."""

    def __init__(self, backend, path: str, parent=None, *, source_pane=None,
                 opener=None, editor=None, view_menu=None) -> None:
        super().__init__(parent)
        set_window_icon(self, "markdown")
        self.backend, self.path, self.source_pane = backend, path, source_pane
        self._opener, self._editor, self._view_menu = opener, editor, view_menu
        self.cut = False
        self.loaded_once = False
        self._generation = 0
        #: what is shown: "markdown", or "text" (a text file shown as its text)
        self.shown_as = "markdown"
        #: the places visited before and after this one: (path, scroll, shown_as)
        self.back_list: list[tuple[str, int, str]] = []
        self.forward_list: list[tuple[str, int, str]] = []
        self._changed_on_disk = False
        self.watcher = QFileSystemWatcher(self)
        self.watcher.fileChanged.connect(self._file_touched)  # (a method, not a lambda: see _file_touched)
        self.watcher.directoryChanged.connect(self._folder_changed)
        self._watch_timer = QTimer(self)
        self._watch_timer.setSingleShot(True)
        self._watch_timer.setInterval(300)  # (an editor writes in several steps)
        self._watch_timer.timeout.connect(self._file_changed)
        self._find_timer = QTimer(self)
        self._find_timer.setSingleShot(True)
        self._find_timer.setInterval(150)
        self._find_timer.timeout.connect(self._find_as_typed)
        VW.allow_maximize(self)
        self._build_ui()
        self._update_title()
        VW.restore_window_state(self, STATE_NAME)
        self._watch()
        self.reload()

    # -- the window --

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        add_close_corner(self)
        bar = QHBoxLayout()
        self.outline_button = QPushButton(tr("Outline"))
        self.outline_button.setCheckable(True)
        self.outline_button.setChecked(True)
        self.outline_button.setToolTip(tr("Show or hide the headings beside the text"))
        self.outline_button.toggled.connect(self._outline_toggled)
        self._outline_chosen, self._outline_auto = False, False
        self.reload_button = QPushButton(tr("Reload"))
        self.reload_button.setToolTip(tr("Read the file and its images again (F5)"))
        self.reload_button.clicked.connect(self.reload)
        self.edit_button = QPushButton(tr("Edit"))
        self.edit_button.setToolTip(tr("Open the file in the editor (F4)"))
        self.edit_button.clicked.connect(self.edit)
        self.edit_button.setEnabled(bool(self.path))
        self.reload_button.setEnabled(bool(self.path))
        self.open_button = None
        if self._opener is not None:
            self.open_button = QPushButton(tr("Open…"))
            self.open_button.setToolTip(tr("Open Markdown files (Ctrl+O)"))
            self.open_button.clicked.connect(lambda: self._opener(self))
        zoom_out = QPushButton("−")
        zoom_out.setToolTip(tr("Smaller (Ctrl+-)"))
        zoom_out.clicked.connect(lambda: self.view.zoom_by(-1))
        zoom_reset = QPushButton("100%")  # (the zoom level as it is - a click: its own size again)
        zoom_reset.setToolTip(tr("The text's size – click for the original size (Ctrl+0)"))
        self.zoom_reset = zoom_reset
        zoom_reset.clicked.connect(lambda: self.view.zoom_by(0))
        zoom_in = QPushButton("+")
        zoom_in.setToolTip(tr("Larger (Ctrl++)"))
        zoom_in.clicked.connect(lambda: self.view.zoom_by(1))
        self.back_button = QPushButton("←")
        self.back_button.setToolTip(tr("Back (Alt+Left)"))
        self.back_button.clicked.connect(self.back)
        self.forward_button = QPushButton("→")
        self.forward_button.setToolTip(tr("Forward (Alt+Right)"))
        self.forward_button.clicked.connect(self.forward)
        # (a push button as its neighbours, its menu's arrow beside the text - a
        # tool button's was drawn over its "t")
        self.export_button = QPushButton(tr("Export"))
        self.export_button.setToolTip(tr("Save the page as HTML or PDF, or print it"))
        menu = QMenu(self.export_button)
        menu.addAction(tr("Export HTML…"), self.ask_export_html)
        menu.addAction(tr("Export PDF…"), self.ask_export_pdf)
        if _print_support() is not None:
            menu.addAction(tr("Print…"), self.print_page)
        self.export_button.setMenu(menu)
        self.view_button = None
        if self._view_menu is not None:
            self.view_button = QPushButton(tr("&View"))  # (Alt+V opens it)
            self.view_button.setToolTip(tr("The theme of the window"))
            menu = QMenu(self.view_button)
            self._view_menu(menu)
            self.view_button.setMenu(menu)
        self.find_field = QLineEdit()
        self.find_field.setPlaceholderText(tr("Find (Ctrl+F, Enter: next, Shift+Enter: back)"))
        self.find_field.setClearButtonEnabled(True)
        self.find_field.returnPressed.connect(self.find_next)
        self.find_field.textChanged.connect(self._find_typed)
        self.find_count = QLabel()
        self.find_count.setTextFormat(Qt.TextFormat.PlainText)
        for widget in (self.back_button, self.forward_button, zoom_out, zoom_in):
            widget.setFixedWidth(max(32, widget.fontMetrics().horizontalAdvance("M") * 3))  # (a sign: no more room)
        zoom_reset.setFixedWidth(zoom_reset.fontMetrics().horizontalAdvance("1000%") + 24)
        bar.setSpacing(4)
        self._buttons = [w for w in (self.open_button, self.back_button, self.forward_button, self.outline_button,
                                     self.reload_button, self.edit_button) if w is not None]
        self._zoom = [zoom_out, zoom_reset, zoom_in]
        self._bar = bar
        self._find_bar = QHBoxLayout()  # (a second row in a narrow window: _fold_toolbar)
        self._find_bar.setSpacing(4)
        self._find_wide = None
        root.addLayout(bar)
        root.addLayout(self._find_bar)
        self.find_field.setMinimumWidth(160)
        self._hint_colour()
        # (a narrow window too: the toolbar in two rows - it could not be
        # narrower than 742 pixels)
        self.setMinimumWidth(MINIMUM_WIDTH)
        self._fold_toolbar()
        self.view = MV.MarkdownView(MV.ImageSource(self.backend, self.path), parent=self)
        self.view.navigator = self
        self.view.link.connect(self.follow)
        self.view.zoom_changed.connect(lambda percent: self.zoom_reset.setText(f"{percent}%"))
        root.addWidget(self.view, 1)
        self._update_history_buttons()
        for keys, slot in (
            (QKeySequence.StandardKey.Find, lambda: self.find_field.setFocus()),
            (QKeySequence.StandardKey.ZoomIn, lambda: self.view.zoom_by(1)),
            *(((QKeySequence("Ctrl+="), lambda: self.view.zoom_by(1)),)  # (Ctrl++ without Shift: it did nothing -
              if QKeySequence("Ctrl+=") not in QKeySequence.keyBindings(QKeySequence.StandardKey.ZoomIn)
              else ()),  # unless the platform's own zoom key is it: two on one key fire neither)
            (QKeySequence.StandardKey.ZoomOut, lambda: self.view.zoom_by(-1)),
            (QKeySequence("Ctrl+0"), lambda: self.view.zoom_by(0)),
            (QKeySequence("F5"), self.reload),
            (QKeySequence("F4"), self.edit),
            (QKeySequence("F3"), self.find_next),
            (QKeySequence("Shift+F3"), lambda: self.find_next(backward=True)),
            (QKeySequence.StandardKey.Print, self.print_page),
        ):
            shortcut = QShortcut(QKeySequence(keys), self)
            shortcut.activated.connect(slot)
        for keys, slot in ((QKeySequence("Shift+Return"), lambda: self.find_next(backward=True)),
                           (QKeySequence("Shift+Enter"), lambda: self.find_next(backward=True)),
                           (QKeySequence("Escape"), self.end_find)):
            shortcut = QShortcut(keys, self.find_field)
            shortcut.setContext(Qt.ShortcutContext.WidgetShortcut)
            shortcut.activated.connect(slot)
        if self._opener is not None:
            QShortcut(QKeySequence.StandardKey.Open, self).activated.connect(lambda: self._opener(self))
        VW.install_window_keys(self, fullscreen=False)
        # A dialog presses its default button on Enter: in the text (or after
        # a find) that toggled the outline / went Back. None is default here.
        for button in self.findChildren(QPushButton):
            button.setAutoDefault(False)
            button.setDefault(False)
        # The text has the focus: Space, Page Down, the arrows scroll it at
        # once (it was a tool button's: Space opened its menu).
        self.setFocusProxy(self.view.browser)
        self.view.browser.setFocus()

    def changeEvent(self, event) -> None:  # noqa: N802 - Qt
        super().changeEvent(event)
        if event.type() == event.Type.PaletteChange and hasattr(self, "find_field"):
            self._hint_colour()

    def _hint_colour(self) -> None:
        """The find field's placeholder between its text's colour and its
        ground's, apart from both (in dark it was all but invisible)."""
        from PyQt6.QtGui import QColor, QPalette

        source = self.palette()  # (the window's: the field's own follows it later)
        text, base = source.color(QPalette.ColorRole.Text), source.color(QPalette.ColorRole.Base)
        palette = QPalette(source)
        hint = QColor(round(0.75 * text.red() + 0.25 * base.red()), round(0.75 * text.green() + 0.25 * base.green()),
                      round(0.75 * text.blue() + 0.25 * base.blue()))
        if palette.color(QPalette.ColorRole.PlaceholderText) != hint:
            palette.setColor(QPalette.ColorRole.PlaceholderText, hint)
            self.find_field.setPalette(palette)

    def showEvent(self, event) -> None:  # noqa: N802 - Qt
        super().showEvent(event)
        # (the dialogs' corner buttons let any dialog go down to 120 pixels once shown - ui.close_corner:
        # this one's toolbar folds to MINIMUM_WIDTH, no narrower; at 260 its buttons were cut off)
        QTimer.singleShot(0, self._keep_minimum)

    def _file_touched(self, _path: str) -> None:
        """The watched file changed: looked at once the editor is done
        writing. (A bound method, not a lambda: PyQt drops a method's
        connection with its object - the reader's tests crashed now and
        then, SIGSEGV in one of these two lambdas, called for a dialog
        already gone.)"""
        self._watch_timer.start()

    def _find_typed(self, _text: str) -> None:
        self._find_timer.start()

    def _keep_minimum(self) -> None:
        if not sip.isdeleted(self) and self.minimumWidth() < MINIMUM_WIDTH:
            self.setMinimumWidth(MINIMUM_WIDTH)
            if self.width() < MINIMUM_WIDTH:
                self.resize(MINIMUM_WIDTH, self.height())

    def resizeEvent(self, event) -> None:  # noqa: N802 - Qt
        super().resizeEvent(event)
        self._fold_toolbar()

    def _outline_toggled(self, on: bool) -> None:
        if not hasattr(self, "view"):
            return  # (still being built)
        self.view.outline.setVisible(on)
        if not self._outline_auto:
            self._outline_chosen = True  # (the reader's choice: kept, whatever the width)

    def _fit_outline(self) -> None:
        """No outline in a window narrower than OUTLINE_WIDTH (it took 190 of
        440 pixels) - unless asked for with the button; back when wider."""
        if self._outline_chosen or not hasattr(self, "view"):
            return
        wanted = self.width() >= OUTLINE_WIDTH
        if wanted != self.outline_button.isChecked():
            self._outline_auto = True
            try:
                self.outline_button.setChecked(wanted)
            finally:
                self._outline_auto = False

    def _fold_toolbar(self) -> None:
        """The toolbar in one row - or, in a window too narrow for it, in two:
        the buttons, then zoom and the find field (at 560 pixels it was
        squeezed to "Fi…", and the window could not be narrower than 742)."""
        self._fit_outline()
        wide = self.width() >= NARROW
        if wide == self._find_wide:
            return
        self._find_wide = wide
        for layout in (self._bar, self._find_bar):
            while layout.count():
                layout.takeAt(0)  # (the widgets stay: put in again below)
        first = self._buttons + ([] if not wide else self._zoom) + [self.export_button] \
            + ([self.view_button] if self.view_button is not None else [])
        second = [] if wide else self._zoom
        for widget in first:
            self._bar.addWidget(widget)
        self._bar.addStretch(1)
        target = self._bar if wide else self._find_bar
        for widget in second:
            target.addWidget(widget)
        target.addWidget(self.find_field, 1)
        target.addWidget(self.find_count)

    def _update_title(self) -> None:
        self.view.page_name = self._name() if self.path else ""
        if not self.path:
            self.setWindowTitle(tr("Markdown Viewer"))
            return
        name = self._name() or self.path
        self.setWindowTitle(tr("{name} – Markdown Viewer").format(name=MV.printable(name)))

    def done(self, result: int) -> None:  # noqa: D401 - Qt override
        VW.save_window_state(self, STATE_NAME)
        super().done(result)

    # -- the text --

    def reload(self, anchor: str = "", scroll: int | None = None) -> None:
        """Read the file (and, at the next rendering, its images) again, on
        a worker thread - and show it at *anchor* or *scroll* (else where it
        was)."""
        self._generation += 1
        generation = self._generation
        self.view.forget_images()
        if not self.path:
            self.view.show_text(tr(WELCOME), anchor, scroll)
            self.loaded_once = True
            self.view.status.setText("")
            return
        self.view.status.setText(tr("Reading…"))
        backend, path = self.backend, self.path

        def work():
            if MV._is_local(backend):
                import os
                import stat

                if not stat.S_ISREG(os.stat(path).st_mode):  # a FIFO, a device: never opened
                    raise OSError(tr("not a regular file"))
            return MV.read_text(backend, path)

        MV.in_background(work, lambda result, error: self._read(generation, result, error, anchor, scroll),
                         owner=self)

    def _read(self, generation: int, result, error, anchor: str = "", scroll: int | None = None) -> None:
        if generation != self._generation or sip.isdeleted(self):
            return  # a newer Reload is on its way
        if isinstance(error, MV.BinaryFile):  # (a picture, a program: said in the page - it was garbage)
            name = MV.printable(self._name() or self.path)
            self.view.show_text(tr("{name} is not a text file: it holds binary data, so it is not shown.").format(
                name="`" + name.replace("`", "'") + "`"), anchor, scroll)
            self.view.status.setText("")
            self.loaded_once = True
            return
        if error is not None:
            why = unreadable_reason(error)
            said = tr("Cannot read {path}: {error}").format(path=MV.printable(self.path), error=MV.printable(why))
            self.view.status.setText(said)
            # (said in the page too: a missing file was a blank page, the reason in the status line only)
            name = MV.printable(self._name() or self.path).replace("`", "'")
            self.view.show_text(tr("{name} cannot be read: {error}").format(
                name="`" + name + "`", error=MV.printable(why).replace("`", "'")), anchor, scroll)
            self.view.status.setText(said)
            return
        text, self.cut = result
        if self.shown_as == "text":
            text = as_code(text, self.path)
        if self.view.status.text() == tr("Reading…"):  # ("Reading…" done - what was said since, a link
            self.view.status.setText("")  # followed meanwhile "Not opened (…)", stays)
        self.view.show_text(text, anchor, scroll)
        self.loaded_once = True
        # (said once the page is made: "Rendering…" stays meanwhile - cleared
        # here, a long file showed nothing for seconds)
        if self.cut:
            self.view.say(tr("Only the first {mib} MiB of the file are shown.").format(mib=MV.TEXT_LIMIT >> 20))
        elif self._changed_on_disk:
            self.view.say(tr("Shown anew: the file changed on disk."))
        self._changed_on_disk = False

    # -- changes on disk --

    def _watch(self) -> None:
        """Watch this file (a local one) for changes - and its folder: an
        editor that saves by writing a new file and renaming it over the old
        one ends the watch of the file."""
        for watched in self.watcher.files() + self.watcher.directories():
            self.watcher.removePath(watched)
        if not self.path or not MV._is_local(self.backend):
            return
        import os

        if os.path.isfile(self.path):
            self.watcher.addPath(self.path)
        folder = os.path.dirname(self.path)
        if os.path.isdir(folder):
            self.watcher.addPath(folder)

    def _folder_changed(self, _folder: str) -> None:
        import os

        if self.path and self.path not in self.watcher.files() and os.path.isfile(self.path):
            self._watch_timer.start()  # (written anew under its name)

    def _file_changed(self) -> None:
        """The file changed on disk: shown anew where it was (Reload)."""
        import os

        if not self.path or sip.isdeleted(self):
            return
        if self.path not in self.watcher.files() and os.path.isfile(self.path):
            self.watcher.addPath(self.path)
        if not os.path.isfile(self.path):
            self.view.status.setText(tr("The file is no longer there: {path}").format(
                path=MV.printable(self.path)))
            return
        self._changed_on_disk = True
        self.reload()

    def find_next(self, backward: bool = False) -> bool:
        """Select the next match of the find field's text (*backward*: the
        one before), from the text cursor, round past the end; mark every
        match and say which one this is of how many."""
        needle = self.find_field.text()
        if not needle:
            self.end_find(focus=False)
            return False
        flags = QTextDocument.FindFlag.FindBackward if backward else QTextDocument.FindFlag(0)
        browser = self.view.browser
        since = browser.textCursor().selectionStart() if backward else browser.textCursor().selectionEnd()
        # (in the page's order, round past its end - a part not laid out yet
        # looked in, laid out first when it holds the next match: None meanwhile)
        found = self.view.find_match(needle, backward, flags, lambda: self.find_next(backward))
        if found is None:
            return False
        if found and self._into_fold(needle, since, backward):
            return False  # (a folded <details> on the way holds it: opened, then the match in it selected)
        if not found and self.view.unfold_for(needle=needle, then=lambda: self.find_next(backward)):
            return False  # (in a folded <details>: opened, as a browser's find does, then found)
        self._mark_matches(needle)
        if not found:
            self.view.status.setText(tr("Not found: {text}").format(text=MV.printable(needle)))
        elif self.view.status.text().startswith(tr("Not found: {text}").split("{")[0]):
            self.view.status.setText("")
        return found

    def _into_fold(self, needle: str, since: int, backward: bool) -> bool:
        """A folded <details> between *since* and the match find_match just
        selected (in the page's order, round past its end) that holds
        *needle*: opened, the find going on in it - its first match (its last
        one: *backward*). Find skipped them whenever the page had another
        match (t/find.md: "of 9", the tenth in the fold)."""
        folds = self.view.folds_holding(needle)
        if not folds:
            return False
        browser = self.view.browser
        hit = browser.textCursor().selectionStart()
        end = browser.document().characterCount()
        if not backward:
            spans = [(since, hit)] if hit >= since else [(since, end), (0, hit)]
            on_way = [fold for low, high in spans for fold in folds if low <= fold[0] < high]
        else:
            spans = [(hit, since)] if hit < since else [(hit, end), (0, since)]
            on_way = [fold for low, high in spans for fold in folds if low <= fold[0] < high][::-1]
        if not on_way:
            return False
        _at, number, count = on_way[0]
        cursor = browser.textCursor()
        cursor.setPosition(since)
        browser.setTextCursor(cursor)

        def opened() -> None:
            summary = self.view.summary_of(number)
            if summary is None:
                return
            place = browser.textCursor()
            place.setPosition(summary)
            browser.setTextCursor(place)
            hits = self.view.browser.document()
            match = hits.find(needle, place)
            for _ in range(count - 1 if backward else 0):  # (backward: its last match)
                after = hits.find(needle, match)
                match = after if not after.isNull() else match
            if match.isNull():
                return
            browser.setTextCursor(match)
            browser.ensureCursorVisible()
            self._mark_matches(needle)

        return self.view.unfold_for(needle=needle, then=opened, only=number)

    def _find_as_typed(self) -> None:
        """The find field changed: the first match from where the last one
        began (typing on keeps the place), every match marked."""
        browser = self.view.browser
        cursor = browser.textCursor()
        start = QTextCursor(cursor)
        start.setPosition(cursor.selectionStart())
        # (the last match in view: from there - typing on keeps the place; scrolled away from it: from the
        # top of what is shown - a new search after scrolling went back to the old match)
        if cursor.hasSelection() and browser.viewport().rect().intersects(browser.cursorRect(start)):
            cursor = start
        else:  # (nothing found yet: from the top of what is shown, as a browser - it began at the end)
            cursor = _first_shown(browser)
            for _round in range(200):  # (a table, a picture begun above the view: its block after it)
                if browser.cursorRect(cursor).top() >= 0 or cursor.atEnd():
                    break
                cursor.movePosition(QTextCursor.MoveOperation.NextBlock)
        bar = browser.verticalScrollBar()
        where = bar.value()
        browser.setTextCursor(cursor)
        bar.setValue(where)  # (putting the cursor there scrolled it into view)
        self.find_next()

    def _mark_matches(self, needle: str) -> None:
        """Every match of *needle* marked (at most FIND_MARKS), the count of
        them (at most FIND_COUNT, or as many as FIND_TURN finds: "N+") and
        which one is selected beside the field."""
        browser = self.view.browser
        document = browser.document()
        marks, count, current = [], 0, 0
        selected = browser.textCursor()
        fmt = QTextCharFormat()
        fmt.setBackground(QColor("#f2cc60") if not MV._is_dark(self.view.palette()) else QColor("#7a5b00"))
        cursor = document.find(needle, 0)
        deadline, capped = time.monotonic() + FIND_TURN, False
        while not cursor.isNull() and count < FIND_COUNT:
            if count % 64 == 63 and time.monotonic() > deadline:
                capped = True
                break
            count += 1
            if cursor.selectionStart() == selected.selectionStart() and selected.hasSelection():
                current = count
            if len(marks) < FIND_MARKS:
                mark = QTextEdit.ExtraSelection()
                mark.cursor, mark.format = cursor, fmt
                marks.append(mark)
            if cursor.selectionEnd() == cursor.selectionStart():
                break  # (never: an empty needle is not searched)
            cursor = document.find(needle, cursor)
        browser.setExtraSelections(marks)
        # (the matches in a folded <details> count too, in their place - find goes into them)
        for at, _number, inside in self.view.folds_holding(needle):
            count += inside
            if current and at < selected.selectionStart():
                current += inside
        if not count:
            self.find_count.setText(tr("no match"))
        else:
            # ("N+": counted for at most FIND_TURN, FIND_COUNT matches - or a part of the page is not laid
            # out yet: more may come; one "+" either way, "2495++" said both)
            total = f"{count}+" if count >= FIND_COUNT or capped or self.view.more() else str(count)
            self.find_count.setText(tr("{current} of {total}").format(current=current or "–", total=total))

    def end_find(self, focus: bool = True) -> None:
        """Escape in the find field: the marks go, the text has the focus."""
        self.view.browser.setExtraSelections([])
        self.find_count.setText("")
        if focus:
            self.view.browser.setFocus()

    def edit(self) -> None:
        """The file in the editor of the window it was opened from."""
        if not self.path:
            return
        if self._editor is not None:
            self._editor(self.backend, self.path)
            return
        owner = VW.owner_window(self.source_pane or self.parentWidget())
        opener = getattr(owner, "open_in_editor", None)
        if callable(opener):
            opener(self.backend, self.path)
            return
        from ui.text_editor import TextEditorDialog

        # read off the GUI thread, as the pane opens it: a failed read says
        # why and closes the window
        dialog = TextEditorDialog(self.backend, self.path, parent=owner, background=True)
        VW.show_independent(dialog)

    # -- links and the places visited --

    def target_of(self, url: QUrl) -> tuple[str, str, str]:
        """What a click on *url* does: ``("markdown", path, fragment)``,
        ``("file", path, "")`` (a folder, a text file or an image: decided
        once it is looked at, :meth:`open_file`), ``("web", url, "")`` or
        ``("refused", why, "")``."""
        scheme = url.scheme().lower()
        if scheme in ("http", "https") and url.host():
            return "web", url.toString(QUrl.ComponentFormattingOption.FullyEncoded), ""
        if scheme == "mailto" and url.path() and "\0" not in url.path():
            # (as a web link: a question naming the address - its domain in punycode, not "%D0%B0" -
            # then the mail program)
            return "web", MV.mail_address(url).toString(QUrl.ComponentFormattingOption.FullyEncoded), ""
        refused = ("refused", tr("Not opened: {target}").format(target=MV.printable(url.toString())), "")
        if scheme or url.toString().startswith("//"):
            return refused
        relative = url.path()
        paths = self._paths()
        if not relative or relative.startswith("/") or "\0" in relative or paths.isabs(relative) \
                or paths.splitdrive(relative)[0]:
            return refused
        # (the document's own path functions: on Windows "C:\\docs\\a.md" - posixpath made its folder "/", and
        # a link "b.md" the drive's root's)
        path = paths.normpath(paths.join(paths.dirname(self.path) or paths.sep, relative))
        if MV.is_markdown(path):
            return "markdown", path, url.fragment()
        return "file", path, ""

    def follow(self, url: QUrl) -> None:
        kind, where, fragment = self.target_of(url)
        link_text = self.view.last_link_text
        if kind == "refused":
            self.view.status.setText(where)
            return
        if kind in ("markdown", "file") and not self._may_open(where, link_text):
            return
        if kind == "markdown":
            self.navigate(where, fragment)
            return
        if kind == "file":
            self.open_file(where)
            return
        from core.security_mode import current_policy

        if not current_policy().allow_external_viewer:
            self.view.status.setText(tr("The security mode opens no other program: {target}").format(
                target=MV.printable(where)))
            return
        from ui.markdown_safe import ask_open_link

        if ask_open_link(self, where, link_text, where="document"):
            from core.desktop_open import open_url

            open_url(QUrl(where))

    def _may_open(self, where: str, link_text: str = "") -> bool:
        """Whether a link may open *where* - confined as the images are:
        beside the file or below it; a place above it ("../../../../etc/passwd")
        only when asked, a secret file never (said in the status line). Every
        way into navigate() a link takes: the link, a folder's README."""
        if self._secret(where):
            self.view.status.setText(tr("Not opened (a secret file): {target}").format(
                target=MV.printable(where)))
            return False
        if not self._beside(where) and not self.ask_outside(where, link_text):
            self.view.status.setText(tr("Not opened: {target}").format(target=MV.printable(where)))
            return False
        return True

    def _beside(self, path: str) -> bool:
        """Whether *path* is in the document's folder or below it (its real
        place: a link through a symlink counts where it leads)."""
        paths = self._paths()
        folder = paths.dirname(self.path) if self.path else ""
        if not folder:
            return False
        if MV._is_local(self.backend):
            return MV._inside(paths.realpath(path), paths.realpath(folder), paths)
        return MV._inside(posixpath.normpath(path), folder)

    def _paths(self):
        """The path functions of this window's backend (MV.path_functions): ntpath for a file on Windows."""
        return MV.path_functions(MV._is_local(self.backend))

    def _name(self, path: str | None = None) -> str:
        """The file name of *path* (this window's file's): its last part, as the backend's paths are cut."""
        return self._paths().basename(self.path if path is None else path)

    def _secret(self, path: str) -> str | None:
        if not MV._is_local(self.backend):
            return None
        from core.protected_places import read_refusal

        return read_refusal(path)

    def ask_outside(self, path: str, text: str = "") -> bool:
        """Whether a link to *path* - above the document's folder - opens
        (asked; No is the default)."""
        from PyQt6.QtWidgets import QMessageBox

        body = tr("This link leads out of the document's folder:\n{target}\n\nOpen it?").format(
            target=MV.printable(path))
        if text and text.strip() != path:
            body += "\n\n" + tr("Link text: {text}").format(text=MV.printable(text.strip())[:200])
        answer = QMessageBox.question(self, tr("Open Link"), body,
                                      QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                      QMessageBox.StandardButton.No)
        return answer == QMessageBox.StandardButton.Yes

    def navigate(self, path: str, anchor: str = "", shown_as: str = "markdown") -> None:
        """Show *path* in this window (at *anchor*), where it was remembered
        for Back; the same file: only the jump to *anchor*."""
        if path == self.path and shown_as == self.shown_as:
            if anchor and not self.view.go_to_anchor(anchor):
                self.view.status.setText(tr("No heading {anchor} here.").format(
                    anchor=MV.printable("#" + anchor)))
            return
        self.remember()
        self._show(path, shown_as, anchor=anchor, scroll=0)

    def _show(self, path: str, shown_as: str, anchor: str = "", scroll: int | None = None) -> None:
        self.path, self.shown_as = path, shown_as
        self.view.source = MV.ImageSource(self.backend, path)
        self.edit_button.setEnabled(bool(path))
        self.reload_button.setEnabled(bool(path))
        self._update_title()
        self._watch()
        self.reload(anchor=anchor, scroll=scroll)

    def remember(self) -> None:
        """This place (file and scroll position) goes on the Back list."""
        place = (self.path, self.view.browser.verticalScrollBar().value(), self.shown_as)
        if not self.back_list or self.back_list[-1] != place:
            self.back_list.append(place)
            del self.back_list[:-HISTORY]
        self.forward_list.clear()
        self._update_history_buttons()

    def back(self) -> bool:
        """Back to the place before the last jump or link (Alt+Left)."""
        return self._go(self.back_list, self.forward_list)

    def forward(self) -> bool:
        """Forward again after Back (Alt+Right)."""
        return self._go(self.forward_list, self.back_list)

    def _go(self, source: list, other: list) -> bool:
        if not source:
            return False
        other.append((self.path, self.view.browser.verticalScrollBar().value(), self.shown_as))
        path, scroll, shown_as = source.pop()
        if path == self.path and shown_as == self.shown_as:
            self.view.browser.verticalScrollBar().setValue(scroll)
        else:
            self._show(path, shown_as, scroll=scroll)
        self._update_history_buttons()
        return True

    def _update_history_buttons(self) -> None:
        self.back_button.setEnabled(bool(self.back_list))
        self.forward_button.setEnabled(bool(self.forward_list))

    def open_file(self, path: str) -> None:
        """A link to a file that is not Markdown: looked at on a worker
        thread - a folder opens its README, a text file is shown as its
        text, an image at its own size; anything else is named, not opened."""
        backend, local, paths = self.backend, MV._is_local(self.backend), self._paths()
        link_text = getattr(self.view, "last_link_text", "")
        self.view.status.setText(tr("Reading…"))

        def look():
            if backend.is_dir(path):
                for name in FOLDER_PAGES:
                    page = paths.join(path, name)
                    if backend.exists(page):
                        return "markdown", page, None
                return "refused", tr("Not opened (a folder without a README): {target}"), None
            if local:
                import os
                import stat

                from core.protected_places import read_refusal

                if not stat.S_ISREG(os.stat(path).st_mode):
                    return "refused", tr("Not opened (not a regular file): {target}"), None
                if read_refusal(path):  # (a file the document names: as its images)
                    return "refused", tr("Not opened (a secret file): {target}"), None
            if path.lower().endswith(IMAGE_SUFFIXES):
                with backend.open_read(path) as fh:
                    data = fh.read(MV.IMAGE_LIMIT + 1)
                if len(data) > MV.IMAGE_LIMIT:
                    return "refused", tr("Not opened (too big): {target}"), None
                image, why = MV.decode(data)
                if image is None:
                    return "refused", tr("Not opened ({why}): {target}").replace("{why}", str(why)), None
                return "image", path, image
            with backend.open_read(path) as fh:
                head = fh.read(8192)
            if b"\0" in head and not head.startswith((b"\xff\xfe", b"\xfe\xff")):
                return "refused", tr("Not opened (not a text file): {target}"), None
            return "text", path, None

        def done(result, error):
            if sip.isdeleted(self):
                return
            # (said once the page is made: set while it was, its end took it away)
            if error is not None:
                self.view.say(tr("Cannot read {path}: {error}").format(
                    path=MV.printable(path), error=MV.printable(error)))
                return
            kind, where, image = result
            if kind == "refused":
                self.view.say(where.replace("{target}", MV.printable(path)))
            elif kind == "image":
                self.view.status.setText("")
                zoom = MV.ImageZoom(image, MV.printable(self._name(where)), self)
                zoom.show()
            elif where == path or self._may_open(where, link_text):  # (a folder's README: checked as a link -
                self.navigate(where, shown_as=kind)  # one leading to a secret file opened it unasked)

        MV.in_background(look, done, owner=self)

    # -- export --

    def _export_name(self, suffix: str) -> str:
        import os

        base = self._paths().splitext(self._name() or "page")[0] + suffix
        if self.path and MV._is_local(self.backend):
            return os.path.join(os.path.dirname(self.path), base)
        return os.path.join(os.path.expanduser("~"), base)

    def ask_export_html(self) -> str:
        # (the file asked for at once: the page laid out whole first took 24 s to minutes - the export works from
        # the text, the images it shows read on a worker: _prepared)
        path, _chosen = QFileDialog.getSaveFileName(self, tr("Export HTML"), self._export_name(".html"),
                                                    tr("HTML (*.html *.htm)"))
        return self.export_html(path) if path else ""

    def ask_export_pdf(self) -> str:
        path, _chosen = QFileDialog.getSaveFileName(self, tr("Export PDF"), self._export_name(".pdf"),
                                                    tr("PDF (*.pdf)"))
        return self.export_pdf(path) if path else ""

    def _prepared(self, label: str):
        """(the kind, the parts) of the page to print or export (MV.print_parts) - made on a worker thread with
        the images they show that are not read yet (MV.image_names, the view's source), a progress window
        with Cancel meanwhile; those images then the view's, as if the page had shown them. None when
        cancelled. The page itself is not laid out for it."""
        text = self.view.markdown.replace("\r\n", "\n").replace("\r", "\n")
        full, source, read = self.view.full, self.view.source, set(self.view.originals)

        def work():
            kind, parts = MV.print_parts(text, full)
            names = []
            if source is not None:
                names = [name for name in MV.image_names(kind, parts)
                         if name not in read and source.kind(name)[0] in ("local", "data")][:MV.IMAGES]
            return kind, parts, names, source.read(names) if names else {}

        made = self._in_background(work, label)
        if made is None:
            return None
        kind, parts, names, found = made
        if names:
            self.view.images_read(names, found, None)
        return kind, parts

    def export_html(self, target: str) -> str:
        """The page as HTML for a web browser, written to the local file
        *target* (ui.markdown_html.export_html: the images read for the page
        in it, nothing it may load from elsewhere). Returns *target*, or ""
        when it could not be written (said in the status line)."""
        from core import markdown_doc as MD
        from ui import markdown_html as H

        title = self._name() if self.path else tr("Markdown Viewer")
        if self.view.full:
            text = MD.clean(self.view.markdown.removeprefix("\ufeff"))
            source, originals = self.view.source, dict(self.view.originals)

            def work():
                doc = MD.parse(text)
                # (the images it shows that the page has not read yet - not laid out whole first: read here)
                if source is not None:
                    names = [name for name in _image_sources(doc) if name not in originals
                             and source.kind(name)[0] in ("local", "data")][:MV.IMAGES]
                    originals.update((name, image) for name, image in source.read(names).items()
                                     if not isinstance(image, str))
                return H.export_html(doc, title=title, dark=False, images=_embedded(originals))

            # (made on a worker thread, the window going on: big.md held it 3.2 s)
            page = self._in_background(work, tr("Exporting HTML…"))
            if page is None:
                return ""
        else:  # (Qt's own parser: its HTML, made as safe as the other's - not by its policy alone)
            page = self._md4c_html(tr("Exporting HTML…"))
            if page is None:
                return ""
        return self._write(target, page.encode("utf-8"))

    def _md4c_html(self, label: str) -> str | None:
        """Qt's own parser's page as HTML (light colours): its parts made on a worker (_prepared), each one
        laid out and written as HTML a turn (the page's own document whole, then toHtml and safe_page on the
        GUI thread: 0.4 to 4.4 s in one turn), made safe on a worker. None when cancelled."""
        from PyQt6.QtCore import QCoreApplication
        from PyQt6.QtWidgets import QProgressDialog

        from ui import markdown_html as H

        made = self._prepared(label)
        if made is None:
            return None
        kind, parts = made
        progress = QProgressDialog(label, tr("Cancel"), 0, len(parts), self)
        progress.setWindowModality(Qt.WindowModality.WindowModal)
        progress.setMinimumDuration(400)
        head, bodies = "", []
        try:
            for number, part_text in enumerate(parts):
                if sip.isdeleted(self) or progress.wasCanceled():
                    return None
                part = self.view._part_document(None, part_text, counted=False, kind=kind, dark=False, printed=True)
                try:
                    written = part.toHtml()
                finally:
                    part.deleteLater()
                opened = _BODY_OPEN.search(written)
                closed = written.rfind("</body>")
                if opened is None or closed < 0:
                    continue
                head = head or written[:opened.end()]
                bodies.append(written[opened.end():closed])
                progress.setValue(number + 1)
                QCoreApplication.processEvents()  # (a turn between two parts: the window goes on)
            if sip.isdeleted(self) or progress.wasCanceled():
                return None
        finally:
            if not sip.isdeleted(progress):
                progress.close()
                progress.deleteLater()
        whole = (head or "<html><head></head><body>") + "".join(bodies) + "</body></html>"
        images = dict(self.view.originals)

        def safe():
            page = H.safe_page(whole, _embedded(images))
            return page.replace("<head>", f'<head><meta http-equiv="Content-Security-Policy" '
                                          f'content="{H.EXPORT_POLICY}">', 1)

        return self._in_background(safe, label)

    def export_pdf(self, target: str) -> str:
        """The page as PDF (light colours) in the local file *target* - made
        a part at a time (_print_to), the window going on; Cancel stops it."""
        import os

        from PyQt6.QtGui import QPageSize, QPdfWriter

        try:
            writer = QPdfWriter(target)
            writer.setPageSize(QPageSize(QPageSize.PageSizeId.A4))
            writer.setTitle(self._name() or tr("Markdown Viewer"))
            done = self._print_to(writer, tr("Exporting PDF…"))
            del writer  # (the file is complete once the writer is gone)
        except Exception as exc:  # noqa: BLE001 - said, not raised
            if sip.isdeleted(self):
                return ""
            self.view.status.setText(tr("Export failed: {error}").format(error=MV.printable(exc)))
            return ""
        if not done:
            try:
                os.remove(target)  # (a PDF cut short: none)
            except OSError:
                pass
            if not sip.isdeleted(self):  # (the window closed meanwhile: cancelled, nothing to say it in)
                self.view.status.setText(tr("Export cancelled."))
            return ""
        if not os.path.isfile(target):
            self.view.status.setText(tr("Export failed: {error}").format(error=MV.printable(target)))
            return ""
        self.view.status.setText(tr("Saved: {path}").format(path=MV.printable(target)))
        return target

    def print_page(self) -> bool:
        """Print the page (light colours) - when Qt's printing is there."""
        support = _print_support()
        if support is None:
            return False
        printer = support.QPrinter(support.QPrinter.PrinterMode.HighResolution)
        # (asked at once - the page laid out whole first took minutes, and a dialog made before that was left
        # behind, a new one made the next time: the parts and their images are made after it, _print_to)
        dialog = support.QPrintDialog(printer, self)
        try:
            if dialog.exec() != QDialog.DialogCode.Accepted:
                return False
        finally:
            dialog.deleteLater()
        if not self._print_to(printer, tr("Printing…")):
            printer.abort()
            if not sip.isdeleted(self):  # (the window closed meanwhile)
                self.view.status.setText(tr("Printing cancelled."))
            return False
        return True

    def _in_background(self, work, label: str):
        """*work()* on a worker thread, the window going on meanwhile (a
        progress window with Cancel once it takes a while): its result, or
        None when cancelled or it failed (said)."""
        from PyQt6.QtCore import QEventLoop
        from PyQt6.QtWidgets import QProgressDialog

        state = {"done": False, "result": None, "error": None}
        loop = QEventLoop()
        progress = QProgressDialog(label, tr("Cancel"), 0, 0, self)
        progress.setWindowModality(Qt.WindowModality.WindowModal)
        progress.setMinimumDuration(400)
        progress.canceled.connect(loop.quit)

        def done(result, error):
            state.update(done=True, result=result, error=error)
            loop.quit()

        # (the window closed meanwhile - Escape, its close button, axross quitting -: its delivery of *done*
        # is dropped with it, MV.in_background; the loop waited on until the program ended, then raised)
        closed = self.destroyed.connect(loop.quit)
        MV.in_background(work, done, owner=self)
        if not state["done"]:
            loop.exec()
        if sip.isdeleted(self):
            return None  # (nothing of the window left to touch: the export is cancelled)
        self.destroyed.disconnect(closed)
        progress.close()
        progress.deleteLater()
        if not state["done"]:
            self.view.status.setText(tr("Export cancelled."))
            return None
        if state["error"] is not None:
            self.view.status.setText(tr("Export failed: {error}").format(error=MV.printable(state["error"])))
            return None
        return state["result"]

    def _print_to(self, device, label: str) -> bool:
        """The page drawn on *device* (a QPdfWriter, a QPrinter) in light
        colours: its parts made on a worker thread (MV.print_parts), then
        laid out and drawn one a turn (_PagePrinter) - progress said,
        Cancel stops it. True when every page was drawn."""
        from PyQt6.QtCore import QCoreApplication
        from PyQt6.QtWidgets import QProgressDialog

        made = self._prepared(label)
        if made is None:
            return False
        kind, parts = made
        progress = QProgressDialog(label, tr("Cancel"), 0, len(parts), self)
        progress.setWindowModality(Qt.WindowModality.WindowModal)
        progress.setMinimumDuration(400)
        pages = _PagePrinter(device, self.view.browser.document().defaultFont())
        try:
            for number, part_text in enumerate(parts):
                if sip.isdeleted(self) or progress.wasCanceled():  # (the window first: the progress is its child)
                    return False
                part = self.view._part_document(None, part_text, counted=False, kind=kind, dark=False, printed=True)
                try:
                    for _page in pages.add(part):  # (a turn between two pages too: a part of 16 pages, 0.2 s)
                        QCoreApplication.processEvents()
                        if sip.isdeleted(self) or sip.isdeleted(progress) or progress.wasCanceled():
                            return False
                finally:
                    if not sip.isdeleted(part):
                        part.deleteLater()
                progress.setValue(number + 1)
                QCoreApplication.processEvents()  # (a turn between two parts: the window goes on)
            return not sip.isdeleted(self) and not progress.wasCanceled()
        finally:
            pages.end()
            if not sip.isdeleted(progress):
                progress.close()
                progress.deleteLater()

    def _write(self, target: str, data: bytes) -> str:
        try:
            with open(target, "wb") as fh:
                fh.write(data)
        except OSError as exc:
            self.view.status.setText(tr("Export failed: {error}").format(error=MV.printable(exc)))
            return ""
        self.view.status.setText(tr("Saved: {path}").format(path=MV.printable(target)))
        return target


class _PagePrinter:
    """Documents drawn one after another on a paint device's pages, as
    QTextDocument.print draws one (2 cm margins, the page's number at its
    foot) - each laid out on its own: one document of the whole page went
    past Qt's layout's reach (8,388,607 of its units: big.md's PDF lost its
    last hundreds of pages). The next document goes on where the one before
    ended on its last page (an empty line that high above it)."""

    def __init__(self, device, font):
        from PyQt6.QtCore import QPointF, QRectF
        from PyQt6.QtGui import QFontMetrics, QPainter

        self.device, self.font = device, font
        self.painter = QPainter(device)
        # (as Qt's own: the margin in units of 96 dots an inch - the layout scales it to the device's -,
        # the page in the device's own)
        self.margin = int(2 / 2.54 * 96)
        self.scale = device.logicalDpiY() / 96.0
        self.body = QRectF(0, 0, device.width(), device.height())
        ascent = QFontMetrics(font, device).ascent()
        self.number_at = QPointF(self.body.width() - self.margin * device.logicalDpiX() / 96.0,
                                 self.body.height() - self.margin * self.scale + ascent + 5 * self.scale)
        self.number, self.used = 0, 0.0  # (pages begun; how far down the last one is written)

    def add(self, document):
        """*document* drawn on the pages after the last one's (see the class) - a page at a time: a generator,
        each step one page drawn (the caller's turn may end between two)."""
        from PyQt6.QtGui import QTextBlockFormat, QTextCharFormat

        if not self.painter.isActive():
            raise OSError("cannot draw on the printer")
        layout = document.documentLayout()
        layout.setPaintDevice(self.device)
        frame = document.rootFrame().frameFormat()
        frame.setMargin(self.margin)
        document.rootFrame().setFrameFormat(frame)
        height = self.body.height()
        margin = self.margin * self.scale  # (in the device's units)
        going_on = self.number and self.used and self.used < height - margin - height / 8
        if going_on:  # (on where the last one ended: an empty line that high first)
            cursor = QTextCursor(document)
            first = document.begin()
            cursor.insertBlock(first.blockFormat(), first.charFormat())  # (a block of its own: one before a
            # table - a code block's band, a quote's box - took no height)
            spacer = QTextBlockFormat()
            spacer.setLineHeight(max(1.0, (self.used - margin) / self.scale), 2)  # (2: FixedHeight - in 96ths)
            small = QTextCharFormat()
            small.setFontPointSize(1)
            cursor.setPosition(0)
            cursor.setBlockFormat(spacer)
            cursor.setBlockCharFormat(small)
        document.setPageSize(self.body.size())
        pages = document.pageCount()
        for index in range(pages):
            if index or not going_on:
                if self.number:
                    self.device.newPage()
                self.number += 1
            self._draw(document, index, numbered=bool(index or not going_on))
            if index + 1 < pages:
                yield index
        block = document.lastBlock()
        last = layout.blockBoundingRect(block)
        # (the room below the last line too: the next document's first line kept its distance; the
        # empty block after a table: where it begins - below the table's own room)
        bottom = last.top() if not block.text() else last.bottom() + block.blockFormat().bottomMargin() * self.scale
        self.used = bottom - (pages - 1) * height

    def _draw(self, document, index: int, numbered: bool) -> None:
        from PyQt6.QtCore import QRectF
        from PyQt6.QtGui import QAbstractTextDocumentLayout, QFont, QPalette

        painter, height = self.painter, self.body.height()
        painter.save()
        painter.translate(self.body.left(), self.body.top() - index * height)
        view = QRectF(0, index * height, self.body.width(), height)
        # (drawn between the page's margins only: a box going on to the next page - an alert, a code
        # block - had its ground drawn on through the margins, under the page's number, and at the
        # next page's top an empty piece of it)
        margin = self.margin * self.scale
        inside = QRectF(0, index * height + margin, self.body.width(), height - 2 * margin)
        context = QAbstractTextDocumentLayout.PaintContext()
        context.clip = inside
        context.palette.setColor(QPalette.ColorRole.Text, QColor("black"))
        painter.setClipRect(inside)
        document.documentLayout().draw(painter, context)
        if numbered:
            painter.setClipping(False)
            painter.setFont(QFont(self.font))
            shown = str(self.number)
            painter.drawText(round(self.number_at.x() - painter.fontMetrics().horizontalAdvance(shown)),
                             round(self.number_at.y() + view.top()), shown)
        painter.restore()

    def end(self) -> None:
        if self.painter.isActive():
            self.painter.end()


def _print_support():
    """PyQt6.QtPrintSupport, or None where Qt's printing is not there."""
    try:
        from PyQt6 import QtPrintSupport
    except ImportError:
        return None
    return QtPrintSupport


_BODY_OPEN = re.compile(r"<body\b[^<>]*>", re.IGNORECASE)


def _image_sources(doc) -> list[str]:
    """The names of the images markdown-it's *doc* shows (Markdown's and raw HTML's <img>), each once."""
    from core import markdown_doc as MD

    names: dict[str, None] = {}
    for token in doc.tokens:
        if token.type == "safe_html_block":
            names.update((attrs.get("src", ""), None) for kind, *rest in MD.html_events(token)
                         if kind == "start" and rest[0] == "img" and len(rest) > 1 and (attrs := rest[1]))
        for child in token.children or ():
            if child.type == "image" and child.attrGet("src"):
                names[str(child.attrGet("src"))] = None
            elif child.type == "safe_html_inline":
                names.update((attrs.get("src", ""), None) for kind, *rest in MD.html_events(child)
                             if kind == "start" and rest[0] == "img" and len(rest) > 1 and (attrs := rest[1]))
    names.pop("", None)
    return list(names)


def _embedded(images: dict) -> dict[str, str]:
    """The images the page read, as ``data:`` addresses ({name: address})
    for a page of its own."""
    from PyQt6.QtCore import QBuffer, QByteArray, QIODevice

    found = {}
    for name, image in images.items():
        data = QByteArray()
        buffer = QBuffer(data)
        buffer.open(QIODevice.OpenModeFlag.WriteOnly)
        if image.save(buffer, "PNG"):
            found[name] = "data:image/png;base64," + bytes(data.toBase64()).decode("ascii")
    return found


def as_code(text: str, path: str) -> str:
    """A text file as Markdown that shows it: a fenced block (longer than
    any run of backticks in it) in the language its name says."""
    import re

    longest = max((len(run) for run in re.findall(r"`{3,}", text)), default=2)
    fence = "`" * (longest + 1)
    language = _language(posixpath.basename(path))
    return f"{fence}{language}\n{text}\n{fence}\n"


def _language(name: str) -> str:
    """The Pygments name of the language a file *name* says (or "")."""
    try:
        from pygments.lexers import get_lexer_for_filename
        from pygments.util import ClassNotFound
    except ImportError:
        return ""
    try:
        lexer = get_lexer_for_filename(name)
    except ClassNotFound:
        return ""
    return next((alias for alias in getattr(lexer, "aliases", None) or ()
                 if alias and not any(c.isspace() or c == "`" for c in alias)), "")


def open_markdown_viewer(backend, path: str, parent=None, *, source_pane=None, opener=None,
                         editor=None, view_menu=None) -> MarkdownViewerDialog:
    """Show the Markdown file *path* of *backend* in a viewer window of its
    own (non-modal)."""
    dialog = MarkdownViewerDialog(backend, path, VW.owner_window(parent), source_pane=source_pane,
                                  opener=opener, editor=editor, view_menu=view_menu)
    VW.show_independent(dialog)
    return dialog


__all__ = ["MarkdownViewerDialog", "open_markdown_viewer"]
