"""The editor window: every file opened for editing, as tabs (item 48).

One window per main window. A tab is a file on any backend (core.
text_document keeps the bytes faithful) or an untitled one (New); the
window has New, Open… (the local file system - remote files open from
their pane), Save, Save As… (a local tab picks a local file, a remote tab a
path on its own backend), Save All, find and replace (regex, case, whole
word), go to line, wrap, zoom, the language, line endings and encoding of a
tab, and read-only tabs. Closing a modified tab or the window asks Save /
Discard / Cancel; Save on an untitled tab asks where first.
"""

from __future__ import annotations

import logging
import os
import posixpath
import re

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QAction, QKeySequence, QTextCursor
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from core.i18n import tr
from core.text_document import TextDocument
from ui.code_editor import TEXT_ONLY, CodeEditor, language_for
from ui.scan_job import ScanJob

log = logging.getLogger(__name__)

#: The languages offered in the status bar (any Pygments one works).
LANGUAGES = (TEXT_ONLY, "Python", "Bash", "JavaScript", "TypeScript", "JSON", "YAML", "TOML", "INI",
             "XML", "HTML", "CSS", "Markdown", "C", "C++", "Go", "Rust", "Java", "SQL", "PHP",
             "Perl", "Ruby", "Lua", "PowerShell", "Dockerfile", "Makefile", "Nginx configuration file",
             "Diff")
ENCODINGS = (("UTF-8", "utf-8", False), ("UTF-8 BOM", "utf-8", True), ("Latin-1", "latin-1", False),
             ("UTF-16", "utf-16", True))

#: What QTextDocument.toPlainText() - the text find searches - shows for the
#: characters QTextCursor.selectedText() keeps: block and line breaks as "\n",
#: a no-break space as a space. One character for one, so offsets agree.
_AS_PLAIN_TEXT = str.maketrans({"\u2029": "\n", "\u2028": "\n", "\ufdd0": "\n",
                                "\ufdd1": "\n", "\u00a0": " "})


class _Offsets:
    """Python string indexes of a text and QTextCursor positions in it.

    Qt counts UTF-16 code units, so every character outside the BMP (an
    emoji) is two positions there and one index here; used as each other,
    find selected the wrong text after the first emoji."""

    def __init__(self, text: str) -> None:
        self._text = text
        self._units = text.encode("utf-16-le")
        self._same = len(self._units) == 2 * len(text)

    def to_qt(self, index: int) -> int:
        if self._same:
            return index
        return len(self._text[:index].encode("utf-16-le")) // 2

    def to_py(self, position: int) -> int:
        if self._same:
            return position
        # A position inside a surrogate pair counts as the character's start.
        return len(self._units[: 2 * position].decode("utf-16-le", errors="ignore"))


class EditorTab(QWidget):
    """One file in the editor; *backend* None and *path* "" for an untitled
    tab (New) that has no file until its first save."""

    modified_changed = pyqtSignal(bool)

    def __init__(self, backend, path: str, text: str, document: TextDocument, read_only: bool,
                 untitled_name: str = "") -> None:
        super().__init__()
        self.backend = backend
        self.path = path
        self.document = document
        self.read_only = read_only
        self.untitled_name = untitled_name
        self.editor = CodeEditor(self)
        self.editor.setPlainText(text)
        if path:
            name = posixpath.basename(path.replace("\\", "/"))
            self.editor.set_language(language_for(name, text))
        self.editor.setReadOnly(read_only)
        self.editor.document().setModified(False)
        self.editor.document().modificationChanged.connect(self.modified_changed.emit)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.editor)

    @property
    def untitled(self) -> bool:
        return self.backend is None

    @property
    def name(self) -> str:
        if self.untitled:
            return self.untitled_name
        return posixpath.basename(self.path.replace("\\", "/")) or self.path

    def is_modified(self) -> bool:
        return self.editor.document().isModified()

    def mark_modified(self) -> None:
        self.editor.document().setModified(True)

    def blocks(self) -> list[str]:
        out = []
        block = self.editor.document().begin()
        while block.isValid():
            out.append(block.text())
            block = block.next()
        return out


class FindBar(QWidget):
    """Find and replace in the current tab."""

    def __init__(self, window: "EditorWindow") -> None:
        super().__init__(window)
        self._window = window
        layout = QHBoxLayout(self)
        layout.setContentsMargins(4, 2, 4, 2)
        self.find_edit = QLineEdit()
        self.find_edit.setPlaceholderText(tr("Find"))
        self.find_edit.returnPressed.connect(self.find_next)
        self.replace_edit = QLineEdit()
        self.replace_edit.setPlaceholderText(tr("Replace with"))
        self.regex = QCheckBox(tr("Regex"))
        self.case = QCheckBox(tr("Case"))
        self.whole_word = QCheckBox(tr("Whole word"))
        previous = QPushButton(tr("Previous"))
        previous.clicked.connect(lambda: self.find_next(backwards=True))
        following = QPushButton(tr("Next"))
        following.clicked.connect(lambda: self.find_next())
        replace = QPushButton(tr("Replace"))
        replace.clicked.connect(self.replace_one)
        replace_all = QPushButton(tr("Replace All"))
        replace_all.clicked.connect(self.replace_all)
        close = QPushButton("×")
        close.setFlat(True)
        close.clicked.connect(self.hide)
        self.message = QLabel("")
        self.replace_widgets = (self.replace_edit, replace, replace_all)
        for widget in (self.find_edit, previous, following, self.replace_edit, replace, replace_all,
                       self.regex, self.case, self.whole_word, self.message, close):
            layout.addWidget(widget)

    def _pattern(self) -> re.Pattern | None:
        needle = self.find_edit.text()
        if not needle:
            return None
        source = needle if self.regex.isChecked() else re.escape(needle)
        if self.whole_word.isChecked():
            source = rf"\b(?:{source})\b"
        try:
            return re.compile(source, 0 if self.case.isChecked() else re.IGNORECASE)
        except re.error as exc:
            self.message.setText(tr("Bad regex: {error}").format(error=exc))
            return None

    def find_next(self, backwards: bool = False) -> bool:
        tab = self._window.current_tab()
        pattern = self._pattern()
        if tab is None or pattern is None:
            return False
        self.message.setText("")
        editor = tab.editor
        text = editor.toPlainText()
        offsets = _Offsets(text)
        cursor = editor.textCursor()
        if backwards:
            start = offsets.to_py(cursor.selectionStart())
            matches = [m for m in pattern.finditer(text) if m.end() <= start]
            match = matches[-1] if matches else None
            if match is None:  # wrap
                matches = list(pattern.finditer(text))
                match = matches[-1] if matches else None
        else:
            end = offsets.to_py(cursor.selectionEnd())
            match = pattern.search(text, end) or pattern.search(text, 0)
        if match is None or match.end() == match.start():
            self.message.setText(tr("Not found"))
            return False
        cursor.setPosition(offsets.to_qt(match.start()))
        cursor.setPosition(offsets.to_qt(match.end()), QTextCursor.MoveMode.KeepAnchor)
        editor.setTextCursor(cursor)
        return True

    def replace_one(self) -> bool:
        tab = self._window.current_tab()
        pattern = self._pattern()
        if tab is None or pattern is None or tab.read_only:
            return False
        cursor = tab.editor.textCursor()
        # As find saw it: a match across a line break is "\n" there, U+2029 here.
        selected = cursor.selectedText().translate(_AS_PLAIN_TEXT)
        if selected and pattern.fullmatch(selected):
            cursor.insertText(pattern.sub(self._replacement(), selected, count=1))
        return self.find_next()

    def _replacement(self) -> str:
        text = self.replace_edit.text()
        # Without Regex the replacement is literal: escape what re.sub reads.
        return text if self.regex.isChecked() else text.replace("\\", "\\\\")

    def replace_all(self) -> int:
        """Replace every match as one undo step; returns the count."""
        tab = self._window.current_tab()
        pattern = self._pattern()
        if tab is None or pattern is None or tab.read_only:
            return 0
        editor = tab.editor
        # From the blocks, not toPlainText(): that one turns no-break spaces
        # into spaces and U+2028 into "\n", and the whole text is written
        # back below, so every untouched line would change too.
        text = "\n".join(tab.blocks())
        new, count = pattern.subn(self._replacement(), text)
        if count:
            cursor = editor.textCursor()
            cursor.beginEditBlock()
            cursor.select(QTextCursor.SelectionType.Document)
            cursor.insertText(new)
            cursor.endEditBlock()
        self.message.setText(tr("{n} replaced").format(n=count))
        return count


class EditorWindow(QMainWindow):
    #: (backend, path) after a save: the panes showing its folder refresh.
    saved = pyqtSignal(object, str)
    #: A tab was added (the main window shows the editor then).
    opened = pyqtSignal(object)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        # Files being read in the background: (backend, path, job).
        self._loads: list[tuple[object, str, ScanJob]] = []
        self.setWindowTitle(tr("Editor") + " — axross")
        self.resize(1000, 720)
        self.tabs = QTabWidget()
        self.tabs.setTabsClosable(True)
        self.tabs.setMovable(True)
        self.tabs.setDocumentMode(True)
        self.tabs.tabCloseRequested.connect(self.close_tab)
        self.tabs.currentChanged.connect(lambda _i: self._update_status())
        self.find_bar = FindBar(self)
        self.find_bar.hide()
        central = QWidget()
        layout = QVBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.tabs, 1)
        layout.addWidget(self.find_bar)
        self.setCentralWidget(central)
        self.position_label = QLabel("")
        self.encoding_label = QLabel("")
        self.eol_label = QLabel("")
        self.language_combo = QComboBox()
        self.language_combo.addItems(LANGUAGES)
        self.language_combo.setEditable(True)
        self.language_combo.activated.connect(lambda _i: self._language_chosen())
        for widget in (self.position_label, self.encoding_label, self.eol_label, self.language_combo):
            self.statusBar().addPermanentWidget(widget)
        self._untitled_count = 0
        self._build_menus()
        self._add_corner()

    def _add_corner(self) -> None:
        """Maximize and [x] at the right end of the menu bar, as every
        editor dialog has them (ui/close_corner.py): on a window manager
        without title-bar buttons this window had no visible close control.
        The [x] is close(), so unsaved tabs ask as always."""
        from ui.close_corner import make_close_corner, make_maximize_corner

        corner = QWidget(self.menuBar())
        row = QHBoxLayout(corner)
        row.setContentsMargins(0, 0, 4, 0)
        row.setSpacing(0)
        row.addWidget(make_maximize_corner(self))
        row.addWidget(make_close_corner(self, self.close))
        self.menuBar().setCornerWidget(corner, Qt.Corner.TopRightCorner)

    # -- menus ---------------------------------------------------------------------------

    def _action(self, menu, text, slot, shortcut=None, checkable=False) -> QAction:
        action = menu.addAction(tr(text))
        if shortcut:
            action.setShortcut(QKeySequence(shortcut))
        action.setCheckable(checkable)
        # A checkable action also changes by setChecked, which emits toggled only.
        (action.toggled if checkable else action.triggered).connect(slot)
        return action

    def _build_menus(self) -> None:
        bar = self.menuBar()
        file_menu = bar.addMenu(tr("&File"))
        self._action(file_menu, "&New", lambda: self.new_tab(), "Ctrl+N")
        self._action(file_menu, "&Open…", lambda: self.open_dialog(), "Ctrl+O")
        file_menu.addSeparator()
        self._action(file_menu, "&Save", lambda: self.save_current(), "Ctrl+S")
        self._action(file_menu, "Save &As…", lambda: self.save_as(), "Ctrl+Shift+S")
        # Ctrl+Shift+S is Save As everywhere; Save All takes Kate's key.
        self._action(file_menu, "Save A&ll", lambda: self.save_all(), "Ctrl+L")
        self._action(file_menu, "&Reload", lambda: self.reload_current())
        file_menu.addSeparator()
        self._action(file_menu, "&Close Tab", lambda: self.close_tab(self.tabs.currentIndex()), "Ctrl+W")
        edit = bar.addMenu(tr("&Edit"))
        for text, name, shortcut in (("&Undo", "undo", "Ctrl+Z"), ("&Redo", "redo", "Ctrl+Y"),
                                     ("Cu&t", "cut", "Ctrl+X"), ("&Copy", "copy", "Ctrl+C"),
                                     ("&Paste", "paste", "Ctrl+V"), ("Select &All", "selectAll", "Ctrl+A")):
            action = edit.addAction(tr(text))
            action.setShortcut(QKeySequence(shortcut))
            action.setShortcutContext(Qt.ShortcutContext.WidgetWithChildrenShortcut)
            action.triggered.connect(lambda _c=False, n=name: self._editor_call(n))
        edit.addSeparator()
        self._action(edit, "&Find…", lambda: self.show_find(False), "Ctrl+F")
        self._action(edit, "R&eplace…", lambda: self.show_find(True), "Ctrl+H")
        self._action(edit, "Find &Next", lambda: self.find_bar.find_next(), "F3")
        self._action(edit, "&Go to Line…", lambda: self._ask_line(), "Ctrl+G")
        view = bar.addMenu(tr("&View"))
        self.wrap_action = self._action(view, "&Wrap Lines", lambda on: self._set_wrap(on), checkable=True)
        self._action(view, "Zoom &In", lambda: self._zoom(1), "Ctrl++")
        self._action(view, "Zoom &Out", lambda: self._zoom(-1), "Ctrl+-")
        fmt = bar.addMenu(tr("F&ormat"))
        endings = fmt.addMenu(tr("Line &Endings"))
        for label, newline in (("LF (Unix)", "\n"), ("CRLF (Windows)", "\r\n"), ("CR (old Mac)", "\r")):
            self._action(endings, label, lambda _c=False, n=newline: self.set_newline(n))
        encodings = fmt.addMenu(tr("En&coding"))
        for label, codec, bom in ENCODINGS:
            self._action(encodings, label, lambda _c=False, c=codec, b=bom: self.set_encoding(c, bom=b))

    def _editor_call(self, name: str) -> None:
        tab = self.current_tab()
        if tab is not None:
            getattr(tab.editor, name)()

    # -- tabs ----------------------------------------------------------------------------

    def current_tab(self) -> EditorTab | None:
        widget = self.tabs.currentWidget()
        return widget if isinstance(widget, EditorTab) else None

    def _tabs(self) -> list[EditorTab]:
        return [self.tabs.widget(i) for i in range(self.tabs.count())]

    @staticmethod
    def _same_backend(a, b) -> bool:
        """Whether *a* and *b* show the same files: the same object, or two
        plain LocalFS - every local pane has one of its own, and the same
        file opened from two of them became two tabs with separate edits.
        A LocalFS subclass (an MTP device) is a filesystem of its own."""
        from core.local_fs import LocalFS

        return a is b or (type(a) is LocalFS and type(b) is LocalFS)

    @staticmethod
    def _is_local(backend) -> bool:
        """A plain local file system: saved and opened through the local
        file dialog. Anything else (a LocalFS subclass such as an MTP
        device included) is a backend of its own."""
        from core.local_fs import LocalFS

        return type(backend) is LocalFS

    def _tab_of(self, backend, path: str, *, besides: EditorTab | None = None) -> EditorTab | None:
        """The open tab showing *path* on *backend* (other than *besides*)."""
        for tab in self._tabs():
            if (tab is not besides and not tab.untitled and tab.path == path
                    and self._same_backend(tab.backend, backend)):
                return tab
        return None

    def is_loading(self, backend, path: str) -> bool:
        """Whether *path* on *backend* is being read for a tab."""
        return any(self._same_backend(b, backend) and p == path for b, p, _job in self._loads)

    def open_file(self, backend, path: str, *, read_only: bool = False,
                  background: bool = False) -> EditorTab | None:
        """The tab of *path* on *backend*, opened now or already open.

        With *background* a file not open yet is read off the GUI thread -
        a slow remote file freezes no window - and None is returned; the
        tab follows with the ``opened`` signal (an unreadable file: a
        message instead)."""
        tab = self._tab_of(backend, path)
        if tab is not None:
            self.tabs.setCurrentWidget(tab)
            return tab
        if background:
            self._load_in_background(backend, path, read_only)
            return None
        document = TextDocument(backend, path)
        try:
            text = document.load()
        except OSError as exc:
            self._report_unreadable(path, exc)
            return None
        return self._add_tab(EditorTab(backend, path, text, document, read_only))

    def new_tab(self) -> EditorTab:
        """File > New: an empty untitled tab (UTF-8, LF); its first save
        asks where."""
        self._untitled_count += 1
        name = tr("Untitled-{n}").format(n=self._untitled_count)
        return self._add_tab(EditorTab(None, "", "", TextDocument.untitled(), False, name))

    def open_dialog(self) -> list[EditorTab]:
        """File > Open…: files picked on the local file system, each in its
        tab. A remote file opens from its pane (Edit / F4): the pane is that
        backend's file browser, axross has no remote file dialog."""
        from core.local_fs import LocalFS

        tabs = []
        for path in self._ask_open_paths():
            tab = self.open_file(LocalFS(), path)
            if tab is not None:
                tabs.append(tab)
        return tabs

    def _start_folder(self) -> str:
        """Where the local file dialogs start: the current local tab's
        folder, else the home folder."""
        tab = self.current_tab()
        if tab is not None and not tab.untitled and self._is_local(tab.backend):
            return os.path.dirname(tab.path)
        return os.path.expanduser("~")

    def _ask_open_paths(self) -> list[str]:
        paths, _filter = QFileDialog.getOpenFileNames(self, tr("Open"), self._start_folder())
        return list(paths)

    def _report_unreadable(self, path: str, exc: BaseException) -> None:
        QMessageBox.warning(
            self, tr("Open"), tr("Cannot open {path}:\n{error}").format(path=path, error=exc))

    def _load_in_background(self, backend, path: str, read_only: bool) -> None:
        if self.is_loading(backend, path):
            return  # the tab is on its way
        document = TextDocument(backend, path)
        job = ScanJob(self)
        entry = (backend, path, job)
        self._loads.append(entry)
        job.finished.connect(
            lambda kind, value, _cancelled, e=entry, d=document, ro=read_only:
            self._background_loaded(e, d, ro, kind, value)
        )
        self.statusBar().showMessage(tr("Opening {path}…").format(path=path))
        job.start(lambda _cancel, _progress: document.load())

    def _background_loaded(self, entry, document: TextDocument, read_only: bool,
                           kind: str, value) -> None:
        if entry not in self._loads:
            return  # dropped: the window closed meanwhile
        self._loads.remove(entry)
        backend, path, job = entry
        job.deleteLater()
        if not self._loads:  # another file may still be on its way
            self.statusBar().clearMessage()
        if kind != "done":
            log.info("Cannot open %s: %s", path, value)
            self._report_unreadable(path, value)
            return
        tab = self._tab_of(backend, path)
        if tab is not None:  # opened meanwhile without the background
            self.tabs.setCurrentWidget(tab)
            return
        self._add_tab(EditorTab(backend, path, value, document, read_only))

    def _add_tab(self, tab: EditorTab) -> EditorTab:
        tab.modified_changed.connect(lambda _m, t=tab: self._update_title(t))
        tab.editor.cursorPositionChanged.connect(self._update_status)
        tab.editor.setLineWrapMode(
            QPlainTextEdit.LineWrapMode.WidgetWidth if self.wrap_action.isChecked()
            else QPlainTextEdit.LineWrapMode.NoWrap)
        index = self.tabs.addTab(tab, "")
        self._update_title(tab)
        self.tabs.setCurrentIndex(index)
        tab.editor.setFocus()
        self.opened.emit(tab)
        return tab

    def _update_title(self, tab: EditorTab) -> None:
        index = self.tabs.indexOf(tab)
        if index < 0:
            return
        title = tab.name + (" [read-only]" if tab.read_only else "") + (" *" if tab.is_modified() else "")
        self.tabs.setTabText(index, title)
        if tab.untitled:
            tip = tr("{name} (not saved yet)").format(name=tab.name)
        else:
            tip = f"{tab.path} [{getattr(tab.backend, 'name', '')}]"
        self.tabs.setTabToolTip(index, tip)

    def _update_status(self) -> None:
        tab = self.current_tab()
        if tab is None:
            for label in (self.position_label, self.encoding_label, self.eol_label):
                label.setText("")
            return
        cursor = tab.editor.textCursor()
        self.position_label.setText(tr("Ln {line}, Col {col}").format(
            line=cursor.blockNumber() + 1, col=cursor.positionInBlock() + 1))
        self.encoding_label.setText(tab.document.encoding_name)
        self.eol_label.setText(tab.document.newline_name)
        self.language_combo.setCurrentText(tab.editor.language)

    def _language_chosen(self) -> None:
        tab = self.current_tab()
        if tab is not None:
            tab.editor.set_language(self.language_combo.currentText())
            self.language_combo.setCurrentText(tab.editor.language)

    # -- saving --------------------------------------------------------------------------

    def save_tab(self, tab: EditorTab) -> bool:
        if tab.read_only:
            self.statusBar().showMessage(tr("{name} is open read-only").format(name=tab.name), 4000)
            return False
        if tab.untitled:
            return self.save_as(tab)
        try:
            result = tab.document.save(tab.blocks())
            if result == "conflict":
                answer = QMessageBox.question(
                    self, tr("File Changed"),
                    tr("{path} was changed since it was opened. Overwrite it with your version?").format(
                        path=tab.path),
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.No,
                )
                if answer != QMessageBox.StandardButton.Yes:
                    return False
                tab.document.save(tab.blocks(), force=True)
        except UnicodeEncodeError as exc:
            QMessageBox.critical(self, tr("Save"), tr(
                "The text holds characters {encoding} cannot store; nothing was written. Choose "
                "another encoding (Format > Encoding).\n{error}").format(
                encoding=tab.document.encoding_name, error=exc))
            return False
        except OSError as exc:
            QMessageBox.critical(self, tr("Save"), tr("Cannot save {path}:\n{error}").format(
                path=tab.path, error=exc))
            return False
        tab.editor.document().setModified(False)
        self._update_title(tab)
        self._update_status()
        self.statusBar().showMessage(tr("Saved {name}").format(name=tab.name), 3000)
        self.saved.emit(tab.backend, tab.path)
        return True

    def save_as(self, tab: EditorTab | None = None) -> bool:
        """File > Save As…: *tab* (the current one) written to a file the
        user picks - on the local file system for a local or untitled tab,
        on the tab's own backend otherwise. An existing file asks before it
        is replaced; the tab then is the new file."""
        tab = tab if tab is not None else self.current_tab()
        if tab is None:
            return False
        if tab.read_only:
            self.statusBar().showMessage(tr("{name} is open read-only").format(name=tab.name), 4000)
            return False
        target = self._ask_save_path(tab)
        if target is None:
            return False
        backend, path = target
        if not tab.untitled and path == tab.path and self._same_backend(backend, tab.backend):
            return self.save_tab(tab)  # its own file: the conflict check of a plain save
        if self._tab_of(backend, path, besides=tab) is not None:
            QMessageBox.warning(self, tr("Save As"), tr(
                "{path} is open in another tab. Close that tab first, or save under another "
                "name.").format(path=path))
            return False
        try:
            exists = backend.exists(path)
            folder = exists and backend.is_dir(path)
        except OSError:
            exists = folder = False  # the write below says what is wrong
        if folder:
            QMessageBox.warning(self, tr("Save As"), tr(
                "{path} is a folder. Choose a file name.").format(path=path))
            return False
        if exists and QMessageBox.question(
                self, tr("Save As"), tr("{path} already exists. Replace it?").format(path=path),
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No) != QMessageBox.StandardButton.Yes:
            return False
        try:
            tab.document.save_as(backend, path, tab.blocks())
        except UnicodeEncodeError as exc:
            QMessageBox.critical(self, tr("Save"), tr(
                "The text holds characters {encoding} cannot store; nothing was written. Choose "
                "another encoding (Format > Encoding).\n{error}").format(
                encoding=tab.document.encoding_name, error=exc))
            return False
        except OSError as exc:
            QMessageBox.critical(self, tr("Save"), tr("Cannot save {path}:\n{error}").format(
                path=path, error=exc))
            return False
        tab.backend, tab.path = backend, path
        # The language follows the new name, unless the name says nothing.
        language = language_for(posixpath.basename(path.replace("\\", "/")), "")
        if language != TEXT_ONLY:
            tab.editor.set_language(language)
        tab.editor.document().setModified(False)
        self._update_title(tab)
        self._update_status()
        self.statusBar().showMessage(tr("Saved {name}").format(name=tab.name), 3000)
        self.saved.emit(tab.backend, tab.path)
        return True

    def _ask_save_path(self, tab: EditorTab):
        """``(backend, path)`` to save *tab* as, or None (cancelled). A local
        or untitled tab: the local file dialog (it does not ask about
        overwriting - save_as() does, for every backend alike). A remote
        tab: a path on its backend; a relative one is below the tab's
        folder."""
        from core.local_fs import LocalFS

        if tab.untitled or self._is_local(tab.backend):
            start = tab.path or os.path.join(self._start_folder(), tab.name)
            path, _filter = QFileDialog.getSaveFileName(
                self, tr("Save As"), start, options=QFileDialog.Option.DontConfirmOverwrite)
            if not path:
                return None
            return (tab.backend if not tab.untitled else LocalFS()), path
        label = tr("Path on {backend}:").format(backend=getattr(tab.backend, "name", ""))
        text, ok = QInputDialog.getText(self, tr("Save As"), label, text=tab.path)
        path = text.strip() if ok else ""
        if not path:
            return None
        if not re.match(r"[/\\]|[A-Za-z]:[/\\]", path):
            path = tab.backend.join(tab.backend.parent(tab.path), path)
        return tab.backend, path

    def save_current(self) -> bool:
        tab = self.current_tab()
        return self.save_tab(tab) if tab is not None else False

    def save_all(self) -> bool:
        return all([self.save_tab(t) for t in self._tabs() if t.is_modified() and not t.read_only])

    def reload_current(self) -> None:
        tab = self.current_tab()
        if tab is None or tab.untitled:
            return  # an untitled tab has no file to read again
        if tab.is_modified() and QMessageBox.question(
                self, tr("Reload"), tr("Discard your changes to {name}?").format(name=tab.name),
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No) != QMessageBox.StandardButton.Yes:
            return
        try:
            text = tab.document.load()
        except OSError as exc:
            QMessageBox.warning(self, tr("Reload"), str(exc))
            return
        tab.editor.setPlainText(text)
        tab.editor.document().setModified(False)
        self._update_status()

    def _confirm_close(self, tab: EditorTab) -> bool:
        if not tab.is_modified():
            return True
        answer = QMessageBox.question(
            self, tr("Unsaved Changes"), tr("Save the changes to {name}?").format(name=tab.name),
            QMessageBox.StandardButton.Save | QMessageBox.StandardButton.Discard
            | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel,
        )
        if answer == QMessageBox.StandardButton.Save:
            return self.save_tab(tab)
        return answer == QMessageBox.StandardButton.Discard

    def close_tab(self, index: int) -> bool:
        """Close the tab at *index* (asking for unsaved changes); the last
        tab takes the window with it - an empty editor window has nothing
        to show - unless a file is still being read for a tab. Close Tab in
        an empty window closes the window."""
        tab = self.tabs.widget(index)
        if tab is None and self.tabs.count() == 0:
            return self.close()
        if not isinstance(tab, EditorTab) or not self._confirm_close(tab):
            return False
        self.tabs.removeTab(index)
        tab.deleteLater()
        self._update_status()
        if self.tabs.count() == 0 and not self._loads:
            # Nothing left to ask about: closes at once. A file still being
            # read keeps the window - closing it would drop that read.
            self.close()
        return True

    def closeEvent(self, event) -> None:  # noqa: N802 - Qt
        for tab in self._tabs():
            if not self._confirm_close(tab):
                event.ignore()
                return
        while self.tabs.count():
            widget = self.tabs.widget(0)
            self.tabs.removeTab(0)
            widget.deleteLater()
        for _backend, _path, job in self._loads:
            job.abandon()  # a read still running opens no tab later
        self._loads.clear()
        event.accept()

    # -- view and format -------------------------------------------------------------------

    def show_find(self, replace: bool = False) -> None:
        self.find_bar.show()
        for widget in self.find_bar.replace_widgets:
            widget.setVisible(replace)
        tab = self.current_tab()
        if tab is not None and tab.editor.textCursor().hasSelection():
            self.find_bar.find_edit.setText(tab.editor.textCursor().selectedText())
        self.find_bar.find_edit.setFocus()
        self.find_bar.find_edit.selectAll()

    def go_to_line(self, line: int) -> None:
        tab = self.current_tab()
        if tab is None:
            return
        document = tab.editor.document()
        block = document.findBlockByNumber(max(0, min(line, document.blockCount()) - 1))
        cursor = QTextCursor(block)
        tab.editor.setTextCursor(cursor)
        tab.editor.centerCursor()
        self._update_status()

    def _ask_line(self) -> None:
        tab = self.current_tab()
        if tab is None:
            return
        line, ok = QInputDialog.getInt(self, tr("Go to Line"), tr("Line:"),
                                       tab.editor.textCursor().blockNumber() + 1, 1,
                                       tab.editor.document().blockCount())
        if ok:
            self.go_to_line(line)

    def _set_wrap(self, on: bool) -> None:
        mode = QPlainTextEdit.LineWrapMode.WidgetWidth if on else QPlainTextEdit.LineWrapMode.NoWrap
        for tab in self._tabs():
            tab.editor.setLineWrapMode(mode)

    def _zoom(self, steps: int) -> None:
        tab = self.current_tab()
        if tab is not None:
            tab.editor.zoom(steps)

    def set_newline(self, newline: str) -> None:
        tab = self.current_tab()
        if tab is None or tab.read_only:
            return
        tab.document.set_newline(newline)
        tab.mark_modified()
        self._update_status()

    def set_encoding(self, codec: str, *, bom: bool | None = None) -> None:
        tab = self.current_tab()
        if tab is None or tab.read_only:
            return
        tab.document.set_encoding(codec, bom=bom)
        tab.mark_modified()
        self._update_status()

