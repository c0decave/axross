"""Keyboard shortcut reference (F1): a scrollable list with a search field.

``/`` jumps to the search from anywhere in the dialog; the search matches
keys, descriptions and section names. Escape clears a search first and
closes the dialog second; Down moves from the search into the list.

Window-level shortcuts are QActions on the main window, and
``tests/test_shortcuts_dialog.py`` holds every one of them to this list.
Pane keys are handled in ``FilePaneWidget.eventFilter``.
"""

from __future__ import annotations

from PyQt6.QtCore import QEvent, Qt
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QDialog,
    QDialogButtonBox,
    QLabel,
    QLineEdit,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
)

from core.i18n import tr
from ui.close_corner import add_close_corner

#: (section, keys, description). Keys use QKeySequence's portable text.
SHORTCUTS: list[tuple[str, tuple[str, ...], str]] = [
    ("File operations", ("F2", "F9"), "Rename"),
    ("File operations", ("F3",), "View file (text / hex)"),
    ("File operations", ("F4",), "Edit file (text / hex)"),
    ("File operations", ("F5",), "Copy to the target pane"),
    ("File operations", ("F6",), "Move to the target pane"),
    ("File operations", ("F7",), "New folder"),
    ("File operations", ("Del",), "Delete"),
    ("File operations", ("Return",), "Open file / enter folder"),
    ("File operations", ("Alt+Return",), "Properties (size, owner, permissions)"),
    ("File operations", ("F10",), "Context menu"),
    ("File operations", ("Ctrl+Z",), "Undo the last operation"),
    ("Navigation", ("Ctrl+R",), "Refresh"),
    ("Navigation", ("Backspace",), "Parent folder"),
    ("Navigation", ("Alt+Left",), "History back"),
    ("Navigation", ("Alt+Right",), "History forward"),
    ("Navigation", ("Ctrl+L",), "Focus the path bar"),
    ("Navigation", ("Ctrl+F",), "Focus the filter"),
    ("Navigation", ("Ctrl+Shift+F",), "Find in index"),
    ("Navigation", ("Ctrl+Shift+D",), "Duplicate Finder"),
    ("Navigation", ("Tab",), "Next pane"),
    ("Navigation", ("Shift+Tab",), "Previous pane"),
    ("Selection", ("Space",), "Mark the file and move down"),
    ("Selection", ("Ctrl+A",), "Select all"),
    ("Selection", ("Ctrl+Shift+A",), "Invert selection"),
    ("Selection", ("Shift+Click",), "Select a range"),
    ("Selection", ("Ctrl+Click",), "Add to / remove from the selection"),
    ("Selection", ("Esc",), "Clear the selection, or stop a running load"),
    ("Bookmarks", ("F8", "Ctrl+Shift+B"), "Bookmark the current folder"),
    ("Bookmarks", ("Ctrl+D",), "Bookmark the current folder (in the file list)"),
    ("Bookmarks", ("Ctrl+B",), "Open the bookmarks menu"),
    ("Bookmarks", ("F12",), "Show / hide the bookmark sidebar"),
    ("Pane management", ("Ctrl+Shift+H",), "Split horizontally"),
    ("Pane management", ("Ctrl+Shift+V",), "Split vertically"),
    ("Pane management", ("Ctrl+W",), "Close the active pane"),
    ("Pane management", ("Ctrl+Shift+L",), "Toggle the layout (H / V)"),
    ("Pane management", ("Ctrl+Shift+E",), "Equalize pane sizes"),
    ("Pane management", ("Ctrl+Shift+Left", "Ctrl+Shift+Right"), "Move the pane left / right"),
    ("Pane management", ("Ctrl+Shift+X",), "Extract the pane to the root"),
    ("Pane management", ("Ctrl+Alt+L", "Ctrl+Alt+Shift+L"), "Next / previous layout preset"),
    ("Window", ("Ctrl+N",), "Quick Connect"),
    ("Window", ("Ctrl+Shift+N",), "Connection Manager"),
    ("Window", ("Ctrl+Shift+T",), "Open a shell terminal"),
    ("Window", ("Ctrl+Shift+R",), "Restore the last session"),
    ("Window", ("Ctrl+Shift+I",), "Show / hide the Analysis panel"),
    ("Window", ("Ctrl+H",), "Show / hide hidden files"),
    ("Window", ("Ctrl+Shift+G",), "Thumbnail view for the active pane (images, PDFs, videos)"),
    ("Window", ("Ctrl+C",), "Copy the selected paths"),
    ("Window", ("Ctrl+=", "Ctrl+-", "Ctrl+0"), "Zoom in / out / reset"),
    ("Window", ("Ctrl+Q",), "Quit"),
    ("Window", ("F1",), "This list"),
    (
        "Viewers",
        ("Ctrl+M",),
        "Maximize / restore the window: viewers, editors and dialogs "
        "(also the button left of the [x])",
    ),
    ("Viewers", ("F11",), "Fullscreen on / off (image and media viewer)"),
    ("Viewers", ("Delete",), "Delete the shown file (image and media viewer)"),
    (
        "Viewers",
        ("Left", "Right", "PageUp", "PageDown", "Space"),
        "Previous / next file (media viewer; never a page)",
    ),
    ("Viewers", ("Up", "Down"), "Previous / next page of a PDF (media viewer)"),
    ("Scripting", ("Ctrl+S",), "Save the script (Scripts panel)"),
    ("Scripting", ("Ctrl+Return",), "Run the script in its own process (Scripts panel)"),
    ("Scripting", ("Tab", "Shift+Tab"), "Indent / dedent the line or selection (script editor)"),
    ("Scripting", (".help",), "Console: list the slash commands"),
    ("Scripting", (".scripts",), "Console: list the saved scripts"),
    ("Scripting", (".run <name>",), "Console: run a saved script in the live namespace"),
    ("Scripting", (".save <name>",), "Console: save this session's input as a script"),
    ("Scripting", (".load <name>",), "Console: print a saved script"),
    ("Scripting", (".delete <name>",), "Console: delete a saved script"),
    ("Scripting", (".open",), "Console: show the script directory"),
    ("Terminal pane", ("Ctrl+Shift+P",), "Pin: capture all keyboard input"),
    ("Terminal pane", ("Ctrl+A..Z",), "Terminal control characters (while pinned)"),
    # Matches file_pane._drop_action (tests/test_shortcuts_drag_matches_drop.py).
    ("Drag and drop", ("Drag",), "Move"),
    ("Drag and drop", ("Ctrl+Drag",), "Copy"),
    ("Drag and drop", ("Header drag",), "Rearrange panes"),
]


class ShortcutsDialog(QDialog):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        from axross._version import __version__

        self.setWindowTitle(tr("Keyboard Shortcuts") + f" — axross {__version__}")
        self.resize(560, 640)
        self.entries = SHORTCUTS

        self.search = QLineEdit()
        self.search.setPlaceholderText(tr("Search (press / to focus)"))
        self.search.setClearButtonEnabled(True)
        self.search.textChanged.connect(self._apply_filter)
        self.search.installEventFilter(self)

        self.tree = QTreeWidget()
        self.tree.setColumnCount(2)
        self.tree.setHeaderLabels([tr("Keys"), tr("Action")])
        self.tree.setRootIsDecorated(False)
        self.tree.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        # Per item: per pixel leaves the last row 1 px under the edge after End.
        self.tree.setVerticalScrollMode(QAbstractItemView.ScrollMode.ScrollPerItem)
        from ui.column_fit import ColumnFitter

        # Keys as wide as they are, Action the rest; both dividers draggable.
        self._columns = ColumnFitter(self.tree, fill=1)
        self.tree.installEventFilter(self)

        sections: dict[str, QTreeWidgetItem] = {}
        for section, keys, description in SHORTCUTS:
            parent = sections.get(section)
            if parent is None:
                parent = QTreeWidgetItem(self.tree, [tr(section)])
                parent.setFirstColumnSpanned(True)
                parent.setFlags(Qt.ItemFlag.ItemIsEnabled)
                font = parent.font(0)
                font.setBold(True)
                parent.setFont(0, font)
                sections[section] = parent
            item = QTreeWidgetItem(parent, [" / ".join(keys), tr(description)])
            # English and translated text: what is shown must be findable.
            haystack = " ".join((*keys, description, tr(description), section, tr(section)))
            item.setData(0, Qt.ItemDataRole.UserRole, haystack.lower())
        self.tree.expandAll()

        self.empty_hint = QLabel(tr("No shortcut matches."))
        self.empty_hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.empty_hint.hide()

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        for button in buttons.buttons():  # Return in the search must not press Close
            button.setAutoDefault(False)
            button.setDefault(False)

        layout = QVBoxLayout(self)
        layout.addWidget(self.search)
        layout.addWidget(self.tree, 1)
        layout.addWidget(self.empty_hint)
        layout.addWidget(buttons)
        self.tree.setFocus()
        add_close_corner(self)

    def _apply_filter(self, text: str) -> None:
        words = text.lower().split()
        shown = 0
        for i in range(self.tree.topLevelItemCount()):
            section = self.tree.topLevelItem(i)
            visible_rows = 0
            for j in range(section.childCount()):
                item = section.child(j)
                haystack = item.data(0, Qt.ItemDataRole.UserRole)
                match = all(w in haystack for w in words)
                item.setHidden(not match)
                visible_rows += match
            section.setHidden(visible_rows == 0)
            shown += visible_rows
        self.empty_hint.setVisible(shown == 0)

    def _first_visible_row(self) -> QTreeWidgetItem | None:
        for i in range(self.tree.topLevelItemCount()):
            section = self.tree.topLevelItem(i)
            for j in range(section.childCount()):
                if not section.child(j).isHidden():
                    return section.child(j)
        return None

    def keyPressEvent(self, event) -> None:
        """'/' from anywhere the key is not typed into the search itself."""
        if event.key() == Qt.Key.Key_Slash and not self.search.hasFocus():
            self.search.setFocus()
            self.search.selectAll()
            return
        if event.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
            return  # no default button: Return never closes the dialog
        if event.key() == Qt.Key.Key_Escape and self.search.text():
            self.search.clear()  # from the list too: the search goes first, then the dialog
            return
        super().keyPressEvent(event)

    def eventFilter(self, watched, event) -> bool:
        if event.type() == QEvent.Type.KeyPress:
            key = event.key()
            if watched is self.tree and key == Qt.Key.Key_Slash:
                self.search.setFocus()
                self.search.selectAll()
                return True
            if watched is self.search:
                if key == Qt.Key.Key_Escape and self.search.text():
                    self.search.clear()
                    return True
                if key in (Qt.Key.Key_Down, Qt.Key.Key_PageDown):
                    row = self._first_visible_row()
                    if row is not None:
                        self.tree.setCurrentItem(row)
                        self.tree.setFocus()
                    return True
        return super().eventFilter(watched, event)
