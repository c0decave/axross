"""Bookmarks > Manage Bookmarks...: every bookmark and group in one window.

Before, this was a flat list with one button, "Delete Selected" (reported:
"manage bookmark tab, kann ja im grunde nur löschen und nicht wirklich
managen"). It is now the sidebar's tree with its name, location and
connection, and the sidebar's own actions as buttons - the code is shared
(:class:`ui.bookmark_sidebar.BookmarkTreeEditing`), and so is the store: the
main window rebuilds the sidebar and the Bookmarks menu after each change.

Double-click or Enter edits, F2 renames, Del deletes the selection; the
right-click menu and drag & drop are the sidebar's.
"""

from __future__ import annotations

import dataclasses
import logging

from PyQt6.QtCore import QEvent, QSize, Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMenu,
    QPushButton,
    QTreeWidgetItem,
    QVBoxLayout,
)

from core.bookmarks import LOCAL_SHELL, BookmarkGroup, BookmarkManager
from core.i18n import tr
from ui.bookmark_sidebar import BookmarkTreeEditing, _BookmarkTree, _count_bookmarks
from ui.close_corner import add_close_corner

log = logging.getLogger(__name__)

COL_NAME, COL_LOCATION, COL_CONNECTION = range(3)


class BookmarkManagerDialog(BookmarkTreeEditing, QDialog):
    """The bookmark tree with every action as a button."""

    navigate_requested = pyqtSignal(object)
    changed = pyqtSignal()
    # Declared for BookmarkTreeEditing; a pane drag cannot reach a modal
    # dialog, so nothing emits these here.
    bookmark_drop_requested = pyqtSignal(list, str, object, object)
    transfer_drop_requested = pyqtSignal(list, str, object, bool)

    def __init__(
        self, bookmark_manager: BookmarkManager, parent=None, *, terminal_profiles=None
    ) -> None:
        QDialog.__init__(self, parent)
        self._manager = bookmark_manager
        self._terminal_profiles = terminal_profiles or (lambda: [])
        self._rebuilding = False
        self.setWindowTitle(tr("Manage Bookmarks"))
        self.resize(820, 480)
        self._build_ui()
        self.rebuild()
        self._update_buttons()
        add_close_corner(self)

    # -- UI ---------------------------------------------------------------
    def _build_ui(self) -> None:
        # A QVBoxLayout on top: add_close_corner gives the corner buttons a
        # row of their own above it instead of laying them over a button.
        root = QVBoxLayout(self)
        body = QHBoxLayout()
        root.addLayout(body, 1)
        left = QVBoxLayout()
        body.addLayout(left, 1)

        self._hint = QLabel(
            tr(
                "No bookmarks yet. Bookmark a folder with Bookmarks > Add Current "
                "Directory (F8), or drag it onto the Bookmarks sidebar; create a "
                "group here."
            )
        )
        self._hint.setProperty("role", "muted")
        self._hint.setWordWrap(True)
        self._hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        left.addWidget(self._hint, 1)

        self._tree = _BookmarkTree(self)
        self._tree.setHeaderHidden(False)
        self._tree.setColumnCount(3)
        self._tree.setHeaderLabels([tr("Name"), tr("Location"), tr("Connection")])
        self._tree.setIconSize(QSize(18, 18))
        # Del / F2 / Enter on the tree (an event filter: no shortcut that
        # could clash with the window's own Del or F2).
        self._tree.installEventFilter(self)
        self._tree.itemDoubleClicked.connect(self._on_double_clicked)
        self._tree.itemExpanded.connect(lambda item: self._on_expanded(item, True))
        self._tree.itemCollapsed.connect(lambda item: self._on_expanded(item, False))
        self._tree.itemSelectionChanged.connect(self._update_buttons)
        self._tree.customContextMenuRequested.connect(self._show_context_menu)
        self._tree.drop_requested.connect(self._apply_drop)
        from ui.column_fit import ColumnFitter

        # The location takes the free width, the name keeps its content.
        self._columns = ColumnFitter(self._tree, fill=COL_LOCATION, keep=(COL_NAME,))
        left.addWidget(self._tree, 1)

        buttons = QVBoxLayout()
        body.addLayout(buttons)

        def button(text: str, slot, tip: str = "") -> QPushButton:
            b = QPushButton(tr(text), self)
            b.setAutoDefault(False)
            if tip:
                b.setToolTip(tr(tip))
            if slot is not None:
                b.clicked.connect(lambda _checked=False: slot())
            buttons.addWidget(b)
            return b

        self._edit_btn = button("Edit…", self._edit_selected,
                                "Name, path, icon, colour and group (Enter)")
        self._rename_btn = button("Rename…", self._rename_selected, "F2")
        buttons.addSpacing(10)
        self._new_group_btn = button("New Group…", lambda: self._new_group(None))
        self._new_terminal_btn = button(
            "New Terminal Bookmark…", lambda: self._new_terminal_bookmark(None)
        )
        buttons.addSpacing(10)
        self._up_btn = button("Move Up", lambda: self._move_selected(-1))
        self._down_btn = button("Move Down", lambda: self._move_selected(+1))
        self._top_btn = button("Move to Top", self._move_selected_to_top)
        self._group_btn = button("Move to Group", None)
        self._group_menu = QMenu(self._group_btn)
        self._group_menu.aboutToShow.connect(self._fill_group_menu)
        self._group_btn.setMenu(self._group_menu)
        self._sort_btn = button("Sort", None)
        self._sort_menu = QMenu(self._sort_btn)
        self._sort_menu.aboutToShow.connect(self._fill_sort_button_menu)
        self._sort_btn.setMenu(self._sort_menu)
        buttons.addSpacing(10)
        self._delete_btn = button("Delete…", self._delete_selected, "Del")
        buttons.addStretch(1)
        close = button("Close", self.accept)
        close.setDefault(False)

    def eventFilter(self, obj, event) -> bool:  # noqa: N802 - Qt override
        if obj is self._tree and event.type() == QEvent.Type.KeyPress and (
            event.modifiers() == Qt.KeyboardModifier.NoModifier
            or event.modifiers() == Qt.KeyboardModifier.KeypadModifier
        ):
            slot = {
                Qt.Key.Key_Delete: self._delete_selected,
                Qt.Key.Key_F2: self._rename_selected,
                Qt.Key.Key_Return: self._edit_selected,
                Qt.Key.Key_Enter: self._edit_selected,
            }.get(Qt.Key(event.key()))
            if slot is not None:
                slot()
                return True
        return False

    # -- rows -------------------------------------------------------------
    def _decorate_item(self, item: QTreeWidgetItem, node) -> None:
        if isinstance(node, BookmarkGroup):
            count = _count_bookmarks(node)
            item.setText(COL_CONNECTION, tr("{count} bookmarks").format(count=count)
                         if count != 1 else tr("1 bookmark"))
            return
        if node.is_smart_folder:
            from core.file_search import describe_saved_search

            item.setText(COL_LOCATION, describe_saved_search(node.search))
            item.setText(COL_CONNECTION, tr("Smart Folder"))
        elif node.is_terminal:
            host = tr("Local Shell") if node.profile_name == LOCAL_SHELL else node.profile_name
            item.setText(COL_LOCATION, node.path)
            item.setText(COL_CONNECTION, tr("Terminal: {host}").format(host=host))
        else:
            item.setText(COL_LOCATION, node.path)
            item.setText(COL_CONNECTION, node.backend_name)
        for col in (COL_LOCATION, COL_CONNECTION):
            item.setToolTip(col, item.text(col))

    def _after_change(self) -> None:
        """Rebuild, the same entries still selected, and tell the window."""
        selected = self._tree.selected_nodes()
        current = self._tree.currentItem()
        current_node = current.data(0, Qt.ItemDataRole.UserRole) if current else None
        self.rebuild()
        self._reselect(selected, current_node)
        self._update_buttons()
        self.changed.emit()

    def _reselect(self, nodes: list, current) -> None:
        def walk(parent) -> None:
            for i in range(parent.childCount()):
                item = parent.child(i)
                node = item.data(0, Qt.ItemDataRole.UserRole)
                if node is current:
                    self._tree.setCurrentItem(item)
                if any(node is n for n in nodes):
                    item.setSelected(True)
                walk(item)

        walk(self._tree.invisibleRootItem())

    # -- selection -------------------------------------------------------
    def _selected(self) -> list:
        return self._tree.selected_nodes()

    def _single(self):
        nodes = self._selected()
        return nodes[0] if len(nodes) == 1 else None

    def _update_buttons(self) -> None:
        nodes = self._selected()
        single = nodes[0] if len(nodes) == 1 else None
        for b in (self._edit_btn, self._rename_btn):
            b.setEnabled(single is not None)
        pos, count = -1, 0
        if single is not None:
            siblings = self._siblings_of(single)
            count = len(siblings)
            pos = next(i for i, s in enumerate(siblings) if s is single)
        self._up_btn.setEnabled(pos > 0)
        self._top_btn.setEnabled(pos > 0)
        self._down_btn.setEnabled(0 <= pos < count - 1)
        self._group_btn.setEnabled(bool(nodes))
        self._delete_btn.setEnabled(bool(nodes))
        group = single if isinstance(single, BookmarkGroup) else None
        self._sort_btn.setToolTip(
            tr("Sort the entries of '{name}'").format(name=group.name) if group is not None
            else tr("Sort the top level (select a group to sort its entries)")
        )

    # -- actions ------------------------------------------------------------
    def _on_double_clicked(self, item: QTreeWidgetItem, _col: int) -> None:
        node = item.data(0, Qt.ItemDataRole.UserRole)
        if node is not None:
            self._edit_node(node)

    def _edit_node(self, node) -> None:
        """The sidebar's edit; then the edited row is selected again (a
        bookmark edit stores a new object in the old one's place)."""
        before = {id(b) for b in self._manager.all()}  # *node* keeps its id taken
        super()._edit_node(node)
        fresh = [b for b in self._manager.all() if id(b) not in before]
        if fresh:
            self._tree.clearSelection()
            self._reselect(fresh, fresh[0])
            self._update_buttons()

    def _edit_selected(self) -> None:
        node = self._single()
        if node is not None:
            self._edit_node(node)

    def _rename_selected(self) -> None:
        node = self._single()
        if node is None:
            return
        title = tr("Rename Group") if isinstance(node, BookmarkGroup) else tr("Rename Bookmark")
        name, ok = QInputDialog.getText(
            self, title, tr("New name:"), QLineEdit.EchoMode.Normal, node.name
        )
        name = name.strip()
        if not ok or not name or name == node.name:
            return
        try:
            if isinstance(node, BookmarkGroup):
                self._manager.update_group(node, name=name)
            else:
                renamed = dataclasses.replace(node, name=name)
                self._manager.update_bookmark(node, renamed)  # takes node's place
                node = renamed
        except KeyError as exc:
            log.debug("bookmark rename ignored: %s", exc)
            return
        self.rebuild()
        self._reselect([node], node)
        self._update_buttons()
        self.changed.emit()

    def _move_selected(self, delta: int) -> None:
        node = self._single()
        if node is not None:
            self._move_by(node, delta)

    def _move_selected_to_top(self) -> None:
        node = self._single()
        if node is not None:
            self._move_to_top(node)

    def _fill_group_menu(self) -> None:
        self._group_menu.clear()
        nodes = self._selected()
        if nodes:
            self._fill_move_to_group_menu(self._group_menu, nodes)

    def _fill_sort_button_menu(self) -> None:
        self._sort_menu.clear()
        single = self._single()
        self._fill_sort_menu(
            self._sort_menu, single if isinstance(single, BookmarkGroup) else None
        )

    def _delete_selected(self) -> None:
        nodes = self._selected()
        if nodes:
            self._delete_nodes(nodes)


__all__ = ["BookmarkManagerDialog"]
