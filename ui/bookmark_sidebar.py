"""Bookmark sidebar — dockable tree of bookmarks and groups.

Bookmarks show their (optionally coloured) icon and name; clicking one
emits :pyattr:`BookmarkSidebar.navigate_requested` with the bookmark, the
main window decides which pane navigates. Groups fold: a click on a group
opens or closes it (the state is remembered). Entries can be reordered and
moved into / out of groups by drag & drop or from the right-click menu.

Every change goes through :class:`core.bookmarks.BookmarkManager`; the tree
rebuilds from it afterwards and ``changed`` tells the main window to refresh
its Bookmarks menu.
"""

from __future__ import annotations

import logging
from html import escape as _html_escape

from PyQt6.QtCore import QSize, Qt, QTimer, pyqtSignal
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QDialog,
    QDockWidget,
    QLabel,
    QMenu,
    QMessageBox,
    QPushButton,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core.bookmarks import Bookmark, BookmarkGroup, BookmarkManager
from ui.bookmark_edit_dialog import BookmarkEditDialog, GroupEditDialog
from ui.icon_provider import icon

log = logging.getLogger(__name__)

_NODE_ROLE = Qt.ItemDataRole.UserRole


def _count_bookmarks(group: BookmarkGroup) -> int:
    return sum(_count_bookmarks(c) if isinstance(c, BookmarkGroup) else 1 for c in group.children)


class _BookmarkTree(QTreeWidget):
    """Tree whose drops are NOT applied by Qt: they are reported as
    ``(dragged node, target node or None, where)`` and the sidebar applies
    them through the manager, then rebuilds."""

    drop_requested = pyqtSignal(object, object, str)  # dragged, target, "above|below|into"

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setHeaderHidden(True)
        self.setIconSize(QSize(20, 20))
        self.setIndentation(14)
        self.setExpandsOnDoubleClick(False)
        self.setUniformRowHeights(True)
        self.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.setDragEnabled(True)
        self.setAcceptDrops(True)
        self.setDropIndicatorShown(True)
        self.setDragDropMode(QAbstractItemView.DragDropMode.InternalMove)
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)

    def dropEvent(self, event) -> None:
        selected = self.selectedItems() or ([self.currentItem()] if self.currentItem() else [])
        if not selected:
            event.ignore()
            return
        dragged = selected[0].data(0, _NODE_ROLE)
        target_item = self.itemAt(event.position().toPoint())
        target = target_item.data(0, _NODE_ROLE) if target_item is not None else None
        position = self.dropIndicatorPosition()
        where = {
            QAbstractItemView.DropIndicatorPosition.AboveItem: "above",
            QAbstractItemView.DropIndicatorPosition.BelowItem: "below",
        }.get(position, "into")
        event.ignore()  # the manager does the move; the tree is rebuilt from it
        # Rebuilding inside the drop handler would delete the item Qt is
        # still working with, so hand over on the next event-loop turn.
        QTimer.singleShot(0, lambda: self.drop_requested.emit(dragged, target, where))


class BookmarkSidebar(QDockWidget):
    """Dockable panel listing every bookmark and group."""

    navigate_requested = pyqtSignal(object)  # emits Bookmark
    changed = pyqtSignal()  # after any edit / move / delete / new group

    def __init__(self, bookmark_manager: BookmarkManager, parent=None) -> None:
        super().__init__("Bookmarks", parent)
        self._manager = bookmark_manager
        self._rebuilding = False
        self.setObjectName("BookmarkSidebar")
        self.setAllowedAreas(
            Qt.DockWidgetArea.LeftDockWidgetArea | Qt.DockWidgetArea.RightDockWidgetArea,
        )
        self._build_ui()
        self.rebuild()

    # ------------------------------------------------------------------
    # UI
    # ------------------------------------------------------------------
    def _build_ui(self) -> None:
        container = QWidget(self)
        layout = QVBoxLayout(container)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(4)

        self._new_group_btn = QPushButton("New Group", container)
        self._new_group_btn.setIcon(icon("plus", 16))
        self._new_group_btn.setToolTip("Create a group to collect bookmarks")
        self._new_group_btn.clicked.connect(lambda _c=False: self._new_group(None))
        layout.addWidget(self._new_group_btn)

        # Empty-state hint — tells the user how to populate the panel so a
        # fresh install doesn't look broken.
        self._hint = QLabel(
            "No bookmarks yet.\n\n"
            "Right-click a folder in a pane and choose\n"
            '"Bookmark This Directory" to add one.',
            container,
        )
        self._hint.setProperty("role", "muted")
        self._hint.setStyleSheet("padding: 16px;")
        self._hint.setWordWrap(True)
        self._hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self._hint)

        self._tree = _BookmarkTree(container)
        self._tree.itemClicked.connect(self._on_item_clicked)
        self._tree.itemExpanded.connect(lambda item: self._on_expanded(item, True))
        self._tree.itemCollapsed.connect(lambda item: self._on_expanded(item, False))
        self._tree.customContextMenuRequested.connect(self._show_context_menu)
        self._tree.drop_requested.connect(self._apply_drop)
        layout.addWidget(self._tree, stretch=1)
        self.setWidget(container)
        self._container = container

    def rebuild(self) -> None:
        """Rebuild the tree from the manager."""
        self._rebuilding = True
        try:
            self._tree.clear()
            nodes = self._manager.tree()
            self._hint.setVisible(not nodes)
            self._tree.setVisible(bool(nodes))
            self._add_nodes(self._tree.invisibleRootItem(), nodes)
        finally:
            self._rebuilding = False

    def _add_nodes(self, parent_item: QTreeWidgetItem, nodes: list) -> None:
        for node in nodes:
            item = QTreeWidgetItem(parent_item)
            item.setData(0, _NODE_ROLE, node)
            item.setText(0, node.name)  # plain text: markup is not interpreted
            if isinstance(node, BookmarkGroup):
                item.setIcon(0, icon(node.icon_name or "folder", 32, node.color))
                item.setToolTip(0, _html_escape(node.name))
                self._add_nodes(item, node.children)
                item.setExpanded(node.expanded)
            else:
                item.setIcon(0, icon(node.icon_name or "bookmark", 32, node.color))
                # Qt renders tooltips as rich text, so escape every value.
                item.setToolTip(
                    0,
                    f"{_html_escape(node.name)}<br>{_html_escape(node.path)}"
                    f"<br>({_html_escape(node.backend_name)})",
                )

    # ------------------------------------------------------------------
    # Clicks
    # ------------------------------------------------------------------
    def _on_item_clicked(self, item: QTreeWidgetItem, _col: int) -> None:
        node = item.data(0, _NODE_ROLE)
        if isinstance(node, BookmarkGroup):
            item.setExpanded(not item.isExpanded())  # persisted by itemExpanded/Collapsed
        elif isinstance(node, Bookmark):
            self.navigate_requested.emit(node)

    def _on_expanded(self, item: QTreeWidgetItem, expanded: bool) -> None:
        if self._rebuilding:
            return
        node = item.data(0, _NODE_ROLE)
        if isinstance(node, BookmarkGroup):
            self._manager.set_expanded(node, expanded)

    # ------------------------------------------------------------------
    # Menu
    # ------------------------------------------------------------------
    def _siblings_of(self, node) -> list:
        parent = self._manager.parent_of(node)
        return self._manager.tree() if parent is None else parent.children

    def _build_menu(self, node) -> QMenu:
        menu = QMenu(self)
        if node is None:
            menu.addAction("New Group").triggered.connect(lambda: self._new_group(None))
            return menu
        is_group = isinstance(node, BookmarkGroup)
        if is_group:
            menu.addAction("New Group Inside").triggered.connect(lambda: self._new_group(node))
        menu.addAction("Edit…").triggered.connect(lambda: self._edit_node(node))
        menu.addSeparator()
        siblings = self._siblings_of(node)
        pos = next(i for i, s in enumerate(siblings) if s is node)
        up = menu.addAction("Move Up")
        up.setEnabled(pos > 0)
        up.triggered.connect(lambda: self._move_by(node, -1))
        down = menu.addAction("Move Down")
        down.setEnabled(pos < len(siblings) - 1)
        down.triggered.connect(lambda: self._move_by(node, +1))
        top = menu.addAction("Move to Top")
        top.setEnabled(pos > 0)
        top.triggered.connect(lambda: self._move_to_top(node))
        menu.addSeparator()
        menu.addAction("Delete Group" if is_group else "Delete").triggered.connect(
            lambda: self._delete_node(node)
        )
        return menu

    def _show_context_menu(self, pos) -> None:
        item = self._tree.itemAt(pos)
        node = item.data(0, _NODE_ROLE) if item is not None else None
        self._build_menu(node).exec(self._tree.viewport().mapToGlobal(pos))

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------
    def _after_change(self) -> None:
        self.rebuild()
        self.changed.emit()

    def _move_by(self, node, delta: int) -> None:
        if self._manager.move_by(node, delta):
            self._after_change()

    def _move_to_top(self, node) -> None:
        if self._manager.move_to_top(node):
            self._after_change()

    def _apply_drop(self, dragged, target, where: str) -> None:
        """Move *dragged* relative to *target* (``None`` = end of the top
        level). Invalid drops (a group into itself) change nothing."""
        if dragged is target:
            return
        try:
            if target is None:
                parent, index = None, None
            elif where == "into" and isinstance(target, BookmarkGroup):
                parent, index = target, None
            else:  # above / below a sibling, or "onto" a bookmark = after it
                parent = self._manager.parent_of(target)
                position = next(i for i, s in enumerate(self._siblings_of(target)) if s is target)
                index = position if where == "above" else position + 1
            self._manager.move(dragged, parent, index)
        except (ValueError, KeyError) as exc:
            log.debug("bookmark drop ignored: %s", exc)
            return
        self._after_change()

    def _new_group(self, parent: BookmarkGroup | None) -> None:
        dialog = GroupEditDialog(parent=self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        name, icon_name, color = dialog.result()
        self._manager.add_group(name, icon_name, color, parent=parent)
        if parent is not None:
            self._manager.set_expanded(parent, True)
        self._after_change()

    def _edit_node(self, node) -> None:
        if isinstance(node, BookmarkGroup):
            dialog = GroupEditDialog(node, parent=self)
            if dialog.exec() != QDialog.DialogCode.Accepted:
                return
            name, icon_name, color = dialog.result()
            self._manager.update_group(node, name=name, icon_name=icon_name, color=color)
        else:
            dialog = BookmarkEditDialog(
                node,
                parent=self,
                groups=self._manager.groups(),
                current_group=self._manager.parent_of(node),
            )
            if dialog.exec() != QDialog.DialogCode.Accepted:
                return
            try:
                self._manager.update_bookmark(
                    node, dialog.result_bookmark(), group=dialog.result_group()
                )
            except KeyError as exc:
                QMessageBox.warning(self, "Edit Bookmark", f"Could not save changes: {exc}")
                return
        self._after_change()

    def _delete_node(self, node) -> None:
        # QMessageBox interprets rich text by default. Escape every
        # user-controlled value so a hostile bookmark name like
        # ``<img src="file:///etc/shadow">`` can't forge a resource
        # load attempt or inject HTML into the confirmation dialog.
        if isinstance(node, BookmarkGroup):
            kept = _count_bookmarks(node)
            text = (
                f"Delete group '{_html_escape(node.name)}'?\n\n"
                f"Its {kept} bookmark(s) are kept and move up one level."
            )
            title = "Delete Group"
        else:
            text = f"Delete bookmark '{_html_escape(node.name)}' ({_html_escape(node.path)})?"
            title = "Delete Bookmark"
        reply = QMessageBox.question(
            self,
            title,
            text,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        if isinstance(node, BookmarkGroup):
            self._manager.remove_group(node)
        else:
            self._manager.remove_node(node)
        self._after_change()


__all__ = ["BookmarkSidebar"]
