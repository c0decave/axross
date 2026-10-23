"""Bookmark sidebar — dockable tree of bookmarks and groups.

Bookmarks show their (optionally coloured) icon and name; clicking one
emits :pyattr:`BookmarkSidebar.navigate_requested` with the bookmark, the
main window decides which pane navigates. Groups fold: a click on a group
opens or closes it (the state is remembered). Entries can be reordered and
moved into / out of groups by drag & drop or from the right-click menu.

Every change goes through :class:`core.bookmarks.BookmarkManager`; the tree
rebuilds from it afterwards and ``changed`` tells the main window to refresh
its Bookmarks menu.

Files and folders dragged from a file pane can be dropped here as well:
folders dropped on empty space, onto a group or between entries become
bookmarks there (:pyattr:`BookmarkSidebar.bookmark_drop_requested`), and
anything dropped onto a bookmark is moved (Ctrl: copied) into the
bookmarked folder (:pyattr:`BookmarkSidebar.transfer_drop_requested`).
A Smart Folder (a saved Find Files search) is no folder: a click on it
asks the main window to run the search, and nothing is dropped into it.
The sidebar only reads the drag payload and its own tree - it never
touches a backend, so a dead mount or an unreachable remote behind a
bookmark cannot freeze a drag; the main window does the rest off the GUI
thread. Payloads from other programs (text, URLs) are ignored.
"""

from __future__ import annotations

import logging
from html import escape as _html_escape

from PyQt6.QtCore import QRect, QSize, Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QPainter, QPalette, QPen
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

from core.bookmarks import KIND_TERMINAL, LOCAL_SHELL, Bookmark, BookmarkGroup, BookmarkManager
from core.i18n import tr
from ui.bookmark_edit_dialog import BookmarkEditDialog, GroupEditDialog
from ui.file_pane import TRANSFER_MIME_TYPE, _drop_action, decode_transfer_payload
from ui.icon_provider import icon

log = logging.getLogger(__name__)

_NODE_ROLE = Qt.ItemDataRole.UserRole


def _count_bookmarks(group: BookmarkGroup) -> int:
    return sum(_count_bookmarks(c) if isinstance(c, BookmarkGroup) else 1 for c in group.children)


def _emit_later(owner: QWidget, signal, *args) -> None:
    """Emit *signal* on the next event-loop turn.

    A drop is handed over this way: rebuilding the tree inside the drop
    handler would delete the item Qt is still working with, and modal
    dialogs do not belong inside a drag. The timer is a child of *owner*,
    so when the owner is destroyed first nothing fires (a bare
    ``QTimer.singleShot`` lambda would then raise a RuntimeError inside
    Qt, which aborts a process without main.py's excepthook)."""
    timer = QTimer(owner)
    timer.setSingleShot(True)

    def fire() -> None:
        timer.deleteLater()
        signal.emit(*args)

    timer.timeout.connect(fire)
    timer.start(0)


class _BookmarkTree(QTreeWidget):
    """Tree whose drops are NOT applied by Qt: they are reported as
    ``(dragged node, target node or None, where)`` and the sidebar applies
    them through the manager, then rebuilds.

    Pane drags (:data:`ui.file_pane.TRANSFER_MIME_TYPE`) are reported as
    ``(payload, target node or None, where, move)`` with *where* one of
    ``onto`` (a bookmark: transfer into it), ``into`` (a group),
    ``above`` / ``below`` (an entry) or ``end`` (empty space)."""

    # (dragged nodes in tree order, target, "above|below|into")
    drop_requested = pyqtSignal(object, object, str)
    external_drop_requested = pyqtSignal(dict, object, str, bool)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._drop_marker: tuple[QRect, str] | None = None
        # Modifiers of the last mouse press: a Ctrl/Shift click only
        # selects (see BookmarkSidebar._on_item_clicked).
        self.press_modifiers = Qt.KeyboardModifier.NoModifier
        self.setHeaderHidden(True)
        self.setIconSize(QSize(20, 20))
        self.setIndentation(14)
        self.setExpandsOnDoubleClick(False)
        self.setUniformRowHeights(True)
        # Ctrl+click adds to the selection, Shift+click selects a range.
        self.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.setDragEnabled(True)
        self.setAcceptDrops(True)
        self.setDropIndicatorShown(True)
        self.setDragDropMode(QAbstractItemView.DragDropMode.InternalMove)
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)

    def mousePressEvent(self, event) -> None:  # noqa: N802 - Qt override
        self.press_modifiers = event.modifiers()
        super().mousePressEvent(event)

    def selected_nodes(self) -> list:
        """The nodes of the selected rows, in tree order."""
        out: list = []

        def walk(parent) -> None:
            for i in range(parent.childCount()):
                child = parent.child(i)
                if child.isSelected():
                    out.append(child.data(0, _NODE_ROLE))
                walk(child)

        walk(self.invisibleRootItem())
        return out

    # -- pane drags -------------------------------------------------------
    def _external_drop(self, event) -> tuple[dict, object, str, QRect] | None:
        """What a pane drag at the event position means:
        ``(payload, target node or None, where, marker rect)``, or ``None``
        when it would do nothing. Reads the payload and the tree only."""
        payload = decode_transfer_payload(event.mimeData())
        if payload is None or not payload["paths"]:
            return None
        pos = event.position().toPoint()
        item = self.itemAt(pos)
        node = item.data(0, _NODE_ROLE) if item is not None else None
        if node is None:
            where, rect = "end", self.viewport().rect()
        else:
            rect = self.visualItemRect(item)
            margin = max(2, min(rect.height() // 4, 12))
            if pos.y() < rect.top() + margin:
                where = "above"
            elif pos.y() > rect.bottom() - margin:
                where = "below"
            elif isinstance(node, Bookmark) and node.is_smart_folder:
                # A saved search is no folder: nothing can be moved into it.
                where = "above" if pos.y() < rect.center().y() else "below"
            else:
                where = "into" if isinstance(node, BookmarkGroup) else "onto"
            if isinstance(node, Bookmark) and node.is_terminal:
                # A terminal bookmark is no folder: nothing goes into it;
                # folders may still be bookmarked next to it.
                if where == "onto" or not payload["dirs"]:
                    return None
                return payload, node, where, rect
            # Files can only go INTO a bookmark; near its edge they still do.
            if (
                isinstance(node, Bookmark)
                and not node.is_smart_folder
                and (where == "onto" or not payload["dirs"])
            ):
                return payload, node, "onto", rect
        if not payload["dirs"]:
            return None  # only folders can be bookmarked
        return payload, node, where, rect

    def _set_drop_marker(self, marker: tuple[QRect, str] | None) -> None:
        if marker != self._drop_marker:
            self._drop_marker = marker
            self.viewport().update()

    def paintEvent(self, event) -> None:
        super().paintEvent(event)
        if self._drop_marker is None:
            return
        rect, where = self._drop_marker
        painter = QPainter(self.viewport())
        try:
            pen = QPen(self.palette().color(QPalette.ColorRole.Highlight))
            pen.setWidth(2)
            painter.setPen(pen)
            if where == "above":
                painter.drawLine(rect.topLeft(), rect.topRight())
            elif where == "below":
                painter.drawLine(rect.bottomLeft(), rect.bottomRight())
            else:
                painter.drawRect(rect.adjusted(1, 1, -2, -2))
        finally:
            painter.end()

    def dragEnterEvent(self, event) -> None:
        if event.mimeData().hasFormat(TRANSFER_MIME_TYPE):
            self.dragMoveEvent(event)
        elif event.source() is self:
            super().dragEnterEvent(event)  # reordering inside the tree
        else:
            event.ignore()  # text, URLs, other programs' drags

    def dragMoveEvent(self, event) -> None:
        if event.mimeData().hasFormat(TRANSFER_MIME_TYPE):
            target = self._external_drop(event)
            if target is None:
                self._set_drop_marker(None)
                event.ignore()
                return
            self._set_drop_marker((target[3], target[2]))
            event.setDropAction(_drop_action(event))
            event.accept()
        elif event.source() is self:
            super().dragMoveEvent(event)
        else:
            event.ignore()

    def dragLeaveEvent(self, event) -> None:
        self._set_drop_marker(None)
        super().dragLeaveEvent(event)

    def dropEvent(self, event) -> None:
        self._set_drop_marker(None)
        mime = event.mimeData()
        if mime.hasFormat(TRANSFER_MIME_TYPE):
            target = self._external_drop(event)
            if target is None:
                event.ignore()
                return
            payload, node, where, _rect = target
            action = _drop_action(event)
            event.setDropAction(action)
            event.accept()
            _emit_later(
                self,
                self.external_drop_requested,
                payload,
                node,
                where,
                action == Qt.DropAction.MoveAction,
            )
            return
        if not any(mime.hasFormat(fmt) for fmt in self.mimeTypes()):
            event.ignore()  # not one of our own rows: never move the selection
            return
        dragged = self.selected_nodes() or (
            [self.currentItem().data(0, _NODE_ROLE)] if self.currentItem() else []
        )
        if not dragged:
            event.ignore()
            return
        target_item = self.itemAt(event.position().toPoint())
        target = target_item.data(0, _NODE_ROLE) if target_item is not None else None
        position = self.dropIndicatorPosition()
        where = {
            QAbstractItemView.DropIndicatorPosition.AboveItem: "above",
            QAbstractItemView.DropIndicatorPosition.BelowItem: "below",
        }.get(position, "into")
        event.ignore()  # the manager does the move; the tree is rebuilt from it
        _emit_later(self, self.drop_requested, dragged, target, where)


class _DropHint(QLabel):
    """The empty-state hint; folders dragged from a pane can be dropped on
    it (the tree is hidden while there are no bookmarks)."""

    external_drop_requested = pyqtSignal(dict, object, str, bool)

    def __init__(self, text: str, parent: QWidget | None = None) -> None:
        super().__init__(text, parent)
        self.setAcceptDrops(True)

    @staticmethod
    def _folders(event) -> dict | None:
        payload = decode_transfer_payload(event.mimeData())
        return payload if payload is not None and payload["dirs"] else None

    def dragEnterEvent(self, event) -> None:
        self.dragMoveEvent(event)

    def dragMoveEvent(self, event) -> None:
        if self._folders(event) is None:
            event.ignore()
            return
        event.setDropAction(_drop_action(event))
        event.accept()

    def dropEvent(self, event) -> None:
        payload = self._folders(event)
        if payload is None:
            event.ignore()
            return
        action = _drop_action(event)
        event.setDropAction(action)
        event.accept()
        _emit_later(
            self,
            self.external_drop_requested,
            payload,
            None,
            "end",
            action == Qt.DropAction.MoveAction,
        )


class BookmarkTreeEditing:
    """The bookmark tree and everything done to it - shared by the sidebar
    (:class:`BookmarkSidebar`) and Bookmarks > Manage Bookmarks...
    (:class:`ui.bookmark_manager_dialog.BookmarkManagerDialog`), so both
    edit the one store the same way.

    The class mixing it in builds ``_tree`` (a :class:`_BookmarkTree`),
    ``_hint`` (shown when there is nothing), sets ``_manager``,
    ``_terminal_profiles`` and ``_rebuilding`` and declares the signals
    ``navigate_requested``, ``changed``, ``bookmark_drop_requested`` and
    ``transfer_drop_requested`` (PyQt signals live on the QObject class)."""

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

    def _decorate_item(self, item: QTreeWidgetItem, node) -> None:
        """More columns for *node*'s row; the sidebar shows the name only."""

    def _add_nodes(self, parent_item: QTreeWidgetItem, nodes: list) -> None:
        for node in nodes:
            item = QTreeWidgetItem(parent_item)
            item.setData(0, _NODE_ROLE, node)
            item.setText(0, node.name)  # plain text: markup is not interpreted
            if isinstance(node, BookmarkGroup):
                item.setIcon(0, icon(node.icon_name or "folder", 32, node.color))
                # Rich text like the other tooltips, so the escaped name is
                # read back as typed (alone it was shown with its entities).
                item.setToolTip(0, f"<qt>{_html_escape(node.name)}</qt>")
                self._add_nodes(item, node.children)
                item.setExpanded(node.expanded)
            elif node.is_smart_folder:
                from core.file_search import describe_saved_search

                item.setIcon(0, icon(node.icon_name or "find-index", 32, node.color))
                item.setToolTip(
                    0,
                    f"{_html_escape(node.name)}<br>Smart Folder: "
                    f"{_html_escape(describe_saved_search(node.search))}"
                    "<br>Click to run the search again.",
                )
            elif node.is_terminal:
                item.setIcon(0, icon(node.icon_name or "terminal", 32, node.color))
                if node.is_host_terminal:
                    host = node.backend_name  # user@host:port, no profile
                else:
                    host = (
                        tr("Local Shell") if node.profile_name == LOCAL_SHELL
                        else node.profile_name
                    )
                item.setToolTip(
                    0,
                    f"{_html_escape(node.name)}<br>"
                    + _html_escape(tr("Terminal: {host}").format(host=host))
                    + (f"<br>{_html_escape(node.path)}" if node.path else ""),
                )
            else:
                item.setIcon(0, icon(node.icon_name or "bookmark", 32, node.color))
                # Qt renders tooltips as rich text, so escape every value.
                item.setToolTip(
                    0,
                    f"{_html_escape(node.name)}<br>{_html_escape(node.path)}"
                    f"<br>({_html_escape(node.backend_name)})",
                )
            self._decorate_item(item, node)

    # ------------------------------------------------------------------
    # Clicks
    # ------------------------------------------------------------------
    def _on_item_clicked(self, item: QTreeWidgetItem, _col: int) -> None:
        if self._tree.press_modifiers & (
            Qt.KeyboardModifier.ControlModifier | Qt.KeyboardModifier.ShiftModifier
        ):
            return  # Ctrl/Shift+click selects; it neither opens nor folds
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

    def _selection_for(self, node) -> list:
        """What a menu opened on *node* acts on: the selection when *node*
        is part of it, else *node* alone."""
        selected = self._tree.selected_nodes()
        if any(n is node for n in selected):
            return selected
        return [node]

    def _add_move_to_group_menu(self, menu: QMenu, nodes: list) -> None:
        """Move to Group ▸ Top Level / every group the nodes can go into."""
        self._fill_move_to_group_menu(menu.addMenu(tr("&Move to Group")), nodes)

    def _fill_move_to_group_menu(self, sub: QMenu, nodes: list) -> None:
        top = sub.addAction(tr("Top Level"))
        top.triggered.connect(lambda _c=False: self._move_nodes(nodes, None))
        moving_groups = [n for n in nodes if isinstance(n, BookmarkGroup)]
        for depth, group in self._manager.groups():
            # As the Bookmarks menu does: no markup, "&" is no mnemonic.
            label = group.name.replace("<", "").replace(">", "").replace("&", "&&")
            action = sub.addAction("    " * depth + label)
            # A group cannot go into itself or below itself.
            action.setEnabled(not any(BookmarkManager._contains(g, group) for g in moving_groups))
            action.triggered.connect(lambda _c=False, g=group: self._move_nodes(nodes, g))

    #: Sort ▸ entries: (label, key, reverse).
    SORT_ENTRIES: tuple[tuple[str, str, bool], ...] = (
        ("By Name", "name", False),
        ("By Name (Reverse)", "name", True),
        ("By Path", "path", False),
        ("By Path (Reverse)", "path", True),
        ("By Name + Path", "name_path", False),
        ("By Name + Path (Reverse)", "name_path", True),
        ("By Age (Oldest First)", "age", False),
        ("By Age (Newest First)", "age", True),
    )

    def _add_sort_menu(self, menu: QMenu, group: BookmarkGroup | None) -> None:
        """Sort ▸ for the entries of *group* (``None`` = the top level)."""
        self._fill_sort_menu(menu.addMenu(tr("&Sort")), group)

    def _fill_sort_menu(self, sub: QMenu, group: BookmarkGroup | None) -> None:
        sub.setToolTipsVisible(True)
        for index, (label, key, reverse) in enumerate(self.SORT_ENTRIES):
            if index and index % 2 == 0:
                sub.addSeparator()
            action = sub.addAction(tr(label))
            action.setToolTip(tr("Groups stay first; the order is saved"))
            action.triggered.connect(
                lambda _c=False, k=key, r=reverse: self._sort(group, k, r)
            )

    def _sort(self, group: BookmarkGroup | None, key: str, reverse: bool) -> None:
        try:
            changed = self._manager.sort_children(group, key, reverse)
        except (KeyError, ValueError) as exc:
            log.debug("bookmark sort ignored: %s", exc)
            return
        if changed:
            self._after_change()

    @staticmethod
    def _entry(menu: QMenu, label: str, slot, icon_name: str = ""):
        """A menu entry; *icon_name* is the icon the same command has
        elsewhere (the file pane menu's New Folder, Rename, Delete and the
        terminal), so it looks the same. Entries without one there get none."""
        action = menu.addAction(label)
        if icon_name:
            action.setProperty("axIcon", icon_name)
            action.setIcon(icon(icon_name))
        action.triggered.connect(lambda _c=False: slot())
        return action

    def _build_menu(self, node) -> QMenu:
        """Create, then edit, then move and sort, then delete - each group
        behind a separator; every entry has its own "&" letter."""
        menu = QMenu(self)
        entry = self._entry
        if node is None:
            entry(menu, tr("&New Group"), lambda: self._new_group(None), "folder")
            entry(menu, tr("New &Terminal Bookmark…"),
                  lambda: self._new_terminal_bookmark(None), "terminal")
            menu.addSeparator()
            self._add_sort_menu(menu, None)
            return menu
        nodes = self._selection_for(node)
        if len(nodes) > 1:
            self._add_move_to_group_menu(menu, nodes)
            menu.addSeparator()
            entry(menu, tr("&Delete {count} Selected…").format(count=len(nodes)),
                  lambda: self._delete_nodes(nodes), "x")
            return menu
        is_group = isinstance(node, BookmarkGroup)
        if is_group:
            entry(menu, tr("New Group &Inside"), lambda: self._new_group(node), "folder")
            entry(menu, tr("New &Terminal Bookmark…"),
                  lambda: self._new_terminal_bookmark(node), "terminal")
            menu.addSeparator()
        entry(menu, tr("&Edit…"), lambda: self._edit_node(node), "edit")
        menu.addSeparator()
        siblings = self._siblings_of(node)
        pos = next(i for i, s in enumerate(siblings) if s is node)
        entry(menu, tr("Move &Up"), lambda: self._move_by(node, -1)).setEnabled(pos > 0)
        entry(menu, tr("Move Do&wn"), lambda: self._move_by(node, +1)).setEnabled(
            pos < len(siblings) - 1)
        entry(menu, tr("Move to To&p"), lambda: self._move_to_top(node)).setEnabled(pos > 0)
        self._add_move_to_group_menu(menu, [node])
        if is_group:
            self._add_sort_menu(menu, node)
        menu.addSeparator()
        entry(menu, tr("&Delete Group") if is_group else tr("&Delete"),
              lambda: self._delete_node(node), "x")
        return menu

    def _show_context_menu(self, pos) -> None:
        item = self._tree.itemAt(pos)
        node = item.data(0, _NODE_ROLE) if item is not None else None
        if item is not None and not item.isSelected():
            # A right click outside the selection acts on that entry alone,
            # as in a file manager: the selection follows it.
            self._tree.clearSelection()
            self._tree.setCurrentItem(item)
            item.setSelected(True)
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

    def _move_nodes(self, nodes: list, group: BookmarkGroup | None) -> None:
        """Move to Group: *nodes* to the end of *group* (``None`` = top level)."""
        try:
            moved = self._manager.move_nodes(nodes, group)
        except (ValueError, KeyError) as exc:
            log.debug("bookmark move ignored: %s", exc)
            return
        if moved:
            if group is not None:
                self._manager.set_expanded(group, True)
            self._after_change()

    def _apply_drop(self, dragged, target, where: str) -> None:
        """Move *dragged* (a node, or a list of nodes in tree order)
        relative to *target* (``None`` = end of the top level). Invalid
        drops (a group into itself) change nothing."""
        nodes = list(dragged) if isinstance(dragged, (list, tuple)) else [dragged]
        if not nodes or (len(nodes) == 1 and nodes[0] is target):
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
            self._manager.move_nodes(nodes, parent, index)
        except (ValueError, KeyError, StopIteration) as exc:
            log.debug("bookmark drop ignored: %s", exc)
            return
        self._after_change()

    def _apply_external_drop(self, payload: dict, target, where: str, is_move: bool) -> None:
        """Turn a pane drop into a request for the main window: a transfer
        into the bookmark dropped onto, or bookmarks for the dragged folders
        at the drop position. A target that vanished meanwhile (the tree
        was rebuilt) means the end of the top level."""
        paths = list(payload["paths"])
        source_pane_id = payload["source_pane_id"]
        if where == "onto" and isinstance(target, Bookmark):
            if not target.is_smart_folder:
                self.transfer_drop_requested.emit(paths, source_pane_id, target, is_move)
            return
        folders = list(payload["dirs"])
        if not folders:
            return
        group, index = None, None
        try:
            if where == "into" and isinstance(target, BookmarkGroup):
                self._manager.parent_of(target)  # KeyError when gone
                group = target
            elif target is not None and where in ("above", "below"):
                group = self._manager.parent_of(target)
                position = next(i for i, s in enumerate(self._siblings_of(target)) if s is target)
                index = position if where == "above" else position + 1
        except (KeyError, StopIteration):
            group, index = None, None
        self.bookmark_drop_requested.emit(folders, source_pane_id, group, index)

    def _new_group(self, parent: BookmarkGroup | None) -> None:
        dialog = GroupEditDialog(parent=self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        name, icon_name, color = dialog.result()
        self._manager.add_group(name, icon_name, color, parent=parent)
        if parent is not None:
            self._manager.set_expanded(parent, True)
        self._after_change()

    def _new_terminal_bookmark(self, group: BookmarkGroup | None) -> None:
        self.new_terminal_bookmark(
            Bookmark(
                name="",
                path="",
                profile_name=LOCAL_SHELL,
                icon_name="terminal",
                kind=KIND_TERMINAL,
            ),
            group,
        )

    def new_terminal_bookmark(self, draft: Bookmark, group: BookmarkGroup | None = None) -> bool:
        """The terminal-bookmark dialog for *draft* (connection, working
        folder, name, icon, group); adds the result. Returns whether a
        bookmark was added."""
        dialog = BookmarkEditDialog(
            draft,
            parent=self,
            groups=self._manager.groups(),
            current_group=group,
            new=True,
            terminal_profiles=list(self._terminal_profiles()),
        )
        try:
            if dialog.exec() != QDialog.DialogCode.Accepted:
                return False
            bookmark = dialog.result_bookmark()
            target = dialog.result_group()
        finally:
            dialog.deleteLater()
        if not self._manager.add(bookmark, group=target):
            taken = self._manager.find(bookmark.path, bookmark.backend_name, bookmark.kind)
            QMessageBox.information(
                self,
                tr("New Terminal Bookmark"),
                tr("Not added: this terminal is already bookmarked as '{name}'.").format(
                    name=taken.name if taken is not None else ""
                ),
            )
            return False
        if target is not None:
            self._manager.set_expanded(target, True)
        self._after_change()
        return True

    def edit_node(self, node) -> None:
        """Open the edit dialog for *node* - the context menu's "Edit..."
        flow, for callers outside the sidebar."""
        self._edit_node(node)

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
                terminal_profiles=list(self._terminal_profiles()) if node.is_terminal else None,
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

    def _delete_nodes(self, nodes: list) -> None:
        """Delete a selection after one question that names the count."""
        if len(nodes) == 1:
            self._delete_node(nodes[0])
            return
        groups = sum(1 for n in nodes if isinstance(n, BookmarkGroup))
        marks = len(nodes) - groups
        parts = []
        if marks:
            parts.append(tr("{count} bookmarks").format(count=marks) if marks > 1
                         else tr("1 bookmark"))
        if groups:
            parts.append(tr("{count} groups").format(count=groups) if groups > 1
                         else tr("1 group"))
        text = tr("Delete {what}?").format(what=tr(" and ").join(parts))
        if groups:
            text += "\n\n" + tr(
                "The bookmarks inside a deleted group are kept and move up one level."
            )
        reply = QMessageBox.question(
            self,
            tr("Delete Bookmarks"),
            text,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        try:
            self._manager.remove_nodes(nodes)
        except KeyError as exc:
            log.debug("bookmark delete ignored: %s", exc)
        self._after_change()

    def _delete_node(self, node) -> None:
        # QMessageBox guesses rich text from the first line only: that line
        # is fixed text, the names follow as typed on their own lines, so a
        # hostile name like ``<img src="file:///etc/shadow">`` stays text.
        # (Escaped instead, "Bob's & Co" was shown as "Bob&#x27;s &amp; Co".)
        if isinstance(node, BookmarkGroup):
            kept = _count_bookmarks(node)
            text = (
                f"Delete this group?\n\n{node.name}\n\n"
                f"Its {kept} bookmark(s) are kept and move up one level."
            )
            title = "Delete Group"
        else:
            # A Smart Folder's path is its key in the store, not a place.
            where = "" if node.is_smart_folder or not node.path else f"\n{node.path}"
            text = f"Delete this bookmark?\n\n{node.name}{where}"
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


class BookmarkSidebar(BookmarkTreeEditing, QDockWidget):
    """Dockable panel listing every bookmark and group."""

    navigate_requested = pyqtSignal(object)  # emits Bookmark
    changed = pyqtSignal()  # after any edit / move / delete / new group
    # Folders dragged from a pane: (folder paths, source pane id,
    # group or None for the top level, index or None to append).
    bookmark_drop_requested = pyqtSignal(list, str, object, object)
    # Items dragged from a pane onto a bookmark:
    # (paths, source pane id, Bookmark, move? - False when Ctrl copies).
    transfer_drop_requested = pyqtSignal(list, str, object, bool)

    def __init__(
        self, bookmark_manager: BookmarkManager, parent=None, *, terminal_profiles=None
    ) -> None:
        super().__init__("Bookmarks", parent)
        self._manager = bookmark_manager
        # () -> the connection profile names a terminal bookmark may use.
        self._terminal_profiles = terminal_profiles or (lambda: [])
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
        self._hint = _DropHint(
            "No bookmarks yet.\n\n"
            "Drag folders here from a pane, or right-click\n"
            'a folder and choose "Bookmark This Directory".',
            container,
        )
        self._hint.external_drop_requested.connect(self._apply_external_drop)
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
        self._tree.external_drop_requested.connect(self._apply_external_drop)
        layout.addWidget(self._tree, stretch=1)
        self.setWidget(container)
        self._container = container


__all__ = ["BookmarkSidebar", "BookmarkTreeEditing"]
