"""Bookmark sidebar — dockable panel with clickable bookmarks.

Each bookmark renders as an icon button with its name as a tooltip.
Clicking emits :pyattr:`BookmarkSidebar.navigate_requested` with the
full bookmark; the main window decides which pane to navigate.

Right-click on a button surfaces Edit / Remove via a small menu.
"""
from __future__ import annotations

from html import escape as _html_escape

from PyQt6.QtCore import QSize, Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QDockWidget,
    QMenu,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from core.bookmarks import Bookmark, BookmarkManager
from ui.bookmark_edit_dialog import BookmarkEditDialog
from ui.icon_provider import icon


class _BookmarkButton(QPushButton):
    """One row in the sidebar. Shows the bookmark's icon + its name;
    clicking navigates, right-clicking pops an Edit/Delete menu."""

    navigate_requested = pyqtSignal(object)     # emits Bookmark
    edit_requested = pyqtSignal(int)            # emits list index
    delete_requested = pyqtSignal(int)          # emits list index

    def __init__(self, index: int, bookmark: Bookmark, parent=None) -> None:
        super().__init__(parent)
        self._index = index
        self._bookmark = bookmark
        self.setIcon(icon(bookmark.icon_name or "bookmark"))
        self.setIconSize(QSize(22, 22))
        # A hostile bookmarks.json (manual edit, cloud-sync tamper)
        # could put HTML / rich-text markup in ``name`` or ``path``.
        # Two distinct widget surfaces with different escaping needs:
        #
        # 1. ``setText`` — QPushButton uses Qt.AutoText. Strip ``<``
        #    and ``>`` so no HTML tag can form in the first place;
        #    keep the rest of the string human-readable. html.escape
        #    would render user-entered ``<`` literally as ``&lt;``,
        #    which is ugly AND surprising for non-adversarial names.
        # 2. ``setToolTip`` — Qt ALWAYS renders tooltips as rich
        #    text, so a literal ``<img src="file://…">`` would
        #    trigger a resource-load attempt. html.escape() here
        #    so entities display correctly and no tag executes.
        def _strip_html_markers(s: str) -> str:
            return s.replace("<", "").replace(">", "")

        display_name = _strip_html_markers(bookmark.name)
        self.setText(display_name)
        safe_name_tt = _html_escape(bookmark.name)
        safe_path_tt = _html_escape(bookmark.path)
        safe_backend_tt = _html_escape(bookmark.backend_name)
        self.setToolTip(
            f"{safe_name_tt}\n"
            f"{safe_path_tt}\n"
            f"({safe_backend_tt})",
        )
        self.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed,
        )
        self.setStyleSheet("text-align: left; padding: 6px 10px;")
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.customContextMenuRequested.connect(self._on_context_menu)
        self.clicked.connect(self._on_click)

    def _on_click(self) -> None:
        self.navigate_requested.emit(self._bookmark)

    def _on_context_menu(self, pos) -> None:
        menu = QMenu(self)
        edit_action = menu.addAction("Edit…")
        edit_action.triggered.connect(
            lambda: self.edit_requested.emit(self._index),
        )
        delete_action = menu.addAction("Delete")
        delete_action.triggered.connect(
            lambda: self.delete_requested.emit(self._index),
        )
        menu.exec(self.mapToGlobal(pos))


class BookmarkSidebar(QDockWidget):
    """Dockable panel listing every bookmark.

    ``navigate_requested`` fires when the user clicks a button; the
    main window is the authoritative router (it knows which pane
    is active, which backends are connected, etc.). The sidebar
    intentionally doesn't try to open connections itself.

    The panel rebuilds from scratch on every change (add / edit /
    delete) — realistic bookmark counts are small enough that a
    full rebuild is simpler than diff-patching.
    """

    navigate_requested = pyqtSignal(object)  # emits Bookmark

    def __init__(self, bookmark_manager: BookmarkManager, parent=None) -> None:
        super().__init__("Bookmarks", parent)
        self._manager = bookmark_manager
        self.setObjectName("BookmarkSidebar")
        self.setAllowedAreas(
            Qt.DockWidgetArea.LeftDockWidgetArea
            | Qt.DockWidgetArea.RightDockWidgetArea,
        )
        self._build_ui()
        self.rebuild()

    def _build_ui(self) -> None:
        container = QWidget(self)
        self._layout = QVBoxLayout(container)
        self._layout.setContentsMargins(0, 0, 0, 0)
        self._layout.setSpacing(2)

        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff,
        )
        scroll.setWidget(container)
        self.setWidget(scroll)
        self._container = container

    def rebuild(self) -> None:
        """Clear + rebuild the button list from the manager. Called
        on every add / edit / delete so the panel always reflects
        persisted state."""
        # Remove every previous widget from the layout.
        while self._layout.count():
            item = self._layout.takeAt(0)
            w = item.widget()
            if w is not None:
                w.setParent(None)
                w.deleteLater()
        bookmarks = self._manager.all()
        if not bookmarks:
            # Empty-state hint — tells the user how to populate the
            # panel so a fresh install doesn't look broken.
            from PyQt6.QtWidgets import QLabel
            hint = QLabel(
                "No bookmarks yet.\n\n"
                "Right-click a folder in a pane and choose\n"
                "\"Bookmark This Directory\" to add one.",
                self._container,
            )
            hint.setStyleSheet("color: #888; padding: 16px;")
            hint.setWordWrap(True)
            hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self._layout.addWidget(hint)
            self._layout.addStretch(1)
            return
        for index, bm in enumerate(bookmarks):
            btn = _BookmarkButton(index, bm, self._container)
            btn.navigate_requested.connect(self.navigate_requested.emit)
            btn.edit_requested.connect(self._on_edit)
            btn.delete_requested.connect(self._on_delete)
            self._layout.addWidget(btn)
        self._layout.addStretch(1)

    # ------------------------------------------------------------------
    # Slots
    # ------------------------------------------------------------------
    def _on_edit(self, index: int) -> None:
        bookmarks = self._manager.all()
        if not (0 <= index < len(bookmarks)):
            return
        dialog = BookmarkEditDialog(bookmarks[index], parent=self)
        if dialog.exec() == BookmarkEditDialog.DialogCode.Accepted:
            try:
                self._manager.update(index, dialog.result_bookmark())
            except IndexError as exc:
                QMessageBox.warning(
                    self, "Edit Bookmark",
                    f"Could not save changes: {exc}",
                )
                return
            self.rebuild()

    def _on_delete(self, index: int) -> None:
        bookmarks = self._manager.all()
        if not (0 <= index < len(bookmarks)):
            return
        bm = bookmarks[index]
        # QMessageBox interprets rich text by default. Escape every
        # user-controlled value so a hostile bookmark name like
        # ``<img src="file:///etc/shadow">`` can't forge a resource
        # load attempt or inject HTML into the confirmation dialog.
        safe_name = _html_escape(bm.name)
        safe_path = _html_escape(bm.path)
        reply = QMessageBox.question(
            self, "Delete Bookmark",
            f"Delete bookmark '{safe_name}' ({safe_path})?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        self._manager.remove(index)
        self.rebuild()


__all__ = ["BookmarkSidebar"]
