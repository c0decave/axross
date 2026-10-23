"""Tags in the interface: the pane's Tags submenu, the coloured dots in the
Name column, a new tag, and View > Tagged Files… (core.tags)."""

from __future__ import annotations

import posixpath

from PyQt6.QtCore import QRectF, Qt
from PyQt6.QtGui import QColor, QIcon, QPainter
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QColorDialog,
    QDialog,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMenu,
    QMessageBox,
    QPushButton,
    QSplitter,
    QStyle,
    QStyledItemDelegate,
    QStyleOptionViewItem,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
)

from core import tags as T
from core.i18n import tr
from ui.close_corner import add_close_corner

DOT = 8
#: Room between dots, and between the name and the first dot / the last dot
#: and the cell's right edge.
DOT_GAP = 3
DOT_MARGIN = 4


def dots_width(count: int) -> int:
    """The width *count* tag dots take at the right of a Name cell: the
    name is measured and cut with this much less room, so no dot is
    painted over it."""
    if count <= 0:
        return 0
    return DOT_MARGIN + count * DOT + (count - 1) * DOT_GAP + DOT_MARGIN


def ask_new_tag(parent) -> T.Tag | None:
    """A name and a colour from the user; the new tag, or None."""
    name, ok = QInputDialog.getText(parent, tr("New Tag"), tr("Tag name:"))
    if not ok or not name.strip():
        return None
    colour = QColorDialog.getColor(QColor("#5b8def"), parent, tr("Tag Colour"))
    if not colour.isValid():
        return None
    try:
        return T.store().define(name, colour.name())
    except ValueError as exc:
        QMessageBox.warning(parent, tr("New Tag"), str(exc))
        return None


def add_tags_menu(pane, menu: QMenu) -> None:
    """Tags ▸ in the pane's context menu: one tick per tag (ticked when every
    selected file has it), New Tag…, Tagged Files…."""
    paths = pane.selected_items()
    if not paths:
        return
    store = T.store()
    sub = menu.addMenu(tr("Tags"))
    for tag in store.tags():
        action = sub.addAction(tag.name)
        action.setCheckable(True)
        action.setChecked(all(tag.name in store.tags_of(pane.backend.name, p) for p in paths))
        action.setIcon(_dot_icon(tag.colour))
        action.triggered.connect(lambda _checked=False, n=tag.name: pane.toggle_tag(n))
    sub.addSeparator()
    sub.addAction(tr("New Tag…")).triggered.connect(lambda _c=False: pane.new_tag_for_selection())
    window = pane.window()
    if hasattr(window, "_show_tagged_files"):
        sub.addAction(tr("Tagged Files…")).triggered.connect(lambda _c=False: window._show_tagged_files())


def _dot_icon(colour: str):
    from PyQt6.QtGui import QIcon, QPixmap

    pixmap = QPixmap(12, 12)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.setBrush(QColor(colour))
    painter.setPen(Qt.PenStyle.NoPen)
    painter.drawEllipse(1, 1, 10, 10)
    painter.end()
    return QIcon(pixmap)


class TagDotsDelegate(QStyledItemDelegate):
    """The Name column as usual, with a dot per tag at its right edge."""

    def __init__(self, pane) -> None:
        super().__init__(pane)
        self._pane = pane

    def sizeHint(self, option, index):
        size = super().sizeHint(option, index)
        size.setWidth(size.width() + dots_width(len(self._pane.tag_colours_at(index))))
        return size

    def paint(self, painter: QPainter, option, index) -> None:
        colours = self._pane.tag_colours_at(index)
        if not colours:
            super().paint(painter, option, index)
            return
        # The name gets the cell minus the dots: it is cut (elided) before
        # them, never painted under them. The selection still spans the
        # whole cell: the background is drawn first over the full rect.
        style = option.widget.style() if option.widget is not None else None
        full = QStyleOptionViewItem(option)
        self.initStyleOption(full, index)
        full.text = ""
        full.icon = QIcon()
        if style is not None:
            style.drawControl(QStyle.ControlElement.CE_ItemViewItem, full, painter, option.widget)
        narrowed = QStyleOptionViewItem(option)
        narrowed.rect = option.rect.adjusted(0, 0, -dots_width(len(colours)), 0)
        narrowed.state &= ~QStyle.StateFlag.State_HasFocus
        super().paint(painter, narrowed, index)
        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setPen(Qt.PenStyle.NoPen)
        rect = option.rect
        x = rect.right() - DOT_MARGIN - DOT
        y = rect.center().y() - DOT / 2
        for colour in reversed(colours):
            painter.setBrush(QColor(colour))
            painter.drawEllipse(QRectF(x, y, DOT, DOT))
            x -= DOT + DOT_GAP
        painter.restore()


class TaggedFilesDialog(QDialog):
    """Every tag and the files that carry it; double-click goes there."""

    def __init__(self, parent=None, *, go_to=None) -> None:
        super().__init__(parent)
        self.setWindowTitle(tr("Tagged Files"))
        self.resize(820, 480)
        self._go_to = go_to
        self._entries: list[T.TaggedFile] = []
        split = QSplitter()
        self.tags = QListWidget()
        self.tags.currentItemChanged.connect(lambda item, _old: self._show(item))
        self.files = QTableWidget(0, 3)
        self.files.setHorizontalHeaderLabels([tr("Name"), tr("Folder"), tr("Where")])
        self.files.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.files.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.files.verticalHeader().setVisible(False)
        self.files.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.files.horizontalHeader().setStretchLastSection(True)
        self.files.setSortingEnabled(True)
        self.files.doubleClicked.connect(lambda _i: self.go_to_selected())
        split.addWidget(self.tags)
        split.addWidget(self.files)
        split.setSizes([200, 620])
        layout = QVBoxLayout(self)
        layout.addWidget(split, 1)
        row = QHBoxLayout()
        self.note = QLabel("")
        go = QPushButton(tr("Go to File"))
        go.clicked.connect(self.go_to_selected)
        untag = QPushButton(tr("Remove Tag"))
        untag.clicked.connect(self.untag_selected)
        close = QPushButton(tr("Close"))
        close.clicked.connect(self.close)
        row.addWidget(self.note, 1)
        row.addWidget(go)
        row.addWidget(untag)
        row.addWidget(close)
        layout.addLayout(row)
        add_close_corner(self)
        self.reload()

    def reload(self) -> None:
        current = self.tags.currentItem().text() if self.tags.currentItem() else None
        self.tags.clear()
        store = T.store()
        for tag in store.tags():
            item = QListWidgetItem(_dot_icon(tag.colour), tag.name)
            item.setData(Qt.ItemDataRole.UserRole, tag.name)
            item.setToolTip(tr("{n} files").format(n=len(store.items_with(tag.name))))
            self.tags.addItem(item)
        if current:
            self.select_tag(current)
        elif self.tags.count():
            self.tags.setCurrentRow(0)

    def select_tag(self, name: str) -> None:
        for row in range(self.tags.count()):
            if self.tags.item(row).data(Qt.ItemDataRole.UserRole) == name:
                self.tags.setCurrentRow(row)
                self._show(self.tags.item(row))
                return

    def _show(self, item) -> None:
        self.files.setSortingEnabled(False)
        self._entries = T.store().items_with(item.data(Qt.ItemDataRole.UserRole)) if item else []
        self.files.setRowCount(len(self._entries))
        for row, entry in enumerate(self._entries):
            name = QTableWidgetItem(posixpath.basename(entry.path.replace("\\", "/")))
            name.setData(Qt.ItemDataRole.UserRole, row)
            folder = QTableWidgetItem(posixpath.dirname(entry.path.replace("\\", "/")) or "/")
            where = QTableWidgetItem(entry.backend_name + (f" ({entry.profile_name})" if entry.profile_name else ""))
            for col, cell in enumerate((name, folder, where)):
                self.files.setItem(row, col, cell)
        self.files.setSortingEnabled(True)
        self.files.resizeColumnsToContents()
        self.note.setText(tr("{n} files").format(n=len(self._entries)))

    def _selected(self) -> list[T.TaggedFile]:
        rows = sorted({i.row() for i in self.files.selectedIndexes()})
        return [self._entries[self.files.item(r, 0).data(Qt.ItemDataRole.UserRole)] for r in rows]

    def go_to_selected(self) -> None:
        for entry in self._selected()[:1]:
            if self._go_to is not None:
                self._go_to(entry)

    def untag_selected(self) -> None:
        tag = self.tags.currentItem()
        if tag is None:
            return
        for entry in self._selected():
            T.store().untag(entry.backend_name, entry.path, tag.data(Qt.ItemDataRole.UserRole))
        self._show(tag)

