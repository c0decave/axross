"""Bookmark editor — name, path, and SVG icon picker."""

from __future__ import annotations

from PyQt6.QtCore import QSize, Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from core.bookmarks import Bookmark, BookmarkGroup
from ui.close_corner import add_close_corner
from ui.icon_provider import BOOKMARK_COLORS, bookmark_icon_names, icon


class _IconGridPicker(QWidget):
    """Scrollable grid of icon buttons. Radio-like — exactly one is
    checked at a time. ``selected_name`` is the currently-chosen
    icon's name.

    Built from :func:`ui.icon_provider.bookmark_icon_names` so new
    icons added to the provider automatically show up in the
    picker without dialog changes.
    """

    def __init__(
        self, initial: str = "bookmark", columns: int = 8, parent=None, color: str = ""
    ) -> None:
        super().__init__(parent)
        self._columns = columns
        self._color = color
        self._buttons: dict[str, QPushButton] = {}
        # The initial value must also appear in the grid's own list
        # — the grid only shows ``bookmark_icon_names()``, which is
        # a strict subset of ``ICONS``. If the caller passed a
        # toolbar-verb icon name (say "split-h") it'd never match
        # a grid button and the dialog would look empty-selected.
        # Coerce to the default so the picker always has a visibly
        # checked button.
        if initial not in bookmark_icon_names():
            initial = "bookmark"
        self.selected_name: str = initial
        self._build_ui()
        self._update_check_state()

    def _build_ui(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff,
        )
        container = QWidget(scroll)
        grid = QGridLayout(container)
        grid.setSpacing(4)
        grid.setContentsMargins(6, 6, 6, 6)
        names = bookmark_icon_names()
        for idx, name in enumerate(names):
            btn = QPushButton(container)
            btn.setCheckable(True)
            btn.setIcon(icon(name, 32, self._color))
            btn.setIconSize(QSize(28, 28))
            btn.setFixedSize(QSize(40, 40))
            btn.setToolTip(name)
            btn.clicked.connect(lambda _checked, n=name: self._on_pick(n))
            row, col = divmod(idx, self._columns)
            grid.addWidget(btn, row, col)
            self._buttons[name] = btn
        container.setLayout(grid)
        scroll.setWidget(container)
        outer.addWidget(scroll)

    def set_color(self, color: str) -> None:
        """Preview every icon in *color* ("" = each icon's own colour)."""
        self._color = color
        for name, btn in self._buttons.items():
            btn.setIcon(icon(name, 32, color))

    def _on_pick(self, name: str) -> None:
        self.selected_name = name
        self._update_check_state()

    def _update_check_state(self) -> None:
        for name, btn in self._buttons.items():
            btn.setChecked(name == self.selected_name)


class _ColorRow(QWidget):
    """"None" plus one swatch per palette colour; exactly one is checked.
    ``selected_color`` is ``""`` (the icon's own colour) or ``#rrggbb``."""

    changed = pyqtSignal(str)

    def __init__(self, initial: str = "", parent=None) -> None:
        super().__init__(parent)
        self.selected_color = initial if initial in {h for _n, h in BOOKMARK_COLORS} else ""
        self._buttons: dict[str, QPushButton] = {}
        row = QHBoxLayout(self)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(4)
        none = QPushButton("None", self)
        none.setCheckable(True)
        none.setToolTip("Use the icon's own colour")
        none.clicked.connect(lambda _c=False: self._pick(""))
        row.addWidget(none)
        self._buttons[""] = none
        for name, hexv in BOOKMARK_COLORS:
            btn = QPushButton(self)
            btn.setCheckable(True)
            btn.setFixedSize(QSize(24, 24))
            btn.setToolTip(name)
            btn.setAccessibleName(name)
            btn.setObjectName(f"axSwatch_{name}")
            btn.setStyleSheet(
                f"QPushButton {{ background-color: {hexv}; border: 2px solid transparent; "
                f"border-radius: 4px; }} QPushButton:checked {{ border-color: palette(text); }}"
            )
            btn.clicked.connect(lambda _c=False, h=hexv: self._pick(h))
            row.addWidget(btn)
            self._buttons[hexv] = btn
        row.addStretch(1)
        self._sync()

    def _pick(self, color: str) -> None:
        self.selected_color = color
        self._sync()
        self.changed.emit(color)

    def _sync(self) -> None:
        for hexv, btn in self._buttons.items():
            btn.setChecked(hexv == self.selected_color)


class BookmarkEditDialog(QDialog):
    """Edit or create a bookmark — name, path (read-only when the
    bookmark already exists to prevent breakage; editable otherwise),
    and icon via the grid picker.

    Construct with ``bookmark=`` to edit; omit for a new entry.
    ``allow_path_edit=False`` is the default for existing bookmarks
    so the user doesn't silently detach an existing navigation
    from its sidebar entry.
    """

    def __init__(
        self,
        bookmark: Bookmark | None = None,
        *,
        parent=None,
        groups: list[tuple[int, BookmarkGroup]] | None = None,
        current_group: BookmarkGroup | None = None,
        new: bool = False,
    ) -> None:
        super().__init__(parent)
        self._bookmark = bookmark or Bookmark(name="", path="")
        self._is_new = bookmark is None or new
        self._groups = groups
        self._current_group = current_group
        self.setWindowTitle(
            "New Bookmark" if self._is_new else "Edit Bookmark",
        )
        self.resize(540, 420)
        self._build_ui()
        add_close_corner(self)

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)

        form = QFormLayout()
        self._name_edit = QLineEdit(self._bookmark.name, self)
        form.addRow("Name:", self._name_edit)
        self._path_edit = QLineEdit(self._bookmark.path, self)
        # Path is always editable — user asked for this explicitly.
        # Previously read-only for existing bookmarks under the
        # theory that letting the path change detaches the sidebar
        # entry from its navigation target. In practice that's a
        # legitimate flow (rename a target folder, relocate a
        # server's home, fix a typo). The bookmark is just a
        # (name, path, icon) tuple; any of the three should be
        # editable.
        form.addRow("Path:", self._path_edit)
        backend_label = QLabel(self._bookmark.backend_name or "Local", self)
        backend_label.setProperty("role", "muted")
        form.addRow("Backend:", backend_label)
        if self._groups is not None:
            self._group_combo = QComboBox(self)
            self._group_options: list[BookmarkGroup | None] = [None]
            self._group_combo.addItem("(top level)")
            for depth, group in self._groups:
                self._group_options.append(group)
                self._group_combo.addItem("    " * depth + group.name)
            for i, option in enumerate(self._group_options):
                if option is self._current_group:
                    self._group_combo.setCurrentIndex(i)
            form.addRow("Group:", self._group_combo)
        root.addLayout(form)

        root.addWidget(QLabel("Color:", self))
        self._colors = _ColorRow(self._bookmark.color, self)
        root.addWidget(self._colors)

        root.addWidget(QLabel("Icon:", self))
        self._picker = _IconGridPicker(
            self._bookmark.icon_name, parent=self, color=self._colors.selected_color
        )
        self._colors.changed.connect(self._picker.set_color)
        root.addWidget(self._picker, stretch=1)

        row = QHBoxLayout()
        row.addStretch(1)
        btns = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel,
            parent=self,
        )
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)
        row.addWidget(btns)
        root.addLayout(row)

    def result_bookmark(self) -> Bookmark:
        """Return a new Bookmark carrying the dialog's current
        field values. Called by the caller on Accepted."""
        return Bookmark(
            name=self._name_edit.text().strip() or self._bookmark.name,
            path=self._path_edit.text() or self._bookmark.path,
            backend_name=self._bookmark.backend_name,
            profile_name=self._bookmark.profile_name,
            icon_name=self._picker.selected_name,
            color=self._colors.selected_color,
        )

    def result_group(self) -> BookmarkGroup | None:
        """The group chosen in the dialog (``None`` = top level, or no
        group chooser was offered)."""
        if self._groups is None:
            return self._current_group
        return self._group_options[self._group_combo.currentIndex()]


class GroupEditDialog(QDialog):
    """Name, colour and icon of a bookmark group."""

    def __init__(self, group: BookmarkGroup | None = None, *, parent=None) -> None:
        super().__init__(parent)
        self._group = group or BookmarkGroup(name="")
        self.setWindowTitle("New Group" if group is None else "Edit Group")
        self.resize(540, 420)
        root = QVBoxLayout(self)
        form = QFormLayout()
        self._name_edit = QLineEdit(self._group.name, self)
        form.addRow("Name:", self._name_edit)
        root.addLayout(form)
        root.addWidget(QLabel("Color:", self))
        self._colors = _ColorRow(self._group.color, self)
        root.addWidget(self._colors)
        root.addWidget(QLabel("Icon:", self))
        self._picker = _IconGridPicker(
            self._group.icon_name, parent=self, color=self._colors.selected_color
        )
        self._colors.changed.connect(self._picker.set_color)
        root.addWidget(self._picker, stretch=1)
        btns = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel,
            parent=self,
        )
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)
        root.addWidget(btns)
        add_close_corner(self)

    def result(self) -> tuple[str, str, str]:
        """``(name, icon_name, color)``; an empty name keeps the old one
        (or "New Group")."""
        name = self._name_edit.text().strip() or self._group.name or "New Group"
        return name, self._picker.selected_name, self._colors.selected_color


__all__ = ["BookmarkEditDialog", "GroupEditDialog"]
