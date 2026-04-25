"""Bookmark editor — name, path, and SVG icon picker."""
from __future__ import annotations

from PyQt6.QtCore import QSize, Qt
from PyQt6.QtWidgets import (
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

from core.bookmarks import Bookmark
from ui.icon_provider import bookmark_icon_names, icon, has_icon


class _IconGridPicker(QWidget):
    """Scrollable grid of icon buttons. Radio-like — exactly one is
    checked at a time. ``selected_name`` is the currently-chosen
    icon's name.

    Built from :func:`ui.icon_provider.bookmark_icon_names` so new
    icons added to the provider automatically show up in the
    picker without dialog changes.
    """

    def __init__(self, initial: str = "bookmark",
                 columns: int = 8, parent=None) -> None:
        super().__init__(parent)
        self._columns = columns
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
            btn.setIcon(icon(name))
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

    def _on_pick(self, name: str) -> None:
        self.selected_name = name
        self._update_check_state()

    def _update_check_state(self) -> None:
        for name, btn in self._buttons.items():
            btn.setChecked(name == self.selected_name)


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
        self, bookmark: Bookmark | None = None,
        *, parent=None,
    ) -> None:
        super().__init__(parent)
        self._bookmark = bookmark or Bookmark(name="", path="")
        self._is_new = bookmark is None
        self.setWindowTitle(
            "New Bookmark" if self._is_new else "Edit Bookmark",
        )
        self.resize(540, 420)
        self._build_ui()

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
        backend_label.setStyleSheet("color: #888;")
        form.addRow("Backend:", backend_label)
        root.addLayout(form)

        root.addWidget(QLabel("Icon:", self))
        self._picker = _IconGridPicker(self._bookmark.icon_name, parent=self)
        root.addWidget(self._picker, stretch=1)

        row = QHBoxLayout()
        row.addStretch(1)
        btns = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok
            | QDialogButtonBox.StandardButton.Cancel,
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
        )


__all__ = ["BookmarkEditDialog"]
