"""Bookmark editor — name, path, and SVG icon picker."""

from __future__ import annotations

import dataclasses

from PyQt6.QtCore import QSize, Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from core.bookmarks import (
    DEFAULT_SSH_PORT,
    LOCAL_SHELL,
    Bookmark,
    BookmarkGroup,
    host_address,
    host_bookmark_problem,
)
from core.i18n import tr
from ui.close_corner import add_close_corner
from ui.icon_provider import BOOKMARK_COLORS, bookmark_icon_names, has_icon, icon


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
        # The grid shows ``bookmark_icon_names()``, a strict subset of
        # ``ICONS``. An icon the provider knows but the grid does not list
        # (a Smart Folder's "find-index") gets a button of its own in
        # front, so it stays chosen and checked: coerced to the default, a
        # mere rename gave the entry a plain bookmark's icon. A name the
        # provider does not know at all falls back to the default.
        self._names = bookmark_icon_names()
        if initial not in self._names:
            if has_icon(initial):
                self._names = [initial, *self._names]
            else:
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
        for idx, name in enumerate(self._names):
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
        terminal_profiles: list[str] | None = None,
    ) -> None:
        super().__init__(parent)
        self._bookmark = bookmark or Bookmark(name="", path="")
        self._is_new = bookmark is None or new
        self._groups = groups
        self._current_group = current_group
        # A terminal bookmark chooses its connection: a local shell or one
        # of these profiles (names only - the profile keeps the secrets).
        self._terminal_profiles = list(terminal_profiles or [])
        if self._bookmark.is_terminal:
            title = tr("New Terminal Bookmark") if self._is_new else tr("Edit Terminal Bookmark")
        else:
            title = "New Bookmark" if self._is_new else "Edit Bookmark"
        self.setWindowTitle(title)
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
        if self._bookmark.is_smart_folder:
            # A Smart Folder's "path" is its key in the store, not a folder.
            from core.file_search import describe_saved_search

            self._path_edit.setText(describe_saved_search(self._bookmark.search))
            self._path_edit.setReadOnly(True)
            form.addRow("Search:", self._path_edit)
            backend_label = QLabel(self._bookmark.backend_name or "Local", self)
            backend_label.setProperty("role", "muted")
            form.addRow("Backend:", backend_label)
        elif self._bookmark.is_terminal:
            self._path_edit.setPlaceholderText(tr("optional: the shell starts in this folder"))
            form.addRow(tr("Working Folder:"), self._path_edit)
            self._connection_combo = QComboBox(self)
            self._connection_combo.addItem(tr("Local Shell"), LOCAL_SHELL)
            # A bare host: its own fields below, no profile. Told apart by its
            # index, not its data - a profile may have any name.
            self.host_choice_index = self._connection_combo.count()
            self._connection_combo.addItem(tr("SSH Host (no profile)"), "")
            for name in self._terminal_profiles:
                self._connection_combo.addItem(name, name)
            form.addRow(tr("Connection:"), self._connection_combo)
            self._host_box = self._build_host_box()
            form.addRow(self._host_box)
            if self._bookmark.is_host_terminal:
                self._connection_combo.setCurrentIndex(self.host_choice_index)
            else:
                current = self._bookmark.profile_name or LOCAL_SHELL
                index = self._connection_combo.findData(current)
                if index < 0 or index == self.host_choice_index:
                    # A profile renamed or deleted since: kept visible, never
                    # quietly replaced by another connection.
                    self._connection_combo.addItem(
                        tr("{name} (missing)").format(name=current), current)
                    index = self._connection_combo.count() - 1
                self._connection_combo.setCurrentIndex(index)
            self._connection_combo.currentIndexChanged.connect(self._update_host_box)
            self._update_host_box()
        else:
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

    # -- a terminal bookmark on a bare host ------------------------------------
    def _build_host_box(self) -> QWidget:
        """Host, port, user and key file of a host terminal bookmark. No
        password field: it is asked for when the bookmark connects."""
        import getpass

        box = QWidget(self)
        form = QFormLayout(box)
        form.setContentsMargins(0, 0, 0, 0)
        bookmark = self._bookmark
        self._host_edit = QLineEdit(bookmark.host, box)
        self._host_edit.setPlaceholderText(tr("host name or IP address"))
        form.addRow(tr("Host:"), self._host_edit)
        self._port_spin = QSpinBox(box)
        self._port_spin.setRange(1, 65535)
        self._port_spin.setValue(bookmark.port if bookmark.is_host_terminal else DEFAULT_SSH_PORT)
        form.addRow(tr("Port:"), self._port_spin)
        user = bookmark.username
        if not bookmark.is_host_terminal:
            try:
                user = getpass.getuser()
            except Exception:  # noqa: BLE001 - no passwd entry: leave it empty
                user = ""
        self._user_edit = QLineEdit(user, box)
        form.addRow(tr("User:"), self._user_edit)
        key_row = QHBoxLayout()
        self._key_edit = QLineEdit(bookmark.key_file, box)
        self._key_edit.setPlaceholderText(tr("optional: else ssh-agent, else a password prompt"))
        key_row.addWidget(self._key_edit, stretch=1)
        browse = QPushButton(tr("Browse…"), box)
        browse.clicked.connect(self._browse_key_file)
        key_row.addWidget(browse)
        form.addRow(tr("Key File:"), key_row)
        note = QLabel(tr("No password is stored: it is asked for when the bookmark connects."),
                      box)
        note.setProperty("role", "muted")
        note.setWordWrap(True)
        form.addRow(note)
        return box

    def _browse_key_file(self) -> None:
        import os

        start = self._key_edit.text().strip() or os.path.expanduser("~/.ssh")
        path, _filter = QFileDialog.getOpenFileName(self, tr("Key File"), start)
        if path:
            self._key_edit.setText(path)

    def _host_chosen(self) -> bool:
        return (
            self._bookmark.is_terminal
            and self._connection_combo.currentIndex() == self.host_choice_index
        )

    def _update_host_box(self, *_args) -> None:
        self._host_box.setVisible(self._host_chosen())

    def accept(self) -> None:  # noqa: D102 - Qt override: a host must be usable
        if self._bookmark.is_terminal and self._host_chosen():
            problem = host_bookmark_problem(self.result_bookmark())
            if problem:
                # A fixed first line: Qt reads markup there as rich text,
                # and the problem quotes what was typed.
                QMessageBox.warning(self, self.windowTitle(),
                                    tr("This host cannot be used:") + "\n\n" + problem)
                return
        super().accept()

    def result_bookmark(self) -> Bookmark:
        """Return a new Bookmark carrying the dialog's current
        field values. Called by the caller on Accepted. What the dialog
        does not show (kind, creation time, a Smart Folder's search) is
        carried over; a Smart Folder keeps its store key as path."""
        if self._bookmark.is_terminal and self._host_chosen():
            host = self._host_edit.text().strip()
            port = self._port_spin.value()
            user = self._user_edit.text().strip()
            folder = self._path_edit.text().strip()
            address = host_address(host, port, user)
            return dataclasses.replace(
                self._bookmark,
                name=(self._name_edit.text().strip()
                      or (f"{address}: {folder}" if folder else address)),
                path=folder,
                backend_name=address,
                profile_name=address,  # see core.bookmarks.Bookmark: never ""
                host=host,
                port=port,
                username=user,
                key_file=self._key_edit.text().strip(),
                icon_name=self._picker.selected_name,
                color=self._colors.selected_color,
            )
        if self._bookmark.is_terminal:
            profile = self._connection_combo.currentData() or LOCAL_SHELL
            return dataclasses.replace(
                self._bookmark,
                name=(
                    self._name_edit.text().strip()
                    or self._bookmark.name
                    or self._connection_combo.currentText()
                ),
                # Empty is a choice here: no working folder.
                path=self._path_edit.text().strip(),
                backend_name="Local" if profile == LOCAL_SHELL else profile,
                profile_name=profile,
                host="",
                port=DEFAULT_SSH_PORT,
                username="",
                key_file="",
                icon_name=self._picker.selected_name,
                color=self._colors.selected_color,
            )
        smart = self._bookmark.is_smart_folder
        return dataclasses.replace(
            self._bookmark,
            name=self._name_edit.text().strip() or self._bookmark.name,
            path=self._bookmark.path if smart else (self._path_edit.text() or self._bookmark.path),
            icon_name=self._picker.selected_name,
            color=self._colors.selected_color,
            search=dict(self._bookmark.search),
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
