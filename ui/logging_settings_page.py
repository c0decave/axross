"""Edit > Settings… > Logging: what axross writes to its log, and how much.

* **Overall level** - DEBUG, INFO (the default), WARNING or ERROR.
* **Areas** - a level per area (core.log_areas): *Inherit* (the parent
  area's level, at the top the overall level), a level, or *Off*. A tree:
  Protocols holds one entry per protocol family, Third-Party Libraries one
  per library family (WARNING by default, so paramiko, urllib3, Pillow and
  asyncio stay quiet).
* **Log file** - where it is, the size at which it rolls over, how many
  rotated files are kept.
* **Log to terminal** - also write to stderr.
* **Collapse repeated messages** - an identical message within the window
  is written once, then "Last message repeated K more times".
* **Reset to Defaults** - shows the defaults; OK or Apply saves them.

Saved to ``~/.config/axross/logging.json`` (core.log_config) and applied at
once: the loggers' levels, the file's size and count, the terminal, the
collapse. ``--debug`` and ``--verbose`` lower the levels for the run they
start; the page says so while one is in force.
"""

from __future__ import annotations

import logging
from pathlib import Path

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSpinBox,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core import log_areas as LA
from core import log_config as LC
from core.i18n import tr
from ui.column_fit import ColumnFitter

log = logging.getLogger(__name__)

TITLE = "Logging"
KEYWORDS = ("logging", "log", "log file", "debug", "verbose", "level", "areas", "terminal",
            "stderr", "rotation", "repeated", "third-party", "paramiko")
CHOICE_LABELS = {"inherit": "Inherit", "DEBUG": "DEBUG", "INFO": "INFO", "WARNING": "WARNING",
                 "ERROR": "ERROR", "off": "Off"}


def _note(text: str) -> QLabel:
    label = QLabel(text)
    label.setWordWrap(True)
    label.setProperty("role", "muted")
    label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    return label


class LoggingPage(QWidget):
    """The Logging page (see the module docstring)."""

    TITLE = TITLE

    def __init__(self, parent: QWidget | None = None, *, path: Path | None = None,
                 log_file: Path | None = None) -> None:
        super().__init__(parent)
        #: The store (None: core.log_config.settings_file()).
        self._path = path
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self.floor_note = _note("")
        self.floor_note.hide()
        layout.addWidget(self.floor_note)

        form = QFormLayout()
        self.level_combo = QComboBox()
        for level in LC.LEVELS:
            self.level_combo.addItem(level, level)
        self.level_combo.setToolTip(tr("The level of every area set to Inherit"))
        form.addRow(tr("Overall level"), self.level_combo)
        layout.addLayout(form)

        areas = QGroupBox(tr("Areas"))
        areas_layout = QVBoxLayout(areas)
        areas_layout.addWidget(_note(tr(
            "Inherit takes the level of the area above, at the top the overall level. "
            "Off writes nothing of that area. Third-party libraries are quiet (WARNING) "
            "by default.")))
        self.area_tree = QTreeWidget()
        self.area_tree.setColumnCount(2)
        self.area_tree.setHeaderLabels([tr("Area"), tr("Level")])
        self.area_tree.setRootIsDecorated(True)
        self.area_tree.setUniformRowHeights(True)
        # Every divider draggable (ui.column_fit): the area takes the free
        # width, the level column its content.
        ColumnFitter(self.area_tree, fill=0, keep=(1,))
        self.area_combos: dict[str, QComboBox] = {}
        items: dict[str, QTreeWidgetItem] = {}
        for area in LA.AREAS:
            parent_item = items.get(area.parent) if area.parent else None
            item = QTreeWidgetItem([tr(area.label), ""])
            item.setData(0, Qt.ItemDataRole.UserRole, area.id)
            if parent_item is None:
                self.area_tree.addTopLevelItem(item)
            else:
                parent_item.addChild(item)
            items[area.id] = item
            combo = QComboBox()
            for choice in LC.AREA_CHOICES:
                combo.addItem(tr(CHOICE_LABELS[choice]), choice)
            self.area_tree.setItemWidget(item, 1, combo)
            self.area_combos[area.id] = combo
        self.area_tree.expandAll()
        self.area_tree.setMinimumHeight(260)
        areas_layout.addWidget(self.area_tree)
        layout.addWidget(areas, 1)

        file_box = QGroupBox(tr("Log file"))
        file_form = QFormLayout(file_box)
        where = log_file or _running_log_file()
        self.file_label = _note(str(where) if where else tr("(no log file in this run)"))
        file_form.addRow(tr("File"), self.file_label)
        self.file_size_spin = QSpinBox()
        self.file_size_spin.setRange(*LC.FILE_MIB_RANGE)
        self.file_size_spin.setSuffix(" MiB")
        file_form.addRow(tr("Roll over at"), self.file_size_spin)
        self.backups_spin = QSpinBox()
        self.backups_spin.setRange(*LC.BACKUPS_RANGE)
        file_form.addRow(tr("Rotated files kept"), self.backups_spin)
        layout.addWidget(file_box)

        self.terminal_check = QCheckBox(tr("Log to terminal (stderr)"))
        layout.addWidget(self.terminal_check)
        repeats = QHBoxLayout()
        self.collapse_check = QCheckBox(tr("Collapse repeated messages within"))
        self.collapse_check.setToolTip(tr(
            "An identical message is written once per window; the count follows as "
            "\"Last message repeated K more times\"."))
        self.window_spin = QSpinBox()
        self.window_spin.setRange(*LC.WINDOW_RANGE)
        self.window_spin.setSuffix(" s")
        repeats.addWidget(self.collapse_check)
        repeats.addWidget(self.window_spin)
        repeats.addStretch(1)
        layout.addLayout(repeats)
        self.collapse_check.toggled.connect(self.window_spin.setEnabled)

        buttons = QHBoxLayout()
        self.reset_button = QPushButton(tr("Reset to Defaults"))
        self.reset_button.clicked.connect(self.reset_to_defaults)
        buttons.addWidget(self.reset_button)
        buttons.addStretch(1)
        layout.addLayout(buttons)
        layout.addWidget(_note(tr(
            "Applied at once and kept for the next start. --debug and --verbose on the "
            "command line lower the levels for the run they start.")))

        self._baseline = LC.LogSettings.load(self._path)
        self._show(self._baseline)
        self._show_floor()

    # -- values ----------------------------------------------------------------

    def _show(self, settings: LC.LogSettings) -> None:
        self.level_combo.setCurrentIndex(self.level_combo.findData(settings.level))
        for area_id, combo in self.area_combos.items():
            combo.setCurrentIndex(combo.findData(settings.area_choice(area_id)))
        self.file_size_spin.setValue(settings.file_max_mib)
        self.backups_spin.setValue(settings.file_backups)
        self.terminal_check.setChecked(settings.terminal)
        self.collapse_check.setChecked(settings.collapse_repeats)
        self.window_spin.setValue(settings.repeat_window)
        self.window_spin.setEnabled(settings.collapse_repeats)

    def _show_floor(self) -> None:
        floor = LC.run_floor()
        if floor is None:
            self.floor_note.hide()
            return
        flag = "--debug" if floor == logging.DEBUG else "--verbose"
        self.floor_note.setText(tr(
            "This run was started with {flag}: every area logs at least {level} until "
            "axross exits, whatever is chosen here.").format(
                flag=flag, level=logging.getLevelName(floor)))
        self.floor_note.show()

    def values(self) -> LC.LogSettings:
        out = LC.LogSettings()
        out.set("level", self.level_combo.currentData())
        for area_id, combo in self.area_combos.items():
            out.set_area(area_id, combo.currentData())
        out.set("file_max_mib", self.file_size_spin.value())
        out.set("file_backups", self.backups_spin.value())
        out.set("terminal", self.terminal_check.isChecked())
        out.set("collapse_repeats", self.collapse_check.isChecked())
        out.set("repeat_window", self.window_spin.value())
        return out

    def reset_to_defaults(self) -> None:
        self._show(LC.LogSettings())

    # -- the page protocol (ui.settings_dialog) ----------------------------------

    def is_dirty(self) -> bool:
        return self.values() != self._baseline

    def problems(self) -> list[str]:
        return []

    def save(self) -> bool:
        settings = self.values()
        settings.save(self._path)  # OSError reaches the dialog, which names it
        LC.apply(settings)
        self._baseline = settings
        return True


def _running_log_file() -> Path | None:
    handler = LC.file_handler()
    return Path(handler.baseFilename) if handler is not None else None


__all__ = ["CHOICE_LABELS", "KEYWORDS", "TITLE", "LoggingPage"]
