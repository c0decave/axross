"""Apply Profile…: choose an agent profile (core.agent_profiles) for an
Agent tab and see first what it gives the tab - within Agent Settings >
Access - what the ceiling cuts and which MCP servers are missing."""

from __future__ import annotations

from typing import Callable

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QPlainTextEdit,
    QVBoxLayout,
)

from core import agent_profiles as AP
from core.i18n import tr
from ui.close_corner import add_close_corner


def profile_label(profile: AP.AgentProfile) -> str:
    """How menus and lists name a profile: presets carry "(preset)"."""
    return tr("{name} (preset)").format(name=profile.name) if profile.preset else profile.name


class ProfilePickerDialog(QDialog):
    """A list of the profiles, the chosen one's description and what it
    would give the tab; OK applies (the caller's *on_accept*)."""

    def __init__(self, parent, title: str, profiles: list[AP.AgentProfile],
                 resolve: Callable[[AP.AgentProfile], AP.Resolution], *,
                 conversation: bool = False) -> None:
        super().__init__(parent)
        self.setWindowTitle(tr("Apply Profile to {title}").format(title=title))
        self.resize(720, 460)
        self._profiles = list(profiles)
        self._resolve = resolve
        self.list = QListWidget()
        for profile in self._profiles:
            item = QListWidgetItem(profile_label(profile))
            item.setData(Qt.ItemDataRole.UserRole, profile.name)
            item.setToolTip(profile.description)
            self.list.addItem(item)
        self.description = QLabel()
        self.description.setWordWrap(True)
        self.description.setTextFormat(Qt.TextFormat.PlainText)
        self.preview = QPlainTextEdit()
        self.preview.setReadOnly(True)
        self.note = QLabel(
            tr("The tab's model, prompt profile, mode, sandbox, tools and access change; its "
               "folder, extra folders and conversation stay.") if conversation else
            tr("The tab's model, prompt profile, mode, sandbox, tools and access change; its "
               "folder stays."))
        self.note.setWordWrap(True)
        self.buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        self.buttons.button(QDialogButtonBox.StandardButton.Ok).setText(tr("Apply"))
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        right = QVBoxLayout()
        right.addWidget(self.description)
        right.addWidget(QLabel(tr("The tab gets (within Agent Settings > Access):")))
        right.addWidget(self.preview, 1)
        top = QHBoxLayout()
        top.addWidget(self.list, 1)
        top.addLayout(right, 2)
        layout = QVBoxLayout(self)
        layout.addLayout(top, 1)
        layout.addWidget(self.note)
        layout.addWidget(self.buttons)
        self.list.currentRowChanged.connect(self._show)
        if self._profiles:
            self.list.setCurrentRow(0)
        else:
            self._show(-1)
        add_close_corner(self)

    def _show(self, row: int) -> None:
        ok = self.buttons.button(QDialogButtonBox.StandardButton.Ok)
        if not 0 <= row < len(self._profiles):
            self.description.clear()
            self.preview.clear()
            ok.setEnabled(False)
            return
        profile = self._profiles[row]
        self.description.setText(profile.description)
        self.preview.setPlainText("\n".join(AP.summary_lines(profile,
                                                             self._resolve(profile))))
        ok.setEnabled(True)

    def select(self, name: str) -> bool:
        for row, profile in enumerate(self._profiles):
            if profile.name == name:
                self.list.setCurrentRow(row)
                return True
        return False

    def chosen(self) -> AP.AgentProfile | None:
        row = self.list.currentRow()
        return self._profiles[row] if 0 <= row < len(self._profiles) else None
