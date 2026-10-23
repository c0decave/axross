"""Agent dock > Topics ▸ + New Topic… / Edit or Delete My Topics…: the
user's own agent tasks ("work prompts" in the code and the file name).

An own topic (core.agent_topics.Topic) has a title,
a slash command, the task text (``{folder}`` and ``{backend}`` are filled in
when it is used), the protection mode it suggests, what it needs switched on
and the tool groups it ticks. Stored in
``~/.config/axross/agent/work_prompts.json``.
"""

from __future__ import annotations

from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QFormLayout,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QVBoxLayout,
    QWidget,
)

from core import agent_topics as AT
from core.agent_settings import OFFERED_GROUPS
from core.i18n import tr
from ui.close_corner import add_close_corner

_NEED_LABELS = {
    "exec": "Remote commands",
    "remote": "Remote files",
    "write": "Changes to files",
}


class WorkPromptsDialog(QDialog):
    YES = QMessageBox.StandardButton.Yes

    def __init__(self, parent=None, *, task: str = "", new: bool = False) -> None:
        """*new* (or a *task* to start from) opens an empty form; otherwise
        the first stored topic is shown."""
        super().__init__(parent)
        self.setWindowTitle(tr("My Topics"))
        self.resize(860, 560)
        self._topics: list[AT.Topic] = AT.load_user_topics()
        self._row = -1  # the list row in the form; -1 = a new, unsaved prompt
        self._build()
        add_close_corner(self)
        self._fill_list()
        if task or new:
            self.new_prompt()
            self.task_edit.setPlainText(task)
        elif self._topics:
            self.list.setCurrentRow(0)
        else:
            self.new_prompt()

    def _build(self) -> None:
        root = QVBoxLayout(self)
        split = QSplitter()
        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 0, 0)
        self.list = QListWidget()
        self.list.currentRowChanged.connect(self._show_row)
        left_layout.addWidget(self.list)
        row = QHBoxLayout()
        new = QPushButton(tr("New Topic"))
        new.clicked.connect(self.new_prompt)
        self.delete_button = QPushButton(tr("Delete"))
        self.delete_button.clicked.connect(self.delete_prompt)
        row.addWidget(new)
        row.addWidget(self.delete_button)
        left_layout.addLayout(row)
        split.addWidget(left)

        right = QWidget()
        form = QFormLayout(right)
        self.title_edit = QLineEdit()
        self.title_edit.setMaxLength(AT.MAX_TITLE)
        self.command_edit = QLineEdit()
        self.command_edit.setPlaceholderText(tr("e.g. etc-review (empty: made from the title)"))
        self.description_edit = QLineEdit()
        self.description_edit.setMaxLength(AT.MAX_DESCRIPTION)
        self.task_edit = QPlainTextEdit()
        self.task_edit.setPlaceholderText(
            tr("What the agent should do. {folder} becomes the tab's folder, {backend} the "
               "remote connection of the active pane.")
        )
        self.mode_combo = QComboBox()
        self.mode_combo.addItem(tr("(keep the tab's mode)"), None)
        for mode in AT.TOPIC_MODES:
            self.mode_combo.addItem(mode.capitalize(), mode)
        needs = QHBoxLayout()
        self.need_checks: dict[str, QCheckBox] = {}
        for need in AT.NEEDS:
            box = QCheckBox(tr(_NEED_LABELS[need]))
            self.need_checks[need] = box
            needs.addWidget(box)
        needs.addStretch(1)
        groups = QGridLayout()
        self.group_checks: dict[str, QCheckBox] = {}
        for i, group in enumerate(OFFERED_GROUPS):
            box = QCheckBox(group)
            self.group_checks[group] = box
            groups.addWidget(box, i // 4, i % 4)
        form.addRow(tr("Title:"), self.title_edit)
        form.addRow(tr("Command: /"), self.command_edit)
        form.addRow(tr("Description:"), self.description_edit)
        form.addRow(tr("Prompt:"), self.task_edit)
        form.addRow(tr("Mode:"), self.mode_combo)
        form.addRow(tr("Needs:"), needs)
        form.addRow(tr("Tool groups:"), groups)
        split.addWidget(right)
        split.setSizes([260, 600])
        root.addWidget(split, 1)

        self.error_label = QLabel("")
        self.error_label.setWordWrap(True)
        self.error_label.setStyleSheet("color: #d03030;")
        root.addWidget(self.error_label)
        buttons = QHBoxLayout()
        buttons.addStretch(1)
        self.save_button = QPushButton(tr("Save"))
        self.save_button.setDefault(True)
        self.save_button.clicked.connect(self.save)
        close = QPushButton(tr("Close"))
        close.clicked.connect(self.close)
        buttons.addWidget(self.save_button)
        buttons.addWidget(close)
        root.addLayout(buttons)

    # -- list ------------------------------------------------------------------------------

    def _fill_list(self) -> None:
        self.list.blockSignals(True)
        self.list.clear()
        for topic in self._topics:
            self.list.addItem(f"{topic.title}   /{AT.command_of(topic)}")
        self.list.blockSignals(False)
        self.delete_button.setEnabled(bool(self._topics))

    def _show_row(self, row: int) -> None:
        if not 0 <= row < len(self._topics):
            return
        self._row = row
        topic = self._topics[row]
        self.title_edit.setText(topic.title)
        self.command_edit.setText(topic.command)
        self.description_edit.setText(topic.description)
        self.task_edit.setPlainText(topic.task)
        self.mode_combo.setCurrentIndex(max(0, self.mode_combo.findData(topic.mode)))
        for need, box in self.need_checks.items():
            box.setChecked(need in topic.needs)
        for group, box in self.group_checks.items():
            box.setChecked(group in topic.groups)
        self.error_label.setText("")

    def new_prompt(self) -> None:
        self._row = -1
        self.list.clearSelection()
        for edit in (self.title_edit, self.command_edit, self.description_edit):
            edit.clear()
        self.task_edit.clear()
        self.mode_combo.setCurrentIndex(0)
        for box in (*self.need_checks.values(), *self.group_checks.values()):
            box.setChecked(False)
        self.error_label.setText("")
        self.title_edit.setFocus()

    # -- store -----------------------------------------------------------------------------

    def _form_topic(self) -> AT.Topic:
        return AT.Topic(
            title=self.title_edit.text().strip(),
            task=self.task_edit.toPlainText().strip(),
            description=self.description_edit.text().strip(),
            mode=self.mode_combo.currentData(),
            needs=tuple(n for n, box in self.need_checks.items() if box.isChecked()),
            source="user",
            command=self.command_edit.text().strip().lstrip("/"),
            groups=tuple(g for g, box in self.group_checks.items() if box.isChecked()),
        )

    def save(self) -> bool:
        """Store the form as a new prompt or over the one shown. False (and
        the reason shown) when it is invalid."""
        topic = self._form_topic()
        # On top of what is stored now: a hand edit or another window may
        # have changed the file since this one read it.
        topics = AT.load_user_topics()
        original = self._topics[self._row] if 0 <= self._row < len(self._topics) else None
        if original is not None and original in topics:
            row = topics.index(original)
            topics[row] = topic
        else:  # new, or changed / removed elsewhere meanwhile: added, not lost
            topics.append(topic)
            row = len(topics) - 1
        try:
            AT.save_user_topics(topics)
        except (OSError, ValueError) as exc:
            self.error_label.setText(str(exc))
            return False
        self._topics = topics
        self._fill_list()
        self.list.setCurrentRow(row)
        self.error_label.setText("")
        return True

    def delete_prompt(self) -> None:
        if not 0 <= self._row < len(self._topics):
            return
        topic = self._topics[self._row]
        answer = QMessageBox.question(
            self, tr("My Topics"), tr("Delete the topic {title}?").format(title=topic.title),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        # Only this prompt goes; what was added elsewhere meanwhile stays.
        topics = [t for t in AT.load_user_topics() if t != topic]
        try:
            AT.save_user_topics(topics)
        except (OSError, ValueError) as exc:
            self.error_label.setText(str(exc))
            return
        self._topics = topics
        self._fill_list()
        if topics:
            self.list.setCurrentRow(0)
        else:
            self.new_prompt()
