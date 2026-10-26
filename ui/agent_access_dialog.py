"""What one Agent tab may reach (core.agent_access): an editor for the
tab's axross functions, network and folders, the tab's Access… dialog
around it, and the summary line the tab's button shows.

Agent Settings > Access is the ceiling: a function switched off there is
shown here but cannot be ticked, and the sandbox level decides which
network choices exist at all.
"""

from __future__ import annotations

import os

from PyQt6.QtCore import QEvent, Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core import agent_access as X
from core.agent_net import parse_host
from core.i18n import tr
from ui.close_corner import add_close_corner

FUNCTION_LABELS = {
    "remote_files": "Files of the remote connections open in the panes",
    "saved_profiles": "Saved connections the agent opens itself",
    "remote_commands": "Commands on remote hosts (SSH, WinRM, ...)",
    "mcp_servers": "Tools of further MCP servers",
    "extensions": "Tools of axross extensions",
}
NETWORK_LABELS = {
    "profile": "As the sandbox profile says (no sandbox: no limit)",
    "none": "None",
    "hosts": "Only these hosts",
    "all": "All hosts",
}


def summary(access: X.SessionAccess, folders) -> str:
    """One line for the tab's Access… button."""
    if not access.axross:
        functions = tr("axross functions: off")
    else:
        functions = tr("axross functions: {names}").format(
            names=", ".join(access.functions) if access.functions else tr("none"))
    if access.network == "hosts":
        count = len(access.hosts)
        network = (
            tr("network: only 1 host")
            if count == 1
            else tr("network: only {n} hosts").format(n=count)
        )
    else:
        network = tr("network: {mode}").format(mode=access.network)
    writable = sum(1 for _p, rw in folders if rw)
    folders_text = tr("folders: {n} ({rw} read-write)").format(n=len(folders), rw=writable)
    return " · ".join((functions, network, folders_text))


class AccessEditor(QWidget):
    """The three parts of a tab's access; :meth:`access` and :meth:`folders`
    read them back. Without *folders* the folder part is left out (an agent
    profile has no folders of its own)."""

    changed = pyqtSignal()

    def __init__(self, parent=None, *, folders: bool = True) -> None:
        super().__init__(parent)
        self._ceiling = None
        self._loading = False
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        functions = QGroupBox(tr("axross functions"))
        box = QVBoxLayout(functions)
        self.axross_check = QCheckBox(tr("Let the agent use axross functions"))
        self.axross_check.setToolTip(tr(
            "Tools axross runs itself, outside the agent's sandbox and with axross's rights: "
            "a way out of the sandbox, so only what is ticked here."))
        box.addWidget(self.axross_check)
        self.function_checks: dict[str, QCheckBox] = {}
        for name in X.FUNCTIONS:
            check = QCheckBox(tr(FUNCTION_LABELS[name]))
            check.setContentsMargins(18, 0, 0, 0)
            check.toggled.connect(self._emit)
            self.function_checks[name] = check
            box.addWidget(check)
        # Says why the boxes above are locked; hidden while they are not.
        self.functions_note = QLabel()
        self.functions_note.setWordWrap(True)
        self.functions_note.setContentsMargins(18, 0, 0, 0)
        self.functions_note.setEnabled(False)
        box.addWidget(self.functions_note)
        self.axross_check.toggled.connect(self._update)
        self.axross_check.toggled.connect(self._emit)
        layout.addWidget(functions)

        network = QGroupBox(tr("Network"))
        box = QVBoxLayout(network)
        self.network_combo = QComboBox()
        self.network_combo.currentIndexChanged.connect(self._update)
        self.network_combo.currentIndexChanged.connect(self._emit)
        box.addWidget(self.network_combo)
        self.hosts_list = QListWidget()
        self.hosts_list.setMaximumHeight(90)
        box.addWidget(self.hosts_list)
        row = QHBoxLayout()
        self.host_edit = QLineEdit()
        self.host_edit.setPlaceholderText("db.example:5432")
        # Enter adds the host and stays in the field (an event filter, not
        # returnPressed: that let the key go on to the dialog's OK button,
        # which closed the Access dialog after the first host).
        self.host_edit.installEventFilter(self)
        self.host_add = QPushButton(tr("Add host"))
        self.host_add.clicked.connect(self.add_host)
        self.host_remove = QPushButton(tr("Remove"))
        self.host_remove.clicked.connect(self.remove_host)
        row.addWidget(self.host_edit, 1)
        row.addWidget(self.host_add)
        row.addWidget(self.host_remove)
        box.addLayout(row)
        self.host_note = QLabel()
        self.host_note.setWordWrap(True)
        box.addWidget(self.host_note)
        layout.addWidget(network)

        folders_box = QGroupBox(tr("Folders"))
        if not folders:
            folders_box.hide()  # stays hidden once the layout takes it
        box = QVBoxLayout(folders_box)
        self.folders_table = QTableWidget(0, 2)
        self.folders_table.setHorizontalHeaderLabels([tr("Folder"), tr("Access")])
        self.folders_table.setColumnWidth(0, 330)
        self.folders_table.setMaximumHeight(120)
        box.addWidget(self.folders_table)
        row = QHBoxLayout()
        add = QPushButton(tr("Add folder…"))
        add.clicked.connect(lambda: self.add_folder())
        remove = QPushButton(tr("Remove"))
        remove.clicked.connect(self.remove_folder)
        row.addWidget(add)
        row.addWidget(remove)
        row.addStretch(1)
        box.addLayout(row)
        self.folder_note = QLabel()
        self.folder_note.setWordWrap(True)
        box.addWidget(self.folder_note)
        layout.addWidget(folders_box)

    # -- in and out ----------------------------------------------------------------

    def load(self, access: X.SessionAccess, folders, *, ceiling, sandbox) -> None:
        """Show *access* and *folders* (``(path, writable)``) for a tab whose
        Agent Settings > Access is *ceiling* (None: no ceiling) and whose
        sandbox profile is *sandbox* (None: none)."""
        self._loading = True
        try:
            self._ceiling = ceiling
            self.axross_check.setChecked(access.axross)
            for name, check in self.function_checks.items():
                check.setChecked(name in access.functions)
            self.network_combo.clear()
            choices = X.network_choices(sandbox)
            for choice in choices:
                self.network_combo.addItem(tr(NETWORK_LABELS[choice]), choice)
            self.network_combo.setCurrentIndex(max(0, self.network_combo.findData(access.network)))
            self.hosts_list.clear()
            self.hosts_list.addItems(list(access.hosts))
            self.host_note.setText("")
            self.folders_table.setRowCount(0)
            for path, writable in folders:
                self._add_folder_row(path, writable)
            if sandbox is None:
                note = tr("Without a sandbox the agent reads and writes as axross does; "
                          "read-write needs Allow changes to files.")
            elif sandbox.rules.extra_writable:
                note = tr("Read-write needs Allow changes to files.")
            else:
                note = tr("The level {level} mounts every extra folder read-only.").format(
                    level=sandbox.level
                )
            self.folder_note.setText(note)
        finally:
            self._loading = False
        self._update()

    def access(self) -> X.SessionAccess:
        return X.SessionAccess(
            axross=self.axross_check.isChecked(),
            functions=tuple(n for n in X.FUNCTIONS if self.function_checks[n].isChecked()),
            network=self.network_combo.currentData() or "profile",
            hosts=X.clean_hosts(
                self.hosts_list.item(i).text() for i in range(self.hosts_list.count())
            ),
        )

    def folders(self) -> list[tuple[str, bool]]:
        out = []
        for row in range(self.folders_table.rowCount()):
            path = self.folders_table.item(row, 0).text()
            out.append((path, bool(self.folders_table.cellWidget(row, 1).currentData())))
        return out

    # -- the parts ------------------------------------------------------------------

    def _emit(self, *_args) -> None:
        if not self._loading:
            self.changed.emit()

    def _update(self, *_args) -> None:
        master = self.axross_check.isChecked()
        ceiling = self._ceiling
        if ceiling is not None and not getattr(ceiling, "axross_functions", False):
            self.axross_check.setEnabled(False)
            self.axross_check.setToolTip(tr("axross functions are off in Agent Settings > Access"))
            locked = tr("axross functions are off in Agent Settings > Access: switch them on there first.")
        else:
            self.axross_check.setEnabled(True)
            locked = "" if master else tr(
                'Switch on "Let the agent use axross functions" first to choose these.')
        self.functions_note.setText(locked)
        self.functions_note.setHidden(not locked)
        for name, check in self.function_checks.items():
            allowed = ceiling is None or bool(getattr(ceiling, name, False))
            check.setEnabled(not locked and allowed)
            check.setToolTip(locked or ("" if allowed else tr("Off in Agent Settings > Access")))
        hosts = self.network_combo.currentData() == "hosts"
        for widget in (self.hosts_list, self.host_edit, self.host_add, self.host_remove):
            widget.setEnabled(hosts)

    def eventFilter(self, watched, event) -> bool:
        if (
            watched is self.host_edit
            and event.type() == QEvent.Type.KeyPress
            and event.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter)
        ):
            self.add_host()
            return True
        return super().eventFilter(watched, event)

    def add_host(self) -> None:
        text = self.host_edit.text().strip()
        try:
            host, port = parse_host(text)
        except ValueError as exc:
            self.host_note.setText(str(exc))
            return
        entry = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
        if not self.hosts_list.findItems(entry, Qt.MatchFlag.MatchExactly):
            self.hosts_list.addItem(entry)
        self.host_edit.clear()
        self.host_note.setText("")
        self._emit()

    def remove_host(self) -> None:
        row = self.hosts_list.currentRow()
        if row >= 0:
            self.hosts_list.takeItem(row)
            self._emit()

    def _add_folder_row(self, path: str, writable: bool) -> None:
        row = self.folders_table.rowCount()
        self.folders_table.insertRow(row)
        item = QTableWidgetItem(path)
        item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
        self.folders_table.setItem(row, 0, item)
        mode = QComboBox()
        mode.addItem(tr("read-only"), False)
        mode.addItem(tr("read-write"), True)
        mode.setCurrentIndex(1 if writable else 0)
        mode.currentIndexChanged.connect(self._emit)
        self.folders_table.setCellWidget(row, 1, mode)

    def add_folder(self, path: str | None = None) -> None:
        if path is None:
            path = QFileDialog.getExistingDirectory(self, tr("Folder for the agent"))
        if not path or not os.path.isabs(path):
            return
        path = os.path.normpath(path)
        if path in (p for p, _rw in self.folders()):
            return
        self._add_folder_row(path, False)
        self._emit()

    def remove_folder(self) -> None:
        row = self.folders_table.currentRow()
        if row >= 0:
            self.folders_table.removeRow(row)
            self._emit()


class SessionAccessDialog(QDialog):
    """The tab's Access… dialog: the editor with OK and Cancel."""

    def __init__(
        self, parent, title: str, access: X.SessionAccess, folders, *, ceiling, sandbox
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle(tr("Access of {title}").format(title=title))
        self.editor = AccessEditor(self)
        self.editor.load(access, folders, ceiling=ceiling, sandbox=sandbox)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout = QVBoxLayout(self)
        layout.addWidget(self.editor, 1)
        layout.addWidget(buttons)
        add_close_corner(self)
