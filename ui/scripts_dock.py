"""Scripts dock: start, manage and edit saved scripts in the GUI.

Left, the saved scripts in ``~/.config/axross/scripts`` and, below them,
the bundled examples (read-only; "Copy to My Scripts" makes an editable
copy). Centre, a Python editor (:mod:`ui.script_editor`). Bottom, the
output of the last run.

Run starts the saved script in its own process (:mod:`core.script_runner`):
the window never waits for it, Stop terminates it and kills it after
``STOP_GRACE_SECONDS``, closing the window ends it. One run at a time.
Unsaved edits are saved before a run — the child runs the file on disk,
and running anything but the text on screen would be the surprise. "Run
in Console" hands the script to the REPL instead, where it shares the
live namespace and runs on the GUI thread.

Scripts a scheduled job runs (View > Scheduled Jobs) are marked; renaming
or deleting one warns first, because the job refers to it by name.

Paranoid security mode disables Run and Run in Console (with a tooltip
saying why); run() checks the policy again, and the child checks it a
third time with the mode handed over in its environment.
"""

from __future__ import annotations

import logging
import os
import time
from typing import Callable

from PyQt6.QtCore import QObject, QProcess, QProcessEnvironment, Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QAction, QColor, QFont, QKeySequence, QTextCharFormat, QTextCursor
from PyQt6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QDockWidget,
    QInputDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPlainTextEdit,
    QSplitter,
    QToolBar,
    QVBoxLayout,
    QWidget,
)

from core import script_runner as SR
from core import scripting, security_mode
from core.i18n import tr
from ui.script_editor import CodeEditor

log = logging.getLogger(__name__)

#: List-item data: ``(kind, name)`` with kind ``"user"`` or ``"example"``.
ENTRY_ROLE = Qt.ItemDataRole.UserRole + 1

_STDERR_COLOUR = "#e06c75"

_TEMPLATE = '''"""{name} — what this script does.

Runs with ``axross`` in its namespace. Run starts it in its own process
(Stop ends it); Run in Console runs it in the live REPL namespace.
axross.help() lists the API; Help > Scripting Guide explains the rest.
"""

fs = axross.localfs()
for item in fs.list_dir(fs.home())[:10]:
    print(item.name)
'''


class ScriptRun(QObject):
    """One child process: streams its output, reports how it ended."""

    #: (text, from stderr)
    output = pyqtSignal(str, bool)
    #: A one-line account: "exit status 0 after 1.23 s", "stopped after …".
    ended = pyqtSignal(str)

    def __init__(self, command: SR.ChildCommand, env: dict, parent: QObject | None = None):
        super().__init__(parent)
        self._command = command
        self._proc = QProcess(self)
        self._proc.setProgram(command.argv[0])
        self._proc.setArguments(command.argv[1:])
        self._proc.setWorkingDirectory(command.cwd)
        penv = QProcessEnvironment()
        for key, value in env.items():
            penv.insert(key, value)
        self._proc.setProcessEnvironment(penv)
        self._limiters = {
            False: SR.OutputLimiter(max_lines=SR.MAX_OUTPUT_LINES),
            True: SR.OutputLimiter(max_lines=SR.MAX_OUTPUT_LINES),
        }
        self._proc.readyReadStandardOutput.connect(lambda: self._read(False))
        self._proc.readyReadStandardError.connect(lambda: self._read(True))
        self._proc.finished.connect(self._on_finished)
        self._proc.errorOccurred.connect(self._on_error)
        self._kill_timer = QTimer(self)
        self._kill_timer.setSingleShot(True)
        self._kill_timer.timeout.connect(self._kill)
        self._started_at = 0.0
        self._stopping = False
        self._done = False

    def start(self) -> None:
        self._started_at = time.monotonic()
        self._proc.start()
        if self._command.stdin_text:
            self._proc.write(self._command.stdin_text.encode("utf-8"))
        # End of input: input() gets EOF, and axross.confirm() raises
        # NonInteractiveError (no terminal) unless the script passed assume_yes.
        self._proc.closeWriteChannel()

    def is_running(self) -> bool:
        return not self._done

    def pid(self) -> int | None:
        if self._proc.state() == QProcess.ProcessState.NotRunning:
            return None
        return int(self._proc.processId()) or None

    def stop(self) -> None:
        """Terminate now, kill after the grace period. Returns at once."""
        if self._proc.state() == QProcess.ProcessState.NotRunning:
            return
        self._stopping = True
        self._proc.terminate()
        self._kill_timer.start(int(SR.STOP_GRACE_SECONDS * 1000))

    def shutdown(self) -> None:
        """Stop and wait for the end (window close): terminate, then kill."""
        if self._proc.state() == QProcess.ProcessState.NotRunning:
            return
        self._stopping = True
        self._proc.terminate()
        if not self._proc.waitForFinished(int(SR.STOP_GRACE_SECONDS * 1000)):
            self._proc.kill()
            self._proc.waitForFinished(5000)

    def _kill(self) -> None:
        if self._proc.state() != QProcess.ProcessState.NotRunning:
            log.info("script run did not end after terminate; killing pid %s", self.pid())
            self._proc.kill()

    def _read(self, from_stderr: bool) -> None:
        data = bytes(
            self._proc.readAllStandardError() if from_stderr else self._proc.readAllStandardOutput()
        )
        if data:
            text = self._limiters[from_stderr].feed(data)
            if text:
                self.output.emit(text, from_stderr)

    def _on_finished(self, code: int, status: QProcess.ExitStatus) -> None:
        if self._done:
            return
        self._kill_timer.stop()
        self._read(False)
        self._read(True)
        for from_stderr, limiter in self._limiters.items():
            rest = limiter.flush()
            if rest:
                self.output.emit(rest, from_stderr)
        elapsed = time.monotonic() - self._started_at
        if self._stopping:
            message = tr("stopped after {s:.2f} s").format(s=elapsed)
        elif status == QProcess.ExitStatus.CrashExit:
            message = tr("ended by a signal after {s:.2f} s").format(s=elapsed)
        else:
            message = tr("exit status {code} after {s:.2f} s").format(code=code, s=elapsed)
        self._done = True
        self.ended.emit(message)

    def _on_error(self, error: QProcess.ProcessError) -> None:
        if error == QProcess.ProcessError.FailedToStart and not self._done:
            self._done = True
            self.ended.emit(tr("could not start: {e}").format(e=self._proc.errorString()))


class _OutputView(QPlainTextEdit):
    """Read-only, bounded output pane; a click on a traceback line of the
    script reports that line (``line_clicked``)."""

    line_clicked = pyqtSignal(str)

    def __init__(self, is_link: Callable[[str], bool], parent: QWidget | None = None):
        super().__init__(parent)
        self._is_link = is_link
        self.setReadOnly(True)
        self.setUndoRedoEnabled(False)
        self.setMaximumBlockCount(SR.MAX_OUTPUT_LINES)
        font = QFont("Monospace")
        font.setStyleHint(QFont.StyleHint.Monospace)
        self.setFont(font)
        self.viewport().setMouseTracking(True)

    def append_output(self, text: str, from_stderr: bool) -> None:
        bar = self.verticalScrollBar()
        at_bottom = bar.value() >= bar.maximum() - 2
        cursor = QTextCursor(self.document())
        cursor.movePosition(QTextCursor.MoveOperation.End)
        fmt = QTextCharFormat()
        if from_stderr:
            fmt.setForeground(QColor(_STDERR_COLOUR))
        cursor.insertText(text, fmt)
        if at_bottom:
            bar.setValue(bar.maximum())

    def _line_at(self, event) -> str:
        return self.cursorForPosition(event.position().toPoint()).block().text()

    def mouseMoveEvent(self, event) -> None:  # noqa: N802 — Qt
        super().mouseMoveEvent(event)
        shape = (
            Qt.CursorShape.PointingHandCursor
            if self._is_link(self._line_at(event))
            else Qt.CursorShape.IBeamCursor
        )
        self.viewport().setCursor(shape)

    def mouseReleaseEvent(self, event) -> None:  # noqa: N802 — Qt
        super().mouseReleaseEvent(event)
        if event.button() == Qt.MouseButton.LeftButton and not self.textCursor().hasSelection():
            self.line_clicked.emit(self._line_at(event))


class ScriptsDock(QDockWidget):
    """The Scripts panel (View > Panels > Scripts)."""

    #: Output arrived or a run ended — the tab highlighter's cue.
    activity = pyqtSignal()
    #: The user asked to run this saved script in the Console's REPL.
    run_in_console_requested = pyqtSignal(str)
    #: (example name, its call): Run in Console of a bundled example.
    run_example_in_console_requested = pyqtSignal(str, str)

    def __init__(
        self,
        parent: QWidget | None = None,
        *,
        scheduled_jobs: Callable[[], dict[str, list[str]]] | None = None,
    ):
        super().__init__(tr("Scripts"), parent)
        self.setObjectName("axScriptsDock")
        self.setAllowedAreas(
            Qt.DockWidgetArea.BottomDockWidgetArea | Qt.DockWidgetArea.TopDockWidgetArea
        )
        self._scheduled_jobs = scheduled_jobs or (lambda: {})
        self._jobs_by_script: dict[str, list[str]] = {}
        self._current: tuple[str, str] | None = None
        self._saved_text = ""
        self._dirty = False
        self._loading = False
        self._run: ScriptRun | None = None
        self._run_name = ""
        #: What the running script only defines (SR.only_defines), for its end.
        self._run_library: list[str] = []
        self._run_path = ""

        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(2)

        self.toolbar = QToolBar()
        self.toolbar.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextOnly)
        layout.addWidget(self.toolbar)

        def action(text: str, slot, tip: str, shortcut: str | None = None) -> QAction:
            act = QAction(text, self)
            act.setToolTip(tip)
            act.triggered.connect(lambda _checked=False: slot())
            if shortcut:
                act.setShortcut(QKeySequence(shortcut))
                act.setShortcutContext(Qt.ShortcutContext.WidgetWithChildrenShortcut)
                container.addAction(act)  # active while focus is anywhere in the dock
            self.toolbar.addAction(act)
            return act

        self.new_action = action(tr("New"), self.new_script, tr("Create a new script"))
        self.save_action = action(tr("Save"), self.save, tr("Save the script (Ctrl+S)"), "Ctrl+S")
        self.save_as_action = action(
            tr("Save As…"), self.save_as, tr("Save a copy under a new name")
        )
        self.rename_action = action(tr("Rename…"), self.rename, tr("Rename the script"))
        self.delete_action = action(tr("Delete"), self.delete, tr("Delete the script"))
        self.toolbar.addSeparator()
        self.run_action = action(tr("Run"), self.run, "", "Ctrl+Return")
        self.stop_action = action(tr("Stop"), self.stop, tr("Stop the running script"))
        self.console_action = action(tr("Run in Console"), self.run_in_console, "")
        self.toolbar.addSeparator()
        self.copy_example_action = action(
            tr("Copy to My Scripts"),
            self.copy_example,
            tr("Make an editable copy of this example"),
        )

        self.list = QListWidget()
        self.list.currentItemChanged.connect(self._on_list_current_changed)

        self.header = QLabel()
        self.editor = CodeEditor()
        self.editor.setPlaceholderText(tr("Select a script on the left, or press New."))
        self.editor.textChanged.connect(self._on_text_changed)
        editor_box = QWidget()
        editor_layout = QVBoxLayout(editor_box)
        editor_layout.setContentsMargins(0, 0, 0, 0)
        editor_layout.addWidget(self.header)
        editor_layout.addWidget(self.editor)

        self.status = QLabel(tr("Not running."))
        self.output = _OutputView(lambda text: self._traceback_line(text) is not None)
        self.output.line_clicked.connect(self.jump_to_traceback_line)
        output_box = QWidget()
        output_layout = QVBoxLayout(output_box)
        output_layout.setContentsMargins(0, 0, 0, 0)
        output_layout.addWidget(self.status)
        output_layout.addWidget(self.output)

        right = QSplitter(Qt.Orientation.Vertical)
        right.addWidget(editor_box)
        right.addWidget(output_box)
        right.setStretchFactor(0, 3)
        right.setStretchFactor(1, 2)
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(self.list)
        splitter.addWidget(right)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 4)
        splitter.setSizes([200, 800])
        layout.addWidget(splitter, 1)
        self.setWidget(container)

        self._show_nothing()
        self.refresh()

    # ------------------------------------------------------------------
    # Dialogs — one method each, so tests can answer them
    # ------------------------------------------------------------------
    def _ask_name(self, title: str, label: str, default: str = "") -> str | None:
        text, ok = QInputDialog.getText(self, title, label, QLineEdit.EchoMode.Normal, default)
        return text.strip() if ok else None

    def _ask_example_call(self, name: str, usage: str) -> str | None:
        """The call to run bundled example *name* with: its Usage block, to
        adjust (paths, hosts, profiles). None: cancelled."""
        from ui.close_corner import add_close_corner

        dialog = QDialog(self)
        dialog.setWindowTitle(tr("Run Example {name}").format(name=name))
        layout = QVBoxLayout(dialog)
        note = QLabel(tr(
            "{name} defines functions; this code calls them after it. Adjust paths, hosts "
            "or profiles, then Run.").format(name=name))
        note.setWordWrap(True)
        layout.addWidget(note)
        edit = CodeEditor(dialog)
        edit.setObjectName("axExampleCall")
        edit.setPlainText(usage)
        layout.addWidget(edit, 1)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel, dialog)
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText(tr("Run"))
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        add_close_corner(dialog)
        dialog.resize(640, 320)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return None
        return edit.toPlainText()

    def _example_call(self) -> str | None:
        name = self._current[1]
        return self._ask_example_call(name, SR.usage_block(self.editor.toPlainText()))

    def _ask_unsaved(self, name: str) -> str:
        """``"save"``, ``"discard"`` or ``"cancel"``."""
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Warning)
        box.setWindowTitle(tr("Unsaved Changes"))
        box.setTextFormat(Qt.TextFormat.PlainText)
        box.setText(tr("The script {name} has unsaved changes.").format(name=name))
        box.setStandardButtons(
            QMessageBox.StandardButton.Save
            | QMessageBox.StandardButton.Discard
            | QMessageBox.StandardButton.Cancel
        )
        box.setDefaultButton(QMessageBox.StandardButton.Save)
        answer = box.exec()
        if answer == QMessageBox.StandardButton.Save:
            return "save"
        if answer == QMessageBox.StandardButton.Discard:
            return "discard"
        return "cancel"

    def _confirm(self, title: str, text: str) -> bool:
        answer = QMessageBox.question(
            self,
            title,
            text,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        return answer == QMessageBox.StandardButton.Yes

    def _warn(self, title: str, text: str) -> None:
        QMessageBox.warning(self, title, text)

    def _ask_new_name(self, title: str, label: str, default: str = "") -> str | None:
        """Ask until the name is valid and free, or the user cancels."""
        value = default
        while True:
            name = self._ask_name(title, label, value)
            if name is None:
                return None
            value = name
            try:
                scripting._validate_script_name(name)
            except ValueError as exc:
                self._warn(title, str(exc))
                continue
            if name in scripting.list_scripts():
                self._warn(title, tr("A script named {name} already exists.").format(name=name))
                continue
            return name

    # ------------------------------------------------------------------
    # State
    # ------------------------------------------------------------------
    def current(self) -> tuple[str, str] | None:
        return self._current

    def is_dirty(self) -> bool:
        return self._dirty

    def is_running(self) -> bool:
        return self._run is not None

    def running_pid(self) -> int | None:
        return self._run.pid() if self._run is not None else None

    def status_text(self) -> str:
        return self.status.text()

    def header_text(self) -> str:
        return self.header.text()

    def last_run_path(self) -> str:
        return self._run_path

    def _is_user(self) -> bool:
        return self._current is not None and self._current[0] == "user"

    def _set_editor(self, text: str, *, read_only: bool) -> None:
        self._loading = True
        try:
            self.editor.setPlainText(text)
            self.editor.setReadOnly(read_only)
        finally:
            self._loading = False
        self._saved_text = text
        self._set_dirty(False)

    def _show(self, entry: tuple[str, str], text: str, *, read_only: bool) -> None:
        self._current = entry
        self._set_editor(text, read_only=read_only)
        self._update_header()
        self._select_current_item()
        self._update_actions()

    def _show_nothing(self) -> None:
        self._current = None
        self._set_editor("", read_only=True)
        self._update_header()
        self._select_current_item()
        self._update_actions()

    def _on_text_changed(self) -> None:
        if self._loading or self.editor.isReadOnly():
            return
        self._set_dirty(self.editor.toPlainText() != self._saved_text)

    def _set_dirty(self, dirty: bool) -> None:
        if dirty == self._dirty:
            return
        self._dirty = dirty
        self._update_header()
        if self._is_user():
            item = self._item_for(self._current)
            if item is not None:
                item.setText(self._user_label(self._current[1]))

    def _update_header(self) -> None:
        if self._current is None:
            self.header.setText(tr("No script open"))
        elif self._current[0] == "example":
            self.header.setText(
                tr("{name} — bundled example, read-only").format(name=self._current[1])
            )
        else:
            self.header.setText(self._current[1] + (" *" if self._dirty else ""))

    def _update_actions(self) -> None:
        user = self._is_user()
        example = self._current is not None and self._current[0] == "example"
        running = self.is_running()
        policy = security_mode.current_policy()
        self.save_action.setEnabled(user)
        self.save_as_action.setEnabled(user)
        self.rename_action.setEnabled(user)
        self.delete_action.setEnabled(user)
        self.copy_example_action.setEnabled(example)
        self.stop_action.setEnabled(running)
        if not policy.allow_scripts:
            blocked = tr(
                "Scripts are blocked in {mode} security mode (Edit > Settings > Security)."
            ).format(mode=policy.name)
            self.run_action.setEnabled(False)
            self.console_action.setEnabled(False)
            self.run_action.setToolTip(blocked)
            self.console_action.setToolTip(blocked)
            return
        self.run_action.setEnabled((user or example) and not running)
        self.console_action.setEnabled(user or example)
        if example:
            self.run_action.setToolTip(tr(
                "Run this example in its own process with its call, shown first to adjust "
                "(Ctrl+Return)"))
            self.console_action.setToolTip(tr(
                "Run this example with its call in the Console's live namespace"))
            return
        self.run_action.setToolTip(tr("Run the saved script in its own process (Ctrl+Return)"))
        self.console_action.setToolTip(
            tr("Run in the Console's live namespace; the window waits until it finishes")
        )

    def refresh_policy(self) -> None:
        """Re-read the security mode (Edit > Settings > Security)."""
        self._update_actions()

    # ------------------------------------------------------------------
    # List
    # ------------------------------------------------------------------
    def _user_label(self, name: str) -> str:
        label = name
        if name in self._jobs_by_script:
            label += " " + tr("[scheduled]")
        if self._current == ("user", name) and self._dirty:
            label += " *"
        return label

    def refresh(self) -> None:
        """Rebuild the list from disk and the schedule."""
        try:
            self._jobs_by_script = {
                str(k): list(v) for k, v in (self._scheduled_jobs() or {}).items()
            }
        except Exception:  # noqa: BLE001 — a broken schedule must not empty the list
            log.warning("scripts dock: could not read the schedule", exc_info=True)
            self._jobs_by_script = {}
        try:
            saved = scripting.list_scripts()
        except OSError as exc:
            log.warning("scripts dock: cannot list scripts: %s", exc)
            saved = []
        self.list.blockSignals(True)
        try:
            self.list.clear()
            self._add_header(tr("My Scripts"))
            for name in saved:
                item = QListWidgetItem(self._user_label(name))
                item.setData(ENTRY_ROLE, ("user", name))
                jobs = self._jobs_by_script.get(name)
                if jobs:
                    item.setToolTip(
                        tr("Run by scheduled job(s): {jobs}").format(jobs=", ".join(jobs))
                    )
                self.list.addItem(item)
            if not saved:
                hint = QListWidgetItem(tr("(none yet — press New)"))
                hint.setFlags(Qt.ItemFlag.NoItemFlags)
                self.list.addItem(hint)
            self._add_header(tr("Examples (read-only)"))
            for name in scripting._list_bundled_scripts():
                item = QListWidgetItem(name)
                item.setData(ENTRY_ROLE, ("example", name))
                self.list.addItem(item)
        finally:
            self.list.blockSignals(False)
        self._select_current_item()

    def _add_header(self, text: str) -> None:
        item = QListWidgetItem(text)
        item.setFlags(Qt.ItemFlag.NoItemFlags)
        font = item.font()
        font.setBold(True)
        item.setFont(font)
        self.list.addItem(item)

    def _item_for(self, entry) -> QListWidgetItem | None:
        for i in range(self.list.count()):
            item = self.list.item(i)
            if item.data(ENTRY_ROLE) == entry:
                return item
        return None

    def _select_current_item(self) -> None:
        self.list.blockSignals(True)
        try:
            item = self._item_for(self._current) if self._current else None
            self.list.setCurrentItem(item)
        finally:
            self.list.blockSignals(False)

    def _on_list_current_changed(self, current, _previous) -> None:
        if current is None:
            return
        entry = current.data(ENTRY_ROLE)
        if not entry or tuple(entry) == self._current:
            return
        kind, name = entry
        if kind == "user":
            self.open_script(name)
        else:
            self.open_example(name)

    # ------------------------------------------------------------------
    # Opening, saving, the unsaved-changes guard
    # ------------------------------------------------------------------
    def _guard_unsaved(self) -> bool:
        """True when it is fine to replace the editor's content."""
        if not (self._is_user() and self._dirty):
            return True
        answer = self._ask_unsaved(self._current[1])
        if answer == "save":
            return self.save()
        if answer == "discard":
            self._set_dirty(False)
            return True
        return False

    def maybe_close(self) -> bool:
        """The window is closing: False keeps it open (unsaved, cancelled)."""
        return self._guard_unsaved()

    def open_script(self, name: str) -> bool:
        if self._current == ("user", name):
            return True
        if not self._guard_unsaved():
            self._select_current_item()
            return False
        try:
            source = scripting.load_script(name)
        except (OSError, ValueError, UnicodeDecodeError) as exc:
            self._warn(tr("Open Script"), str(exc))
            self._select_current_item()
            return False
        self._show(("user", name), source, read_only=False)
        return True

    def open_example(self, name: str) -> bool:
        if self._current == ("example", name):
            return True
        if not self._guard_unsaved():
            self._select_current_item()
            return False
        try:
            source = scripting._load_bundled_script(name)
        except (OSError, ValueError, UnicodeDecodeError) as exc:
            self._warn(tr("Open Example"), str(exc))
            self._select_current_item()
            return False
        self._show(("example", name), source, read_only=True)
        return True

    def save(self) -> bool:
        if not self._is_user():
            return False
        text = self.editor.toPlainText()
        try:
            scripting.save_script(self._current[1], text)
        except (OSError, ValueError) as exc:
            self._warn(tr("Save Script"), str(exc))
            return False
        self._saved_text = text
        self._set_dirty(False)
        return True

    def _save_new(self, name: str, text: str, title: str) -> bool:
        try:
            scripting.save_script(name, text)
        except (OSError, ValueError) as exc:
            self._warn(title, str(exc))
            return False
        self._current = ("user", name)
        self.refresh()
        self._show(("user", name), text, read_only=False)
        return True

    def new_script(self) -> None:
        if not self._guard_unsaved():
            return
        title = tr("New Script")
        name = self._ask_new_name(title, tr("Script name (letters, digits, _ and -):"))
        if name:
            self._save_new(name, _TEMPLATE.format(name=name), title)

    def save_as(self) -> None:
        """Save the editor's text under a new name; the original file keeps
        what it had on disk."""
        if not self._is_user():
            return
        title = tr("Save Script As")
        name = self._ask_new_name(title, tr("New script name:"), f"{self._current[1]}_copy")
        if name:
            self._save_new(name, self.editor.toPlainText(), title)

    def copy_example(self) -> None:
        if self._current is None or self._current[0] != "example":
            return
        title = tr("Copy to My Scripts")
        name = self._ask_new_name(title, tr("Name of your copy:"), self._current[1])
        if name:
            text = self.editor.toPlainText()
            usage = SR.usage_block(text)
            if usage:
                commented = "\n".join(f"# {line}" if line else "#" for line in usage.splitlines())
                text = f"{text.rstrip()}\n\n\n{SR.TRY_IT_HEADER}\n{commented}\n"
            self._save_new(name, text, title)

    def _jobs_note(self, name: str) -> str:
        jobs = self._jobs_by_script.get(name)
        if not jobs:
            return ""
        return tr("Scheduled job(s) {jobs} run {name} by name and will fail without it.").format(
            jobs=", ".join(jobs), name=name
        )

    def rename(self) -> None:
        """Rename the file on disk; unsaved edits stay in the editor."""
        if not self._is_user():
            return
        old = self._current[1]
        title = tr("Rename Script")
        new = self._ask_new_name(title, tr("New name for {name}:").format(name=old), old)
        if not new:
            return
        note = self._jobs_note(old)
        if note and not self._confirm(title, note + "\n\n" + tr("Rename anyway?")):
            return
        try:
            source = scripting.load_script(old)
            scripting.save_script(new, source)
            scripting.delete_script(old)
        except (OSError, ValueError) as exc:
            self._warn(title, str(exc))
            return
        self._current = ("user", new)
        self._saved_text = source
        self._dirty = self.editor.toPlainText() != source
        self.refresh()
        self._update_header()
        self._update_actions()

    def delete(self) -> None:
        if not self._is_user():
            return
        name = self._current[1]
        title = tr("Delete Script")
        text = tr("Delete the script {name}? This cannot be undone.").format(name=name)
        note = self._jobs_note(name)
        if note:
            text += "\n\n" + note
        if not self._confirm(title, text):
            return
        try:
            scripting.delete_script(name)
        except (OSError, ValueError) as exc:
            self._warn(title, str(exc))
            return
        self._show_nothing()
        self.refresh()

    # ------------------------------------------------------------------
    # Running
    # ------------------------------------------------------------------
    def run(self) -> None:
        example = self._current is not None and self._current[0] == "example"
        if self.is_running() or not (self._is_user() or example):
            return
        policy = security_mode.current_policy()
        if not policy.allow_scripts:
            self.status.setText(
                tr("Scripts are blocked in {mode} security mode.").format(mode=policy.name)
            )
            return
        name = self._current[1]
        if example:
            call = self._example_call()
            if call is None:
                return
        elif self._dirty and not self.save():
            return
        try:
            command = SR.build_example_command(name, call) if example else SR.build_command(name)
        except (OSError, ValueError) as exc:
            self.status.setText(tr("Cannot run {name}: {e}").format(name=name, e=exc))
            return
        self.output.clear()
        self._run_name = name
        self._run_library = [] if example else SR.only_defines(self.editor.toPlainText())
        self._run_path = (os.path.join(scripting._bundled_scripts_dir(), f"{name}.py")
                          if example else os.path.join(command.cwd, f"{name}.py"))
        run = ScriptRun(command, SR.child_env(policy.name, watched=True), self)
        run.output.connect(self._on_run_output)
        run.ended.connect(self._on_run_ended)
        self._run = run
        self.status.setText(tr("Running {name} …").format(name=name))
        run.start()
        self._update_actions()

    def stop(self) -> None:
        if self._run is not None:
            self.status.setText(tr("Stopping {name} …").format(name=self._run_name))
            self._run.stop()

    def _on_run_output(self, text: str, from_stderr: bool) -> None:
        self.output.append_output(text, from_stderr)
        self.activity.emit()

    def _on_run_ended(self, message: str) -> None:
        run, self._run = self._run, None
        if run is not None:
            run.deleteLater()
        text = f"{self._run_name}: {message}"
        library = self._run_library
        if library and message.startswith("exit status 0") and not self.output.toPlainText().strip():
            text += " - " + tr(
                "the script only defines {names}; nothing calls it. Call one at the end "
                "(see the Try it section of a copied example).").format(names=", ".join(library))
        self.status.setText(text)
        self._update_actions()
        self.activity.emit()

    def run_in_console(self) -> None:
        if not security_mode.current_policy().allow_scripts:
            return
        if self._current is not None and self._current[0] == "example":
            call = self._example_call()
            if call is not None:
                self.run_example_in_console_requested.emit(self._current[1], call)
            return
        if not self._is_user():
            return
        if self._dirty and not self.save():
            return
        self.run_in_console_requested.emit(self._current[1])

    def _traceback_line(self, text: str) -> int | None:
        if not self._run_path:
            return None
        return SR.script_line_in(text, self._run_path)

    def jump_to_traceback_line(self, text: str) -> bool:
        """Open the script of the last run at the line ``text`` points to."""
        line = self._traceback_line(text)
        if line is None:
            return False
        if self._current != ("user", self._run_name):
            if self._run_name not in scripting.list_scripts():
                self.status.setText(tr("{name} no longer exists.").format(name=self._run_name))
                return False
            if not self.open_script(self._run_name):
                return False
        return self.editor.go_to_line(line)

    def shutdown(self) -> None:
        """Window closing: end a running script (terminate, then kill)."""
        if self._run is not None:
            self._run.shutdown()

    def showEvent(self, event) -> None:  # noqa: N802 — Qt
        # Scripts saved from the REPL (.save) or by hand appear on return.
        self.refresh()
        self._update_actions()
        super().showEvent(event)


__all__ = ["ENTRY_ROLE", "ScriptRun", "ScriptsDock"]
