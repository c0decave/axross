"""The Android Device window: what an ADB connection's phone is, its apps,
its SMS, its log and its screen - the device tools of core.adb_device in
axross's own window.

Opened from an ADB pane (right-click > More > Android Device…) and from
Pane > Android Device… in the menu bar, one window per connection. Five
tabs:

* **Info** - model, Android version, security patch, serial, IMEI where
  the shell may read it, battery; Reboot…;
* **Apps** - the installed apps, filtered by name and kind; Details
  (version, permissions, Grant / Revoke), Start, Stop, Uninstall…,
  Install APK…, Back Up APK…;
* **SMS** - the messages of one box; Write into Store… and Prepare SMS…
  (the safe paths of the MCP tools: written into the store and read back,
  or composed in the SMS app - never sent by axross);
* **Logcat** - the newest lines by priority, tag or app; Follow, Pause,
  Save…;
* **Screenshot** - the screen, and Save….

Every device call runs on a worker thread (ui.scan_job.ScanJob, one per
tab), so a slow phone never holds the window. Every change asks first;
Uninstall and Reboot count down as the production gate does, and on a
profile flagged production every change passes ui.production_gate. In
the paranoid security mode the changes are off (as in the MCP server).
"""

from __future__ import annotations

import logging
import os
import time
import weakref

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QPixmap
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from core import adb_device as A
from core.i18n import tr
from ui.scan_job import BusyStrip, ScanJob

log = logging.getLogger(__name__)

#: Seconds Uninstall and Reboot count down before they go ahead.
COUNTDOWN_S = 3.0
#: Milliseconds between two reads of the log while Follow is on.
FOLLOW_MS = 2000

#: One window per connection (the backend object).
_WINDOWS: "weakref.WeakValueDictionary[int, AndroidDeviceWindow]" = weakref.WeakValueDictionary()


def is_android(backend) -> bool:
    """Whether *backend* is an ADB connection (an Android device)."""
    return callable(getattr(backend, "exec", None)) and any(
        cls.__name__ == "AdbSession" for cls in type(backend).__mro__)


def open_for(backend, parent: QWidget | None = None) -> "AndroidDeviceWindow":
    """The Android Device window of *backend*, made or raised."""
    from PyQt6 import sip

    window = _WINDOWS.get(id(backend))
    if window is None or sip.isdeleted(window) or window.backend is not backend:
        window = AndroidDeviceWindow(backend, parent)
        _WINDOWS[id(backend)] = window
    window.show()
    window.raise_()
    window.activateWindow()
    return window


def _changes_allowed() -> bool:
    from core.security_mode import current_policy

    return bool(current_policy().allow_remote_exec)


def _error_text(exc: BaseException) -> str:
    from core.user_errors import describe

    if isinstance(exc, (A.DeviceRefused, ValueError)):
        return str(exc)
    return describe(exc)


def _cell(text) -> QTableWidgetItem:
    item = QTableWidgetItem("" if text is None else str(text))
    item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
    return item


class CountdownDialog(QDialog):
    """A change that cannot be taken back, with a countdown as the
    production gate has: Esc or Cancel stops it, the end of the countdown
    lets it go ahead."""

    def __init__(self, action: str, seconds: float, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        from ui.close_corner import add_close_corner
        from ui.icon_provider import set_window_icon
        from ui.plain_text import set_plain

        set_window_icon(self, "shield")
        self.setWindowTitle(tr("Confirm"))
        self._seconds = max(0.0, float(seconds))
        self._deadline = 0.0
        layout = QVBoxLayout(self)
        text = set_plain(QLabel(self), tr("About to: {action}\n\nPress Esc or Cancel to stop. It "
                                          "goes ahead when the countdown ends.").format(action=action))
        text.setWordWrap(True)
        layout.addWidget(text)
        self._bar = QProgressBar(self)
        self._bar.setRange(0, max(1, int(self._seconds * 10)))
        self._bar.setTextVisible(False)
        layout.addWidget(self._bar)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Cancel, self)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self._timer = QTimer(self)
        self._timer.setInterval(100)
        self._timer.timeout.connect(self._tick)
        add_close_corner(self)

    def exec(self) -> int:  # noqa: D102 - QDialog.exec with the countdown running
        self._deadline = time.monotonic() + self._seconds
        self._tick()
        self._timer.start()
        try:
            return super().exec()
        finally:
            self._timer.stop()

    def _tick(self) -> None:
        left = self._deadline - time.monotonic()
        if left <= 0:
            self._timer.stop()
            self.accept()
            return
        self._bar.setValue(int((self._seconds - left) * 10))


class _Tab(QWidget):
    """A tab: its own background job, a busy strip and a note line."""

    def __init__(self, window: "AndroidDeviceWindow") -> None:
        super().__init__(window)
        self.window_ = window
        self.job = ScanJob(self, formatter=lambda _state: tr("Asking the device…"))
        self.job.finished.connect(self._finished)
        self._done = None
        self.layout_ = QVBoxLayout(self)
        self.note = QLabel("", self)
        self.note.setWordWrap(True)
        self.note.setTextFormat(Qt.TextFormat.PlainText)
        self.note.setProperty("role", "muted")
        self.strip = BusyStrip(self.job, self, cancel_text=tr("Stop"))

    def finish_layout(self) -> None:
        self.layout_.addWidget(self.note)
        self.layout_.addWidget(self.strip)

    def run(self, work, done, *, keep_note: bool = False) -> bool:
        """Run ``work(tools)`` off the GUI thread with an AndroidTools of
        this connection; ``done(value)`` on the GUI thread. False (and
        nothing started) while the tab's last call still runs."""
        backend = self.window_.backend
        if self.job.running:
            self.note.setText(tr("The device is still answering the last request."))
            return False
        self._done = done
        if not keep_note:
            self.note.setText("")
        return self.job.start(lambda cancel, _progress: work(
            A.AndroidTools(backend, cancelled=cancel)))

    def _finished(self, kind: str, value, cancelled: bool) -> None:
        done, self._done = self._done, None
        if cancelled:
            self.note.setText(tr("Stopped."))
            return
        if kind == "error":
            self.note.setText(_error_text(value))
            return
        if done is not None:
            done(value)

    def confirm(self, title: str, question: str, action: str, *, countdown: bool = False) -> bool:
        """Whether the change *action* may go ahead: a question, a countdown
        for what cannot be taken back, the production gate."""
        if not _changes_allowed():
            QMessageBox.information(self, title, tr("The paranoid security mode turns changes on a "
                                                    "device off."))
            return False
        from ui.plain_text import as_written

        if QMessageBox.question(self, title, as_written(question),
                                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                QMessageBox.StandardButton.No) != QMessageBox.StandardButton.Yes:
            return False
        from ui.production_gate import confirm_production

        backend = self.window_.backend
        production = getattr(getattr(backend, "_axross_profile", None), "production", False)
        if not confirm_production(self, backend, action):
            return False
        if countdown and not production:
            return CountdownDialog(action, self.window_.countdown_s, self).exec() == QDialog.DialogCode.Accepted
        return True


# ---------------------------------------------------------------------------
# Info
# ---------------------------------------------------------------------------

class InfoTab(_Tab):
    FIELDS = (("manufacturer", "Manufacturer"), ("model", "Model"), ("device", "Device"),
              ("android_version", "Android version"), ("sdk", "SDK level"),
              ("security_patch", "Security patch"), ("build_id", "Build"),
              ("abis", "CPU ABIs"), ("serial", "Serial number"), ("imei", "IMEI"),
              ("meid", "MEID"))

    def __init__(self, window) -> None:
        super().__init__(window)
        form = QFormLayout()
        self.values: dict[str, QLabel] = {}
        for key, label in self.FIELDS + (("battery", "Battery"), ("storage", "Storage")):
            value = QLabel("–", self)
            value.setTextFormat(Qt.TextFormat.PlainText)
            value.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            value.setWordWrap(True)
            self.values[key] = value
            form.addRow(tr(label), value)
        self.layout_.addLayout(form)
        row = QHBoxLayout()
        self.refresh_button = QPushButton(tr("Refresh"), self)
        self.refresh_button.clicked.connect(lambda _checked=False: self.refresh())
        row.addWidget(self.refresh_button)
        row.addStretch(1)
        self.reboot_mode = QComboBox(self)
        for mode, label in (("system", "Android"), ("recovery", "Recovery"),
                            ("bootloader", "Bootloader")):
            self.reboot_mode.addItem(tr(label), mode)
        row.addWidget(self.reboot_mode)
        self.reboot_button = QPushButton(tr("Reboot…"), self)
        self.reboot_button.clicked.connect(lambda _checked=False: self.reboot())
        row.addWidget(self.reboot_button)
        self.layout_.addLayout(row)
        self.layout_.addStretch(1)
        self.finish_layout()

    def refresh(self) -> None:
        def work(tools):
            info = tools.device_info()
            try:
                battery = tools.battery()
            except (OSError, ValueError) as exc:
                battery = {"error": _error_text(exc)}
            try:
                _status, out = tools.run("df", "/data", timeout=20.0, cap=64 * 1024)
                storage = _df(out)
            except (OSError, ValueError):
                storage = None
            return info, battery, storage

        self.run(work, self._show)

    def _show(self, value) -> None:
        info, battery, storage = value
        for key, _label in self.FIELDS:
            text = info.get(key)
            if text in (None, ""):
                text = info.get(f"{key}_note") or "–"
            self.values[key].setText(str(text))
        if not info.get("imei"):
            self.values["imei"].setText(info.get("imei_note") or "–")
        if "error" in battery:
            self.values["battery"].setText(battery["error"])
        else:
            parts = [f"{battery['level_percent']} %" if battery["level_percent"] is not None else "",
                     tr(battery["status"]), tr(battery["health"])]
            if battery["temperature_c"] is not None:
                parts.append(f"{battery['temperature_c']:.1f} °C")
            if battery["simulated"]:
                parts.append(tr("simulated values"))
            self.values["battery"].setText(", ".join(p for p in parts if p))
        if storage:
            self.values["storage"].setText(tr("{free} free of {total}").format(
                free=_size(storage[1]), total=_size(storage[0])))
        else:
            self.values["storage"].setText(tr("not readable"))

    def reboot(self) -> None:
        mode = self.reboot_mode.currentData()
        label = self.reboot_mode.currentText()
        action = tr("reboot the device into {mode}").format(mode=label)
        if not self.confirm(tr("Reboot"), tr("Reboot the device into {mode}? Every app ends and "
                                             "unsaved work is lost; the connection drops.")
                            .format(mode=label), action, countdown=True):
            return
        self.run(lambda tools: tools.reboot({"mode": mode}),
                 lambda _out: self.note.setText(tr("The device is restarting. Close this "
                                                   "connection and connect again once it is up.")))


def _df(out: str) -> tuple[int, int] | None:
    """``(total, free)`` bytes of a ``df`` line (1K blocks), None when
    the answer has none."""
    for line in out.replace("\r", "").split("\n")[1:]:
        fields = line.split()
        if len(fields) >= 4:
            total, free = A.ascii_int(fields[1]), A.ascii_int(fields[3])
            if total is not None and free is not None:
                return total * 1024, free * 1024
    return None


def _size(count: int) -> str:
    value = float(count)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024
    return f"{count} B"


# ---------------------------------------------------------------------------
# Apps
# ---------------------------------------------------------------------------

class AppsTab(_Tab):
    COLUMNS = ("Package", "Version", "Installer", "Kind", "State")

    def __init__(self, window) -> None:
        super().__init__(window)
        top = QHBoxLayout()
        self.filter_edit = QLineEdit(self)
        self.filter_edit.setPlaceholderText(tr("Filter by package name"))
        self.filter_edit.textChanged.connect(lambda _text: self._fill())
        top.addWidget(self.filter_edit, 1)
        self.kind = QComboBox(self)
        for kind, label in (("all", "All apps"), ("user", "User apps"), ("system", "System apps")):
            self.kind.addItem(tr(label), kind)
        self.kind.currentIndexChanged.connect(lambda _i: self.refresh())
        top.addWidget(self.kind)
        self.refresh_button = QPushButton(tr("Refresh"), self)
        self.refresh_button.clicked.connect(lambda _checked=False: self.refresh())
        top.addWidget(self.refresh_button)
        self.layout_.addLayout(top)
        self.table = QTableWidget(0, len(self.COLUMNS), self)
        self.table.setHorizontalHeaderLabels([tr(c) for c in self.COLUMNS])
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        from ui.column_fit import ColumnFitter

        # Package takes the free width; every divider stays draggable.
        self._columns = ColumnFitter(self.table, fill=0)
        self.table.doubleClicked.connect(lambda _index: self.details())
        self.layout_.addWidget(self.table, 1)
        buttons = QHBoxLayout()
        self.buttons = {}
        for key, label, slot in (("details", "Details…", self.details), ("start", "Start", self.start),
                                 ("stop", "Stop", self.stop), ("uninstall", "Uninstall…", self.uninstall),
                                 ("install", "Install APK…", self.install),
                                 ("backup", "Back Up APK…", self.backup)):
            button = QPushButton(tr(label), self)
            button.clicked.connect(lambda _checked=False, s=slot: s())
            buttons.addWidget(button)
            self.buttons[key] = button
        buttons.addStretch(1)
        self.layout_.addLayout(buttons)
        self.finish_layout()
        self.apps: list[dict] = []

    def refresh(self, *, keep_note: bool = False) -> None:
        kind = self.kind.currentData()
        self.run(lambda tools: tools.list_apps({"kind": kind, "max_results": A.MAX_APPS}),
                 lambda out: self._listed(out, keep_note), keep_note=keep_note)

    def _listed(self, out, keep_note: bool = False) -> None:
        self.apps = out["apps"]
        self._fill()
        if not keep_note:
            self.note.setText(tr("{count} apps").format(count=out["count"]))

    def _fill(self) -> None:
        wanted = self.filter_edit.text().strip().lower()
        rows = [a for a in self.apps if wanted in a["package"].lower()]
        self.table.setRowCount(len(rows))
        for row, app in enumerate(rows):
            self.table.setItem(row, 0, _cell(app["package"]))
            self.table.setItem(row, 1, _cell(app["version_code"]))
            self.table.setItem(row, 2, _cell(app["installer"]))
            self.table.setItem(row, 3, _cell(tr("system") if app["system"] else tr("user")))
            self.table.setItem(row, 4, _cell(tr("enabled") if app["enabled"] else tr("disabled")))

    def selected(self) -> str | None:
        row = self.table.currentRow()
        item = self.table.item(row, 0) if row >= 0 else None
        if item is None:
            self.note.setText(tr("Select an app first."))
            return None
        return item.text()

    def details(self) -> None:
        package = self.selected()
        if package is None:
            return
        self.run(lambda tools: tools.app_info({"package": package}),
                 lambda info: AppInfoDialog(self, info).exec())

    def start(self) -> None:
        package = self.selected()
        if package is None or not self.confirm(
                tr("Start"), tr("Start {package} on the device?").format(package=package),
                tr("start {package}").format(package=package)):
            return
        self.run(lambda tools: tools.start_app({"package": package}),
                 lambda out: self.note.setText(tr("{package} started.").format(package=package)))

    def stop(self) -> None:
        package = self.selected()
        if package is None or not self.confirm(
                tr("Stop"), tr("Force-stop {package}? What it has not saved is lost.").format(
                    package=package), tr("force-stop {package}").format(package=package)):
            return
        self.run(lambda tools: tools.stop_app({"package": package}),
                 lambda out: self.note.setText(tr("{package} stopped.").format(package=package)))

    def uninstall(self) -> None:
        package = self.selected()
        if package is None or not self.confirm(
                tr("Uninstall"), tr("Uninstall {package} and everything it stored? This cannot "
                                    "be undone.").format(package=package),
                tr("uninstall {package}").format(package=package), countdown=True):
            return

        def done(_out):
            self.note.setText(tr("{package} uninstalled.").format(package=package))
            self.refresh_later()

        self.run(lambda tools: tools.uninstall_app({"package": package}), done)

    def refresh_later(self) -> None:
        """The list again after a change, the change's note kept."""
        QTimer.singleShot(0, lambda: self.refresh(keep_note=True))

    def install(self) -> None:
        path, _filter = QFileDialog.getOpenFileName(self, tr("Install APK"), "",
                                                    tr("Android apps (*.apk)"))
        if not path or not self.confirm(
                tr("Install APK"), tr("Install {name} on the device? An installed app of that "
                                      "package is updated.").format(name=os.path.basename(path)),
                tr("install {name}").format(name=os.path.basename(path))):
            return

        def done(_out):
            self.note.setText(tr("{name} installed.").format(name=os.path.basename(path)))
            self.refresh_later()

        real = os.path.realpath(path)  # picked by a person: a link of theirs is fine
        self.run(lambda tools: tools.install_app({}, real, one_name=False), done)

    def backup(self) -> None:
        package = self.selected()
        if package is None:
            return
        folder = QFileDialog.getExistingDirectory(self, tr("Back Up APK to"))
        if not folder:
            return

        def place(name, write):
            target = _free_local_name(folder, name)
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            with os.fdopen(os.open(target, flags, 0o644), "wb") as fh:
                try:
                    write(fh)
                except BaseException:
                    fh.close()
                    os.unlink(target)
                    raise
            return target, os.path.getsize(target)

        self.run(lambda tools: tools.export_app({"package": package}, place),
                 lambda out: self.note.setText(tr("{count} files saved in {folder}.").format(
                     count=len(out["files"]), folder=folder)))


def _free_local_name(folder: str, name: str) -> str:
    """``folder/name``, or ``name (2)`` ... when it is taken; *name* is
    the device's (a package and an APK name) and holds no folder."""
    name = os.path.basename(name.replace("\\", "/")) or "app.apk"
    stem, ext = os.path.splitext(name)
    for n in range(1, 10_000):
        candidate = os.path.join(folder, name if n == 1 else f"{stem} ({n}){ext}")
        if not os.path.lexists(candidate):
            return candidate
    raise OSError(f"no free name for {name} in {folder}")


class AppInfoDialog(QDialog):
    """One app's details and runtime permissions, with Grant / Revoke."""

    def __init__(self, tab: AppsTab, info: dict) -> None:
        super().__init__(tab)
        from ui.close_corner import add_close_corner
        from ui.icon_provider import set_window_icon

        set_window_icon(self, "android")
        self.tab = tab
        self.info = info
        self.setWindowTitle(tr("App: {package}").format(package=info["package"]))
        layout = QVBoxLayout(self)
        form = QFormLayout()
        for key, label in (("version_name", "Version"), ("version_code", "Version code"),
                           ("target_sdk", "Target SDK"), ("installer", "Installer"),
                           ("first_install_time", "Installed"), ("last_update_time", "Updated"),
                           ("uid", "UID")):
            value = QLabel("–" if info.get(key) in (None, "") else str(info[key]), self)
            value.setTextFormat(Qt.TextFormat.PlainText)
            form.addRow(tr(label), value)
        layout.addLayout(form)
        if not info.get("consistent", True):
            warning = QLabel(info.get("note", ""), self)
            warning.setTextFormat(Qt.TextFormat.PlainText)
            warning.setWordWrap(True)
            layout.addWidget(warning)
        self.table = QTableWidget(0, 2, self)
        self.table.setHorizontalHeaderLabels([tr("Permission"), tr("Granted")])
        from ui.column_fit import ColumnFitter

        self._columns = ColumnFitter(self.table, fill=0)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        perms = info.get("runtime_permissions", [])
        self.table.setRowCount(len(perms))
        for row, perm in enumerate(perms):
            self.table.setItem(row, 0, _cell(perm["name"]))
            self.table.setItem(row, 1, _cell(tr("yes") if perm["granted"] else tr("no")))
        layout.addWidget(self.table, 1)
        row = QHBoxLayout()
        self.grant_button = QPushButton(tr("Grant…"), self)
        self.grant_button.clicked.connect(lambda _checked=False: self.change("grant"))
        self.revoke_button = QPushButton(tr("Revoke…"), self)
        self.revoke_button.clicked.connect(lambda _checked=False: self.change("revoke"))
        row.addWidget(self.grant_button)
        row.addWidget(self.revoke_button)
        row.addStretch(1)
        close = QPushButton(tr("Close"), self)
        close.clicked.connect(self.accept)
        row.addWidget(close)
        layout.addLayout(row)
        self.resize(560, 480)
        add_close_corner(self)

    def change(self, verb: str) -> None:
        row = self.table.currentRow()
        item = self.table.item(row, 0) if row >= 0 else None
        if item is None:
            return
        permission, package = item.text(), self.info["package"]
        if verb == "grant":
            ok = self.tab.confirm(tr("Grant"), tr("Grant {permission} to {package}?").format(
                permission=permission, package=package),
                tr("grant {permission} to {package}").format(permission=permission, package=package))
        else:
            ok = self.tab.confirm(tr("Revoke"), tr("Revoke {permission} of {package}? Android ends "
                                                   "the app; what it has not saved is lost.").format(
                permission=permission, package=package),
                tr("revoke {permission} of {package}").format(permission=permission, package=package))
        if not ok:
            return
        method = "grant_permission" if verb == "grant" else "revoke_permission"

        def done(out, row=row):
            granted = out.get("granted")
            self.table.setItem(row, 1, _cell("?" if granted is None else tr("yes") if granted else tr("no")))

        self.tab.run(lambda tools: getattr(tools, method)({"package": package, "permission": permission}),
                     done)


# ---------------------------------------------------------------------------
# SMS
# ---------------------------------------------------------------------------

class SmsTab(_Tab):
    def __init__(self, window) -> None:
        super().__init__(window)
        top = QHBoxLayout()
        self.box = QComboBox(self)
        for box, label in (("inbox", "Inbox"), ("sent", "Sent"), ("draft", "Drafts"), ("all", "All")):
            self.box.addItem(tr(label), box)
        top.addWidget(self.box)
        self.read_button = QPushButton(tr("Read Messages"), self)
        self.read_button.setToolTip(tr("Messages are private; Android lets the shell read them on "
                                       "some builds only"))
        self.read_button.clicked.connect(lambda _checked=False: self.refresh())
        top.addWidget(self.read_button)
        top.addStretch(1)
        self.layout_.addLayout(top)
        self.table = QTableWidget(0, 3, self)
        self.table.setHorizontalHeaderLabels([tr("Date"), tr("From / To"), tr("Text")])
        from ui.column_fit import ColumnFitter

        self._columns = ColumnFitter(self.table, fill=2)  # the text takes the free width
        self.layout_.addWidget(self.table, 1)
        row = QHBoxLayout()
        self.write_button = QPushButton(tr("Write into Store…"), self)
        self.write_button.setToolTip(tr("Store a message on the device without sending it"))
        self.write_button.clicked.connect(lambda _checked=False: self.write())
        self.send_button = QPushButton(tr("Prepare SMS…"), self)
        self.send_button.setToolTip(tr("Open the phone's SMS app with number and text; a person "
                                       "at the phone taps Send"))
        self.send_button.clicked.connect(lambda _checked=False: self.prepare())
        row.addWidget(self.write_button)
        row.addWidget(self.send_button)
        row.addStretch(1)
        self.layout_.addLayout(row)
        self.finish_layout()

    def refresh(self) -> None:
        box = self.box.currentData()
        self.run(lambda tools: tools.list_sms({"box": box, "max_results": A.SMS_MAX_LIMIT}),
                 self._listed)

    def _listed(self, out) -> None:
        messages = out["messages"]
        self.table.setRowCount(len(messages))
        for row, msg in enumerate(messages):
            self.table.setItem(row, 0, _cell((msg["date"] or "").replace("T", " ").rstrip("Z")))
            self.table.setItem(row, 1, _cell(msg["address"]))
            self.table.setItem(row, 2, _cell((msg["body"] or "").replace("\n", " ")))
        self.note.setText(tr("{shown} of {count} messages").format(shown=len(messages),
                                                                    count=out["count"]))

    def _ask(self, title: str, who: str) -> tuple[str, str] | None:
        dialog = SmsDialog(self, title, who)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return None
        return dialog.who.text().strip(), dialog.text.toPlainText()

    def write(self) -> None:
        got = self._ask(tr("Write into Store"), tr("Sender or recipient"))
        if got is None:
            return
        address, body = got
        if not self.confirm(tr("Write into Store"), tr("Store a message from or to {address} on the "
                                                       "device? Nothing is sent.").format(address=address),
                            tr("write an SMS into the store")):
            return
        self.run(lambda tools: tools.write_sms({"address": address, "body": body}),
                 lambda out: self.note.setText(tr("Stored.") if out.get("stored")
                                               else out.get("note", "")))

    def prepare(self) -> None:
        got = self._ask(tr("Prepare SMS"), tr("Number"))
        if got is None:
            return
        number, text = got
        if not self.confirm(tr("Prepare SMS"), tr("Open the SMS app on the phone with a message to "
                                                  "{number}? axross does not send it: a person at "
                                                  "the phone taps Send.").format(number=number),
                            tr("prepare an SMS to {number}").format(number=number)):
            return
        self.run(lambda tools: tools.compose_sms({"number": number, "text": text}),
                 lambda out: self.note.setText(tr("The SMS app is open on the phone; nothing "
                                                  "has been sent.")))


class SmsDialog(QDialog):
    """An address or number, and a text."""

    def __init__(self, parent: QWidget, title: str, who: str) -> None:
        super().__init__(parent)
        from ui.close_corner import add_close_corner
        from ui.icon_provider import set_window_icon

        set_window_icon(self, "chat")
        self.setWindowTitle(title)
        layout = QFormLayout(self)
        self.who = QLineEdit(self)
        self.who.setMaxLength(40)
        layout.addRow(who, self.who)
        self.text = QPlainTextEdit(self)
        layout.addRow(tr("Text"), self.text)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok
                                   | QDialogButtonBox.StandardButton.Cancel, self)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addRow(buttons)
        add_close_corner(self)


# ---------------------------------------------------------------------------
# Logcat
# ---------------------------------------------------------------------------

class LogcatTab(_Tab):
    def __init__(self, window) -> None:
        super().__init__(window)
        top = QHBoxLayout()
        self.priority = QComboBox(self)
        for code, label in (("V", "Verbose"), ("D", "Debug"), ("I", "Info"), ("W", "Warning"),
                            ("E", "Error"), ("F", "Fatal")):
            self.priority.addItem(tr(label), code)
        top.addWidget(self.priority)
        self.tag = QLineEdit(self)
        self.tag.setPlaceholderText(tr("Tag"))
        top.addWidget(self.tag)
        self.package = QLineEdit(self)
        self.package.setPlaceholderText(tr("App package"))
        top.addWidget(self.package)
        self.lines = QSpinBox(self)
        self.lines.setRange(10, A.LOGCAT_MAX_LINES)
        self.lines.setValue(300)
        self.lines.setSuffix(tr(" lines"))
        top.addWidget(self.lines)
        self.refresh_button = QPushButton(tr("Read"), self)
        self.refresh_button.clicked.connect(lambda _checked=False: self.refresh())
        top.addWidget(self.refresh_button)
        self.follow = QCheckBox(tr("Follow"), self)
        self.follow.toggled.connect(self._follow_toggled)
        top.addWidget(self.follow)
        self.pause_button = QPushButton(tr("Pause"), self)
        self.pause_button.setCheckable(True)
        top.addWidget(self.pause_button)
        self.save_button = QPushButton(tr("Save…"), self)
        self.save_button.clicked.connect(lambda _checked=False: self.save())
        top.addWidget(self.save_button)
        self.layout_.addLayout(top)
        self.view = QPlainTextEdit(self)
        self.view.setReadOnly(True)
        self.view.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.view.setMaximumBlockCount(A.LOGCAT_MAX_LINES)
        self.layout_.addWidget(self.view, 1)
        self.finish_layout()
        self.timer = QTimer(self)
        self.timer.setInterval(FOLLOW_MS)
        self.timer.timeout.connect(self._tick)

    def _follow_toggled(self, on: bool) -> None:
        if on:
            self.timer.start()
            self.refresh()
        else:
            self.timer.stop()

    def _tick(self) -> None:
        if not self.pause_button.isChecked() and not self.job.running and self.isVisible():
            self.refresh()

    def args(self) -> dict:
        args = {"max_lines": self.lines.value(), "min_priority": self.priority.currentData()}
        if self.tag.text().strip():
            args["tag"] = self.tag.text().strip()
        if self.package.text().strip():
            args["package"] = self.package.text().strip()
        return args

    def refresh(self) -> None:
        args = self.args()
        self.run(lambda tools: tools.logcat(args), self._show)

    def _show(self, out) -> None:
        if self.pause_button.isChecked():
            return
        bar = self.view.verticalScrollBar()
        at_end = bar.value() >= bar.maximum() - 2
        self.view.setPlainText("\n".join(out["lines"]))
        if at_end:
            bar.setValue(bar.maximum())
        self.note.setText(tr("{count} lines").format(count=out["count"]))

    def save(self) -> None:
        path, _filter = QFileDialog.getSaveFileName(self, tr("Save Log"), "logcat.txt",
                                                    tr("Text files (*.txt)"))
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(self.view.toPlainText() + "\n")
        except OSError as exc:
            self.note.setText(_error_text(exc))
            return
        self.note.setText(tr("Saved as {path}.").format(path=path))


# ---------------------------------------------------------------------------
# Screenshot
# ---------------------------------------------------------------------------

class ScreenshotTab(_Tab):
    def __init__(self, window) -> None:
        super().__init__(window)
        top = QHBoxLayout()
        self.take_button = QPushButton(tr("Take Screenshot"), self)
        self.take_button.clicked.connect(lambda _checked=False: self.take())
        top.addWidget(self.take_button)
        self.save_button = QPushButton(tr("Save…"), self)
        self.save_button.setEnabled(False)
        self.save_button.clicked.connect(lambda _checked=False: self.save())
        top.addWidget(self.save_button)
        top.addStretch(1)
        self.layout_.addLayout(top)
        self.image = QLabel(tr("No screenshot yet."), self)
        self.image.setAlignment(Qt.AlignmentFlag.AlignCenter)
        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        scroll.setWidget(self.image)
        self.layout_.addWidget(scroll, 1)
        self.finish_layout()
        self.png = b""

    def take(self) -> None:
        self.run(lambda tools: tools.screenshot(), self._show)

    def _show(self, out) -> None:
        pixmap = QPixmap()
        if not pixmap.loadFromData(out["png"], "PNG"):
            self.note.setText(tr("The device sent no image that can be shown."))
            return
        self.png = out["png"]
        target = self.image.parentWidget().size() if self.image.parentWidget() else self.image.size()
        if pixmap.height() > max(200, target.height()):
            pixmap = pixmap.scaledToHeight(max(200, target.height()),
                                           Qt.TransformationMode.SmoothTransformation)
        self.image.setPixmap(pixmap)
        self.save_button.setEnabled(True)
        self.note.setText(tr("{width} × {height} pixels").format(width=out["width"],
                                                                height=out["height"]))

    def save(self) -> None:
        if not self.png:
            return
        path, _filter = QFileDialog.getSaveFileName(self, tr("Save Screenshot"), "screenshot.png",
                                                    tr("PNG images (*.png)"))
        if not path:
            return
        try:
            with open(path, "wb") as fh:
                fh.write(self.png)
        except OSError as exc:
            self.note.setText(_error_text(exc))
            return
        self.note.setText(tr("Saved as {path}.").format(path=path))


# ---------------------------------------------------------------------------
# The window
# ---------------------------------------------------------------------------

class AndroidDeviceWindow(QDialog):
    """The Android Device window of one ADB connection (not modal)."""

    def __init__(self, backend, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        from ui.close_corner import add_close_corner
        from ui.icon_provider import set_window_icon

        self.backend = backend
        self.countdown_s = COUNTDOWN_S
        self.setModal(False)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose, True)
        set_window_icon(self, "android")
        name = getattr(getattr(backend, "_axross_profile", None), "name", "") or \
            getattr(backend, "name", "") or "ADB"
        self.setWindowTitle(tr("Android Device – {name}").format(name=name))
        layout = QVBoxLayout(self)
        self.tabs = QTabWidget(self)
        self.info_tab = InfoTab(self)
        self.apps_tab = AppsTab(self)
        self.sms_tab = SmsTab(self)
        self.logcat_tab = LogcatTab(self)
        self.screenshot_tab = ScreenshotTab(self)
        for tab, label in ((self.info_tab, "Info"), (self.apps_tab, "Apps"), (self.sms_tab, "SMS"),
                           (self.logcat_tab, "Logcat"), (self.screenshot_tab, "Screenshot")):
            self.tabs.addTab(tab, tr(label))
        layout.addWidget(self.tabs)
        self._loaded: set[int] = set()
        self.tabs.currentChanged.connect(self._first_look)
        if not _changes_allowed():
            for button in (self.info_tab.reboot_button, *(
                    self.apps_tab.buttons[k] for k in ("start", "stop", "uninstall", "install")),
                    self.sms_tab.write_button, self.sms_tab.send_button):
                button.setEnabled(False)
                button.setToolTip(tr("The paranoid security mode turns changes on a device off."))
        self.resize(860, 600)
        add_close_corner(self)
        self._first_look(0)

    def _first_look(self, index: int) -> None:
        """A tab reads the device the first time it is shown (Info, Apps);
        SMS, the log and the screen only when asked."""
        if index in self._loaded:
            return
        self._loaded.add(index)
        tab = self.tabs.widget(index)
        if tab is self.info_tab:
            tab.refresh()
        elif tab is self.apps_tab:
            tab.refresh()

    def jobs(self) -> list[ScanJob]:
        return [self.tabs.widget(i).job for i in range(self.tabs.count())]

    def done(self, result: int) -> None:  # noqa: D102 - stop the jobs with the window
        for job in self.jobs():
            job.abandon()
        self.logcat_tab.timer.stop()
        super().done(result)

    def closeEvent(self, event) -> None:  # noqa: N802 - Qt override
        for job in self.jobs():
            job.abandon()
        self.logcat_tab.timer.stop()
        super().closeEvent(event)


__all__ = ["AndroidDeviceWindow", "CountdownDialog", "is_android", "open_for"]
