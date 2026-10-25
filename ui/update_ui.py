"""The self-update in the window (core.self_update does the work).

* :class:`UpdateController` - one per main window: the check at start (once,
  in the background, after the window is shown; a failure is a log line and
  the status on Settings > Updates, never a dialog), Help > Check for
  Updates…, the download, Skip This Version, Remind Me Later, Restart Now.
* The notice: a button at the right of the status bar and a Help menu entry,
  "Update to X.Y.Z…", shown only when a newer version is there; both open
* :class:`UpdateDialog` - not modal: the versions, the release notes, a link
  to the release page and the buttons.
* :class:`UpdatesPage` - Settings > Updates.
"""

from __future__ import annotations

import html
import logging
import time
import types
from pathlib import Path

from PyQt6.QtCore import QObject, Qt, QTimer, pyqtSignal
from PyQt6.QtWidgets import (
    QApplication,
    QCheckBox,
    QDialog,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from core import self_update as SU
from core.i18n import tr
from ui.close_corner import add_close_corner
from ui.scan_job import ScanJob
from ui.settings_dialog import _FormPage, _note

log = logging.getLogger(__name__)

#: Milliseconds between the window appearing and the check at start.
START_CHECK_DELAY_MS = 2000

#: Controller states.
IDLE, CHECKING, CURRENT, AVAILABLE, ERROR, DOWNLOADING, INSTALLED, FINISH = (
    "idle", "checking", "current", "available", "error", "downloading", "installed", "finish")


def schedule_start_check(window, delay_ms: int = START_CHECK_DELAY_MS) -> None:
    """The check at start, *delay_ms* after the event loop runs (main.py
    calls this once the window is shown)."""
    QTimer.singleShot(delay_ms, window.start_update_check)


class UpdateController(QObject):
    """The update state of one window; ``changed`` after every step."""

    changed = pyqtSignal()

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        #: Builds the urllib opener of a request (tests hand in a fake).
        self.opener_factory = SU.build_opener
        #: This process's Install, found on first use (tests set it).
        self.install_info: SU.Install | None = None
        from axross._version import __version__

        self.current_version = __version__
        self.state = IDLE
        self.message = ""
        self.release: SU.Release | None = None
        self.result: SU.Installed | None = None
        self.progress = (0, 0)
        self._manual = False
        self._dismissed = False
        self._start_check_ran = False
        self._check_job = ScanJob(self)
        self._check_job.finished.connect(self._on_checked)
        self._download_job = ScanJob(self, formatter=self._progress_text)
        self._download_job.progress.connect(lambda _text: self.changed.emit())
        self._download_job.finished.connect(self._on_downloaded)

    # -- what the window shows ------------------------------------------------------
    def install(self) -> SU.Install:
        if self.install_info is None:
            self.install_info = SU.detect_install()
        return self.install_info

    def notice_visible(self) -> bool:
        return self.state in (AVAILABLE, DOWNLOADING, INSTALLED, FINISH) and not self._dismissed

    def notice_text(self) -> str:
        version = self.release.version if self.release else ""
        if self.state == DOWNLOADING:
            done, total = self.progress
            percent = int(done * 100 / total) if total else 0
            return tr("Downloading {version}… {percent} %").format(version=version,
                                                                   percent=percent)
        if self.state == INSTALLED:
            return tr("Restart to Use {version}…").format(version=version)
        if self.state == FINISH:
            return tr("Finish the Update to {version}…").format(version=version)
        return tr("Update to {version}…").format(version=version)

    def _progress_text(self, state: dict) -> str:
        self.progress = (state.get("scanned", 0), state.get("indexed", 0))
        return ""

    def _set(self, state: str, message: str) -> None:
        self.state, self.message = state, message
        self.changed.emit()

    # -- the check --------------------------------------------------------------------
    def start_check(self) -> bool:
        """The check at start: once per start, only when Settings > Updates,
        the environment and the security mode allow it."""
        if self._start_check_ran:
            return False
        self._start_check_ran = True
        allowed, reason = SU.start_check_allowed()
        if not allowed:
            log.info("update check at start skipped: %s", reason)
            return False
        return self._check(manual=False)

    def check_now(self) -> bool:
        """Help > Check for Updates…, Settings > Updates > Check Now."""
        return self._check(manual=True)

    def _check(self, *, manual: bool) -> bool:
        if self._check_job.running or self.state == DOWNLOADING:
            return False
        self._manual = manual
        factory, current = self.opener_factory, self.current_version

        def work(_cancel, _report):
            return SU.check(current, opener=factory())

        self._set(CHECKING, tr("Checking for updates…"))
        self._check_job.start(work)
        return True

    def _on_checked(self, kind: str, value, _cancelled: bool) -> None:
        if kind == "error":
            reason = str(value) if isinstance(value, SU.UpdateError) else repr(value)
            log.warning("update check failed: %s", reason)
            message = tr("The update check failed: {reason}").format(reason=reason)
            SU.record_check(message)
            self._set(ERROR, message)
            return
        result: SU.CheckResult = value
        SU.record_check(result.message)
        self.release = result.release
        if not result.newer:
            log.info("update check: %s", result.message)
            self._set(CURRENT, result.message)
            return
        log.info("update check: %s", result.message)
        done = self.result
        if done is not None and done.version == result.release.version:
            # Already downloaded in this run: keep Restart Now / Save to….
            self._set(INSTALLED if done.replaced else FINISH, self._finished_message(done))
            return
        skipped = SU.skipped_version() == result.release.version
        self._dismissed = skipped and not self._manual
        inst = self.install()
        message = result.message
        if not inst.can_download:
            message += "\n" + inst.why_not()
        self._set(AVAILABLE, message)
        if not self._manual and not skipped and SU.auto_download() and inst.can_download:
            self.download()

    # -- the download -----------------------------------------------------------------
    def download(self) -> bool:
        if self.release is None or self._download_job.running or self.state == DOWNLOADING:
            return False
        inst = self.install()
        if not inst.can_download:
            self._set(AVAILABLE, inst.why_not())
            return False
        release, factory = self.release, self.opener_factory
        asset = release.asset(inst.asset)
        self.progress = (0, asset.size if asset else 0)

        def work(cancel, report):
            flag = types.SimpleNamespace(is_set=cancel)
            return SU.update(release, inst, opener=factory(), cancel=flag,
                             progress=lambda done, total: report(done, total, ""))

        self._dismissed = False
        self._set(DOWNLOADING, tr("Downloading {name} {version}…").format(
            name=inst.asset, version=release.version))
        self._download_job.start(work)
        return True

    def cancel_download(self) -> None:
        self._download_job.cancel()

    def _on_downloaded(self, kind: str, value, _cancelled: bool) -> None:
        if kind == "error":
            if isinstance(value, SU.Cancelled):
                message = tr("The download was cancelled; nothing was changed.")
            else:
                reason = str(value) if isinstance(value, SU.UpdateError) else repr(value)
                log.warning("update download failed: %s", reason)
                message = tr("The download failed: {reason}. Nothing was changed.").format(
                    reason=reason.rstrip("."))
            self._set(AVAILABLE, message)
            return
        self.result = value
        self._set(INSTALLED if value.replaced else FINISH, self._finished_message(value))

    @staticmethod
    def _finished_message(result: SU.Installed) -> str:
        if not result.replaced:
            return result.how_to_finish
        return tr("axross {version} is installed in {path} and takes effect at the next "
                  "start. The old version is kept as {previous}.").format(
                      version=result.version, path=result.path,
                      previous=result.previous.name if result.previous else "-")

    # -- the answers ------------------------------------------------------------------
    def skip_version(self) -> None:
        if self.release is not None:
            SU.set_skipped_version(self.release.version)
        self._dismissed = True
        self.changed.emit()

    def remind_later(self) -> None:
        self._dismissed = True
        self.changed.emit()

    def can_save_copy(self) -> bool:
        return self.state == FINISH and self.result is not None and \
            self.result.path.parent == SU.cache_dir()

    def save_to(self, destination) -> Path:
        saved = SU.save_copy(self.result, destination)
        self.message = tr("The new version is saved as {path}. Replace your axross binary "
                          "with it to finish the update.").format(path=saved)
        self.changed.emit()
        return saved

    def restart_now(self, window) -> bool:
        """Close *window* (it may still ask about unsaved work), start the
        installed binary, quit. Only after a verified install."""
        if self.state != INSTALLED or self.result is None or not self.result.replaced:
            return False
        path, sha256 = self.result.path, self.result.sha256
        try:  # before the window closes: a refusal can still be shown
            SU.check_restartable(path, sha256)
        except (SU.UpdateError, OSError) as exc:
            log.error("restart into the new version refused: %s", exc)
            self._set(INSTALLED, tr("Restart Now is refused: {reason}").format(reason=exc))
            return False
        if not window.close():
            return False
        try:
            SU.restart(path, expected_sha256=sha256)
        except (SU.UpdateError, OSError) as exc:
            log.error("restart into the new version failed: %s", exc)
            return False
        QApplication.quit()
        return True

    def shutdown(self) -> None:
        """The window closes: a running check or download stops (a partial
        file is removed by the download itself)."""
        self._check_job.abandon()
        self._download_job.abandon()


class UpdateDialog(QDialog):
    """Help > Check for Updates…, and what the notice opens."""

    def __init__(self, controller: UpdateController, window, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle(tr("Software Update"))
        self.resize(620, 460)
        self._controller = controller
        self._window = window
        self.status_label = QLabel()
        self.status_label.setWordWrap(True)
        self.status_label.setTextFormat(Qt.TextFormat.PlainText)
        self.status_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.version_label = QLabel()
        self.version_label.setProperty("role", "muted")
        self.version_label.setWordWrap(True)
        self.notes = QPlainTextEdit()
        self.notes.setReadOnly(True)
        self.link_label = QLabel()
        self.link_label.setTextFormat(Qt.TextFormat.RichText)
        self.link_label.setTextInteractionFlags(Qt.TextInteractionFlag.LinksAccessibleByMouse)
        self.link_label.linkActivated.connect(self._open_link)
        self.progress_bar = QProgressBar()

        self.download_button = QPushButton(tr("Download"))
        self.download_button.clicked.connect(controller.download)
        self.cancel_button = QPushButton(tr("Cancel Download"))
        self.cancel_button.clicked.connect(controller.cancel_download)
        self.skip_button = QPushButton(tr("Skip This Version"))
        self.skip_button.clicked.connect(self._skip)
        self.later_button = QPushButton(tr("Remind Me Later"))
        self.later_button.clicked.connect(self._later)
        self.restart_button = QPushButton(tr("Restart Now"))
        self.restart_button.setToolTip(tr("Close axross and start the new version"))
        self.restart_button.clicked.connect(lambda: controller.restart_now(self._window))
        self.save_button = QPushButton(tr("Save to…"))
        self.save_button.clicked.connect(self._save)
        self.check_button = QPushButton(tr("Check Again"))
        self.check_button.clicked.connect(controller.check_now)
        self.close_button = QPushButton(tr("Close"))
        self.close_button.clicked.connect(self.close)

        buttons = QHBoxLayout()
        for button in (self.download_button, self.cancel_button, self.restart_button,
                       self.save_button, self.check_button, self.skip_button, self.later_button):
            buttons.addWidget(button)
        buttons.addStretch(1)
        buttons.addWidget(self.close_button)
        layout = QVBoxLayout(self)
        layout.addWidget(self.status_label)
        layout.addWidget(self.version_label)
        layout.addWidget(self.notes, 1)
        layout.addWidget(self.link_label)
        layout.addWidget(self.progress_bar)
        layout.addLayout(buttons)
        add_close_corner(self)
        controller.changed.connect(self.refresh)
        self.refresh()

    def refresh(self) -> None:
        c = self._controller
        inst = c.install()
        release = c.release
        self.status_label.setText(c.message or tr("No update check has run yet."))
        kind = inst.title if inst.frozen else tr("Python installation")
        self.version_label.setText(tr("This version: {version} ({kind})").format(
            version=c.current_version, kind=kind))
        has_notes = release is not None and bool(release.notes)
        self.notes.setVisible(has_notes)
        if has_notes and self.notes.toPlainText() != release.notes:
            self.notes.setPlainText(release.notes)
        self.link_label.setVisible(release is not None)
        if release is not None:
            self.link_label.setText(
                f'<a href="{html.escape(release.page_url, quote=True)}">'
                + html.escape(tr("Release notes of {version} on GitHub").format(
                    version=release.version))
                + "</a>")
        available = c.state == AVAILABLE
        self.download_button.setVisible(available and inst.can_download)
        self.download_button.setText(
            tr("Download and Install") if inst.can_self_replace else tr("Download"))
        self.skip_button.setVisible(available)
        self.later_button.setVisible(available)
        downloading = c.state == DOWNLOADING
        self.cancel_button.setVisible(downloading)
        self.progress_bar.setVisible(downloading)
        if downloading:
            done, total = c.progress
            self.progress_bar.setRange(0, max(1, total // 1024))
            self.progress_bar.setValue(min(done, total) // 1024)
        self.restart_button.setVisible(c.state == INSTALLED)
        self.save_button.setVisible(c.can_save_copy())
        self.check_button.setVisible(c.state in (IDLE, CURRENT, ERROR))
        self.check_button.setEnabled(c.state != CHECKING)

    def _open_link(self, url: str) -> None:
        from PyQt6.QtCore import QUrl

        from core import desktop_open

        desktop_open.open_url(QUrl(url))

    def _skip(self) -> None:
        self._controller.skip_version()
        self.close()

    def _later(self) -> None:
        self._controller.remind_later()
        self.close()

    def _save(self) -> None:
        result = self._controller.result
        if result is None:
            return
        start = str(Path.home() / result.path.name)
        path, _filter = QFileDialog.getSaveFileName(self, tr("Save the New Version"), start)
        if not path:
            return
        try:
            self._controller.save_to(path)
        except (SU.UpdateError, OSError) as exc:
            self.status_label.setText(tr("Could not save it: {reason}").format(reason=exc))

    def closeEvent(self, event) -> None:  # noqa: N802 - Qt
        try:
            self._controller.changed.disconnect(self.refresh)
        except TypeError:
            pass
        super().closeEvent(event)


def _when(stamp: float | None) -> str:
    if stamp is None:
        return tr("Never")
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(stamp))


def updates_page(parent, window):
    """The factory of Settings > Updates (ui.settings_dialog)."""
    return UpdatesPage(window, parent)


class UpdatesPage(_FormPage):
    """Check at start, download automatically, Check Now, the last check."""

    def __init__(self, window, parent: QWidget | None = None) -> None:
        super().__init__(window, parent)
        self.check_box = QCheckBox(tr("Check for updates at start"))
        self.check_box.setToolTip(tr(
            "One request to api.github.com, in the background, after the window is shown"))
        self.check_box.setChecked(SU.check_at_start())
        self.auto_box = QCheckBox(tr("Download updates automatically"))
        self.auto_box.setToolTip(tr(
            "Download, verify and install a new version found at start; it takes effect at "
            "the next start. Off: the window offers a Download button."))
        self.auto_box.setChecked(SU.auto_download())
        self.check_now_button = QPushButton(tr("Check Now"))
        self.check_now_button.clicked.connect(self.check_now)
        self.last_label = QLabel()
        self.last_label.setWordWrap(True)
        self.last_label.setTextFormat(Qt.TextFormat.PlainText)
        form = QFormLayout()
        form.addRow(tr("Start"), self.check_box)
        form.addRow("", self.auto_box)
        row = QHBoxLayout()
        row.addWidget(self.check_now_button)
        row.addWidget(self.last_label, 1)
        form.addRow(tr("Last check"), row)
        self.layout_.addLayout(form)
        allowed, reason = SU.start_check_allowed()
        self.start_note = _note(
            "" if allowed or not self.check_box.isChecked()
            else tr("The check at start does not run: {reason}.").format(reason=reason))
        self.start_note.setVisible(bool(self.start_note.text()))
        self.layout_.addWidget(self.start_note)
        controller = self._controller()
        inst = controller.install() if controller is not None else SU.detect_install()
        if inst.can_self_replace:
            where = tr("An update replaces {path} and keeps the old file as {name}.previous; "
                       "it takes effect at the next start.").format(
                           path=inst.executable, name=inst.executable.name)
        else:
            where = inst.why_not()
        self.install_note = _note(where)
        self.layout_.addWidget(self.install_note)
        self.layout_.addWidget(_note(tr(
            "Only github.com, api.github.com and release-assets.githubusercontent.com are "
            "contacted, over https, through the default proxy (Network & Proxy). A download "
            "is checked against the SHA256SUMS of its release before anything is replaced.")))
        if controller is not None:
            controller.changed.connect(self._show_last)
        self._show_last()
        self._finish()

    def _controller(self) -> UpdateController | None:
        getter = getattr(self._window, "update_controller", None)
        return getter() if callable(getter) else None

    def check_now(self) -> None:
        controller = self._controller()
        if controller is not None:
            controller.check_now()
        self._show_last()

    def _show_last(self) -> None:
        controller = self._controller()
        if controller is not None and controller.state == CHECKING:
            self.last_label.setText(tr("Checking…"))
            self.check_now_button.setEnabled(False)
            return
        self.check_now_button.setEnabled(True)
        when, text = SU.last_check()
        self.last_label.setText(f"{_when(when)} - {text}" if when is not None else tr("Never"))

    def _values(self) -> dict:
        return {"check": self.check_box.isChecked(), "auto": self.auto_box.isChecked()}

    def _store(self, changed: dict) -> None:
        if "check" in changed:
            SU.set_check_at_start(changed["check"])
        if "auto" in changed:
            SU.set_auto_download(changed["auto"])

    def shutdown(self) -> None:
        controller = self._controller()
        if controller is not None:
            try:
                controller.changed.disconnect(self._show_last)
            except TypeError:
                pass


__all__ = [
    "START_CHECK_DELAY_MS",
    "UpdateController",
    "UpdateDialog",
    "UpdatesPage",
    "schedule_start_check",
    "updates_page",
]
