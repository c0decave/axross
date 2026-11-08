"""Help > Features…: every optional feature, installed or missing, and how
to get it (core.features).

Install runs pip in the Python that runs axross, after a question naming
the exact command, with its output in the log; afterwards the features are
asked again. A frozen build cannot pip install: it offers the axross-full
download of the same release. External tools show the package command of
this system to copy - axross never runs a system package manager.

Voices and speech recognition models (group Voice) are no pip packages:
Download Model fetches them on a background thread with pinned SHA-256
sums (core.voice_models) - in a frozen build too. Closing the window
cancels a running download; nothing half-downloaded stays.

A binary with packs (ui/packs_dialog.py, core.packs) asks its release's
signed manifest once the window is open, off the GUI thread: when it was
re-issued (same version, a pack fixed), "Update packs" appears and fetches
the fixed blobs through core.packs.update - the same signature and hash
checks as adding a pack. It asks under the rules of the update check at
start (core.self_update.start_check_allowed: AXROSS_NO_UPDATE_CHECK, the
setting, the paranoid security mode).
"""

from __future__ import annotations

import logging
import threading

from PyQt6.QtCore import QProcess, Qt, QUrl
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QCheckBox,
    QDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
)

from core import features as F
from core.i18n import tr
from core.thread_relay import GuiCall
from ui.close_corner import add_close_corner
from ui.scan_job import ScanJob
from ui.icon_provider import set_window_icon

log = logging.getLogger(__name__)

_COLUMNS = ("Feature", "Group", "Status", "How to get it")


def _qprocess_runner(owner):
    """A runner that starts *cmd* as a QProcess owned by *owner*."""

    def run(cmd, on_output, on_done):
        proc = QProcess(owner)
        proc.setProgram(cmd[0])
        proc.setArguments(cmd[1:])
        proc.setProcessChannelMode(QProcess.ProcessChannelMode.MergedChannels)
        proc.readyReadStandardOutput.connect(
            lambda: on_output(bytes(proc.readAllStandardOutput()).decode("utf-8", "replace"))
        )
        proc.finished.connect(lambda code, _status: on_done(code))
        proc.errorOccurred.connect(
            lambda error: on_done(-1) if error == QProcess.ProcessError.FailedToStart else None
        )
        owner._process = proc
        proc.start()

    return run


def _voice_download(model, progress, cancel):
    from core import voice_models as VM

    return VM.download(model, progress=progress, cancel=cancel)


class FeaturesDialog(QDialog):
    def __init__(self, parent=None, *, runner=None, version: str | None = None,
                 downloader=None, packs: dict | None = None) -> None:
        super().__init__(parent)
        #: fetch / root / verify for core.packs and the Packs window (tests).
        self._packs = dict(packs or {})
        self._packs_release = None
        set_window_icon(self, "features")
        #: ``downloader(model, progress(done, total), cancel_event)``
        self._downloader = downloader or _voice_download
        self._download_cancel: threading.Event | None = None
        self.setWindowTitle(tr("Features"))
        self.resize(980, 620)
        self._runner = runner or _qprocess_runner(self)
        self._process = None
        if version is None:
            from axross import __version__ as version
        self._version = version
        self._features: list[F.Feature] = []
        # collect() runs off the GUI thread (_collect_job): its backend probes
        # import every optional package the first time (~1 s). A feature
        # asked for meanwhile is selected when the answer is in.
        self._loaded = False
        self._pending_select = ""
        self._collect_job = ScanJob(self)
        self._collect_job.finished.connect(self._on_collected)
        self._family = F.system_family()
        root = QVBoxLayout(self)
        top = QHBoxLayout()
        self.missing_only = QCheckBox(tr("Missing only"))
        self.missing_only.toggled.connect(lambda _on: self._fill())
        self.summary = QLabel("")
        top.addWidget(self.missing_only)
        top.addStretch(1)
        top.addWidget(self.summary)
        root.addLayout(top)
        self.table = QTableWidget(0, len(_COLUMNS))
        self.table.setHorizontalHeaderLabels([tr(c) for c in _COLUMNS])
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.itemSelectionChanged.connect(self._update_buttons)
        root.addWidget(self.table, 1)
        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)
        self.log.setMaximumHeight(140)
        self.log.setPlaceholderText(tr("pip output appears here"))
        root.addWidget(self.log)
        self.status = QLabel("")
        self.status.setWordWrap(True)
        root.addWidget(self.status)
        buttons = QHBoxLayout()
        self.install_button = QPushButton(tr("Install Selected"))
        self.install_button.clicked.connect(self.install_selected)
        self.copy_button = QPushButton(tr("Copy Command"))
        self.copy_button.clicked.connect(self.copy_command)
        self.download_button = QPushButton(tr("Download axross-full…"))
        self.download_button.clicked.connect(self._open_download)
        self.download_models_button = QPushButton(tr("Download Model"))
        self.download_models_button.setToolTip(tr(
            "Download the selected voices and speech recognition models (pinned SHA-256)"))
        self.download_models_button.clicked.connect(self.download_selected)
        # A binary adds units from its own signed release (ui/packs_dialog.py).
        self.packs_button = QPushButton(tr("Packs…"))
        self.packs_button.setToolTip(tr("Add or remove parts of axross from this release's packs"))
        self.packs_button.clicked.connect(self._open_packs)
        self.update_packs_button = QPushButton(tr("Update packs"))
        self.update_packs_button.setToolTip(tr(
            "This release's packs were re-issued (a pack fixed): fetch the fixed ones, "
            "checked against the signed release"))
        self.update_packs_button.clicked.connect(self.update_packs)
        close = QPushButton(tr("Close"))
        close.clicked.connect(self.close)
        for button in (self.install_button, self.download_models_button, self.copy_button,
                       self.download_button, self.packs_button, self.update_packs_button):
            buttons.addWidget(button)
        buttons.addStretch(1)
        buttons.addWidget(close)
        root.addLayout(buttons)
        add_close_corner(self)
        self._can_pip, self._why_not = F.can_pip_install()
        self.download_button.setVisible(F.is_frozen())
        self.packs_button.setVisible(F.is_frozen())
        self.update_packs_button.setVisible(False)    # until the release says so
        if not self._can_pip:
            self.status.setText(self._why_not)
        self.reload()
        if F.is_frozen():
            self.check_packs()

    # -- table -----------------------------------------------------------------------------

    @property
    def loaded(self) -> bool:
        """The table shows an answer of collect() (or why there is none)."""
        return self._loaded

    def reload(self) -> None:
        """Ask every feature's state again, off the GUI thread; the table
        keeps the last answer until the new one arrives."""
        self._loaded = False
        self.summary.setText(tr("Checking what is installed…"))
        self._update_buttons()
        self._collect_job.start(lambda _cancel, _progress: F.collect(), replace=True)

    def _on_collected(self, kind: str, value, _cancelled: bool) -> None:
        self._loaded = True
        if kind != "done":
            log.warning("Could not check the features: %s", value)
            self.summary.setText(tr("Could not check the features: {error}").format(error=value))
            self._update_buttons()
            return
        self._features = value
        self._fill()
        key, self._pending_select = self._pending_select, ""
        if key:
            self.select(key)

    def _fill(self) -> None:
        shown = [f for f in self._features if not (self.missing_only.isChecked() and f.available)]
        self.table.setRowCount(len(shown))
        for row, feature in enumerate(shown):
            name = QTableWidgetItem(feature.name)
            name.setData(Qt.ItemDataRole.UserRole, feature)
            if feature.note:
                name.setToolTip(feature.note)
            state = QTableWidgetItem(tr("Installed") if feature.available else tr("Missing"))
            how = QTableWidgetItem("" if feature.available else F.how_to_get(feature, family=self._family))
            for col, item in enumerate((name, QTableWidgetItem(tr(feature.group)), state, how)):
                self.table.setItem(row, col, item)
        self.table.resizeColumnsToContents()
        missing = sum(1 for f in self._features if not f.available)
        self.summary.setText(tr("{n} features, {m} missing").format(n=len(self._features), m=missing))
        self._update_buttons()

    def feature_at(self, row: int) -> F.Feature:
        return self.table.item(row, 0).data(Qt.ItemDataRole.UserRole)

    def _selected(self) -> list[F.Feature]:
        rows = sorted({index.row() for index in self.table.selectedIndexes()})
        return [self.feature_at(row) for row in rows]

    def select(self, key: str) -> None:
        """Show the feature *key* selected (the missing-only filter off) -
        once the features are in, when they are still being checked."""
        if not self._loaded:
            self._pending_select = key
            return
        if not any(f.key == key for f in self._features):
            return
        self.missing_only.setChecked(False)
        for row in range(self.table.rowCount()):
            if self.feature_at(row).key == key:
                self.table.clearSelection()
                self.table.selectRow(row)
                self.table.scrollToItem(self.table.item(row, 0))
                return

    def _update_buttons(self) -> None:
        chosen = self._selected() if self._loaded else []
        pip = [f for f in chosen if f.requirements and not f.available]
        self.install_button.setEnabled(self._can_pip and bool(pip) and self._process is None)
        models = [f for f in chosen if f.download and not f.available]
        self.download_models_button.setEnabled(bool(models) and self._download_cancel is None)
        self.copy_button.setEnabled(any(not f.available for f in chosen))

    # -- actions ---------------------------------------------------------------------------

    def install_selected(self) -> None:
        chosen = [f for f in self._selected() if f.requirements and not f.available]
        if not chosen or not self._can_pip:
            return
        cmd = F.pip_command(chosen)
        where = tr("this virtual environment") if F.in_virtualenv() else tr("the system Python")
        answer = QMessageBox.question(
            self, tr("Install Features"),
            tr("Run this command in {where}?\n\n{cmd}").format(
                where=where, cmd="python -m pip install " + " ".join(cmd[4:])),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        self.log.clear()
        self.log.appendPlainText("$ " + " ".join(cmd))
        self.status.setText(tr("Installing…"))
        self.install_button.setEnabled(False)
        self._process = object()  # busy until on_done
        self._runner(cmd, self._on_output, self._on_done)

    def _on_output(self, text: str) -> None:
        self.log.moveCursor(self.log.textCursor().MoveOperation.End)
        self.log.insertPlainText(text)

    def _on_done(self, code: int) -> None:
        self._process = None
        if code == 0:
            F.refresh_availability()
            self.status.setText(tr("Installed. Some features need a restart of axross."))
        else:
            self.status.setText(tr("pip failed (exit code {code}); see the log.").format(code=code))
        self.reload()

    def download_selected(self) -> None:
        """Download the selected models one after the other, off the GUI thread."""
        from core import voice_models as VM

        models = [VM.model(f.download) for f in self._selected() if f.download and not f.available]
        models = [m for m in models if m is not None]
        if not models or self._download_cancel is not None:
            return
        cancel = self._download_cancel = threading.Event()
        downloader = self._downloader
        # Not signals of a bridge object: the exit clean-up deletes every
        # Python-owned QObject while this thread may still report
        # (core/thread_relay.py). Dropped once the dialog is gone.
        progress = GuiCall(self._on_download_progress)
        finished = GuiCall(self._on_download_finished)
        self.log.clear()
        self.status.setText(tr("Downloading…"))
        self._update_buttons()

        def work() -> None:
            for model in models:
                if cancel.is_set():
                    break
                progress(model.id, 0, model.size)
                try:
                    downloader(model, lambda done, total, i=model.id: progress(i, done, total),
                               cancel)
                    error = ""
                except VM.DownloadCancelled:
                    error = "cancelled"
                except VM.DownloadError as exc:
                    error = str(exc) or "failed"
                except Exception as exc:  # noqa: BLE001 - shown in the window
                    error = f"{type(exc).__name__}: {exc}"
                finished(model.id, error)
            finished("", "")

        threading.Thread(target=work, name="axross-model-download", daemon=True).start()

    def _on_download_progress(self, model_id: str, done, total) -> None:
        from core import voice_models as VM

        model = VM.model(model_id)
        name = model.title if model is not None else model_id
        percent = int(100 * done / total) if total else 0
        self.status.setText(tr("Downloading {name}: {percent} %").format(name=name,
                                                                          percent=percent))

    def _on_download_finished(self, model_id: str, error: str) -> None:
        from core import voice_models as VM

        if not model_id:  # all done
            self._download_cancel = None
            F.refresh_availability()
            self.reload()
            return
        model = VM.model(model_id)
        name = model.title if model is not None else model_id
        if error:
            self.log.appendPlainText(f"{name}: {error}")
            self.status.setText(tr("Download failed: {name}").format(name=name))
        else:
            self.log.appendPlainText(tr("{name}: downloaded and verified").format(name=name))
            self.status.setText(tr("Downloaded: {name}").format(name=name))

    def _open_packs(self) -> None:
        from ui.packs_dialog import PacksDialog

        dlg = PacksDialog(self, version=self._version, **self._packs)
        dlg.activated.connect(lambda _units: self.reload())   # a pure-Python pack: in use now
        dlg.exec()

    # -- packs re-issued -------------------------------------------------------------------

    def check_packs(self) -> None:
        """Ask, off the GUI thread, whether this release's manifest was
        re-issued for the installed packs (core.packs.check_reissued)."""
        from core import self_update as SU

        allowed, why = SU.start_check_allowed()   # the same rules as the update check
        if not allowed:
            log.info("The packs of %s are not checked: %s", self._version, why)
            return
        post = GuiCall(self._packs_checked)
        opts, version = dict(self._packs), self._version

        def work() -> None:
            from core import packs as P

            try:
                release, stale = P.check_reissued(version, **opts)
                post(release, stale, "")
            except Exception as exc:  # noqa: BLE001 - offline, rate limit, a bad signature: no offer
                post(None, [], f"{type(exc).__name__}: {exc}")

        threading.Thread(target=work, name="axross-packs-check", daemon=True).start()

    def _packs_checked(self, release, stale: list, error: str) -> None:
        if error:
            log.info("The packs of %s could not be checked: %s", self._version, error)
        self._packs_release = release if stale else None
        self.update_packs_button.setVisible(bool(stale))
        self.update_packs_button.setEnabled(bool(stale))
        if stale:
            self.status.setText(tr("The packs of this release were re-issued: Update packs fetches "
                                   "the fixed ones for {units}.").format(units=", ".join(stale)))

    def update_packs(self) -> None:
        """Fetch the re-issued packs (core.packs.update: signature, manifest
        and every blob checked), off the GUI thread."""
        release = self._packs_release
        if release is None:
            return
        self.update_packs_button.setEnabled(False)
        self.status.setText(tr("Updating packs…"))
        post = GuiCall(self._packs_updated)
        opts = dict(self._packs)

        def work() -> None:
            from core import packs as P

            try:
                post(len(P.update(release, **opts)), "")
            except Exception as exc:  # noqa: BLE001 - shown in the window
                post(0, f"{type(exc).__name__}: {exc}")

        threading.Thread(target=work, name="axross-packs-update", daemon=True).start()

    def _packs_updated(self, files: int, error: str) -> None:
        if error:
            self.update_packs_button.setEnabled(True)
            self.status.setText(tr("Packs not updated: {e}").format(e=error))
            return
        self._packs_release = None
        self.update_packs_button.setVisible(False)
        self.status.setText(tr("Packs updated: {n} files checked and unpacked. "
                               "Restart axross to use them.").format(n=files))

    def copy_command(self) -> None:
        lines = [F.how_to_get(f, family=self._family) for f in self._selected() if not f.available]
        if lines:
            QApplication.clipboard().setText("\n".join(lines))
            self.status.setText(tr("Copied: {text}").format(text=lines[0]))

    def _open_download(self) -> None:
        from core import desktop_open

        # Through core.desktop_open: this button is shown in the frozen build,
        # whose environment the desktop's opener cannot start with.
        desktop_open.open_url(QUrl(F.download_url(self._version)))

    def closeEvent(self, event) -> None:  # noqa: N802 - Qt
        self._collect_job.abandon()  # an answer still coming fills no closed window
        if self._download_cancel is not None:
            self._download_cancel.set()  # the download stops and leaves nothing behind
        proc = self._process
        if isinstance(proc, QProcess) and proc.state() != QProcess.ProcessState.NotRunning:
            # pip keeps running to its end; the window only stops showing it.
            # The window is deleted on close: a parentless QProcess went with
            # its last reference and killed pip half way, so the application
            # owns it until it ends.
            for signal in (proc.readyReadStandardOutput, proc.finished, proc.errorOccurred):
                signal.disconnect()
            proc.setParent(QApplication.instance())
            proc.finished.connect(lambda code, _status, p=proc: _install_ended(p, code))
            self._process = None
        super().closeEvent(event)


def _install_ended(proc, code: int) -> None:
    """A pip run whose window was closed has ended."""
    log.info("pip finished after its window was closed (exit code %d)", code)
    if code == 0:
        F.refresh_availability()
    try:
        proc.deleteLater()
    except RuntimeError:  # the application is going down and took it along
        pass


def offer_features(parent, key: str, text: str) -> None:
    """*text* (what is missing) with a button that opens Help > Features…
    at the feature *key*."""
    box = QMessageBox(parent)
    box.setIcon(QMessageBox.Icon.Information)
    box.setWindowTitle(tr("Feature not installed"))
    box.setText(text)
    show = box.addButton(tr("Show in Features…"), QMessageBox.ButtonRole.AcceptRole)
    box.addButton(QMessageBox.StandardButton.Close)
    box.exec()
    if box.clickedButton() is show:
        dlg = FeaturesDialog(parent)
        dlg.select(key)
        dlg.exec()
