"""axross-markdown's updates in the window: Help > Check for Updates…, Help > Updates (Off / Tell me /
Install automatically), and the checks at the start and every 24 hours (core.markdown_update).

Nothing of it runs on the GUI thread but the menus and the notices: every request, the signature's
check, the download, its SHA-256, the new program's self-test and the swap run on a thread of their own
(:class:`UpdateController`), their outcome handed back through a queued signal. A notice is a window of
its own that does not wait (no modal loop), shown once a version a session.

In axross's own Markdown viewer there is none of it: axross updates itself (core.self_update).
"""

from __future__ import annotations

import logging
import threading

from PyQt6.QtCore import QObject, Qt, QTimer, pyqtSignal

from core import markdown_update as MU

log = logging.getLogger(__name__)

#: The first check after the start (the window drawn first), and how often the timer looks whether one is
#: due (the 24 hours count from the last check, kept in the settings).
FIRST_CHECK_MS = 5000
TICK_MS = 3600 * 1000


class UpdateController(QObject):
    """The program's updates (one an application). ``said(kind, text)``: "available", "installed",
    "current" or "error" - on the GUI thread."""

    said = pyqtSignal(str, str)
    _from_worker = pyqtSignal(str, str, object)

    def __init__(self, parent=None, *, fetcher=None, install=None, current: str | None = None,
                 test=None, start_thread=None) -> None:
        super().__init__(parent)
        self.fetcher = fetcher
        self.install_info = MU.detect_install() if install is None else install
        self.current = MU.current_version() if current is None else current
        self.test = test
        self.start_thread = start_thread or (lambda target: threading.Thread(
            target=target, name="markdown-update", daemon=True).start())
        self.notified: set[str] = set()
        self.last_result: MU.CheckResult | None = None
        self.busy = False
        self.parent_window = None
        #: whether the check under way was asked for (Help > Check for Updates…, Install): its answer shown
        #: whatever it is - a background check's only when it found a newer version
        self.asked = False
        #: an update was begun in this session: the old program it keeps (.previous) is not removed
        #: by this one's cleanup - it goes once the new program has run a minute
        self.updating = False
        #: the version this session installed (it starts next time): no check finds it newer again - auto mode
        #: installed the same release every 24 hours
        self.installed: str | None = None
        self._installing = threading.Lock()
        self._from_worker.connect(self._arrived)
        self.scheduler = MU.Scheduler(self._background_check, start=self.start_thread)
        self.timer = QTimer(self)
        self.timer.setInterval(TICK_MS)
        self.timer.timeout.connect(self.scheduler.tick)

    # -- the checks at the start and every day ------------------------------------------------------

    def start(self) -> None:
        """The timer: a first look soon after the start, then hourly (a check every 24 hours); the old
        program of an update removed once this one has run a minute."""
        QTimer.singleShot(FIRST_CHECK_MS, self.scheduler.tick)
        self.timer.start()
        if self.install_info.target is not None:
            QTimer.singleShot(MU.KEEP_PREVIOUS_SECONDS * 1000, self.cleanup)

    def cleanup(self) -> None:
        """(this program has run a minute) the old program an earlier update kept, and what a cut
        download left - on a worker; not when this session has updated (its .previous is the program
        running now)."""
        target = self.install_info.target
        if target is None or self.updating:
            return
        self.start_thread(lambda: None if self.updating else (MU.cleanup_previous(target),
                                                              MU.cleanup_partials(target)))

    def _newer(self, result) -> bool:
        """Whether *result* is newer than this program - and than what this session installed already."""
        return result.newer and (self.installed is None or MU.is_newer(result.release.version, self.installed))

    def _worker(self, work, result=None):
        """*work()* as a worker's body: whatever it raises (not only an UpdateError: a reset connection, a full
        disk, a bug) said as "error" - the controller never left busy, Check for Updates never dead for the
        session."""
        def run() -> None:
            try:
                work()
            except MU.UpdateError as exc:
                self._from_worker.emit("error", str(exc), result)
            except Exception as exc:  # noqa: BLE001 - said, never a dead worker
                log.warning("The update failed", exc_info=True)
                self._from_worker.emit("error", f"{type(exc).__name__}: {exc}"[:300], result)
        return run

    def _background_check(self) -> None:
        """(a worker thread) the check - and in "auto", the update."""
        result = MU.check(self.current, self.fetcher)
        MU.record_check(result)
        if not self._newer(result):
            return
        if MU.mode() == "auto" and self.install_info.can_update:
            self.updating = True
            self._worker(lambda: self._install(result), result)()
            return
        self._from_worker.emit("available", result.text, result)

    def _install(self, result) -> None:
        """(a worker thread) the update to *result*'s release - "installed" said."""
        if not self._installing.acquire(blocking=False):  # (auto mode's own and an Install click: one)
            raise MU.UpdateError("an update is under way already")
        try:
            if self.installed is not None and not MU.is_newer(result.release.version, self.installed):
                raise MU.UpdateError(f"{self.installed} is installed already - it starts the next time")
            text = MU.update(self.install_info, self.current, self.fetcher, test=self.test, check_result=result)
            self.installed = result.release.version
        finally:
            self._installing.release()
        self._from_worker.emit("installed", text, result)

    # -- asked for -----------------------------------------------------------------------------------

    def check_now(self, parent=None) -> None:
        """Help > Check for Updates…: asked at once, on a worker; the answer in a notice."""
        if self.busy:
            return
        self.busy, self.asked = True, True
        self.parent_window = parent

        def check() -> None:
            result = MU.check(self.current, self.fetcher)
            MU.record_check(result)
            self._from_worker.emit("available" if self._newer(result) else "current", result.text, result)

        self._start(self._worker(check))

    def _start(self, run) -> None:
        """*run* on a worker - a thread that cannot start said as "error" too."""
        try:
            self.start_thread(run)
        except Exception as exc:  # noqa: BLE001 - (no thread: said, not busy for ever)
            log.warning("The update's thread did not start", exc_info=True)
            self._arrived("error", str(exc) or type(exc).__name__, None)

    def install_now(self, parent=None) -> None:
        """Install (the notice's button): download, check, self-test and swap on a worker."""
        result = self.last_result
        if self.busy or result is None or not self._newer(result):
            return
        self.busy, self.asked = True, True
        self.parent_window = parent
        self.updating = True
        self._start(self._worker(lambda: self._install(result), result))

    def _arrived(self, kind: str, text: str, result) -> None:
        """(the GUI thread) a worker's outcome."""
        self.busy = False
        if result is not None:
            self.last_result = result
        asked, self.asked = self.asked, False
        version = result.release.version if result is not None else ""
        if kind == "available" and not asked and version in self.notified:
            return
        if kind == "available":
            self.notified.add(version)
        self.said.emit(kind, text)
        if kind in ("current", "error") and not asked:
            return  # (a background check that found nothing new, or failed: the log has it)
        self.notice(kind, text, self.parent_window)
        self.parent_window = None

    # -- what the window shows ------------------------------------------------------------------------

    def notice(self, kind: str, text: str, parent=None):
        """A window that says *text* and does not wait - with Install (a newer release, a program that can
        be replaced) or the pip command (an install by pip)."""
        from PyQt6.QtWidgets import QApplication, QMessageBox

        from core.i18n import tr

        parent = parent or QApplication.activeWindow()
        box = QMessageBox(parent)
        box.setWindowTitle(tr("axross-markdown updates"))
        box.setIcon(QMessageBox.Icon.Warning if kind == "error" else QMessageBox.Icon.Information)
        box.setText(self._said(kind, text))
        box.setModal(False)
        if kind == "available" and self.install_info.can_update:
            install = box.addButton(tr("Install"), QMessageBox.ButtonRole.AcceptRole)
            install.clicked.connect(lambda: self.install_now(parent))
        box.addButton(QMessageBox.StandardButton.Close)
        box.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        box.show()
        self.box = box
        return box

    def _said(self, kind: str, text: str) -> str:
        from core.i18n import tr

        result = self.last_result
        if kind == "available" and result is not None:
            said = tr("axross-markdown {new} is available (this is {current}).").format(
                new=result.release.version, current=result.current)
            if not self.install_info.can_update:
                said += "\n\n" + (tr("To update it: {command}").format(command=MU.pip_hint(result.release.version))
                                  if self.install_info.kind == "pip" else self.install_info.why_not())
            return said
        if kind == "current":
            return tr("axross-markdown {current} is up to date.").format(current=self.current)
        if kind == "installed" and result is not None:
            return tr("axross-markdown {new} is installed and checked – it starts the next time.").format(
                new=result.release.version)
        return tr("The update was not installed: {why}").format(why=text)

    def fill_help_menu(self, menu) -> None:
        """Help: Check for Updates…, and Updates (Off / Tell me / Install automatically, the one set
        checked)."""
        from PyQt6.QtGui import QActionGroup

        from core.i18n import tr

        menu.addAction(tr("Check for Updates…"), lambda: self.check_now(menu.parentWidget()))
        modes = menu.addMenu(tr("Updates"))
        group = QActionGroup(modes)
        group.setExclusive(True)
        labels = (("off", tr("Off")), ("notify", tr("Tell me about new versions")),
                  ("auto", tr("Install new versions automatically")))
        for value, label in labels:
            action = modes.addAction(label)
            action.setCheckable(True)
            action.setData(value)
            group.addAction(action)
            if value == "auto" and not self.install_info.can_update:
                action.setEnabled(False)
                action.setToolTip(self.install_info.why_not())

        def checked() -> None:
            now = MU.mode()
            for action in group.actions():
                action.setChecked(action.data() == now)

        def chosen(action) -> None:
            try:
                MU.set_mode(action.data())
            except OSError:
                log.warning("The update setting could not be kept", exc_info=True)

        checked()
        modes.aboutToShow.connect(checked)
        group.triggered.connect(chosen)


_CONTROLLER: list[UpdateController] = []


def controller() -> UpdateController:
    """The application's UpdateController (made at first use; its checks start with start() - the
    program's start, ui.markdown_app.build)."""
    from PyQt6 import sip
    from PyQt6.QtCore import QCoreApplication

    if _CONTROLLER and not sip.isdeleted(_CONTROLLER[0]):
        return _CONTROLLER[0]
    _CONTROLLER[:] = [UpdateController(QCoreApplication.instance())]
    return _CONTROLLER[0]


__all__ = ["FIRST_CHECK_MS", "TICK_MS", "UpdateController", "controller"]
