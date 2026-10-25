"""The window's answer to core.auth_prompt: a dialog for a sign-in code.

A backend connects on a worker thread. :meth:`AuthCodePrompt.ask` (any
thread) hands the question to the GUI thread through a queued signal and
waits on an event - the same contract as core.connect_worker.HostKeyPrompt.
The dialog shows the link (with Open Browser Again) and a field for the
code; Cancel, closing it, or :meth:`uninstall` answer None.
"""

from __future__ import annotations

import threading

from PyQt6.QtCore import QObject, Qt, pyqtSignal, pyqtSlot
from PyQt6.QtWidgets import (
    QApplication,
    QDialog,
    QDialogButtonBox,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
)

from core import auth_prompt as AP
from core.desktop_open import open_in_browser
from core.i18n import tr
from ui.close_corner import add_close_corner

#: How long a worker waits for an answer before it gives up (seconds): a
#: sign-in in the browser takes a while, a forgotten dialog must not hold
#: a connect for ever.
REPLY_TIMEOUT_SECONDS = 15 * 60


def code_dialog(service: str, url: str, parent=None) -> str | None:
    """Show the sign-in dialog for *service*; the code typed, or None."""
    dialog = QDialog(parent)
    dialog.setObjectName("axSignInCode")
    dialog.setWindowTitle(tr("Sign in to {service}").format(service=service))
    layout = QVBoxLayout(dialog)
    intro = QLabel(tr("Sign in to {service} in the browser and allow axross access. "
                      "{service} then shows a code: paste it here.").format(service=service))
    intro.setWordWrap(True)
    layout.addWidget(intro)
    link = QLabel(f'<a href="{url}">{url}</a>')
    link.setTextFormat(Qt.TextFormat.RichText)
    link.setWordWrap(True)
    link.setTextInteractionFlags(Qt.TextInteractionFlag.TextBrowserInteraction)
    link.linkActivated.connect(open_in_browser)
    layout.addWidget(link)
    again = QPushButton(tr("Open Browser Again"))
    again.clicked.connect(lambda: open_in_browser(url))
    layout.addWidget(again)
    field = QLineEdit()
    field.setPlaceholderText(tr("Code"))
    layout.addWidget(field)
    buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok
                               | QDialogButtonBox.StandardButton.Cancel)
    buttons.accepted.connect(dialog.accept)
    buttons.rejected.connect(dialog.reject)
    layout.addWidget(buttons)
    add_close_corner(dialog)
    field.setFocus()
    try:
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return None
        return field.text()
    finally:
        dialog.deleteLater()


class AuthCodePrompt(QObject):
    """Lives on the GUI thread; :meth:`ask` may be called from any thread."""

    request = pyqtSignal(str, str)

    def __init__(self, parent: QObject | None = None, *,
                 reply_timeout: float = REPLY_TIMEOUT_SECONDS) -> None:
        super().__init__(parent)
        self._lock = threading.Lock()
        self._event = threading.Event()
        self._answer: str | None = None
        self._timeout = reply_timeout
        self._abandoned = False
        self.request.connect(self._show, Qt.ConnectionType.QueuedConnection)

    def ask(self, service: str, url: str) -> str | None:
        if self._abandoned:
            return None
        if threading.current_thread() is threading.main_thread():
            return code_dialog(service, url, QApplication.activeWindow())
        with self._lock:  # one question at a time
            self._event.clear()
            self._answer = None
            self.request.emit(service, url)
            if not self._event.wait(self._timeout):
                return None
            return self._answer

    @pyqtSlot(str, str)
    def _show(self, service: str, url: str) -> None:
        answer = None
        if not self._abandoned:
            answer = code_dialog(service, url, QApplication.activeWindow())
        self._answer = answer
        self._event.set()

    def uninstall(self) -> None:
        """Nobody is left to answer: release a waiting worker, ask no more."""
        self._abandoned = True
        if AP._HANDLER == self.ask:
            AP.set_handler(None)
        self._answer = None
        self._event.set()


_INSTALLED: AuthCodePrompt | None = None


def install() -> AuthCodePrompt:
    """Answer core.auth_prompt's questions in this window from now on."""
    global _INSTALLED
    if _INSTALLED is not None:
        _INSTALLED.uninstall()
    _INSTALLED = AuthCodePrompt(QApplication.instance())
    AP.set_handler(_INSTALLED.ask)
    return _INSTALLED


__all__ = ["AuthCodePrompt", "REPLY_TIMEOUT_SECONDS", "code_dialog", "install"]
