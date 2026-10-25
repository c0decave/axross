"""A sign-in that shows a code in the browser asks for it in the window.

Incident: Dropbox's first sign-in read the code with input() from stdin
(core/dropbox_client.py). Started from the desktop, axross has no terminal:
the connect failed with "requires interactive input"; started from one, the
question sat unseen in that terminal. core.auth_prompt hands the question
to the GUI (ui.auth_prompt: a dialog with the link and a code field) from
the connect worker's thread, which waits for the answer.
"""

from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication, QDialog, QLineEdit  # noqa: E402

from core import auth_prompt as AP  # noqa: E402

APP = QApplication.instance() or QApplication([])


def pump(until, seconds=10.0):
    end = time.monotonic() + seconds
    while time.monotonic() < end and not until():
        APP.processEvents()
        time.sleep(0.01)
    return until()


@pytest.fixture(autouse=True)
def _no_handler():
    AP.set_handler(None)
    yield
    AP.set_handler(None)


def _find_dialog():
    return next((w for w in APP.topLevelWidgets()
                 if isinstance(w, QDialog) and w.objectName() == "axSignInCode"
                 and w.isVisible()), None)


def _answer_dialog(text: str | None, until=lambda: False, seconds: float = 10.0) -> dict:
    """Answer the next sign-in dialog from inside its modal loop (a timer):
    type *text* and press OK, or Cancel for None. Pumps until *until()* or
    the answer was given; returns what the dialog showed."""
    from PyQt6.QtCore import QTimer
    from PyQt6.QtWidgets import QLabel

    seen: dict = {}
    timer = QTimer()
    timer.setInterval(20)

    def tick():
        dialog = _find_dialog()
        if dialog is None:
            return
        timer.stop()
        seen["text"] = " ".join(label.text() for label in dialog.findChildren(QLabel))
        if text is None:
            dialog.reject()
        else:
            dialog.findChild(QLineEdit).setText(text)
            dialog.accept()

    timer.timeout.connect(tick)
    timer.start()
    pump(lambda: "text" in seen and until(), seconds)
    timer.stop()
    assert "text" in seen, "no sign-in dialog"
    return seen


# -- the core hook ------------------------------------------------------------------------------

def test_sad_without_a_handler_there_is_no_answer():
    assert AP.ask_code("Dropbox", "https://example.invalid/auth") is None


def test_happy_the_handler_gets_service_and_link_and_its_answer_is_trimmed():
    seen = []
    AP.set_handler(lambda service, url: seen.append((service, url)) or "  abc123 \n")
    assert AP.ask_code("Dropbox", "https://example.invalid/auth") == "abc123"
    assert seen == [("Dropbox", "https://example.invalid/auth")]


@pytest.mark.parametrize("answer", [None, "", "   "])
def test_edge_an_empty_or_cancelled_answer_is_none(answer):
    AP.set_handler(lambda service, url: answer)
    assert AP.ask_code("Dropbox", "https://example.invalid/auth") is None


def test_sad_a_handler_that_raises_is_no_answer():
    def boom(service, url):
        raise RuntimeError("dialog exploded")

    AP.set_handler(boom)
    assert AP.ask_code("Dropbox", "https://example.invalid/auth") is None


# -- the GUI bridge -----------------------------------------------------------------------------

def _ask_in_thread(**kw):
    box = {}
    thread = threading.Thread(
        target=lambda: box.update(code=AP.ask_code("Dropbox", "https://example.invalid/auth")),
        daemon=True)
    thread.start()
    return thread, box


def test_happy_e2e_the_window_asks_from_a_worker_thread():
    from ui import auth_prompt as UAP

    bridge = UAP.install()
    try:
        thread, box = _ask_in_thread()
        _answer_dialog(" the-code ", until=lambda: "code" in box)
        thread.join(10)
        assert box["code"] == "the-code"
    finally:
        bridge.uninstall()


def test_sad_e2e_cancel_in_the_window_is_no_answer():
    from ui import auth_prompt as UAP

    bridge = UAP.install()
    try:
        thread, box = _ask_in_thread()
        _answer_dialog(None, until=lambda: "code" in box)
        thread.join(10)
        assert box["code"] is None
    finally:
        bridge.uninstall()


def test_edge_e2e_asking_on_the_gui_thread_itself_shows_the_dialog_directly():
    from PyQt6.QtCore import QTimer

    from ui import auth_prompt as UAP

    bridge = UAP.install()
    try:
        def answer():
            dialog = _find_dialog()
            if dialog is None:
                QTimer.singleShot(20, answer)
                return
            dialog.findChild(QLineEdit).setText("direct")
            dialog.accept()

        QTimer.singleShot(20, answer)
        assert AP.ask_code("Dropbox", "https://example.invalid/auth") == "direct"
    finally:
        bridge.uninstall()


def test_edge_e2e_an_uninstalled_bridge_answers_none_at_once():
    from ui import auth_prompt as UAP

    bridge = UAP.install()
    bridge.uninstall()
    started = time.monotonic()
    assert AP.ask_code("Dropbox", "https://example.invalid/auth") is None
    assert time.monotonic() - started < 1.0


def test_happy_e2e_the_dialog_shows_the_service_and_the_link():
    from ui import auth_prompt as UAP

    bridge = UAP.install()
    try:
        thread, box = _ask_in_thread()
        seen = _answer_dialog(None, until=lambda: "code" in box)
        thread.join(10)
    finally:
        bridge.uninstall()
    assert "Dropbox" in seen["text"] and "https://example.invalid/auth" in seen["text"]


# -- Dropbox, end to end through the real client ------------------------------------------------

class _FakeFlow:
    instances: list = []

    def __init__(self, app_key, use_pkce=False, token_access_type=None):
        self.app_key = app_key
        self.finished_with = None
        _FakeFlow.instances.append(self)

    def start(self):
        return "https://www.dropbox.com/oauth2/authorize?client_id=k&code_challenge=x"

    def finish(self, code):
        from types import SimpleNamespace

        self.finished_with = code
        return SimpleNamespace(access_token="AT-" + code, refresh_token="RT-" + code)


class _FakeDropbox:
    def __init__(self, **kw):
        self.kw = kw
        self._session = type("S", (), {"headers": {}, "proxies": {}})()

    def users_get_current_account(self):
        return None


@pytest.fixture
def fake_dropbox(monkeypatch, tmp_path):
    pytest.importorskip("dropbox")
    from core import dropbox_client as DC

    _FakeFlow.instances.clear()
    monkeypatch.setattr(DC, "DropboxOAuth2FlowNoRedirect", _FakeFlow)
    monkeypatch.setattr(DC.dropbox, "Dropbox", _FakeDropbox)
    opened = []
    monkeypatch.setattr(DC, "open_in_browser", opened.append)
    return DC, opened, tmp_path / "dropbox_token.json"


def test_happy_e2e_a_first_dropbox_sign_in_asks_in_the_window(fake_dropbox, monkeypatch):
    from ui import auth_prompt as UAP

    DC, opened, token = fake_dropbox
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)  # started from the desktop
    bridge = UAP.install()
    box = {}
    try:
        thread = threading.Thread(
            target=lambda: box.update(client=DC.DropboxSession("k", token_file=str(token))),
            daemon=True)
        thread.start()
        _answer_dialog("CODE42", until=lambda: not thread.is_alive(), seconds=15)
        thread.join(15)
    finally:
        bridge.uninstall()
    assert "client" in box, "the connect did not finish"
    assert _FakeFlow.instances[-1].finished_with == "CODE42"
    assert opened and opened[0].startswith("https://www.dropbox.com/oauth2/authorize")
    assert token.exists() and "RT-CODE42" in token.read_text()


def test_sad_e2e_a_cancelled_dropbox_sign_in_fails_with_a_reason(fake_dropbox, monkeypatch):
    from ui import auth_prompt as UAP

    DC, _opened, token = fake_dropbox
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    bridge = UAP.install()
    box = {}
    try:
        def connect():
            try:
                DC.DropboxSession("k", token_file=str(token))
            except OSError as exc:
                box["error"] = str(exc)

        thread = threading.Thread(target=connect, daemon=True)
        thread.start()
        _answer_dialog(None, until=lambda: not thread.is_alive(), seconds=15)
        thread.join(15)
    finally:
        bridge.uninstall()
    assert "cancelled" in box.get("error", "")
    assert not token.exists()


def test_sad_without_a_window_and_without_a_terminal_the_link_is_named(fake_dropbox, monkeypatch):
    DC, _opened, token = fake_dropbox
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    with pytest.raises(OSError, match="dropbox.com/oauth2/authorize"):
        DC.DropboxSession("k", token_file=str(token))


def test_happy_the_main_window_installs_the_bridge(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    from ui.main_window import MainWindow

    win = MainWindow()
    try:
        assert AP.has_handler()
    finally:
        win._reconnect_timer.stop()
        win.close()
        win.deleteLater()
