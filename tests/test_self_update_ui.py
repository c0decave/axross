"""The self-update in the window: the start check, the notice, the dialog,
Help > Check for Updates… and Settings > Updates (ui.update_ui).

Real MainWindow, real Settings dialog, real clicks; GitHub is the local
fake of tests/fake_github.py, the binary a file in a temporary folder.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import stat
import sys
import time
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QEvent, QPoint, Qt  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication, QDialogButtonBox, QFileDialog, QToolButton  # noqa: E402

from axross._version import __version__  # noqa: E402
from core import self_update as SU  # noqa: E402
from tests.fake_github import (  # noqa: E402
    FakeGitHub,
    FakeHttpsHandler,
    FakeRelease,
    newer_than,
    trust_test_key,
)
from tests.settings_testkit import app, isolate  # noqa: E402

APP = app()
NEW = newer_than(__version__)
OLD_BYTES = b"\x7fELF old" * 100
NEW_BYTES = b"\x7fELF new" * 20000


def pump(seconds: float = 0.05) -> None:
    end = time.time() + seconds
    while time.time() < end:
        APP.processEvents()
        time.sleep(0.01)


def wait_for(predicate, timeout: float = 10.0) -> None:
    end = time.time() + timeout
    while time.time() < end:
        APP.processEvents()
        if predicate():
            return
        time.sleep(0.01)
    raise AssertionError("timed out waiting")


@pytest.fixture(autouse=True)
def _no_env_proxy(monkeypatch):
    for name in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY", "all_proxy",
                 "ALL_PROXY", SU.NO_CHECK_ENV):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture(autouse=True)
def _trust_the_test_key(monkeypatch):
    """Every fake release is signed with the test key (tests/fake_github.py)."""
    trust_test_key(monkeypatch)


@pytest.fixture
def stores(tmp_path, monkeypatch):
    s = isolate(tmp_path, monkeypatch)
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    yield s
    s.restore()


@pytest.fixture
def fake():
    server = FakeGitHub(FakeRelease(NEW, {"axross-full": NEW_BYTES}))
    yield server
    server.close()


@pytest.fixture
def binary(tmp_path):
    folder = tmp_path / "apps"
    folder.mkdir()
    exe = folder / "axross-full"
    exe.write_bytes(OLD_BYTES)
    exe.chmod(0o755)
    return exe


def frozen(exe: Path) -> SU.Install:
    return SU.detect_install(frozen=True, executable=str(exe), bundle_dir=None,
                             platform="linux", machine="x86_64")


def wire(win, server, inst=None):
    controller = win.update_controller()
    controller.opener_factory = lambda: SU.build_opener(handlers=[FakeHttpsHandler(server.port)])
    controller.install_info = inst if inst is not None else SU.detect_install(frozen=False)
    return controller


def idle(controller) -> bool:
    return controller.state not in ("checking", "downloading")


def menu(win, title: str):
    return next(a.menu() for a in win.menuBar().actions() if a.text() == title)


def plain(text: str) -> str:
    return text.replace("&&", "\0").replace("&", "").replace("\0", "&")


def notice(win) -> str | None:
    """What the version bottom right says beyond "axross X.Y.Z", or None."""
    text = plain(win._version_button.text())
    shown = f"axross {__version__}"
    if text == shown:
        return None
    assert text.startswith(shown + " · "), text
    return text[len(shown) + 3:]


def entry(win, label: str):
    return next(a for a in menu(win, "&Help").actions() if plain(a.text()) == label)


def update_dialogs():
    from ui.update_ui import UpdateDialog

    return [w for w in QApplication.topLevelWidgets()
            if isinstance(w, UpdateDialog) and w.isVisible()]


def closed(win) -> bool:
    """The window's update dialog was closed (it deletes itself)."""
    APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    return win._update_dialog is None


def started_window(stores, fake, inst=None):
    win = stores.make_window()
    win.show()
    pump()
    controller = wire(win, fake, inst)
    return win, controller


# --- the start check and the notice ----------------------------------------------


def test_happy_e2e_start_check_shows_the_notice(stores, fake):
    win, controller = started_window(stores, fake)
    assert notice(win) is None
    assert win.start_update_check() is True
    wait_for(lambda: idle(controller))
    assert controller.state == "available"
    assert notice(win) is not None
    assert notice(win) == f"Update available: {NEW}"
    action = entry(win, f"Update to {NEW}…")
    assert action.isVisible()
    assert stores.messages == [] and update_dialogs() == []  # nothing modal at start
    when, text = SU.last_check()
    assert when is not None and NEW in text


def test_edge_the_start_check_runs_once_per_start(stores, fake):
    win, controller = started_window(stores, fake)
    assert win.start_update_check() is True
    wait_for(lambda: idle(controller))
    assert win.start_update_check() is False
    pump(0.2)
    assert fake.api_requests() == 1


def test_edge_switched_off_makes_no_request(stores, fake):
    SU.set_check_at_start(False)
    win, controller = started_window(stores, fake)
    assert win.start_update_check() is False
    pump(0.3)
    assert fake.api_requests() == 0
    assert notice(win) is None


def test_sad_a_failure_at_start_is_a_quiet_log_line(stores, fake, caplog):
    fake.api_status = 403
    fake.api_headers = {"X-RateLimit-Remaining": "0",
                        "X-RateLimit-Reset": str(int(time.time()) + 900)}
    win, controller = started_window(stores, fake)
    with caplog.at_level(logging.WARNING, logger="ui.update_ui"):
        win.start_update_check()
        wait_for(lambda: idle(controller))
    assert controller.state == "error"
    assert stores.messages == [] and update_dialogs() == []
    assert notice(win) is None
    assert "rate limit" in SU.last_check()[1]
    assert any("rate limit" in r.getMessage() for r in caplog.records)


def test_edge_up_to_date_shows_nothing(stores, fake):
    fake.release.version = __version__
    win, controller = started_window(stores, fake)
    win.start_update_check()
    wait_for(lambda: idle(controller))
    assert controller.state == "current" and notice(win) is None


def test_happy_the_start_is_scheduled_after_the_window_is_shown(stores, fake):
    from ui.update_ui import schedule_start_check

    win, controller = started_window(stores, fake)
    schedule_start_check(win, delay_ms=0)
    assert fake.api_requests() == 0  # not before the event loop runs
    wait_for(lambda: fake.api_requests() == 1 and idle(controller))
    main_source = (Path(__file__).resolve().parent.parent / "main.py").read_text()
    assert "schedule_start_check(window" in main_source


# --- the dialog ------------------------------------------------------------------


def test_happy_e2e_notice_download_install_restart(stores, fake, binary):
    win, controller = started_window(stores, fake, frozen(binary))
    win.start_update_check()
    wait_for(lambda: idle(controller))
    QTest.mouseClick(win._version_button, Qt.MouseButton.LeftButton)
    pump()
    (dialog,) = update_dialogs()
    assert NEW in dialog.status_label.text()
    assert "faster" in dialog.notes.toPlainText()
    assert dialog.findChildren(QToolButton, "axCloseCorner")
    assert dialog.download_button.isVisible()
    assert plain(dialog.download_button.text()) == "Download and Install"
    assert not dialog.restart_button.isVisible()
    QTest.mouseClick(dialog.download_button, Qt.MouseButton.LeftButton)
    wait_for(lambda: idle(controller))
    assert controller.state == "installed"
    assert binary.read_bytes() == NEW_BYTES
    assert binary.with_name("axross-full.previous").read_bytes() == OLD_BYTES
    assert dialog.restart_button.isVisible() and not dialog.download_button.isVisible()
    assert "next start" in dialog.status_label.text()
    assert notice(win) == f"Restart to Use {NEW}…"
    with mock.patch.object(SU, "restart") as restart, \
            mock.patch.object(QApplication, "quit") as quit_:
        QTest.mouseClick(dialog.restart_button, Qt.MouseButton.LeftButton)
        pump()
    restart.assert_called_once_with(binary.resolve(),
                                    expected_sha256=hashlib.sha256(NEW_BYTES).hexdigest())
    quit_.assert_called_once()
    assert not win.isVisible()


def _installed(stores, fake, binary):
    win, controller = started_window(stores, fake, frozen(binary))
    win.start_update_check()
    wait_for(lambda: idle(controller))
    win.show_update_dialog()
    (dialog,) = update_dialogs()
    QTest.mouseClick(dialog.download_button, Qt.MouseButton.LeftButton)
    wait_for(lambda: idle(controller))
    assert controller.state == "installed"
    return win, controller, dialog


def test_edge_a_check_after_the_install_keeps_restart_now(stores, fake, binary):
    win, controller, dialog = _installed(stores, fake, binary)
    entry(win, "Check for Updates…").trigger()
    wait_for(lambda: idle(controller) and not controller._check_job.running)
    assert controller.state == "installed"
    assert dialog.restart_button.isVisible() and not dialog.download_button.isVisible()
    # SHA256SUMS, its signature and the binary - not again
    assert fake.hosts().count("release-assets.githubusercontent.com") == 3


def test_sad_restart_refused_before_the_window_closes(stores, fake, binary):
    win, controller, dialog = _installed(stores, fake, binary)
    binary.write_bytes(b"replaced by someone else")
    with mock.patch.object(SU, "restart") as restart, \
            mock.patch.object(QApplication, "quit") as quit_:
        QTest.mouseClick(dialog.restart_button, Qt.MouseButton.LeftButton)
        pump()
    restart.assert_not_called()
    quit_.assert_not_called()
    assert win.isVisible()
    assert "refused" in dialog.status_label.text()


def test_happy_skip_this_version_is_remembered(stores, fake):
    win, controller = started_window(stores, fake)
    win.start_update_check()
    wait_for(lambda: idle(controller))
    win.show_update_dialog()
    (dialog,) = update_dialogs()
    QTest.mouseClick(dialog.skip_button, Qt.MouseButton.LeftButton)
    pump()
    assert SU.skipped_version() == NEW
    assert notice(win) is None and closed(win)
    # The next start: the skipped version gives no notice.
    second, controller2 = started_window(stores, fake)
    second.start_update_check()
    wait_for(lambda: idle(controller2))
    assert controller2.state == "available" and notice(second) is None
    # Asked by hand, it is still offered.
    entry(second, "Check for Updates…").trigger()
    wait_for(lambda: idle(controller2))
    assert any(NEW in d.status_label.text() and d.download_button.isEnabled()
               for d in update_dialogs())


def test_happy_remind_me_later_hides_for_this_run_only(stores, fake):
    win, controller = started_window(stores, fake)
    win.start_update_check()
    wait_for(lambda: idle(controller))
    win.show_update_dialog()
    (dialog,) = update_dialogs()
    QTest.mouseClick(dialog.later_button, Qt.MouseButton.LeftButton)
    pump()
    assert notice(win) is None and closed(win)
    assert SU.skipped_version() == ""


def test_sad_a_python_install_is_told_to_use_pip(stores, fake):
    win, controller = started_window(stores, fake, SU.detect_install(frozen=False))
    win.start_update_check()
    wait_for(lambda: idle(controller))
    win.show_update_dialog()
    (dialog,) = update_dialogs()
    assert not dialog.download_button.isVisible()
    assert "pip install -U axross" in dialog.status_label.text()


def test_sad_checksum_mismatch_is_shown_and_nothing_replaced(stores, fake, binary):
    fake.served_override["axross-full"] = b"Z" * len(NEW_BYTES)
    win, controller = started_window(stores, fake, frozen(binary))
    win.start_update_check()
    wait_for(lambda: idle(controller))
    win.show_update_dialog()
    (dialog,) = update_dialogs()
    QTest.mouseClick(dialog.download_button, Qt.MouseButton.LeftButton)
    wait_for(lambda: idle(controller))
    assert "SHA-256" in dialog.status_label.text()
    assert binary.read_bytes() == OLD_BYTES
    assert dialog.download_button.isVisible() and not dialog.restart_button.isVisible()
    assert stores.messages == []


@pytest.mark.parametrize("break_it", ["missing", "wrong-key"])
def test_sad_e2e_an_unsigned_release_is_refused_with_a_clear_message(stores, fake, binary,
                                                                     monkeypatch, break_it):
    """The signature refusal says what happened in words a user reads, and
    that text goes through tr() (marked here to prove it)."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    import ui.update_ui as UU

    monkeypatch.setattr(UU, "tr", lambda text: "\u00bb" + text)
    if break_it == "missing":
        fake.release.without_sig = True
    else:
        fake.release.signing_key = Ed25519PrivateKey.generate()
    win, controller = started_window(stores, fake, frozen(binary))
    win.start_update_check()
    wait_for(lambda: idle(controller))
    win.show_update_dialog()
    (dialog,) = update_dialogs()
    QTest.mouseClick(dialog.download_button, Qt.MouseButton.LeftButton)
    wait_for(lambda: idle(controller))
    text = dialog.status_label.text()
    assert text.startswith("\u00bbThe update is refused"), text
    assert "not signed with the axross release key" in text and NEW in text
    assert "Nothing was changed" in text
    assert binary.read_bytes() == OLD_BYTES
    assert not binary.with_name("axross-full.previous").exists()
    assert dialog.download_button.isVisible() and not dialog.restart_button.isVisible()


@pytest.mark.skipif(os.geteuid() == 0, reason="root writes into a read-only folder")
def test_sad_read_only_folder_offers_save_to(stores, fake, binary, tmp_path):
    win, controller = started_window(stores, fake, frozen(binary))
    win.start_update_check()
    wait_for(lambda: idle(controller))
    win.show_update_dialog()
    (dialog,) = update_dialogs()
    binary.parent.chmod(0o555)
    try:
        QTest.mouseClick(dialog.download_button, Qt.MouseButton.LeftButton)
        wait_for(lambda: idle(controller))
    finally:
        binary.parent.chmod(0o755)
    assert controller.state == "finish" and binary.read_bytes() == OLD_BYTES
    assert dialog.save_button.isVisible() and not dialog.restart_button.isVisible()
    assert "not writable" in dialog.status_label.text()
    target = tmp_path / "chosen" / "axross-full"
    target.parent.mkdir()
    with mock.patch.object(QFileDialog, "getSaveFileName", return_value=(str(target), "")):
        QTest.mouseClick(dialog.save_button, Qt.MouseButton.LeftButton)
        pump()
    assert target.read_bytes() == NEW_BYTES
    assert stat.S_IMODE(target.stat().st_mode) & 0o100
    assert str(target) in dialog.status_label.text()


def test_happy_help_check_for_updates_when_up_to_date(stores, fake):
    fake.release.version = __version__
    win, controller = started_window(stores, fake)
    entry(win, "Check for Updates…").trigger()
    wait_for(lambda: idle(controller))
    (dialog,) = update_dialogs()
    assert "up to date" in dialog.status_label.text()
    assert not dialog.download_button.isVisible()


def test_happy_automatic_download_installs_at_start(stores, fake, binary):
    SU.set_auto_download(True)
    win, controller = started_window(stores, fake, frozen(binary))
    win.start_update_check()
    wait_for(lambda: controller.state == "installed" or controller.state == "error", 15)
    assert controller.state == "installed"
    assert binary.read_bytes() == NEW_BYTES
    assert notice(win) == f"Restart to Use {NEW}…"
    assert stores.messages == [] and update_dialogs() == []


# --- Settings > Updates ----------------------------------------------------------


def test_happy_e2e_settings_page_toggles_and_checks_now(stores, fake):
    win, controller = started_window(stores, fake)
    dialog = stores.settings_dialog(win, "updates")
    dialog.show()
    pump()
    page = dialog.page("updates")
    assert page.check_box.isChecked() and not page.auto_box.isChecked()
    assert "Never" in page.last_label.text()
    for box in (page.check_box, page.auto_box):  # on the indicator, as a user clicks
        QTest.mouseClick(box, Qt.MouseButton.LeftButton, pos=QPoint(8, box.height() // 2))
    assert dialog.dirty_page_ids() == ["updates"]
    QTest.mouseClick(page.check_now_button, Qt.MouseButton.LeftButton)
    wait_for(lambda: idle(controller))
    assert NEW in page.last_label.text()
    QTest.mouseClick(dialog.buttons.button(QDialogButtonBox.StandardButton.Ok),
                     Qt.MouseButton.LeftButton)
    pump()
    data = json.loads(stores.settings.read_text())
    assert data[SU.SETTING_CHECK] is False and data[SU.SETTING_AUTO] is True


def test_edge_settings_page_names_why_the_start_check_is_off(stores, fake, monkeypatch):
    monkeypatch.setenv(SU.NO_CHECK_ENV, "1")
    win, controller = started_window(stores, fake)
    dialog = stores.settings_dialog(win, "updates")
    page = dialog.page("updates")
    assert SU.NO_CHECK_ENV in page.start_note.text()


def test_happy_settings_finds_the_page_by_name(stores, fake):
    win, controller = started_window(stores, fake)
    dialog = stores.settings_dialog(win)
    dialog.apply_filter("github")
    assert "updates" in dialog.visible_page_ids()


# --- the release notes are Markdown (docs/plans entry 4) --------------------------------
#
# The body comes from the network: it is rendered with Qt's own Markdown,
# raw HTML is shown as text, no resource is ever loaded and only http(s)
# links open, through core.desktop_open.

import http.server  # noqa: E402
import threading  # noqa: E402

from PyQt6.QtCore import QUrl  # noqa: E402
from PyQt6.QtGui import QFont, QTextDocument  # noqa: E402


class _Counter:
    """A loopback HTTP server that counts every request it gets."""

    def __init__(self):
        hits = self.hits = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802 - http.server API
                hits.append(self.path)
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *args):
                pass

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def counter():
    server = _Counter()
    yield server
    server.close()


def notes_view(text: str):
    from ui.update_ui import ReleaseNotesView

    view = ReleaseNotesView()
    view.set_notes(text)
    view.resize(500, 400)
    view.show()
    pump(0.1)
    return view


def fragments(view):
    """(text, char format, href) of every text fragment, in order."""
    out = []
    block = view.document().begin()
    while block.isValid():
        it = block.begin()
        while not it.atEnd():
            frag = it.fragment()
            if frag.isValid():
                fmt = frag.charFormat()
                out.append((frag.text(), fmt, fmt.anchorHref()))
            it += 1
        block = block.next()
    return out


def click_anchor(view, href: str) -> None:
    """A real mouse click on the first fragment linking to *href*."""
    from PyQt6.QtGui import QTextCursor

    block = view.document().begin()
    while block.isValid():
        it = block.begin()
        while not it.atEnd():
            frag = it.fragment()
            if frag.isValid() and frag.charFormat().anchorHref() == href:
                cursor = QTextCursor(view.document())
                cursor.setPosition(frag.position() + max(0, frag.length() // 2))
                rect = view.cursorRect(cursor)
                QTest.mouseClick(view.viewport(), Qt.MouseButton.LeftButton,
                                 Qt.KeyboardModifier.NoModifier, rect.center())
                pump()
                return
            it += 1
        block = block.next()
    raise AssertionError(f"no link to {href}")


def test_happy_bold_renders_bold():
    view = notes_view("Now **much faster** than before")
    bold = [(t, f) for t, f, _ in fragments(view) if t == "much faster"]
    assert bold and bold[0][1].fontWeight() >= QFont.Weight.Bold
    assert "**" not in view.toPlainText()


def test_happy_a_heading_renders_as_a_heading():
    view = notes_view("## What is new\n\n- faster\n")
    first = view.document().begin()
    assert first.text() == "What is new" and first.blockFormat().headingLevel() == 2
    assert "##" not in view.toPlainText()
    assert view.document().begin().next().textList() is not None  # "- faster" is a list


def test_sad_a_remote_image_is_never_fetched(counter):
    view = notes_view(f"![logo]({counter.url}/logo.png)\n\ntext after\n")
    pump(0.5)
    assert f"{counter.url}/logo.png" in view.refused_resources  # asked, refused
    assert counter.hits == []  # nothing fetched
    assert "text after" in view.toPlainText()


@pytest.mark.parametrize("url", ["http://127.0.0.1:9/a.png", "https://example.org/a.css",
                                 "file:///etc/passwd", "/etc/hostname", "data:image/png;base64,AA",
                                 "qrc:/icon.png", "a.png"])
def test_sad_load_resource_returns_nothing(url):
    from ui.update_ui import ReleaseNotesView

    view = ReleaseNotesView()
    for kind in (QTextDocument.ResourceType.ImageResource,
                 QTextDocument.ResourceType.StyleSheetResource,
                 QTextDocument.ResourceType.HtmlResource):
        assert view.loadResource(kind.value, QUrl(url)) is None


def test_sad_raw_html_is_shown_as_text_not_run(counter):
    """Qt's Markdown would interpret raw HTML (a <script> block swallows
    the rest of the notes, <img> loads); here it is plain text."""
    view = notes_view(f"<b>not bold</b> <img src='{counter.url}/x.png'>\n\n"
                      "<script>alert(1)</script>\n\n## Still here\n")
    pump(0.3)
    text = view.toPlainText()
    assert "<b>not bold</b>" in text and "<script>alert(1)</script>" in text
    assert "Still here" in text
    assert all(f.fontWeight() < QFont.Weight.Bold for t, f, _ in fragments(view)
               if "not bold" in t)
    assert counter.hits == []


@pytest.mark.parametrize("href", ["javascript:alert(1)", "file:///etc/passwd", "ftp://host/x",
                                  "data:text/html,hi", "#section", "relative/page",
                                  "https:///no-host"])
def test_sad_a_non_web_link_is_not_opened(href):
    view = notes_view(f"[click]({href})")
    with mock.patch("core.desktop_open.open_url") as open_url:
        view.anchorClicked.emit(QUrl(href))
        pump()
    open_url.assert_not_called()


def test_happy_a_web_link_opens_through_desktop_open():
    view = notes_view("[release](https://github.com/c0decave/axross/releases)")
    with mock.patch("core.desktop_open.open_url") as open_url:
        click_anchor(view, "https://github.com/c0decave/axross/releases")
    (call,) = open_url.call_args_list
    assert call.args[0].toString() == "https://github.com/c0decave/axross/releases"


def test_edge_empty_notes_hide_the_view(stores, fake):
    fake.release.notes = ""
    win, controller = started_window(stores, fake)
    win.start_update_check()
    wait_for(lambda: idle(controller))
    win.show_update_dialog()
    (dialog,) = update_dialogs()
    assert not dialog.notes.isVisible()
    assert dialog.link_label.isVisible()  # the release page is still offered
    dialog.notes.set_notes("")
    assert dialog.notes.toPlainText() == ""


def test_edge_whitespace_only_notes_render_nothing():
    view = notes_view("   \n\n  ")
    assert view.toPlainText().strip() == ""


def test_happy_e2e_the_dialog_renders_the_notes_and_guards_the_links(stores, fake, counter):
    fake.release.notes = (
        "## Highlights\n\n**Signed** updates.\n\n"
        f"![shot]({counter.url}/shot.png)\n\n"
        "[Changelog](https://github.com/c0decave/axross/releases) "
        "[evil](javascript:alert(1)) [local](file:///etc/passwd)\n")
    win, controller = started_window(stores, fake)
    win.start_update_check()
    wait_for(lambda: idle(controller))
    QTest.mouseClick(win._version_button, Qt.MouseButton.LeftButton)
    pump(0.3)
    (dialog,) = update_dialogs()
    notes = dialog.notes
    assert notes.isVisible()
    assert notes.document().begin().text() == "Highlights"
    assert notes.document().begin().blockFormat().headingLevel() == 2
    assert "**" not in notes.toPlainText() and "##" not in notes.toPlainText()
    assert counter.hits == []
    clicked: list[str] = []
    notes.anchorClicked.connect(lambda url: clicked.append(url.toString()))
    with mock.patch("core.desktop_open.open_url") as open_url:
        click_anchor(notes, "javascript:alert(1)")
        click_anchor(notes, "file:///etc/passwd")
        open_url.assert_not_called()
        click_anchor(notes, "https://github.com/c0decave/axross/releases")
    assert [c.args[0].toString() for c in open_url.call_args_list] == [
        "https://github.com/c0decave/axross/releases"]
    # every click reached the link handler; only the web link was opened
    assert clicked == ["javascript:alert(1)", "file:///etc/passwd",
                       "https://github.com/c0decave/axross/releases"]
    dialog.refresh()  # a refresh with the same notes keeps the document
    assert notes.document().begin().text() == "Highlights"


def test_happy_e2e_long_notes_open_at_their_first_line(stores, fake):
    """Seen on the 0.14.102 dialog: the notes opened scrolled to their end -
    setMarkdown left the text cursor there, and showing the view scrolled to
    it. A reader starts at the top."""
    fake.release.notes = "## Highlights\n\n" + "".join(
        f"- change number {i}, with enough words to fill the line\n" for i in range(200))
    win, controller = started_window(stores, fake)
    win.start_update_check()
    wait_for(lambda: idle(controller))
    QTest.mouseClick(win._version_button, Qt.MouseButton.LeftButton)
    pump(0.3)
    (dialog,) = update_dialogs()
    bar = dialog.notes.verticalScrollBar()
    assert bar.maximum() > 0  # the notes do not fit: there is somewhere to scroll
    assert bar.value() == 0
    assert dialog.notes.textCursor().position() == 0


def test_edge_new_notes_start_at_the_top_again():
    view = notes_view("".join(f"line {i}\n\n" for i in range(300)))
    view.resize(300, 120)
    view.show()
    view.verticalScrollBar().setValue(view.verticalScrollBar().maximum())
    view.set_notes("".join(f"other {i}\n\n" for i in range(300)))
    pump()
    assert view.verticalScrollBar().value() == 0 and view.textCursor().position() == 0


# --- the version bottom right ----------------------------------------------------


def test_happy_e2e_the_version_says_update_available_and_opens_the_dialog(stores, fake, binary):
    assert not SU.auto_download()
    win, controller = started_window(stores, fake, frozen(binary))
    assert notice(win) is None
    win.start_update_check()
    wait_for(lambda: idle(controller))
    assert notice(win) == f"Update available: {NEW}"
    assert win._version_button.cursor().shape() == Qt.CursorShape.PointingHandCursor
    assert NEW in win._version_button.toolTip()
    assert update_dialogs() == []  # nothing opens by itself
    QTest.mouseClick(win._version_button, Qt.MouseButton.LeftButton)
    pump()
    (dialog,) = update_dialogs()
    assert NEW in dialog.status_label.text()
    assert dialog.download_button.isVisible()


def test_edge_the_plain_version_opens_nothing(stores, fake):
    fake.release.version = __version__
    win, controller = started_window(stores, fake)
    win.start_update_check()
    wait_for(lambda: idle(controller))
    assert notice(win) is None
    assert win._version_button.cursor().shape() != Qt.CursorShape.PointingHandCursor
    QTest.mouseClick(win._version_button, Qt.MouseButton.LeftButton)
    pump()
    assert update_dialogs() == []


def test_happy_e2e_with_automatic_download_the_version_leads_to_restart(stores, fake, binary):
    SU.set_auto_download(True)
    win, controller = started_window(stores, fake, frozen(binary))
    win.start_update_check()
    wait_for(lambda: controller.state in ("installed", "error"), 15)
    assert notice(win) == f"Restart to Use {NEW}…"
    assert update_dialogs() == []
    QTest.mouseClick(win._version_button, Qt.MouseButton.LeftButton)
    pump()
    (dialog,) = update_dialogs()
    assert dialog.restart_button.isVisible()


def test_sad_a_failed_check_leaves_the_plain_version(stores, fake):
    fake.api_status = 500
    win, controller = started_window(stores, fake)
    win.start_update_check()
    wait_for(lambda: idle(controller))
    assert controller.state == "error" and notice(win) is None


@pytest.mark.parametrize("theme", ["modern-dark", "modern-light", "classic", "hacker",
                                   "amber", "native"])
def test_edge_every_theme_shows_the_version_plain_and_the_notice_in_its_accent(theme):
    from ui import themes as TH

    css = TH.stylesheet_for(theme, "dark")
    key = "classic" if TH.resolve(theme, "dark") in ("classic", "dark") else TH.resolve(theme, "dark")
    muted, _base, accent, _mark = TH._INDICATOR_COLOURS[key]
    plain_rule = css.split("QPushButton#axVersion {", 1)[1].split("}", 1)[0]
    assert "border: none" in plain_rule and f"color: {muted}" in plain_rule
    notice_rule = css.split('QPushButton#axVersion[notice="true"] {', 1)[1].split("}", 1)[0]
    assert f"color: {accent}" in notice_rule and "font-weight: bold" in notice_rule
