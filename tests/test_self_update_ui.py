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
    assert not win._update_button.isVisible()
    assert win.start_update_check() is True
    wait_for(lambda: idle(controller))
    assert controller.state == "available"
    assert win._update_button.isVisible()
    assert plain(win._update_button.text()) == f"Update to {NEW}…"
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
    assert not win._update_button.isVisible()


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
    assert not win._update_button.isVisible()
    assert "rate limit" in SU.last_check()[1]
    assert any("rate limit" in r.getMessage() for r in caplog.records)


def test_edge_up_to_date_shows_nothing(stores, fake):
    fake.release.version = __version__
    win, controller = started_window(stores, fake)
    win.start_update_check()
    wait_for(lambda: idle(controller))
    assert controller.state == "current" and not win._update_button.isVisible()


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
    QTest.mouseClick(win._update_button, Qt.MouseButton.LeftButton)
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
    assert plain(win._update_button.text()) == f"Restart to Use {NEW}…"
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
    assert fake.hosts().count("release-assets.githubusercontent.com") == 2  # not again


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
    assert not win._update_button.isVisible() and closed(win)
    # The next start: the skipped version gives no notice.
    second, controller2 = started_window(stores, fake)
    second.start_update_check()
    wait_for(lambda: idle(controller2))
    assert controller2.state == "available" and not second._update_button.isVisible()
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
    assert not win._update_button.isVisible() and closed(win)
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
    assert plain(win._update_button.text()) == f"Restart to Use {NEW}…"
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
