"""The Android Device window (ui.android_device): an ADB connection's phone
in axross's own window - Info, Apps, SMS, Logcat, Screenshot - against a
scripted fake phone, offscreen.

Every device call runs off the GUI thread: while a slow phone answers, the
window's event loop keeps running (the heartbeat test counts a timer's
ticks during the call). Every change asks first; Uninstall and Reboot
count down; a production profile goes through the production gate; the
paranoid mode turns the changes off. It is reached from the ADB pane's
right-click menu (More > Android Device…) and from Pane > Android Device….
"""

from __future__ import annotations

import os
import re
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets")
from PyQt6.QtCore import QTimer  # noqa: E402
from PyQt6.QtWidgets import QApplication, QDialog, QMessageBox  # noqa: E402

from core.local_fs import LocalFS  # noqa: E402
from tests.fake_android import tiny_png  # noqa: E402
from tests.test_adb_device import DUMPSYS, IDENTITY, FakeShell, parcel, stored  # noqa: E402
from ui import android_device as D  # noqa: E402

APP = QApplication.instance() or QApplication([])

BATTERY = ("Current Battery Service state:\n  USB powered: true\n  status: 2\n  health: 2\n"
           "  level: 85\n  scale: 100\n  temperature: 281\n  technology: Li-ion\n")
PACKAGES = ("package:com.android.settings versionCode:34 uid:1000  installer=null\n"
            "package:org.example.notes versionCode:120 uid:10234  installer=com.android.vending\n")


def rules(**extra):
    base = [IDENTITY, (r"^id -u$", "2000\n"), (r"^service call", parcel("490154203237518")),
            (r"^dumpsys battery$", BATTERY),
            (r"^df /data$", "Filesystem 1K-blocks Used Available Use% Mounted on\n"
                            "/dev/block/dm-5 115000000 15000000 100000000 13% /data\n"),
            (r"pm list packages -s$", "package:com.android.settings\n"),
            (r"pm list packages -d$", ""),
            (r"pm list packages -i -U --show-versioncode$", PACKAGES),
            (r"^pm path org\.example\.notes$", "package:/data/app/x/base.apk\n"),
            (r"^dumpsys package org\.example\.notes$", DUMPSYS),
            (r"^pidof", (1, "")),
            (r"resolve-activity", "org.example.notes/.MainActivity\n"),
            (r"^am start", "Status: ok\n"),
            (r"^pm uninstall", "Success\n"),
            (r"^pm grant", ""), (r"^echo AXALIVE$", "AXALIVE\n"),
            (r"--projection _id --sort", "Row: 0 _id=4\n"),
            (r"--where _id=4 ", stored(4, "Bank", "Your code is 4711")),
            (r"content insert", ""), (r"--where date=", "Row: 0 _id=4\n"),
            (r"^logcat", "11-22 10:00:00.000  4321  4321 I Notes   : saved\n"),
            (r"^screencap", "")]
    return list(extra.get("first", [])) + base


class AdbSession:
    """Stands in for core.adb_client.AdbSession: a FakeShell, optionally slow."""

    def __init__(self, shell, delay: float = 0.0, production: bool = False):
        self.fake = shell
        self.delay = delay
        self.threads = set()
        if production:
            from core.profiles import ConnectionProfile

            self._axross_profile = ConnectionProfile(name="prod-phone", protocol="adb",
                                                     production=True)
            self._axross_profile_key = "prod-phone#1"

    def exec(self, command, *, timeout=30.0, stdout_cap=1 << 20, **_kw):
        self.threads.add(threading.current_thread().name)
        if self.delay:
            time.sleep(self.delay)
        return self.fake.exec(command, timeout=timeout, stdout_cap=stdout_cap)

    def push_stream(self, source, remote_path):
        self.fake.push_stream(source, remote_path)

    def pull_stream(self, remote_path, sink, max_bytes):
        sink.write(self.fake.files.get(remote_path, tiny_png(4, 2)))


def wait(tab, seconds: float = 10.0) -> None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        APP.processEvents()
        if not tab.job.running:
            APP.processEvents()
            return
        time.sleep(0.01)
    raise AssertionError("the device call never ended")


@pytest.fixture()
def window(request):
    shell = FakeShell(rules())
    backend = AdbSession(shell, **getattr(request, "param", {}))
    win = D.AndroidDeviceWindow(backend)
    win.countdown_s = 0.2
    win.show()
    wait(win.info_tab)
    win.tabs.setCurrentIndex(1)  # Apps reads the device when it is first shown
    wait(win.apps_tab)
    yield win, shell, backend
    win.close()
    APP.processEvents()


@pytest.fixture()
def yes(monkeypatch):
    asked = []

    def question(_parent, title, text, *_args, **_kw):
        asked.append((title, text))
        return QMessageBox.StandardButton.Yes

    monkeypatch.setattr(QMessageBox, "question", staticmethod(question))
    monkeypatch.setattr(D.CountdownDialog, "exec", lambda self: QDialog.DialogCode.Accepted)
    return asked


def test_info_shows_the_phone_and_its_battery(window):
    win, shell, backend = window
    values = {k: v.text() for k, v in win.info_tab.values.items()}
    assert values["model"] == "Pixel 6" and values["android_version"] == "14"
    assert values["imei"] == "490154203237518" and values["serial"] == "1A2B3C4D"
    assert values["battery"].startswith("85 %") and "28.1" in values["battery"]
    assert values["storage"].startswith("95.4 GB free of 109.7 GB")
    # Off the GUI thread, every call.
    assert threading.main_thread().name not in backend.threads


@pytest.mark.parametrize("window", [{"delay": 0.3}], indirect=True)
def test_the_window_stays_responsive_while_a_slow_phone_answers(window):
    win, shell, backend = window
    ticks = []
    timer = QTimer()
    timer.setInterval(20)
    timer.timeout.connect(lambda: ticks.append(time.monotonic()))
    timer.start()
    started = time.monotonic()
    win.info_tab.refresh()  # about ten commands of 0.3 s each
    assert win.info_tab.job.running
    wait(win.info_tab, 30)
    took = time.monotonic() - started
    timer.stop()
    assert took > 1.0
    # The loop ran all along: no gap between two ticks much longer than one.
    gaps = [b - a for a, b in zip(ticks, ticks[1:])]
    assert len(ticks) > took / 0.1 and max(gaps) < 0.25, (len(ticks), max(gaps))


def test_apps_are_listed_and_filtered(window):
    win, _shell, _backend = window
    tab = win.apps_tab
    assert tab.table.rowCount() == 2
    tab.filter_edit.setText("notes")
    assert tab.table.rowCount() == 1 and tab.table.item(0, 0).text() == "org.example.notes"
    assert tab.table.item(0, 3).text() == "user"


def _select(tab, package):
    tab.filter_edit.setText(package)
    tab.table.setCurrentCell(0, 0)


def test_start_asks_first_and_runs_off_the_gui_thread(window, monkeypatch):
    win, shell, _backend = window
    tab = win.apps_tab
    _select(tab, "org.example.notes")
    monkeypatch.setattr(QMessageBox, "question", staticmethod(
        lambda *a, **k: QMessageBox.StandardButton.No))
    tab.start()
    wait(tab)
    assert not any(c.startswith("am start") for c in shell.commands)
    monkeypatch.setattr(QMessageBox, "question", staticmethod(
        lambda *a, **k: QMessageBox.StandardButton.Yes))
    tab.start()
    wait(tab)
    assert "am start -W -n org.example.notes/.MainActivity" in shell.commands
    assert "started" in tab.note.text()


def test_uninstall_counts_down_and_can_be_stopped(window, yes, monkeypatch):
    win, shell, _backend = window
    tab = win.apps_tab
    _select(tab, "org.example.notes")
    monkeypatch.setattr(D.CountdownDialog, "exec", lambda self: QDialog.DialogCode.Rejected)
    tab.uninstall()
    wait(tab)
    assert not any(c.startswith("pm uninstall") for c in shell.commands)
    monkeypatch.setattr(D.CountdownDialog, "exec", lambda self: QDialog.DialogCode.Accepted)
    tab.uninstall()
    wait(tab)
    assert "pm uninstall org.example.notes" in shell.commands


def test_the_countdown_dialog_goes_ahead_when_it_ends():
    dialog = D.CountdownDialog("reboot the device", 0.2)
    assert D.QDialog.exec is not D.CountdownDialog.exec
    started = time.monotonic()
    assert dialog.exec() == QDialog.DialogCode.Accepted
    assert time.monotonic() - started >= 0.15


@pytest.mark.parametrize("window", [{"production": True}], indirect=True)
def test_a_production_profile_passes_the_production_gate(window, yes, monkeypatch):
    import ui.production_gate as G

    win, shell, _backend = window
    gated = []
    monkeypatch.setattr(G, "confirm_production", lambda parent, backend, op: gated.append(op) or False)
    _select(win.apps_tab, "org.example.notes")
    win.apps_tab.stop()
    wait(win.apps_tab)
    assert gated == ["force-stop org.example.notes"]
    assert not any("force-stop" in c for c in shell.commands)


def test_paranoid_mode_turns_the_changes_off(monkeypatch):
    from core import security_mode

    monkeypatch.setattr(security_mode, "_CURRENT", security_mode.PARANOID)
    win = D.AndroidDeviceWindow(AdbSession(FakeShell(rules())))
    try:
        assert not win.apps_tab.buttons["uninstall"].isEnabled()
        assert not win.info_tab.reboot_button.isEnabled() and not win.sms_tab.send_button.isEnabled()
        assert win.apps_tab.buttons["details"].isEnabled() and win.apps_tab.buttons["backup"].isEnabled()
    finally:
        win.close()


def test_details_show_permissions_and_grant_asks(window, yes, monkeypatch):
    win, shell, _backend = window
    tab = win.apps_tab
    _select(tab, "org.example.notes")
    shown = []
    monkeypatch.setattr(D.AppInfoDialog, "exec", lambda self: shown.append(self) or 0)
    tab.details()
    wait(tab)
    [dialog] = shown
    assert dialog.table.rowCount() == 2 and dialog.table.item(0, 0).text() == "android.permission.CAMERA"
    dialog.table.setCurrentCell(0, 0)
    dialog.change("grant")
    wait(tab)
    assert "pm grant org.example.notes android.permission.CAMERA" in shell.commands


def test_back_up_apk_saves_fresh_files(window, tmp_path, monkeypatch):
    win, shell, _backend = window
    shell.files["/data/app/x/base.apk"] = b"PK\x03\x04apk"
    shell.rules.insert(0, (re.compile(r"^pm list packages --show-versioncode"),
                           "package:org.example.notes versionCode:120\n"))
    monkeypatch.setattr(D.QFileDialog, "getExistingDirectory", staticmethod(lambda *a, **k: str(tmp_path)))
    tab = win.apps_tab
    _select(tab, "org.example.notes")
    for _ in range(2):
        tab.backup()
        wait(tab)
    assert sorted(os.listdir(tmp_path)) == ["org.example.notes-120-base (2).apk",
                                            "org.example.notes-120-base.apk"]
    assert (tmp_path / "org.example.notes-120-base.apk").read_bytes() == b"PK\x03\x04apk"


def test_install_apk_asks_and_sends_the_file(window, yes, tmp_path, monkeypatch):
    win, shell, _backend = window
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"PK\x03\x04new")
    shell.rules.insert(0, (re.compile(r"^pm install"), "Success\n"))
    monkeypatch.setattr(D.QFileDialog, "getOpenFileName", staticmethod(lambda *a, **k: (str(apk), "")))
    win.apps_tab.install()
    wait(win.apps_tab)
    assert list(shell.pushed.values()) == [b"PK\x03\x04new"] and "installed" in win.apps_tab.note.text()


def test_sms_are_read_and_written_only_after_asking(window, yes, monkeypatch):
    win, shell, _backend = window
    tab = win.sms_tab
    tab.refresh()
    wait(tab)
    assert tab.table.rowCount() == 1 and tab.table.item(0, 2).text() == "Your code is 4711"
    monkeypatch.setattr(tab, "_ask", lambda title, who: ("Bank", "Your code is 4711"))
    tab.write()
    wait(tab)
    assert any(c.startswith("content insert") for c in shell.commands) and tab.note.text() == "Stored."
    assert yes and "Nothing is sent" in yes[-1][1]
    shell.rules.insert(0, (re.compile(r"SENDTO"), "Status: ok\n"))
    monkeypatch.setattr(tab, "_ask", lambda title, who: ("+4915112345678", "Hallo"))
    tab.prepare()
    wait(tab)
    assert any("SENDTO" in c for c in shell.commands) and "nothing" in tab.note.text()


def test_logcat_reads_follows_pauses_and_saves(window, tmp_path, monkeypatch):
    win, shell, _backend = window
    tab = win.logcat_tab
    tab.priority.setCurrentIndex(3)  # Warning
    tab.tag.setText("Notes")
    tab.refresh()
    wait(tab)
    assert "saved" in tab.view.toPlainText()
    assert any(c.endswith("Notes:W '*:S'") for c in shell.commands)
    tab.pause_button.setChecked(True)
    tab.view.setPlainText("kept")
    tab.refresh()
    wait(tab)
    assert tab.view.toPlainText() == "kept"  # paused: no update
    tab.follow.setChecked(True)
    assert tab.timer.isActive()
    tab.follow.setChecked(False)
    target = tmp_path / "log.txt"
    monkeypatch.setattr(D.QFileDialog, "getSaveFileName", staticmethod(lambda *a, **k: (str(target), "")))
    tab.save()
    assert target.read_text() == "kept\n"


def test_screenshot_is_shown_and_saved(window, tmp_path, monkeypatch):
    win, shell, _backend = window
    tab = win.screenshot_tab
    tab.take()
    wait(tab)
    assert tab.image.pixmap() is not None and not tab.image.pixmap().isNull()
    assert "4 × 2" in tab.note.text() and tab.save_button.isEnabled()
    target = tmp_path / "shot.png"
    monkeypatch.setattr(D.QFileDialog, "getSaveFileName", staticmethod(lambda *a, **k: (str(target), "")))
    tab.save()
    assert target.read_bytes() == tiny_png(4, 2)
    assert shell.commands[-1].startswith("rm -f /data/local/tmp/axross-shot-")


def test_reboot_counts_down(window, yes):
    win, shell, _backend = window
    win.info_tab.reboot_mode.setCurrentIndex(1)
    win.info_tab.reboot()
    wait(win.info_tab)
    assert "reboot recovery" in shell.commands


def test_an_error_is_said_in_the_tab(window):
    win, shell, _backend = window
    shell.rules.insert(0, (re.compile(r"--projection _id --sort"),
                           "Error while accessing provider:sms\njava.lang.SecurityException: "
                           "Permission Denial: requires android.permission.READ_SMS\n"))
    win.sms_tab.refresh()
    wait(win.sms_tab)
    assert "READ_SMS" in win.sms_tab.note.text()


def test_closing_the_window_drops_a_running_call():
    backend = AdbSession(FakeShell(rules()), delay=0.5)
    win = D.AndroidDeviceWindow(backend)
    win.show()
    APP.processEvents()
    assert win.info_tab.job.running
    jobs = win.jobs()
    win.close()
    APP.processEvents()
    assert all(job._abandoned for job in jobs)


def test_one_window_per_connection():
    backend = AdbSession(FakeShell(rules()))
    first = D.open_for(backend)
    try:
        assert D.open_for(backend) is first
    finally:
        first.close()
        APP.processEvents()


def test_the_pane_and_the_pane_menu_open_it(monkeypatch, tmp_path):
    from ui.file_pane import FilePaneWidget

    class AdbSessionFS(LocalFS):
        def exec(self, *a, **k):
            raise OSError("no device here")

    AdbSessionFS.__name__ = "AdbSession"
    pane = FilePaneWidget(AdbSessionFS())
    plain = FilePaneWidget(LocalFS())
    try:
        def commands(widget):
            menu = widget._build_context_menu()
            found = []
            stack = [menu]
            while stack:
                for action in stack.pop().actions():
                    if action.menu() is not None:
                        stack.append(action.menu())
                    found.append(action.property("axCommand"))
            return found

        assert "android-device" in commands(pane) and "android-device" not in commands(plain)
        opened = []
        monkeypatch.setattr(D, "open_for", lambda backend, parent=None: opened.append(backend) or True)
        assert pane.open_android_device() is True and plain.open_android_device() is None
        assert opened == [pane._backend]
    finally:
        for widget in (pane, plain):
            widget.close()
            widget.deleteLater()
        APP.processEvents()


def test_every_text_of_the_window_has_a_german_translation():
    import ast
    import json

    german = json.loads((Path(D.__file__).resolve().parents[1] / "resources" / "i18n" / "de.json")
                        .read_text(encoding="utf-8"))
    tree = ast.parse(Path(D.__file__).read_text(encoding="utf-8"))
    texts = {node.args[0].value for node in ast.walk(tree)
             if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "tr"
             and node.args and isinstance(node.args[0], ast.Constant)}
    # The labels of the tables, buttons and choices go through tr() by name:
    # the second item of each (key, label[, slot]) row a loop walks.
    for node in ast.walk(tree):
        rows = [node.iter] if isinstance(node, ast.For) else (
            [node.value] if isinstance(node, ast.Assign)
            and getattr(node.targets[0], "id", "") in ("FIELDS", "COLUMNS") else [])
        for row in (r for top in rows for r in ast.walk(top) if isinstance(r, ast.Tuple)):
            if len(row.elts) in (2, 3) and isinstance(row.elts[1], ast.Constant) \
                    and isinstance(row.elts[1].value, str):
                texts.add(row.elts[1].value)
        if isinstance(node, ast.Assign) and getattr(node.targets[0], "id", "") == "COLUMNS":
            texts |= {c.value for c in node.value.elts}
    texts |= {"charging", "discharging", "not charging", "full", "unknown", "good", "overheat",
              "dead", "over voltage", "failure", "cold"}
    missing = sorted(t for t in texts if t not in german)
    assert missing == []
    du = [german[t] for t in texts if re.search(r"\b(Sie|Ihre?n?|Ihnen)\b", german[t])]
    assert du == []


def test_the_pane_menu_entry_follows_the_active_pane(monkeypatch):
    from types import SimpleNamespace

    from PyQt6.QtGui import QAction

    from ui.main_window import MainWindow

    class AdbSessionFS(LocalFS):
        def exec(self, *a, **k):
            raise OSError("no device here")

    AdbSessionFS.__name__ = "AdbSession"
    action = QAction()
    shown = []
    status = SimpleNamespace(showMessage=lambda text, ms: shown.append(text))
    phone = SimpleNamespace(_backend=AdbSessionFS(), open_android_device=lambda: True)
    disk = SimpleNamespace(_backend=LocalFS(), open_android_device=lambda: None)
    for pane, enabled in ((phone, True), (disk, False), (None, False)):
        win = SimpleNamespace(_active_pane=pane, _android_device_action=action,
                              statusBar=lambda: status)
        MainWindow._sync_android_device_action(win)
        assert action.isEnabled() is enabled
        assert (MainWindow._open_android_device(win) is True) is enabled
    assert len(shown) == 2 and "no Android device" in shown[0]
