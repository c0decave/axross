"""Tools > Find on Network Hosts (SMB)…: the dialog over core.remote_sweep.

Targets, one login, a name pattern, "only my files", the number of hosts
searched at once (a setting, default 4). Results stream in while hosts are
searched; Cancel and closing the dialog stop the run; a run over many hosts
asks first. The sweep itself is replaced by a fake here except in the live
test, which searches the podman lab Samba.
"""

from __future__ import annotations

import csv
import os
import sys
import threading
import time
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

QtWidgets = pytest.importorskip("PyQt6.QtWidgets")

from tests.test_remote_sweep import LAB_PASS, LAB_SMB, LAB_USER, lab  # noqa: E402


@pytest.fixture(scope="module")
def app():
    return QtWidgets.QApplication.instance() or QtWidgets.QApplication([])


@pytest.fixture
def settings(monkeypatch):
    from core import open_limits as OL

    store: dict = {}
    monkeypatch.setattr(OL, "read_setting", lambda key, default=None: store.get(key, default))
    monkeypatch.setattr(OL, "write_setting", lambda key, value: store.__setitem__(key, value))
    return store


def _wait(app, cond, timeout=5.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        app.processEvents()
        if cond():
            return True
        time.sleep(0.01)
    return False


def _fake_sweep(hits_per_host=2, delay=0.0, abort=None, block=None):
    """A stand-in for core.remote_sweep.sweep with the same contract."""
    from core import remote_sweep as RS
    from core.net_helpers import parse_targets

    calls = []

    def sweep(config, *, on_hit, on_status, cancel=None, **kw):
        calls.append(config)
        hosts = parse_targets(config.targets, max_hosts=config.max_hosts)
        result = RS.SweepResult(hosts_total=len(hosts))
        for host in hosts:
            if cancel is not None and cancel.is_set():
                on_status(host, "skipped", "")
                continue
            if block is not None:
                block.wait(5)
            on_status(host, "searching", "")
            for i in range(hits_per_host):
                time.sleep(delay)
                on_hit(RS.SweepHit(host, "data", f"/dir/file{i}.txt", 100 + i, 1_700_000_000.0))
                result.hits += 1
            on_status(host, "done", "")
            result.hosts_searched += 1
        if abort:
            result.aborted, result.abort_reason = True, abort
        result.cancelled = bool(cancel and cancel.is_set())
        return result

    return sweep, calls


def _dialog(app, settings, sweep, **kw):
    from ui.network_search_dialog import NetworkSearchDialog

    dlg = NetworkSearchDialog(sweep_fn=sweep, **kw)
    dlg.targets_edit.setPlainText("fs1 fs2")
    dlg.user_edit.setText("alice")
    dlg.password_edit.setText("pw")
    return dlg


def test_happy_results_and_host_states_stream_in(app, settings):
    sweep, calls = _fake_sweep()
    dlg = _dialog(app, settings, sweep)
    dlg.name_edit.setText("*.txt")
    dlg.owner_check.setChecked(True)
    dlg.start_button.click()
    assert _wait(app, lambda: not dlg.is_running())
    assert dlg.results_table.rowCount() == 4
    assert {dlg.results_table.item(r, 0).text() for r in range(4)} >= {r"\\fs1\data\dir\file0.txt"}
    states = {dlg.hosts_table.item(r, 0).text(): dlg.hosts_table.item(r, 1).text()
              for r in range(dlg.hosts_table.rowCount())}
    assert states == {"fs1": "done", "fs2": "done"}
    config = calls[0]
    assert (config.username, config.password, config.name, config.owner_only) == ("alice", "pw", "*.txt", True)
    assert config.parallel == 4
    assert "4 files" in dlg.summary_label.text()
    dlg.close()


def test_happy_parallel_is_the_setting_and_can_be_stored(app, settings):
    from core import remote_sweep as RS

    settings[RS.PARALLEL_SETTING] = 6
    sweep, calls = _fake_sweep()
    dlg = _dialog(app, settings, sweep)
    assert dlg.parallel_spin.value() == 6
    dlg.parallel_spin.setValue(9)
    dlg.remember_parallel_check.setChecked(True)
    dlg.start_button.click()
    assert _wait(app, lambda: not dlg.is_running())
    assert calls[0].parallel == 9 and settings[RS.PARALLEL_SETTING] == 9
    dlg.close()


def test_happy_tools_menu_opens_it(app, settings, tmp_path):
    from ui import main_window as MW

    with mock.patch.object(MW.MainWindow, "_SESSION_FILE", tmp_path / "s.json"), \
            mock.patch.object(MW.MainWindow, "_RECENTS_FILE", tmp_path / "r.json"), \
            mock.patch("pathlib.Path.home", return_value=tmp_path):
        win = MW.MainWindow()
    try:
        action = win._network_search_action
        assert "Find on Network Hosts" in action.text().replace("&", "")
        action.trigger()
        dlg = win._network_search_dialog
        assert dlg.isVisible()
        dlg.close()
    finally:
        win.close()
        win.deleteLater()


def test_sad_bad_targets_show_an_error_and_start_nothing(app, settings):
    sweep, calls = _fake_sweep()
    dlg = _dialog(app, settings, sweep)
    dlg.targets_edit.setPlainText("10.0.0.0/8")
    dlg.start_button.click()
    app.processEvents()
    assert calls == [] and not dlg.is_running()
    assert "limit" in dlg.error_label.text()
    dlg.targets_edit.setPlainText("")
    dlg.start_button.click()
    assert calls == [] and "no targets" in dlg.error_label.text()
    dlg.close()


def test_sad_an_aborted_run_says_why_in_red(app, settings):
    sweep, _ = _fake_sweep(abort="fs1: STATUS_LOGON_FAILURE")
    dlg = _dialog(app, settings, sweep)
    dlg.start_button.click()
    assert _wait(app, lambda: not dlg.is_running())
    assert "STATUS_LOGON_FAILURE" in dlg.error_label.text()
    assert "pw" not in dlg.error_label.text().replace("Stopped", "")
    dlg.close()


def test_sad_many_hosts_ask_first_and_no_starts_nothing(app, settings):
    from PyQt6.QtWidgets import QMessageBox

    sweep, calls = _fake_sweep(hits_per_host=0)
    dlg = _dialog(app, settings, sweep)
    dlg.targets_edit.setPlainText("10.0.0.0/23")  # 510 hosts
    with mock.patch("ui.network_search_dialog.QMessageBox.question",
                    return_value=QMessageBox.StandardButton.No) as asked:
        dlg.start_button.click()
    asked.assert_called_once()
    assert "510" in asked.call_args[0][2]
    assert calls == []
    with mock.patch("ui.network_search_dialog.QMessageBox.question",
                    return_value=QMessageBox.StandardButton.Yes):
        dlg.start_button.click()
    assert _wait(app, lambda: not dlg.is_running())
    assert len(calls) == 1
    dlg.close()


def test_sad_paranoid_mode_refuses_in_the_dialog(app, settings):
    from core import security_mode as SM
    from core.remote_sweep import sweep as real_sweep

    old = SM.current_policy().name
    SM.set_policy("paranoid")
    try:
        dlg = _dialog(app, settings, real_sweep)
        dlg.start_button.click()
        assert _wait(app, lambda: not dlg.is_running())
        assert "paranoid" in dlg.error_label.text()
        assert dlg.results_table.rowCount() == 0
        dlg.close()
    finally:
        SM.set_policy(old)


def test_edge_cancel_stops_the_run(app, settings):
    block = threading.Event()
    sweep, calls = _fake_sweep(block=block)
    dlg = _dialog(app, settings, sweep)
    dlg.targets_edit.setPlainText("fs1 fs2 fs3 fs4")
    dlg.start_button.click()
    assert _wait(app, dlg.is_running)
    assert not dlg.start_button.isEnabled() and dlg.cancel_button.isEnabled()
    dlg.cancel_button.click()
    block.set()
    assert _wait(app, lambda: not dlg.is_running())
    assert dlg.results_table.rowCount() <= 2
    assert "Cancelled" in dlg.summary_label.text()
    assert dlg.start_button.isEnabled()
    dlg.close()


def test_edge_closing_while_running_cancels_and_clears_the_password(app, settings):
    block = threading.Event()
    sweep, _ = _fake_sweep(block=block)
    dlg = _dialog(app, settings, sweep)
    dlg.start_button.click()
    assert _wait(app, dlg.is_running)
    threading.Timer(0.2, block.set).start()
    dlg.close()
    assert _wait(app, lambda: not dlg.is_running())
    assert dlg.password_edit.text() == ""


def test_edge_escape_while_running_cancels_like_close(app, settings):
    """Esc hides a QDialog through reject(), which never sends a close event:
    it must cancel the run and clear the password just like Close does."""
    from PyQt6.QtCore import Qt
    from PyQt6.QtTest import QTest

    block = threading.Event()
    sweep, _ = _fake_sweep(block=block)
    dlg = _dialog(app, settings, sweep)
    dlg.targets_edit.setPlainText("fs1 fs2 fs3 fs4")
    dlg.show()
    dlg.start_button.click()
    assert _wait(app, dlg.is_running)
    cancel = dlg._cancel
    threading.Timer(0.2, block.set).start()
    QTest.keyClick(dlg.results_table, Qt.Key.Key_Escape)
    assert not dlg.isVisible()
    assert cancel.is_set()
    assert _wait(app, lambda: not dlg.is_running())
    assert dlg.results_table.rowCount() <= 2
    assert dlg.password_edit.text() == ""


def test_edge_export_csv_and_context_actions(app, settings, tmp_path):
    opened, analysed = [], []
    sweep, _ = _fake_sweep(hits_per_host=1)
    dlg = _dialog(app, settings, sweep, open_hit=lambda hit, cred: opened.append((hit, cred)),
                  analyse_hit=lambda hit, cred: analysed.append((hit, cred)))
    dlg.start_button.click()
    assert _wait(app, lambda: not dlg.is_running())
    out = tmp_path / "hits.csv"
    dlg.export_csv(str(out))
    rows = list(csv.reader(out.open(encoding="utf-8")))
    assert rows[0][:3] == ["UNC", "Size", "Modified"] and len(rows) == 3
    dlg.results_table.selectRow(0)
    dlg.open_selected()
    dlg.analyse_selected()
    assert opened[0][0].host in {"fs1", "fs2"} and analysed[0][1].username == "alice"
    assert opened[0][1].password == "pw"
    QtWidgets.QApplication.clipboard().clear()
    dlg.copy_selected()
    assert QtWidgets.QApplication.clipboard().text().startswith("\\\\")
    dlg.close()


@lab
def test_live_dialog_against_the_lab_samba(app, settings):
    from core.remote_sweep import sweep as real_sweep

    dlg = _dialog(app, settings, real_sweep)
    dlg.targets_edit.setPlainText(LAB_SMB)
    dlg.user_edit.setText(LAB_USER)
    dlg.password_edit.setText(LAB_PASS)
    dlg.name_edit.setText("*.txt")
    dlg.start_button.click()
    assert _wait(app, lambda: not dlg.is_running(), timeout=30)
    uncs = {dlg.results_table.item(r, 0).text() for r in range(dlg.results_table.rowCount())}
    assert rf"\\{LAB_SMB}\testshare\readme.txt" in uncs
    dlg.close()


@lab
def test_live_e2e_open_a_hit_in_a_new_pane(app, settings, tmp_path):
    """From a result row to a pane listing the hit's folder on the lab share."""
    from core.remote_sweep import SweepHit
    from ui import main_window as MW
    from ui.network_search_dialog import Login

    with mock.patch.object(MW.MainWindow, "_SESSION_FILE", tmp_path / "s.json"), \
            mock.patch.object(MW.MainWindow, "_RECENTS_FILE", tmp_path / "r.json"), \
            mock.patch("pathlib.Path.home", return_value=tmp_path):
        win = MW.MainWindow()
    try:
        before = len(win._panes)
        hit = SweepHit(LAB_SMB, "testshare", "/subdir/nested.txt", 12, 0.0)
        win._open_sweep_hit(hit, Login(LAB_USER, LAB_PASS, "", 445))
        assert _wait(app, lambda: len(win._panes) == before + 1, timeout=20)
        pane = win._panes[-1]

        def listed():
            names = {pane._model.get_item(r).name for r in range(pane._model.rowCount())}
            return "nested.txt" in names

        assert _wait(app, listed, timeout=20)
        assert pane.current_path.rstrip("/") == "/subdir"
    finally:
        win.close()
        win.deleteLater()


@lab
def test_live_sad_open_with_a_wrong_password_warns_without_the_password(app, settings, tmp_path):
    from core.remote_sweep import SweepHit
    from ui import main_window as MW
    from ui.network_search_dialog import Login

    with mock.patch.object(MW.MainWindow, "_SESSION_FILE", tmp_path / "s.json"), \
            mock.patch.object(MW.MainWindow, "_RECENTS_FILE", tmp_path / "r.json"), \
            mock.patch("pathlib.Path.home", return_value=tmp_path):
        win = MW.MainWindow()
    warned = []
    try:
        before = len(win._panes)
        with mock.patch("ui.main_window.QMessageBox.warning",
                        side_effect=lambda *a, **k: warned.append(a[2])):
            win._open_sweep_hit(SweepHit(LAB_SMB, "testshare", "/readme.txt", 1, 0.0),
                                Login(LAB_USER, "Wrong-Pass-77", "", 445))
            assert _wait(app, lambda: bool(warned), timeout=20)
        assert len(win._panes) == before
        assert "Wrong-Pass-77" not in warned[0]
    finally:
        win.close()
        win.deleteLater()


@lab
def test_live_e2e_analyse_a_hit_with_sift(app, settings, tmp_path):
    """A result on the lab share analysed by sift in the Analysis dock."""
    pytest.importorskip("sift")
    from core.remote_sweep import SweepHit
    from ui import main_window as MW
    from ui.network_search_dialog import Login

    with mock.patch.object(MW.MainWindow, "_SESSION_FILE", tmp_path / "s.json"), \
            mock.patch.object(MW.MainWindow, "_RECENTS_FILE", tmp_path / "r.json"), \
            mock.patch("pathlib.Path.home", return_value=tmp_path):
        win = MW.MainWindow()
    try:
        dock = win._analysis_dock
        win._analyse_sweep_hit(SweepHit(LAB_SMB, "testshare", "/readme.txt", 15, 0.0),
                               Login(LAB_USER, LAB_PASS, "", 445))
        assert _wait(app, lambda: dock._auto_result is not None, timeout=120)
        assert dock._auto_result.ok, dock._auto_result.error
        assert "readme" in dock.body.toPlainText().lower() or dock.body.toPlainText().strip()
    finally:
        win.close()
        win.deleteLater()
