"""Help > Features…: what is installed, what is missing, how to get it
(punch-list item 12).

Operator: *„gut wäre auch, dass wenn ein feature nicht installiert ist, direkt
angeboten wird es zu installieren, eine übersicht mit installierten features
und noch zu installieren wäre auch nice an einer stelle z.b. in eienr
features liste die irgendwo sinnvoll im menu untergebracht wird"*. Decided:
pip features -> "Install" runs pip in axross' own environment after a
confirmation, with a log; the slim binary -> a link to axross-full of the
same release; external tools -> the distro's package command to copy.

Also fixed here: the connection dialog showed a pip extra that does not
exist for backends that need a system command ("pip install axross[svn]").

pip itself never runs on the test host (house rule: package managers only
in disposable containers): the runner is faked here; the live pip run is a
separate container check.
"""

from __future__ import annotations

import os
import sys
import tempfile
import tomllib
from pathlib import Path
from unittest import mock

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtWidgets import QApplication, QMessageBox  # noqa: E402

from core import features as F  # noqa: E402

APP = QApplication.instance() or QApplication([])


# -- the table of extras matches pyproject --------------------------------------------


def test_happy_the_extras_table_is_pyprojects():
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    extras = data["project"]["optional-dependencies"]
    assert F.EXTRAS == {name: tuple(reqs) for name, reqs in extras.items() if name != "all"}


# -- collecting ---------------------------------------------------------------------


def test_happy_every_backend_extra_and_tool_is_listed():
    found = {f.key: f for f in F.collect()}
    assert found["backend:sftp"].available
    assert found["backend:smb"].pip_extra == "smb"
    assert found["extra:archive"].requirements == F.EXTRAS["archive"]
    assert "rg" in found["tool:rg"].commands
    assert {f.group for f in found.values()} >= {"Connections", "Files and analysis", "External tools"}


def test_happy_availability_follows_imports_and_commands(monkeypatch):
    monkeypatch.setattr(F.shutil, "which", lambda cmd: "/usr/bin/" + cmd if cmd == "rsync" else None)
    found = {f.key: f for f in F.collect()}
    assert found["tool:rsync"].available and not found["tool:rg"].available


def test_sad_a_backend_without_an_extra_never_gets_a_made_up_one():
    for feature in F.collect():
        if feature.key in ("backend:svn", "backend:rsync", "backend:nfs", "backend:mtp"):
            assert feature.pip_extra is None
            assert "axross[" not in F.how_to_get(feature, family="arch")


def test_edge_how_to_get_names_the_right_thing():
    found = {f.key: f for f in F.collect()}
    assert F.how_to_get(found["extra:sift"], family="arch") == "pip install axross[sift]"
    assert F.how_to_get(found["tool:rg"], family="arch") == "sudo pacman -S --needed ripgrep"
    assert F.how_to_get(found["tool:fd"], family="debian") == "sudo apt install fd-find"
    assert F.how_to_get(found["tool:rg"], family="macos") == "brew install ripgrep"
    assert F.how_to_get(found["backend:svn"], family="fedora") == "sudo dnf install subversion"
    # A tool the family has no package for: the plain description.
    assert "rsh" in F.how_to_get(found["backend:rsh"], family="macos")


@pytest.mark.parametrize("text,family", [
    ('ID=arch\n', "arch"), ('ID=manjaro\nID_LIKE=arch\n', "arch"),
    ('ID=ubuntu\nID_LIKE=debian\n', "debian"), ('ID=debian\n', "debian"),
    ('ID=fedora\n', "fedora"), ('ID="rhel"\nID_LIKE="fedora"\n', "fedora"),
    ('ID="opensuse-tumbleweed"\nID_LIKE="opensuse suse"\n', "suse"), ('ID=alpine\n', "alpine"),
    ('ID=gentoo\n', ""), ('', ""),
])
def test_edge_distro_family(text, family):
    assert F.linux_family(text) == family


# -- installing ----------------------------------------------------------------------


def test_happy_pip_command_installs_the_requirements_into_this_python():
    found = {f.key: f for f in F.collect()}
    cmd = F.pip_command([found["extra:archive"], found["backend:smb"]])
    assert cmd[:4] == [sys.executable, "-m", "pip", "install"]
    assert set(cmd[4:]) == set(F.EXTRAS["archive"]) | set(F.EXTRAS["smb"])


def test_sad_a_frozen_build_cannot_pip_install(monkeypatch):
    monkeypatch.setattr(F, "is_frozen", lambda: True)
    ok, reason = F.can_pip_install()
    assert not ok and "axross-full" in reason


def test_sad_no_pip_module_cannot_install(monkeypatch):
    monkeypatch.setattr(F.importlib.util, "find_spec", lambda name: None if name == "pip" else mock.DEFAULT)
    ok, reason = F.can_pip_install()
    assert not ok and "pip" in reason


def test_edge_the_download_link_is_this_release():
    assert F.download_url("0.12.88") == "https://github.com/c0decave/axross/releases/tag/v0.12.88"


def test_happy_refresh_makes_a_new_install_visible():
    from core import backend_registry as BR

    BR.ensure_initialized()
    info = BR.get("smb")
    probe = info._availability
    if not isinstance(probe, BR._ImportProbe):
        pytest.skip("smb availability is not an import probe here")
    probe._result = False  # as if it was missing at the start
    assert not info.available
    F.refresh_availability()
    assert probe._result is None  # asked again on the next read


# -- the dialog ------------------------------------------------------------------------


class _FakeRunner:
    """Stands in for the pip process: records the command, finishes at once."""

    def __init__(self):
        self.commands = []

    def __call__(self, cmd, on_output, on_done):
        self.commands.append(cmd)
        on_output("Successfully installed fake-1.0\n")
        on_done(0)


@pytest.fixture
def missing(monkeypatch):
    """archive and ripgrep missing, whatever this host has."""
    from dataclasses import replace

    real = F.collect
    gone = {"extra:archive", "tool:rg"}
    monkeypatch.setattr(F, "collect", lambda: [
        replace(f, available=False) if f.key in gone else f for f in real()])


def _wait_loaded(dlg, seconds: float = 30.0) -> None:
    """The window asks what is installed off the GUI thread: wait for it."""
    import time

    end = time.monotonic() + seconds
    while not dlg.loaded and time.monotonic() < end:
        APP.processEvents()
        time.sleep(0.005)
    assert dlg.loaded


def _dialog(**kw):
    from ui.features_dialog import FeaturesDialog

    dlg = FeaturesDialog(**kw)
    dlg.show()
    APP.processEvents()
    _wait_loaded(dlg)
    return dlg


def _row_of(dlg, key):
    for row in range(dlg.table.rowCount()):
        if dlg.feature_at(row).key == key:
            return row
    raise AssertionError(key)


def test_happy_the_table_shows_status_and_the_missing_filter():
    dlg = _dialog()
    try:
        keys = {dlg.feature_at(r).key for r in range(dlg.table.rowCount())}
        assert "backend:sftp" in keys
        dlg.missing_only.setChecked(True)
        assert all(not dlg.feature_at(r).available for r in range(dlg.table.rowCount()))
    finally:
        dlg.close()


def test_happy_install_asks_runs_pip_and_refreshes(monkeypatch, missing):
    runner = _FakeRunner()
    monkeypatch.setattr(F, "can_pip_install", lambda: (True, ""))
    dlg = _dialog(runner=runner)
    try:
        dlg.missing_only.setChecked(False)
        dlg.table.selectRow(_row_of(dlg, "extra:archive"))
        with mock.patch("ui.features_dialog.QMessageBox.question",
                        return_value=QMessageBox.StandardButton.Yes) as asked, \
                mock.patch("ui.features_dialog.F.refresh_availability") as refreshed:
            dlg.install_selected()
        assert "pip install" in asked.call_args[0][2]
        assert runner.commands and runner.commands[0][4:] == list(F.EXTRAS["archive"])
        assert "Successfully installed" in dlg.log.toPlainText()
        refreshed.assert_called_once()
    finally:
        dlg.close()


def test_sad_no_at_the_question_installs_nothing(monkeypatch, missing):
    runner = _FakeRunner()
    monkeypatch.setattr(F, "can_pip_install", lambda: (True, ""))
    dlg = _dialog(runner=runner)
    try:
        dlg.table.selectRow(_row_of(dlg, "extra:archive"))
        with mock.patch("ui.features_dialog.QMessageBox.question",
                        return_value=QMessageBox.StandardButton.No):
            dlg.install_selected()
        assert runner.commands == []
    finally:
        dlg.close()


def test_sad_a_failed_pip_run_is_shown(monkeypatch, missing):
    def runner(cmd, on_output, on_done):
        on_output("error: externally-managed-environment\n")
        on_done(1)

    monkeypatch.setattr(F, "can_pip_install", lambda: (True, ""))
    dlg = _dialog(runner=runner)
    try:
        dlg.table.selectRow(_row_of(dlg, "extra:archive"))
        with mock.patch("ui.features_dialog.QMessageBox.question",
                        return_value=QMessageBox.StandardButton.Yes):
            dlg.install_selected()
        assert "externally-managed" in dlg.log.toPlainText()
        assert "failed" in dlg.status.text().lower()
    finally:
        dlg.close()


def test_edge_frozen_build_offers_the_download_instead(monkeypatch):
    monkeypatch.setattr(F, "can_pip_install", lambda: (False, "frozen"))
    monkeypatch.setattr(F, "is_frozen", lambda: True)
    dlg = _dialog()
    try:
        assert not dlg.install_button.isEnabled()
        assert dlg.download_button.isVisible()
        with mock.patch("PyQt6.QtGui.QDesktopServices.openUrl") as opened:
            dlg.download_button.click()
        assert "/releases/tag/v" in opened.call_args[0][0].toString()
    finally:
        dlg.close()


def test_edge_copy_command_for_a_tool(missing):
    dlg = _dialog()
    try:
        dlg.missing_only.setChecked(False)
        dlg.table.selectRow(_row_of(dlg, "tool:rg"))
        dlg.copy_command()
        assert QApplication.clipboard().text() == F.how_to_get(
            next(f for f in F.collect() if f.key == "tool:rg"))
    finally:
        dlg.close()


def test_happy_select_shows_one_feature():
    dlg = _dialog()
    try:
        dlg.select("extra:sift")
        rows = {i.row() for i in dlg.table.selectedIndexes()}
        assert [dlg.feature_at(r).key for r in rows] == ["extra:sift"]
    finally:
        dlg.close()


# -- offered where it is missing -------------------------------------------------------


@pytest.fixture()
def manager():
    from core.profiles import ProfileManager

    with tempfile.TemporaryDirectory() as tmp:
        with mock.patch("core.profiles.CONFIG_DIR", Path(tmp)), \
                mock.patch("core.profiles.PROFILES_FILE", Path(tmp) / "profiles.json"):
            yield ProfileManager()


def test_sad_connection_dialog_labels_name_no_made_up_extra(manager):
    """The bug: "Subversion (read-only)  (pip install axross[svn])"."""
    from core.backend_registry import get
    from ui.connection_dialog import ConnectionDialog

    dlg = ConnectionDialog(manager)
    try:
        import time

        end = time.monotonic() + 30  # the dialog asks what is installed off the GUI thread
        while not dlg.labels_ready and time.monotonic() < end:
            APP.processEvents()
            time.sleep(0.005)
        assert dlg.labels_ready
        for index, proto in enumerate(dlg._protocol_ids):
            info = get(proto)
            label = dlg._protocol_combo.itemText(index)
            if info.required_extra is None:
                assert "axross[" not in label, label
            if not info.available and info.required_extra:
                assert f"axross[{info.required_extra}]" in label
    finally:
        dlg.close()


def test_happy_a_missing_backend_offers_the_features_window(manager):
    from core.backend_registry import get
    from ui.connection_dialog import ConnectionDialog

    missing = next((p for p in ("svn", "rsh", "iscsi", "mtp") if not get(p).available), None)
    if missing is None:
        pytest.skip("every system-command backend is installed here")
    dlg = ConnectionDialog(manager)
    try:
        dlg._protocol_combo.setCurrentIndex(dlg._protocol_ids.index(missing))
        shown = []
        with mock.patch("ui.connection_dialog.offer_features",
                        side_effect=lambda parent, key, text: shown.append((key, text))):
            assert dlg._validate_backend_available() is False
        assert shown and shown[0][0] == f"backend:{missing}"
        assert "axross[" not in shown[0][1]
    finally:
        dlg.close()


def test_e2e_help_menu_opens_features(tmp_path):
    from ui import main_window as MW

    with mock.patch.object(MW.MainWindow, "_SESSION_FILE", tmp_path / "s.json"), \
            mock.patch.object(MW.MainWindow, "_RECENTS_FILE", tmp_path / "r.json"), \
            mock.patch("pathlib.Path.home", return_value=tmp_path):
        win = MW.MainWindow()
    try:
        action = next(a for m in win.menuBar().actions() if m.menu()
                      for a in m.menu().actions() if a.text().replace("&", "") == "Features…")
        action.trigger()
        APP.processEvents()
        dlg = win._features_dialog
        _wait_loaded(dlg)
        assert dlg.isVisible() and dlg.table.rowCount() > 10
        dlg.close()
    finally:
        win.close()
        win.deleteLater()


def test_happy_the_analysis_dock_offers_sift_in_features():
    from PyQt6.QtCore import QUrl

    from core.file_analysis import Target
    from ui.analysis_dock import AnalysisDock

    dock = AnalysisDock(analyzer_factory=lambda: None, available=lambda: False)
    try:
        asked = []
        dock.features_requested.connect(asked.append)
        dock.analyse(Target(backend=None, path="/x", name="x", size=1, mtime=0.0))
        html = dock.body.toHtml()
        assert "not installed" in dock.body.toPlainText()
        assert 'href="axross:features/extra:sift"' in html
        dock.body.anchorClicked.emit(QUrl("axross:features/extra:sift"))
        assert asked == ["extra:sift"]
    finally:
        dock.shutdown()
        dock.deleteLater()


def test_e2e_window_opens_features_at_sift_from_the_dock(tmp_path):
    from ui import main_window as MW

    with mock.patch.object(MW.MainWindow, "_SESSION_FILE", tmp_path / "s.json"), \
            mock.patch.object(MW.MainWindow, "_RECENTS_FILE", tmp_path / "r.json"), \
            mock.patch("pathlib.Path.home", return_value=tmp_path):
        win = MW.MainWindow()
    try:
        win._analysis_dock.features_requested.emit("extra:sift")
        APP.processEvents()
        dlg = win._features_dialog
        _wait_loaded(dlg)
        rows = {i.row() for i in dlg.table.selectedIndexes()}
        assert [dlg.feature_at(r).key for r in rows] == ["extra:sift"]
        dlg.close()
    finally:
        win.close()
        win.deleteLater()


# -- round-2 verification ---------------------------------------------------------------


def test_edge_closing_the_window_lets_a_running_install_finish(tmp_path):
    """closeEvent says pip keeps running to its end; the window is deleted
    on close (WA_DeleteOnClose), and with it went the only reference to the
    parentless QProcess - which killed pip half way."""
    import gc
    import time

    from PyQt6.QtCore import Qt
    from PyQt6.QtWidgets import QApplication

    from ui import features_dialog as FD

    app = QApplication.instance()
    marker = tmp_path / "finished"
    dlg = FD.FeaturesDialog()
    dlg.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
    dlg.show()
    FD._qprocess_runner(dlg)(
        [sys.executable, "-c", f"import time; time.sleep(1.5); open({str(marker)!r}, 'w')"],
        lambda _text: None, lambda _code: None)
    end = time.time() + 5
    while time.time() < end and dlg._process.state() != dlg._process.ProcessState.Running:
        app.processEvents()
    dlg.close()
    del dlg
    for _ in range(5):
        app.processEvents()
        gc.collect()
    end = time.time() + 10
    while not marker.exists() and time.time() < end:
        app.processEvents()
        time.sleep(0.05)
    assert marker.exists(), "the install was killed when the window closed"
    from PyQt6.QtCore import QProcess

    def running():
        return [p for p in app.findChildren(QProcess)
                if p.state() != QProcess.ProcessState.NotRunning]

    while running() and time.time() < end:
        app.processEvents()
        time.sleep(0.05)
    assert not running()
