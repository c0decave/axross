"""Extensions > Open Extensions Folder shows the folder; the desktop
opener works from the frozen binary; the Extensions list keeps the names.

Reported: "klicken auf open extension folder passiert nichts". The action
handed the folder to ``QDesktopServices.openUrl``, which starts
``xdg-open`` with the process environment - in the PyInstaller binary
``LD_LIBRARY_PATH`` points into the bundle and ``/bin/sh`` (``xdg-open`` is
a shell script) dies on ``undefined symbol: rl_trim_arg_from_keyseq``
(measured with dist/axross-full 0.13.22), while Qt reports success. The
menu action now opens the folder in axross itself (it is a file manager),
the Settings page's button reaches the desktop's file manager through
:mod:`core.desktop_open`, and a failure is reported.

Reported as well: "wenn man extension folder öffnet sieht man manchmal den
namen nicht der extension dafuer beschreibung und ob geladen" - the name
column was squeezed by a long description and status (ui.column_fit keep).
"""

from __future__ import annotations

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

from PyQt6.QtCore import QEvent, QTimer, QUrl  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import desktop_open as DO  # noqa: E402
from core import extensions as EX  # noqa: E402

APP = QApplication.instance() or QApplication([])
ROOT = Path(__file__).resolve().parent.parent


def pump(seconds: float = 0.05) -> None:
    end = time.time() + seconds
    while time.time() < end:
        APP.processEvents()
        time.sleep(0.01)


def wait_until(cond, timeout: float = 5.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        APP.processEvents()
        if cond():
            return True
        time.sleep(0.01)
    return cond()


@pytest.fixture(autouse=True)
def own_home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir()


@pytest.fixture
def window():
    from ui.main_window import MainWindow

    win = MainWindow()
    win._reconnect_timer.stop()
    win.resize(1100, 750)
    win.show()
    pump()
    yield win
    win.close()
    win.deleteLater()
    APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    pump()


def _menu_action(win, text: str):
    for action in win.extensions_menu.actions():
        if action.text().replace("&", "") == text:
            return action
    raise AssertionError(f"no {text!r} in the Extensions menu")


# -- the menu action: the folder in a pane -------------------------------------


def test_happy_the_menu_action_opens_the_folder_in_the_active_pane(window) -> None:
    """e2e: the real menu action, the real local pane."""
    folder = EX.extensions_dir()
    assert not folder.exists()
    pane = window._active_pane
    _menu_action(window, "Open Extensions Folder").trigger()
    assert folder.is_dir()
    assert wait_until(lambda: pane.current_path == str(folder)), pane.current_path
    assert str(folder) in window.statusBar().currentMessage()
    assert stat.S_IMODE(folder.stat().st_mode) == 0o700


def test_edge_a_remote_active_pane_gets_a_local_pane_next_to_it(window) -> None:
    from core.local_fs import LocalFS
    from core.ram_fs import RamFsSession

    ram_pane = window._add_pane_to_splitter(window._root_splitter, RamFsSession())
    window._set_active_pane(ram_pane)
    pump()
    before = list(window._panes)
    _menu_action(window, "Open Extensions Folder").trigger()
    folder = str(EX.extensions_dir())
    assert wait_until(
        lambda: any(
            p not in before and isinstance(p.backend, LocalFS) and p.current_path == folder
            for p in window._panes
        )
    )
    assert ram_pane.current_path != folder


def test_sad_a_folder_that_cannot_be_made_is_reported_in_the_status_bar(window) -> None:
    blocker = EX.extensions_dir()
    blocker.parent.mkdir(parents=True, exist_ok=True)
    blocker.write_text("a file where the folder should be")
    pane = window._active_pane
    before = pane.current_path
    _menu_action(window, "Open Extensions Folder").trigger()
    pump()
    message = window.statusBar().currentMessage()
    assert "Could not create" in message and str(EX.extensions_dir()) in message
    assert pane.current_path == before


# -- the Settings page's button: the desktop's file manager ------------------------


def _settings_page(win, width: int | None = None, check=None):
    """Open Edit > Settings > Extensions as the menu does; run *check*
    against the page while the modal dialog is open."""
    from ui.extensions_dialog import ExtensionsPage
    from ui.settings_dialog import SettingsDialog

    seen = {}

    def inspect() -> None:
        dialog = next(
            w for w in APP.topLevelWidgets() if isinstance(w, SettingsDialog) and w.isVisible()
        )
        page = dialog.findChild(ExtensionsPage)
        if width is not None:
            dialog.resize(width, dialog.height())
        pump(0.1)
        try:
            seen["result"] = check(dialog, page)
        except BaseException as exc:  # handed to the test after exec()
            seen["error"] = exc
        dialog.reject()

    QTimer.singleShot(300, inspect)
    win.open_settings("extensions")
    if "error" in seen:
        raise seen["error"]
    return seen.get("result")


def _button(page, text: str):
    from PyQt6.QtWidgets import QPushButton

    return next(b for b in page.findChildren(QPushButton) if b.text() == text)


def test_happy_the_settings_button_hands_the_folder_to_the_desktop(window) -> None:
    folder = EX.extensions_dir()

    def check(_dialog, page):
        with mock.patch.object(DO, "open_url", return_value=True) as opened:
            _button(page, "Open Extensions Folder").click()
        return opened.call_args[0][0]

    url = _settings_page(window, check=check)
    assert isinstance(url, QUrl) and url.toLocalFile() == str(folder)
    assert folder.is_dir()


def test_sad_the_settings_button_says_so_when_no_opener_starts(window) -> None:
    def check(_dialog, page):
        with mock.patch.object(DO, "open_url", return_value=False), mock.patch(
            "ui.extensions_dialog.QMessageBox.warning"
        ) as warned:
            _button(page, "Open Extensions Folder").click()
        return warned.call_args[0][2]

    text = _settings_page(window, check=check)
    assert str(EX.extensions_dir()) in text


# -- core.desktop_open: the frozen binary's opener ----------------------------------


def _fake_opener(tmp_path) -> tuple[Path, Path]:
    """A fake xdg-open that writes its argv and LD_LIBRARY_PATH to a log."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    log = tmp_path / "opener.log"
    script = bindir / "xdg-open"
    script.write_text(
        "#!/bin/sh\n"
        f'printf "%s\\n%s\\n" "$1" "${{LD_LIBRARY_PATH-<unset>}}" > "{log}"\n'
    )
    script.chmod(0o755)
    return bindir, log


def test_happy_frozen_starts_the_opener_without_the_bundle_loader_path(
    tmp_path, monkeypatch
) -> None:
    bindir, log = _fake_opener(tmp_path)
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setenv("PATH", f"{bindir}:{os.environ.get('PATH', '/usr/bin:/bin')}")
    monkeypatch.setenv("LD_LIBRARY_PATH", "/tmp/_MEI-bundle")
    monkeypatch.delenv("LD_LIBRARY_PATH_ORIG", raising=False)
    target = tmp_path / "ext folder ü"
    target.mkdir()
    with mock.patch("PyQt6.QtGui.QDesktopServices.openUrl") as qt_open:
        assert DO.open_url(QUrl.fromLocalFile(str(target))) is True
    qt_open.assert_not_called()
    assert wait_until(lambda: log.exists() and log.read_text().count("\n") >= 2)
    arg, ld_path = log.read_text().splitlines()[:2]
    # A local path or its file:// URL - spaces and umlauts survive either way.
    assert arg == str(target) or QUrl(arg).toLocalFile() == str(target)
    assert ld_path == "<unset>"


def test_sad_frozen_without_xdg_open_leaves_it_to_qt(tmp_path, monkeypatch) -> None:
    # Qt knows the desktops' own launchers (kde-open, gio) and, since
    # main() restores the environment at start, launches them cleanly.
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    with mock.patch("PyQt6.QtGui.QDesktopServices.openUrl", return_value=False) as qt_open:
        assert DO.open_url(QUrl.fromLocalFile(str(tmp_path))) is False
    qt_open.assert_called_once()


def test_edge_the_source_tree_and_other_systems_keep_qt_opening(monkeypatch) -> None:
    monkeypatch.delattr(sys, "frozen", raising=False)
    with mock.patch("PyQt6.QtGui.QDesktopServices.openUrl", return_value=True) as qt_open:
        assert DO.open_url(QUrl("https://example.invalid/")) is True
    qt_open.assert_called_once()
    for platform, expected in (("linux", True), ("freebsd14", True), ("darwin", False)):
        monkeypatch.setattr(sys, "platform", platform)
        assert DO.needs_clean_opener(frozen=True) is expected, platform
    monkeypatch.setattr(sys, "platform", "linux")
    assert not DO.needs_clean_opener(frozen=False)
    monkeypatch.setattr(os, "name", "nt")
    assert not DO.needs_clean_opener(frozen=True)


def test_edge_no_module_starts_the_desktop_opener_around_desktop_open() -> None:
    """The download button of the frozen build, the guide's links and
    "open externally" had the same dead opener; all go through it now."""
    hits = []
    for top in ("ui", "core"):
        for path in sorted((ROOT / top).rglob("*.py")):
            if path.name == "desktop_open.py":
                continue
            for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if "QDesktopServices.openUrl(" in line and not line.lstrip().startswith("#"):
                    hits.append(f"{path.relative_to(ROOT)}:{n}")
    assert hits == []


# -- the Extensions list keeps the names visible --------------------------------


def _write_extension(name: str, title: str, description: str) -> None:
    folder = EX.extensions_dir()
    folder.mkdir(parents=True, exist_ok=True)
    (folder / f"{name}.py").write_text(
        f'EXTENSION = {{"name": "{title}", "version": "1.0", "description": "{description}"}}\n'
        "def activate(api):\n    pass\n"
    )


@pytest.mark.parametrize("width", [980, 640, 560])
def test_happy_the_extensions_page_shows_every_name(window, width) -> None:
    """e2e: the real Settings dialog, narrowed as a user does."""
    _write_extension("chatty", "Chatty Extension With A Long Name", "words " * 60)
    (EX.extensions_dir() / "broken.py").write_text("print('no manifest here')\n")

    def check(_dialog, page):
        table = page.table
        name_col = 1
        need = min(table.sizeHintForColumn(name_col), table.viewport().width() // 3)
        return table.horizontalHeader().sectionSize(name_col), need

    got, need = _settings_page(window, width=width, check=check)
    assert got >= need, (width, got, need)
