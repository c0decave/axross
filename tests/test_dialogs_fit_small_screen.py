"""Every window the menus open fits a 1280x800 screen - and a 1024x600 one.

Reported: Connect to Server asked for 947 px (minimum height 947: OK and
Cancel off a 768 or 800 px screen), the About box was 967 px high (1009
px in German), System Information opened at exactly 1180x800 - its title
bar and bottom edge off the screen. ui.screen_fit caps them: the Connect
form and the About text scroll, default window sizes stop at the screen.

UX review round 4 (1024x600, a netbook or a small VM window): Settings
opened at 980x660, the Handbook at 1060x700 and Features at 980x620, each
taller than the screen, and Connect to Server widened itself once shown
without moving back: its right and bottom edge stood off the screen.
"""

from __future__ import annotations

import os
import re
import sys
import time
from pathlib import Path
from unittest import mock

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6 import sip  # noqa: E402
from PyQt6.QtCore import QRect, QSize  # noqa: E402
from PyQt6.QtWidgets import (  # noqa: E402
    QApplication,
    QDialog,
    QFileDialog,
    QInputDialog,
    QMenu,
    QMessageBox,
)

APP = QApplication.instance() or QApplication([])

SCREEN = QRect(0, 0, 1280, 800)
#: What a window may take of it with its title bar and frame drawn.
LIMIT = QSize(1240, 760)
#: The small screen of review round 4, and its limit.
SMALL_SCREEN = QRect(0, 0, 1024, 600)
SMALL_LIMIT = QSize(984, 560)

#: Entries that quit, change the layout or the panes, or start work -
#: none of them opens a window of its own.
SKIP = re.compile(
    r"Quit|Exit|Undo|Redo|Restore|Keyring|Reload|Open Extensions Folder|Update|Delete|"
    r"Workspace|Pane|Layout|Theme|Zoom|Hidden|Preview|Next|Previous|Agent|Copy|Move|"
    r"Shell$|Bookmarks$|Add|Panels|Pause|sift|Text Editor|Analy|Terminal|Full Screen|"
    r"Compact|Refresh|Select|Invert|Paste|Cut|Rename|New|Open|Mount|Encrypt|Decrypt|"
    r"Checksum|Compress|Extract|Tag|Swap|Sync|Compare|Media Player$|Treemap|Drives|"
    r"Mixer|Bluetooth",
    re.I,
)


def pump(seconds: float = 0.0, rounds: int = 5) -> None:
    end = time.monotonic() + seconds
    while True:
        for _ in range(rounds):
            APP.processEvents()
        if time.monotonic() >= end:
            return
        time.sleep(0.01)


@pytest.fixture
def screen():
    """The screen the windows open on: 1280x800 unless a test says else."""
    return SCREEN


@pytest.fixture
def window(tmp_path, monkeypatch, screen):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    from ui import main_window as MW
    from ui import screen_fit

    monkeypatch.setattr(MW.MainWindow, "_SESSION_FILE", home / "session.json")
    monkeypatch.setattr(screen_fit, "available_geometry", lambda widget=None: QRect(screen))

    def fake_exec(self, *args, **kwargs):
        self.show()
        pump()
        return 0

    def message(kind):
        def box(*args, **kwargs):
            if kind == "question":
                return QMessageBox.StandardButton.No
            return QMessageBox.StandardButton.Ok

        return staticmethod(box)

    patches = [
        mock.patch.object(QDialog, "exec", fake_exec),
        mock.patch.object(QMessageBox, "exec", fake_exec),
        mock.patch.object(QMenu, "exec", lambda *a, **k: None),
        mock.patch.object(QFileDialog, "getOpenFileName", staticmethod(lambda *a, **k: ("", ""))),
        mock.patch.object(QFileDialog, "getOpenFileNames", staticmethod(lambda *a, **k: ([], ""))),
        mock.patch.object(QFileDialog, "getSaveFileName", staticmethod(lambda *a, **k: ("", ""))),
        mock.patch.object(QFileDialog, "getExistingDirectory", staticmethod(lambda *a, **k: "")),
        mock.patch.object(QInputDialog, "getText", staticmethod(lambda *a, **k: ("", False))),
        mock.patch.object(QInputDialog, "getItem", staticmethod(lambda *a, **k: ("", False))),
    ]
    patches += [mock.patch.object(QMessageBox, k, message(k))
                for k in ("information", "warning", "critical", "question")]
    for patch in patches:
        patch.start()
    from core import extensions

    extensions.set_enabled("bundled:system_info", True)
    win = MW.MainWindow()
    win._reconnect_timer.stop()
    win.apply_first_start_layout()
    win.resize(screen.width(), screen.height())
    win.show()
    pump(0.3)
    try:
        yield win
    finally:
        for widget in APP.topLevelWidgets():
            if widget is not win and widget.isVisible() and not sip.isdeleted(widget):
                widget.close()
        win.close()
        win.deleteLater()
        pump()
        for patch in reversed(patches):
            patch.stop()


def _entries(menu, path):
    for action in menu.actions():
        if action.isSeparator() or not action.text():
            continue
        here = path + [action.text().replace("&", "")]
        if action.menu() is not None:
            yield from _entries(action.menu(), here)
        else:
            yield here, action


def _fits(size: QSize, limit: QSize = LIMIT) -> bool:
    return size.width() <= limit.width() and size.height() <= limit.height()


@pytest.mark.timeout(240)
def test_happy_every_window_the_menus_open_fits_1280x800(window):
    # Marked on the widget, not kept as id(): a closed and deleted window's
    # id() came back for a later one (About axross), which then counted as
    # seen and the walk "never opened" it - now and then.
    for widget in APP.topLevelWidgets():
        widget.setProperty("axFitSeen", True)
    opened, too_big, quiet = [], [], []

    def collect(path) -> bool:
        found = False
        for widget in APP.topLevelWidgets():
            if (sip.isdeleted(widget) or widget.property("axFitSeen") or widget is window
                    or isinstance(widget, QMenu)
                    or not widget.isVisible() or not widget.windowTitle()):
                continue
            widget.setProperty("axFitSeen", True)
            where = " > ".join(path)
            opened.append(where)
            for what, size in (("size", widget.size()), ("minimum", widget.minimumSize()),
                               ("minimum hint", widget.minimumSizeHint())):
                if not _fits(size):
                    too_big.append(f"{where}: {what} {size.width()}x{size.height()}")
            widget.close()
            pump()
            found = True
        return found

    for top in window.menuBar().actions():
        for path, action in list(_entries(top.menu(), [top.text().replace("&", "")])):
            if SKIP.search(" ".join(path[1:])) or not action.isEnabled():
                continue
            action.trigger()
            pump(0.15)
            if not collect(path):
                quiet.append((path, action))
    # A window that took longer than 0.15 s under load (a busy machine in a
    # full parallel run) gets a second, patient try - only these entries.
    for name in ("Connection Manager", "System Information", "About axross"):
        if any(name in where for where in opened):
            continue
        for path, action in quiet:
            if name in " > ".join(path) and action.isEnabled():
                action.trigger()
                end = time.monotonic() + 3.0
                while time.monotonic() < end and not collect(path):
                    pump(0.05)
    # the walk reached the windows the report named
    for name in ("Connection Manager", "System Information", "About axross"):
        assert any(name in where for where in opened), (name, opened)
    assert too_big == []


def test_sad_connect_to_server_with_a_custom_proxy_scrolls_instead_of_growing(window):
    from core.profiles import ProfileManager
    from ui.connection_dialog import ConnectionDialog

    dialog = ConnectionDialog(ProfileManager(), window)
    dialog.show()
    pump(0.1)
    # the proxy group starts folded: its fields take no room
    assert dialog._proxy_host.isHidden()
    dialog._proxy_group.setChecked(True)
    dialog._proxy_mode.setCurrentIndex(1)
    pump(0.1)
    assert not dialog._proxy_host.isHidden()
    assert _fits(dialog.size()), dialog.size()
    assert _fits(dialog.minimumSizeHint()), dialog.minimumSizeHint()
    dialog.close()


def test_edge_about_scrolls_its_text_within_the_screen(window):
    dialog = window.about_dialog()
    dialog.show()
    pump(0.1)
    assert _fits(dialog.size()), dialog.size()
    assert "axross" in dialog.text_browser.toPlainText()
    dialog.close()


# -- 1024x600 ------------------------------------------------------------------


def _settings(win):
    from ui.settings_dialog import SettingsDialog

    return SettingsDialog(win, window=win)


def _handbook(win):
    from ui.handbook import HandbookDialog

    return HandbookDialog(win)


def _features(win):
    from ui.features_dialog import FeaturesDialog

    return FeaturesDialog(win)


@pytest.mark.parametrize("screen", [SMALL_SCREEN])
@pytest.mark.parametrize("make", [_settings, _handbook, _features],
                         ids=["settings", "handbook", "features"])
def test_happy_settings_handbook_and_features_fit_1024x600(window, make):
    dialog = make(window)
    try:
        dialog.show()
        pump(0.2)
        assert _fits(dialog.size(), SMALL_LIMIT), dialog.size()
        assert _fits(dialog.minimumSizeHint(), SMALL_LIMIT), dialog.minimumSizeHint()
        assert _fits(dialog.minimumSize(), SMALL_LIMIT), dialog.minimumSize()
    finally:
        dialog.close()
        dialog.deleteLater()


@pytest.mark.parametrize("screen", [SMALL_SCREEN])
def test_sad_connect_to_server_stays_on_a_1024x600_screen(window, monkeypatch):
    """It widens to its form once shown; it must not stand off the edge."""
    from core.profiles import ProfileManager
    from ui import screen_fit
    from ui.connection_dialog import ConnectionDialog

    dialog = ConnectionDialog(ProfileManager(), window)
    dialog.move(600, 300)  # where a window manager may put it before it grows
    dialog.show()
    pump(0.2)
    frame = dialog.frameGeometry()
    assert _fits(dialog.size(), SMALL_LIMIT), dialog.size()
    assert SMALL_SCREEN.contains(frame.topLeft()), frame
    assert frame.right() <= SMALL_SCREEN.right() and frame.bottom() <= SMALL_SCREEN.bottom(), frame
    dialog._proxy_group.setChecked(True)
    pump(0.2)
    frame = dialog.frameGeometry()
    assert frame.right() <= SMALL_SCREEN.right() and frame.bottom() <= SMALL_SCREEN.bottom(), frame
    dialog.close()
    assert screen_fit.available_geometry() == SMALL_SCREEN


def test_edge_keep_on_screen_moves_only_a_window_past_an_edge():
    from PyQt6.QtWidgets import QWidget

    from ui import screen_fit

    with mock.patch.object(screen_fit, "available_geometry",
                           lambda widget=None: QRect(SMALL_SCREEN)):
        widget = QWidget()
        widget.resize(400, 300)
        widget.move(100, 100)
        screen_fit.keep_on_screen(widget)
        assert (widget.x(), widget.y()) == (100, 100)
        widget.move(900, 500)
        screen_fit.keep_on_screen(widget)
        frame = widget.frameGeometry()
        assert frame.right() <= SMALL_SCREEN.right() and frame.bottom() <= SMALL_SCREEN.bottom()
        widget.deleteLater()
