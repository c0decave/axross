"""The running version is visible: bottom right in the window, in Help >
About and in the F1 help's title. Before, no window showed it at all."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest  # noqa: E402
from PyQt6.QtWidgets import QApplication, QPushButton  # noqa: E402

from axross._version import __version__  # noqa: E402

APP = QApplication.instance() or QApplication([])
LABEL = f"axross {__version__}"


@pytest.fixture
def window():
    from ui.main_window import MainWindow

    win = MainWindow()
    win.resize(1100, 700)
    win.show()
    APP.processEvents()
    yield win
    win.close()
    win.deleteLater()
    APP.processEvents()


def _version_labels(win) -> list[QPushButton]:
    # A flat button since 0.14.61: with an update notice a click opens the
    # update window (tests/test_self_update_ui.py).
    return [w for w in win.statusBar().findChildren(QPushButton) if w.text() == LABEL]


def test_happy_the_status_bar_shows_the_version_bottom_right(window) -> None:
    labels = _version_labels(window)
    assert len(labels) == 1
    label = labels[0]
    assert label.isVisible()
    bar = window.statusBar()
    assert bar.isVisible()
    # a permanent widget sits at the right edge of the status bar
    right_edge = label.mapTo(bar, label.rect().topRight()).x()
    assert right_edge >= bar.width() - 40, (right_edge, bar.width())


def test_sad_a_temporary_status_message_does_not_hide_the_version(window) -> None:
    window.statusBar().showMessage("Transfer enqueued: copy: 3 file(s)", 5000)
    APP.processEvents()
    assert _version_labels(window)[0].isVisible()


def test_edge_the_version_stays_with_docks_open_and_after_a_theme_switch(window) -> None:
    for dock in (window._log_dock, window._console_dock, window._transfer_dock):
        dock.show()
        dock.raise_()
    window._apply_theme("hacker")
    APP.processEvents()
    assert _version_labels(window)[0].isVisible()


def test_happy_help_about_names_the_version(window) -> None:
    with mock.patch("ui.main_window.QMessageBox.about") as about:
        window._show_about()
    title, text = about.call_args.args[1], about.call_args.args[2]
    assert "axross" in title
    assert __version__ in text


def test_edge_about_is_in_english(window) -> None:
    with mock.patch("ui.main_window.QMessageBox.about") as about:
        window._show_about()
    text = about.call_args.args[2]
    for german in ("Unterstützte", "Warteschlange", "Tastenkombinationen", "Dateimanager"):
        assert german not in text


def test_happy_the_f1_help_title_names_the_version() -> None:
    from ui.shortcuts_dialog import ShortcutsDialog

    dlg = ShortcutsDialog()
    try:
        assert __version__ in dlg.windowTitle()
    finally:
        dlg.deleteLater()
