"""Where a column can be dragged is marked by a vertical line in the header.

Reported: "der punkt wo man ansetzen kann um name|spalte etc.pp. verschieben
kann sollte durch eine durchgehende vertikale linie erkennbar sein".
Measured before the fix in the real file pane: the modern themes drew no
line between header sections at all (``border: none`` plus a bottom
border), the classic ones a 1.2-1.4:1 line nobody sees, the native light
theme 2.0:1 - no theme reached the 3:1 that WCAG 1.4.11 asks of a control's
boundary.

Each theme now draws a full-height divider at the right edge of every
horizontal header section, at 3:1 or more against the header background.
The same audit found a checkable button (the Log dock's Auto-Scroll) that
looked the same on and off in every styled theme; a checked button now
shows that it is on.
"""

from __future__ import annotations

import os
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QEvent  # noqa: E402
from PyQt6.QtWidgets import (  # noqa: E402
    QApplication,
    QPushButton,
    QTableWidget,
)

from tests import theme_audit as TA  # noqa: E402

APP = QApplication.instance() or QApplication([])

#: WCAG 1.4.11: the boundary of a control against what is next to it.
MIN_DIVIDER_RATIO = 3.0
#: Share of the header's height the divider must cover ("durchgehend").
MIN_COVERAGE = 0.9


def pump(seconds: float = 0.05) -> None:
    end = time.time() + seconds
    while time.time() < end:
        APP.processEvents()
        time.sleep(0.01)


def _rgb(img, x: int, y: int) -> tuple[int, int, int]:
    c = img.pixelColor(x, y)
    return (c.red(), c.green(), c.blue())


def divider_report(header) -> list[str]:
    """One line per visible section whose right edge has no divider of
    MIN_DIVIDER_RATIO over MIN_COVERAGE of the header height; empty when
    every section has one."""
    img = header.grab().toImage()
    height = img.height()
    problems = []
    visible = [s for s in range(header.count()) if not header.isSectionHidden(s)]
    assert visible, "the header shows no section"
    for section in visible:
        x0 = header.sectionViewportPosition(section)
        width = header.sectionSize(section)
        edge = x0 + width - 1
        if width < 8 or edge >= img.width():
            continue  # scrolled out or too narrow to judge
        # The section's own background: its most common colour.
        bg = Counter(
            _rgb(img, x, y) for x in range(x0 + 2, edge - 2) for y in range(1, height - 1)
        ).most_common(1)[0][0]
        covered = sum(
            1 for y in range(height) if TA.contrast(_rgb(img, edge, y), bg) >= MIN_DIVIDER_RATIO
        )
        if covered < MIN_COVERAGE * height:
            best = max(TA.contrast(_rgb(img, edge, y), bg) for y in range(height))
            problems.append(
                f"section {section} ({header.model().headerData(section, header.orientation())}):"
                f" {covered}/{height} px at >= {MIN_DIVIDER_RATIO}:1, best {best:.2f}"
            )
    return problems


@pytest.fixture(scope="module")
def window():
    home = tempfile.mkdtemp()
    with mock.patch("pathlib.Path.home", return_value=Path(home)):
        from ui.main_window import MainWindow

        win = MainWindow()
        win._reconnect_timer.stop()
        win.resize(1100, 700)
        win.show()
        pump()
        yield win
        win._apply_theme("modern")
        win.close()
        win.deleteLater()
        APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)
        pump()
    __import__("shutil").rmtree(home, ignore_errors=True)


@pytest.mark.parametrize("theme", TA.THEMES)
def test_happy_the_file_pane_header_shows_a_divider_in_every_theme(window, theme) -> None:
    """e2e: the real main window, the theme applied as View > Theme does."""
    window._apply_theme(theme)
    pump()
    header = window._active_pane._table.horizontalHeader()
    assert divider_report(header) == []


@pytest.mark.parametrize("theme", ["modern-dark", "classic", "default"])
def test_edge_compact_mode_keeps_the_divider(window, theme) -> None:
    """Compact mode re-pads the sections; the line stays."""
    window._compact_mode = True
    try:
        window._apply_theme(theme)
        pump()
        assert divider_report(window._active_pane._table.horizontalHeader()) == []
    finally:
        window._compact_mode = False
        window._apply_theme("modern")


@pytest.mark.parametrize("theme", ["modern-light", "hacker"])
def test_edge_every_list_view_gets_it_not_only_the_file_pane(window, theme) -> None:
    """The divider comes from the application stylesheet, so a table in a
    dialog (the Extensions list, Find Files ...) has it as well."""
    window._apply_theme(theme)
    table = QTableWidget(3, 4)
    table.setHorizontalHeaderLabels(["Name", "Version", "Description", "Status"])
    table.resize(500, 200)
    table.show()
    pump()
    try:
        assert divider_report(table.horizontalHeader()) == []
    finally:
        table.deleteLater()
        window._apply_theme("modern")


def test_sad_the_detector_flags_a_header_without_a_line(window) -> None:
    """Negative control: the measurement must catch the reported look."""
    window._apply_theme("modern-dark")
    table = QTableWidget(3, 3)
    table.setHorizontalHeaderLabels(["Name", "Size", "Modified"])
    table.horizontalHeader().setStyleSheet(
        "QHeaderView::section { border: none; border-bottom: 1px solid #2e3340; }"
    )
    table.resize(400, 200)
    table.show()
    pump()
    try:
        assert len(divider_report(table.horizontalHeader())) == 3
    finally:
        table.deleteLater()
        window._apply_theme("modern")


@pytest.mark.parametrize("theme", TA.THEMES)
def test_happy_a_checked_button_looks_checked(window, theme) -> None:
    """The Log dock's Auto-Scroll is a checkable button: on and off must
    not look the same, and the text of the checked one stays readable."""
    window._apply_theme(theme)
    shots = []
    buttons = []
    for on in (False, True):
        button = QPushButton("Auto-Scroll")
        button.setCheckable(True)
        button.setChecked(on)
        button.resize(110, 30)
        button.show()
        buttons.append(button)
    pump()
    try:
        for button in buttons:
            shots.append(button.grab().toImage())
        assert shots[0] != shots[1], f"{theme}: a checked button looks unchecked"
        ratio, bg, fg = TA.measure_widget(buttons[1])
        bound = 3.0 if theme == "default" else 4.5
        assert ratio is not None and ratio >= bound, (theme, ratio, bg, fg)
    finally:
        for button in buttons:
            button.deleteLater()
        window._apply_theme("modern")
