"""Tours frame the right part of the window (review round 3, UX).

The tour videos showed steps that framed nothing or the wrong area:

- **A dock tabbed behind another** (Scripts, Console behind Transfers) was
  never raised: Qt parks such a dock outside the window and still calls it
  visible, so the tour framed an empty corner at the top left.
- **A stale rectangle**: the rectangle of the lookup was kept for the whole
  step. The Agent dock, opened for its step, was framed at the small size
  it had before its layout ran.
- **Source and target** and **Check the target first** pointed at the
  active pane (its ◎ does nothing: that pane is the source) instead of the
  other pane's ◎, framed one pane, and never named the SOURCE / TARGET
  badges the panes show.
- A click on ◎ of the active pane did nothing at all, and the ◎ glyph was
  cut to a 4-pixel sliver by the theme's button padding.
- ``scripts/tour_videos.py`` captured a one-pane window (no target pane)
  and the previous tour's "Tour finished" message stood in every frame.
"""

from __future__ import annotations

import importlib.util
import os
import sys
import time
from pathlib import Path
from unittest import mock

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QEvent, QPoint, QRect, Qt  # noqa: E402
from PyQt6.QtGui import QFontMetrics  # noqa: E402
from PyQt6.QtWidgets import QApplication, QDockWidget, QWidget  # noqa: E402

from ui.tour_engine import Tour, TourRunner, TourStep, shown  # noqa: E402
from ui.tours import tour  # noqa: E402

APP = QApplication.instance() or QApplication([])


def pump(seconds: float = 0.05) -> None:
    end = time.time() + seconds
    while True:
        APP.processEvents()
        if time.time() >= end:
            return
        time.sleep(0.01)


def _make_window():
    from ui import main_window as MW

    win = MW.MainWindow()
    win._reconnect_timer.stop()
    win.resize(1280, 800)
    win.show()
    pump(0.2)
    return win


def _close(win) -> None:
    runner = getattr(win, "_tour", None)
    if runner is not None:
        runner.end()
    win._quit_with_transfers = True
    win.close()
    win.deleteLater()
    APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    pump()


@pytest.fixture(scope="module")
def window(tmp_path_factory):
    """One window with two panes side by side (a window takes seconds)."""
    from ui import main_window as MW

    tmp = tmp_path_factory.mktemp("tour-targets")
    patches = [mock.patch.object(MW.MainWindow, "_SESSION_FILE", tmp / "session.json"),
               mock.patch.object(MW.MainWindow, "_RECENTS_FILE", tmp / "recents.json")]
    for patch in patches:
        patch.start()
    win = _make_window()
    win._split_pane(Qt.Orientation.Horizontal)
    pump(0.3)
    try:
        yield win
    finally:
        _close(win)
        for patch in reversed(patches):
            patch.stop()


@pytest.fixture
def runner_of(window):
    runners = []

    def start(tour_or_id, title=None):
        one = tour(tour_or_id) if isinstance(tour_or_id, str) else tour_or_id
        runner = TourRunner(window, one)
        runners.append(runner)
        assert runner.start()
        if title is not None:
            while runner.running and runner.step.title != title:
                runner.next()
            assert runner.running, title
        pump(0.1)
        return runner

    yield start
    for runner in runners:
        runner.end()
    window._agent_dock.close()
    window._transfer_dock.show()
    window._transfer_dock.raise_()
    window.statusBar().clearMessage()
    pump()


def _in_window(window, widget) -> QRect:
    return QRect(widget.mapTo(window, QPoint(0, 0)), widget.size())


# ---------------------------------------------------------------------------
# Docks tabbed behind another, widgets outside the window
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("title, dock_name", [("Scripts", "axScriptsDock"),
                                              ("The console", "axConsoleDock")])
def test_sad_a_dock_tabbed_behind_another_is_raised_and_framed(window, runner_of, title,
                                                                dock_name):
    """Scripts and Console sit behind Transfers: the step framed an empty
    corner at the top left, because the dock was never raised."""
    dock = window.findChild(QDockWidget, dock_name)
    window._transfer_dock.raise_()
    pump()
    assert window.tabifiedDockWidgets(dock), "the default layout tabs this dock"
    runner = runner_of("automate", title)
    hole = runner.spotlight.hole
    assert not hole.isEmpty() and window.rect().contains(hole)
    assert hole == _in_window(window, dock)
    assert not dock.visibleRegion().isEmpty()  # it is the front tab now
    runner.end()
    pump()
    # the tab that was in front before the tour is in front again
    assert shown((window._transfer_dock, window._transfer_dock.rect()))
    assert not shown((dock, dock.rect()))


def test_sad_a_widget_parked_outside_the_window_is_not_shown(window):
    """Qt calls a dock tabbed away visible while it sits outside the window:
    such a spot is nothing to point at."""
    parked = QWidget(window)
    parked.setGeometry(-600, -500, 200, 80)
    parked.show()
    try:
        assert parked.isVisible()
        assert not shown((parked, parked.rect()))
        parked.move(40, 300)
        assert shown((parked, parked.rect()))
    finally:
        parked.deleteLater()


def test_sad_the_frame_is_read_again_when_the_widget_changes_size(window, runner_of):
    """The rectangle of the lookup was kept: a widget laid out after its step
    started (the Agent dock just opened) was framed at its old size."""
    box = QWidget(window)
    box.setGeometry(300, 300, 60, 40)
    box.show()
    try:
        runner = runner_of(Tour("custom", "Custom", "a test tour",
                                (TourStep("Box", "a box", lambda w: box),
                                 TourStep("After", "the queue", "axTransferDock"))))
        assert runner.spotlight.hole == QRect(300, 300, 60, 40)
        box.setGeometry(280, 260, 240, 120)
        pump(0.4)  # longer than the follow interval
        assert runner.spotlight.hole == QRect(280, 260, 240, 120)
    finally:
        box.deleteLater()


# ---------------------------------------------------------------------------
# Source and target
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tour_id, title", [("getting-started", "Source and target"),
                                            ("copy-safely", "Check the target first")])
def test_sad_target_steps_point_at_the_other_panes_button_and_frame_both(
        window, runner_of, tour_id, title):
    """They pointed at the active pane, whose ◎ does nothing (it is the
    source), and framed only that pane."""
    active, target = window._active_pane, window._target_pane
    assert target is not None and target is not active
    runner = runner_of(tour_id, title)
    assert runner.spot[0] is target.findChild(QWidget, "axPaneTarget")
    both = _in_window(window, active).united(_in_window(window, target))
    assert runner.spotlight.context == both
    assert runner.spotlight.hole == _in_window(window, runner.spot[0])
    assert window.rect().contains(runner.callout.geometry())
    assert not runner.callout.geometry().intersects(runner.spotlight.hole)


def test_happy_the_target_steps_explain_the_badges_in_both_languages():
    """The panes say SOURCE and TARGET; the tour never named them."""
    import json

    catalogue = json.loads((ROOT / "resources/i18n/de.json").read_text(encoding="utf-8"))
    for tour_id, title in (("getting-started", "Source and target"),
                           ("copy-safely", "Check the target first")):
        step = next(s for s in tour(tour_id).steps if s.title == title)
        assert "SOURCE" in step.text and "TARGET" in step.text, title
        german = catalogue[step.text]
        assert catalogue["SOURCE"] in german and catalogue["TARGET"] in german, title


def test_sad_target_on_the_active_pane_says_why(window):
    """◎ on the active pane did nothing, silently."""
    active, target = window._active_pane, window._target_pane
    window.statusBar().clearMessage()
    active._btn_target.click()
    pump()
    assert window._target_pane is target and window._active_pane is active
    message = window.statusBar().currentMessage()
    assert "source" in message and "◎" in message


def test_edge_target_on_the_only_pane_says_how_to_get_one(tmp_path):
    from ui import main_window as MW

    with mock.patch.object(MW.MainWindow, "_SESSION_FILE", tmp_path / "session.json"), \
            mock.patch.object(MW.MainWindow, "_RECENTS_FILE", tmp_path / "recents.json"):
        win = _make_window()
        try:
            assert len(win._panes) == 1
            win._active_pane._btn_target.click()
            pump()
            assert "Ctrl+Shift+H" in win.statusBar().currentMessage()
        finally:
            _close(win)


def test_sad_the_target_glyph_is_not_clipped(window):
    """The theme's QPushButton padding (4px 8px) left the 20x20 button a
    contents box 4 px wide: ◎ showed as a sliver."""
    button = window._active_pane._btn_target
    assert button.size().width() == 20 and button.size().height() == 20
    image = button.grab().toImage()
    background = image.pixelColor(1, 1).lightness()
    xs, ys = [], []
    for y in range(image.height()):
        for x in range(image.width()):
            if abs(image.pixelColor(x, y).lightness() - background) > 40:
                xs.append(x)
                ys.append(y)
    glyph = QFontMetrics(button.font()).tightBoundingRect("◎")
    assert xs and max(xs) - min(xs) + 1 >= glyph.width() - 2
    assert max(ys) - min(ys) + 1 >= glyph.height() - 2


# ---------------------------------------------------------------------------
# scripts/tour_videos.py
# ---------------------------------------------------------------------------


def _tour_videos():
    spec = importlib.util.spec_from_file_location("tour_videos_t",
                                                  ROOT / "scripts" / "tour_videos.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_happy_the_videos_start_from_the_first_start_layout(tmp_path):
    """capture_frames used a bare MainWindow(): one pane, no target."""
    from ui import main_window as MW

    TV = _tour_videos()
    with mock.patch.object(MW.MainWindow, "_SESSION_FILE", MW.MainWindow._SESSION_FILE), \
            mock.patch.object(MW.MainWindow, "_RECENTS_FILE", MW.MainWindow._RECENTS_FILE):
        win = TV.first_start_window(tmp_path)
        try:
            win.show()
            pump(0.3)
            assert MW.MainWindow._SESSION_FILE.parent == tmp_path / ".config" / "axross"
            panes = [p for p in win._panes if p.isVisible()]
            assert len(panes) == 2
            assert win._target_pane in panes and win._target_pane is not win._active_pane
            assert (win.width(), win.height()) == TV.SIZE
        finally:
            _close(win)


def test_sad_the_status_bar_is_clear_in_every_frame(window, tmp_path, monkeypatch):
    """The previous tour's "Tour finished" stood in the next tour's frames."""
    TV = _tour_videos()
    monkeypatch.setattr(TV, "_pump", lambda app, seconds: pump(0.02))
    messages = []
    real_grab = window.grab

    def grab(*args):
        messages.append(window.statusBar().currentMessage())
        return real_grab(*args)

    monkeypatch.setattr(window, "grab", grab)
    window.statusBar().showMessage("Tour finished - from the tour before")
    one = Tour("custom", "Custom", "a test tour",
               (TourStep("Undo", "undo", "axUndoAction"),))
    entry = TV.capture_tour(APP, window, one, tmp_path, tmp_path)
    assert [s["title"] for s in entry["steps"]] == ["Undo"]
    assert (tmp_path / "00.png").exists() and (tmp_path / "intro.png").exists()
    assert messages and all(m == "" for m in messages), messages
