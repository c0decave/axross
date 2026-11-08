"""Help > Tours…: guided tours over the real window, and the first-start offer.

The user asked for "tours for the right way to use it". A tour is data
(ui.tours.TOURS: steps with a widget lookup, a title and a text); the engine
(ui.tour_engine) frames the widget, shows a callout with Step k of n, Back,
Next and End Tour, ends on Escape and skips a step whose widget is missing.
Covered here, and why:

- **Every step points at something real.** In a default window each step's
  widget is found (or the step is marked optional), every objectName a tour
  names exists, and each tour has 4-8 steps - a renamed or removed widget
  fails here instead of silently shortening a tour.
- **Walking.** Forward, back (not before the first), Finish on the last step;
  Escape and End Tour end it; a dock the tour opened is closed again.
- **Missing widgets.** A closed dock, an unknown name, a lookup that raises,
  a widget deleted while its step shows: skipped, said so, never a crash; a
  tour with nothing to show does not start.
- **No grabs, no modality.** The spotlight lets the mouse through, the
  callout is a child widget, not a window; nothing modal appears - the
  window starts offscreen in tests and under the startup watchdog.
- **The first-start offer.** Once, as a status bar notice; never a dialog;
  not again at the next start; off when Settings > General says so.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6 import sip  # noqa: E402
from PyQt6.QtCore import QEvent, QRect, Qt  # noqa: E402
from PyQt6.QtGui import QAction  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication, QDialog, QMessageBox, QWidget  # noqa: E402

from ui.tour_engine import Tour, TourRunner, TourStep, place, resolve, shown  # noqa: E402
from ui.tours import FIRST_TOUR, TOURS, tour  # noqa: E402

APP = QApplication.instance() or QApplication([])


def pump(seconds: float = 0.05) -> None:
    end = time.time() + seconds
    while True:
        APP.processEvents()
        if time.time() >= end:
            return
        time.sleep(0.01)


@pytest.fixture
def settings(tmp_path, monkeypatch):
    from core import open_limits as OL

    path = tmp_path / "settings.json"
    monkeypatch.setattr(OL, "SETTINGS_PATH", path)
    return path


def _make_window():
    from ui import main_window as MW

    win = MW.MainWindow()
    win._reconnect_timer.stop()
    win.resize(1280, 800)
    win.show()
    pump(0.1)
    return win


def _close(win) -> None:
    runner = getattr(win, "_tour", None)
    if runner is not None:
        runner.end()
    win.close()
    win.deleteLater()
    APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    pump()


@pytest.fixture(scope="module")
def _module_window(tmp_path_factory):
    from unittest import mock

    from ui import main_window as MW

    tmp = tmp_path_factory.mktemp("tours-window")
    patches = [mock.patch.object(MW.MainWindow, "_SESSION_FILE", tmp / "session.json"),
               mock.patch.object(MW.MainWindow, "_RECENTS_FILE", tmp / "recents.json")]
    for patch in patches:
        patch.start()
    win = _make_window()
    try:
        yield win
    finally:
        _close(win)
        for patch in reversed(patches):
            patch.stop()


@pytest.fixture
def window(_module_window, settings):
    """The module's window (a window takes seconds to build), put back after
    each test: no tour, no notice, the Transfers dock open, the Agent dock
    closed."""
    win = _module_window
    made = []

    def make():
        made.append(_make_window())
        return made[-1]

    win.make_another = make
    yield win
    for one in made:
        _close(one)
    runner = getattr(win, "_tour", None)
    if runner is not None:
        runner.end()
    win._tour = None
    win._dismiss_tour_offer()
    win._transfer_dock.show()
    win._agent_dock.close()
    for widget in APP.topLevelWidgets():
        if widget is not win and widget.isVisible():
            widget.close()
    APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    pump()


def _custom(*steps: TourStep) -> Tour:
    return Tour("custom", "Custom", "a test tour", steps)


# ---------------------------------------------------------------------------
# The data: every step points at something real
# ---------------------------------------------------------------------------


def test_happy_the_six_tours_with_four_to_eight_steps_each():
    assert [t.id for t in TOURS] == ["getting-started", "connect", "copy-safely",
                                     "find-organize", "automate", "extensions"]
    assert tour(FIRST_TOUR) is TOURS[0] and tour("nope") is None
    for one in TOURS:
        assert 4 <= len(one.steps) <= 8, one.id
        assert one.title and one.summary
        for step in one.steps:
            assert step.title and len(step.text) > 60, (one.id, step.title)
        assert len({s.title for s in one.steps}) == len(one.steps), one.id


def test_happy_every_step_widget_exists_in_a_default_window(window):
    missing = []
    for one in TOURS:
        runner = TourRunner(window, one)
        for step in one.steps:
            if runner.locate(step) is None and not step.optional:
                missing.append(f"{one.id}: {step.title}")
        runner.end()
    assert missing == []


def test_happy_every_object_name_a_tour_names_exists(window):
    names = set()
    for one in TOURS:
        for step in one.steps:
            if isinstance(step.target, str):
                names.add(step.target)
            elif isinstance(step.target, tuple):
                names.update(step.target)
    assert names
    gone = sorted(n for n in names if window.findChild(QWidget, n) is None
                  and window.findChild(QAction, n) is None)
    assert gone == []


def test_edge_the_german_catalogue_has_the_tour_names_summaries_and_step_titles():
    """Help > Tours… and the callout's title speak German in a German
    interface; the step texts may stay English (core.i18n falls back)."""
    import json

    catalogue = json.loads((ROOT / "resources/i18n/de.json").read_text(encoding="utf-8"))
    for one in TOURS:
        assert one.title in catalogue and one.summary in catalogue, one.id
        assert [s.title for s in one.steps if s.title not in catalogue] == [], one.id
    for text in ("Back", "Next", "Finish", "End Tour", "Step {k} of {n}", "T&ours…",
                 "&Handbook"):
        assert text in catalogue, text


# ---------------------------------------------------------------------------
# Walking a tour
# ---------------------------------------------------------------------------


def test_happy_a_tour_walks_forward_and_back(window):
    runner = window.start_tour("getting-started")
    assert runner is not None and runner.running
    callout = runner.callout
    n = len(runner.tour.steps)
    assert runner.index == 0 and callout.step_label.text() == f"Step 1 of {n}"
    assert callout.title_label.text() == "Panes side by side"
    assert not callout.back_button.isEnabled()
    runner.back()  # nothing before the first step
    assert runner.index == 0
    callout.next_button.click()
    pump()
    assert runner.index == 1 and callout.step_label.text() == f"Step 2 of {n}"
    assert callout.back_button.isEnabled()
    callout.back_button.click()
    assert runner.index == 0
    for _ in range(n - 1):
        runner.next()
    assert runner.index == n - 1 and callout.next_button.text() == "Finish"
    assert runner.skipped == []
    callout.next_button.click()
    pump()
    assert not runner.running and runner.reason == "done"
    assert runner.callout is None
    assert "Tour finished" in window.statusBar().currentMessage()


def test_happy_the_callout_sits_beside_its_widget_inside_the_window(window):
    runner = window.start_tour("getting-started")
    for _ in runner.tour.steps:
        pump()
        box = runner._target_rect()
        geometry = runner.callout.geometry()
        assert window.rect().contains(geometry), (runner.step.title, geometry)
        if box.width() < window.width() / 2 and box.height() < window.height() / 2:
            assert not geometry.intersects(box), runner.step.title
        assert runner.spotlight.hole == box
        runner.next()


def test_happy_escape_ends_the_tour(window):
    runner = window.start_tour("copy-safely")
    table = window._active_pane._table
    table.setFocus()
    QTest.keyClick(table, Qt.Key.Key_Escape)
    pump()
    assert not runner.running and runner.reason == "escape"
    assert window.findChild(QWidget, "axTourCallout") is None or sip.isdeleted(
        window.findChild(QWidget, "axTourCallout")) or not window.findChild(
            QWidget, "axTourCallout").isVisible()


def test_happy_end_tour_ends_it_and_the_list_starts_one(window):
    dialog = window.show_tours()
    assert dialog.list.topLevelItemCount() == len(TOURS)
    assert dialog.list.topLevelItem(1).text(1) == TOURS[1].summary
    dialog.list.setCurrentItem(dialog.list.topLevelItem(3))
    runner = dialog.start_selected()
    assert runner is window._tour and runner.tour.id == "find-organize"
    assert not dialog.isVisible()
    runner.callout.end_button.click()
    assert not runner.running and runner.reason == "ended"


def test_edge_a_new_tour_replaces_the_running_one(window):
    first = window.start_tour("connect")
    second = window.start_tour("extensions")
    assert not first.running and first.reason == "replaced" and second.running
    assert len(window.findChildren(QWidget, "axTourCallout")) >= 1
    assert sum(1 for w in window.findChildren(QWidget, "axTourCallout")
               if not sip.isdeleted(w) and w.isVisible()) == 1


def test_edge_a_closed_dock_is_opened_for_its_step_and_closed_again(window):
    dock = window._agent_dock
    dock.close()
    pump()
    runner = window.start_tour("automate")
    pump()
    assert runner.step.title == "The Agent" and dock.isVisible()
    runner.end()
    pump()
    assert not dock.isVisible()


# ---------------------------------------------------------------------------
# Missing widgets are skipped, never a crash
# ---------------------------------------------------------------------------


def test_sad_a_missing_widget_is_skipped_and_said(window):
    def broken(_window):
        raise RuntimeError("lookup failed")

    runner = TourRunner(window, _custom(
        TourStep("One", "first", "axUndoAction"),
        TourStep("Gone", "missing", "axNoSuchWidget"),
        TourStep("Broken", "raises", broken),
        TourStep("Three", "last", "axTransferDock"),
    ))
    assert runner.start()
    runner.next()
    assert runner.index == 3 and runner.skipped == ["Gone", "Broken"]
    note = runner.callout.skip_label
    assert not note.isHidden() and "Gone" in note.text() and "Broken" in note.text()
    runner.back()  # back over the missing ones to the first
    assert runner.index == 0 and runner.skipped == ["Broken", "Gone"]
    runner.end()


def test_sad_a_closed_dock_is_skipped_in_the_real_tour(window):
    window._transfer_dock.close()
    pump()
    runner = window.start_tour("getting-started")
    titles = [s.title for s in runner.tour.steps]
    while runner.step.title != "Copy between panes":
        runner.next()
    runner.next()
    assert runner.step.title == "Undo"
    assert runner.skipped == ["The transfer queue"]
    assert titles.index("Undo") == runner.index


def test_sad_a_widget_deleted_during_its_step_moves_on(window):
    temp = QWidget(window)
    temp.setGeometry(10, 200, 120, 40)
    temp.show()
    runner = TourRunner(window, _custom(
        TourStep("Temp", "goes away", lambda w: temp),
        TourStep("After", "stays", "axTransferDock"),
    ))
    runner.start()
    assert runner.index == 0
    temp.deleteLater()
    APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    runner._follow_step()
    assert runner.index == 1 and runner.skipped == ["Temp"]
    runner.end()


def test_sad_a_tour_with_nothing_to_show_does_not_start(window):
    runner = TourRunner(window, _custom(TourStep("Gone", "x", "axNothing"),
                                        TourStep("Gone too", "y", lambda w: None)))
    assert runner.start() is False and runner.reason == "nothing"
    assert "nothing to show" in window.statusBar().currentMessage()
    assert window.start_tour("no-such-tour") is None


def test_sad_the_last_steps_missing_finishes_the_tour(window):
    runner = TourRunner(window, _custom(TourStep("One", "x", "axUndoAction"),
                                        TourStep("Gone", "y", "axNothing")))
    runner.start()
    runner.next()
    assert not runner.running and runner.reason == "done" and runner.skipped == ["Gone"]


# ---------------------------------------------------------------------------
# No grabs, no modality
# ---------------------------------------------------------------------------


def test_edge_the_spotlight_lets_the_mouse_through_and_nothing_is_a_window(window):
    runner = window.start_tour("find-organize")
    assert runner.spotlight.testAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
    assert not runner.callout.isWindow() and not runner.spotlight.isWindow()
    assert runner.callout.parentWidget() is window
    assert QApplication.activeModalWidget() is None
    assert APP.mouseButtons() == Qt.MouseButton.NoButton
    runner.end()


def test_edge_a_menu_entry_points_at_its_menu_title(window):
    spot = resolve(window, "axUndoAction")
    assert spot[0] is window.menuBar() and shown(spot)
    edit = next(a for a in window.menuBar().actions() if a.text() == "&Edit")
    assert spot[1] == window.menuBar().actionGeometry(edit)


def test_edge_place_keeps_the_callout_inside_and_off_the_widget():
    area = QRect(0, 0, 800, 600)
    for box in (QRect(10, 10, 40, 30), QRect(700, 500, 90, 90), QRect(380, 0, 40, 600),
                QRect(0, 280, 800, 40)):
        rect = place(box, (360, 180), area)
        assert area.contains(rect), (box, rect)
        assert not rect.intersects(box), (box, rect)
    huge = place(QRect(0, 0, 800, 600), (360, 180), area)
    assert area.contains(huge)
    tiny = place(QRect(0, 0, 10, 10), (360, 180), QRect(0, 0, 200, 100))
    assert QRect(0, 0, 200, 100).contains(tiny)


# ---------------------------------------------------------------------------
# The first-start offer
# ---------------------------------------------------------------------------


def _modal_or_dialog_shown(win) -> list:
    return [w for w in APP.topLevelWidgets()
            if w is not win and w.isVisible() and isinstance(w, (QDialog, QMessageBox))]


def test_happy_the_first_start_offers_the_tour_once_and_never_modally(window, settings):
    from core import tour_offer

    assert tour_offer.offer_at_start() is True
    assert window.offer_getting_started_tour() is True
    pump()
    notice = window.findChild(QWidget, "axTourOffer")
    assert notice is not None and notice.isVisible()
    assert notice.parentWidget() is not None and not notice.isWindow()
    assert QApplication.activeModalWidget() is None and _modal_or_dialog_shown(window) == []
    assert window.offer_getting_started_tour() is False  # one notice
    assert tour_offer.offer_at_start() is False  # remembered: shown once
    again = window.make_another()
    assert again.offer_getting_started_tour() is False  # the next start offers nothing


def test_happy_take_the_tour_starts_it_and_the_notice_goes(window):
    window.offer_getting_started_tour()
    window.findChild(QWidget, "axTourOfferTake").click()
    pump()
    assert window._tour.running and window._tour.tour.id == FIRST_TOUR
    assert window._tour_offer is None


def test_happy_no_thanks_dismisses_it(window):
    window.offer_getting_started_tour()
    window.findChild(QWidget, "axTourOfferDismiss").click()
    APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    pump()
    assert window._tour_offer is None and window.findChild(QWidget, "axTourOffer") is None
    assert getattr(window, "_tour", None) is None


def test_sad_switched_off_in_settings_nothing_is_offered(window, settings):
    from core import tour_offer

    tour_offer.set_offer_at_start(False)
    assert window.offer_getting_started_tour() is False
    assert window.findChild(QWidget, "axTourOffer") is None


def test_edge_a_hand_edited_value_reads_as_the_default(settings):
    from core import tour_offer

    settings.write_text('{"offer_tour_at_start": "no"}')
    assert tour_offer.offer_at_start() is True
    with pytest.raises(TypeError):
        tour_offer.set_offer_at_start("no")


def test_edge_main_offers_it_after_the_window_is_up_and_not_in_a_smoke_start():
    source = (ROOT / "main.py").read_text(encoding="utf-8")
    start = source.index("schedule_start_check(window)")
    smoke = source.rindex("if smoke_ms is not None:", 0, start)
    assert source.index("window.show()") < smoke
    assert "QTimer.singleShot(0, window.offer_getting_started_tour)" in source[start:start + 400]


def test_sad_the_callout_is_opaque_and_the_rest_is_dimmed(window):
    """The callout's style sheet set only a border: Qt then paints the frame
    itself and autoFillBackground no longer applies, so the box was
    transparent and its text ran over the toolbar below. The dim (alpha 90)
    was all but invisible on the dark theme."""
    from ui.tour_engine import Spotlight, TourRunner
    from ui.tours import TOURS

    runner = TourRunner(window, TOURS[0])
    assert runner.start()
    try:
        pump(0.3)
        box = runner.callout
        image = window.grab(box.geometry()).toImage()
        inner = image.pixelColor(box.width() // 2, box.height() - 6)
        expected = box.palette().color(box.backgroundRole())
        assert inner.name() == expected.name()
        assert Spotlight.DIM.alpha() >= 140
    finally:
        runner.end()
